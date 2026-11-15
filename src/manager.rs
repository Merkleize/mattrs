//! Contract Manager
//!
//! Manages the lifecycle of contract instances from funding through spending,
//! with automatic output tracking and witness decoding.
//!
//! Spending goes through the fluent [`SpendBuilder`]: a clause is invoked with its
//! typed arguments (already encoded to a witness stack), signers are registered by
//! public key, and `exec`/`exec_one`/`exec_none` build, sign and broadcast the
//! spend, wait for it to settle, and materialize the resulting child instances.
//!
//! Covenants driven by *someone else* are followed with chain observation:
//! [`ContractManager::track_instance`] registers an externally funded instance,
//! and [`ContractManager::wait_for_spend`] (or the RPC-free
//! [`ContractManager::observe_spend`]) detects its spend, decodes the witness
//! back into the clause and its arguments, and materializes the child instances
//! — so both parties of a protocol hold the same view of the contract's state.
//!
//! # What the manager records
//!
//! A manager on a chain records settled facts only. A transaction is
//! *settled* once it has the manager's
//! [`confirmations`](ContractManager::confirmations) (one by default). An
//! instance is registered when its funding transaction is settled; it becomes
//! spent, and its children exist, when a transaction spending it is settled.
//! That holds for the manager's own spends too: broadcasting is an attempt
//! ([`ContractManager::broadcast_batch`] returns a [`PendingSpend`] and
//! records nothing), and what gets recorded is whichever spend the chain
//! confirms ([`PendingSpend::settle`]). The children of a spend therefore
//! cannot be spent before the spend is settled: every step of a protocol
//! costs that many blocks.
//!
//! # Known limitations
//!
//! - **Deep reorganizations.** What is recorded is never revisited. A
//!   reorganization deeper than the manager's confirmations leaves it
//!   describing a chain that no longer exists, and nothing detects that.
//!   Recording the block each fact settled in, and checking that it is still
//!   on the active chain, would at least turn this into an error; rolling
//!   the instance graph back would handle it.
//! - **Fees and replacement.** Spends carry whatever fee their clause leaves
//!   and are never bumped. A conflicting transaction sitting in the mempool
//!   blocks ours for as long as it stays there; the manager (and a
//!   [`Runner`](crate::protocol::Runner)) waits correctly for whichever
//!   confirms, but cannot make ours win.
//! - **Explicit observation.** [`ContractManager::observe_spend`] and
//!   [`ContractManager::observe_batch`] record the transaction they are
//!   handed, with no chain lookup: the caller vouches that it is settled.
//!   They are how an [`offline`](ContractManager::offline) manager learns
//!   anything at all.
//!
//! The public facade composes RPC-free preparation/signing, shared constraint
//! validation, and staged lifecycle updates. A spend is validated before it is
//! broadcast, and recorded through the same staging/commit path as an
//! observation once it settles. See `src/manager/README.md` for the internal
//! component boundaries.

use crate::chain::ChainView;
use crate::contracts::ContractInstance;
use bitcoin::Transaction;
use std::{cell::RefCell, rc::Rc};

mod builder;
mod chain;
mod error;
mod handles;
#[cfg(feature = "inspector")]
mod inspection;
mod lifecycle;
mod observation;
mod signing;
mod transaction;
mod validation;
mod wallet;

#[cfg(feature = "rpc")]
pub use crate::chain::regtest_rpc_client;
pub use builder::SpendBuilder;
pub use error::{ManagerError, WrongContractType};
pub use handles::{Children, InstanceHandle};
use transaction::PreparedBatch;
pub use wallet::{BatchObservation, ExternalInput, SignedWalletSpend, WalletSpend};

/// Build and sign (without broadcasting or recording) a single transaction
/// that spends several instances at once, merging their clause outputs by
/// index. It needs no manager or node: everything comes from the builders,
/// including the signers (a manager's standing signers are not consulted).
/// [`ContractManager::spend_batch`] also broadcasts it and records it once
/// it settles.
pub fn build_batch_tx(builders: &[SpendBuilder]) -> Result<Transaction, ManagerError> {
    signing::sign_prepared(
        builders,
        transaction::prepare(builders)?,
        &Default::default(),
    )
}

/// Manages contract instances and their lifecycle.
pub struct ContractManager {
    /// The chain backend; `None` for an offline manager.
    chain: Option<Rc<dyn ChainView>>,

    /// The network the contracts live on.
    network: bitcoin::Network,

    /// All instances managed by this manager.
    instances: Vec<Rc<RefCell<ContractInstance>>>,

    /// This party's standing signers, by the key they sign for.
    signers: signing::Signers,

    /// How many confirmations a spend found on the chain needs before it is
    /// recorded.
    confirmations: u32,

    /// Whether to mine a block after each transaction this manager broadcasts.
    auto_mine: bool,

    /// The outpoints this manager is looking for a spend of, at its current
    /// `confirmations`: the lookups the chain backend may be keeping state
    /// for, to release when they are abandoned.
    watched: RefCell<std::collections::BTreeSet<bitcoin::OutPoint>>,

    /// The snapshot shared with the inspector server, if enabled.
    #[cfg(feature = "inspector")]
    inspector_state: Option<std::sync::Arc<std::sync::Mutex<crate::inspector::ManagerSnapshot>>>,
    /// Wakes the inspector server's client threads after a snapshot update.
    #[cfg(feature = "inspector")]
    inspector_notify: Option<std::sync::Arc<std::sync::Condvar>>,
}

impl ContractManager {
    /// Create a manager talking to a Bitcoin node over RPC, on `network`.
    /// Shorthand for [`on`](Self::on) with an
    /// [`RpcChain`](crate::chain::RpcChain).
    #[cfg(feature = "rpc")]
    pub fn new(rpc: bitcoincore_rpc::Client, network: bitcoin::Network) -> Self {
        Self::on(Rc::new(crate::chain::RpcChain::new(rpc)), network)
    }

    /// Create a manager on any chain backend: a node
    /// (`RpcChain`, with the `rpc` feature), the in-memory
    /// [`LocalChain`](crate::chain::LocalChain) for deterministic tests, or
    /// your own [`ChainView`]. Share one `Rc` between managers to put several
    /// parties on the same chain.
    pub fn on(chain: Rc<dyn ChainView>, network: bitcoin::Network) -> Self {
        Self {
            chain: Some(chain),
            ..Self::offline(network)
        }
    }

    /// Create a manager with no chain behind it. Everything that does not need
    /// one works as usual: building and signing spends, recording spends
    /// observed elsewhere ([`observe_spend`](Self::observe_spend),
    /// [`observe_batch`](Self::observe_batch)), and executing spends through
    /// an external broadcaster
    /// ([`broadcast_batch_with`](Self::broadcast_batch_with)).
    /// Operations that must reach a chain return [`ManagerError::NoNode`].
    pub fn offline(network: bitcoin::Network) -> Self {
        Self {
            chain: None,
            network,
            instances: Vec::new(),
            signers: Default::default(),
            confirmations: 1,
            auto_mine: false,
            watched: Default::default(),
            #[cfg(feature = "inspector")]
            inspector_state: None,
            #[cfg(feature = "inspector")]
            inspector_notify: None,
        }
    }

    /// Register a standing signer: every spend this manager executes fills
    /// the signature arguments naming its key, with no per-spend
    /// [`SpendBuilder::sign`]. A signer given to a builder still wins for
    /// that spend. Registering a second signer for the same key replaces
    /// the first.
    pub fn add_signer(&mut self, signer: impl crate::signer::Signer + 'static) -> &mut Self {
        self.signers.insert(signer.public_key(), Rc::new(signer));
        self
    }

    /// [`add_signer`](Self::add_signer), for construction chains:
    /// `ContractManager::on(chain, network).with_signer(signer)`.
    pub fn with_signer(mut self, signer: impl crate::signer::Signer + 'static) -> Self {
        self.add_signer(signer);
        self
    }

    /// How many confirmations a transaction needs before this manager takes
    /// it as settled and records what it did. The default is 1: a
    /// transaction counts once it is in a block.
    pub fn confirmations(&self) -> u32 {
        self.confirmations
    }

    /// Set the [`confirmations`](Self::confirmations) a transaction needs to
    /// be settled.
    ///
    /// Everything a manager on a chain records is settled: an instance is
    /// registered once its funding transaction is that deep
    /// ([`fund_instance`](Self::fund_instance),
    /// [`track_instance`](Self::track_instance)), and it is spent, with its
    /// children created, once a transaction spending it is that deep —
    /// whoever broadcast it, this manager included. A transaction that is
    /// only in the mempool, or in a shallower block, changes nothing.
    ///
    /// What is recorded is never revisited, so the depth is the manager's
    /// whole answer to chain reorganizations: one deeper than this leaves
    /// the manager describing a chain that no longer exists, and nothing
    /// detects it. Pick a depth at which you take a block as final.
    ///
    /// The exception is an explicit [`observe_spend`](Self::observe_spend) /
    /// [`observe_batch`](Self::observe_batch), which records the transaction
    /// it is handed: there the caller vouches for it.
    ///
    /// Changing the depth while waiting for a spend is fine: the wait goes on
    /// at the new depth.
    ///
    /// # Panics
    ///
    /// Panics if `confirmations` is zero: an unconfirmed transaction is
    /// never settled.
    pub fn set_confirmations(&mut self, confirmations: u32) -> &mut Self {
        assert!(
            confirmations >= 1,
            "an unconfirmed transaction is never settled: at least one confirmation is needed"
        );
        if confirmations != self.confirmations {
            // The lookups in progress were at the old depth: nobody will
            // continue them, so the backend should not keep their state.
            let abandoned = std::mem::take(&mut *self.watched.borrow_mut());
            if let Some(chain) = &self.chain {
                for outpoint in abandoned {
                    chain.stop_watching(outpoint, self.confirmations);
                }
            }
            self.confirmations = confirmations;
        }
        self
    }

    /// [`set_confirmations`](Self::set_confirmations), for construction
    /// chains.
    pub fn with_confirmations(mut self, confirmations: u32) -> Self {
        self.set_confirmations(confirmations);
        self
    }

    /// Mine [`confirmations`](Self::confirmations) blocks after every
    /// transaction this manager broadcasts through its chain backend
    /// (spends and fundings), so that it settles without anyone else mining.
    /// For regtest and test chains only: the backend must support
    /// [`ChainView::mine_blocks`]. Off by default — and without it, or a
    /// miner, [`fund_instance`](Self::fund_instance) and
    /// [`spend_batch`](Self::spend_batch) wait forever.
    ///
    /// A spend sent through
    /// [`broadcast_batch_with`](Self::broadcast_batch_with)'s own broadcaster
    /// is not followed by a block.
    pub fn set_auto_mining(&mut self, auto_mine: bool) -> &mut Self {
        self.auto_mine = auto_mine;
        self
    }

    /// [`set_auto_mining`](Self::set_auto_mining)`(true)`, for construction
    /// chains.
    pub fn with_auto_mining(mut self) -> Self {
        self.auto_mine = true;
        self
    }

    /// The network this manager's contracts live on.
    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    /// The chain backend; [`ManagerError::NoNode`] for an
    /// [`offline`](Self::offline) manager.
    pub fn chain(&self) -> Result<&Rc<dyn ChainView>, ManagerError> {
        self.chain.as_ref().ok_or(ManagerError::NoNode)
    }

    /// Spend several instances in one transaction and return handles to the
    /// child instances created — one per merged output index. Shorthand for
    /// [`broadcast_batch`](Self::broadcast_batch) followed by
    /// [`PendingSpend::settle`]: it returns once the spend has the manager's
    /// [`confirmations`](Self::confirmations), however long that takes.
    ///
    /// Mirrors pymatt's multi-input `get_spend_tx`: within each input the
    /// deduct outputs must precede its preserve outputs, and a preserve output at
    /// a shared index accumulates each contributing input's remaining amount (so N
    /// vaults triggering to the same next contract merge into one output). CTV
    /// template clauses are single-input only and are rejected here.
    pub fn spend_batch(&mut self, builders: &[SpendBuilder]) -> Result<Children, ManagerError> {
        self.broadcast_batch(builders)?.settle(self)
    }

    /// Build, sign and broadcast one transaction spending several instances,
    /// without recording anything: a broadcast transaction is an attempt, and
    /// the instances are spent only once *some* transaction spending them is
    /// confirmed. [`PendingSpend::settle`] waits for that and records it.
    ///
    /// The spend is fully validated before it is sent: a transaction this
    /// manager could not record is never broadcast.
    pub fn broadcast_batch(&self, builders: &[SpendBuilder]) -> Result<PendingSpend, ManagerError> {
        let pending = self.sign_batch(builders)?;
        self.send(&pending)?;
        Ok(pending)
    }

    /// Like [`broadcast_batch`](Self::broadcast_batch), but hands the signed
    /// transaction to `broadcast` instead of this manager's own chain backend
    /// — for callers that reach the chain another way (e.g. a relay). The
    /// spend is validated *before* `broadcast` runs, and nothing is recorded:
    /// settle the returned spend on a manager with a chain, or record the
    /// confirmed transaction with [`observe_batch`](Self::observe_batch).
    pub fn broadcast_batch_with<E: From<ManagerError>>(
        &self,
        builders: &[SpendBuilder],
        broadcast: impl FnOnce(&Transaction) -> Result<(), E>,
    ) -> Result<PendingSpend, E> {
        let pending = self.sign_batch(builders)?;
        broadcast(pending.transaction())?;
        Ok(pending)
    }

    /// Build, sign and validate a spend, without sending it.
    pub(crate) fn sign_batch(
        &self,
        builders: &[SpendBuilder],
    ) -> Result<PendingSpend, ManagerError> {
        let prepared = transaction::prepare(builders)?;
        self.sign_prepared(builders, prepared, |_| Ok(()))
    }

    /// Sign a prepared spend and validate it as an observation would, with a
    /// last `check` of the children it would create: what fails here is never
    /// sent. The children are discarded: the real ones are created when the
    /// spend settles.
    fn sign_prepared(
        &self,
        builders: &[SpendBuilder],
        prepared: PreparedBatch,
        check: impl FnOnce(Vec<InstanceHandle>) -> Result<(), ManagerError>,
    ) -> Result<PendingSpend, ManagerError> {
        let tx = signing::sign_prepared(builders, prepared, &self.signers)?;
        let inputs: Vec<_> = builders
            .iter()
            .map(|builder| InstanceHandle {
                instance: builder.instance.clone(),
            })
            .collect();
        let staged = self.stage_batch(&inputs.iter().collect::<Vec<_>>(), &[], &tx)?;
        check(staged.children())?;
        Ok(PendingSpend { tx, inputs })
    }

    /// Broadcast a signed spend through this manager's chain backend (and
    /// mine it, when auto-mining). Sending the same spend again is how it is
    /// re-broadcast.
    pub(crate) fn send(&self, pending: &PendingSpend) -> Result<(), ManagerError> {
        self.chain()?.broadcast(&pending.tx)?;
        self.mine_if_auto();
        Ok(())
    }

    /// With auto-mining on, bury what was just broadcast under the manager's
    /// confirmations.
    fn mine_if_auto(&self) {
        if self.auto_mine
            && let Some(chain) = &self.chain
        {
            // The transaction is out: a failure to mine is not a failure to
            // send it.
            let _ = chain.mine_blocks(self.confirmations);
        }
    }

    /// Wait (within `window`; `None` = forever) until one of the instances
    /// `pending` spends is spent by a transaction with the manager's
    /// confirmations, and record that transaction.
    fn settle(
        &mut self,
        pending: &PendingSpend,
        window: Option<std::time::Duration>,
    ) -> Result<Children, ManagerError> {
        // Any input, not just the first: a rival spending only some of them
        // is enough to rule our transaction out.
        let settled = self.wait_for_any_spending_tx(&pending.inputs, window)?;
        let txid = settled.compute_txid();
        if pending.is(&settled) {
            return self.observe_batch(&pending.inputs.iter().collect::<Vec<_>>(), &settled);
        }
        // Another transaction got there first. It is what happened, so it is
        // what gets recorded, for every input of ours that it spends — all
        // together, so that the links between them do not depend on order.
        let spent: Vec<&InstanceHandle> = pending
            .inputs
            .iter()
            .filter(|input| {
                let outpoint = input.outpoint();
                settled.input.iter().any(|i| i.previous_output == outpoint)
            })
            .collect();
        self.observe_inputs(&spent, &settled)?;
        Err(ManagerError::SpentByAnother {
            outpoint: spent
                .first()
                .expect("the settled transaction spends one of the inputs")
                .outpoint(),
            txid,
        })
    }
}

/// A signed spend that was broadcast and is not recorded yet.
///
/// Broadcasting is an attempt: until a transaction spending the same
/// instances is confirmed, a conflicting one can still win, and this one can
/// be evicted. [`settle`](Self::settle) waits for the confirmed outcome and
/// records it, whichever transaction it is.
#[derive(Debug, Clone)]
pub struct PendingSpend {
    tx: Transaction,
    inputs: Vec<InstanceHandle>,
}

impl PendingSpend {
    /// The signed transaction.
    pub fn transaction(&self) -> &Transaction {
        &self.tx
    }

    /// The transaction's id.
    pub fn txid(&self) -> bitcoin::Txid {
        self.tx.compute_txid()
    }

    /// Whether `tx` is this very transaction, witnesses included. The txid
    /// alone does not say: it does not cover the witness, so a transaction
    /// spending the same instances through another clause, or with other
    /// arguments, has the same txid whenever its inputs, outputs and
    /// sequences agree.
    pub fn is(&self, tx: &Transaction) -> bool {
        tx.compute_wtxid() == self.tx.compute_wtxid()
    }

    /// The instances this transaction spends, in the order of the builders
    /// it was made from.
    pub fn inputs(&self) -> &[InstanceHandle] {
        &self.inputs
    }

    /// Wait until the instances are spent by a transaction with the manager's
    /// [`confirmations`](ContractManager::confirmations), record that spend,
    /// and return the children. There is no time limit: confirmation takes
    /// as long as the chain takes (see
    /// [`settle_within`](Self::settle_within)).
    ///
    /// If a *different* transaction ends up spending any of the instances,
    /// ours can no longer confirm: that transaction is recorded instead (for
    /// each of these instances it spends) and the error is
    /// [`ManagerError::SpentByAnother`], naming the first of them. The
    /// handles then show what actually happened; an instance the other
    /// transaction left alone is still unspent. "Different" includes a
    /// transaction with our txid but another witness (see [`is`](Self::is)):
    /// it may have spent through another clause.
    pub fn settle(&self, manager: &mut ContractManager) -> Result<Children, ManagerError> {
        manager.settle(self, None)
    }

    /// [`settle`](Self::settle), giving up with
    /// [`ManagerError::SpendNotFound`] if nothing is confirmed within
    /// `window`. Nothing is recorded then, and settling can be tried again.
    pub fn settle_within(
        &self,
        manager: &mut ContractManager,
        window: std::time::Duration,
    ) -> Result<Children, ManagerError> {
        manager.settle(self, Some(window))
    }
}

#[cfg(test)]
#[path = "manager/observation_tests.rs"]
mod observation_tests;
#[cfg(test)]
#[path = "manager/tests.rs"]
mod tests;
