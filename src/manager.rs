//! Contract Manager
//!
//! Manages the lifecycle of contract instances from funding through spending,
//! with automatic output tracking and witness decoding.
//!
//! Spending goes through the fluent [`SpendBuilder`]: a clause is invoked with its
//! typed arguments (already encoded to a witness stack), signers are registered by
//! public key, and `exec`/`exec_one`/`exec_none` build, sign, broadcast and
//! materialize the resulting child instances.
//!
//! Covenants driven by *someone else* are followed with chain observation:
//! [`ContractManager::track_instance`] registers an externally funded instance,
//! and [`ContractManager::wait_for_spend`] (or the RPC-free
//! [`ContractManager::observe_spend`]) detects its spend, decodes the witness
//! back into the clause and its arguments, and materializes the child instances
//! — so both parties of a protocol hold the same view of the contract's state.
//! A spend found on the chain is recorded once it has the manager's
//! [`confirmations`](ContractManager::confirmations) (one by default) and is
//! never revisited: reorganizations deeper than that are not handled.
//!
//! The public facade composes RPC-free preparation/signing, shared constraint
//! validation, and staged lifecycle updates. Ordinary execution validates and
//! stages the signed transaction before broadcasting; only successful broadcast
//! commits those updates. Observation uses the same staging/commit path without
//! broadcasting. See `src/manager/README.md` for the internal component boundaries.

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
/// [`ContractManager::spend_batch`] also broadcasts and records the spend.
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
    /// an external broadcaster ([`spend_batch_with`](Self::spend_batch_with)).
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

    /// How many confirmations a spend found on the chain needs before this
    /// manager records it ([`wait_for_spend`](Self::wait_for_spend) and its
    /// variants, and a protocol [`Runner`](crate::protocol::Runner) following
    /// a counterparty). The default is 1: a spend counts once it is in a
    /// block.
    pub fn confirmations(&self) -> u32 {
        self.confirmations
    }

    /// Set the [`confirmations`](Self::confirmations) a spend found on the
    /// chain needs before it is recorded.
    ///
    /// A recorded spend is never revisited, so this is the manager's whole
    /// answer to chain reorganizations: wait for a depth at which you take a
    /// block as final. With 0, a spend is recorded as soon as it reaches the
    /// node's mempool, where it can still be replaced or never confirm; that
    /// is only suitable for tests and demos.
    ///
    /// Two things are not covered by this setting. A spend this manager
    /// broadcasts itself is recorded at once, and an explicit
    /// [`observe_spend`](Self::observe_spend) /
    /// [`observe_batch`](Self::observe_batch) records the transaction it is
    /// handed, whatever its confirmation status.
    ///
    /// Changing the depth while waiting for a spend is fine: the wait goes on
    /// at the new depth.
    pub fn set_confirmations(&mut self, confirmations: u32) -> &mut Self {
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

    /// Mine [`confirmations`](Self::confirmations) blocks (at least one)
    /// after every transaction this manager broadcasts through its chain
    /// backend, so the parties watching the chain see the spend without
    /// anyone else mining. For regtest and test chains only: the backend must
    /// support [`ChainView::mine_blocks`]. Off by default.
    ///
    /// A spend sent through [`spend_batch_with`](Self::spend_batch_with)'s
    /// own broadcaster is not followed by a block.
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

    /// Spend several instances in one transaction (build, sign, broadcast), and
    /// return handles to the child instances created — one per merged output index.
    ///
    /// Mirrors pymatt's multi-input `get_spend_tx`: within each input the
    /// deduct outputs must precede its preserve outputs, and a preserve output at
    /// a shared index accumulates each contributing input's remaining amount (so N
    /// vaults triggering to the same next contract merge into one output). CTV
    /// template clauses are single-input only and are rejected here.
    pub fn spend_batch(&mut self, builders: &[SpendBuilder]) -> Result<Children, ManagerError> {
        let prepared = transaction::prepare(builders)?;
        self.execute_prepared(builders, prepared, Self::send_to_node)
    }

    /// Broadcast through this manager's own chain backend.
    fn send_to_node(&self, tx: &Transaction) -> Result<(), ManagerError> {
        let chain = self.chain()?;
        chain.broadcast(tx)?;
        if self.auto_mine {
            // The transaction is out: a failure to mine must not be reported
            // as a failed spend, which would leave it unrecorded.
            let _ = chain.mine_blocks(self.confirmations.max(1));
        }
        Ok(())
    }

    /// Like [`spend_batch`](Self::spend_batch), but hands the signed
    /// transaction to `broadcast` instead of this manager's own chain backend
    /// — for callers that reach the chain another way (e.g. a relay).
    ///
    /// The order is the same as for `spend_batch`: the spend is fully
    /// validated and staged *before* `broadcast` runs, and recorded only if it
    /// returns `Ok`. A transaction this manager could not record is therefore
    /// never sent, and a failed broadcast leaves the manager untouched.
    pub fn spend_batch_with<E: From<ManagerError>>(
        &mut self,
        builders: &[SpendBuilder],
        broadcast: impl FnOnce(&Transaction) -> Result<(), E>,
    ) -> Result<Children, E> {
        let prepared = transaction::prepare(builders)?;
        self.execute_prepared(builders, prepared, |_, tx| broadcast(tx))
    }

    fn execute_prepared<E: From<ManagerError>>(
        &mut self,
        builders: &[SpendBuilder],
        prepared: PreparedBatch,
        broadcast: impl FnOnce(&Self, &Transaction) -> Result<(), E>,
    ) -> Result<Children, E> {
        let ((), children) =
            self.execute_prepared_checked(builders, prepared, |_| Ok(()), broadcast)?;
        Ok(children)
    }

    /// [`execute_prepared`](Self::execute_prepared), with a last `check` of
    /// the staged children before the transaction is broadcast: what it
    /// rejects is never sent, and what it returns is handed back with the
    /// committed children. The staged handles are the ones later committed.
    fn execute_prepared_checked<T, E: From<ManagerError>>(
        &mut self,
        builders: &[SpendBuilder],
        prepared: PreparedBatch,
        check: impl FnOnce(Vec<InstanceHandle>) -> Result<T, ManagerError>,
        broadcast: impl FnOnce(&Self, &Transaction) -> Result<(), E>,
    ) -> Result<(T, Children), E> {
        let tx = signing::sign_prepared(builders, prepared, &self.signers)?;
        let handles: Vec<_> = builders
            .iter()
            .map(|builder| InstanceHandle {
                instance: builder.instance.clone(),
            })
            .collect();
        let staged = self.stage_batch(&handles.iter().collect::<Vec<_>>(), &[], &tx)?;

        let checked = check(staged.children())?;

        broadcast(self, &tx)?;
        Ok((checked, staged.commit(self)))
    }
}

#[cfg(test)]
#[path = "manager/observation_tests.rs"]
mod observation_tests;
#[cfg(test)]
#[path = "manager/tests.rs"]
mod tests;
