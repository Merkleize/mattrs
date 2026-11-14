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
/// index. It needs no manager or node: everything comes from the builders.
/// [`ContractManager::spend_batch`] also broadcasts and records the spend.
pub fn build_batch_tx(builders: &[SpendBuilder]) -> Result<Transaction, ManagerError> {
    signing::sign_prepared(builders, transaction::prepare(builders)?)
}

/// Manages contract instances and their lifecycle.
pub struct ContractManager {
    /// The chain backend; `None` for an offline manager.
    chain: Option<Rc<dyn ChainView>>,

    /// The network the contracts live on.
    network: bitcoin::Network,

    /// All instances managed by this manager.
    instances: Vec<Rc<RefCell<ContractInstance>>>,

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
            #[cfg(feature = "inspector")]
            inspector_state: None,
            #[cfg(feature = "inspector")]
            inspector_notify: None,
        }
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
        Ok(self.chain()?.broadcast(tx)?)
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
        let tx = signing::sign_prepared(builders, prepared)?;
        let handles: Vec<_> = builders
            .iter()
            .map(|builder| InstanceHandle {
                instance: builder.instance.clone(),
            })
            .collect();
        let staged = self.stage_batch(&handles.iter().collect::<Vec<_>>(), &[], &tx)?;

        broadcast(self, &tx)?;
        Ok(staged.commit(self))
    }
}

#[cfg(test)]
#[path = "manager/observation_tests.rs"]
mod observation_tests;
#[cfg(test)]
#[path = "manager/tests.rs"]
mod tests;
