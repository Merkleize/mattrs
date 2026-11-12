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

use crate::contracts::ContractInstance;
use bitcoin::Transaction;
use bitcoincore_rpc::{Client, RpcApi};
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

pub use builder::SpendBuilder;
pub use chain::regtest_rpc_client;
pub(crate) use chain::{
    BlockCache, POLL_INTERVAL, find_spending_tx_once, is_tx_not_found, spend_scan_start,
    tx_confirmation_height,
};
pub use error::{ManagerError, WrongContractType};
pub use handles::{Children, InstanceHandle};
use transaction::PreparedBatch;
pub use wallet::{BatchObservation, ExternalInput, SignedWalletSpend, WalletSpend};

/// Manages contract instances and their lifecycle.
pub struct ContractManager {
    /// RPC client for blockchain interaction.
    rpc: Client,

    /// The network the node runs on (used to derive contract addresses).
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
    /// Create a new contract manager owning the RPC client (use
    /// [`rpc`](Self::rpc) for direct access to it) and talking to a node on
    /// `network` (used to derive contract addresses).
    pub fn new(rpc: Client, network: bitcoin::Network) -> Self {
        Self {
            rpc,
            network,
            instances: Vec::new(),
            #[cfg(feature = "inspector")]
            inspector_state: None,
            #[cfg(feature = "inspector")]
            inspector_notify: None,
        }
    }

    /// The RPC client, for callers that need direct access (e.g. mining or funding).
    pub fn rpc(&self) -> &Client {
        &self.rpc
    }
    /// Build (without broadcasting) a single transaction that spends several
    /// instances at once, merging their clause outputs by index. Useful for
    /// inspection/tests; [`spend_batch`](Self::spend_batch) also broadcasts.
    pub fn build_batch_tx(&self, builders: &[SpendBuilder]) -> Result<Transaction, ManagerError> {
        signing::sign_prepared(builders, transaction::prepare(builders)?)
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
        self.execute_prepared(builders, prepared)
    }

    fn execute_prepared(
        &mut self,
        builders: &[SpendBuilder],
        prepared: PreparedBatch,
    ) -> Result<Children, ManagerError> {
        let tx = signing::sign_prepared(builders, prepared)?;
        let handles: Vec<_> = builders
            .iter()
            .map(|builder| InstanceHandle {
                instance: builder.instance.clone(),
            })
            .collect();
        let staged = self.stage_batch(&handles.iter().collect::<Vec<_>>(), &[], &tx)?;

        self.rpc.send_raw_transaction(&tx)?;
        Ok(staged.commit(self))
    }
}

#[cfg(test)]
#[path = "manager/observation_tests.rs"]
mod observation_tests;
#[cfg(test)]
#[path = "manager/tests.rs"]
mod tests;
