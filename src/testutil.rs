//! Helpers for building spends offline, without a Bitcoin node — used by the
//! runnable examples and the `tests/support` fixtures.
//!
//! [`SpendBuilder::build_tx`](crate::manager::SpendBuilder::build_tx) (and the
//! batch variant) perform no RPC, so a spend can be built and inspected against a
//! *fake-funded* instance: [`fund_fake`] materializes an instance at a made-up
//! outpoint paying the contract's own address, and [`offline_client`] supplies a
//! [`ContractManager`] client that is never
//! actually contacted. Drive real funding/spending against a live node with
//! [`ContractManager`] instead.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use bitcoin::{Amount, OutPoint, Transaction, TxOut};
use bitcoincore_rpc::{Auth, Client};

use crate::contracts::{ContractInstance, ContractState, ErasedContract};
use crate::manager::{Children, ContractManager, InstanceHandle, ManagerError, SpendBuilder};

/// An RPC client that is never actually contacted: building (as opposed to
/// broadcasting) a spend performs no RPC, so this lets a
/// [`ContractManager`] run fully offline.
pub fn offline_client() -> Client {
    Client::new("http://127.0.0.1:1", Auth::None).expect("offline client is infallible")
}

/// Fake a funded instance of `contract` carrying `state` (`()` for a stateless
/// contract) and holding `amount`, at a distinct outpoint keyed by `seed`.
///
/// The in-memory "funding transaction" pays the contract's own address (derived
/// from its committed state), so a spend built against the returned handle is
/// valid to inspect — it simply is never broadcast. `seed` distinguishes the
/// outpoints when a caller fake-funds several instances.
pub fn fund_fake(
    contract: Arc<dyn ErasedContract>,
    state: impl ContractState + 'static,
    amount: Amount,
    seed: u8,
) -> InstanceHandle {
    let script_pubkey = contract
        .script_pubkey(&state.commitment())
        .expect("contract script_pubkey");
    let funding_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(seed.into()),
        input: vec![],
        output: vec![TxOut {
            script_pubkey,
            value: amount,
        }],
    };
    let outpoint = OutPoint {
        txid: funding_tx.compute_txid(),
        vout: 0,
    };
    let instance =
        ContractInstance::funded(contract, Box::new(state), outpoint, Arc::new(funding_tx))
            .expect("state matches contract");
    InstanceHandle::new(Rc::new(RefCell::new(instance)))
}

/// Build the batch transaction for `builders` and decode it against each of
/// `parents` with [`ContractManager::observe_batch`], materializing the
/// (deduplicated) children — the offline counterpart of
/// [`ContractManager::spend_batch`]: no broadcast, no RPC. Children merged
/// across inputs (a shared preserve index) are returned once, and the
/// order of `parents` does not matter. Every input must have a parent context;
/// constraints are checked together before any parent is changed, and joins
/// are linked in the same call.
pub fn apply_batch(
    manager: &mut ContractManager,
    parents: &[&InstanceHandle],
    builders: &[SpendBuilder],
) -> Result<(Transaction, Children), ManagerError> {
    let tx = crate::manager::build_batch_tx(builders)?;
    let children = manager.observe_batch(parents, &tx)?;
    Ok((tx, children))
}
