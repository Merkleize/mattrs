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

use crate::contracts::{ContractInstance, ErasedContract, ErasedState};
use crate::manager::{Children, ContractManager, InstanceHandle, ManagerError, SpendBuilder};

/// An RPC client that is never actually contacted: building (as opposed to
/// broadcasting) a spend performs no RPC, so this lets a
/// [`ContractManager`] run fully offline.
pub fn offline_client() -> Client {
    Client::new("http://127.0.0.1:1", Auth::None).expect("offline client is infallible")
}

/// Fake a funded instance of `contract` (optionally carrying `expanded` logical
/// state) holding `amount`, at a distinct outpoint keyed by `seed`.
///
/// The in-memory "funding transaction" pays the contract's own address (derived
/// from its committed state), so a spend built against the returned handle is
/// valid to inspect — it simply is never broadcast. `seed` distinguishes the
/// outpoints when a caller fake-funds several instances.
pub fn fund_fake(
    contract: Arc<dyn ErasedContract>,
    expanded: Option<Box<dyn ErasedState>>,
    amount: Amount,
    seed: u8,
) -> InstanceHandle {
    let instance = Rc::new(RefCell::new(
        ContractInstance::new(contract, expanded).expect("state matches contract"),
    ));
    let script_pubkey = instance
        .borrow()
        .script_pubkey()
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
    instance.borrow_mut().mark_funded(outpoint, funding_tx);
    InstanceHandle::new(instance)
}

/// Build the batch transaction for `builders` and decode it against each of
/// `parents` with [`ContractManager::observe_spend`], materializing the
/// (deduplicated) children — the offline counterpart of
/// [`ContractManager::spend_batch`]: no broadcast, no RPC. Children merged
/// across inputs (a shared `PreserveOutput` index) are returned once, and the
/// order of `parents` does not matter: a joining input (`NextOutputs::Join`)
/// observed before its defining input is re-observed after every other parent,
/// so its link to the shared child is never missed.
pub fn apply_batch(
    manager: &mut ContractManager,
    parents: &[&InstanceHandle],
    builders: &[SpendBuilder],
) -> Result<(Transaction, Children), ManagerError> {
    let tx = manager.build_batch_tx(builders)?;
    let mut children: Vec<InstanceHandle> = Vec::new();
    // Two passes: the second links any join observed before its defining input.
    for parent in parents.iter().chain(parents.iter()) {
        for child in manager.observe_spend(parent, &tx)? {
            if !children.contains(&child) {
                children.push(child);
            }
        }
    }
    Ok((tx, Children::new(children)))
}
