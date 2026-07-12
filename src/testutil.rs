//! Helpers for building spends offline, without a Bitcoin node — used by the
//! runnable examples and the `tests/support` fixtures.
//!
//! [`SpendBuilder::build_tx`](crate::manager::SpendBuilder::build_tx) (and the
//! batch variant) perform no RPC, so a spend can be built and inspected against a
//! *fake-funded* instance: [`fund_fake`] materializes an instance at a made-up
//! outpoint paying the contract's own address, and [`offline_client`] supplies a
//! [`ContractManager`](crate::manager::ContractManager) client that is never
//! actually contacted. Drive real funding/spending against a live node with
//! [`ContractManager`](crate::manager::ContractManager) instead.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};
use bitcoincore_rpc::{Auth, Client};

use crate::contracts::{ContractInstance, ErasedContract, ErasedState};
use crate::manager::{Children, ContractManager, InstanceHandle, ManagerError, SpendBuilder};

/// An RPC client that is never actually contacted: building (as opposed to
/// broadcasting) a spend performs no RPC, so this lets a
/// [`ContractManager`](crate::manager::ContractManager) run fully offline.
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
    let instance = Rc::new(RefCell::new(ContractInstance::new(contract, expanded)));
    let script_pubkey = instance
        .borrow()
        .script_pubkey()
        .expect("contract script_pubkey");
    let funding_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            script_pubkey,
            value: amount,
        }],
    };
    instance.borrow_mut().mark_funded(
        OutPoint {
            txid: Txid::from_byte_array([seed; 32]),
            vout: 0,
        },
        funding_tx,
    );
    InstanceHandle::new(instance)
}

/// Build the batch transaction for `builders` and decode it against each of
/// `parents` with [`ContractManager::observe_spend`], materializing the
/// (deduplicated) children — the offline counterpart of
/// [`ContractManager::spend_batch`]: no broadcast, no RPC. Children merged
/// across inputs (a shared `PreserveOutput` index) are returned once.
pub fn apply_batch(
    manager: &mut ContractManager,
    parents: &[&InstanceHandle],
    builders: &[SpendBuilder],
) -> Result<(Transaction, Children), ManagerError> {
    let tx = manager.build_batch_tx(builders)?;
    let mut children: Vec<InstanceHandle> = Vec::new();
    for parent in parents {
        for child in manager.observe_spend(parent, &tx)? {
            if !children.contains(&child) {
                children.push(child);
            }
        }
    }
    Ok((tx, Children::new(children)))
}
