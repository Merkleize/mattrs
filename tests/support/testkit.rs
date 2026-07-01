//! Helpers for exercising contract spends locally, without a `bitcoind`.
//!
//! `SpendBuilder::build_tx` (and the batch `build_batch_tx`) perform no RPC, so a
//! spend can be built and inspected offline against a fake-funded instance.
#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use bitcoin::{hashes::Hash, Amount, OutPoint, Transaction, TxOut, Txid};
use bitcoincore_rpc::{Auth, Client};
use mattrs::contracts::{ContractInstance, ErasedContract, ErasedState};
use mattrs::manager::InstanceHandle;

/// An offline RPC client. It is never actually contacted — building (as opposed to
/// broadcasting) a spend performs no RPC.
pub fn offline_client() -> Client {
    Client::new("http://127.0.0.1:1", Auth::None).unwrap()
}

/// Fake a funded instance of `contract` (optionally carrying `expanded` logical
/// state) holding `amount` sats, at a distinct outpoint keyed by `seed`. The
/// funding output pays the contract's own address, derived from its committed state.
pub fn fund_fake(
    contract: Arc<dyn ErasedContract>,
    expanded: Option<Box<dyn ErasedState>>,
    amount: u64,
    seed: u8,
) -> InstanceHandle {
    let instance = Rc::new(RefCell::new(ContractInstance::new_with_expanded(
        contract, expanded,
    )));
    let script_pubkey = {
        let inst = instance.borrow();
        inst.contract
            .script_pubkey(inst.state_bytes.as_deref())
            .unwrap()
    };
    let funding_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            script_pubkey,
            value: Amount::from_sat(amount),
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
