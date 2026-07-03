//! Shared test fixtures: keys, RPC clients, and fake-funded instances.
//!
//! `SpendBuilder::build_tx` (and the batch `build_batch_tx`) perform no RPC, so a
//! spend can be built and inspected offline against a fake-funded instance
//! (`offline_client` + `fund_fake`). The `#[ignore]`d end-to-end tests use
//! `regtest_client` against a real regtest `bitcoind` instead.

use std::cell::RefCell;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::bip32::Xpriv;
use bitcoin::key::Secp256k1;
use bitcoin::{hashes::Hash, Amount, OutPoint, Transaction, TxOut, Txid, XOnlyPublicKey};
use bitcoincore_rpc::{Auth, Client};
use mattrs::contracts::{ContractInstance, ErasedContract, ErasedState};
use mattrs::manager::InstanceHandle;

/// Alice's test key. Its x-only pubkey (`67c20aa2…`) is the "alice" key of the
/// pymatt reference fixtures (and the vault's unvault key).
pub fn alice_xpriv() -> Xpriv {
    Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )
    .unwrap()
}

/// Bob's test key. Its x-only pubkey (`5f6929a3…`) is the "bob" key of the
/// pymatt reference fixtures (and the vault's recover key).
pub fn bob_xpriv() -> Xpriv {
    Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )
    .unwrap()
}

fn xonly_of(xpriv: &Xpriv) -> XOnlyPublicKey {
    xpriv.to_priv().public_key(&Secp256k1::new()).into()
}

/// The x-only pubkey of [`alice_xpriv`] (`67c20aa2…`).
pub fn alice_pk() -> XOnlyPublicKey {
    xonly_of(&alice_xpriv())
}

/// The x-only pubkey of [`bob_xpriv`] (`5f6929a3…`).
pub fn bob_pk() -> XOnlyPublicKey {
    xonly_of(&bob_xpriv())
}

/// An offline RPC client. It is never actually contacted — building (as opposed to
/// broadcasting) a spend performs no RPC.
pub fn offline_client() -> Client {
    Client::new("http://127.0.0.1:1", Auth::None).unwrap()
}

/// An RPC client for the local regtest node, used by the `#[ignore]`d e2e
/// tests (see [`mattrs::manager::regtest_rpc_client`] for the auth rules).
pub fn regtest_client(wallet_name: &str) -> Client {
    mattrs::manager::regtest_rpc_client(wallet_name)
}

/// Convert an untyped handle into the typed handle `T`, panicking on a
/// contract-type mismatch (test fixtures know which contract they funded).
pub fn try_handle<T: TryFrom<InstanceHandle>>(handle: InstanceHandle) -> T
where
    T::Error: std::fmt::Debug,
{
    handle.try_into().expect("fixture contract type mismatch")
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
    let instance = Rc::new(RefCell::new(ContractInstance::new(
        contract, expanded,
    )));
    let script_pubkey = {
        let inst = instance.borrow();
        inst.contract()
            .script_pubkey(inst.committed_state_bytes().as_deref())
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
