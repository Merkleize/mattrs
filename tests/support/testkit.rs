//! Shared test fixtures: keys, RPC clients, and fake-funded instances.
//!
//! `SpendBuilder::build_tx` (and the batch `build_batch_tx`) perform no RPC, so a
//! spend can be built and inspected offline against a fake-funded instance
//! (`offline_client` + `fund_fake`). The `#[ignore]`d end-to-end tests use
//! `regtest_client` against a real regtest `bitcoind` instead.

use std::cell::RefCell;
use std::path::PathBuf;
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

/// An RPC client for the local regtest node, used by the `#[ignore]`d e2e tests.
/// The `wallet_name` wallet must be already loaded and funded.
///
/// # Environment variables
///
/// - `BITCOIN_RPC_URL`: the node's URL (default `http://localhost:18443`).
/// - `BITCOIN_RPC_USER` / `BITCOIN_RPC_PASSWORD`: RPC credentials. When unset,
///   falls back to cookie authentication with `BITCOIN_RPC_COOKIE` (default
///   `~/.bitcoin/regtest/.cookie`) — a stock regtest `bitcoind` works with no
///   configuration at all.
pub fn regtest_client(wallet_name: &str) -> Client {
    let rpc_url =
        std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_url_full = format!("{}/wallet/{}", rpc_url, wallet_name);

    let auth = match (
        std::env::var("BITCOIN_RPC_USER"),
        std::env::var("BITCOIN_RPC_PASSWORD"),
    ) {
        (Ok(user), Ok(password)) => Auth::UserPass(user, password),
        _ => {
            let cookie = std::env::var("BITCOIN_RPC_COOKIE")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    let home = std::env::var("HOME").expect("HOME not set");
                    PathBuf::from(home).join(".bitcoin/regtest/.cookie")
                });
            Auth::CookieFile(cookie)
        }
    };

    Client::new(&rpc_url_full, auth).expect("Failed to create RPC client")
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
