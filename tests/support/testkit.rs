//! Shared test fixtures: keys, RPC clients, and fake-funded instances.
//!
//! `SpendBuilder::build_tx` (and the batch `build_batch_tx`) perform no RPC, so a
//! spend can be built and inspected offline against a fake-funded instance
//! (`offline_client` + `fund_fake`). The `#[ignore]`d end-to-end tests use
//! `regtest_client` against a real regtest `bitcoind` instead.

use std::str::FromStr;
use std::sync::Arc;

use bitcoin::bip32::Xpriv;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, XOnlyPublicKey};
use bitcoincore_rpc::{Client, RpcApi};
use mattrs::contracts::{ErasedContract, ErasedState};
use mattrs::manager::{ContractManager, InstanceHandle};
use mattrs::report::Report;

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
    mattrs::testutil::offline_client()
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
/// state) holding `amount` sats, at a distinct outpoint keyed by `seed`.
///
/// Thin wrapper over [`mattrs::testutil::fund_fake`] taking sats directly.
pub fn fund_fake(
    contract: Arc<dyn ErasedContract>,
    expanded: Option<Box<dyn ErasedState>>,
    amount: u64,
    seed: u8,
) -> InstanceHandle {
    mattrs::testutil::fund_fake(contract, expanded, Amount::from_sat(amount), seed)
}

/// Fetch the broadcast transaction that spent `handle` from the node and append
/// it to `report` as a collapsible markdown block (regtest e2e tests only).
///
/// Polls briefly: right after a concurrently-running test mines the tx out of
/// the mempool, the node's txindex can lag a moment behind.
pub fn report_spend(
    report: &mut Report,
    section: &str,
    title: &str,
    manager: &ContractManager,
    handle: &InstanceHandle,
) {
    let txid = handle.spent_in_tx().expect("instance not spent");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let tx = loop {
        match manager.rpc().get_raw_transaction(&txid, None) {
            Ok(tx) => break tx,
            Err(e) if std::time::Instant::now() >= deadline => {
                panic!("spending tx {txid} not found on node: {e}")
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    };
    report.write_tx(section, title, &tx);
}
