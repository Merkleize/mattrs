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
use bitcoincore_rpc::Client;
use mattrs::contracts::{ErasedContract, ErasedState};
use mattrs::manager::InstanceHandle;
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

/// Append the transaction that spent `handle` to `report` as a collapsible
/// markdown block (the manager records the full spending transaction).
pub fn report_spend(report: &mut Report, section: &str, title: &str, handle: &InstanceHandle) {
    let tx = handle.spending_tx().expect("instance not spent");
    report.write_tx(section, title, &tx);
}

/// Follow a single-token spend chain from `entry` to its last instance (the
/// first one with no materialized children).
pub fn walk_tip(entry: &InstanceHandle) -> InstanceHandle {
    let mut current = entry.clone();
    loop {
        let mut outputs = current.outputs();
        match outputs.len() {
            0 => return current,
            1 => current = outputs.remove(0),
            n => panic!("walk_tip expects a single-token chain, found {n} children"),
        }
    }
}
