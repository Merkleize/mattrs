//! game256 port tests (base case).
//!
//! Verifies the `Leaf` contract's taptree root and the `merkle_root`/`dup` script
//! fragments against the pymatt reference (`examples/game256`, `hub/fraud.py`).

mod support;

use std::str::FromStr;

use bitcoin::XOnlyPublicKey;

use support::game256::{
    Bisect1, Bisect2, BisectParams, G256Params, G256S0, G256S1, G256S2, Leaf, LeafParams,
};
use mattrs::script_helpers::{dup, merkle_root};

fn keys() -> (XOnlyPublicKey, XOnlyPublicKey) {
    (
        XOnlyPublicKey::from_str(
            "67c20aa213479676398b79d7cbc7a6b888ccb5944f6d5bb6b1c33b1ab9bdeb4b",
        )
        .unwrap(),
        XOnlyPublicKey::from_str(
            "5f6929a36535c7e95cf99e56a49a745cc548d2147427a62f5b8d015cbd70b122",
        )
        .unwrap(),
    )
}

#[test]
fn test_leaf_taptree_matches_reference() {
    let (alice_pk, bob_pk) = keys();
    let leaf = Leaf::new(LeafParams { alice_pk, bob_pk });
    assert_eq!(
        hex::encode(leaf.contract.taptree().root_hash()),
        "82dda0e32408a73bf19265805bcba563421e853fa22870bfd5887a402cf34916"
    );
}

#[test]
fn test_bisect_taptrees_match_reference() {
    // The recursion at every level: base range (children are leaves), size-4
    // (children are sub-Bisect_1s), and the full 8-step game bisect. All roots
    // match the pymatt reference (hub/fraud.py).
    let (alice_pk, bob_pk) = keys();
    let bp = |i, j| BisectParams {
        alice_pk,
        bob_pk,
        i,
        j,
    };
    let root = |b: &[u8; 32]| hex::encode(b);

    // base range: both children are Leaves
    assert_eq!(
        root(&Bisect2::new(bp(0, 1)).contract.taptree().root_hash()),
        "051002010223fec1898647323c278a6f9aebdae955ba66b2c1989875204bbe60"
    );
    assert_eq!(
        root(&Bisect1::new(bp(0, 1)).contract.taptree().root_hash()),
        "646593ebe11ebd3b03663c56b502d0cc910678aafabac268bb33381b7dedbc52"
    );
    // size 4: children are sub-Bisect_1s
    assert_eq!(
        root(&Bisect2::new(bp(0, 3)).contract.taptree().root_hash()),
        "6eebc0a155c3b98c6b812f44e75242a39187c2e4a8f0f145ee4de83347e7b942"
    );
    assert_eq!(
        root(&Bisect1::new(bp(0, 3)).contract.taptree().root_hash()),
        "0b82edb494d12798f767348922edeed15ba45f13771bee50133d23561a1af263"
    );
    // the full 8-step game bisect nests the entire recursion
    assert_eq!(
        root(&Bisect1::new(bp(0, 7)).contract.taptree().root_hash()),
        "3f9b156e3ccf21e59c79c6de2b4cb8f018a1f11e9a6c133af4906e7e6b9cfc2f"
    );
}

#[test]
fn test_g256_stage_taptrees_match_reference() {
    // The top-level game stages: G256S0 (Bob picks x) -> G256S1 (Alice reveals y)
    // -> G256S2 (withdraw, or start_challenge which hands off to Bisect_1(0,7)).
    // Roots match the pymatt reference (examples/game256).
    let (alice_pk, bob_pk) = keys();
    let p = G256Params { alice_pk, bob_pk };

    assert_eq!(
        hex::encode(G256S0::new(p.clone()).contract.taptree().root_hash()),
        "ddba91cb57ac4e1b4c79c8dc48c5b62e39ecd4687b6256ec1eb5f77fad6f3429"
    );
    assert_eq!(
        hex::encode(G256S1::new(p.clone()).contract.taptree().root_hash()),
        "3186a6c6434dd328e3664f72b93186981087d94b13359dfd8ecc5384d8a3cc84"
    );
    assert_eq!(
        hex::encode(G256S2::new(p).contract.taptree().root_hash()),
        "d04adc2924609a0c189c095d320829e22b9879017f81bd84f245a23d3e9c18be"
    );
}

#[test]
fn test_merkle_root_and_dup_script_bytes() {
    // Byte-exact against pymatt's script_helpers.merkle_root(3) / dup(1).
    assert_eq!(hex::encode(merkle_root(3).as_bytes()), "6b7ea86c7ea8");
    assert_eq!(hex::encode(dup(1).as_bytes()), "76");
}

// ----------------------------------------------------------------------------
// Spend flow (build-level, no node): each state transition drives its child.
// ----------------------------------------------------------------------------

use bitcoin::bip32::Xpriv;
use mattrs::contracts::{ContractState, ErasedContract};
use mattrs::manager::ContractManager;
use mattrs::signer::HotSigner;
use std::sync::Arc;
use support::game256::{
    Bisect1Handle, Bisect1State, Bisect2Handle, Bisect2State, G256S0Handle, G256S1Handle,
    G256S1State, G256S2Handle, G256S2State, LeafState,
};
use support::testkit::{fund_fake, offline_client};

fn alice_xpriv() -> Xpriv {
    Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )
    .unwrap()
}
fn bob_xpriv() -> Xpriv {
    Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )
    .unwrap()
}

/// The committed address of `contract` with committed `state`.
fn addr<S: ContractState + 'static>(contract: Arc<dyn ErasedContract>, state: &S) -> bitcoin::ScriptBuf {
    contract
        .script_pubkey(Some(ContractState::encode(state).as_slice()))
        .unwrap()
}

#[test]
fn test_game256_state_transitions() {
    let (alice_pk, bob_pk) = keys();
    let p = G256Params { alice_pk, bob_pk };
    let bp = |i, j| BisectParams {
        alice_pk,
        bob_pk,
        i,
        j,
    };
    let client = offline_client();
    let manager = ContractManager::new(&client);

    // 1. G256S0.choose(x) -> G256S1 committed to x.
    let s0 = G256S0Handle(fund_fake(G256S0::new(p.clone()).as_erased(), None, 100_000, 1));
    let tx = s0.choose(5).sign(HotSigner::new(bob_xpriv())).build_tx(&manager).unwrap();
    assert_eq!(
        tx.output[0].script_pubkey,
        addr(G256S1::new(p.clone()).as_erased(), &G256S1State { x: 5 })
    );

    // 2. G256S2.start_challenge -> Bisect_1(0,7) with sha256-committed endpoints.
    let s2 = G256S2Handle(fund_fake(
        G256S2::new(p.clone()).as_erased(),
        Some(Box::new(G256S2State { t_a: [7; 32], y: 10, x: 5 })),
        100_000,
        2,
    ));
    let tx = s2
        .start_challenge([7; 32], 10, 5, 11, [8; 32])
        .sign(HotSigner::new(bob_xpriv()))
        .build_tx(&manager)
        .unwrap();
    let commit = |v: i64| {
        use bitcoin::hashes::Hash;
        bitcoin::hashes::sha256::Hash::hash(&mattrs::script_utils::bn2vch(v)).to_byte_array()
    };
    assert_eq!(
        tx.output[0].script_pubkey,
        addr(
            Bisect1::new(bp(0, 7)).as_erased(),
            &Bisect1State {
                h_start: commit(5),
                h_end_a: commit(10),
                h_end_b: commit(11),
                trace_a: [7; 32],
                trace_b: [8; 32],
            }
        )
    );

    // 3. Bisect_2(0,7).bob_reveal_left -> a *sub-Bisect_1(0,3)* (children not leaves).
    let b2 = Bisect2Handle(fund_fake(
        Bisect2::new(bp(0, 7)).as_erased(),
        Some(Box::new(Bisect2State {
            h_start: [1; 32],
            h_end_a: [2; 32],
            h_end_b: [3; 32],
            trace_a: [4; 32],
            trace_b: [5; 32],
            h_mid_a: [6; 32],
            trace_left_a: [7; 32],
            trace_right_a: [8; 32],
        })),
        100_000,
        3,
    ));
    let tx = b2
        .bob_reveal_left(
            [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], [7; 32], [8; 32], [9; 32],
            [10; 32], [11; 32],
        )
        .sign(HotSigner::new(bob_xpriv()))
        .build_tx(&manager)
        .unwrap();
    assert_eq!(
        tx.output[0].script_pubkey,
        addr(
            Bisect1::new(bp(0, 3)).as_erased(),
            &Bisect1State {
                h_start: [1; 32],   // h_start
                h_end_a: [6; 32],   // h_mid_a
                h_end_b: [9; 32],   // h_mid_b
                trace_a: [7; 32],   // trace_left_a
                trace_b: [10; 32],  // trace_left_b
            }
        )
    );

    // 4. Bisect_2(0,1).bob_reveal_left -> a *Leaf* (children ARE leaves).
    let b2_leaf = Bisect2Handle(fund_fake(
        Bisect2::new(bp(0, 1)).as_erased(),
        Some(Box::new(Bisect2State {
            h_start: [1; 32],
            h_end_a: [2; 32],
            h_end_b: [3; 32],
            trace_a: [4; 32],
            trace_b: [5; 32],
            h_mid_a: [6; 32],
            trace_left_a: [7; 32],
            trace_right_a: [8; 32],
        })),
        100_000,
        4,
    ));
    let tx = b2_leaf
        .bob_reveal_left(
            [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], [7; 32], [8; 32], [9; 32],
            [10; 32], [11; 32],
        )
        .sign(HotSigner::new(bob_xpriv()))
        .build_tx(&manager)
        .unwrap();
    assert_eq!(
        tx.output[0].script_pubkey,
        addr(
            Leaf::new(LeafParams { alice_pk, bob_pk }).as_erased(),
            &LeafState { h_start: [1; 32], h_end_alice: [6; 32], h_end_bob: [9; 32] }
        )
    );

    // 5. G256S1.reveal -> G256S2 (state passthrough of t_a/y/x).
    let s1 = G256S1Handle(fund_fake(
        G256S1::new(p.clone()).as_erased(),
        Some(Box::new(G256S1State { x: 5 })),
        100_000,
        5,
    ));
    let tx = s1
        .reveal([7; 32], 10, 5)
        .sign(HotSigner::new(alice_xpriv()))
        .build_tx(&manager)
        .unwrap();
    assert_eq!(
        tx.output[0].script_pubkey,
        addr(
            G256S2::new(p.clone()).as_erased(),
            &G256S2State { t_a: [7; 32], y: 10, x: 5 }
        )
    );

    // 6. Bisect_1.alice_reveal -> Bisect_2 (same range), state passthrough.
    let b1 = Bisect1Handle(fund_fake(
        Bisect1::new(bp(0, 7)).as_erased(),
        Some(Box::new(Bisect1State {
            h_start: [1; 32],
            h_end_a: [2; 32],
            h_end_b: [3; 32],
            trace_a: [4; 32],
            trace_b: [5; 32],
        })),
        100_000,
        6,
    ));
    let tx = b1
        .alice_reveal(
            [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], [7; 32], [8; 32],
        )
        .sign(HotSigner::new(alice_xpriv()))
        .build_tx(&manager)
        .unwrap();
    assert_eq!(
        tx.output[0].script_pubkey,
        addr(
            Bisect2::new(bp(0, 7)).as_erased(),
            &Bisect2State {
                h_start: [1; 32],
                h_end_a: [2; 32],
                h_end_b: [3; 32],
                trace_a: [4; 32],
                trace_b: [5; 32],
                h_mid_a: [6; 32],
                trace_left_a: [7; 32],
                trace_right_a: [8; 32],
            }
        )
    );
}
