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
use support::script_helpers::{dup, merkle_root};

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
        hex::encode(leaf.contract.taptree.root_hash()),
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
        root(&Bisect2::new(bp(0, 1)).contract.taptree.root_hash()),
        "051002010223fec1898647323c278a6f9aebdae955ba66b2c1989875204bbe60"
    );
    assert_eq!(
        root(&Bisect1::new(bp(0, 1)).contract.taptree.root_hash()),
        "646593ebe11ebd3b03663c56b502d0cc910678aafabac268bb33381b7dedbc52"
    );
    // size 4: children are sub-Bisect_1s
    assert_eq!(
        root(&Bisect2::new(bp(0, 3)).contract.taptree.root_hash()),
        "6eebc0a155c3b98c6b812f44e75242a39187c2e4a8f0f145ee4de83347e7b942"
    );
    assert_eq!(
        root(&Bisect1::new(bp(0, 3)).contract.taptree.root_hash()),
        "0b82edb494d12798f767348922edeed15ba45f13771bee50133d23561a1af263"
    );
    // the full 8-step game bisect nests the entire recursion
    assert_eq!(
        root(&Bisect1::new(bp(0, 7)).contract.taptree.root_hash()),
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
        hex::encode(G256S0::new(p.clone()).contract.taptree.root_hash()),
        "ddba91cb57ac4e1b4c79c8dc48c5b62e39ecd4687b6256ec1eb5f77fad6f3429"
    );
    assert_eq!(
        hex::encode(G256S1::new(p.clone()).contract.taptree.root_hash()),
        "3186a6c6434dd328e3664f72b93186981087d94b13359dfd8ecc5384d8a3cc84"
    );
    assert_eq!(
        hex::encode(G256S2::new(p).contract.taptree.root_hash()),
        "d04adc2924609a0c189c095d320829e22b9879017f81bd84f245a23d3e9c18be"
    );
}

#[test]
fn test_merkle_root_and_dup_script_bytes() {
    // Byte-exact against pymatt's script_helpers.merkle_root(3) / dup(1).
    assert_eq!(hex::encode(merkle_root(3).as_bytes()), "6b7ea86c7ea8");
    assert_eq!(hex::encode(dup(1).as_bytes()), "76");
}
