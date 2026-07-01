//! game256 port tests (base case).
//!
//! Verifies the `Leaf` contract's taptree root and the `merkle_root`/`dup` script
//! fragments against the pymatt reference (`examples/game256`, `hub/fraud.py`).

mod support;

use std::str::FromStr;

use bitcoin::XOnlyPublicKey;

use support::game256::{Bisect1, Bisect2, BisectParams, Leaf, LeafParams};
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
    // Bisect_2(0,1) and Bisect_1(0,1) — the base range where both children are
    // leaves; roots match the pymatt reference (hub/fraud.py).
    let (alice_pk, bob_pk) = keys();
    let params = BisectParams { alice_pk, bob_pk };

    assert_eq!(
        hex::encode(Bisect2::new(params.clone()).contract.taptree.root_hash()),
        "051002010223fec1898647323c278a6f9aebdae955ba66b2c1989875204bbe60"
    );
    assert_eq!(
        hex::encode(Bisect1::new(params).contract.taptree.root_hash()),
        "646593ebe11ebd3b03663c56b502d0cc910678aafabac268bb33381b7dedbc52"
    );
}

#[test]
fn test_merkle_root_and_dup_script_bytes() {
    // Byte-exact against pymatt's script_helpers.merkle_root(3) / dup(1).
    assert_eq!(hex::encode(merkle_root(3).as_bytes()), "6b7ea86c7ea8");
    assert_eq!(hex::encode(dup(1).as_bytes()), "76");
}
