//! Rock-Paper-Scissors port tests.
//!
//! The taptree-root assertions are the byte-compatibility proof: they match the
//! roots computed by the pymatt reference (`examples/rps`) for the same fixed keys
//! and commitment, so the ported tapscripts (and their embedded CTV hashes) are
//! byte-identical.

mod support;

use std::str::FromStr;

use bitcoin::XOnlyPublicKey;

use support::rps::{move_commitment, RpsGameS0, RpsGameS1, RpsParams, DEFAULT_STAKE};

fn reference_params() -> RpsParams {
    let alice_pk = XOnlyPublicKey::from_str(
        "67c20aa213479676398b79d7cbc7a6b888ccb5944f6d5bb6b1c33b1ab9bdeb4b",
    )
    .unwrap();
    let bob_pk = XOnlyPublicKey::from_str(
        "5f6929a36535c7e95cf99e56a49a745cc548d2147427a62f5b8d015cbd70b122",
    )
    .unwrap();
    // c_a = sha256(bn(0) || 0^32) = sha256(0x00 * 32)
    let c_a: [u8; 32] = hex::decode(
        "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
    )
    .unwrap()
    .try_into()
    .unwrap();
    RpsParams {
        alice_pk,
        bob_pk,
        c_a,
        stake: DEFAULT_STAKE,
    }
}

#[test]
fn test_rps_s0_taptree_matches_reference() {
    let s0 = RpsGameS0::new(reference_params());
    assert_eq!(
        hex::encode(s0.contract.taptree.root_hash()),
        "627bc918efafddfc00f69cc3d14bc2b8d9a7854d05fd048a6eee0640aaa4a26f"
    );
}

#[test]
fn test_rps_s1_taptree_matches_reference() {
    // This root bakes in the three CTV template hashes, so matching it proves the
    // adjudication scripts and payout templates are byte-identical to pymatt.
    let s1 = RpsGameS1::new(reference_params());
    assert_eq!(
        hex::encode(s1.contract.taptree.root_hash()),
        "3a7709078e9ce23ab2fa1c8191bba476a27ced73c6a372e290d3a273305a250c"
    );
}

#[test]
fn test_move_commitment_values() {
    // sha256(bn(0)) = sha256(empty); sha256(bn(1)) = sha256(0x01).
    assert_eq!(
        hex::encode(move_commitment(0)),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex::encode(move_commitment(1)),
        "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"
    );
}
