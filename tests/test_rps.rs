//! Rock-Paper-Scissors port tests.
//!
//! The taptree-root assertions are the byte-compatibility proof: they match the
//! roots computed by the pymatt reference (`examples/rps`) for the same fixed keys
//! and commitment, so the ported tapscripts (and their embedded CTV hashes) are
//! byte-identical.

mod support;

use support::rps::{move_commitment, RpsGameS0, RpsGameS1, RpsParams, DEFAULT_STAKE};
use support::testkit::{alice_pk, bob_pk};

// Regenerate the pinned roots with pymatt (from the repo root):
//   pymatt/venv/bin/python -c "
//   import sys; sys.path[:0] = ['pymatt/src', 'pymatt/examples/rps']
//   from rps_contracts import RPSGameS0, RPSGameS1
//   a = bytes.fromhex('67c20aa213479676398b79d7cbc7a6b888ccb5944f6d5bb6b1c33b1ab9bdeb4b')
//   b = bytes.fromhex('5f6929a36535c7e95cf99e56a49a745cc548d2147427a62f5b8d015cbd70b122')
//   c_a = bytes.fromhex('66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925')
//   print(RPSGameS0(a, b, c_a, 1000).get_tr_info().merkle_root.hex())
//   print(RPSGameS1(a, b, c_a, 1000).get_tr_info(b'\x00'*32).merkle_root.hex())"
fn reference_params() -> RpsParams {
    let alice_pk = alice_pk();
    let bob_pk = bob_pk();
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
        hex::encode(s0.taptree_root()),
        "627bc918efafddfc00f69cc3d14bc2b8d9a7854d05fd048a6eee0640aaa4a26f"
    );
}

#[test]
fn test_rps_s1_taptree_matches_reference() {
    // This root bakes in the three CTV template hashes, so matching it proves the
    // adjudication scripts and payout templates are byte-identical to pymatt.
    let s1 = RpsGameS1::new(reference_params());
    assert_eq!(
        hex::encode(s1.taptree_root()),
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

// ----------------------------------------------------------------------------
// Spend flow (build-level, no node): bob_move -> RpsGameS1 -> CTV payout.
// ----------------------------------------------------------------------------

use bitcoin::key::Secp256k1;
use bitcoin::{Amount, ScriptBuf, Sequence, TxOut};
use mattrs::manager::ContractManager;
use mattrs::signer::HotSigner;
use support::rps::{RpsGameS0Handle, RpsGameS1Handle, RpsGameS1State};
use support::testkit::{bob_xpriv, fund_fake, offline_client, try_handle};

#[test]
fn test_rps_bob_move_commits_s1_state() {
    let params = reference_params();

    let handle = try_handle::<RpsGameS0Handle>(fund_fake(
        RpsGameS0::new(params.clone()).as_erased(),
        None,
        2000,
        0,
    ));

    let client = offline_client();
    let manager = ContractManager::new(client);

    // Bob plays paper (m_b = 1), signing with his key.
    let tx = handle
        .bob_move(1)
        .sign(HotSigner::new(bob_xpriv()))
        .build_tx(&manager)
        .unwrap();

    // Output 0 commits RpsGameS1 with state sha256(m_b), preserving the amount.
    let expected = RpsGameS1::new(params)
        .as_erased()
        .script_pubkey(Some(move_commitment(1).as_slice()))
        .unwrap();
    assert_eq!(tx.output[0].script_pubkey, expected);
    assert_eq!(tx.output[0].value, Amount::from_sat(2000));
}

#[test]
fn test_rps_bob_wins_pays_out_via_ctv() {
    let params = reference_params();
    let bob_pk = params.bob_pk;

    let handle = try_handle::<RpsGameS1Handle>(fund_fake(
        RpsGameS1::new(params).as_erased(),
        Some(Box::new(RpsGameS1State {
            commitment: move_commitment(1),
        })),
        2000,
        0,
    ));

    let client = offline_client();
    let manager = ContractManager::new(client);

    // The bob_wins clause pays out the whole pot to Bob via a CTV template.
    let tx = handle
        .bob_wins(1, 0, [0u8; 32])
        .build_tx(&manager)
        .unwrap();

    let secp = Secp256k1::new();
    let bob_spk = ScriptBuf::new_p2tr(&secp, bob_pk, None);
    assert_eq!(
        tx.output,
        vec![TxOut {
            script_pubkey: bob_spk,
            value: Amount::from_sat((2 * DEFAULT_STAKE) as u64),
        }]
    );
    assert_eq!(tx.input[0].sequence, Sequence::ZERO);
}

// ----------------------------------------------------------------------------
// End-to-end (regtest): the full game, adjudicated by a validating node.
// ----------------------------------------------------------------------------

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_rps_full_game_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    use support::testkit::regtest_client;

    // Alice has committed to rock (m_a = 0) with an all-zeros nonce:
    // c_a = sha256(bn(0) || r_a), where bn(0) is empty.
    let params = reference_params();
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);

    let client = regtest_client("testwallet");
    let mut manager = ContractManager::new(client);

    // Fund the game with both players' stakes.
    let s0 = RpsGameS0::new(params).fund(&mut manager, pot)?;

    // Bob reveals paper (m_b = 1), signed; the S1 child commits sha256(bn(1)).
    let s1: RpsGameS1Handle = s0
        .bob_move(1)
        .sign(HotSigner::new(bob_xpriv()))
        .exec_one(&mut manager)?
        .try_into()?;
    let state = s1.state().expect("S1 state");
    assert_eq!(state.commitment, move_commitment(1));

    // Rock vs paper: Bob wins. A cheating alice_wins spend must be rejected by
    // the node's script interpreter (the adjudication is consensus-enforced).
    let cheat = s1.alice_wins(1, 0, [0u8; 32]).exec_none(&mut manager);
    assert!(
        cheat.is_err(),
        "alice_wins must not validate for rock vs paper"
    );

    // The honest outcome pays the whole pot to Bob via the clause's CTV template.
    s1.bob_wins(1, 0, [0u8; 32]).exec_none(&mut manager)?;
    Ok(())
}

