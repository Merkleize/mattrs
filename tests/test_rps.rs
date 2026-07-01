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

// ----------------------------------------------------------------------------
// Spend flow (build-level, no node): bob_move -> RpsGameS1 -> CTV payout.
// ----------------------------------------------------------------------------

use std::cell::RefCell;
use std::rc::Rc;

use bitcoin::bip32::Xpriv;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Txid};
use bitcoincore_rpc::{Auth, Client};
use mattrs::contracts::ContractInstance;
use mattrs::manager::{ContractManager, InstanceHandle};
use mattrs::signer::HotSigner;
use support::rps::{RpsGameS0Handle, RpsGameS1Handle, RpsGameS1State};

fn bob_xpriv() -> Xpriv {
    // The private key whose x-only pubkey is the reference bob_pk (5f6929..).
    Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )
    .unwrap()
}

fn funding_tx(script_pubkey: ScriptBuf, value: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            script_pubkey,
            value: Amount::from_sat(value),
        }],
    }
}

#[test]
fn test_rps_bob_move_commits_s1_state() {
    let params = reference_params();

    // Fund an RpsGameS0 instance with the game stake.
    let s0 = RpsGameS0::new(params.clone());
    let instance = Rc::new(RefCell::new(ContractInstance::new(s0.as_erased(), None)));
    instance.borrow_mut().mark_funded(
        OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        },
        funding_tx(s0.as_erased().script_pubkey(None).unwrap(), 2000),
    );
    let handle = RpsGameS0Handle(InstanceHandle::new(instance));

    let client = Client::new("http://127.0.0.1:1", Auth::None).unwrap();
    let manager = ContractManager::new(&client);

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

    // Fund an RpsGameS1 instance committed to some m_b (Bob's move).
    let s1 = RpsGameS1::new(params.clone());
    let instance = Rc::new(RefCell::new(ContractInstance::new_with_expanded(
        s1.as_erased(),
        Some(Box::new(RpsGameS1State {
            commitment: move_commitment(1),
        })),
    )));
    instance.borrow_mut().mark_funded(
        OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        },
        funding_tx(
            s1.as_erased()
                .script_pubkey(Some(move_commitment(1).as_slice()))
                .unwrap(),
            2000,
        ),
    );
    let handle = RpsGameS1Handle(InstanceHandle::new(instance));

    let client = Client::new("http://127.0.0.1:1", Auth::None).unwrap();
    let manager = ContractManager::new(&client);

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
