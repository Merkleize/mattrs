//! End-to-end vault contract tests

mod common;
mod support;

use std::str::FromStr;

use bitcoin::{
    Address, Amount, KnownHrp, TapNodeHash, XOnlyPublicKey, bip32::Xpriv, hashes::Hash,
    hex::DisplayHex, key::Secp256k1,
};

use mattrs::{
    contracts::{InstanceStatus, OutputIndex},
    ctv::create_ctv_template,
    manager::ContractManager,
    signer::HotSigner,
};
use support::vault::{UnvaultingHandle, UnvaultingState, Vault, VaultParams};

#[test]
fn test_vault_address_matches_reference() {
    // Test that our vault address matches the Python reference implementation
    let secp = Secp256k1::new();

    let unvault_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    ).unwrap();
    let unvault_pubkey: XOnlyPublicKey = unvault_privkey.to_priv().public_key(&secp).into();

    let recover_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    ).unwrap();
    let recover_pubkey: XOnlyPublicKey = recover_privkey.to_priv().public_key(&secp).into();

    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    });

    let internal_key = vault.contract.internal_pubkey();
    let taptree_hash = TapNodeHash::from_byte_array(vault.contract.taptree().root_hash());

    let address = Address::p2tr(&secp, internal_key, Some(taptree_hash), KnownHrp::Regtest);

    // This should match the Python reference implementation and mattrs_old
    assert_eq!(
        address.to_string(),
        "bcrt1plkh3clum5e2rynql75ufxxqxw898arfumqnua60hwr76q4y0jeksu88u3m"
    );

    println!("Vault address: {}", address);
}

#[test]
fn test_ctv_template_hash() {
    // Test CTV hash computation matches reference
    let template = vec![
        (
            Address::from_str("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437")
                .unwrap()
                .assume_checked(),
            Amount::from_sat(16663333),
        ),
        (
            Address::from_str("bcrt1qpnpjyzkfe7n5eppp2ktwpvuxfw5qfn2zjdum83")
                .unwrap()
                .assume_checked(),
            Amount::from_sat(16663333),
        ),
        (
            Address::from_str("bcrt1q6vqduw24yjjll6nfkxlfy2twwt52w58tnvnd46")
                .unwrap()
                .assume_checked(),
            Amount::from_sat(16663334),
        ),
    ];

    let (_, ctv_hash) = create_ctv_template(&template, bitcoin::Sequence(10)).unwrap();

    // Expected hash from mattrs_old test
    let expected_hex = "b288279b3012acaedfde4e4e347ad6f3147d416edbebf76668f16b91f2969215";
    let expected: [u8; 32] = hex::decode(expected_hex).unwrap().try_into().unwrap();

    assert_eq!(
        ctv_hash, expected,
        "CTV hash should match reference implementation"
    );
}

#[test]
fn test_vault_trigger_outputs() {
    // Test that trigger clause generates correct outputs
    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap(),
        unvault_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
    });

    let ctv_hash = [0u8; 32];
    let outputs = vault.trigger_outputs(ctv_hash, 0).unwrap();

    assert_eq!(outputs.len(), 1, "Trigger should create 1 output");
    assert_eq!(
        outputs[0].index,
        OutputIndex::Explicit(0),
        "Output index should be 0"
    );
    assert!(
        outputs[0].next_state.is_some(),
        "Unvaulting should have state"
    );
}

#[test]
fn test_vault_trigger_and_revault_outputs() {
    // Test that trigger_and_revault generates correct outputs
    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap(),
        unvault_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
    });

    let ctv_hash = [0u8; 32];
    let outputs = vault.trigger_and_revault_outputs(ctv_hash, 0, 1).unwrap();

    assert_eq!(
        outputs.len(),
        2,
        "Should create 2 outputs (revault + unvaulting)"
    );
    assert_eq!(
        outputs[0].index,
        OutputIndex::Explicit(1),
        "Revault output index should be 1"
    );
    assert_eq!(
        outputs[1].index,
        OutputIndex::Explicit(0),
        "Unvaulting output index should be 0"
    );
    assert!(
        outputs[0].next_state.is_none(),
        "Revault (vault) has no state"
    );
    assert!(
        outputs[1].next_state.is_some(),
        "Unvaulting should have state"
    );
}

#[test]
fn test_vault_recover_outputs() {
    // Test that recover is terminal
    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap(),
        unvault_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
    });

    let outputs = vault.recover_outputs().unwrap();
    assert_eq!(outputs.len(), 0, "Recover should be terminal (no outputs)");
}

#[test]
fn test_trigger_without_signer_errors() {
    // A trigger clause needs the unvault key. Spending without registering a signer
    // must fail loudly (MissingSigner) rather than broadcast an unsigned witness.
    // This builds the tx locally and does no RPC.
    use mattrs::manager::ManagerError;
    use support::testkit::{fund_fake, offline_client};
    use support::vault::VaultHandle;

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap(),
        unvault_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
    };
    let vault = Vault::new(params);

    // Fake a funded instance so the tx can be built (and a prevout exists).
    let handle = VaultHandle(fund_fake(vault.as_erased(), None, 100_000, 0));

    let client = offline_client();
    let manager = ContractManager::new(&client);

    let err = handle
        .trigger([7u8; 32], 0)
        .build_tx(&manager)
        .unwrap_err();

    assert!(
        matches!(err, ManagerError::MissingSigner(_)),
        "expected MissingSigner, got: {:?}",
        err
    );
}

#[test]
fn test_batch_merges_and_deducts_outputs() {
    // Three vaults spent in one transaction: one triggers with a partial revault,
    // the other two trigger normally. All three unvaulting outputs share index 0 and
    // merge into a single output; the revault is a separate deducted output at
    // index 1. Mirrors pymatt's trigger_with_revault batch. Builds locally, no RPC.
    use mattrs::signer::HotSigner;
    use support::testkit::{fund_fake, offline_client};
    use support::vault::VaultHandle;

    let secp = Secp256k1::new();
    let unvault_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )
    .unwrap();
    let unvault_pubkey: XOnlyPublicKey = unvault_privkey.to_priv().public_key(&secp).into();
    let recover_pubkey = XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap();

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    };
    let vault = Vault::new(params);

    // Fund three vault instances of 100_000 sat each (same address, distinct txids).
    let funded = |seed: u8| VaultHandle(fund_fake(vault.as_erased(), None, 100_000, seed));
    let h1 = funded(1);
    let h2 = funded(2);
    let h3 = funded(3);

    let client = offline_client();
    let manager = ContractManager::new(&client);

    let ctv_hash = [7u8; 32];
    let revault_amount = Amount::from_sat(30_000);

    let tx = manager
        .build_batch_tx(&[
            h1.trigger_and_revault(ctv_hash, 0, 1)
                .sign(HotSigner::new(unvault_privkey))
                .output_amount(1, revault_amount),
            h2.trigger(ctv_hash, 0).sign(HotSigner::new(unvault_privkey)),
            h3.trigger(ctv_hash, 0).sign(HotSigner::new(unvault_privkey)),
        ])
        .unwrap();

    assert_eq!(tx.input.len(), 3);
    assert_eq!(tx.output.len(), 2);
    // index 0: merged unvaulting output = (100k - 30k revault) + 100k + 100k
    assert_eq!(tx.output[0].value, Amount::from_sat(270_000));
    // index 1: the deducted revault output
    assert_eq!(tx.output[1].value, revault_amount);
    // every input carries a completed witness (args + sig + script + control block)
    assert!(tx.input.iter().all(|i| !i.witness.is_empty()));
}

// Integration test - requires a running regtest bitcoind.
// Ignored by default so `cargo test` is green without a node; run with
// `cargo test -- --ignored` against a configured regtest daemon.
#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_vault_trigger_and_withdraw() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    // Initialize the RPC client
    let client = common::get_rpc_client("testwallet");

    let unvault_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )?;
    let unvault_pubkey: XOnlyPublicKey = unvault_privkey.to_priv().public_key(&secp).into();

    let recover_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )?;
    let recover_pubkey: XOnlyPublicKey = recover_privkey.to_priv().public_key(&secp).into();

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    };

    let vault_contract = Vault::new(params.clone());
    let internal_key = vault_contract.contract.internal_pubkey();
    let taptree_hash = TapNodeHash::from_byte_array(vault_contract.contract.taptree().root_hash());

    let address = Address::p2tr(&secp, internal_key, Some(taptree_hash), KnownHrp::Regtest);

    // compare with pymatt's address and v1 implementation
    assert_eq!(
        address.to_string(),
        "bcrt1plkh3clum5e2rynql75ufxxqxw898arfumqnua60hwr76q4y0jeksu88u3m"
    );

    let amount = 49999900;

    let mut manager = ContractManager::new(&client);

    // Create and fund a Vault instance, getting a typed VaultHandle back.
    let vault = Vault::fund(&mut manager, Amount::from_sat(amount), params)?;

    let ctv_template = vec![
        (
            Address::from_str("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437")?.assume_checked(),
            Amount::from_sat(16663333u64),
        ),
        (
            Address::from_str("bcrt1qpnpjyzkfe7n5eppp2ktwpvuxfw5qfn2zjdum83")?.assume_checked(),
            Amount::from_sat(16663333u64),
        ),
        (
            Address::from_str("bcrt1q6vqduw24yjjll6nfkxlfy2twwt52w58tnvnd46")?.assume_checked(),
            Amount::from_sat(16663334u64),
        ),
    ];

    let (_, ctv_hash) = create_ctv_template(&ctv_template, bitcoin::Sequence(10))?;

    assert_eq!(
        ctv_hash.to_hex_string(bitcoin::hex::Case::Lower),
        "b288279b3012acaedfde4e4e347ad6f3147d416edbebf76668f16b91f2969215"
    );

    // Trigger the vault: read like a function call, signed, one child returned.
    let unvaulting: UnvaultingHandle = vault
        .trigger(ctv_hash, 0)
        .sign(HotSigner::new(unvault_privkey))
        .exec_one(&mut manager)?
        .try_into()?;

    // The child Unvaulting instance is funded and carries the ctv_hash as its state.
    assert_eq!(unvaulting.handle().status(), InstanceStatus::Funded);
    let state = unvaulting
        .handle()
        .state::<UnvaultingState>()
        .expect("Unvaulting instance should have state");
    assert_eq!(state.ctv_hash, ctv_hash);

    let withdraw_outputs: Vec<bitcoin::TxOut> = ctv_template
        .iter()
        .map(|(addr, amount)| bitcoin::TxOut {
            script_pubkey: addr.script_pubkey(),
            value: *amount,
        })
        .collect();

    // Try to withdraw BEFORE the spend_delay - should fail (non-BIP68-final).
    let withdraw_result_early = unvaulting
        .withdraw(ctv_hash)
        .outputs(withdraw_outputs.clone())
        .sequence(10) // Must match the nSequence in the CTV template
        .exec_none(&mut manager);

    assert!(
        withdraw_result_early.is_err(),
        "Withdrawal should fail before spend_delay"
    );
    if let Err(err) = withdraw_result_early {
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("non-BIP68-final") || err_msg.contains("non-final"),
            "Expected non-BIP68-final error, got: {}",
            err_msg
        );
    }

    manager.mine_blocks(10)?;

    // Now withdraw AFTER the spend_delay - should succeed; terminal (no children).
    unvaulting
        .withdraw(ctv_hash)
        .outputs(withdraw_outputs)
        .sequence(10)
        .exec_none(&mut manager)?;

    Ok(())
}
