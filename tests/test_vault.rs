//! End-to-end vault contract tests

mod common;

use std::{collections::HashMap, str::FromStr};

use bitcoin::{
    Address, Amount, KnownHrp, TapNodeHash, XOnlyPublicKey, bip32::Xpriv, hashes::Hash,
    hex::DisplayHex, key::Secp256k1,
};

use mattrs::{
    argtypes::ArgValue,
    contracts::{ContractParams, InstanceStatus},
    ctv::create_ctv_template,
    manager::ContractManager,
    signer::{HotSigner, Signer},
    vault::{Vault, VaultParams},
};

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

    let internal_key = vault.contract.internal_pubkey;
    let taptree_hash = TapNodeHash::from_byte_array(vault.contract.taptree.root_hash());

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
    assert_eq!(outputs[0].n, 0, "Output index should be 0");
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
    assert_eq!(outputs[0].n, 1, "Revault output index should be 1");
    assert_eq!(outputs[1].n, 0, "Unvaulting output index should be 0");
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

// Integration test - requires running bitcoind
#[test]
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

    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    });

    let internal_key = vault.contract.internal_pubkey;
    let taptree_hash = TapNodeHash::from_byte_array(vault.contract.taptree.root_hash());

    let address = Address::p2tr(&secp, internal_key, Some(taptree_hash), KnownHrp::Regtest);

    // compare with pymatt's address and v1 implementation
    assert_eq!(
        address.to_string(),
        "bcrt1plkh3clum5e2rynql75ufxxqxw898arfumqnua60hwr76q4y0jeksu88u3m"
    );

    let amount = 49999900;

    let mut manager = ContractManager::new(&client);

    // Create and fund a Vault instance
    let params_bytes = vault.params.encode();
    let inst = manager.fund_instance(
        vault.as_erased(),
        params_bytes,
        None,
        Amount::from_sat(amount),
    )?;

    // Clone the instance for later use
    let inst_clone = inst.instance.clone();

    let mut signers: HashMap<XOnlyPublicKey, Box<dyn Signer>> = HashMap::new();

    signers.insert(unvault_pubkey, Box::new(HotSigner::new(unvault_privkey)));

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

    // Prepare arguments for the trigger clause
    let mut args = HashMap::new();
    args.insert(
        "sig".to_string(),
        ArgValue::Signature(vec![0u8; 64]), // Placeholder signature - will be filled by manager
    );
    args.insert("ctv_hash".to_string(), ArgValue::Bytes(ctv_hash.to_vec()));
    args.insert("out_i".to_string(), ArgValue::Int(0));

    // Spend the Vault instance with the "trigger" clause
    let out_instances =
        manager.spend_instance(inst_clone, "trigger", args, None, Some(&signers), None)?;

    // Verify that the unvaulting instance was created
    assert_eq!(
        out_instances.len(),
        1,
        "Should create one unvaulting instance"
    );

    let unvaulting_inst = &out_instances[0];

    // Verify the unvaulting instance has correct state
    {
        let inst = unvaulting_inst.instance.borrow();
        assert_eq!(inst.status, InstanceStatus::Funded);

        if let Some(state_bytes) = &inst.state_bytes {
            // Verify it contains our ctv_hash
            assert_eq!(state_bytes.as_slice(), ctv_hash);
        } else {
            panic!("Unvaulting instance should have state");
        }
    }

    // Try to withdraw BEFORE the spend_delay - should fail
    let mut withdraw_args = HashMap::new();
    withdraw_args.insert("ctv_hash".to_string(), ArgValue::Bytes(ctv_hash.to_vec()));

    let withdraw_outputs: Vec<bitcoin::TxOut> = ctv_template
        .iter()
        .map(|(addr, amount)| bitcoin::TxOut {
            script_pubkey: addr.script_pubkey(),
            value: *amount,
        })
        .collect();

    // Clone before borrowing manager
    let unvaulting_inst_clone = unvaulting_inst.instance.clone();
    let unvaulting_inst_clone2 = unvaulting_inst.instance.clone();

    let withdraw_result_early = manager.spend_instance(
        unvaulting_inst_clone,
        "withdraw",
        withdraw_args.clone(),
        Some(withdraw_outputs.clone()),
        None, // No signatures needed for CTV
        Some(bitcoin::Sequence(10)), // Must match the nSequence in the CTV template
    );

    // Verify that withdrawal fails with the expected RPC error
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

    // Now try to withdraw AFTER the spend_delay - should succeed
    let final_insts = manager.spend_instance(
        unvaulting_inst_clone2,
        "withdraw",
        withdraw_args,
        Some(withdraw_outputs),
        None, // No signatures needed for CTV
        Some(bitcoin::Sequence(10)), // Must match the nSequence in the CTV template
    )?;

    // Withdraw tx is terminal - should create no new instances
    assert_eq!(
        final_insts.len(),
        0,
        "Withdraw transaction should be terminal (no new instances)"
    );

    Ok(())
}
