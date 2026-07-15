//! End-to-end vault contract tests

mod support;

use std::str::FromStr;

use bitcoin::{
    Address, Amount, KnownHrp, TapNodeHash, XOnlyPublicKey, hashes::Hash, hex::DisplayHex,
    key::Secp256k1,
};

use mattrs::{
    contracts::{InstanceStatus, OutputIndex},
    ctv::create_ctv_template,
    manager::ContractManager,
    signer::HotSigner,
};
use support::testkit::{alice_pk, alice_xpriv, bob_pk, regtest_client};
use support::vault::{UnvaultingHandle, UnvaultingState, Vault, VaultParams};

// Regenerate the pinned address with pymatt (from the repo root):
//   pymatt/venv/bin/python -c "
//   import sys; sys.path[:0] = ['pymatt/src', 'pymatt/examples/vault']
//   from vault_contracts import Vault
//   a = bytes.fromhex('67c20aa213479676398b79d7cbc7a6b888ccb5944f6d5bb6b1c33b1ab9bdeb4b')
//   b = bytes.fromhex('5f6929a36535c7e95cf99e56a49a745cc548d2147427a62f5b8d015cbd70b122')
//   print(Vault(None, 10, b, a).get_address())"
#[test]
fn test_vault_address_matches_reference() {
    // Test that our vault address matches the Python reference implementation
    let secp = Secp256k1::new();

    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    })
    .unwrap();

    let internal_key = vault.contract().internal_pubkey();
    let taptree_hash = TapNodeHash::from_byte_array(vault.contract().taptree().root_hash());

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

    let ctv_hash = create_ctv_template(&template, bitcoin::Sequence(10)).ctv_hash();

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
    })
    .unwrap();

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
    })
    .unwrap();

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
    })
    .unwrap();

    let outputs = vault.recover_outputs().unwrap();
    assert_eq!(outputs.len(), 0, "Recover should be terminal (no outputs)");
}

#[test]
fn test_trigger_without_signer_errors() {
    // A trigger clause needs the unvault key. Spending without registering a signer
    // must fail loudly (MissingSigner) rather than broadcast an unsigned witness.
    // This builds the tx locally and does no RPC.
    use mattrs::manager::ManagerError;
    use support::testkit::{fund_fake, offline_client, try_handle};
    use support::vault::VaultHandle;

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap(),
        unvault_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
    };
    let vault = Vault::new(params).unwrap();

    // Fake a funded instance so the tx can be built (and a prevout exists).
    let handle = try_handle::<VaultHandle>(fund_fake(vault.as_erased(), None, 100_000, 0));

    let client = offline_client();
    let manager = ContractManager::new(client, bitcoin::Network::Regtest);

    let err = handle.trigger([7u8; 32], 0).build_tx(&manager).unwrap_err();

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
    use support::testkit::{fund_fake, offline_client, try_handle};
    use support::vault::VaultHandle;

    let unvault_privkey = alice_xpriv();
    let recover_pubkey = XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap();

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: alice_pk(),
    };
    let vault = Vault::new(params).unwrap();

    // Fund three vault instances of 100_000 sat each (same address, distinct txids).
    let funded =
        |seed: u8| try_handle::<VaultHandle>(fund_fake(vault.as_erased(), None, 100_000, seed));
    let h1 = funded(1);
    let h2 = funded(2);
    let h3 = funded(3);

    let client = offline_client();
    let manager = ContractManager::new(client, bitcoin::Network::Regtest);

    let ctv_hash = [7u8; 32];
    let revault_amount = Amount::from_sat(30_000);

    let tx = manager
        .build_batch_tx(&[
            h1.trigger_and_revault(ctv_hash, 0, 1)
                .sign(HotSigner::new(unvault_privkey))
                .output_amount(1, revault_amount),
            h2.trigger(ctv_hash, 0)
                .sign(HotSigner::new(unvault_privkey)),
            h3.trigger(ctv_hash, 0)
                .sign(HotSigner::new(unvault_privkey)),
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
    let client = regtest_client("testwallet");

    let unvault_privkey = alice_xpriv();

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    };

    let vault_contract = Vault::new(params.clone())?;
    let internal_key = vault_contract.contract().internal_pubkey();
    let taptree_hash =
        TapNodeHash::from_byte_array(vault_contract.contract().taptree().root_hash());

    let address = Address::p2tr(&secp, internal_key, Some(taptree_hash), KnownHrp::Regtest);

    // compare with pymatt's address and v1 implementation
    assert_eq!(
        address.to_string(),
        "bcrt1plkh3clum5e2rynql75ufxxqxw898arfumqnua60hwr76q4y0jeksu88u3m"
    );

    let amount = 49999900;

    let mut manager = ContractManager::new(client, bitcoin::Network::Regtest);

    // Create and fund a Vault instance, getting a typed VaultHandle back.
    let vault = Vault::new(params)?.fund(&mut manager, Amount::from_sat(amount))?;

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

    let ctv_hash = create_ctv_template(&ctv_template, bitcoin::Sequence(10)).ctv_hash();

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
        .state()
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

#[test]
fn test_observe_spend_decodes_clause_and_children() {
    // An observer with its own view of the same funded instance decodes a
    // spending transaction it did not build: clause identified from the
    // tapscript, witness args recorded (and typed-decodable), and the child
    // instance materialized with its logical state. No node involved.
    use mattrs::contracts::ClauseArgs;
    use mattrs::signer::HotSigner;
    use support::testkit::{alice_xpriv, fund_fake, offline_client};
    use support::vault::VaultTriggerArgs;

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    };
    let vault = Vault::new(params.clone()).unwrap();
    let ctv_hash = [0xabu8; 32];

    // The actor builds (but does not broadcast) a trigger spend.
    let actor_client = offline_client();
    let actor_manager = ContractManager::new(actor_client, bitcoin::Network::Regtest);
    let actor_handle: support::vault::VaultHandle = fund_fake(vault.as_erased(), None, 100_000, 7)
        .try_into()
        .unwrap();
    let tx = actor_handle
        .trigger(ctv_hash, 0)
        .sign(HotSigner::new(alice_xpriv()))
        .build_tx(&actor_manager)
        .unwrap();

    // The observer holds its own instance of the same (deterministic) funding.
    let observer_client = offline_client();
    let mut observer = ContractManager::new(observer_client, bitcoin::Network::Regtest);
    let observed = fund_fake(vault.as_erased(), None, 100_000, 7);

    let children = observer.observe_spend(&observed, &tx).unwrap();

    // The spend is decoded: clause, typed args, and status.
    assert_eq!(observed.status(), InstanceStatus::Spent);
    assert_eq!(observed.clause_name().as_deref(), Some("trigger"));
    let args = VaultTriggerArgs::decode_from_witness(&observed.spending_args().unwrap()).unwrap();
    assert_eq!(args.ctv_hash, ctv_hash);
    assert_eq!(args.out_i, 0);
    assert!(!args.sig.is_empty());

    // The child is the Unvaulting instance, carrying the ctv_hash as its state.
    assert_eq!(children.len(), 1);
    let unvaulting: UnvaultingHandle = children[0].clone().try_into().unwrap();
    assert_eq!(
        unvaulting
            .handle()
            .state::<UnvaultingState>()
            .unwrap()
            .ctv_hash,
        ctv_hash
    );
    assert_eq!(observed.outputs().len(), 1);

    // Re-observing the same transaction is idempotent.
    let again = observer.observe_spend(&observed, &tx).unwrap();
    assert_eq!(again.len(), 1);
    assert_eq!(observer_instances_count(&observed), 1);
}

#[test]
fn test_observe_batch_spend_decodes_all_inputs() {
    // Two vaults spent by one batch transaction (a trigger_and_revault plus a
    // plain trigger, merging into one unvaulting output). An observer with twin
    // instances decodes each input's clause — including at vin > 0 — and
    // materializes the merged child once, shared between both parents.
    use mattrs::signer::HotSigner;
    use support::testkit::{alice_xpriv, fund_fake, offline_client, try_handle};
    use support::vault::VaultHandle;

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    };
    let vault = Vault::new(params).unwrap();
    let ctv_hash = [7u8; 32];
    let revault_amount = Amount::from_sat(30_000);

    let funded =
        |seed: u8| try_handle::<VaultHandle>(fund_fake(vault.as_erased(), None, 100_000, seed));
    let h1 = funded(1);
    let h2 = funded(2);

    let actor = ContractManager::new(offline_client(), bitcoin::Network::Regtest);
    let tx = actor
        .build_batch_tx(&[
            h1.trigger_and_revault(ctv_hash, 0, 1)
                .sign(HotSigner::new(alice_xpriv()))
                .output_amount(1, revault_amount),
            h2.trigger(ctv_hash, 0).sign(HotSigner::new(alice_xpriv())),
        ])
        .unwrap();

    // The observer holds its own twin instances (same deterministic outpoints).
    let mut observer = ContractManager::new(offline_client(), bitcoin::Network::Regtest);
    let o1 = fund_fake(vault.as_erased(), None, 100_000, 1);
    let o2 = fund_fake(vault.as_erased(), None, 100_000, 2);

    let children1 = observer.observe_spend(&o1, &tx).unwrap();
    let children2 = observer.observe_spend(&o2, &tx).unwrap();

    // Each input decodes to its own clause, at its own input index.
    assert_eq!(o1.clause_name().as_deref(), Some("trigger_and_revault"));
    assert_eq!(o2.clause_name().as_deref(), Some("trigger"));
    assert_eq!(o1.spending_vin(), Some(0));
    assert_eq!(o2.spending_vin(), Some(1));
    assert_eq!(o1.spending_tx().unwrap().compute_txid(), tx.compute_txid());

    // Input 0 yields the unvaulting (index 0) and the revault (index 1); input
    // 1's unvaulting output is the same child, materialized only once.
    assert_eq!(children1.len(), 2);
    assert_eq!(children2.len(), 1);
    assert!(children1.contains(&children2[0]));
    // The merged unvaulting holds both inputs' amounts, net of the revault.
    assert_eq!(
        children2[0].prevout().unwrap().value,
        Amount::from_sat(170_000)
    );
}

/// The parent's recorded children (used to check no duplicates were created).
fn observer_instances_count(handle: &mattrs::manager::InstanceHandle) -> usize {
    handle.outputs().len()
}
