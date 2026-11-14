//! End-to-end vault contract tests

mod support;

use std::str::FromStr;

use bitcoin::{
    Address, Amount, KnownHrp, TapNodeHash, XOnlyPublicKey, hashes::Hash, hex::DisplayHex,
    key::Secp256k1,
};

use mattrs::{
    contracts::{CcvIndex, ClauseError, InstanceStatus},
    ctv::create_ctv_template,
    manager::{ContractManager, ManagerError},
    signer::HotSigner,
};
use support::testkit::{alice_pk, alice_xpriv, bob_pk, regtest_client};
use support::vault::{UnvaultingHandle, UnvaultingState, Vault, VaultParams};

#[test]
fn test_vault_address_is_stable() {
    let secp = Secp256k1::new();

    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    })
    .unwrap();

    let internal_key = vault.contract().naked_internal_pubkey();
    let taptree_hash = TapNodeHash::from_byte_array(vault.contract().taptree().root_hash());

    let address = Address::p2tr(&secp, internal_key, Some(taptree_hash), KnownHrp::Regtest);

    // Pin the declarative-timelock script layout. It intentionally differs
    // from pymatt's hand-written opcode order while enforcing the same rules.
    assert_eq!(
        address.to_string(),
        "bcrt1pgyumg5qgqks20e4ggz9gzpu5pu6xh0ne77k5penj97ernld8tpts4gwuzv"
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
        CcvIndex::from(0u16),
        "Output index should be 0"
    );
    assert!(
        !outputs[0].state_commitment().is_empty(),
        "Unvaulting should have state"
    );
}

#[test]
fn test_vault_output_indices_follow_ccv_semantics() {
    use support::testkit::{fund_fake, try_handle};
    use support::vault::VaultHandle;

    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    })
    .unwrap();
    let handle = try_handle::<VaultHandle>(fund_fake(vault.as_erased(), (), 100_000, 9));

    let err = handle.trigger([0; 32], -2).build_tx().unwrap_err();
    assert!(matches!(
        err,
        ManagerError::ClauseError(ClauseError::Other(message))
            if message.contains("CCV index -2")
    ));

    // `-1` is CCV's "same index as this input", exactly as the script reads it.
    // The clause accepts it; the spend only lacks its (unprovided) signer.
    let err = handle.trigger([0; 32], -1).build_tx().unwrap_err();
    assert!(matches!(err, ManagerError::MissingSigner(_)));
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
        CcvIndex::from(1u16),
        "Revault output index should be 1"
    );
    assert_eq!(
        outputs[1].index,
        CcvIndex::from(0u16),
        "Unvaulting output index should be 0"
    );
    assert!(
        outputs[0].state_commitment().is_empty(),
        "Revault (vault) has no state"
    );
    assert!(
        !outputs[1].state_commitment().is_empty(),
        "Unvaulting should have state"
    );
}

#[test]
fn test_trigger_without_signer_errors() {
    // A trigger clause needs the unvault key. Spending without registering a signer
    // must fail loudly (MissingSigner) rather than broadcast an unsigned witness.
    // This builds the tx locally and does no RPC.
    use mattrs::manager::ManagerError;
    use support::testkit::{fund_fake, try_handle};
    use support::vault::VaultHandle;

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap(),
        unvault_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
    };
    let vault = Vault::new(params).unwrap();

    // Fake a funded instance so the tx can be built (and a prevout exists).
    let handle = try_handle::<VaultHandle>(fund_fake(vault.as_erased(), (), 100_000, 0));

    let err = handle.trigger([7u8; 32], 0).build_tx().unwrap_err();

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
    use support::testkit::{fund_fake, try_handle};
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
        |seed: u8| try_handle::<VaultHandle>(fund_fake(vault.as_erased(), (), 100_000, seed));
    let h1 = funded(1);
    let h2 = funded(2);
    let h3 = funded(3);

    let ctv_hash = [7u8; 32];
    let revault_amount = Amount::from_sat(30_000);

    let tx = mattrs::manager::build_batch_tx(&[
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
    let internal_key = vault_contract.contract().naked_internal_pubkey();
    let taptree_hash =
        TapNodeHash::from_byte_array(vault_contract.contract().taptree().root_hash());

    let address = Address::p2tr(&secp, internal_key, Some(taptree_hash), KnownHrp::Regtest);

    // Pin the same declarative-timelock address as the offline test above.
    assert_eq!(
        address.to_string(),
        "bcrt1pgyumg5qgqks20e4ggz9gzpu5pu6xh0ne77k5penj97ernld8tpts4gwuzv"
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
    let state = unvaulting.state();
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
        .withdraw()
        .outputs(withdraw_outputs.clone())
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
        .withdraw()
        .outputs(withdraw_outputs)
        .exec_none(&mut manager)?;

    Ok(())
}

#[test]
fn test_observe_spend_decodes_clause_and_children() {
    // An observer with its own view of the same funded instance decodes a
    // spending transaction it did not build: clause identified from the
    // tapscript, witness args recorded (and typed-decodable), and the child
    // instance materialized with its logical state. No node involved.
    use mattrs::signer::HotSigner;
    use support::testkit::{alice_xpriv, fund_fake};
    use support::vault::{VaultClause, VaultSpend};

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    };
    let vault = Vault::new(params.clone()).unwrap();
    let ctv_hash = [0xabu8; 32];

    // The actor builds (but does not broadcast) a trigger spend.
    let actor_handle: support::vault::VaultHandle = fund_fake(vault.as_erased(), (), 100_000, 7)
        .try_into()
        .unwrap();
    let tx = actor_handle
        .trigger(ctv_hash, 0)
        .sign(HotSigner::new(alice_xpriv()))
        .build_tx()
        .unwrap();

    // The observer holds its own instance of the same (deterministic) funding.
    let mut observer = ContractManager::offline(bitcoin::Network::Regtest);
    let observed = fund_fake(vault.as_erased(), (), 100_000, 7);

    assert!(actor_handle.spent().is_none());
    let children = observer.observe_spend(&observed, &tx).unwrap();

    // The spend is decoded: clause, typed args, and status.
    assert_eq!(observed.status(), InstanceStatus::Spent);
    assert_eq!(observed.clause_name().as_deref(), Some("trigger"));
    let typed: support::vault::VaultHandle = observed.clone().try_into().unwrap();
    let Some(VaultSpend::Trigger(args)) = typed.spent() else {
        panic!("the recorded spend decodes to a typed trigger");
    };
    assert_eq!(typed.spent().unwrap().clause(), VaultClause::Trigger);
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
    use support::testkit::{alice_xpriv, fund_fake, try_handle};
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
        |seed: u8| try_handle::<VaultHandle>(fund_fake(vault.as_erased(), (), 100_000, seed));
    let h1 = funded(1);
    let h2 = funded(2);

    let tx = mattrs::manager::build_batch_tx(&[
        h1.trigger_and_revault(ctv_hash, 0, 1)
            .sign(HotSigner::new(alice_xpriv()))
            .output_amount(1, revault_amount),
        h2.trigger(ctv_hash, 0).sign(HotSigner::new(alice_xpriv())),
    ])
    .unwrap();

    // The observer holds its own twin instances (same deterministic outpoints).
    let mut observer = ContractManager::offline(bitcoin::Network::Regtest);
    let o1 = fund_fake(vault.as_erased(), (), 100_000, 1);
    let o2 = fund_fake(vault.as_erased(), (), 100_000, 2);

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
    assert_eq!(children2[0].prevout().value, Amount::from_sat(170_000));
}

/// The parent's recorded children (used to check no duplicates were created).
fn observer_instances_count(handle: &mattrs::manager::InstanceHandle) -> usize {
    handle.outputs().len()
}

/// A spend handed to an external broadcaster is staged first and recorded only
/// if the broadcast succeeds; an actor and an observer of the same spend then
/// list its children in the same (output-index) order.
#[test]
fn test_external_broadcast_is_staged_first_and_orders_children_like_observation() {
    use mattrs::signer::HotSigner;
    use support::testkit::{alice_xpriv, fund_fake, offline_manager, try_handle};
    use support::vault::VaultHandle;

    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    })
    .unwrap();
    let spend = |handle: &VaultHandle| {
        // The clause declares the revault (output 1) before the unvaulting
        // (output 0).
        handle
            .trigger_and_revault([7; 32], 0, 1)
            .output_amount(1, Amount::from_sat(30_000))
            .sign(HotSigner::new(alice_xpriv()))
    };

    // A refused broadcast leaves the instance untouched.
    let mut actor = offline_manager();
    let handle = try_handle::<VaultHandle>(fund_fake(vault.as_erased(), (), 100_000, 11));
    let refused = actor.spend_batch_with(&[spend(&handle)], |_| {
        Err(ManagerError::Other("the relay refused it".into()))
    });
    assert!(matches!(refused, Err(ManagerError::Other(_))));
    assert_eq!(handle.handle().status(), InstanceStatus::Funded);
    assert!(handle.handle().outputs().is_empty());

    // An accepted one is recorded, with the transaction the broadcaster saw.
    let mut sent = None;
    let children = actor
        .spend_batch_with(&[spend(&handle)], |tx| {
            sent = Some(tx.clone());
            Ok::<_, ManagerError>(())
        })
        .unwrap();
    assert_eq!(handle.handle().status(), InstanceStatus::Spent);
    let sent = sent.expect("the broadcaster ran");

    // An observer of that transaction sees the same children, in the same order.
    let mut observer = offline_manager();
    let observed = fund_fake(vault.as_erased(), (), 100_000, 11);
    let seen = observer.observe_spend(&observed, &sent).unwrap();
    let outpoints = |children: &[mattrs::manager::InstanceHandle]| -> Vec<_> {
        children.iter().map(|child| child.outpoint()).collect()
    };
    assert_eq!(outpoints(&children), outpoints(&seen));
    assert_eq!(outpoints(&seen), outpoints(&observed.outputs()));
    assert_eq!(
        seen.iter().map(|c| c.outpoint().vout).collect::<Vec<_>>(),
        [0, 1]
    );

    // Children are addressed by the output they live at, typed.
    let _: UnvaultingHandle = children.at(0).unwrap();
    let _: VaultHandle = children.at(1).unwrap();
    assert!(matches!(
        children.at::<VaultHandle>(0),
        Err(ManagerError::WrongContract(_))
    ));
    assert!(matches!(
        children.at::<VaultHandle>(2),
        Err(ManagerError::NoChildAtOutput { index: 2 })
    ));
}

/// An offline manager reports node operations as `NoNode` instead of trying to
/// reach one.
#[test]
fn test_offline_manager_reports_node_operations() {
    let mut manager = ContractManager::offline(bitcoin::Network::Regtest);
    assert!(matches!(manager.chain(), Err(ManagerError::NoNode)));
    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    })
    .unwrap();
    assert!(matches!(
        vault.fund(&mut manager, Amount::from_sat(1_000)),
        Err(ManagerError::NoNode)
    ));
}

/// The whole funded → spent lifecycle on the in-memory chain: one party funds
/// and spends with the ordinary `fund` / `exec` API, another tracks the same
/// outpoint and follows the spend, and both end with the same child.
#[test]
fn test_fund_exec_and_follow_on_a_local_chain() {
    use mattrs::chain::{ChainView, LocalChain};
    use mattrs::signer::HotSigner;
    use std::rc::Rc;
    use support::testkit::alice_xpriv;

    let chain = Rc::new(LocalChain::new());
    let mut actor = ContractManager::on(chain.clone(), bitcoin::Network::Regtest);
    let mut observer = ContractManager::on(chain.clone(), bitcoin::Network::Regtest);

    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    })
    .unwrap();
    let funded = vault.fund(&mut actor, Amount::from_sat(100_000)).unwrap();
    let outpoint = funded.handle().outpoint();
    actor.mine_blocks(1).unwrap();
    assert_eq!(chain.confirmation_height(outpoint.txid).unwrap(), Some(1));

    let watched = Vault::track(&vault, &mut observer, outpoint).unwrap();

    let children = funded
        .trigger([9; 32], 0)
        .sign(HotSigner::new(alice_xpriv()))
        .exec(&mut actor)
        .unwrap();
    assert_eq!(children.len(), 1);

    let seen = observer.wait_for_spend(watched.handle()).unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].outpoint(), children[0].outpoint());

    // The chain refuses a second spend of the same output, and the manager
    // records nothing for it.
    let again = vault.fund(&mut actor, Amount::from_sat(100_000)).unwrap();
    let first = again
        .trigger([1; 32], 0)
        .sign(HotSigner::new(alice_xpriv()));
    let tx = first.build_tx().unwrap();
    let mut conflicting = tx.clone();
    conflicting.lock_time = bitcoin::absolute::LockTime::from_consensus(7);
    chain.broadcast(&conflicting).unwrap();
    assert!(matches!(
        first.exec(&mut actor),
        Err(ManagerError::Chain(mattrs::chain::ChainError::Rejected(_)))
    ));
    assert_eq!(again.handle().status(), InstanceStatus::Funded);
}

/// A standing signer on the manager signs every spend it executes; a signer
/// given to one spend wins for that spend; a key nobody holds is an error.
#[test]
fn test_standing_signers_fill_signatures() {
    use mattrs::chain::LocalChain;
    use mattrs::signer::{HotSigner, Signer, SignerError};
    use std::rc::Rc;
    use support::testkit::alice_xpriv;

    /// Signs for Alice's key, but refuses.
    struct Refusing;
    impl Signer for Refusing {
        fn sign(&self, _: &[u8; 32]) -> Result<mattrs::Signature, SignerError> {
            Err(SignerError("refused".into()))
        }
        fn public_key(&self) -> XOnlyPublicKey {
            alice_pk()
        }
    }

    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    })
    .unwrap();
    let chain = Rc::new(LocalChain::new());
    let mut manager = ContractManager::on(chain, bitcoin::Network::Regtest);
    let fund =
        |manager: &mut ContractManager| vault.fund(manager, Amount::from_sat(100_000)).unwrap();

    // No signer anywhere.
    assert!(matches!(
        fund(&mut manager).trigger([1; 32], 0).exec(&mut manager),
        Err(ManagerError::MissingSigner(key)) if key == alice_pk()
    ));

    // A standing signer: no `.sign(..)` on the spend.
    manager.add_signer(HotSigner::new(alice_xpriv()));
    let spent = fund(&mut manager);
    spent.trigger([1; 32], 0).exec(&mut manager).unwrap();
    assert_eq!(spent.handle().status(), InstanceStatus::Spent);

    // A per-spend signer takes precedence over the standing one.
    let kept = fund(&mut manager);
    assert!(
        kept.trigger([1; 32], 0)
            .sign(Refusing)
            .exec(&mut manager)
            .is_err()
    );
    assert_eq!(kept.handle().status(), InstanceStatus::Funded);
}
