use super::*;
use bitcoin::hashes::Hash;

fn wallet_input(tag: u8) -> (ExternalInput, TxIn) {
    let ext = ExternalInput {
        outpoint: OutPoint {
            txid: Txid::from_byte_array([tag; 32]),
            vout: 0,
        },
        prevout: TxOut {
            value: sat(10_000),
            script_pubkey: crate::script::opaque_p2tr(crate::nums_key()),
        },
    };
    let input = TxIn {
        previous_output: ext.outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: bitcoin::Witness::new(),
    };
    (ext, input)
}

fn add_wallet_input(tx: &mut Transaction) -> ExternalInput {
    let (external, input) = wallet_input(200);
    tx.input.push(input);
    tx.output.push(TxOut {
        value: sat(9_000),
        script_pubkey: external.prevout.script_pubkey.clone(),
    });
    external
}

fn finalize(signed: &SignedWalletSpend) -> Transaction {
    let mut tx = signed.transaction().clone();
    tx.input.last_mut().unwrap().witness = bitcoin::Witness::from_slice(&[vec![1; 64]]);
    tx
}

#[test]
fn funding_signs_all_prevouts_and_observes_only_final_transaction() {
    let mut manager = offline_manager();
    let (handle, builder, calls) = signed_spend_fixture(true);
    let plan = manager.prepare_wallet_spend(vec![builder]).unwrap();
    assert_eq!(calls.get(), 0);
    let mut funded = plan.transaction().clone();
    let external = add_wallet_input(&mut funded);
    let signed = plan
        .sign_funded(&manager, funded, vec![external.clone()], sat(1_000))
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(handle.status(), InstanceStatus::Funded);
    assert_eq!(signed.fee(), sat(1_000));
    assert_eq!(
        plan.input_weights(),
        &[164 + signed.transaction().input[0].witness.size() as u64]
    );

    let witness = signed.transaction().input[0].witness.to_vec();
    let leaf = bitcoin::taproot::TapLeafHash::from_script(
        bitcoin::Script::from_bytes(&witness[1]),
        bitcoin::taproot::LeafVersion::TapScript,
    );
    let prevouts = [handle.prevout(), external.prevout.clone()];
    let hash = crate::signer::compute_tap_sighash(
        signed.transaction(),
        0,
        &prevouts,
        Some(leaf),
        bitcoin::sighash::TapSighashType::Default,
    )
    .unwrap();
    let signer = crate::signer::HotSigner::new(
        bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &[42]).unwrap(),
    );
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&witness[0]).unwrap();
    bitcoin::secp256k1::Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &bitcoin::secp256k1::Message::from_digest(hash),
            &signer.public_key(),
        )
        .unwrap();
    let mut wrong_prevouts = prevouts;
    wrong_prevouts[1].value = sat(9_999);
    let wrong_hash = crate::signer::compute_tap_sighash(
        signed.transaction(),
        0,
        &wrong_prevouts,
        Some(leaf),
        bitcoin::sighash::TapSighashType::Default,
    )
    .unwrap();
    assert!(
        bitcoin::secp256k1::Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &bitcoin::secp256k1::Message::from_digest(wrong_hash),
                &signer.public_key()
            )
            .is_err()
    );

    assert!(signed.validate_final(signed.transaction()).is_err());
    let tx = finalize(&signed);
    let mut altered = tx.clone();
    altered.output[1].value = sat(8_999);
    assert!(signed.observe_final(&mut manager, &altered).is_err());
    altered = tx.clone();
    altered.input[0].witness = bitcoin::Witness::new();
    assert!(signed.validate_final(&altered).is_err());
    assert_eq!(handle.status(), InstanceStatus::Funded);

    let observation = signed.observe_final(&mut manager, &tx).unwrap();
    assert_eq!(observation.children.len(), 1);
    assert_eq!(observation.fee, sat(1_000));
    assert_eq!(handle.status(), InstanceStatus::Spent);
    assert_eq!(observation.children[0].outpoint().txid, tx.compute_txid());
    // Reobservation must reclassify wallet witnesses even when txid is cached.
    altered = tx.clone();
    altered.input[1].witness =
        bitcoin::Witness::from_slice(&[vec![1; 64], vec![0x51], vec![0xc0; 33]]);
    assert_eq!(altered.compute_txid(), tx.compute_txid());
    assert!(
        manager
            .observe_batch_with_external_inputs(
                &[&handle],
                std::slice::from_ref(&external),
                &altered
            )
            .is_err()
    );
    let waited = manager
        .wait_for_batch_with_external_inputs(&[&handle], |outpoint| {
            assert_eq!(outpoint, external.outpoint);
            Ok(external.prevout.clone())
        })
        .unwrap();
    assert_eq!(waited.children.len(), 1);
    assert_eq!(waited.fee, sat(1_000));
}

#[test]
fn invalid_wallet_funding_never_prompts_signers() {
    let manager = offline_manager();
    let (_, builder, calls) = signed_spend_fixture(true);
    let plan = manager.prepare_wallet_spend(vec![builder]).unwrap();
    let mut funded = plan.transaction().clone();
    let external = add_wallet_input(&mut funded);
    for change in 0..9 {
        let mut tx = funded.clone();
        match change {
            0 => tx.version = bitcoin::transaction::Version::ONE,
            1 => tx.lock_time = bitcoin::absolute::LockTime::from_consensus(1),
            2 => tx.input.swap(0, 1),
            3 => tx.input[0].sequence = Sequence::MAX,
            4 => tx.output.swap(0, 1),
            5 => tx.output[0].value = sat(9_999),
            6 => tx.input[0].witness = bitcoin::Witness::from_slice(&[vec![0; 64]]),
            7 => tx.output[1].value = sat(20_001),
            8 => tx.input[1].script_sig = bitcoin::script::Builder::new().push_int(1).into_script(),
            _ => unreachable!(),
        }
        assert!(
            plan.sign_funded(&manager, tx, vec![external.clone()], sat(10_000))
                .is_err(),
            "mutation {change}"
        );
    }
    assert!(matches!(
        plan.sign_funded(&manager, funded.clone(), vec![external.clone()], sat(999)),
        Err(ManagerError::FeeTooHigh { .. })
    ));
    assert!(matches!(
        plan.sign_funded(&manager, funded.clone(), vec![], sat(1_000)),
        Err(ManagerError::IncompleteObservation { .. })
    ));
    assert!(
        plan.sign_funded(
            &manager,
            funded.clone(),
            vec![external.clone(), external],
            sat(1_000)
        )
        .is_err()
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn prefilled_signatures_and_ctv_expansion_are_rejected() {
    let manager = offline_manager();
    let (_, mut builder, calls) = signed_spend_fixture(true);
    builder.witness_args[0] = vec![0; 64];
    assert!(manager.prepare_wallet_spend(vec![builder]).is_err());
    assert_eq!(calls.get(), 0);
    let (_, builder, _) = signed_spend_fixture(false);
    let hash =
        crate::ctv::compute_ctv_hash(builder.explicit_outputs.as_ref().unwrap(), Sequence::ZERO);
    let (_, builder, calls) =
        signed_spend_with_constraint(false, Some(NextOutputs::TemplateHash(hash)));
    let plan = manager.prepare_wallet_spend(vec![builder]).unwrap();
    let mut tx = plan.transaction().clone();
    let external = add_wallet_input(&mut tx);
    assert!(matches!(
        plan.sign_funded(&manager, tx, vec![external], sat(2_000)),
        Err(ManagerError::CtvTemplateMismatch { .. })
    ));
    assert_eq!(calls.get(), 0);
}

#[test]
fn mixed_batch_uses_contract_contributions_not_wallet_value() {
    let mut manager = offline_manager();
    let child = test_contract(90, None);
    let parent = contract_yielding(80, vec![ClauseOutput::at(0).to(child).build()]);
    let first = fund_fake(parent.clone(), (), sat(10_000), 1);
    let second = fund_fake(parent, (), sat(20_000), 2);
    let mut tx = crate::manager::build_batch_tx(&[spend(&first), spend(&second)]).unwrap();
    let external = add_wallet_input(&mut tx);
    tx.input[2].witness = bitcoin::Witness::from_slice(&[vec![1; 64], vec![0x50, 1]]);
    tx.input.swap(1, 2); // Passive observation accepts interleaved wallet inputs.
    assert!(matches!(
        manager.observe_batch(&[&first, &second], &tx),
        Err(ManagerError::IncompleteObservation { .. })
    ));
    let mut underpaid = tx.clone();
    underpaid.output[0].value = sat(29_999);
    assert!(matches!(
        manager.observe_batch_with_external_inputs(
            &[&second, &first],
            std::slice::from_ref(&external),
            &underpaid
        ),
        Err(ManagerError::InsufficientOutputAmount { .. })
    ));
    assert_eq!(first.status(), InstanceStatus::Funded);
    assert_eq!(second.status(), InstanceStatus::Funded);
    let result = manager
        .observe_batch_with_external_inputs(&[&second, &first], &[external], &tx)
        .unwrap();
    assert_eq!(result.fee, sat(1_000));
    assert_eq!(result.children.len(), 1);
    assert_eq!(
        first.outputs()[0].outpoint(),
        second.outputs()[0].outpoint()
    );
}

#[test]
fn invalid_external_contexts_are_atomic() {
    let mut manager = offline_manager();
    let (handle, builder, _) = signed_spend_fixture(true);
    let mut tx = builder.build_tx().unwrap();
    let external = add_wallet_input(&mut tx);
    tx.input[1].witness = bitcoin::Witness::from_slice(&[vec![1; 64]]);
    for change in 0..7 {
        let mut contexts = vec![external.clone()];
        let mut bad_tx = tx.clone();
        match change {
            0 => contexts.clear(),
            1 => contexts.push(external.clone()),
            2 => contexts[0].outpoint.vout = 42,
            3 => contexts[0].prevout.script_pubkey = ScriptBuf::new(),
            4 => contexts[0].prevout.value = sat(u64::MAX),
            5 => bad_tx.output[1].value = sat(20_000),
            6 => bad_tx.input.push(bad_tx.input[1].clone()),
            _ => unreachable!(),
        }
        assert!(
            manager
                .observe_batch_with_external_inputs(&[&handle], &contexts, &bad_tx)
                .is_err()
        );
        assert_eq!(handle.status(), InstanceStatus::Funded);
        assert!(handle.outputs().is_empty());
        assert!(manager.instances.is_empty());
    }
    let disguised = fund_fake(test_contract(23, None), (), sat(10_000), 5);
    manager.instances.push(disguised.instance.clone());
    tx.input[1].previous_output = disguised.outpoint();
    let mut context = external;
    context.outpoint = disguised.outpoint(); // Even a forged native prevout cannot hide a known contract.
    assert!(
        manager
            .observe_batch_with_external_inputs(&[&handle], &[context], &tx)
            .is_err()
    );
    assert_eq!(handle.status(), InstanceStatus::Funded);
}

#[test]
fn p2wpkh_inputs_require_matching_compressed_pubkeys() {
    let mut manager = offline_manager();
    let (handle, builder, _) = signed_spend_fixture(true);
    let mut tx = builder.build_tx().unwrap();
    let mut external = add_wallet_input(&mut tx);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let key = bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap(),
    );
    let pk = bitcoin::CompressedPublicKey(key);
    external.prevout.script_pubkey = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    tx.input[1].witness = bitcoin::Witness::from_slice(&[vec![1; 71], key.serialize().to_vec()]);
    let mut bad = tx.clone();
    bad.input[1].witness = bitcoin::Witness::from_slice(&[vec![1; 71], vec![2; 33]]);
    assert!(
        manager
            .observe_batch_with_external_inputs(&[&handle], &[external.clone()], &bad)
            .is_err()
    );
    assert_eq!(handle.status(), InstanceStatus::Funded);
    assert_eq!(
        manager
            .observe_batch_with_external_inputs(&[&handle], &[external], &tx)
            .unwrap()
            .fee,
        sat(1_000)
    );
}

#[test]
fn same_index_outputs_follow_real_input_positions() {
    let mut manager = offline_manager();
    let child = test_contract(90, None);
    let parent = contract_yielding(80, vec![ClauseOutput::at_same_index().to(child).build()]);
    let handle = fund_fake(parent, (), sat(10_000), 1);
    let mut tx = spend(&handle).build_tx().unwrap();
    let external = add_wallet_input(&mut tx);
    tx.input[1].witness = bitcoin::Witness::from_slice(&[vec![1; 64]]);
    tx.input.swap(0, 1);
    // Wrong: the contract is now input 1, so Same targets output 1, not 0.
    assert!(
        manager
            .observe_batch_with_external_inputs(&[&handle], std::slice::from_ref(&external), &tx)
            .is_err()
    );
    assert_eq!(handle.status(), InstanceStatus::Funded);
    tx.output.swap(0, 1);
    // Extra wallet value can top up a contract output without becoming a CCV
    // contribution. Only the contract's original value is the required minimum.
    tx.output[1].value = sat(10_500);
    let result = manager
        .observe_batch_with_external_inputs(&[&handle], &[external], &tx)
        .unwrap();
    assert_eq!(result.children[0].outpoint().vout, 1);
    assert_eq!(result.fee, sat(500));
}

#[test]
fn join_links_are_atomic_with_interleaved_fee_inputs() {
    let mut manager = offline_manager();
    let (defining, joining) = join_fixture();
    let mut tx = crate::manager::build_batch_tx(&[spend(&defining), spend(&joining)]).unwrap();
    let external = add_wallet_input(&mut tx);
    tx.input[2].witness = bitcoin::Witness::from_slice(&[vec![1; 64]]);
    tx.input.swap(1, 2);
    let result = manager
        .observe_batch_with_external_inputs(&[&joining, &defining], &[external], &tx)
        .unwrap();
    assert_eq!(result.children.len(), 1);
    assert_eq!(
        joining.outputs()[0].outpoint(),
        defining.outputs()[0].outpoint()
    );
    assert_eq!(result.fee, sat(1_000));
}

#[test]
fn late_missing_signer_is_detected_before_any_signing() {
    let manager = offline_manager();
    let (_, first, first_calls) = signed_spend_fixture(true);
    // Distinct funding outpoint, same output contract and signing key.
    let (_, mut second, second_calls) = signed_spend_seeded(true, None, 9);
    second.signers.clear();
    let plan = manager.prepare_wallet_spend(vec![first, second]).unwrap();
    let mut tx = plan.transaction().clone();
    let external = add_wallet_input(&mut tx);
    assert!(matches!(
        plan.sign_funded(&manager, tx, vec![external], sat(1_000)),
        Err(ManagerError::MissingSigner(_))
    ));
    assert_eq!(first_calls.get(), 0);
    assert_eq!(second_calls.get(), 0);
}

#[test]
fn prepared_spend_cannot_sign_after_parent_is_spent() {
    let mut manager = offline_manager();
    let (handle, builder, calls) = signed_spend_fixture(true);
    let plan = manager.prepare_wallet_spend(vec![builder]).unwrap();
    let signed = plan
        .sign_funded(&manager, plan.transaction().clone(), vec![], sat(0))
        .unwrap();
    signed
        .observe_final(&mut manager, signed.transaction())
        .unwrap();
    assert_eq!(handle.status(), InstanceStatus::Spent);
    assert!(
        plan.sign_funded(&manager, plan.transaction().clone(), vec![], sat(0))
            .is_err()
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn nondefault_contract_signatures_are_rejected() {
    struct NondefaultSigner(XOnlyPublicKey);
    impl Signer for NondefaultSigner {
        fn public_key(&self) -> XOnlyPublicKey {
            self.0
        }
        fn sign(&self, _: &[u8; 32]) -> Result<crate::Signature, crate::signer::SignerError> {
            Ok(crate::Signature::new(vec![1; 65]).unwrap())
        }
    }
    let manager = offline_manager();
    let (handle, mut builder, _) = signed_spend_fixture(true);
    let key = *builder.signers.keys().next().unwrap();
    builder.signers.insert(key, Box::new(NondefaultSigner(key)));
    let plan = manager.prepare_wallet_spend(vec![builder]).unwrap();
    assert!(matches!(
        plan.sign_funded(&manager, plan.transaction().clone(), vec![], sat(0)),
        Err(ManagerError::InvalidWalletFunding(_))
    ));
    assert_eq!(handle.status(), InstanceStatus::Funded);
}

#[test]
fn external_context_from_transaction_binds_the_outpoint() {
    let (handle, _, _) = signed_spend_fixture(true);
    let tx = handle.funding_tx();
    let context = ExternalInput::from_transaction(&tx, 0).unwrap();
    assert_eq!(context.outpoint, handle.outpoint());
    assert_eq!(context.prevout, handle.prevout());
    assert!(ExternalInput::from_transaction(&tx, 1).is_err());
}
