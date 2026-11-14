//! Childless withdrawals must still satisfy their declared CTV commitment.

mod support;

use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxOut};
use mattrs::contracts::{CtvTemplate, InstanceStatus};
use mattrs::manager::ManagerError;
use support::testkit::bob_pk;
use support::vault::{Unvaulting, UnvaultingHandle, UnvaultingParams, UnvaultingState};

fn fixture(manager: &mut mattrs::manager::ContractManager) -> (UnvaultingHandle, CtvTemplate) {
    let template = CtvTemplate::new(
        vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        Sequence(10),
    );
    let contract = Unvaulting::new(UnvaultingParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
    })
    .unwrap();
    let handle = contract
        .fund(
            manager,
            Amount::from_sat(10_000),
            UnvaultingState {
                ctv_hash: template.ctv_hash(),
            },
        )
        .unwrap();
    (handle, template)
}

#[test]
fn construction_checks_the_committed_outputs_and_sequence() {
    let mut manager = mattrs::testutil::local_manager();
    let (handle, template) = fixture(&mut manager);
    assert!(handle.withdraw().build_tx().is_err());
    let tx = handle
        .withdraw()
        .outputs(template.outputs.clone())
        .build_tx()
        .unwrap();
    assert_eq!(tx.output, template.outputs);
    assert_eq!(tx.input[0].sequence, template.sequence);
    let mut wrong_amount = template.outputs.clone();
    wrong_amount[0].value = Amount::from_sat(8_999);
    let mut wrong_script = template.outputs.clone();
    wrong_script[0].script_pubkey = ScriptBuf::new();
    for outputs in [wrong_amount, wrong_script] {
        assert!(matches!(
            handle.withdraw().outputs(outputs).build_tx(),
            Err(ManagerError::CtvTemplateMismatch { input_index: 0 })
        ));
    }
    // A larger sequence satisfies CSV but does not match the exact CTV hash.
    assert!(matches!(
        handle
            .withdraw()
            .outputs(template.outputs)
            .sequence(11)
            .build_tx(),
        Err(ManagerError::CtvTemplateMismatch { input_index: 0 })
    ));
    assert_eq!(handle.status(), InstanceStatus::Funded);
}

#[test]
fn observation_checks_every_committed_transaction_field_before_marking_spent() {
    let mut manager = mattrs::testutil::local_manager();
    let (handle, template) = fixture(&mut manager);
    let tx = handle
        .withdraw()
        .outputs(template.outputs)
        .build_tx()
        .unwrap();
    let mutations: &[fn(&mut Transaction)] = &[
        |tx| tx.version = bitcoin::transaction::Version::ONE,
        |tx| tx.lock_time = bitcoin::absolute::LockTime::from_consensus(1),
        |tx| tx.input[0].sequence = Sequence(11),
        |tx| tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]),
        |tx| tx.input.push(bitcoin::TxIn::default()),
        |tx| tx.input.insert(0, bitcoin::TxIn::default()),
        |tx| tx.output[0].value = Amount::from_sat(8_999),
        |tx| tx.output[0].script_pubkey = ScriptBuf::new(),
        |tx| tx.output.push(tx.output[0].clone()),
        |tx| tx.output.clear(),
    ];
    for mutate in mutations {
        let mut invalid = tx.clone();
        mutate(&mut invalid);
        assert!(matches!(
            manager.observe_spend(&handle, &invalid),
            Err(ManagerError::CtvTemplateMismatch { .. })
        ));
        assert_eq!(handle.status(), InstanceStatus::Funded);
        assert!(handle.spend_record().is_none());
        assert!(handle.outputs().is_empty());
    }
    assert!(manager.observe_spend(&handle, &tx).unwrap().is_empty());
    assert_eq!(handle.status(), InstanceStatus::Spent);
    assert_eq!(
        handle.spend_record().unwrap().args()[0],
        tx.input[0].witness.to_vec()[0]
    );
}

#[test]
fn withdrawal_cannot_replace_the_hash_revealed_from_state() {
    let mut manager = mattrs::testutil::local_manager();
    let (handle, template) = fixture(&mut manager);
    assert!(
        handle
            .spend_clause("withdraw", vec![vec![42; 32]])
            .outputs(template.outputs.clone())
            .build_tx()
            .is_err()
    );
    let mut tx = handle
        .withdraw()
        .outputs(template.outputs)
        .build_tx()
        .unwrap();
    let mut witness = tx.input[0].witness.to_vec();
    witness[0] = vec![42; 32];
    tx.input[0].witness = bitcoin::Witness::from_slice(&witness);
    assert!(manager.observe_spend(&handle, &tx).is_err());
    assert_eq!(handle.status(), InstanceStatus::Funded);
}

#[test]
fn hash_only_templates_cannot_be_batched_by_the_builder() {
    let mut manager = mattrs::testutil::local_manager();
    let (handle, template) = fixture(&mut manager);
    let other: UnvaultingHandle = Unvaulting::new(handle.params())
        .unwrap()
        .fund(&mut manager, Amount::from_sat(10_000), handle.state())
        .unwrap();
    // Check both with and without explicit outputs on the hash-only input.
    for explicit in [false, true] {
        let builder = handle.withdraw();
        let builder = if explicit {
            builder.outputs(template.outputs.clone())
        } else {
            builder
        };
        let err = mattrs::manager::build_batch_tx(&[builder, other.withdraw()]).unwrap_err();
        assert!(matches!(err, ManagerError::InvalidSpend(ref message)
            if message.contains("template-hash clauses are single-input only")));
    }
}
