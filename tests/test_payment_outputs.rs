//! Terminal CCV payments retain output constraints without creating children.

mod support;

use bitcoin::{Amount, ScriptBuf, TxOut};
use mattrs::ccv::CcvIndex;
use mattrs::contract;
use mattrs::contracts::{ClauseOutput, InstanceStatus, NextOutputs};
use mattrs::manager::{InstanceHandle, ManagerError};
use mattrs::script_helpers::opaque_p2tr;
use support::testkit::{alice_pk, bob_pk};
use support::vault::{
    Unvaulting, UnvaultingHandle, UnvaultingParams, UnvaultingState, Vault, VaultHandle,
    VaultParams,
};

fn sat(value: u64) -> Amount {
    Amount::from_sat(value)
}

fn vault(manager: &mut mattrs::manager::ContractManager) -> VaultHandle {
    Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    })
    .unwrap()
    .fund(manager, sat(10_000))
    .unwrap()
}

fn unvaulting(manager: &mut mattrs::manager::ContractManager) -> UnvaultingHandle {
    Unvaulting::new(UnvaultingParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
    })
    .unwrap()
    .fund(manager, sat(20_000), UnvaultingState { ctv_hash: [42; 32] })
    .unwrap()
}

#[test]
fn recovery_derives_the_untweaked_payment_and_has_no_children() {
    let mut manager = mattrs::testutil::local_manager();
    let a = vault(&mut manager);
    let b = unvaulting(&mut manager);
    for handle in [a.handle(), b.handle()] {
        let tx = handle
            .spend_clause("recover", vec![vec![]])
            .build_tx()
            .unwrap();
        assert_eq!(
            tx.output,
            vec![TxOut {
                script_pubkey: opaque_p2tr(bob_pk()),
                value: handle.prevout().value,
            }]
        );
        assert!(manager.observe_spend(handle, &tx).unwrap().is_empty());
        assert_eq!(handle.status(), InstanceStatus::Spent);
        assert!(handle.outputs().is_empty());
        // Repeat observation remains childless and does not fabricate an instance.
        assert!(manager.observe_spend(handle, &tx).unwrap().is_empty());
    }
}

#[test]
fn explicit_recovery_outputs_cannot_change_destination_or_reduce_value() {
    let mut manager = mattrs::testutil::local_manager();
    let h = vault(&mut manager);
    let tx = h.recover(0).build_tx().unwrap();
    let mut wrong_script = tx.output.clone();
    wrong_script[0].script_pubkey = opaque_p2tr(alice_pk());
    let mut underpayment = tx.output.clone();
    underpayment[0].value = sat(9_999);
    for invalid in [wrong_script, underpayment] {
        assert!(h.recover(0).outputs(invalid.clone()).build_tx().is_err());
        let mut observed = tx.clone();
        observed.output = invalid;
        assert!(manager.observe_spend(&h, &observed).is_err());
        assert_eq!(h.status(), InstanceStatus::Funded);
        assert!(h.spending_args().is_none());
    }
    let mut missing = tx.clone();
    missing.output.clear();
    assert!(matches!(
        manager.observe_spend(&h, &missing),
        Err(ManagerError::PaymentOutputMismatch { index: 0 })
    ));
    assert!(h.recover(0).outputs(tx.output).build_tx().is_ok());
}

#[test]
fn recovery_respects_explicit_and_same_input_indices() {
    let mut manager = mattrs::testutil::local_manager();
    let a = vault(&mut manager);
    let b = unvaulting(&mut manager);
    let tx = mattrs::manager::build_batch_tx(&[
        a.recover(CcvIndex::CURRENT),
        b.recover(CcvIndex::CURRENT),
    ])
    .unwrap();
    assert_eq!(
        tx.output.iter().map(|out| out.value).collect::<Vec<_>>(),
        vec![sat(10_000), sat(20_000)]
    );
    for h in [a.handle(), b.handle()] {
        assert!(manager.observe_spend(h, &tx).unwrap().is_empty());
    }
    let a = vault(&mut manager);
    // Gaps require explicit outputs; the manager does not invent fillers.
    assert!(matches!(
        a.recover(1).build_tx(),
        Err(ManagerError::NonContiguousOutputs { missing_index: 0 })
    ));
    let outputs = vec![
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        },
        TxOut {
            value: sat(10_000),
            script_pubkey: opaque_p2tr(bob_pk()),
        },
    ];
    let tx = a.recover(1).outputs(outputs.clone()).build_tx().unwrap();
    assert_eq!(tx.output, outputs);
    assert!(manager.observe_spend(&a, &tx).unwrap().is_empty());
}

#[test]
fn batched_recoveries_aggregate_without_creating_children() {
    let mut manager = mattrs::testutil::local_manager();
    let a = vault(&mut manager);
    let b = unvaulting(&mut manager);
    let tx = mattrs::manager::build_batch_tx(&[a.recover(0), b.recover(0)]).unwrap();
    assert_eq!(
        tx.output,
        vec![TxOut {
            script_pubkey: opaque_p2tr(bob_pk()),
            value: sat(30_000)
        }]
    );
    for h in [a.handle(), b.handle()] {
        assert!(manager.observe_spend(h, &tx).unwrap().is_empty());
        assert!(h.outputs().is_empty());
    }
}

#[derive(Debug, Clone)]
struct SplitParams {
    ignore: bool,
}

contract! {
    contract SplitPayments {
        params SplitParams;
        // Host-accounting fixture, not a consensus-script test.
        clause split {
            script |_| ScriptBuf::from_bytes(vec![0x51]);
            next(p, _a) {
                let first = ClauseOutput::at(0).pay(opaque_p2tr(alice_pk()));
                Ok(NextOutputs::Outputs(vec![
                    if p.ignore { first.ignore_amount() } else { first.deduct_amount() },
                    ClauseOutput::at(1).pay(opaque_p2tr(bob_pk())),
                ]))
            }
        }
        tree [split];
    }
}

fn split(manager: &mut mattrs::manager::ContractManager, ignore: bool) -> InstanceHandle {
    SplitPayments::new(SplitParams { ignore })
        .unwrap()
        .fund(manager, sat(10_000))
        .unwrap()
        .handle()
        .clone()
}

#[test]
fn payment_amounts_use_the_shared_deduct_and_preserve_rules() {
    let mut manager = mattrs::testutil::local_manager();
    let h = split(&mut manager, false);
    assert!(matches!(
        h.spend_clause("split", vec![]).build_tx(),
        Err(ManagerError::MissingDeductAmount { index: 0 })
    ));
    let tx = h
        .spend_clause("split", vec![])
        .output_amount(0, sat(3_000))
        .build_tx()
        .unwrap();
    assert_eq!(
        tx.output.iter().map(|out| out.value).collect::<Vec<_>>(),
        vec![sat(3_000), sat(7_000)]
    );
    assert!(
        h.spend_clause("split", vec![])
            .output_amount(0, sat(10_001))
            .build_tx()
            .is_err()
    );
    assert!(matches!(
        h.spend_clause("split", vec![])
            .output_amount(0, sat(3_000))
            .output_amount(2, sat(1))
            .build_tx(),
        Err(ManagerError::UnusedOutputAmount { index: 2 })
    ));
    let mut invalid = tx.clone();
    invalid.output[1].value = sat(6_999);
    assert!(manager.observe_spend(&h, &invalid).is_err());
    assert_eq!(h.status(), InstanceStatus::Funded);
    assert!(manager.observe_spend(&h, &tx).unwrap().is_empty());
}

#[test]
fn ignored_payments_require_an_amount_but_do_not_reduce_the_residual() {
    let mut manager = mattrs::testutil::local_manager();
    let h = split(&mut manager, true);
    assert!(matches!(
        h.spend_clause("split", vec![]).build_tx(),
        Err(ManagerError::MissingIgnoredAmount { index: 0 })
    ));
    // The builder accounts for CCV only, not external fee/value funding.
    let tx = h
        .spend_clause("split", vec![])
        .output_amount(0, Amount::ZERO)
        .build_tx()
        .unwrap();
    assert_eq!(tx.output[1].value, sat(10_000));
    assert!(
        h.spend_clause("split", vec![])
            .outputs(tx.output)
            .output_amount(0, sat(1))
            .build_tx()
            .is_err()
    );
}
