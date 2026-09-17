//! Adversarial tests of the declared model, not consensus-script execution.

use super::signing::input_witness;
use super::*;
use crate::contracts::NextOutputs;
use crate::contracts::{
    ClauseOutput, ClauseOutputAmountBehaviour, ErasedContract, InstanceStatus, OutputIndex,
};
use crate::contracts::{ClauseTree, PaymentOutput, RawArgs, StandardClause, StandardP2TR};
use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut};
use bitcoincore_rpc::Client;
use std::sync::Arc;
use std::{cell::RefCell, rc::Rc};

fn manager() -> ContractManager {
    ContractManager::new(
        Client::new("http://127.0.0.1:1", bitcoincore_rpc::Auth::None).unwrap(),
        bitcoin::Network::Regtest,
    )
}

fn sat(value: u64) -> Amount {
    Amount::from_sat(value)
}

fn contract(tag: i64, next: NextOutputs) -> Arc<dyn ErasedContract> {
    let clause = StandardClause::<(), (), RawArgs>::new(
        "spend".into(),
        bitcoin::script::Builder::new()
            .push_int(tag)
            .push_opcode(bitcoin::opcodes::all::OP_DROP)
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script(),
        vec![],
        Some(Arc::new(move |_, _, _| Ok(next.clone()))),
    );
    Arc::new(
        StandardP2TR::new(
            "ObservationTest",
            crate::nums_key(),
            &(),
            ClauseTree::leaf(Arc::new(clause)),
        )
        .unwrap(),
    )
}

fn fund(tag: u8, value: Amount, next: NextOutputs) -> InstanceHandle {
    crate::testutil::fund_fake(contract(tag.into(), next), None, value, tag)
}

fn pay(value: Amount, tag: u8) -> InstanceHandle {
    fund(tag, value, PaymentOutput::at(0, script()).into())
}

fn script() -> bitcoin::ScriptBuf {
    crate::script_helpers::opaque_p2tr(crate::nums_key())
}

// Assemble deliberately invalid metadata-level transactions that the normal
// builder refuses. Witnesses still authenticate each fixture's actual leaf.
fn transaction(handles: &[&InstanceHandle], output: Vec<TxOut>) -> Transaction {
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: handles
            .iter()
            .map(|h| TxIn {
                previous_output: h.outpoint().unwrap(),
                sequence: Sequence::ZERO,
                ..Default::default()
            })
            .collect(),
        output,
    };
    let prevouts: Vec<_> = handles.iter().map(|h| h.prevout().unwrap()).collect();
    for (vin, handle) in handles.iter().enumerate() {
        tx.input[vin].witness =
            input_witness(&handle.spend_clause("spend", vec![]), &tx, vin, &prevouts).unwrap();
    }
    tx
}

fn untouched(manager: &ContractManager, handles: &[&InstanceHandle]) {
    assert!(manager.instances.is_empty());
    for h in handles {
        assert_eq!(h.status(), InstanceStatus::Funded);
        assert!(h.outputs().is_empty());
        assert!(h.spending_args().is_none());
    }
}

#[test]
fn combined_preserve_is_not_two_independent_lower_bounds() {
    let a = pay(sat(10_000), 1);
    let b = pay(sat(20_000), 2);
    let mut tx = transaction(
        &[&a, &b],
        vec![TxOut {
            value: sat(20_000),
            script_pubkey: script(),
        }],
    );
    let mut manager = manager();
    assert!(matches!(manager.observe_batch(&[&b, &a], &tx),
        Err(ManagerError::InsufficientOutputAmount { index: 0, required, actual })
            if required == sat(30_000) && actual == sat(20_000)));
    untouched(&manager, &[&a, &b]);
    tx.output[0].value = sat(30_000);
    assert!(manager.observe_batch(&[&b, &a], &tx).unwrap().is_empty());
    assert!(manager.observe_batch(&[&a, &b], &tx).unwrap().is_empty());
    assert_eq!(a.status(), InstanceStatus::Spent);
    assert_eq!(b.status(), InstanceStatus::Spent);
}

#[test]
fn cross_input_deduct_conflicts_are_rejected_in_either_order() {
    use ClauseOutputAmountBehaviour::{DeductOutput, PreserveOutput};
    for modes in [
        [DeductOutput, DeductOutput],
        [DeductOutput, PreserveOutput],
        [PreserveOutput, DeductOutput],
    ] {
        let payment = |amount| {
            NextOutputs::Payments(vec![PaymentOutput {
                index: OutputIndex::Explicit(0),
                script_pubkey: script(),
                amount,
            }])
        };
        let a = fund(1, sat(10_000), payment(modes[0]));
        let b = fund(2, sat(10_000), payment(modes[1]));
        let tx = transaction(
            &[&a, &b],
            vec![TxOut {
                value: sat(10_000),
                script_pubkey: script(),
            }],
        );
        let mut manager = manager();
        assert!(matches!(
            manager.observe_batch(&[&b, &a], &tx),
            Err(ManagerError::MixedOutputSemantics { index: 0 })
        ));
        untouched(&manager, &[&a, &b]);
    }
}

#[test]
fn preserve_aggregates_residuals_after_actual_deductions() {
    let a = fund(
        1,
        sat(10_000),
        NextOutputs::Payments(vec![
            PaymentOutput::at(0, script()).deduct_amount(),
            PaymentOutput::at(1, script()),
        ]),
    );
    let b = fund(2, sat(10_000), PaymentOutput::at(1, script()).into());
    let mut tx = transaction(
        &[&a, &b],
        vec![
            TxOut {
                value: sat(3_000),
                script_pubkey: script(),
            },
            TxOut {
                value: sat(10_000),
                script_pubkey: script(),
            },
        ],
    );
    let mut manager = manager();
    assert!(matches!(manager.observe_batch(&[&a, &b], &tx),
        Err(ManagerError::InsufficientOutputAmount { index: 1, required, .. }) if required == sat(17_000)));
    untouched(&manager, &[&a, &b]);
    tx.output[1].value = sat(17_000);
    assert!(manager.observe_batch(&[&b, &a], &tx).unwrap().is_empty());
}

#[test]
fn ignore_mode_does_not_conflict_with_another_inputs_amount_check() {
    let a = fund(
        1,
        sat(10_000),
        PaymentOutput::at(0, script()).ignore_amount().into(),
    );
    let b = pay(sat(10_000), 2);
    let tx = transaction(
        &[&a, &b],
        vec![TxOut {
            value: sat(10_000),
            script_pubkey: script(),
        }],
    );
    assert!(manager().observe_batch(&[&a, &b], &tx).unwrap().is_empty());
}

#[test]
fn joins_contribute_value_and_link_without_a_second_observation_pass() {
    let dest = contract(90, NextOutputs::Contracts(vec![]));
    let a = fund(1, sat(5_000), NextOutputs::join(0));
    let b = fund(
        2,
        sat(10_000),
        vec![ClauseOutput::at(0).to(dest.clone()).build()].into(),
    );
    let mut tx = transaction(
        &[&a, &b],
        vec![TxOut {
            value: sat(10_000),
            script_pubkey: dest.script_pubkey(None).unwrap(),
        }],
    );
    let mut manager = manager();
    assert!(matches!(
        manager.observe_batch(&[&a, &b], &tx),
        Err(ManagerError::InsufficientOutputAmount { .. })
    ));
    untouched(&manager, &[&a, &b]);
    tx.output[0].value = sat(15_000);
    let children = manager.observe_batch(&[&a, &b], &tx).unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(a.outputs()[0], children[0]);
    assert_eq!(b.outputs()[0], children[0]);
    assert_eq!(
        manager.observe_batch(&[&b, &a], &tx).unwrap()[0],
        children[0]
    );
    assert_eq!(manager.instances.len(), 1);
    assert_eq!(a.outputs().len(), 1);
    assert_eq!(b.outputs().len(), 1);
    // Already-observed spends can be checked through the waiting API without RPC.
    assert_eq!(manager.wait_for_batch(&[&b, &a]).unwrap()[0], children[0]);
    assert!(manager.wait_for_batch(&[]).is_err());
}

#[test]
fn context_must_cover_every_input_exactly_once() {
    let a = pay(sat(10_000), 1);
    let b = pay(sat(20_000), 2);
    let extra = pay(sat(30_000), 3);
    let tx = transaction(
        &[&a, &b],
        vec![TxOut {
            value: sat(30_000),
            script_pubkey: script(),
        }],
    );
    let mut manager = manager();
    assert!(matches!(manager.observe_batch(&[&a], &tx),
        Err(ManagerError::IncompleteObservation { missing }) if missing == vec![b.outpoint().unwrap()]));
    assert!(manager.observe_batch(&[], &tx).is_err());
    assert!(manager.observe_batch(&[&a, &a], &tx).is_err());
    assert!(manager.observe_batch(&[&a, &b, &extra], &tx).is_err());
    let duplicate = transaction(&[&a, &a], tx.output.clone());
    assert!(manager.observe_batch(&[&a], &duplicate).is_err());
    let mut empty = tx.clone();
    empty.output.clear();
    assert!(matches!(
        manager.observe_batch(&[&a, &b], &empty),
        Err(ManagerError::NoOutputs)
    ));
    untouched(&manager, &[&a, &b, &extra]);
}

#[test]
fn a_bad_later_witness_does_not_commit_an_earlier_parent_or_child() {
    let dest = contract(90, NextOutputs::Contracts(vec![]));
    let a = fund(
        1,
        sat(10_000),
        vec![ClauseOutput::at(0).to(dest.clone()).build()].into(),
    );
    let b = fund(
        2,
        sat(10_000),
        vec![ClauseOutput::at(0).to(dest.clone()).build()].into(),
    );
    let tx = transaction(
        &[&a, &b],
        vec![TxOut {
            value: sat(20_000),
            script_pubkey: dest.script_pubkey(None).unwrap(),
        }],
    );
    let mut invalid = tx.clone();
    invalid.input[1].witness.clear();
    assert_eq!(invalid.compute_txid(), tx.compute_txid());
    let mut manager = manager();
    assert!(manager.observe_batch(&[&a, &b], &invalid).is_err());
    untouched(&manager, &[&a, &b]);
    let children = manager.observe_batch(&[&a, &b], &tx).unwrap();
    // Cached children must not make the malformed witness acceptable on replay.
    assert!(manager.observe_spend(&b, &invalid).is_err());
    assert!(manager.observe_batch(&[&a, &b], &invalid).is_err());
    assert_eq!(manager.instances.len(), 1);
    assert_eq!(
        manager.observe_batch(&[&a, &b], &tx).unwrap()[0],
        children[0]
    );
}

#[test]
fn a_late_child_registry_conflict_leaves_every_parent_unchanged() {
    let dest = contract(90, NextOutputs::Contracts(vec![]));
    let a = fund(
        1,
        sat(10_000),
        vec![ClauseOutput::at(0).to(dest.clone()).build()].into(),
    );
    let b = fund(
        2,
        sat(10_000),
        vec![ClauseOutput::at(1).to(dest.clone()).build()].into(),
    );
    let output = TxOut {
        value: sat(10_000),
        script_pubkey: dest.script_pubkey(None).unwrap(),
    };
    let tx = transaction(&[&a, &b], vec![output.clone(), output]);
    // Same nominal type/params, but an incompatible script at the second child:
    // identity checks alone must not allow reusing this cached instance.
    let wrong = contract(91, NextOutputs::Contracts(vec![]));
    let mut existing = ContractInstance::new(wrong, None).unwrap();
    existing.mark_funded(
        OutPoint {
            txid: tx.compute_txid(),
            vout: 1,
        },
        tx.clone(),
    );
    let mut manager = manager();
    manager.instances.push(Rc::new(RefCell::new(existing)));
    assert!(matches!(
        manager.observe_batch(&[&a, &b], &tx),
        Err(ManagerError::ConflictingOutputContract { index: 1 })
    ));
    assert_eq!(manager.instances.len(), 1);
    for h in [&a, &b] {
        assert_eq!(h.status(), InstanceStatus::Funded);
        assert!(h.outputs().is_empty());
        assert!(h.spending_args().is_none());
    }
}

#[test]
fn aggregate_amount_overflow_returns_an_error() {
    let a = pay(sat(u64::MAX), 1);
    let b = pay(sat(1), 2);
    let tx = transaction(
        &[&a, &b],
        vec![TxOut {
            value: sat(u64::MAX),
            script_pubkey: script(),
        }],
    );
    let mut manager = manager();
    assert!(matches!(
        manager.observe_batch(&[&a, &b], &tx),
        Err(ManagerError::AmountOverflow)
    ));
    untouched(&manager, &[&a, &b]);
}
