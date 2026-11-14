//! Manager behavior and integration boundaries, tested without a Bitcoin node.
use super::validation::parse_script_path_witness;
use crate::chain::poll_until;
use crate::contracts::{
    ContractError, ErasedContract, InstanceStatus, NextOutputs, StateCommitment,
};
use crate::signer::Signer;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey};
use bitcoincore_rpc::Client;
use std::{rc::Rc, time::Duration};

#[path = "tests/architecture_tests.rs"]
mod architecture_tests;
#[path = "tests/wallet_tests.rs"]
mod wallet_tests;

use super::*;
use crate::contracts::{
    ClauseOutput, ClauseTree, CtvTemplate, NextOutputsFn, RawArgs, StandardClause, StandardP2TR,
};
use crate::testutil::fund_fake;
use bitcoin::ScriptBuf;
use std::sync::Arc;

fn offline_manager() -> ContractManager {
    ContractManager::offline(bitcoin::Network::Regtest)
}

/// A one-request RPC endpoint: acknowledge and return the broadcast tx.
fn broadcast_rpc() -> (Client, std::thread::JoinHandle<Transaction>) {
    broadcast_rpc_with_error(None)
}

fn broadcast_rpc_with_error(
    error: Option<serde_json::Value>,
) -> (Client, std::thread::JoinHandle<Transaction>) {
    use std::io::{BufRead, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = std::io::BufReader::new(&mut stream);
        let mut len = None;
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                len = Some(value.trim().parse::<usize>().unwrap());
            }
        }
        let mut body = vec![0; len.unwrap()];
        reader.read_exact(&mut body).unwrap();
        let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["method"], "sendrawtransaction");
        let tx: Transaction = bitcoin::consensus::deserialize(
            &hex::decode(request["params"][0].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let result = if error.is_some() {
            serde_json::Value::Null
        } else {
            serde_json::json!(tx.compute_txid().to_string())
        };
        let response = serde_json::json!({ "result": result, "error": error, "id": request["id"] })
            .to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.len(),
            response
        )
        .unwrap();
        tx
    });
    (
        Client::new(&url, bitcoincore_rpc::Auth::None).unwrap(),
        server,
    )
}

struct CountingSigner {
    calls: Rc<std::cell::Cell<usize>>,
    signer: crate::signer::HotSigner,
}

impl Signer for CountingSigner {
    fn public_key(&self) -> XOnlyPublicKey {
        self.signer.public_key()
    }
    fn sign(&self, hash: &[u8; 32]) -> Result<crate::Signature, crate::signer::SignerError> {
        self.calls.set(self.calls.get() + 1);
        self.signer.sign(hash)
    }
}

fn signed_spend_fixture(child: bool) -> (InstanceHandle, SpendBuilder, Rc<std::cell::Cell<usize>>) {
    signed_spend_with_constraint(child, None)
}

fn signed_spend_with_constraint(
    child: bool,
    constraint: Option<NextOutputs>,
) -> (InstanceHandle, SpendBuilder, Rc<std::cell::Cell<usize>>) {
    signed_spend_seeded(child, constraint, 1)
}

/// The signed-spend fixture funded at the outpoint keyed by `seed`, so two of
/// them can share a transaction.
fn signed_spend_seeded(
    child: bool,
    constraint: Option<NextOutputs>,
    seed: u8,
) -> (InstanceHandle, SpendBuilder, Rc<std::cell::Cell<usize>>) {
    let calls = Rc::new(std::cell::Cell::new(0));
    let signer = CountingSigner {
        calls: calls.clone(),
        signer: crate::signer::HotSigner::new(
            bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &[42]).unwrap(),
        ),
    };
    let pk = signer.public_key();
    let dest = test_contract(90, None);
    let next = if child {
        vec![ClauseOutput::at(0).to(dest.clone()).build()]
    } else {
        vec![]
    };
    let next = constraint.unwrap_or(NextOutputs::Outputs(next));
    let clause = StandardClause::<(), (), RawArgs>::new(
        "spend".into(),
        bitcoin::script::Builder::new()
            .push_x_only_key(&pk)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script(),
        vec![crate::contracts::ArgSpec {
            name: "sig".into(),
            arg_type: Arc::new(crate::argtypes::SignerType::new(pk)),
        }],
        Some(Arc::new(move |_, _, _| Ok(next.clone()))),
    );
    let c = Arc::new(
        StandardP2TR::<_>::new(
            "Signed",
            crate::nums_key(),
            &(),
            ClauseTree::leaf(Arc::new(clause)),
        )
        .unwrap(),
    );
    let h = fund_fake(c, (), sat(10_000), seed);
    let mut builder = h.spend_clause("spend", vec![vec![]]).sign(signer);
    if !child {
        builder = builder.outputs(vec![TxOut {
            value: sat(9_000),
            script_pubkey: spk_of(&dest),
        }]);
    }
    (h, builder, calls)
}

#[test]
fn child_count_errors_do_not_request_signatures() {
    let (_, builder, calls) = signed_spend_fixture(false);
    assert!(matches!(
        builder.exec_one::<InstanceHandle>(&mut offline_manager()),
        Err(ManagerError::UnexpectedOutputCount {
            expected: 1,
            got: 0
        })
    ));
    assert_eq!(calls.get(), 0);
    let (_, builder, calls) = signed_spend_fixture(true);
    assert!(matches!(
        builder.exec_none(&mut offline_manager()),
        Err(ManagerError::UnexpectedOutputCount {
            expected: 0,
            got: 1
        })
    ));
    assert_eq!(calls.get(), 0);
}

#[test]
fn template_hash_is_checked_before_signing_and_executes_without_children() {
    let (_, builder, _) = signed_spend_fixture(false);
    let hash =
        crate::ctv::compute_ctv_hash(builder.explicit_outputs.as_ref().unwrap(), Sequence::ZERO);
    let (_, invalid, calls) =
        signed_spend_with_constraint(false, Some(NextOutputs::TemplateHash(hash)));
    let err = invalid
        .sequence(1)
        .exec_none(&mut offline_manager())
        .unwrap_err();
    assert!(matches!(
        err,
        ManagerError::CtvTemplateMismatch { input_index: 0 }
    ));
    assert_eq!(calls.get(), 0);

    let (h, valid, calls) =
        signed_spend_with_constraint(false, Some(NextOutputs::TemplateHash(hash)));
    let (rpc, server) = broadcast_rpc();
    let mut manager = ContractManager::new(rpc, bitcoin::Network::Regtest);
    valid.exec_none(&mut manager).unwrap();
    let tx = server.join().unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(h.status(), InstanceStatus::Spent);
    assert!(h.outputs().is_empty());
    assert_eq!(
        h.spend_record().unwrap().args()[0],
        tx.input[0].witness.to_vec()[0]
    );
}

/// Asking `exec_one` for the wrong contract's handle is refused before the
/// broadcast (which, with no node behind the manager, would report `NoNode`),
/// so the error never comes with a spent instance.
#[test]
fn exec_one_rejects_a_wrong_handle_type_before_broadcast() {
    #[derive(Debug)]
    struct OtherHandle;
    impl TryFrom<InstanceHandle> for OtherHandle {
        type Error = crate::manager::WrongContractType;
        fn try_from(_: InstanceHandle) -> Result<Self, Self::Error> {
            Err(crate::manager::WrongContractType { expected: "Other" })
        }
    }

    let mut manager = offline_manager();
    let (handle, builder, _) = signed_spend_fixture(true);
    assert!(matches!(
        builder.exec_one::<OtherHandle>(&mut manager),
        Err(ManagerError::WrongContract(_))
    ));
    assert_eq!(handle.status(), InstanceStatus::Funded);
    assert!(handle.outputs().is_empty());
    assert!(manager.instances.is_empty());
}

/// The handle `exec_one` returns is the child the manager registered.
#[test]
fn exec_one_returns_the_registered_child() {
    let (handle, builder, _) = signed_spend_fixture(true);
    let (rpc, server) = broadcast_rpc();
    let mut manager = ContractManager::new(rpc, bitcoin::Network::Regtest);
    let child: InstanceHandle = builder.exec_one(&mut manager).unwrap();
    server.join().unwrap();
    assert_eq!(handle.outputs().into_vec(), vec![child.clone()]);
    assert!(Rc::ptr_eq(&child.instance, &manager.instances[0]));
}

#[test]
fn checked_execution_signs_once_and_records_the_broadcast_witness() {
    for child in [false, true] {
        let (h, builder, calls) = signed_spend_fixture(child);
        let (rpc, server) = broadcast_rpc();
        let mut manager = ContractManager::new(rpc, bitcoin::Network::Regtest);
        if child {
            builder.exec_one::<InstanceHandle>(&mut manager).unwrap();
        } else {
            builder.exec_none(&mut manager).unwrap();
        }
        let tx = server.join().unwrap();
        assert_eq!(calls.get(), 1);
        let record = h.spend_record().unwrap();
        let recorded = record.args();
        assert_eq!(recorded[0], tx.input[0].witness.to_vec()[0]);
        assert_eq!(recorded[0].len(), 64);

        let (observer, _, _) = signed_spend_fixture(child);
        offline_manager().observe_spend(&observer, &tx).unwrap();
        assert_eq!(observer.spend_record(), h.spend_record());
    }
}

#[test]
fn payment_checks_run_before_signing_and_execution_tracks_no_children() {
    use crate::contracts::ClauseOutput;
    let (_, fixture, _) = signed_spend_fixture(false);
    let script = fixture.explicit_outputs.unwrap()[0].script_pubkey.clone();
    let next = NextOutputs::from(ClauseOutput::at(0).pay(script.clone()));
    let (_, invalid, calls) = signed_spend_with_constraint(false, Some(next.clone()));
    // The fixture supplies only 9,000 of the required 10,000 sats.
    assert!(invalid.exec_none(&mut offline_manager()).is_err());
    assert_eq!(calls.get(), 0);

    let (h, valid, calls) = signed_spend_with_constraint(false, Some(next.clone()));
    let (rpc, server) = broadcast_rpc();
    let mut manager = ContractManager::new(rpc, bitcoin::Network::Regtest);
    valid
        .outputs(vec![TxOut {
            value: sat(10_000),
            script_pubkey: script,
        }])
        .exec_none(&mut manager)
        .unwrap();
    let tx = server.join().unwrap();
    assert_eq!(calls.get(), 1);
    assert!(h.outputs().is_empty());
    let (observer, _, _) = signed_spend_with_constraint(false, Some(next));
    assert!(
        offline_manager()
            .observe_spend(&observer, &tx)
            .unwrap()
            .is_empty()
    );
    assert_eq!(observer.spend_record(), h.spend_record());
}

#[test]
fn payments_cannot_conflict_with_contract_tracking_or_join_targets() {
    use crate::contracts::ClauseOutput;
    let dest = test_contract(90, None);
    let payment = ClauseOutput::at(0).pay(spk_of(&dest));
    let paid = test_contract(1, Some(Arc::new(move |_, _, _| Ok(payment.clone().into()))));
    let h1 = fund_fake(paid, (), sat(10_000), 1);
    let tracked = contract_yielding(2, vec![ClauseOutput::at(0).to(dest).build()]);
    let h2 = fund_fake(tracked, (), sat(10_000), 2);
    assert!(matches!(
        crate::manager::build_batch_tx(&[spend(&h1), spend(&h2)]),
        Err(ManagerError::ConflictingOutputContract { index: 0 })
    ));
    let joining = test_contract(3, Some(Arc::new(|_, _, _| Ok(NextOutputs::join(0)))));
    let h3 = fund_fake(joining, (), sat(10_000), 3);
    assert!(matches!(
        crate::manager::build_batch_tx(&[spend(&h1), spend(&h3)]),
        Err(ManagerError::JoinWithoutTarget { index: 0 })
    ));
}

#[test]
fn a_payment_can_share_a_transaction_but_not_tracking_with_a_contract() {
    use crate::contracts::ClauseOutput;
    let dest = test_contract(90, None);
    let payment = ClauseOutput::at(1).pay(spk_of(&dest));
    let paid = test_contract(1, Some(Arc::new(move |_, _, _| Ok(payment.clone().into()))));
    let h1 = fund_fake(paid, (), sat(10_000), 1);
    let tracked = contract_yielding(2, vec![ClauseOutput::at(0).to(dest).build()]);
    let h2 = fund_fake(tracked, (), sat(20_000), 2);
    let mut manager = offline_manager();
    let tx = crate::manager::build_batch_tx(&[spend(&h1), spend(&h2)]).unwrap();
    assert_eq!(
        tx.output
            .iter()
            .map(|output| output.value)
            .collect::<Vec<_>>(),
        vec![sat(20_000), sat(10_000)]
    );
    assert!(manager.observe_spend(&h1, &tx).unwrap().is_empty());
    assert_eq!(manager.observe_spend(&h2, &tx).unwrap().len(), 1);
    assert!(h1.outputs().is_empty());
    assert_eq!(h2.outputs()[0].outpoint().vout, 0);
}

fn sat(n: u64) -> Amount {
    Amount::from_sat(n)
}

/// A single-clause (`"spend"`) contract for exercising the output derivation:
/// the clause takes no arguments and yields `next_outputs_fn`'s result when
/// spent (terminal when `None`). `tag` differentiates the script — and thus
/// the address — of otherwise identical contracts.
fn test_contract(
    tag: i64,
    next_outputs_fn: Option<NextOutputsFn<(), (), RawArgs>>,
) -> Arc<dyn ErasedContract> {
    test_contract_with_identity::<StandardP2TR<()>>(tag, next_outputs_fn)
}

fn test_contract_with_identity<I: 'static>(
    tag: i64,
    next_outputs_fn: Option<NextOutputsFn<(), (), RawArgs>>,
) -> Arc<dyn ErasedContract> {
    let script = bitcoin::script::Builder::new()
        .push_int(tag)
        .push_opcode(bitcoin::opcodes::all::OP_DROP)
        .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
        .into_script();
    let clause = StandardClause::<(), (), RawArgs>::new(
        "spend".to_string(),
        script,
        vec![],
        next_outputs_fn,
    );
    Arc::new(
        StandardP2TR::<_>::new_with_identity::<I>(
            "Test",
            crate::nums_key(),
            &(),
            ClauseTree::leaf(Arc::new(clause)),
        )
        .expect("test contract is valid"),
    )
}

/// A contract whose clause produces exactly `outputs` when spent.
fn contract_yielding(tag: i64, outputs: Vec<ClauseOutput>) -> Arc<dyn ErasedContract> {
    test_contract(
        tag,
        Some(Arc::new(move |_: &(), _: &RawArgs, _: &()| {
            Ok(NextOutputs::Outputs(outputs.clone()))
        })),
    )
}

/// A contract whose clause fixes the spending transaction via a CTV template.
fn contract_with_template(tag: i64, template: CtvTemplate) -> Arc<dyn ErasedContract> {
    test_contract(
        tag,
        Some(Arc::new(move |_: &(), _: &RawArgs, _: &()| {
            Ok(NextOutputs::Template(template.clone()))
        })),
    )
}

/// Begin a spend of the (only) clause of a [`test_contract`] instance.
fn spend(handle: &InstanceHandle) -> SpendBuilder {
    handle.spend_clause("spend", vec![])
}

fn spk_of(contract: &Arc<dyn ErasedContract>) -> ScriptBuf {
    contract.script_pubkey(&StateCommitment::empty()).unwrap()
}

// ------------------------------------------------------------------
// Output derivation (merging preserves/deducts across batch inputs)
// ------------------------------------------------------------------

#[test]
fn merges_preserves_and_deducts_across_inputs() {
    let unvault = test_contract(90, None);
    let revault = test_contract(91, None);
    // Input 0 revaults 30k (deduct at index 1) and preserves the rest into
    // index 0; input 1 preserves its whole amount into the same index 0.
    let c1 = contract_yielding(
        1,
        vec![
            ClauseOutput::at(1)
                .to(revault.clone())
                .deduct_amount()
                .build(),
            ClauseOutput::at(0)
                .to(unvault.clone())
                .preserve_amount()
                .build(),
        ],
    );
    let c2 = contract_yielding(
        2,
        vec![
            ClauseOutput::at(0)
                .to(unvault.clone())
                .preserve_amount()
                .build(),
        ],
    );
    let h1 = fund_fake(c1, (), sat(100_000), 1);
    let h2 = fund_fake(c2, (), sat(60_000), 2);

    let tx =
        crate::manager::build_batch_tx(&[spend(&h1).output_amount(1, sat(30_000)), spend(&h2)])
            .unwrap();

    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    // index 0: (100k - 30k) + 60k merged; index 1: the deducted revault.
    assert_eq!(tx.output[0].value, sat(130_000));
    assert_eq!(tx.output[0].script_pubkey, spk_of(&unvault));
    assert_eq!(tx.output[1].value, sat(30_000));
    assert_eq!(tx.output[1].script_pubkey, spk_of(&revault));
}

#[test]
fn join_contributes_to_another_inputs_output() {
    let dest = test_contract(90, None);
    let defining = contract_yielding(
        1,
        vec![
            ClauseOutput::at(0)
                .to(dest.clone())
                .preserve_amount()
                .build(),
        ],
    );
    let joining = test_contract(
        2,
        Some(Arc::new(|_: &(), _: &RawArgs, _: &()| {
            Ok(NextOutputs::join(0))
        })),
    );
    let hd = fund_fake(defining, (), sat(100_000), 1);
    let hj = fund_fake(joining, (), sat(60_000), 2);

    // Both orders: the join is resolved after all defining inputs.
    for builders in [[spend(&hd), spend(&hj)], [spend(&hj), spend(&hd)]] {
        let tx = crate::manager::build_batch_tx(&builders).unwrap();
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, sat(160_000));
        assert_eq!(tx.output[0].script_pubkey, spk_of(&dest));
    }
}

#[test]
fn join_without_target_errors() {
    let joining = test_contract(
        1,
        Some(Arc::new(|_: &(), _: &RawArgs, _: &()| {
            Ok(NextOutputs::join(0))
        })),
    );
    let h = fund_fake(joining, (), sat(60_000), 1);
    let err = crate::manager::build_batch_tx(&[spend(&h)]).unwrap_err();
    assert!(matches!(err, ManagerError::JoinWithoutTarget { index: 0 }));
}

#[test]
fn join_into_a_deduct_output_errors() {
    let dest = test_contract(90, None);
    let deducting = contract_yielding(
        1,
        vec![ClauseOutput::at(0).to(dest.clone()).deduct_amount().build()],
    );
    let joining = test_contract(
        2,
        Some(Arc::new(|_: &(), _: &RawArgs, _: &()| {
            Ok(NextOutputs::join(0))
        })),
    );
    let hd = fund_fake(deducting, (), sat(100_000), 1);
    let hj = fund_fake(joining, (), sat(60_000), 2);
    let err =
        crate::manager::build_batch_tx(&[spend(&hd).output_amount(0, sat(10_000)), spend(&hj)])
            .unwrap_err();
    assert!(matches!(
        err,
        ManagerError::MixedOutputSemantics { index: 0 }
    ));
}

/// A defining input and a joining input funded and batched, for the
/// observation-order tests.
fn join_fixture() -> (InstanceHandle, InstanceHandle) {
    let dest = test_contract(90, None);
    let defining = contract_yielding(
        1,
        vec![ClauseOutput::at(0).to(dest).preserve_amount().build()],
    );
    let joining = test_contract(
        2,
        Some(Arc::new(|_: &(), _: &RawArgs, _: &()| {
            Ok(NextOutputs::join(0))
        })),
    );
    (
        fund_fake(defining, (), sat(100_000), 1),
        fund_fake(joining, (), sat(60_000), 2),
    )
}

#[test]
fn join_link_survives_observation_order() {
    let (hd, hj) = join_fixture();
    let mut manager = offline_manager();
    let tx = crate::manager::build_batch_tx(&[spend(&hd), spend(&hj)]).unwrap();

    // The joining input observed first: the shared child does not exist yet.
    assert!(manager.observe_spend(&hj, &tx).unwrap().is_empty());
    // The defining input's observation materializes it...
    let children = manager.observe_spend(&hd, &tx).unwrap();
    assert_eq!(children.len(), 1);
    // ...and re-observing the joining input repairs its link.
    let relinked = manager.observe_spend(&hj, &tx).unwrap();
    assert_eq!(relinked.len(), 1);
    assert_eq!(relinked[0], children[0]);
    assert_eq!(hj.outputs().len(), 1);
    // A further re-observation serves the cached link, without duplicating it.
    assert_eq!(manager.observe_spend(&hj, &tx).unwrap().len(), 1);
    assert_eq!(hj.outputs().len(), 1);
}

#[test]
fn apply_batch_links_joins_regardless_of_parent_order() {
    let (hd, hj) = join_fixture();
    let mut manager = offline_manager();
    // The joining parent listed first must not lose its link to the child.
    let (_, children) =
        crate::testutil::apply_batch(&mut manager, &[&hj, &hd], &[spend(&hd), spend(&hj)]).unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(hd.outputs().len(), 1);
    assert_eq!(hj.outputs().len(), 1);
}

#[test]
fn second_preserve_in_one_input_errors() {
    let dest_a = test_contract(90, None);
    let dest_b = test_contract(91, None);
    // One input cannot preserve its remaining amount into two outputs.
    let c = contract_yielding(
        1,
        vec![
            ClauseOutput::at(0).to(dest_a).preserve_amount().build(),
            ClauseOutput::at(1).to(dest_b).preserve_amount().build(),
        ],
    );
    let h = fund_fake(c, (), sat(100_000), 1);

    let err = crate::manager::build_batch_tx(&[spend(&h)]).unwrap_err();
    assert!(
        matches!(&err, ManagerError::InvalidSpend(msg) if msg.contains("PreserveOutput")),
        "unexpected error: {err:?}"
    );
}

#[test]
fn mixing_preserve_and_deduct_at_same_index_errors() {
    let dest = test_contract(90, None);
    let preserving = contract_yielding(
        1,
        vec![
            ClauseOutput::at(0)
                .to(dest.clone())
                .preserve_amount()
                .build(),
        ],
    );
    let deducting = contract_yielding(
        2,
        vec![ClauseOutput::at(0).to(dest.clone()).deduct_amount().build()],
    );
    let hp = fund_fake(preserving, (), sat(100_000), 1);
    let hd = fund_fake(deducting, (), sat(50_000), 2);

    // Preserve first, deduct second — and the other way around.
    let err =
        crate::manager::build_batch_tx(&[spend(&hp), spend(&hd).output_amount(0, sat(10_000))])
            .unwrap_err();
    assert!(matches!(
        err,
        ManagerError::MixedOutputSemantics { index: 0 }
    ));

    let err =
        crate::manager::build_batch_tx(&[spend(&hd).output_amount(0, sat(10_000)), spend(&hp)])
            .unwrap_err();
    assert!(matches!(
        err,
        ManagerError::MixedOutputSemantics { index: 0 }
    ));
}

#[test]
fn merged_output_requires_one_contract_identity() {
    struct First;
    struct Second;

    let first = test_contract_with_identity::<First>(90, None);
    let second = test_contract_with_identity::<Second>(90, None);
    assert_eq!(spk_of(&first), spk_of(&second));

    let c1 = contract_yielding(
        1,
        vec![ClauseOutput::at(0).to(first).preserve_amount().build()],
    );
    let c2 = contract_yielding(
        2,
        vec![ClauseOutput::at(0).to(second).preserve_amount().build()],
    );
    let h1 = fund_fake(c1, (), sat(50_000), 1);
    let h2 = fund_fake(c2, (), sat(50_000), 2);

    let err = crate::manager::build_batch_tx(&[spend(&h1), spend(&h2)]).unwrap_err();
    assert!(matches!(
        err,
        ManagerError::ConflictingOutputContract { index: 0 }
    ));
}

#[test]
fn observation_validates_child_outputs_before_marking_spent() {
    let destination = test_contract(90, None);
    let parent = contract_yielding(
        1,
        vec![
            ClauseOutput::at(0)
                .to(destination)
                .preserve_amount()
                .build(),
        ],
    );
    let handle = fund_fake(parent, (), sat(50_000), 1);
    let mut manager = offline_manager();
    let valid = spend(&handle).build_tx().unwrap();

    let mut wrong_script = valid.clone();
    wrong_script.output[0].script_pubkey = ScriptBuf::new();
    let err = manager.observe_spend(&handle, &wrong_script).unwrap_err();
    assert!(matches!(err, ManagerError::WrongContractOutput(_)));
    assert_eq!(handle.status(), InstanceStatus::Funded);
    assert!(handle.outputs().is_empty());

    let mut missing = valid;
    missing.output.clear();
    let err = manager.observe_spend(&handle, &missing).unwrap_err();
    assert!(matches!(err, ManagerError::MissingContractOutput(_)));
    assert_eq!(handle.status(), InstanceStatus::Funded);
    assert!(handle.outputs().is_empty());
}

#[test]
fn child_state_must_match_the_destination_contract() {
    // The destination is stateless (state type `()`); handing it any other
    // state type must fail before a transaction is built.
    #[derive(Debug, Clone)]
    struct Stray;
    impl crate::contracts::ContractState for Stray {
        fn commitment(&self) -> crate::contracts::StateCommitment {
            crate::contracts::StateCommitment::identity([7u8; 32])
        }
    }
    let stateless = test_contract(90, None);
    let parent = contract_yielding(
        1,
        vec![
            ClauseOutput::at(0)
                .to(stateless)
                .with_state(&Stray)
                .preserve_amount()
                .build(),
        ],
    );
    let handle = fund_fake(parent, (), sat(50_000), 1);

    let err = spend(&handle).build_tx().unwrap_err();
    assert!(matches!(
        err,
        ManagerError::Contract(ContractError::WrongStateType)
    ));
}

#[test]
fn unused_output_amount_errors() {
    let dest = test_contract(90, None);
    let c = contract_yielding(
        1,
        vec![ClauseOutput::at(0).to(dest).preserve_amount().build()],
    );
    let h = fund_fake(c, (), sat(100_000), 1);

    let err =
        crate::manager::build_batch_tx(&[spend(&h).output_amount(1, sat(10_000))]).unwrap_err();
    assert!(matches!(err, ManagerError::UnusedOutputAmount { index: 1 }));
}

#[test]
fn missing_deduct_amount_errors() {
    let dest = test_contract(90, None);
    let c = contract_yielding(
        1,
        vec![ClauseOutput::at(0).to(dest).deduct_amount().build()],
    );
    let h = fund_fake(c, (), sat(100_000), 1);

    let err = crate::manager::build_batch_tx(&[spend(&h)]).unwrap_err();
    assert!(matches!(
        err,
        ManagerError::MissingDeductAmount { index: 0 }
    ));
}

#[test]
fn ignore_output_requires_an_explicit_amount() {
    let dest = test_contract(90, None);
    let c = contract_yielding(
        1,
        vec![ClauseOutput::at(0).to(dest).ignore_amount().build()],
    );
    let h = fund_fake(c, (), sat(100_000), 1);

    let err = crate::manager::build_batch_tx(&[spend(&h)]).unwrap_err();
    assert!(matches!(
        err,
        ManagerError::MissingIgnoredAmount { index: 0 }
    ));

    let tx = crate::manager::build_batch_tx(&[spend(&h).output_amount(0, sat(25_000))]).unwrap();
    assert_eq!(tx.output[0].value, sat(25_000));
}

#[test]
fn deduct_exceeding_input_errors() {
    let dest = test_contract(90, None);
    let c = contract_yielding(
        1,
        vec![ClauseOutput::at(0).to(dest).deduct_amount().build()],
    );
    let h = fund_fake(c, (), sat(50_000), 1);

    let err =
        crate::manager::build_batch_tx(&[spend(&h).output_amount(0, sat(60_000))]).unwrap_err();
    assert!(matches!(err, ManagerError::DeductExceedsInput));
}

#[test]
fn conflicting_output_amounts_error() {
    let dest = test_contract(90, None);
    let deducting = |tag, seed| {
        let c = contract_yielding(
            tag,
            vec![ClauseOutput::at(0).to(dest.clone()).deduct_amount().build()],
        );
        fund_fake(c, (), sat(100_000), seed)
    };
    let h1 = deducting(1, 1);
    let h2 = deducting(2, 2);

    let err = crate::manager::build_batch_tx(&[
        spend(&h1).output_amount(0, sat(10_000)),
        spend(&h2).output_amount(0, sat(20_000)),
    ])
    .unwrap_err();
    assert!(matches!(
        err,
        ManagerError::ConflictingOutputAmount { index: 0 }
    ));
}

#[test]
fn non_contiguous_outputs_error() {
    let dest = test_contract(90, None);
    let c = contract_yielding(
        1,
        vec![ClauseOutput::at(1).to(dest).preserve_amount().build()],
    );
    let h = fund_fake(c, (), sat(100_000), 1);

    let err = crate::manager::build_batch_tx(&[spend(&h)]).unwrap_err();
    assert!(matches!(
        err,
        ManagerError::NonContiguousOutputs { missing_index: 0 }
    ));
}

#[test]
fn terminal_clause_without_explicit_outputs_errors() {
    let c = test_contract(1, None);
    let h = fund_fake(c, (), sat(100_000), 1);

    let err = crate::manager::build_batch_tx(&[spend(&h)]).unwrap_err();
    assert!(matches!(err, ManagerError::NoOutputs));
}

// ------------------------------------------------------------------
// CTV templates and explicit outputs

#[test]
fn empty_outputs_are_rejected_even_for_childless_spends() {
    let template = CtvTemplate::new(vec![], Sequence::ZERO);
    for next in [
        NextOutputs::Outputs(vec![]),
        NextOutputs::Template(template.clone()),
        NextOutputs::TemplateHash(template.ctv_hash()),
    ] {
        let explicit = !matches!(next, NextOutputs::Template(_));
        let c = test_contract(1, Some(Arc::new(move |_, _, _| Ok(next.clone()))));
        let h = fund_fake(c, (), sat(10_000), 1);
        let builder = spend(&h);
        let builder = if explicit {
            builder.outputs(vec![])
        } else {
            builder
        };
        assert!(matches!(builder.build_tx(), Err(ManagerError::NoOutputs)));
    }
}
// ------------------------------------------------------------------

fn template_to(dest: &Arc<dyn ErasedContract>, amount: Amount, sequence: u32) -> CtvTemplate {
    CtvTemplate::new(
        vec![TxOut {
            script_pubkey: spk_of(dest),
            value: amount,
        }],
        Sequence(sequence),
    )
}

#[test]
fn template_fixes_outputs_and_sequence() {
    let dest = test_contract(90, None);
    let template = template_to(&dest, sat(50_000), 5);
    let c = contract_with_template(1, template.clone());
    let h = fund_fake(c, (), sat(50_000), 1);

    let tx = spend(&h).build_tx().unwrap();
    assert_eq!(tx.output, template.outputs);
    assert_eq!(tx.input[0].sequence, Sequence(5));

    // A caller-set sequence must agree with the template's...
    let tx = spend(&h).sequence(5).build_tx().unwrap();
    assert_eq!(tx.input[0].sequence, Sequence(5));

    // ...or the build is rejected.
    let err = spend(&h).sequence(6).build_tx().unwrap_err();
    assert!(matches!(err, ManagerError::InvalidSpend(_)));
}

#[test]
fn template_in_batch_errors() {
    let dest = test_contract(90, None);
    let templated = contract_with_template(1, template_to(&dest, sat(50_000), 0));
    let preserving = contract_yielding(
        2,
        vec![
            ClauseOutput::at(0)
                .to(dest.clone())
                .preserve_amount()
                .build(),
        ],
    );
    let h1 = fund_fake(templated, (), sat(50_000), 1);
    let h2 = fund_fake(preserving, (), sat(60_000), 2);

    let err = crate::manager::build_batch_tx(&[spend(&h1), spend(&h2)]).unwrap_err();
    assert!(matches!(err, ManagerError::InvalidSpend(_)));
}

#[test]
fn explicit_outputs_in_batch_error() {
    let dest = test_contract(90, None);
    let preserving = |tag, seed| {
        let c = contract_yielding(
            tag,
            vec![
                ClauseOutput::at(0)
                    .to(dest.clone())
                    .preserve_amount()
                    .build(),
            ],
        );
        fund_fake(c, (), sat(100_000), seed)
    };
    let h1 = preserving(1, 1);
    let h2 = preserving(2, 2);
    let outputs = vec![TxOut {
        script_pubkey: spk_of(&dest),
        value: sat(100_000),
    }];

    let err =
        crate::manager::build_batch_tx(&[spend(&h1).outputs(outputs), spend(&h2)]).unwrap_err();
    assert!(matches!(err, ManagerError::InvalidSpend(_)));
}

#[test]
fn explicit_outputs_cannot_override_a_template() {
    let dest = test_contract(90, None);
    let c = contract_with_template(1, template_to(&dest, sat(50_000), 0));
    let h = fund_fake(c, (), sat(50_000), 1);

    let err = crate::manager::build_batch_tx(&[spend(&h).outputs(vec![TxOut {
        script_pubkey: spk_of(&dest),
        value: sat(40_000),
    }])])
    .unwrap_err();
    assert!(matches!(err, ManagerError::InvalidSpend(_)));
}

#[test]
fn explicit_outputs_cannot_override_contract_outputs() {
    let dest = test_contract(90, None);
    let c = contract_yielding(
        1,
        vec![
            ClauseOutput::at(0)
                .to(dest.clone())
                .preserve_amount()
                .build(),
        ],
    );
    let h = fund_fake(c, (), sat(50_000), 1);

    let err = crate::manager::build_batch_tx(&[spend(&h).outputs(vec![TxOut {
        script_pubkey: spk_of(&dest),
        value: sat(1),
    }])])
    .unwrap_err();
    assert!(matches!(err, ManagerError::InvalidSpend(_)));
}

#[test]
fn observation_rejects_a_ctv_template_mismatch() {
    let dest = test_contract(90, None);
    let c = contract_with_template(1, template_to(&dest, sat(50_000), 5));
    let h = fund_fake(c, (), sat(50_000), 1);
    let mut manager = offline_manager();
    let tx = spend(&h).build_tx().unwrap();
    let mut wrong_amount = tx.clone();
    wrong_amount.output[0].value = sat(49_999);
    let mut wrong_script_sig = tx.clone();
    wrong_script_sig.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
    for invalid in [wrong_amount, wrong_script_sig] {
        let err = manager.observe_spend(&h, &invalid).unwrap_err();
        assert!(matches!(
            err,
            ManagerError::CtvTemplateMismatch { input_index: 0 }
        ));
        assert_eq!(h.status(), InstanceStatus::Funded);
    }
    assert!(manager.observe_spend(&h, &tx).unwrap().is_empty());
}

#[test]
fn raw_witness_layout_is_checked_when_no_signer_exists() {
    let c = test_contract(1, None);
    let h = fund_fake(c, (), sat(50_000), 1);
    let err = h
        .spend_clause("spend", vec![vec![1]])
        .outputs(vec![TxOut {
            script_pubkey: ScriptBuf::new(),
            value: sat(50_000),
        }])
        .build_tx()
        .unwrap_err();
    assert!(matches!(err, ManagerError::Witness(_)));
}

#[test]
fn duplicate_instance_in_batch_errors() {
    let dest = test_contract(90, None);
    let c = contract_yielding(
        1,
        vec![ClauseOutput::at(0).to(dest).preserve_amount().build()],
    );
    let h = fund_fake(c, (), sat(100_000), 1);

    let err = crate::manager::build_batch_tx(&[spend(&h), spend(&h)]).unwrap_err();
    assert!(
        matches!(&err, ManagerError::InvalidSpend(msg) if msg.contains("duplicate")),
        "unexpected error: {err:?}"
    );
}

// ------------------------------------------------------------------
// Witness parsing and polling
// ------------------------------------------------------------------

#[test]
fn parses_script_path_witness() {
    let arg = vec![1u8, 2, 3];
    let script = vec![0x51u8];
    let control_block = vec![0xc0u8; 33];

    // args + script + control block
    let witness =
        bitcoin::Witness::from_slice(&[arg.clone(), script.clone(), control_block.clone()]);
    let parsed = parse_script_path_witness(&witness).unwrap();
    assert_eq!(parsed.args, vec![arg.clone()]);
    assert_eq!(parsed.leaf_script, script);
    assert_eq!(parsed.control_block, control_block);

    // ... with a trailing annex: the annex is dropped.
    let annex = vec![0x50u8, 0xff];
    let witness = bitcoin::Witness::from_slice(&[
        arg.clone(),
        script.clone(),
        control_block.clone(),
        annex.clone(),
    ]);
    let parsed = parse_script_path_witness(&witness).unwrap();
    assert_eq!(parsed.args, vec![arg]);
    assert_eq!(parsed.leaf_script, script);
    assert_eq!(parsed.control_block, control_block);

    // a zero-argument clause: just script + control block.
    let witness = bitcoin::Witness::from_slice(&[script.clone(), control_block]);
    let parsed = parse_script_path_witness(&witness).unwrap();
    assert!(parsed.args.is_empty());
    assert_eq!(parsed.leaf_script, script);

    // Key-path spends (with or without an annex) carry no tapscript.
    let sig = vec![0xaau8; 64];
    for elements in [vec![sig.clone()], vec![sig, annex]] {
        let witness = bitcoin::Witness::from_slice(&elements);
        let err = parse_script_path_witness(&witness).unwrap_err();
        assert!(matches!(err, ManagerError::UnrecognizedSpend(_)));
    }
}

#[test]
fn poll_until_returns_hit_or_times_out() {
    // An immediate hit is returned without waiting for the window.
    let hit = poll_until(Some(Duration::ZERO), || Ok::<_, ManagerError>(Some(42))).unwrap();
    assert_eq!(hit, Some(42));

    // A never-satisfied check times out with Ok(None).
    let miss = poll_until(Some(Duration::ZERO), || Ok::<_, ManagerError>(None::<i32>)).unwrap();
    assert_eq!(miss, None);

    // Errors from the check propagate immediately.
    let err = poll_until(Some(Duration::ZERO), || {
        Err::<Option<i32>, _>(ManagerError::Other("boom".to_string()))
    })
    .unwrap_err();
    assert!(matches!(err, ManagerError::Other(_)));
}

#[test]
fn batch_accounting_reports_a_missing_output_instead_of_panicking() {
    use super::validation::{
        InputConstraints, OutputIdentity, ResolvedOutput, validate_batch_constraints,
    };
    use crate::contracts::{AmountMode, CcvIndex};

    let script = ScriptBuf::from(vec![0x51u8]);
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            script_pubkey: script.clone(),
            value: Amount::from_sat(1_000),
        }],
    };
    // Both amount modes read the output's value; index 3 does not exist.
    for amount in [AmountMode::Preserve, AmountMode::Deduct] {
        let outputs = [ResolvedOutput {
            index: CcvIndex::from(3u16),
            script_pubkey: script.clone(),
            amount,
            identity: OutputIdentity::Payment(script.clone()),
        }];
        let inputs = [InputConstraints {
            vin: 0,
            value: Amount::from_sat(1_000),
            outputs: &outputs,
            join: None,
        }];
        let err = validate_batch_constraints(&inputs, &tx).unwrap_err();
        assert!(
            matches!(err, ManagerError::MissingContractOutput(outpoint) if outpoint.vout == 3),
            "{err}"
        );
    }
}
