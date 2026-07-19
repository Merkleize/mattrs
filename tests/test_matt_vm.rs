//! MATT-VM tests.
//!
//! Offline: the interpreter and the off-chain computer closures are cross-pinned
//! (the closures must reproduce every `hs` commitment of every trace), and the
//! full dispute protocol — claim, challenge, bisection, leaf, forfaits — runs
//! over the deterministic `LocalChain`.
//!
//! `LocalChain` executes no scripts, so the *tapscripts* (the step re-run with
//! its two bound Merkle walks, the stage transitions) are validated by the
//! `#[ignore]`d regtest tests: the full dispute end-to-end, plus one direct
//! `Leaf` adjudication per instruction so every dispatch branch of the step
//! script runs through the node's interpreter at least once.

mod support;

use std::rc::Rc;
use std::time::Duration;

use bitcoin::Amount;
use mattrs::fraud::roles::{FraudOutcome, FraudResolution, FraudWinner};
use mattrs::manager::InstanceHandle;
use mattrs::protocol::{LocalChain, Progress, Runner};
use mattrs::script_helpers::key_path_p2tr as p2tr;

use support::matt_vm::computer::{n_elements, off_chain_computer, vm_computer};
use support::matt_vm::roles::{
    AliceVmData, BobVmData, VmOutcome, alice_vm_role, bob_vm_role, vm_fraud_data,
};
use support::matt_vm::stages::{FORFAIT_TIMEOUT, VmCtx, VmParams, VmS0};
use support::matt_vm::vm::{Fault, Insn, Machine, Op, VmError, VmSpec, fib_spec};
use support::testkit::{
    alice_pk, alice_xpriv, bob_pk, bob_xpriv, drive_both, fund_fake, offline_manager, walk_tip,
};

const AMOUNT: u64 = 20_000;
const SEED: u8 = 91;

/// The demo computation: fib over 64 traced steps.
fn spec() -> VmSpec {
    fib_spec(5, 64).expect("the demo spec is valid")
}

/// Replay the honest execution, returning `(instruction, acc before the step)`
/// per step.
fn replayed_steps(spec: &VmSpec) -> Vec<(Insn, i64)> {
    let mut machine = Machine::new(spec.mem0().to_vec());
    let mut steps = Vec::with_capacity(spec.n_steps());
    for _ in 0..spec.n_steps() {
        steps.push((spec.code()[machine.pc as usize], machine.acc));
        machine.step(spec.code()).expect("the demo spec runs clean");
    }
    steps
}

/// The first step satisfying `pred` on `(instruction, acc before the step)`.
fn first_step(spec: &VmSpec, pred: impl Fn(&Insn, i64) -> bool) -> usize {
    replayed_steps(spec)
        .iter()
        .position(|(insn, acc)| pred(insn, *acc))
        .expect("the demo trace contains the step")
}

/// The step the demo corrupts: the first `ADDM` (the Fibonacci addition).
fn fault_step(spec: &VmSpec) -> usize {
    first_step(spec, |insn, _| insn.op == Op::Addm)
}

// ============================================================================
// Interpreter and off-chain computer
// ============================================================================

#[test]
fn fib_program_computes_fib() {
    let trace = spec().trace().unwrap();
    // fib pairs from (0, 1), five iterations: (1,1) (1,2) (2,3) (3,5) (5,8).
    assert_eq!(trace.result(), 8);
    // The trace ends parked on the final HALT.
    assert_eq!(trace.machine.pc, 13);
    assert_eq!(trace.hs.len(), 65);
    assert_eq!(trace.xs.len(), 64);
}

#[test]
fn off_chain_computer_matches_interpreter() {
    // The load-bearing cross-pin: for every step of the honest trace, the
    // roles' closures reproduce the interpreter's commitments — encode(x_k) is
    // h_k, and encode(func(x_k)) is h_{k+1}. Every instruction of the ISA is
    // exercised (the fib program uses them all, JZ in both directions).
    let spec = spec();
    let trace = spec.trace().unwrap();
    let computer = off_chain_computer(&spec);
    for k in 0..spec.n_steps() {
        assert_eq!(
            (computer.encode)(&trace.xs[k]),
            trace.hs[k],
            "encode(x_{k}) != h_{k}"
        );
        let next = (computer.func)(&trace.xs[k]);
        assert_eq!(
            (computer.encode)(&next),
            trace.hs[k + 1],
            "encode(func(x_{k})) != h_{}",
            k + 1
        );
        assert_eq!(trace.xs[k].len(), n_elements(&spec));
        assert_eq!(next.len(), n_elements(&spec));
    }
}

#[test]
fn every_instruction_is_traced() {
    let steps = replayed_steps(&spec());
    for op in [Op::Addi, Op::Addm, Op::Load, Op::Store, Op::Jmp, Op::Jz, Op::Halt] {
        assert!(
            steps.iter().any(|(insn, _)| insn.op == op),
            "the demo trace never runs {op:?}"
        );
    }
    // ... and JZ in both directions.
    assert!(steps.iter().any(|(insn, acc)| insn.op == Op::Jz && *acc == 0));
    assert!(steps.iter().any(|(insn, acc)| insn.op == Op::Jz && *acc != 0));
}

#[test]
fn halt_padding_is_the_identity() {
    let trace = spec().trace().unwrap();
    // Once parked on HALT the commitment no longer changes.
    assert_eq!(trace.hs[63], trace.hs[64]);
}

#[test]
fn a_fault_diverges_exactly_after_its_step() {
    let spec = spec();
    let honest = spec.trace().unwrap();
    let step = fault_step(&spec);
    let cheat = spec.trace_with_fault(Some(Fault { step, delta: 1 })).unwrap();

    // Identical up to and including the disputed step's starting state...
    assert_eq!(honest.hs[..=step], cheat.hs[..=step]);
    // ...diverging right after it,
    assert_ne!(honest.hs[step + 1], cheat.hs[step + 1]);
    // and the claims differ.
    assert_ne!(honest.claim(), cheat.claim());

    // At the disputed step the parties share the input, and re-running it
    // yields the honest commitment: the cheater cannot win the leaf.
    assert_eq!(honest.xs[step], cheat.xs[step]);
    let computer = off_chain_computer(&spec);
    let rerun = (computer.encode)(&(computer.func)(&cheat.xs[step]));
    assert_eq!(rerun, honest.hs[step + 1]);
    assert_ne!(rerun, cheat.hs[step + 1]);
}

#[test]
fn bad_geometry_is_rejected() {
    assert!(matches!(
        VmSpec::new(vec![Insn::new(Op::Halt, 0); 3], vec![0; 4], 8),
        Err(VmError::BadGeometry { .. })
    ));
    assert!(matches!(
        VmSpec::new(vec![Insn::new(Op::Halt, 0); 4], vec![0; 4], 6),
        Err(VmError::BadStepCount(6))
    ));
    // A program that walks off the code (no HALT) fails while tracing.
    let runaway = VmSpec::new(vec![Insn::new(Op::Addi, 1); 2], vec![0, 0], 4).unwrap();
    assert!(matches!(
        runaway.trace(),
        Err(VmError::PcOutOfRange { .. })
    ));
}

// ============================================================================
// The dispute protocol over LocalChain
// ============================================================================

fn setup(
    chain: &Rc<LocalChain>,
    fault: Option<Fault>,
) -> (
    Runner<AliceVmData, VmOutcome>,
    Runner<BobVmData, VmOutcome>,
    InstanceHandle,
    InstanceHandle,
) {
    let spec = spec();
    let params = VmParams {
        alice_pk: alice_pk(),
        bob_pk: bob_pk(),
    };
    let ctx = VmCtx::new(spec.clone());

    let entry = |seed| {
        fund_fake(
            VmS0::new(params.clone(), ctx.clone()).unwrap().as_erased(),
            None,
            AMOUNT,
            seed,
        )
    };
    let alice_entry = entry(SEED);
    let bob_entry = entry(SEED);

    let honest = spec.trace().unwrap();
    let claimed = spec.trace_with_fault(fault).unwrap();

    let alice_data = AliceVmData {
        fraud: vm_fraud_data(&spec, &claimed, alice_xpriv(), p2tr(alice_pk())),
        trace: claimed,
        xpriv: alice_xpriv(),
    };
    let bob_data = BobVmData {
        fraud: vm_fraud_data(&spec, &honest, bob_xpriv(), p2tr(bob_pk())),
        trace: honest,
        xpriv: bob_xpriv(),
    };

    let alice = Runner::new(
        offline_manager(),
        chain.clone(),
        alice_vm_role(),
        alice_data,
        alice_entry.clone(),
    );
    let bob = Runner::new(
        offline_manager(),
        chain.clone(),
        bob_vm_role(),
        bob_data,
        bob_entry.clone(),
    );
    (alice, bob, alice_entry, bob_entry)
}

#[test]
fn full_bisection_resolves_at_the_faulted_step() {
    let spec = spec();
    let step = fault_step(&spec);
    let chain = Rc::new(LocalChain::new());
    let (mut alice, mut bob, _alice_entry, bob_entry) =
        setup(&chain, Some(Fault { step, delta: 1 }));

    let (a_out, b_out) = drive_both(&mut alice, &mut bob, 200, Duration::ZERO).expect("both step");

    // Both parties independently reach the same outcome: Bob wins the
    // on-chain re-run of exactly the corrupted instruction.
    let expected = VmOutcome::Fraud(FraudOutcome {
        winner: FraudWinner::Bob,
        resolution: FraudResolution::LeafAdjudicated { step: step as i64 },
    });
    assert_eq!(a_out, Some(expected));
    assert_eq!(b_out, Some(expected));

    // The pot went to Bob.
    let leaf = walk_tip(&bob_entry);
    assert_eq!(leaf.contract_name(), "Leaf");
    assert_eq!(leaf.clause_name().as_deref(), Some("bob_reveal"));
    let payout = leaf.spending_tx().expect("leaf adjudicated");
    assert_eq!(payout.output[0].script_pubkey, p2tr(bob_pk()));
    assert_eq!(payout.output[0].value, Amount::from_sat(AMOUNT));
}

#[test]
fn forfait_collects_when_alice_abandons_the_challenge() {
    let spec = spec();
    let step = fault_step(&spec);
    let chain = Rc::new(LocalChain::new());
    let (mut alice, mut bob, _alice_entry, bob_entry) =
        setup(&chain, Some(Fault { step, delta: 1 }));

    // Alice posts her claim, then goes silent: she never answers the challenge.
    let mut b_out = None;
    for _ in 0..50 {
        if alice.current().map(|h| h.contract_name()) == Some("VmS0") {
            alice.step().expect("alice steps");
        }
        if let Progress::Done(os) = bob.step().expect("bob steps") {
            b_out = os.into_iter().next();
            break;
        }
    }
    assert!(b_out.is_none());
    assert_eq!(
        bob.current().map(|h| h.contract_name()),
        Some("Bisect1"),
        "Bob should be waiting for Alice's first reveal"
    );

    chain.mine(FORFAIT_TIMEOUT + 1);

    let outcome = bob.run_one().expect("bob resolves");
    assert_eq!(
        outcome,
        VmOutcome::Fraud(FraudOutcome {
            winner: FraudWinner::Bob,
            resolution: FraudResolution::Forfait { i: 0, j: 63 },
        })
    );

    let bisect1 = walk_tip(&bob_entry);
    assert_eq!(bisect1.contract_name(), "Bisect1");
    assert_eq!(bisect1.clause_name().as_deref(), Some("forfait"));
}

#[test]
fn an_honest_claim_withdraws_after_the_timeout() {
    let chain = Rc::new(LocalChain::new());
    let (mut alice, mut bob, alice_entry, _bob_entry) = setup(&chain, None);

    // Bob checks Alice's claimed final state and walks away; Alice waits out
    // her withdrawal delay.
    let (a_out, b_out) = drive_both(&mut alice, &mut bob, 30, Duration::ZERO).expect("both step");
    assert_eq!(b_out, Some(VmOutcome::AliceHonest));
    assert!(a_out.is_none());

    chain.mine(FORFAIT_TIMEOUT + 1);

    let outcome = alice.run_one().expect("alice resolves");
    assert_eq!(outcome, VmOutcome::AliceWithdrew);

    let s1 = walk_tip(&alice_entry);
    assert_eq!(s1.contract_name(), "VmS1");
    assert_eq!(s1.clause_name().as_deref(), Some("withdraw"));
    let payout = s1.spending_tx().expect("alice withdrew").output[0].clone();
    assert_eq!(payout.script_pubkey, p2tr(alice_pk()));
    assert_eq!(payout.value, Amount::from_sat(AMOUNT));
}

// ============================================================================
// End-to-end (regtest)
// ============================================================================

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_matt_vm_dispute_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    use mattrs::manager::ContractManager;
    use mattrs::protocol::RpcChain;
    use mattrs::report::Report;
    use support::testkit::{regtest_client, report_spend};

    let spec = spec();
    let step = fault_step(&spec);
    let params = VmParams {
        alice_pk: alice_pk(),
        bob_pk: bob_pk(),
    };
    let ctx = VmCtx::new(spec.clone());

    // Alice funds the game...
    let mut alice_manager =
        ContractManager::new(regtest_client("testwallet"), bitcoin::Network::Regtest);
    let s0 = VmS0::new(params.clone(), ctx.clone())?
        .fund(&mut alice_manager, Amount::from_sat(AMOUNT))?;
    let alice_entry = s0.handle().clone();
    let outpoint = alice_entry.outpoint().expect("just funded");

    // ...and Bob, given the outpoint out-of-band, verifies and tracks it.
    let mut bob_manager =
        ContractManager::new(regtest_client("testwallet"), bitcoin::Network::Regtest);
    let bob_entry = bob_manager.track_instance(
        VmS0::new(params.clone(), ctx.clone())?.as_erased(),
        None,
        outpoint,
    )?;

    let honest = spec.trace()?;
    let cheat = spec.trace_with_fault(Some(Fault { step, delta: 1 }))?;
    let alice_data = AliceVmData {
        fraud: vm_fraud_data(&spec, &cheat, alice_xpriv(), p2tr(alice_pk())),
        trace: cheat,
        xpriv: alice_xpriv(),
    };
    let bob_data = BobVmData {
        fraud: vm_fraud_data(&spec, &honest, bob_xpriv(), p2tr(bob_pk())),
        trace: honest,
        xpriv: bob_xpriv(),
    };

    let mut alice = Runner::new(
        alice_manager,
        Rc::new(RpcChain::new(regtest_client("testwallet"))),
        alice_vm_role(),
        alice_data,
        alice_entry,
    );
    let mut bob = Runner::new(
        bob_manager,
        Rc::new(RpcChain::new(regtest_client("testwallet"))),
        bob_vm_role(),
        bob_data,
        bob_entry.clone(),
    );

    let (a_out, b_out) = drive_both(&mut alice, &mut bob, 600, Duration::from_millis(20))?;

    // Every transition — including the step re-run with its bound fetch and
    // memory walks — was validated by the node's script interpreter.
    let expected = VmOutcome::Fraud(FraudOutcome {
        winner: FraudWinner::Bob,
        resolution: FraudResolution::LeafAdjudicated { step: step as i64 },
    });
    assert_eq!(a_out, Some(expected));
    assert_eq!(b_out, Some(expected));

    // Collect the transaction trail and check the terminal payout.
    let mut report = Report::new();
    let mut current = bob_entry;
    while let Some(clause) = current.clause_name() {
        let section = match current.contract_name() {
            "VmS0" | "VmS1" => "Game setup",
            "Leaf" => "Leaf",
            _ => "Bisection",
        };
        report_spend(
            &mut report,
            section,
            &format!("{} ({})", clause, current.contract_name()),
            &current,
        );
        let outputs = current.outputs();
        if outputs.is_empty() {
            break;
        }
        current = outputs.into_vec().remove(0);
    }
    assert_eq!(current.contract_name(), "Leaf");
    assert_eq!(current.clause_name().as_deref(), Some("bob_reveal"));
    let payout = current.spending_tx().expect("leaf adjudicated");
    assert_eq!(payout.output[0].script_pubkey, p2tr(bob_pk()));
    assert_eq!(payout.output[0].value, Amount::from_sat(AMOUNT));

    report.finalize("reports/report_matt_vm.md")?;
    Ok(())
}

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_matt_vm_leaf_per_opcode_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    // Adjudicate one Leaf per instruction (and both JZ directions) directly:
    // together with the dispute e2e this pushes every dispatch branch of the
    // step tapscript through the node's interpreter.
    use bitcoin::TxOut;
    use mattrs::fraud::{Leaf, LeafParams, LeafState};
    use mattrs::manager::ContractManager;
    use mattrs::signer::HotSigner;
    use support::testkit::regtest_client;

    let spec = spec();
    let trace = spec.trace()?;
    let params = LeafParams {
        alice_pk: alice_pk(),
        bob_pk: bob_pk(),
    };
    let computer = vm_computer(&spec);

    let mut manager = ContractManager::new(regtest_client("testwallet"), bitcoin::Network::Regtest);

    let cases: Vec<(&str, usize)> = vec![
        ("ADDI", first_step(&spec, |i, _| i.op == Op::Addi)),
        ("ADDM", first_step(&spec, |i, _| i.op == Op::Addm)),
        ("LOAD", first_step(&spec, |i, _| i.op == Op::Load)),
        ("STORE", first_step(&spec, |i, _| i.op == Op::Store)),
        ("JMP", first_step(&spec, |i, _| i.op == Op::Jmp)),
        ("JZ (fall-through)", first_step(&spec, |i, acc| i.op == Op::Jz && acc != 0)),
        ("JZ (jump)", first_step(&spec, |i, acc| i.op == Op::Jz && acc == 0)),
        ("HALT", first_step(&spec, |i, _| i.op == Op::Halt)),
    ];

    for (name, step) in cases {
        // Alice's claim for this step is honest; Bob's is junk. Her reveal
        // re-runs the instruction on-chain and takes the pot.
        let leaf = Leaf::new(params.clone(), computer.clone())?.fund(
            &mut manager,
            Amount::from_sat(AMOUNT),
            LeafState {
                h_start: trace.hs[step],
                h_end_alice: trace.hs[step + 1],
                h_end_bob: [0xee; 32],
            },
        )?;
        leaf.alice_reveal(trace.xs[step].clone())?
            .outputs(vec![TxOut {
                script_pubkey: p2tr(alice_pk()),
                value: Amount::from_sat(AMOUNT),
            }])
            .sign(HotSigner::new(alice_xpriv()))
            .exec_none(&mut manager)
            .map_err(|error| format!("{name} leaf reveal (step {step}): {error}"))?;
    }
    Ok(())
}
