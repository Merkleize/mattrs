//! MATT-VM demo: a computation bounty settled by an on-chain dispute (regtest).
//!
//! The public computation is iterative Fibonacci on the tiny VM (see
//! `contracts/vm.rs`), traced for 64 steps. Alice posts a *wrong* claim — her
//! trace is corrupted right after the first `ADDM` (the Fibonacci addition) —
//! and Bob disputes it. The bisection narrows the disagreement, transaction by
//! transaction, to exactly the corrupted step, which Bob wins by re-running
//! that single instruction in a tapscript: its fetch is Merkle-proven against
//! the committed program (path bound to `pc`), and its memory access against
//! the committed memory root (path bound to the operand).
//!
//! Run against a regtest MATT-enabled bitcoind with a funded `testwallet`
//! (cookie auth or `BITCOIN_RPC_*` env vars):
//!
//! ```sh
//! cargo run --example matt_vm
//! ```
//!
//! The full transaction trail is written to `reports/report_matt_vm.md`.

mod contracts;

use std::rc::Rc;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::bip32::Xpriv;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, XOnlyPublicKey};

use mattrs::fraud::roles::{FraudResolution, FraudWinner};
use mattrs::manager::{ContractManager, regtest_rpc_client};
use mattrs::protocol::{Progress, RpcChain, Runner};
use mattrs::report::Report;
use mattrs::script_helpers::key_path_p2tr as p2tr;

use contracts::roles::{
    AliceVmData, BobVmData, VmOutcome, alice_vm_role, bob_vm_role, vm_fraud_data,
};
use contracts::stages::{VmCtx, VmParams, VmS0};
use contracts::vm::{Fault, Machine, Op, VmSpec, fib_spec};

const AMOUNT: u64 = 20_000;

// The standard regtest demo keys (the pymatt "alice"/"bob" fixtures).
fn alice_xpriv() -> Xpriv {
    Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )
    .expect("a valid fixture xpriv")
}

fn bob_xpriv() -> Xpriv {
    Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )
    .expect("a valid fixture xpriv")
}

fn xonly(xpriv: &Xpriv) -> XOnlyPublicKey {
    xpriv.to_priv().public_key(&Secp256k1::new()).into()
}

/// The first step of the honest execution that runs an `ADDM` — the
/// Fibonacci addition Alice will fudge.
fn first_addm_step(spec: &VmSpec) -> usize {
    let mut machine = Machine::new(spec.mem0().to_vec());
    for step in 0..spec.n_steps() {
        let insn = spec.code()[machine.pc as usize];
        if insn.op == Op::Addm {
            return step;
        }
        machine.step(spec.code()).expect("the demo spec runs clean");
    }
    panic!("the demo program runs an ADDM");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The public computation: fib over 64 traced steps.
    let spec = fib_spec(5, 64)?;
    let honest = spec.trace()?;
    let fault_step = first_addm_step(&spec);
    let cheat = spec.trace_with_fault(Some(Fault {
        step: fault_step,
        delta: 1,
    }))?;
    println!("MATT-VM: fib demo, {} steps traced", spec.n_steps());
    println!("  honest result:  acc = {}", honest.result());
    println!(
        "  Alice claims:   acc = {} (trace corrupted after step {}, the first ADDM)",
        cheat.result(),
        fault_step
    );

    let (alice_pk, bob_pk) = (xonly(&alice_xpriv()), xonly(&bob_xpriv()));
    let params = VmParams { alice_pk, bob_pk };
    let ctx = VmCtx::new(spec.clone());

    // Alice funds the game with the pot...
    let mut alice_manager =
        ContractManager::new(regtest_rpc_client("testwallet"), bitcoin::Network::Regtest);
    let s0 = VmS0::new(params.clone(), ctx.clone())?
        .fund(&mut alice_manager, Amount::from_sat(AMOUNT))?;
    let alice_entry = s0.handle().clone();
    let outpoint = alice_entry.outpoint().expect("just funded");
    println!("funded VmS0 at {outpoint}");

    // ...and Bob, given the outpoint out-of-band, verifies and tracks it.
    let mut bob_manager =
        ContractManager::new(regtest_rpc_client("testwallet"), bitcoin::Network::Regtest);
    let bob_entry = bob_manager.track_instance(
        VmS0::new(params.clone(), ctx.clone())?.as_erased(),
        None,
        outpoint,
    )?;

    let alice_data = AliceVmData {
        fraud: vm_fraud_data(&spec, &cheat, alice_xpriv(), p2tr(alice_pk)),
        trace: cheat,
        xpriv: alice_xpriv(),
    };
    let bob_data = BobVmData {
        fraud: vm_fraud_data(&spec, &honest, bob_xpriv(), p2tr(bob_pk)),
        trace: honest,
        xpriv: bob_xpriv(),
    };

    let mut alice = Runner::new(
        alice_manager,
        Rc::new(RpcChain::new(regtest_rpc_client("testwallet"))),
        alice_vm_role(),
        alice_data,
        alice_entry,
    );
    let mut bob = Runner::new(
        bob_manager,
        Rc::new(RpcChain::new(regtest_rpc_client("testwallet"))),
        bob_vm_role(),
        bob_data,
        bob_entry.clone(),
    );

    // Interleave the two parties, narrating Bob's view of the dispute.
    let mut a_out = None;
    let mut b_out = None;
    let mut last_state = String::new();
    for _ in 0..600 {
        if let Some(handle) = bob.current() {
            let state = handle.contract_name().to_string();
            if state != last_state {
                println!("  dispute at {state}");
                last_state = state;
            }
        }
        if a_out.is_none()
            && let Progress::Done(os) = alice.step()?
        {
            a_out = os.into_iter().next();
        }
        if b_out.is_none()
            && let Progress::Done(os) = bob.step()?
        {
            b_out = os.into_iter().next();
        }
        if a_out.is_some() && b_out.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    match b_out {
        Some(VmOutcome::Fraud(outcome)) => {
            let winner = match outcome.winner {
                FraudWinner::Alice => "Alice",
                FraudWinner::Bob => "Bob",
            };
            match outcome.resolution {
                FraudResolution::LeafAdjudicated { step } => println!(
                    "{winner} won the on-chain re-run of step {step} \
                     (the corruption was injected after step {fault_step})"
                ),
                FraudResolution::Forfait { i, j } => {
                    println!("{winner} collected on a stalled dispute over [{i}, {j}]")
                }
            }
        }
        other => println!("unexpected outcome: {other:?}"),
    }

    // The full transaction trail, from Bob's view of the chain.
    let mut report = Report::new();
    let mut current = bob_entry;
    while let Some(clause) = current.clause_name() {
        let section = match current.contract_name() {
            "VmS0" | "VmS1" => "Game setup",
            "Leaf" => "Leaf",
            _ => "Bisection",
        };
        let tx = current.spending_tx().expect("instance was spent");
        report.write_tx(
            section,
            &format!("{} ({})", clause, current.contract_name()),
            &tx,
        );
        let outputs = current.outputs();
        if outputs.is_empty() {
            break;
        }
        current = outputs.into_vec().remove(0);
    }
    report.finalize("reports/report_matt_vm.md")?;
    println!("transaction trail written to reports/report_matt_vm.md");
    Ok(())
}
