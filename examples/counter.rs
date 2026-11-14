//! The second step after `getting_started`: a contract with **state**, a
//! `next` function that says what a spend produces, and a **protocol** that
//! plays it.
//!
//! The contract is a counter. Its UTXO commits to a number; anyone may spend
//! it back into the same contract with the number increased by one, and the
//! owner may close it and take the funds:
//!
//! ```text
//! Counter{owner_pk}[count]
//!   - increment()   => Counter[count + 1]
//!   - close()       => anywhere, with the owner's signature   (terminal)
//! ```
//!
//! Run with `cargo run --example counter`: it plays on an in-memory chain,
//! which records transactions without executing scripts. Add `--regtest` to
//! play the very same role against a MATT-enabled regtest node (with a funded
//! `testwallet`), where the scripts are enforced.

use std::rc::Rc;
use std::str::FromStr;

use bitcoin::bip32::Xpriv;
use bitcoin::{Amount, Network, ScriptBuf, TxOut, XOnlyPublicKey};
use mattrs::prelude::*;
use mattrs::script::{check_input_contract, check_output_same_contract, key_path_p2tr};

// ============================================================================
// Contract definition
// ============================================================================

#[derive(Debug, Clone)]
pub struct CounterParams {
    pub owner_pk: XOnlyPublicKey,
}

/// The state a `Counter` UTXO carries. The UTXO commits to
/// `sha256(<count>)`, where `<count>` is the number as a script would push it;
/// the script below recomputes exactly that.
#[derive(Debug, Clone, ContractState)]
#[commit(sha256)]
pub struct CounterState {
    pub count: i64,
}

contract! {
    contract Counter {
        params CounterParams;
        state CounterState;

        // witness: <count> — anyone bumps the counter. The argument is read
        // from the instance's state, so the spend method takes none.
        clause increment {
            args {
                #[from_state]
                count: i64,
            }
            script Counter::increment_script;
            // What the script enforces, restated for the manager: the output
            // at this input's index is this same contract, holding count + 1.
            next(p, a) {
                let state = CounterState { count: a.count + 1 };
                Ok(vec![Counter::new(p.clone())?.output(CcvIndex::CURRENT, state)])
            }
        }

        // witness: <sig> — the owner closes the counter.
        clause close {
            args {
                #[signer(p.owner_pk)]
                sig: Signature,
            }
            script |p| script! { { p.owner_pk } OP_CHECKSIG };
        }

        tree [increment, close];
    }
}

impl Counter {
    fn increment_script(_params: &CounterParams) -> ScriptBuf {
        script! {
            // <count>: check that it is the count this UTXO commits to...
            OP_DUP OP_SHA256
            { check_input_contract(CcvIndex::CURRENT, None) }
            // ...and commit count + 1 to the same contract, same amount.
            OP_1ADD OP_SHA256
            { check_output_same_contract(CcvIndex::CURRENT, None) }
            OP_TRUE
        }
    }
}

// ============================================================================
// Protocol: one party counts up to a target, then closes
// ============================================================================

/// What the owner knows: how far to count, and where the funds go at the end.
struct OwnerData {
    target: i64,
    payout: ScriptBuf,
}

/// The owner's strategy, as a table from contract state to action. Each time
/// the counter arrives somewhere, this decides the next transaction.
fn owner_role() -> Role<OwnerData, i64> {
    Role::new().on::<Counter, _>(|d: &mut OwnerData, counter: CounterHandle, _cx| {
        let count = counter.state().count;
        if count < d.target {
            // Send the spend and follow the child it creates.
            return Ok(Action::Send(counter.increment()));
        }
        // Close: a final spend, resolving the protocol with the count reached.
        let payout = TxOut {
            script_pubkey: d.payout.clone(),
            value: counter.amount(),
        };
        Ok(Action::SendFinal(
            counter.close().outputs(vec![payout]),
            count,
        ))
    })
}

// ============================================================================
// Demo
// ============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let on_regtest = std::env::args().any(|arg| arg == "--regtest");

    // Demo key (never use it on mainnet).
    let owner = HotSigner::new(Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )?);
    let owner_pk = owner.public_key();

    // The same code runs on either chain; only the manager's backend differs.
    let manager = if on_regtest {
        let client = mattrs::manager::regtest_rpc_client("testwallet");
        ContractManager::new(client, Network::Regtest)
    } else {
        ContractManager::on(Rc::new(LocalChain::new()), Network::Regtest)
    };
    let mut manager = manager.with_signer(owner);

    // Fund a counter starting at zero. A stateful contract's address depends
    // on its state, so `fund` takes the initial state.
    let counter = Counter::new(CounterParams { owner_pk })?;
    let entry = counter.fund(
        &mut manager,
        Amount::from_sat(50_000),
        CounterState { count: 0 },
    )?;
    println!("funded a Counter at {}", entry.outpoint());

    // Play the role from the funded instance to its outcome.
    let data = OwnerData {
        target: 3,
        payout: key_path_p2tr(owner_pk),
    };
    let mut runner = Runner::new(manager, owner_role(), data, entry.clone());
    let reached = runner.run_one()?;
    println!("closed the counter at {reached}");
    assert_eq!(reached, 3);

    // Every step is recorded: walk the chain of instances from the entry.
    let mut current = entry;
    loop {
        match current.spent().ok_or("every counter here was spent")? {
            CounterSpend::Increment(args) => {
                println!("  count {} -> {}", args.count, args.count + 1);
                current = current.outputs().one()?;
            }
            CounterSpend::Close(_) => {
                println!("  closed at {}", current.state().count);
                break;
            }
        }
    }
    Ok(())
}
