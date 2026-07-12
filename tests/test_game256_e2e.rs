//! game256 fraud-proof challenge, end to end on a regtest node.
//!
//! Ports pymatt's `tests/test_fraud.py::test_fraud_proof_full` onto the
//! protocol layer: Alice claims a wrong result for the 8-step doubling
//! computation, Bob challenges her, and the bisection narrows the dispute —
//! every transition validated by the node's script interpreter — down to the
//! single step where Alice cheated, which Bob wins by re-running it on-chain.
//!
//! Unlike the offline `test_game256_protocol` (same roles over a `LocalChain`),
//! this runs the two parties as they would deploy: separate `ContractManager`s
//! and `RpcChain`s against the node, Alice funding the game and Bob tracking
//! the outpoint he learned out-of-band, each `Runner` following the other's
//! transactions purely through chain observation. Neither party's code spells
//! out a bisection step: the game roles mount `fraud::roles` via
//! `Role::embed`, and the whole dispute below `start_challenge` is driven by
//! the library component.

mod support;

use std::rc::Rc;
use std::time::Duration;

use bitcoin::Amount;
use mattrs::fraud::roles::{FraudOutcome, FraudResolution, FraudWinner};
use mattrs::manager::ContractManager;
use mattrs::protocol::{RpcChain, Runner};
use mattrs::script_helpers::key_path_p2tr as p2tr;
use mattrs::report::Report;

use support::game256::{G256Params, G256S0};
use support::game256_roles::{
    alice_game_role, bob_game_role, cheating_vals, fill_fraud_data, game_fraud_data, honest_vals,
    AliceGameData, BobGameData, GameOutcome,
};
use support::testkit::{
    alice_pk, alice_xpriv, bob_pk, bob_xpriv, drive_both, regtest_client, report_spend,
};

const AMOUNT: u64 = 20_000;

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_game256_fraud_challenge_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    let params = G256Params {
        alice_pk: alice_pk(),
        bob_pk: bob_pk(),
    };

    // Alice funds the game with the pot...
    let mut alice_manager =
        ContractManager::new(regtest_client("testwallet"), bitcoin::Network::Regtest);
    let s0 = G256S0::new(params.clone()).fund(&mut alice_manager, Amount::from_sat(AMOUNT))?;
    let alice_entry = s0.handle().clone();
    let outpoint = alice_entry.outpoint().expect("just funded");

    // ...and Bob, given the outpoint out-of-band, verifies and tracks it.
    let mut bob_manager =
        ContractManager::new(regtest_client("testwallet"), bitcoin::Network::Regtest);
    let bob_entry =
        bob_manager.track_instance(G256S0::new(params).as_erased(), None, outpoint)?;

    // The parties: Alice will cheat at step 5, Bob doubles honestly.
    let alice_data = AliceGameData {
        claim: Box::new(cheating_vals),
        fraud: game_fraud_data(alice_xpriv(), p2tr(alice_pk())),
        xpriv: alice_xpriv(),
    };
    let x = 2;
    let vals = honest_vals(x);
    let mut fraud = game_fraud_data(bob_xpriv(), p2tr(bob_pk()));
    fill_fraud_data(&mut fraud, &vals);
    let bob_data = BobGameData {
        x,
        vals,
        fraud,
        xpriv: bob_xpriv(),
    };

    let mut alice = Runner::new(
        alice_manager,
        Rc::new(RpcChain::new(regtest_client("testwallet"))),
        alice_game_role(),
        alice_data,
        alice_entry,
    );
    let mut bob = Runner::new(
        bob_manager,
        Rc::new(RpcChain::new(regtest_client("testwallet"))),
        bob_game_role(),
        bob_data,
        bob_entry.clone(),
    );

    // Interleave the two parties until both resolve (the happy path lives in
    // the mempool; nothing needs mining).
    let (a_out, b_out) = drive_both(&mut alice, &mut bob, 600, Duration::from_millis(20))?;

    // Both parties independently conclude: Bob won the on-chain re-run of
    // exactly the step where Alice cheated (64 -> 128, step 5).
    let expected = GameOutcome::Fraud(FraudOutcome {
        winner: FraudWinner::Bob,
        resolution: FraudResolution::LeafAdjudicated { step: 5 },
    });
    assert_eq!(a_out, Some(expected));
    assert_eq!(b_out, Some(expected));

    // The dispute honed in through the expected bisection path (R, L, R), and
    // the pot went to Bob.
    let mut path = Vec::new();
    let mut report = Report::new();
    let mut current = bob_entry;
    while let Some(clause) = current.clause_name() {
        let section = match current.contract_name() {
            "G256S0" | "G256S1" | "G256S2" => "Game setup",
            "Leaf" => "Leaf",
            _ => "Bisection",
        };
        report_spend(
            &mut report,
            section,
            &format!("{} ({})", clause, current.contract_name()),
            &current,
        );
        if current.contract_name() == "Bisect2" {
            path.push(match clause.as_str() {
                "bob_reveal_left" => 'L',
                _ => 'R',
            });
        }
        let outputs = current.outputs();
        if outputs.is_empty() {
            break;
        }
        current = outputs.into_vec().remove(0);
    }
    assert_eq!(path, ['R', 'L', 'R']);
    assert_eq!(current.contract_name(), "Leaf");
    assert_eq!(current.clause_name().as_deref(), Some("bob_reveal"));
    let payout = current.spending_tx().expect("leaf adjudicated");
    assert_eq!(payout.output[0].script_pubkey, p2tr(bob_pk()));
    assert_eq!(payout.output[0].value, Amount::from_sat(AMOUNT));

    report.finalize("reports/report_game256.md");
    Ok(())
}
