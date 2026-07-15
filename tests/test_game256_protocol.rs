//! The game256 protocol driven end-to-end by [`Runner`]s over the in-memory
//! [`LocalChain`] — deterministic, no node required.
//!
//! Both parties run the composed roles from `support::game256_roles` (the
//! top-level game with the fraud-proof bisection mounted via `Role::embed`),
//! each with its own offline `ContractManager`, sharing one `LocalChain`. The
//! tests interleave the two runners a step at a time, which also exercises the
//! forfait/withdraw timeout paths by mining blocks explicitly — paths that
//! need a chain whose time the test controls.
//!
//! `LocalChain` executes no scripts: these tests validate the protocol logic
//! (turn order, dispute routing, timeouts, outcome classification); consensus
//! validity of the same transitions is covered by the taptree byte tests and
//! the regtest e2e test.

mod support;

use std::rc::Rc;
use std::time::Duration;

use bitcoin::Amount;
use mattrs::fraud::roles::{FraudOutcome, FraudResolution, FraudWinner};
use mattrs::manager::InstanceHandle;
use mattrs::protocol::{LocalChain, Progress, Runner};
use mattrs::script_helpers::key_path_p2tr as p2tr;
use mattrs::testutil::fund_fake;

use support::game256::{FORFAIT_TIMEOUT, G256Params, G256S0};
use support::game256_roles::{
    AliceGameData, BobGameData, GameOutcome, alice_game_role, bob_game_role, cheating_vals,
    fill_fraud_data, game_fraud_data, honest_vals,
};
use support::testkit::{
    alice_pk, alice_xpriv, bob_pk, bob_xpriv, drive_both, offline_manager, walk_tip,
};

const AMOUNT: u64 = 20_000;
const SEED: u8 = 77;

/// Two runners over twin fake-funded `G256S0` entries and a shared chain.
/// Returns (alice, bob, alice's entry, bob's entry) — the entry handles let a
/// test inspect each party's view of the spend chain afterwards.
fn setup(
    chain: &Rc<LocalChain>,
    claim: fn(i64) -> Vec<i64>,
) -> (
    Runner<AliceGameData, GameOutcome>,
    Runner<BobGameData, GameOutcome>,
    InstanceHandle,
    InstanceHandle,
) {
    let params = G256Params {
        alice_pk: alice_pk(),
        bob_pk: bob_pk(),
    };

    let alice_entry = fund_fake(
        G256S0::new(params.clone()).unwrap().as_erased(),
        None,
        Amount::from_sat(AMOUNT),
        SEED,
    );
    let bob_entry = fund_fake(
        G256S0::new(params).unwrap().as_erased(),
        None,
        Amount::from_sat(AMOUNT),
        SEED,
    );

    let alice_data = AliceGameData {
        claim: Box::new(claim),
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

    let alice = Runner::new(
        offline_manager(),
        chain.clone(),
        alice_game_role(),
        alice_data,
        alice_entry.clone(),
    );
    let bob_runner = Runner::new(
        offline_manager(),
        chain.clone(),
        bob_game_role(),
        bob_data,
        bob_entry.clone(),
    );
    (alice, bob_runner, alice_entry, bob_entry)
}

#[test]
fn full_bisection_resolves_at_the_cheated_step() {
    let chain = Rc::new(LocalChain::new());
    let (mut alice, mut bob, _alice_entry, bob_entry) = setup(&chain, cheating_vals);

    let (a_out, b_out) = drive_both(&mut alice, &mut bob, 200, Duration::ZERO).expect("both step");

    // Both parties independently reach the same outcome: Bob wins the on-chain
    // re-run of exactly the step where Alice's claim went wrong.
    let expected = GameOutcome::Fraud(FraudOutcome {
        winner: FraudWinner::Bob,
        resolution: FraudResolution::LeafAdjudicated { step: 5 },
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
    let chain = Rc::new(LocalChain::new());
    let (mut alice, mut bob, _alice_entry, bob_entry) = setup(&chain, cheating_vals);

    // Alice plays only her setup turns (waiting at S0, revealing at S1), then
    // goes silent: she never answers the challenge.
    let mut b_out = None;
    for _ in 0..50 {
        if matches!(
            alice.current().map(|h| h.contract_name()),
            Some("G256S0") | Some("G256S1")
        ) {
            alice.step().expect("alice steps");
        }
        if let Progress::Done(os) = bob.step().expect("bob steps") {
            b_out = os.into_iter().next();
            break;
        }
    }
    // Bob challenged and is now waiting at Bisect1, deadline armed.
    assert!(b_out.is_none());
    assert_eq!(
        bob.current().map(|h| h.contract_name()),
        Some("Bisect1"),
        "Bob should be waiting for Alice's first reveal"
    );

    // Nothing happens until the challenge response window expires...
    chain.mine(FORFAIT_TIMEOUT + 1);

    // ...then Bob's timeout fallback fires and collects the pot.
    let outcome = bob.run_one().expect("bob resolves");
    assert_eq!(
        outcome,
        GameOutcome::Fraud(FraudOutcome {
            winner: FraudWinner::Bob,
            resolution: FraudResolution::Forfait { i: 0, j: 7 },
        })
    );

    let bisect1 = walk_tip(&bob_entry);
    assert_eq!(bisect1.contract_name(), "Bisect1");
    assert_eq!(bisect1.clause_name().as_deref(), Some("forfait"));
    let payout = bisect1.spending_tx().expect("forfait collected");
    assert_eq!(payout.output[0].script_pubkey, p2tr(bob_pk()));
    assert_eq!(payout.output[0].value, Amount::from_sat(AMOUNT));
}

#[test]
fn honest_claim_withdraws_after_the_timeout() {
    let chain = Rc::new(LocalChain::new());
    let (mut alice, mut bob, alice_entry, _bob_entry) = setup(&chain, honest_vals);

    // Bob checks Alice's claimed result and walks away; Alice keeps waiting
    // out her withdrawal delay.
    let (a_out, b_out) = drive_both(&mut alice, &mut bob, 30, Duration::ZERO).expect("both step");
    assert_eq!(b_out, Some(GameOutcome::AliceHonest));
    assert!(a_out.is_none());

    chain.mine(FORFAIT_TIMEOUT + 1);

    let outcome = alice.run_one().expect("alice resolves");
    assert_eq!(outcome, GameOutcome::AliceWithdrew);

    // Alice's withdraw spent S2, paying her the pot.
    let s2 = walk_tip(&alice_entry);
    assert_eq!(s2.contract_name(), "G256S2");
    assert_eq!(s2.clause_name().as_deref(), Some("withdraw"));
    let payout = s2.spending_tx().expect("alice withdrew").output[0].clone();
    assert_eq!(payout.script_pubkey, p2tr(alice_pk()));
    assert_eq!(payout.value, Amount::from_sat(AMOUNT));
}
