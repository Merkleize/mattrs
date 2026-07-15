//! The protocol layer driving Rock-Paper-Scissors offline: two role runners,
//! each with its own offline `ContractManager`, interleaved over a shared
//! in-memory `LocalChain`.
//!
//! The roles under test are the real ones the two-player demo runs
//! (`examples/rps/contracts.rs`, compiled here as `support::rps`); only the
//! chain is simulated. See `test_game256_protocol` for the composed
//! (sub-protocol) case and the timeout paths.

mod support;

use std::rc::Rc;
use std::time::Duration;

use bitcoin::Amount;
use mattrs::protocol::{
    Action, ChainView, LocalChain, Progress, ProtocolError, Role, Runner, RunnerState,
    TimeoutAction,
};
use mattrs::testutil::fund_fake;

use support::rps::roles::{
    AliceData, BobData, RpsOutcome, RpsResult, alice_role, bob_role, outcome_of,
};
use support::rps::{DEFAULT_STAKE, RpsGameS0, RpsGameS0Handle, RpsParams, alice_move_commitment};
use support::testkit::{alice_pk, bob_pk, bob_xpriv, drive_both, offline_manager, walk_tip};

const SEED: u8 = 21;

fn params(c_a: [u8; 32]) -> RpsParams {
    RpsParams {
        alice_pk: alice_pk(),
        bob_pk: bob_pk(),
        c_a,
        stake: DEFAULT_STAKE,
    }
}

/// Play a full game offline; returns both parties' outcomes and Bob's entry
/// handle (his view of the spend chain).
fn play(m_a: i64, m_b: i64) -> (RpsOutcome, RpsOutcome) {
    let chain = Rc::new(LocalChain::new());
    let r_a = [7u8; 32];
    let c_a = alice_move_commitment(m_a, &r_a);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);

    let alice_entry = fund_fake(
        RpsGameS0::new(params(c_a)).unwrap().as_erased(),
        None,
        pot,
        SEED,
    );
    let bob_entry = fund_fake(
        RpsGameS0::new(params(c_a)).unwrap().as_erased(),
        None,
        pot,
        SEED,
    );

    let mut alice = Runner::new(
        offline_manager(),
        chain.clone(),
        alice_role(),
        AliceData {
            m_a,
            r_a,
            before_adjudicating: None,
        },
        alice_entry,
    );
    let mut bob = Runner::new(
        offline_manager(),
        chain.clone(),
        bob_role(),
        BobData {
            m_b,
            c_a,
            xpriv: bob_xpriv(),
        },
        bob_entry.clone(),
    );

    let (a_out, b_out) = drive_both(&mut alice, &mut bob, 20, Duration::ZERO).expect("both step");

    // Both parties saw the same terminal adjudication of Bob's S1 twin.
    let s1 = walk_tip(&bob_entry);
    assert_eq!(s1.contract_name(), "RpsGameS1");
    assert!(s1.clause_name().is_some(), "the game was adjudicated");

    (a_out.expect("alice finished"), b_out.expect("bob finished"))
}

#[test]
fn all_outcomes_resolve_and_agree() {
    // (m_a, m_b): rock/paper/scissors are 0/1/2.
    for (m_a, m_b, expected) in [
        (0, 0, RpsResult::Tie),       // rock ties rock
        (0, 1, RpsResult::BobWins),   // Bob's paper covers Alice's rock
        (1, 0, RpsResult::AliceWins), // Alice's paper covers Bob's rock
    ] {
        let (a_out, b_out) = play(m_a, m_b);
        assert_eq!(a_out, b_out, "both parties agree");
        assert_eq!(a_out.result, expected);
        assert_eq!(a_out.result, outcome_of(m_a, m_b));
        assert_eq!((a_out.m_a, a_out.m_b), (m_a, m_b));
    }
}

#[test]
fn missing_handler_is_reported() {
    let chain = Rc::new(LocalChain::new());
    let r_a = [7u8; 32];
    let c_a = alice_move_commitment(0, &r_a);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);

    // A truncated role: it watches S0 but has no idea what an S1 is.
    let truncated: Role<(), RpsOutcome> =
        Role::new().on::<RpsGameS0, _>(|_d: &mut (), _h: RpsGameS0Handle, _cx| Ok(Action::Wait));
    let mut watcher = Runner::new(
        offline_manager(),
        chain.clone(),
        truncated,
        (),
        fund_fake(
            RpsGameS0::new(params(c_a)).unwrap().as_erased(),
            None,
            pot,
            SEED,
        ),
    );

    let mut bob = Runner::new(
        offline_manager(),
        chain.clone(),
        bob_role(),
        BobData {
            m_b: 1,
            c_a,
            xpriv: bob_xpriv(),
        },
        fund_fake(
            RpsGameS0::new(params(c_a)).unwrap().as_erased(),
            None,
            pot,
            SEED,
        ),
    );

    // Bob moves; the watcher then observes a child it cannot follow.
    watcher.step().expect("nothing to see yet");
    bob.step().expect("bob moves");
    let err = loop {
        match watcher.step() {
            Ok(_) => continue,
            Err(e) => break e,
        }
    };
    assert!(
        matches!(err, ProtocolError::NoHandler { ref contract } if contract == "RpsGameS1"),
        "got: {err}"
    );
    assert_eq!(watcher.state(), RunnerState::Failed);
    assert!(watcher.failed_at().is_some());
    assert!(matches!(watcher.step(), Err(ProtocolError::RunnerFailed)));
}

#[test]
fn action_cannot_spend_a_different_token() {
    let chain = Rc::new(LocalChain::new());
    let c_a = alice_move_commitment(0, &[7u8; 32]);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);
    let entry = fund_fake(
        RpsGameS0::new(params(c_a)).unwrap().as_erased(),
        None,
        pot,
        31,
    );
    let other: RpsGameS0Handle = fund_fake(
        RpsGameS0::new(params(c_a)).unwrap().as_erased(),
        None,
        pot,
        32,
    )
    .try_into()
    .unwrap();
    let wrong = other.clone();
    let role: Role<(), ()> =
        Role::new().on::<RpsGameS0, _>(move |_d, _h, _cx| Ok(Action::Send(wrong.bob_move(1))));
    let mut runner = Runner::new(offline_manager(), chain.clone(), role, (), entry.clone());

    let err = runner.step().unwrap_err();
    assert!(matches!(&err, ProtocolError::Other(msg) if msg.contains("different instance")));
    assert_eq!(runner.state(), RunnerState::Failed);
    assert_eq!(runner.failed_at(), Some(&entry));
    assert!(
        chain
            .find_spending_tx(entry.outpoint().unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn zero_timeout_is_rejected_and_confirmation_moves_reset_the_deadline() {
    let c_a = alice_move_commitment(0, &[7u8; 32]);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);

    let zero_entry = fund_fake(
        RpsGameS0::new(params(c_a)).unwrap().as_erased(),
        None,
        pot,
        41,
    );
    let zero_role: Role<(), ()> = Role::new().on::<RpsGameS0, _>(|_d, _h, _cx| {
        Ok(Action::WaitWithTimeout {
            blocks: 0,
            on_timeout: TimeoutAction::Finish(()),
        })
    });
    let mut zero = Runner::new(
        offline_manager(),
        Rc::new(LocalChain::new()),
        zero_role,
        (),
        zero_entry,
    );
    assert!(matches!(zero.step(), Err(ProtocolError::Other(_))));

    let chain = Rc::new(LocalChain::new());
    let entry = fund_fake(
        RpsGameS0::new(params(c_a)).unwrap().as_erased(),
        None,
        pot,
        42,
    );
    let txid = entry.outpoint().unwrap().txid;
    chain.assume_confirmed(txid, 5);
    let role: Role<(), ()> = Role::new().on::<RpsGameS0, _>(|_d, _h, _cx| {
        Ok(Action::WaitWithTimeout {
            blocks: 3,
            on_timeout: TimeoutAction::Finish(()),
        })
    });
    let mut runner = Runner::new(offline_manager(), chain.clone(), role, (), entry);
    assert!(matches!(runner.step().unwrap(), Progress::Waiting));

    // Simulate a reorg moving the funding transaction much later. A cached
    // deadline of 7 would fire now; recomputing gives the new deadline 102.
    chain.assume_confirmed(txid, 100);
    assert!(matches!(runner.step().unwrap(), Progress::Waiting));
    chain.mine(2);
    assert!(matches!(runner.step().unwrap(), Progress::Done(out) if out == vec![()]));
    assert_eq!(runner.state(), RunnerState::Finished);
}
