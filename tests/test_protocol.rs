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

use bitcoin::Amount;
use mattrs::manager::ContractManager;
use mattrs::protocol::{Action, LocalChain, Progress, ProtocolError, Role, Runner};
use mattrs::testutil::{fund_fake, offline_client};

use support::rps::roles::{
    alice_role, bob_role, outcome_of, AliceData, BobData, RpsOutcome, RpsResult,
};
use support::rps::{alice_move_commitment, RpsGameS0, RpsGameS0Handle, RpsParams, DEFAULT_STAKE};
use support::testkit::{alice_pk, bob_pk, bob_xpriv, walk_tip};

const SEED: u8 = 21;

fn params(c_a: [u8; 32]) -> RpsParams {
    RpsParams {
        alice_pk: alice_pk(),
        bob_pk: bob_pk(),
        c_a,
        stake: DEFAULT_STAKE,
    }
}

fn offline_manager() -> ContractManager {
    ContractManager::new(offline_client(), bitcoin::Network::Regtest)
}

/// Play a full game offline; returns both parties' outcomes and Bob's entry
/// handle (his view of the spend chain).
fn play(m_a: i64, m_b: i64) -> (RpsOutcome, RpsOutcome) {
    let chain = Rc::new(LocalChain::new());
    let r_a = [7u8; 32];
    let c_a = alice_move_commitment(m_a, &r_a);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);

    let alice_entry = fund_fake(RpsGameS0::new(params(c_a)).as_erased(), None, pot, SEED);
    let bob_entry = fund_fake(RpsGameS0::new(params(c_a)).as_erased(), None, pot, SEED);

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

    let mut a_out = None;
    let mut b_out = None;
    for _ in 0..20 {
        if a_out.is_none()
            && let Progress::Done(os) = alice.step().expect("alice steps")
        {
            a_out = os.into_iter().next();
        }
        if b_out.is_none()
            && let Progress::Done(os) = bob.step().expect("bob steps")
        {
            b_out = os.into_iter().next();
        }
        if a_out.is_some() && b_out.is_some() {
            break;
        }
    }

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
        (0, 0, RpsResult::Tie),           // rock ties rock
        (0, 1, RpsResult::BobWins),       // Bob's paper covers Alice's rock
        (1, 0, RpsResult::AliceWins),     // Alice's paper covers Bob's rock
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
    let truncated: Role<(), RpsOutcome> = Role::new().on::<RpsGameS0, _>(
        |_d: &mut (), _h: RpsGameS0Handle, _cx| Ok(Action::Wait),
    );
    let mut watcher = Runner::new(
        offline_manager(),
        chain.clone(),
        truncated,
        (),
        fund_fake(RpsGameS0::new(params(c_a)).as_erased(), None, pot, SEED),
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
        fund_fake(RpsGameS0::new(params(c_a)).as_erased(), None, pot, SEED),
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
}
