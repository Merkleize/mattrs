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
use mattrs::manager::InstanceHandle;
use mattrs::protocol::{
    Action, ChainView, LocalChain, Progress, ProtocolError, Role, Runner, RunnerState,
    TimeoutAction,
};
use mattrs::signer::HotSigner;

use support::rps::roles::{
    AliceData, BobData, RpsOutcome, RpsResult, alice_role, bob_role, outcome_of,
};
use support::rps::{
    DEFAULT_STAKE, RpsGameS0, RpsGameS0Handle, RpsGameS0Spend, RpsGameS1, RpsGameS1Handle,
    RpsParams, alice_move_commitment,
};
use support::testkit::{alice_pk, bob_pk, bob_xpriv, drive_both, manager_on, walk_tip};

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

    // Alice funds the game; Bob tracks the same output in his own manager.
    let game = RpsGameS0::new(params(c_a)).unwrap();
    let mut alice_manager = manager_on(chain.clone());
    let mut bob_manager = manager_on(chain.clone()).with_signer(HotSigner::new(bob_xpriv()));
    let alice_entry: InstanceHandle = game.fund(&mut alice_manager, pot).unwrap().into();
    let bob_entry: InstanceHandle = game
        .track(&mut bob_manager, alice_entry.outpoint())
        .unwrap()
        .into();

    let mut alice = Runner::new(
        alice_manager,
        alice_role(),
        AliceData {
            m_a,
            r_a,
            before_adjudicating: None,
        },
        alice_entry,
    );
    let mut bob = Runner::new(
        bob_manager,
        bob_role(),
        BobData { m_b, c_a },
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
    let truncated: Role<(), RpsOutcome> = Role::new().watch::<RpsGameS0>();
    let game = RpsGameS0::new(params(c_a)).unwrap();
    let mut watcher_manager = manager_on(chain.clone());
    let mut bob_manager = manager_on(chain.clone()).with_signer(HotSigner::new(bob_xpriv()));
    let watched: InstanceHandle = game.fund(&mut watcher_manager, pot).unwrap().into();
    let bob_entry: InstanceHandle = game
        .track(&mut bob_manager, watched.outpoint())
        .unwrap()
        .into();
    let mut watcher = Runner::new(watcher_manager, truncated, (), watched);
    let mut bob = Runner::new(bob_manager, bob_role(), BobData { m_b: 1, c_a }, bob_entry);

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
    let game = RpsGameS0::new(params(c_a)).unwrap();
    let mut manager = manager_on(chain.clone());
    let entry: InstanceHandle = game.fund(&mut manager, pot).unwrap().into();
    let wrong = game.fund(&mut manager, pot).unwrap();
    let role: Role<(), ()> =
        Role::new().on::<RpsGameS0, _>(move |_d, _h, _cx| Ok(Action::Send(wrong.bob_move(1))));
    let mut runner = Runner::new(manager, role, (), entry.clone());

    let err = runner.step().unwrap_err();
    assert!(matches!(&err, ProtocolError::Internal(msg) if msg.contains("different instance")));
    assert_eq!(runner.state(), RunnerState::Failed);
    assert_eq!(runner.failed_at(), Some(&entry));
    assert!(
        chain
            .find_spending_tx(entry.outpoint(), 0)
            .unwrap()
            .is_none()
    );
}

/// A game funded and confirmed on `chain`, and two managers tracking it that
/// can both sign Bob's move and mine nothing: the runner's, and a rival's.
fn contested_game(
    chain: &Rc<LocalChain>,
) -> (
    mattrs::manager::ContractManager,
    RpsGameS0Handle,
    mattrs::manager::ContractManager,
    RpsGameS0Handle,
) {
    let c_a = alice_move_commitment(0, &[7u8; 32]);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);
    let game = RpsGameS0::new(params(c_a)).unwrap();
    let funded = game.fund(&mut manager_on(chain.clone()), pot).unwrap();
    let party = || {
        let mut manager =
            mattrs::manager::ContractManager::on(chain.clone(), bitcoin::Network::Regtest)
                .with_signer(HotSigner::new(bob_xpriv()));
        let entry = game.track(&mut manager, funded.outpoint()).unwrap();
        (manager, entry)
    };
    let (ours, entry) = party();
    let (rival, rival_entry) = party();
    (ours, entry, rival, rival_entry)
}

/// A role that sends Bob's move as its final spend — and, should the game
/// move on some other way, says so.
fn final_move_role() -> Role<(), &'static str> {
    Role::new()
        .on::<RpsGameS0, _>(|_d, h: RpsGameS0Handle, _cx| {
            Ok(Action::SendFinal(h.bob_move(1), "our move settled"))
        })
        .on::<RpsGameS1, _>(|_d, _h, _cx| Ok(Action::Finish("another move settled")))
}

/// Sending is an attempt. When a conflicting spend is the one that settles,
/// the runner follows it instead of failing, and does not claim the outcome
/// of the spend it sent.
#[test]
fn a_lost_race_follows_the_spend_that_settled() {
    let chain = Rc::new(LocalChain::new());
    let (ours, entry, rival, rival_entry) = contested_game(&chain);
    let outpoint = entry.outpoint();

    // The rival's move reaches the mempool first: ours is refused.
    let theirs = rival_entry.bob_move(2).broadcast(&rival).unwrap();
    let entry: InstanceHandle = entry.into();
    let mut runner = Runner::new(ours, final_move_role(), (), entry.clone());
    assert!(matches!(runner.step().unwrap(), Progress::Advanced));
    assert_eq!(runner.state(), RunnerState::Running);

    // Nothing is settled, so nothing is recorded, and the token stays put.
    assert!(matches!(runner.step().unwrap(), Progress::Waiting));
    assert_eq!(entry.status(), mattrs::contracts::InstanceStatus::Funded);

    // The rival's spend confirms: that is the one followed.
    chain.mine(1);
    assert!(matches!(runner.step().unwrap(), Progress::Advanced));
    assert_eq!(entry.spending_tx().unwrap().compute_txid(), theirs.txid());
    assert!(
        matches!(runner.step().unwrap(), Progress::Done(out) if out == vec!["another move settled"])
    );
    assert_eq!(
        chain
            .find_spending_tx(outpoint, 1)
            .unwrap()
            .unwrap()
            .compute_txid(),
        theirs.txid()
    );
}

/// A spend of ours that drops out of the mempool is sent again, and earns
/// its outcome once it settles.
#[test]
fn a_dropped_spend_is_sent_again() {
    let chain = Rc::new(LocalChain::new());
    let (ours, entry, _rival, _) = contested_game(&chain);
    let outpoint = entry.outpoint();

    let mut runner = Runner::new(ours, final_move_role(), (), entry);
    assert!(matches!(runner.step().unwrap(), Progress::Advanced));
    let sent = chain.find_unsettled_spend(outpoint).unwrap().unwrap();

    // The node drops it.
    assert!(chain.evict(sent.compute_txid()));
    assert!(chain.find_unsettled_spend(outpoint).unwrap().is_none());

    // The runner notices nothing is out, and broadcasts the same spend.
    assert!(matches!(runner.step().unwrap(), Progress::Waiting));
    assert_eq!(chain.find_unsettled_spend(outpoint).unwrap(), Some(sent));

    chain.mine(1);
    assert!(
        matches!(runner.step().unwrap(), Progress::Done(out) if out == vec!["our move settled"])
    );
}

/// A refused broadcast with no other spend around is a real failure.
#[test]
fn a_refused_spend_with_no_rival_fails_the_runner() {
    let chain = Rc::new(RecordingChain::default());
    let c_a = alice_move_commitment(0, &[7u8; 32]);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);
    let mut manager =
        mattrs::manager::ContractManager::on(chain.clone(), bitcoin::Network::Regtest)
            .with_signer(HotSigner::new(bob_xpriv()))
            .with_auto_mining();
    let entry = RpsGameS0::new(params(c_a))
        .unwrap()
        .fund(&mut manager, pot)
        .unwrap();

    chain.refusing.set(true);
    let mut runner = Runner::new(manager, final_move_role(), (), entry.clone());
    assert!(matches!(
        runner.step(),
        Err(ProtocolError::Manager(
            mattrs::manager::ManagerError::Chain(mattrs::chain::ChainError::Rejected(_))
        ))
    ));
    assert_eq!(runner.state(), RunnerState::Failed);
    assert_eq!(entry.status(), mattrs::contracts::InstanceStatus::Funded);
}

/// A counterparty spend that is out but not confirmed deeply enough is not a
/// missed deadline: the fallback waits, and the spend is followed once it has
/// the confirmations.
#[test]
fn timeout_does_not_fire_over_a_spend_awaiting_confirmations() {
    let chain = Rc::new(LocalChain::new());
    let c_a = alice_move_commitment(0, &[7u8; 32]);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);
    let game = RpsGameS0::new(params(c_a)).unwrap();

    // The watcher funds the game: two blocks, for its two confirmations.
    let mut watcher_manager =
        mattrs::manager::ContractManager::on(chain.clone(), bitcoin::Network::Regtest)
            .with_confirmations(2)
            .with_auto_mining();
    let bob_manager =
        mattrs::manager::ContractManager::on(chain.clone(), bitcoin::Network::Regtest)
            .with_signer(HotSigner::new(bob_xpriv()));
    let watched: InstanceHandle = game.fund(&mut watcher_manager, pot).unwrap().into();
    let mut bob_manager = bob_manager;
    let bob_entry = game.track(&mut bob_manager, watched.outpoint()).unwrap();
    assert_eq!(chain.height().unwrap(), 2);

    let role: Role<(), &str> = Role::new()
        .on::<RpsGameS0, _>(|_d, _h, _cx| {
            Ok(Action::wait_or_after(3, TimeoutAction::Finish("timed out")))
        })
        .on::<RpsGameS1, _>(|_d, _h, _cx| Ok(Action::Finish("bob moved")));
    let mut watcher = Runner::new(watcher_manager, role, (), watched);
    assert!(matches!(watcher.step().unwrap(), Progress::Waiting));

    // The game confirmed at height 1, so the deadline is height 3. Bob moves
    // just as it passes: his spend is only in the mempool.
    chain.mine(1);
    bob_entry.bob_move(1).broadcast(&bob_manager).unwrap();
    assert!(matches!(watcher.step().unwrap(), Progress::Waiting));
    // One confirmation is still one short of the watcher's two.
    chain.mine(1);
    assert!(matches!(watcher.step().unwrap(), Progress::Waiting));
    chain.mine(1);
    assert!(matches!(watcher.step().unwrap(), Progress::Advanced));
    assert!(matches!(watcher.step().unwrap(), Progress::Done(out) if out == vec!["bob moved"]));
}

/// A `LocalChain` that records which spend lookups it was told to release.
#[derive(Default)]
struct RecordingChain {
    inner: LocalChain,
    released: std::cell::RefCell<Vec<(bitcoin::OutPoint, u32)>>,
    /// Make every spend lookup fail.
    failing: std::cell::Cell<bool>,
    /// Refuse every broadcast.
    refusing: std::cell::Cell<bool>,
}

impl mattrs::chain::ChainView for RecordingChain {
    fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<(), mattrs::chain::ChainError> {
        if self.refusing.get() {
            return Err(mattrs::chain::ChainError::Rejected("refused".into()));
        }
        self.inner.broadcast(tx)
    }
    fn find_spending_tx(
        &self,
        outpoint: bitcoin::OutPoint,
        min_confirmations: u32,
    ) -> Result<Option<bitcoin::Transaction>, mattrs::chain::ChainError> {
        if self.failing.get() {
            return Err(mattrs::chain::ChainError::Other("node unreachable".into()));
        }
        self.inner.find_spending_tx(outpoint, min_confirmations)
    }
    fn find_unsettled_spend(
        &self,
        outpoint: bitcoin::OutPoint,
    ) -> Result<Option<bitcoin::Transaction>, mattrs::chain::ChainError> {
        self.inner.find_unsettled_spend(outpoint)
    }
    fn stop_watching(&self, outpoint: bitcoin::OutPoint, min_confirmations: u32) {
        self.released
            .borrow_mut()
            .push((outpoint, min_confirmations));
    }
    fn transaction(
        &self,
        txid: bitcoin::Txid,
    ) -> Result<Option<bitcoin::Transaction>, mattrs::chain::ChainError> {
        self.inner.transaction(txid)
    }
    fn height(&self) -> Result<u32, mattrs::chain::ChainError> {
        self.inner.height()
    }
    fn confirmation_height(
        &self,
        txid: bitcoin::Txid,
    ) -> Result<Option<u32>, mattrs::chain::ChainError> {
        self.inner.confirmation_height(txid)
    }
    fn fund_output(
        &self,
        script_pubkey: &bitcoin::Script,
        amount: Amount,
    ) -> Result<bitcoin::Transaction, mattrs::chain::ChainError> {
        self.inner.fund_output(script_pubkey, amount)
    }
    fn mine_blocks(&self, n: u32) -> Result<(), mattrs::chain::ChainError> {
        self.inner.mine_blocks(n)
    }
}

/// Changing the confirmation depth while a runner waits abandons its lookup
/// at the old depth: the chain backend is told, so it keeps nothing for it.
#[test]
fn changing_the_depth_releases_the_lookups_at_the_old_one() {
    let chain = Rc::new(RecordingChain::default());
    let c_a = alice_move_commitment(0, &[7u8; 32]);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);
    let mut manager =
        mattrs::manager::ContractManager::on(chain.clone(), bitcoin::Network::Regtest)
            .with_auto_mining();
    let entry: InstanceHandle = RpsGameS0::new(params(c_a))
        .unwrap()
        .fund(&mut manager, pot)
        .unwrap()
        .into();
    let outpoint = entry.outpoint();

    let role: Role<(), ()> = Role::new().watch::<RpsGameS0>();
    let mut runner = Runner::new(manager, role, (), entry);
    assert!(matches!(runner.step().unwrap(), Progress::Waiting));
    assert!(chain.released.borrow().is_empty());

    runner.manager_mut().set_confirmations(3);
    assert_eq!(*chain.released.borrow(), [(outpoint, 1)]);
    // Nothing is being looked for at the new depth yet, and setting the same
    // depth again abandons nothing.
    runner.manager_mut().set_confirmations(3);
    runner.manager_mut().set_confirmations(1);
    assert_eq!(*chain.released.borrow(), [(outpoint, 1)]);

    assert!(matches!(runner.step().unwrap(), Progress::Waiting));
    runner.manager_mut().set_confirmations(6);
    assert_eq!(*chain.released.borrow(), [(outpoint, 1), (outpoint, 1)]);
    assert!(matches!(runner.step().unwrap(), Progress::Waiting));
    runner.manager_mut().set_confirmations(1);
    assert_eq!(chain.released.borrow().last(), Some(&(outpoint, 6)));
}

/// A lookup that fails is over: the backend may have started keeping state
/// for it before failing, so it is released, even when it was the first.
#[test]
fn a_failed_lookup_is_released() {
    let chain = Rc::new(RecordingChain::default());
    let c_a = alice_move_commitment(0, &[7u8; 32]);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);
    let mut manager =
        mattrs::manager::ContractManager::on(chain.clone(), bitcoin::Network::Regtest)
            .with_auto_mining();
    let entry: InstanceHandle = RpsGameS0::new(params(c_a))
        .unwrap()
        .fund(&mut manager, pot)
        .unwrap()
        .into();
    let outpoint = entry.outpoint();

    chain.failing.set(true);
    let role: Role<(), ()> = Role::new().watch::<RpsGameS0>();
    let mut runner = Runner::new(manager, role, (), entry.clone());
    assert!(matches!(runner.step(), Err(ProtocolError::Manager(_))));
    assert_eq!(*chain.released.borrow(), [(outpoint, 1)]);

    // The same through the blocking wait, which gives up on the error.
    assert!(runner.manager_mut().wait_for_spend(&entry).is_err());
    assert_eq!(*chain.released.borrow(), [(outpoint, 1), (outpoint, 1)]);
}

#[test]
fn zero_timeout_is_rejected_and_confirmation_moves_reset_the_deadline() {
    let c_a = alice_move_commitment(0, &[7u8; 32]);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);

    let game = RpsGameS0::new(params(c_a)).unwrap();
    let mut zero_manager = mattrs::testutil::local_manager();
    let zero_entry = game.fund(&mut zero_manager, pot).unwrap();
    let zero_role: Role<(), ()> = Role::new()
        .on::<RpsGameS0, _>(|_d, _h, _cx| Ok(Action::wait_or_after(0, TimeoutAction::Finish(()))));
    let mut zero = Runner::new(zero_manager, zero_role, (), zero_entry);
    assert!(matches!(
        zero.step(),
        Err(ProtocolError::Manager(
            mattrs::manager::ManagerError::Contract(
                mattrs::contracts::ContractError::InvalidBlockDelay { blocks: 0 }
            )
        ))
    ));

    let chain = Rc::new(LocalChain::new());
    let mut manager = manager_on(chain.clone());
    let entry: InstanceHandle = game.fund(&mut manager, pot).unwrap().into();
    let txid = entry.outpoint().txid;
    chain.assume_confirmed(txid, 5);
    let role: Role<(), ()> = Role::new()
        .on::<RpsGameS0, _>(|_d, _h, _cx| Ok(Action::wait_or_after(3, TimeoutAction::Finish(()))));
    let mut runner = Runner::new(manager, role, (), entry);
    assert!(matches!(runner.step().unwrap(), Progress::Waiting));

    // Simulate a reorg moving the funding transaction much later. A cached
    // deadline of 7 would fire now; recomputing gives the new deadline 102.
    chain.assume_confirmed(txid, 100);
    assert!(matches!(runner.step().unwrap(), Progress::Waiting));
    chain.mine(2);
    assert!(matches!(runner.step().unwrap(), Progress::Done(out) if out == vec![()]));
    assert_eq!(runner.state(), RunnerState::Finished);
}

/// `parent_spend` is typed: it names the parent contract, and says so when
/// the token did not come from one.
#[test]
fn parent_spend_checks_where_the_token_came_from() {
    let chain = Rc::new(LocalChain::new());
    let c_a = alice_move_commitment(0, &[7u8; 32]);
    let pot = Amount::from_sat((2 * DEFAULT_STAKE) as u64);
    let game = RpsGameS0::new(params(c_a)).unwrap();
    let mut manager = manager_on(chain).with_signer(HotSigner::new(bob_xpriv()));
    let entry = game.fund(&mut manager, pot).unwrap();

    let role: Role<(), i64> = Role::new()
        .on::<RpsGameS0, _>(|_d: &mut (), h: RpsGameS0Handle, cx| {
            // The entry instance has no parent.
            assert!(matches!(
                cx.parent_spend::<RpsGameS0>(),
                Err(ProtocolError::Internal(_))
            ));
            Ok(Action::Send(h.bob_move(2)))
        })
        .on::<RpsGameS1, _>(|_d, _h: RpsGameS1Handle, cx| {
            // The parent is an S0, not an S1...
            assert!(matches!(
                cx.parent_spend::<RpsGameS1>(),
                Err(ProtocolError::WrongContract(_))
            ));
            // ...and its spend carries Bob's move, typed.
            let (_s0, RpsGameS0Spend::BobMove(args)) = cx.parent_spend::<RpsGameS0>()?;
            Ok(Action::Finish(args.m_b))
        });
    let outcomes = Runner::new(manager, role, (), entry).run().unwrap();
    assert_eq!(outcomes, vec![2]);
}
