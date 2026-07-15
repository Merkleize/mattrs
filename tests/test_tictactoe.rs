//! Tic-tac-toe tests: the board-in-the-UTXO contract from
//! `examples/tictactoe/contracts.rs` (compiled here as `support::tictactoe`).
//!
//! Coverage mirrors the other examples:
//! - state/rules unit tests;
//! - build-level spend tests against fake-funded instances (no node): a move
//!   commits the updated board to the same contract, claims pay out via their
//!   CTV templates, and `next_outputs` rejects illegal moves;
//! - the full protocol offline: both players' [`Runner`]s over a shared
//!   `LocalChain`, playing a won game, a tied game, and a forfait (timeout);
//! - `#[ignore]`d regtest e2e tests where a validating node adjudicates the
//!   same transitions (including rejecting cheats) at the consensus level.

mod support;

use std::rc::Rc;
use std::time::Duration;

use bitcoin::{Amount, Sequence};
use mattrs::contracts::ContractState;
use mattrs::manager::ContractManager;
use mattrs::protocol::{LocalChain, ProtocolError, Runner};
use mattrs::script_helpers::key_path_p2tr as p2tr;
use mattrs::signer::HotSigner;

use support::testkit::{
    alice_pk, alice_xpriv, bob_pk, bob_xpriv, drive_both, fund_fake, offline_client,
    offline_manager, try_handle, walk_tip,
};
use support::tictactoe::roles::{
    PlayerData, Strategy, TttOutcome, TttResult, alice_role, bob_role,
};
use support::tictactoe::{
    DEFAULT_STAKE, EMPTY, MARK_ALICE, MARK_BOB, TURN_ALICE, TURN_BOB, TicTacToe, TicTacToeHandle,
    TttParams, TttState, board_full, line_winner,
};

const POT: u64 = (2 * DEFAULT_STAKE) as u64;
const TIMEOUT: u32 = 10;
const SEED: u8 = 42;

fn params() -> TttParams {
    TttParams {
        alice_pk: alice_pk(),
        bob_pk: bob_pk(),
        stake: DEFAULT_STAKE,
        timeout_blocks: TIMEOUT,
    }
}

/// A fake-funded game holding the pot, carrying `state` as expanded state.
fn funded_game(state: TttState) -> TicTacToeHandle {
    try_handle(fund_fake(
        TicTacToe::new(params()).unwrap().as_erased(),
        Some(Box::new(state)),
        POT,
        SEED,
    ))
}

/// A board from a compact picture: 'X', 'O', '.' per cell.
fn board(picture: &str) -> [u8; 9] {
    let cells: Vec<u8> = picture
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            'X' => MARK_ALICE,
            'O' => MARK_BOB,
            '.' => EMPTY,
            other => panic!("unknown cell {other:?}"),
        })
        .collect();
    cells.try_into().expect("nine cells")
}

// ----------------------------------------------------------------------------
// State encoding and game rules
// ----------------------------------------------------------------------------

#[test]
fn state_roundtrips_through_its_commitment() {
    let state = TttState {
        turn: TURN_BOB,
        board: board("XO. .X. ..O"),
    };
    let bytes = state.encode();
    assert_eq!(bytes.len(), 10);
    assert_eq!(TttState::decode(&bytes).unwrap(), state);

    assert!(TttState::decode(&bytes[..9]).is_err(), "wrong length");
    let mut bad_turn = bytes.clone();
    bad_turn[0] = 7;
    assert!(TttState::decode(&bad_turn).is_err(), "invalid turn byte");
    let mut bad_cell = bytes.clone();
    bad_cell[3] = 7;
    assert!(TttState::decode(&bad_cell).is_err(), "invalid cell byte");
}

#[test]
fn game_rules_match_the_boards() {
    assert_eq!(line_winner(&board("XXX OO. ...")), Some(MARK_ALICE));
    assert_eq!(line_winner(&board("XO. XO. .OX")), Some(MARK_BOB)); // column 1
    assert_eq!(line_winner(&board("X.O .OX O.X")), Some(MARK_BOB)); // anti-diagonal
    assert_eq!(line_winner(&board("XOX XOO OXX")), None);
    assert!(board_full(&board("XOX XOO OXX")));
    assert!(!board_full(&board("XOX XO. OXX")));

    let s = TttState::initial();
    assert_eq!((s.turn, s.board), (TURN_ALICE, [EMPTY; 9]));
    let s = s.after_move(4, MARK_ALICE);
    assert_eq!(s.turn, TURN_BOB);
    assert_eq!(s.board, board(".. . .X. ..."));
    assert_eq!(
        s.prefix_suffix(4),
        (s.board[..4].to_vec(), s.board[5..].to_vec())
    );
}

// ----------------------------------------------------------------------------
// Spend flow (build-level, no node)
// ----------------------------------------------------------------------------

#[test]
fn moves_commit_the_updated_board() {
    let game = funded_game(TttState::initial());
    let manager = ContractManager::new(offline_client(), bitcoin::Network::Regtest);

    // Alice opens in the center.
    let tx = game
        .make_move(4)
        .unwrap()
        .sign(HotSigner::new(alice_xpriv()))
        .build_tx(&manager)
        .unwrap();

    // Output 0 is the same contract committing the updated board, whole pot.
    let next = TttState::initial().after_move(4, MARK_ALICE);
    let expected = TicTacToe::new(params())
        .unwrap()
        .as_erased()
        .script_pubkey(Some(&next.encode()))
        .unwrap();
    assert_eq!(tx.output[0].script_pubkey, expected);
    assert_eq!(tx.output[0].value, Amount::from_sat(POT));
}

#[test]
fn claims_pay_out_via_their_ctv_templates() {
    let manager = ContractManager::new(offline_client(), bitcoin::Network::Regtest);
    let pot = Amount::from_sat(POT);
    let stake = Amount::from_sat(DEFAULT_STAKE as u64);

    // Alice took the top row: her claim pays her the pot.
    let won = funded_game(TttState {
        turn: TURN_BOB,
        board: board("XXX OO. ..."),
    });
    let tx = won
        .claim_win(MARK_ALICE)
        .unwrap()
        .build_tx(&manager)
        .unwrap();
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].script_pubkey, p2tr(alice_pk()));
    assert_eq!(tx.output[0].value, pot);
    assert_eq!(tx.input[0].sequence, Sequence::ZERO);

    // A full, lineless board: the tie splits the stakes.
    let tied = funded_game(TttState {
        turn: TURN_BOB,
        board: board("XOX XOO OXX"),
    });
    let tx = tied.claim_tie().unwrap().build_tx(&manager).unwrap();
    assert_eq!(tx.output.len(), 2);
    assert_eq!(tx.output[0].script_pubkey, p2tr(alice_pk()));
    assert_eq!(tx.output[1].script_pubkey, p2tr(bob_pk()));
    assert!(tx.output.iter().all(|o| o.value == stake));

    // Bob idled: Alice's forfait claim pays her the pot, and the input
    // sequence is the CSV delay the template commits to.
    let idle = funded_game(TttState {
        turn: TURN_BOB,
        board: board("X.. ... ..."),
    });
    let tx = idle.timeout_bob_idle().unwrap().build_tx(&manager).unwrap();
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].script_pubkey, p2tr(alice_pk()));
    assert_eq!(tx.output[0].value, pot);
    assert_eq!(tx.input[0].sequence, Sequence(TIMEOUT));
}

#[test]
fn illegal_moves_are_rejected_when_building() {
    let manager = ContractManager::new(offline_client(), bitcoin::Network::Regtest);

    // Out of turn: it is Alice's move, Bob tries to play.
    let game = funded_game(TttState::initial());
    let err = game
        .move_bob(vec![], vec![EMPTY; 8])
        .sign(HotSigner::new(bob_xpriv()))
        .build_tx(&manager);
    assert!(err.is_err(), "out-of-turn move must not build");

    // Occupied cell: the center is already taken.
    let game = funded_game(TttState {
        turn: TURN_BOB,
        board: board("... .X. ..."),
    });
    let err = game
        .move_bob(board("... .X. ...")[..4].to_vec(), vec![EMPTY; 4])
        .sign(HotSigner::new(bob_xpriv()))
        .build_tx(&manager);
    assert!(err.is_err(), "a move onto a taken cell must not build");

    // A move whose revealed board contradicts the committed one.
    let game = funded_game(TttState {
        turn: TURN_ALICE,
        board: board("O.. ... ..."),
    });
    let err = game
        .move_alice(vec![], vec![EMPTY; 8])
        .sign(HotSigner::new(alice_xpriv()))
        .build_tx(&manager);
    assert!(err.is_err(), "a fabricated board must not build");
}

// ----------------------------------------------------------------------------
// The protocol offline: two runners over a shared LocalChain
// ----------------------------------------------------------------------------

/// A strategy playing a fixed sequence of cells.
fn scripted(moves: &[usize]) -> Strategy {
    let mut moves = Box::<[usize]>::from(moves).into_iter();
    Box::new(move |_board| Ok(moves.next().expect("the scripted game should be over")))
}

#[test]
fn strategy_errors_propagate_from_the_role() {
    let chain = Rc::new(LocalChain::new());
    let entry = funded_game(TttState::initial());
    let mut runner = Runner::new(
        offline_manager(),
        chain,
        alice_role(),
        PlayerData {
            xpriv: alice_xpriv(),
            strategy: Box::new(|_| Err(ProtocolError::Other("input closed".to_string()))),
        },
        entry.handle().clone(),
    );

    let err = runner.step().unwrap_err();
    assert!(matches!(
        err,
        ProtocolError::Other(message) if message == "input closed"
    ));
}

/// Twin runners over the same fake-funded game and a shared chain. The two
/// entry handles are each party's own view of the spend chain.
fn setup(
    chain: &Rc<LocalChain>,
    alice_moves: &[usize],
    bob_moves: &[usize],
) -> (
    Runner<PlayerData, TttOutcome>,
    Runner<PlayerData, TttOutcome>,
    TicTacToeHandle,
    TicTacToeHandle,
) {
    let alice_entry = fund_fake(
        TicTacToe::new(params()).unwrap().as_erased(),
        Some(Box::new(TttState::initial())),
        POT,
        SEED,
    );
    let bob_entry = fund_fake(
        TicTacToe::new(params()).unwrap().as_erased(),
        Some(Box::new(TttState::initial())),
        POT,
        SEED,
    );

    let alice = Runner::new(
        offline_manager(),
        chain.clone(),
        alice_role(),
        PlayerData {
            xpriv: alice_xpriv(),
            strategy: scripted(alice_moves),
        },
        alice_entry.clone(),
    );
    let bob = Runner::new(
        offline_manager(),
        chain.clone(),
        bob_role(),
        PlayerData {
            xpriv: bob_xpriv(),
            strategy: scripted(bob_moves),
        },
        bob_entry.clone(),
    );
    (alice, bob, try_handle(alice_entry), try_handle(bob_entry))
}

#[test]
fn played_win_resolves_for_both_parties() {
    let chain = Rc::new(LocalChain::new());
    // Alice takes the top row while Bob starts the middle one.
    let (mut alice, mut bob, _alice_entry, bob_entry) = setup(&chain, &[0, 1, 2], &[3, 4]);

    let (a_out, b_out) = drive_both(&mut alice, &mut bob, 40, Duration::ZERO).expect("both step");
    let expected = TttOutcome {
        result: TttResult::AliceWins,
        by_timeout: false,
        board: board("XXX OO. ..."),
    };
    assert_eq!(a_out, Some(expected));
    assert_eq!(b_out, Some(expected));

    // The terminal claim spent the last game state, paying Alice the pot.
    let tip = walk_tip(bob_entry.handle());
    assert_eq!(tip.clause_name().as_deref(), Some("alice_wins"));
    let payout = tip.spending_tx().expect("adjudicated");
    assert_eq!(payout.output[0].script_pubkey, p2tr(alice_pk()));
    assert_eq!(payout.output[0].value, Amount::from_sat(POT));
}

#[test]
fn full_board_resolves_as_a_tie() {
    let chain = Rc::new(LocalChain::new());
    // A drawn game: X X O / X O O / O X X, played to a full board.
    let (mut alice, mut bob, _alice_entry, bob_entry) =
        setup(&chain, &[0, 2, 3, 7, 8], &[1, 4, 5, 6]);

    let (a_out, b_out) = drive_both(&mut alice, &mut bob, 40, Duration::ZERO).expect("both step");
    let final_board = board("XOX XOO OXX");
    assert_eq!(line_winner(&final_board), None, "the game is truly drawn");
    let expected = TttOutcome {
        result: TttResult::Tie,
        by_timeout: false,
        board: final_board,
    };
    assert_eq!(a_out, Some(expected));
    assert_eq!(b_out, Some(expected));

    // Bob (whose "turn" a full board always is) declared the tie; the stakes
    // went back to their owners.
    let tip = walk_tip(bob_entry.handle());
    assert_eq!(tip.clause_name().as_deref(), Some("tie"));
    let payout = tip.spending_tx().expect("settled");
    assert_eq!(payout.output[0].script_pubkey, p2tr(alice_pk()));
    assert_eq!(payout.output[1].script_pubkey, p2tr(bob_pk()));
}

#[test]
fn idle_opponent_forfaits_after_the_timeout() {
    let chain = Rc::new(LocalChain::new());
    let (mut alice, _bob, alice_entry, _bob_entry) = setup(&chain, &[4], &[]);

    // Alice opens; Bob's runner never steps (he walked away).
    for _ in 0..3 {
        alice.step().expect("alice steps");
    }
    // Nothing to claim until Bob's response window expires...
    chain.mine(TIMEOUT + 1);

    // ...then Alice's timeout fallback fires and takes the pot.
    let outcome = alice.run_one().expect("alice resolves");
    assert_eq!(
        outcome,
        TttOutcome {
            result: TttResult::AliceWins,
            by_timeout: true,
            board: board("... .X. ..."),
        }
    );

    let tip = walk_tip(alice_entry.handle());
    assert_eq!(tip.clause_name().as_deref(), Some("timeout_bob_idle"));
    let payout = tip.spending_tx().expect("forfait collected");
    assert_eq!(payout.output[0].script_pubkey, p2tr(alice_pk()));
    assert_eq!(payout.output[0].value, Amount::from_sat(POT));
    assert_eq!(payout.input[0].sequence, Sequence(TIMEOUT));
}

// ----------------------------------------------------------------------------
// End-to-end (regtest): the same transitions, adjudicated by a validating node
// ----------------------------------------------------------------------------

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_tictactoe_full_game_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    use mattrs::report::Report;
    use support::testkit::{regtest_client, report_spend};

    let client = regtest_client("testwallet");
    let mut manager = ContractManager::new(client, bitcoin::Network::Regtest);
    let mut report = Report::new();

    let game =
        TicTacToe::new(params())?.fund(&mut manager, Amount::from_sat(POT), TttState::initial())?;
    let entry = game.handle().clone();

    // Alice takes the top row while Bob starts the middle one: the moves
    // alternate A0 B3 A1 B4, each spend re-committing the board.
    let mut h = game;
    for (cell, alice_moves) in [(0, true), (3, false), (1, true), (4, false)] {
        let xpriv = if alice_moves {
            alice_xpriv()
        } else {
            bob_xpriv()
        };
        h = h
            .make_move(cell)?
            .sign(HotSigner::new(xpriv))
            .exec_one(&mut manager)?
            .try_into()?;
    }
    report_spend(&mut report, "TicTacToe", "the first four moves", &entry);

    // No line on the board yet: a win claim must be rejected by the node's
    // script interpreter (the line scan is consensus-enforced)...
    assert!(
        h.claim_win(MARK_BOB)?.exec_none(&mut manager).is_err(),
        "bob_wins must not validate without a line of O's"
    );
    // ...and so must a forfait claim before the CSV delay has passed.
    assert!(
        h.timeout_alice_idle()?.exec_none(&mut manager).is_err(),
        "the forfait must not validate before the timeout"
    );

    // Alice completes her line and claims the pot via the CTV template.
    let won: TicTacToeHandle = h
        .make_move(2)?
        .sign(HotSigner::new(alice_xpriv()))
        .exec_one(&mut manager)?
        .try_into()?;
    let state = won.state().expect("expanded state");
    assert_eq!(state.board, board("XXX OO. ..."));
    won.claim_win(MARK_ALICE)?.exec_none(&mut manager)?;
    report_spend(
        &mut report,
        "TicTacToe",
        "alice_wins (CTV payout of the pot)",
        won.handle(),
    );

    report.finalize("reports/report_tictactoe.md")?;
    Ok(())
}

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_tictactoe_forfait_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    use support::testkit::regtest_client;

    let client = regtest_client("testwallet");
    let mut manager = ContractManager::new(client, bitcoin::Network::Regtest);

    let game =
        TicTacToe::new(params())?.fund(&mut manager, Amount::from_sat(POT), TttState::initial())?;

    // Alice opens; Bob never answers.
    let h: TicTacToeHandle = game
        .make_move(4)?
        .sign(HotSigner::new(alice_xpriv()))
        .exec_one(&mut manager)?
        .try_into()?;

    // Once the CSV delay has passed, the forfait claim validates and pays
    // Alice the whole pot.
    manager.mine_blocks((TIMEOUT + 1).into())?;
    h.timeout_bob_idle()?.exec_none(&mut manager)?;
    let payout = h.handle().spending_tx().expect("forfait collected");
    assert_eq!(payout.output[0].script_pubkey, p2tr(alice_pk()));
    assert_eq!(payout.output[0].value, Amount::from_sat(POT));
    Ok(())
}
