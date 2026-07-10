//! Tic-tac-toe over a MATT covenant: the whole board lives in the UTXO.
//!
//! One augmented contract, [`TicTacToe`], holds the pot and commits
//! `sha256(turn_byte || 9 cell bytes)` as its state. Every spend reveals the
//! 10-byte preimage in the witness and rebuilds it with `OP_CAT`; moves commit
//! the updated board back **to the same contract** (`CHECKCONTRACTVERIFY` with
//! "same taptree", like the RAM example's `write`), so the game walks a chain
//! of UTXOs of the same contract until a terminal clause pays out via CTV:
//!
//! - `move_alice` / `move_bob`: the mover reveals the board as
//!   `prefix || suffix` around the chosen cell. The old preimage is rebuilt
//!   with the *constants* turn-byte and `EMPTY` inserted — which is what
//!   enforces turn order and that the cell was free — and the new preimage
//!   with the flipped turn and the mover's mark. The sha256 preimage length
//!   pins `|prefix| + |suffix| = 8`, so no explicit size checks are needed.
//! - `alice_wins` / `bob_wins`: the revealed board contains a line of the
//!   claimant's marks; the pot goes to them via a CTV template. No signature:
//!   the payout is fixed, so anyone may settle.
//! - `tie`: the revealed board is full (the turn byte is then provably
//!   `TURN_BOB`: Alice makes moves 1,3,5,7,9); the pot is split. There is
//!   deliberately no "no line" check — a player who could win but declares
//!   (or, by dawdling, allows) a tie eats the loss themselves.
//! - `timeout_alice_idle` / `timeout_bob_idle`: the player to move sat idle
//!   for `timeout_blocks` (CSV), and the opponent takes the whole pot. This
//!   also backstops a full board nobody settles: it is always Bob's "turn"
//!   there.
//!
//! Accepted looseness (by design): a winning move and its win claim are two
//! spends, and claims are first-come-first-served — honest roles claim
//! immediately, and a winner who forgoes the claim only hurts themselves.

use bitcoin::{Amount, ScriptBuf, Sequence, TxOut, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{
    ClauseError, ClauseOutput, ContractState, CtvTemplate, WitnessError,
};
use mattrs::manager::{MissingStateError, SpendBuilder};
use mattrs::script_helpers::{check_input_contract, concat, dup, key_path_p2tr, older};
use mattrs::{contract, Signature};
use mattrs_derive::ContractParams;

define_pushable!();

/// The default stake (in sats) each player bets.
pub const DEFAULT_STAKE: i64 = 1000;

/// The default forfait timeout, in blocks: how long the player to move may
/// idle before the opponent can claim the pot.
pub const DEFAULT_TIMEOUT_BLOCKS: u32 = 10;

// Cells and turns are 1-byte *strings* in script (`OP_CAT`/`OP_EQUAL` against
// pushed byte constants), never script numbers: 0x00 is not a minimal number.
/// An empty cell.
pub const EMPTY: u8 = 0x00;
/// Alice's mark (X). Alice moves first.
pub const MARK_ALICE: u8 = 0x01;
/// Bob's mark (O).
pub const MARK_BOB: u8 = 0x02;
/// Turn byte: Alice to move.
pub const TURN_ALICE: u8 = 0x00;
/// Turn byte: Bob to move.
pub const TURN_BOB: u8 = 0x01;

/// The eight winning lines: rows, columns, diagonals.
pub const LINES: [[usize; 3]; 8] = [
    [0, 1, 2],
    [3, 4, 5],
    [6, 7, 8],
    [0, 3, 6],
    [1, 4, 7],
    [2, 5, 8],
    [0, 4, 8],
    [2, 4, 6],
];

/// Whether `board` contains a full line of `mark`.
pub fn has_line(board: &[u8; 9], mark: u8) -> bool {
    LINES
        .iter()
        .any(|line| line.iter().all(|&i| board[i] == mark))
}

/// The mark holding a line, if any.
pub fn line_winner(board: &[u8; 9]) -> Option<u8> {
    [MARK_ALICE, MARK_BOB]
        .into_iter()
        .find(|&m| has_line(board, m))
}

/// Whether every cell is taken.
pub fn board_full(board: &[u8; 9]) -> bool {
    board.iter().all(|&c| c != EMPTY)
}

#[derive(Debug, Clone, ContractParams)]
pub struct TttParams {
    pub alice_pk: XOnlyPublicKey,
    pub bob_pk: XOnlyPublicKey,
    /// Each player's stake; the pot is `2 * stake`.
    pub stake: i64,
    /// The CSV delay after which an idle player forfeits the pot.
    pub timeout_blocks: u32,
}

/// The game state: whose turn it is and the nine cells. Committed on-chain as
/// the raw 10 bytes `turn || board` (the framework hashes non-32-byte
/// commitments, and the tapscripts rebuild that same sha256 with `OP_CAT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TttState {
    pub turn: u8,
    pub board: [u8; 9],
}

impl TttState {
    /// The state of a freshly funded game: empty board, Alice to move.
    pub fn initial() -> Self {
        TttState {
            turn: TURN_ALICE,
            board: [EMPTY; 9],
        }
    }

    /// The committed preimage, `turn || board`.
    pub fn preimage(&self) -> [u8; 10] {
        let mut bytes = [0u8; 10];
        bytes[0] = self.turn;
        bytes[1..].copy_from_slice(&self.board);
        bytes
    }

    /// The board split around `cell`, as a move clause's witness reveals it.
    pub fn prefix_suffix(&self, cell: usize) -> (Vec<u8>, Vec<u8>) {
        (self.board[..cell].to_vec(), self.board[cell + 1..].to_vec())
    }

    /// The state after placing `mark` at `cell`: the turn flips.
    pub fn after_move(&self, cell: usize, mark: u8) -> TttState {
        let mut board = self.board;
        board[cell] = mark;
        TttState {
            turn: if self.turn == TURN_ALICE { TURN_BOB } else { TURN_ALICE },
            board,
        }
    }
}

impl ContractState for TttState {
    fn encode(&self) -> Vec<u8> {
        self.preimage().to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        let bytes: &[u8; 10] = bytes.try_into().map_err(|_| {
            WitnessError::InvalidData("a TttState commits exactly 10 bytes".to_string())
        })?;
        let turn = bytes[0];
        let board: [u8; 9] = bytes[1..].try_into().expect("9 bytes");
        if turn != TURN_ALICE && turn != TURN_BOB {
            return Err(WitnessError::InvalidData(format!(
                "invalid turn byte {turn:#04x}"
            )));
        }
        if let Some(&cell) = board
            .iter()
            .find(|&&c| c != EMPTY && c != MARK_ALICE && c != MARK_BOB)
        {
            return Err(WitnessError::InvalidData(format!(
                "invalid cell byte {cell:#04x}"
            )));
        }
        Ok(TttState { turn, board })
    }
}

contract! {
    contract TicTacToe {
        params TttParams;
        state TttState;

        // witness: <prefix> <suffix> <alice_sig>
        clause move_alice {
            args {
                prefix: Vec<u8>,
                suffix: Vec<u8>,
                #[signer(p.alice_pk)]
                sig: Signature,
            }
            script TicTacToe::move_alice_script;
            next(p, a, s) {
                TicTacToe::next_after_move(p, s, &a.prefix, &a.suffix, TURN_ALICE, MARK_ALICE)
            }
        }

        // witness: <prefix> <suffix> <bob_sig>
        clause move_bob {
            args {
                prefix: Vec<u8>,
                suffix: Vec<u8>,
                #[signer(p.bob_pk)]
                sig: Signature,
            }
            script TicTacToe::move_bob_script;
            next(p, a, s) {
                TicTacToe::next_after_move(p, s, &a.prefix, &a.suffix, TURN_BOB, MARK_BOB)
            }
        }

        // witness: <t> <c0> ... <c8>
        clause alice_wins {
            args {
                t: [u8; 1],
                c0: [u8; 1], c1: [u8; 1], c2: [u8; 1],
                c3: [u8; 1], c4: [u8; 1], c5: [u8; 1],
                c6: [u8; 1], c7: [u8; 1], c8: [u8; 1],
            }
            script TicTacToe::alice_wins_script;
            next(p, _a) { Ok(TicTacToe::tmpl_alice_wins(p)) }
        }

        // witness: <t> <c0> ... <c8>
        clause bob_wins {
            args {
                t: [u8; 1],
                c0: [u8; 1], c1: [u8; 1], c2: [u8; 1],
                c3: [u8; 1], c4: [u8; 1], c5: [u8; 1],
                c6: [u8; 1], c7: [u8; 1], c8: [u8; 1],
            }
            script TicTacToe::bob_wins_script;
            next(p, _a) { Ok(TicTacToe::tmpl_bob_wins(p)) }
        }

        // witness: <c0> ... <c8> (the turn at a full board is always TURN_BOB)
        clause tie {
            args {
                c0: [u8; 1], c1: [u8; 1], c2: [u8; 1],
                c3: [u8; 1], c4: [u8; 1], c5: [u8; 1],
                c6: [u8; 1], c7: [u8; 1], c8: [u8; 1],
            }
            script TicTacToe::tie_script;
            next(p, _a) { Ok(TicTacToe::tmpl_tie(p)) }
        }

        // witness: <c0> ... <c8> (the turn byte is this clause's constant)
        clause timeout_alice_idle {
            args {
                c0: [u8; 1], c1: [u8; 1], c2: [u8; 1],
                c3: [u8; 1], c4: [u8; 1], c5: [u8; 1],
                c6: [u8; 1], c7: [u8; 1], c8: [u8; 1],
            }
            script TicTacToe::timeout_alice_idle_script;
            next(p, _a) { Ok(TicTacToe::tmpl_timeout_alice_idle(p)) }
        }

        // witness: <c0> ... <c8>
        clause timeout_bob_idle {
            args {
                c0: [u8; 1], c1: [u8; 1], c2: [u8; 1],
                c3: [u8; 1], c4: [u8; 1], c5: [u8; 1],
                c6: [u8; 1], c7: [u8; 1], c8: [u8; 1],
            }
            script TicTacToe::timeout_bob_idle_script;
            next(p, _a) { Ok(TicTacToe::tmpl_timeout_bob_idle(p)) }
        }

        tree [
            [move_alice, move_bob],
            [alice_wins, bob_wins],
            tie,
            [timeout_alice_idle, timeout_bob_idle]
        ];
    }
}

/// Push the 1-byte string `[b]` minimally. `OP_1..OP_16` leave exactly the
/// byte `[b]` on the stack (and minimal-push policy *requires* them over a
/// literal data push), while `[0x00]` needs the literal push — `OP_0` would
/// push the empty string instead.
fn push_byte(b: u8) -> ScriptBuf {
    if (1..=16).contains(&b) {
        script! { { b as i64 } }
    } else {
        script! { { vec![b] } }
    }
}

impl TicTacToe {
    /// The `next_outputs` of both move clauses: validate the move against the
    /// expanded state and re-emit the contract with the updated board.
    fn next_after_move(
        p: &TttParams,
        s: Option<&TttState>,
        prefix: &[u8],
        suffix: &[u8],
        turn: u8,
        mark: u8,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = s.ok_or_else(|| ClauseError::Other("a move needs the board state".to_string()))?;
        let cell = prefix.len();
        if cell >= 9 || suffix.len() != 8 - cell {
            return Err(ClauseError::Other(
                "malformed move: the prefix and suffix must split 8 cells".to_string(),
            ));
        }
        if state.turn != turn {
            return Err(ClauseError::Other("it is not this player's turn".to_string()));
        }
        if state.board[cell] != EMPTY {
            return Err(ClauseError::Other(format!("cell {cell} is already taken")));
        }
        if prefix != &state.board[..cell] || suffix != &state.board[cell + 1..] {
            return Err(ClauseError::Other(
                "the revealed board does not match the state".to_string(),
            ));
        }
        Ok(vec![ClauseOutput::at_same_index()
            .to(TicTacToe::new(p.clone()).as_erased())
            .with_state(&state.after_move(cell, mark))
            .preserve_amount()
            .build()])
    }

    // ------------------------------------------------------------------
    // CTV payout templates
    // ------------------------------------------------------------------

    /// The whole pot to `pk`. Timeout claims commit the CSV sequence (BIP-119
    /// commits the input's nSequence), settlements commit `Sequence::ZERO`.
    fn tmpl_pot_to(pk: XOnlyPublicKey, stake: i64, sequence: Sequence) -> CtvTemplate {
        CtvTemplate::new(
            vec![TxOut {
                script_pubkey: key_path_p2tr(pk),
                value: Amount::from_sat((2 * stake) as u64),
            }],
            sequence,
        )
    }

    fn tmpl_alice_wins(p: &TttParams) -> CtvTemplate {
        Self::tmpl_pot_to(p.alice_pk, p.stake, Sequence::ZERO)
    }

    fn tmpl_bob_wins(p: &TttParams) -> CtvTemplate {
        Self::tmpl_pot_to(p.bob_pk, p.stake, Sequence::ZERO)
    }

    fn tmpl_timeout_alice_idle(p: &TttParams) -> CtvTemplate {
        Self::tmpl_pot_to(p.bob_pk, p.stake, Sequence(p.timeout_blocks))
    }

    fn tmpl_timeout_bob_idle(p: &TttParams) -> CtvTemplate {
        Self::tmpl_pot_to(p.alice_pk, p.stake, Sequence(p.timeout_blocks))
    }

    fn tmpl_tie(p: &TttParams) -> CtvTemplate {
        CtvTemplate::new(
            vec![
                TxOut {
                    script_pubkey: key_path_p2tr(p.alice_pk),
                    value: Amount::from_sat(p.stake as u64),
                },
                TxOut {
                    script_pubkey: key_path_p2tr(p.bob_pk),
                    value: Amount::from_sat(p.stake as u64),
                },
            ],
            Sequence::ZERO,
        )
    }

    // ------------------------------------------------------------------
    // Tapscripts
    // ------------------------------------------------------------------

    /// Both move clauses, parameterized by the mover. The witness reveals the
    /// board split around the chosen cell; the *constants* spliced into the
    /// two preimages enforce everything else (turn order, cell emptiness, the
    /// flipped turn and the placed mark), and the preimage length pins
    /// `|prefix| + |suffix| = 8`.
    fn move_script(pk: XOnlyPublicKey, turn_old: u8, turn_new: u8, mark: u8) -> ScriptBuf {
        script! {
            // witness: <prefix> <suffix> <sig>
            { pk }
            OP_CHECKSIGVERIFY

            // rebuild the current preimage: turn_old || prefix || EMPTY || suffix
            OP_2DUP
            { push_byte(turn_old) }
            2 OP_ROLL
            OP_CAT
            { push_byte(EMPTY) }
            OP_CAT
            OP_SWAP
            OP_CAT
            OP_SHA256
            { check_input_contract(-1, None) }

            // build the next preimage: turn_new || prefix || mark || suffix
            { push_byte(turn_new) }
            2 OP_ROLL
            OP_CAT
            { push_byte(mark) }
            OP_CAT
            OP_SWAP
            OP_CAT
            OP_SHA256

            // commit it to the same contract at the same output index
            -1 0 -1 0 CHECKCONTRACTVERIFY
            OP_TRUE
        }
    }

    fn move_alice_script(p: &TttParams) -> ScriptBuf {
        Self::move_script(p.alice_pk, TURN_ALICE, TURN_BOB, MARK_ALICE)
    }

    fn move_bob_script(p: &TttParams) -> ScriptBuf {
        Self::move_script(p.bob_pk, TURN_BOB, TURN_ALICE, MARK_BOB)
    }

    /// Rebuild `turn || c0 || .. || c8` from the (duplicated) witness cells and
    /// check it against the input's committed state; the originals stay on the
    /// stack for the caller's own checks.
    fn check_revealed_board() -> ScriptBuf {
        script! {
            { dup(10) }
            OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
            OP_SHA256
            { check_input_contract(-1, None) }
        }
    }

    /// A win claim: the revealed board holds a line of `mark`; the pot goes
    /// out via `ctv_hash`. No signature — the template fixes the payout.
    ///
    /// The committed preimage only pins the *concatenation* of the witness
    /// elements, so each revealed cell is also pinned to exactly one byte
    /// (while tearing the stack down) — otherwise a claimant could shift
    /// bytes between elements and pass a line check with scattered marks.
    fn wins_script(mark: u8, ctv_hash: [u8; 32]) -> ScriptBuf {
        // witness: <t> <c0> ... <c8>; after the state check, cell i sits at
        // stack depth 8-i (and one deeper once the line accumulator is up).
        let mut parts = vec![Self::check_revealed_board()];
        for (i, [a, b, c]) in LINES.iter().copied().enumerate() {
            let off = i64::from(i > 0);
            let pa = 8 - a as i64 + off;
            let pb = 9 - b as i64 + off;
            let pc = 9 - c as i64 + off;
            parts.push(script! {
                { pa } OP_PICK
                { pb } OP_PICK
                OP_CAT
                { pc } OP_PICK
                OP_CAT
                { vec![mark; 3] }
                OP_EQUAL
            });
            if i > 0 {
                parts.push(script! { OP_BOOLOR });
            }
        }
        parts.push(script! { OP_VERIFY });
        // Consume the nine cells, pinning each to one byte (the turn byte's
        // size then follows from the 10-byte preimage).
        parts.extend(std::iter::repeat_n(
            script! { OP_SIZE 1 OP_EQUALVERIFY OP_DROP },
            9,
        ));
        parts.push(script! {
            OP_DROP
            { ctv_hash }
            OP_CHECKTEMPLATEVERIFY
        });
        concat(&parts)
    }

    fn alice_wins_script(p: &TttParams) -> ScriptBuf {
        Self::wins_script(MARK_ALICE, Self::tmpl_alice_wins(p).ctv_hash())
    }

    fn bob_wins_script(p: &TttParams) -> ScriptBuf {
        Self::wins_script(MARK_BOB, Self::tmpl_bob_wins(p).ctv_hash())
    }

    /// The tie claim: every revealed cell is taken. The turn byte at a full
    /// board is always `TURN_BOB` (Alice makes the odd-numbered moves), so it
    /// is a script constant rather than witness data.
    fn tie_script(p: &TttParams) -> ScriptBuf {
        // witness: <c0> ... <c8>
        let head = script! {
            { dup(9) }
            OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
            { push_byte(TURN_BOB) }
            OP_SWAP
            OP_CAT
            OP_SHA256
            { check_input_contract(-1, None) }
        };
        // Consume the nine originals: each exactly one byte (the preimage
        // only pins their concatenation) and taken.
        let non_empty = script! {
            OP_SIZE
            1
            OP_EQUALVERIFY
            { push_byte(EMPTY) }
            OP_EQUAL
            OP_NOT
            OP_VERIFY
        };
        let tail = script! {
            { Self::tmpl_tie(p).ctv_hash() }
            OP_CHECKTEMPLATEVERIFY
        };

        let mut parts = vec![head];
        parts.extend(std::iter::repeat_n(non_empty, 9));
        parts.push(tail);
        concat(&parts)
    }

    /// A forfait claim: the committed turn byte is `idle_turn` (a constant of
    /// the clause), the UTXO sat unspent for the CSV delay, and the opponent
    /// takes the pot via `ctv_hash`.
    fn timeout_script(timeout_blocks: u32, idle_turn: u8, ctv_hash: [u8; 32]) -> ScriptBuf {
        script! {
            // witness: <c0> ... <c8>
            OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT OP_CAT
            { push_byte(idle_turn) }
            OP_SWAP
            OP_CAT
            OP_SHA256
            { check_input_contract(-1, None) }
            { older(timeout_blocks) }
            { ctv_hash }
            OP_CHECKTEMPLATEVERIFY
        }
    }

    fn timeout_alice_idle_script(p: &TttParams) -> ScriptBuf {
        Self::timeout_script(
            p.timeout_blocks,
            TURN_ALICE,
            Self::tmpl_timeout_alice_idle(p).ctv_hash(),
        )
    }

    fn timeout_bob_idle_script(p: &TttParams) -> ScriptBuf {
        Self::timeout_script(
            p.timeout_blocks,
            TURN_BOB,
            Self::tmpl_timeout_bob_idle(p).ctv_hash(),
        )
    }
}

/// Ergonomic spend methods filling the board-reveal arguments from the
/// instance's typed state, so callers pass only what is genuinely new.
impl TicTacToeHandle {
    fn state_or_err(&self) -> Result<TttState, MissingStateError> {
        self.state().ok_or(MissingStateError {
            contract: "TicTacToe",
        })
    }

    /// The current player's move at `cell` (which must be empty).
    pub fn make_move(&self, cell: usize) -> Result<SpendBuilder, MissingStateError> {
        let s = self.state_or_err()?;
        let (prefix, suffix) = s.prefix_suffix(cell);
        Ok(if s.turn == TURN_ALICE {
            self.move_alice(prefix, suffix)
        } else {
            self.move_bob(prefix, suffix)
        })
    }

    pub fn claim_alice_wins(&self) -> Result<SpendBuilder, MissingStateError> {
        let s = self.state_or_err()?;
        let b = s.board;
        Ok(self.alice_wins(
            [s.turn],
            [b[0]], [b[1]], [b[2]], [b[3]], [b[4]], [b[5]], [b[6]], [b[7]], [b[8]],
        ))
    }

    pub fn claim_bob_wins(&self) -> Result<SpendBuilder, MissingStateError> {
        let s = self.state_or_err()?;
        let b = s.board;
        Ok(self.bob_wins(
            [s.turn],
            [b[0]], [b[1]], [b[2]], [b[3]], [b[4]], [b[5]], [b[6]], [b[7]], [b[8]],
        ))
    }

    pub fn claim_tie(&self) -> Result<SpendBuilder, MissingStateError> {
        let b = self.state_or_err()?.board;
        Ok(self.tie(
            [b[0]], [b[1]], [b[2]], [b[3]], [b[4]], [b[5]], [b[6]], [b[7]], [b[8]],
        ))
    }

    pub fn claim_timeout_alice_idle(&self) -> Result<SpendBuilder, MissingStateError> {
        let b = self.state_or_err()?.board;
        Ok(self.timeout_alice_idle(
            [b[0]], [b[1]], [b[2]], [b[3]], [b[4]], [b[5]], [b[6]], [b[7]], [b[8]],
        ))
    }

    pub fn claim_timeout_bob_idle(&self) -> Result<SpendBuilder, MissingStateError> {
        let b = self.state_or_err()?.board;
        Ok(self.timeout_bob_idle(
            [b[0]], [b[1]], [b[2]], [b[3]], [b[4]], [b[5]], [b[6]], [b[7]], [b[8]],
        ))
    }
}

// ============================================================================
// The players, as protocol roles
// ============================================================================

/// The two players as declarative [`Role`](mattrs::protocol::Role)s, driven by
/// a [`Runner`](mattrs::protocol::Runner) — against a regtest node in the
/// two-player demo (`main.rs`) and against the offline `LocalChain` in
/// `tests/test_tictactoe.rs`.
pub mod roles {
    use bitcoin::bip32::Xpriv;

    use mattrs::protocol::{Action, ProtocolError, Role};
    use mattrs::signer::HotSigner;

    use super::{
        board_full, has_line, TicTacToe, TicTacToeClause, TicTacToeHandle, EMPTY, MARK_ALICE,
        MARK_BOB, TURN_ALICE, TURN_BOB,
    };

    /// How a player picks the next cell, given the board. Tests inject
    /// scripted sequences; the demo injects a stdin prompt.
    pub type Strategy = Box<dyn FnMut(&[u8; 9]) -> usize>;

    /// A player's private side: their key and their move-picking strategy.
    pub struct PlayerData {
        pub xpriv: Xpriv,
        pub strategy: Strategy,
    }

    /// Who takes the pot.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TttResult {
        AliceWins,
        BobWins,
        Tie,
    }

    /// The settled game, as one party resolved it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TttOutcome {
        pub result: TttResult,
        /// Whether the pot moved on a forfait rather than a played outcome.
        pub by_timeout: bool,
        /// The final board (as of the settled instance).
        pub board: [u8; 9],
    }

    pub fn alice_role() -> Role<PlayerData, TttOutcome> {
        player_role(true)
    }

    pub fn bob_role() -> Role<PlayerData, TttOutcome> {
        player_role(false)
    }

    /// Both players run the same state machine, parameterized by their side:
    /// claim a win the moment the board shows it; on their own turn, move (or
    /// declare the tie on a full board); on the opponent's turn, wait — with
    /// the forfait claim as the timeout fallback.
    fn player_role(alice: bool) -> Role<PlayerData, TttOutcome> {
        let (my_mark, opp_mark) = if alice {
            (MARK_ALICE, MARK_BOB)
        } else {
            (MARK_BOB, MARK_ALICE)
        };
        let my_turn = if alice { TURN_ALICE } else { TURN_BOB };
        let my_win = if alice {
            TttResult::AliceWins
        } else {
            TttResult::BobWins
        };

        Role::new()
            .on::<TicTacToe, _>(move |d: &mut PlayerData, h: TicTacToeHandle, _cx| {
                let params = h.params()?;
                let s = h.state().ok_or_else(|| {
                    ProtocolError::Other("the game state is unavailable".to_string())
                })?;

                // My line is on the board: claim the pot.
                if has_line(&s.board, my_mark) {
                    let builder = if alice {
                        h.claim_alice_wins()?
                    } else {
                        h.claim_bob_wins()?
                    };
                    return Ok(Action::SendFinal(
                        builder,
                        TttOutcome {
                            result: my_win,
                            by_timeout: false,
                            board: s.board,
                        },
                    ));
                }

                if s.turn == my_turn {
                    if has_line(&s.board, opp_mark) {
                        // I lost; the opponent's runner claims.
                        return Ok(Action::Wait);
                    }
                    if board_full(&s.board) {
                        return Ok(Action::SendFinal(
                            h.claim_tie()?,
                            TttOutcome {
                                result: TttResult::Tie,
                                by_timeout: false,
                                board: s.board,
                            },
                        ));
                    }
                    let cell = (d.strategy)(&s.board);
                    if cell >= 9 || s.board[cell] != EMPTY {
                        return Err(ProtocolError::Other(format!(
                            "the strategy chose an invalid cell ({cell})"
                        )));
                    }
                    return Ok(Action::Send(
                        h.make_move(cell)?.sign(HotSigner::new(d.xpriv)),
                    ));
                }

                // The opponent's turn: watch the UTXO, and claim the forfait
                // if they idle past the timeout.
                let builder = if alice {
                    h.claim_timeout_bob_idle()?
                } else {
                    h.claim_timeout_alice_idle()?
                };
                Ok(Action::wait_or_send_final(
                    params.timeout_blocks,
                    builder,
                    TttOutcome {
                        result: my_win,
                        by_timeout: true,
                        board: s.board,
                    },
                ))
            })
            .on_settled::<TicTacToe, _>(move |_d, h: TicTacToeHandle, _cx| {
                let clause = h.spent_clause().ok_or_else(|| {
                    ProtocolError::Other("the game instance is not settled".to_string())
                })?;
                let s = h.state().ok_or_else(|| {
                    ProtocolError::Other("the game state is unavailable".to_string())
                })?;

                // Classify the counterparty's terminal claim, checking it
                // against the board we know.
                let (result, by_timeout, justified) = match clause {
                    TicTacToeClause::AliceWins => {
                        (TttResult::AliceWins, false, has_line(&s.board, MARK_ALICE))
                    }
                    TicTacToeClause::BobWins => {
                        (TttResult::BobWins, false, has_line(&s.board, MARK_BOB))
                    }
                    TicTacToeClause::Tie => (TttResult::Tie, false, board_full(&s.board)),
                    TicTacToeClause::TimeoutAliceIdle => {
                        (TttResult::BobWins, true, s.turn == TURN_ALICE)
                    }
                    TicTacToeClause::TimeoutBobIdle => {
                        (TttResult::AliceWins, true, s.turn == TURN_BOB)
                    }
                    TicTacToeClause::MoveAlice | TicTacToeClause::MoveBob => {
                        return Err(ProtocolError::Other(
                            "a move is not a settlement".to_string(),
                        ));
                    }
                };
                if !justified {
                    return Err(ProtocolError::Other(format!(
                        "the `{}` claim does not match the board",
                        clause.name()
                    )));
                }
                Ok(TttOutcome {
                    result,
                    by_timeout,
                    board: s.board,
                })
            })
    }
}
