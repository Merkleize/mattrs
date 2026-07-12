//! The bisection fraud proof on Ingrid's claimed `(R, 0) => (R', X)` run.
//!
//! Modeled on `mattrs::fraud` (same trace commitments, same turn structure),
//! with two differences forced by the setting:
//!
//! - The parties are dynamic (Ingrid and the challenger appear long after the
//!   pool is created), so their keys — and everything else a settlement needs,
//!   packed into the *carry* leaf ([`super::ChallengeContext`]) — live in
//!   committed state rather than params. The scripts stay party-independent,
//!   which keeps every taptree in the chain a params-only constant.
//! - No clause needs a sighash signature: reveals are data-bound to the trace
//!   commitments both parties posted up front, and the terminal clauses fix
//!   every output. A reveal "turn" is enforced by its forfait deadline alone.
//!
//! Termination routes the pot back into the covenant: the challenger winning
//! reverts the pool to [`Unwind`]`{r}` and slashes Ingrid's bond (half to the
//! challenger, half burned); Ingrid winning resumes [`PendingExit`] with the
//! original claim (fresh challenge period) and slashes the challenger's bond
//! the same way. If *both* parties committed false traces, neither [`ExitLeaf`]
//! clause is satisfiable and the pot is stuck — a mutual-griefing corner also
//! present in the generic fraud module (both bonds are already lost at that
//! point).

use bitcoin::ScriptBuf;
use bitcoin_script::{define_pushable, script};
use mattrs::contract;
use mattrs::contracts::{
    ArgSpec, ClauseError, ClauseOutput, CCV_FLAG_CHECK_INPUT, CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
};
use mattrs::manager::SpendBuilder;
use mattrs::merkle::{get_directions, is_power_of_2, MerkleTree, NIL};
use mattrs::script_utils::{bn2vch, commit_int};
use mattrs_derive::ContractParams;

use super::pending_exit::PendingExit;
use mattrs::stack::{Source, StackScript};
use super::unwind::{Unwind, UnwindState};
use super::{
    reveal_mids, spec, spec_num, w32, ChallengeContext, ExitClaim, PoolParams, PoolTree,
    CARRY_ITEMS,
};

define_pushable!();

// ============================================================================
// Params
// ============================================================================

/// A bisection stage over step range `[i, j]` (inclusive; the range size is a
/// power of two by protocol invariant).
#[derive(Debug, Clone, ContractParams)]
pub struct BisectRangeParams {
    pub pool: PoolParams,
    pub i: i64,
    pub j: i64,
}

impl BisectRangeParams {
    /// The entry range: all `padded_size` steps.
    pub fn entry(pool: &PoolParams) -> Self {
        BisectRangeParams {
            pool: pool.clone(),
            i: 0,
            j: pool.padded_size() as i64 - 1,
        }
    }

    /// Half the range size; panics on a malformed range (as in `fraud`).
    pub fn m(&self) -> i64 {
        let n = self.j - self.i + 1;
        assert!(
            self.j > self.i && is_power_of_2(n as usize),
            "a bisect range must span 2+ steps, a power of two (got [{}, {}])",
            self.i,
            self.j
        );
        n / 2
    }

    /// Whether the two halves are single steps ([`ExitLeaf`]s).
    pub fn children_are_leaves(&self) -> bool {
        self.m() == 1
    }
}

/// The single disputed step `k`, re-run on-chain.
#[derive(Debug, Clone, ContractParams)]
pub struct LeafStepParams {
    pub pool: PoolParams,
    pub k: i64,
}

// ============================================================================
// States
// ============================================================================

/// [`ExitBisect1`] state: the range endpoints/traces plus the carry leaf.
#[derive(Debug, Clone)]
pub struct ExitBisect1State {
    pub h_start: [u8; 32],
    pub h_end_i: [u8; 32],
    pub h_end_c: [u8; 32],
    pub trace_i: [u8; 32],
    pub trace_c: [u8; 32],
    pub ctx: ChallengeContext,
}

impl ExitBisect1State {
    fn leaves(&self) -> Vec<[u8; 32]> {
        vec![
            self.h_start,
            self.h_end_i,
            self.h_end_c,
            self.trace_i,
            self.trace_c,
            self.ctx.carry(),
        ]
    }

    fn to_witness(&self) -> Vec<Vec<u8>> {
        self.leaves().iter().map(|l| l.to_vec()).collect()
    }
}

mattrs::opaque_merkle_state!(ExitBisect1State);

/// [`ExitBisect2`] state: [`ExitBisect1State`] plus Ingrid's revealed midpoint
/// and half-traces.
#[derive(Debug, Clone)]
pub struct ExitBisect2State {
    pub h_start: [u8; 32],
    pub h_end_i: [u8; 32],
    pub h_end_c: [u8; 32],
    pub trace_i: [u8; 32],
    pub trace_c: [u8; 32],
    pub h_mid_i: [u8; 32],
    pub trace_left_i: [u8; 32],
    pub trace_right_i: [u8; 32],
    pub ctx: ChallengeContext,
}

impl ExitBisect2State {
    fn leaves(&self) -> Vec<[u8; 32]> {
        vec![
            self.h_start,
            self.h_end_i,
            self.h_end_c,
            self.trace_i,
            self.trace_c,
            self.ctx.carry(),
            self.h_mid_i,
            self.trace_left_i,
            self.trace_right_i,
        ]
    }

    fn to_witness(&self) -> Vec<Vec<u8>> {
        self.leaves().iter().map(|l| l.to_vec()).collect()
    }
}

mattrs::opaque_merkle_state!(ExitBisect2State);

/// [`ExitLeaf`] state: the agreed start, the two claimed ends, the carry.
#[derive(Debug, Clone)]
pub struct ExitLeafState {
    pub h_start: [u8; 32],
    pub h_end_i: [u8; 32],
    pub h_end_c: [u8; 32],
    pub ctx: ChallengeContext,
}

impl ExitLeafState {
    fn leaves(&self) -> Vec<[u8; 32]> {
        vec![self.h_start, self.h_end_i, self.h_end_c, self.ctx.carry()]
    }
}

mattrs::opaque_merkle_state!(ExitLeafState);

// ============================================================================
// Settlement (shared by forfaits and leaf outcomes)
// ============================================================================

/// Who a dispute resolved for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeWinner {
    Ingrid,
    Challenger,
}

fn xonly(bytes: &[u8; 32]) -> Result<bitcoin::XOnlyPublicKey, ClauseError> {
    bitcoin::XOnlyPublicKey::from_slice(bytes)
        .map_err(|e| ClauseError::Other(format!("invalid x-only key in state: {e}")))
}

/// The three settlement outputs: the winner's slash payout, the burn, and the
/// covenant continuation (resume the claim if Ingrid won, revert the pool if
/// the challenger did).
fn settlement_outputs(
    pool: &PoolParams,
    ctx: &ChallengeContext,
    winner: DisputeWinner,
) -> Result<Vec<ClauseOutput>, ClauseError> {
    let continuation = match winner {
        DisputeWinner::Ingrid => ClauseOutput::at(2)
            .to(PendingExit::new(pool.clone()).as_erased())
            .with_state(&ctx.resume_state)
            .preserve_amount()
            .build(),
        DisputeWinner::Challenger => ClauseOutput::at(2)
            .to(Unwind::new(pool.clone()).as_erased())
            .with_state(&UnwindState {
                root: ctx.resume_state.r,
            })
            .preserve_amount()
            .build(),
    };
    let winner_pk = match winner {
        DisputeWinner::Ingrid => xonly(&ctx.resume_state.ingrid_pk)?,
        DisputeWinner::Challenger => xonly(&ctx.challenger_pk)?,
    };
    Ok(vec![
        ClauseOutput::pay_key(0, winner_pk),
        ClauseOutput::burn(1),
        continuation,
    ])
}

/// The settlement tail of a script whose stack still tracks the expanded carry
/// ([`CARRY_ITEMS`]): output 0 pays the winner, output 1 burns, output 2
/// continues the covenant.
///
/// TODO(OP_AMOUNT): the slash amounts cannot be enforced yet. The intended
/// split is `bond / 2` to the winner and `bond - bond / 2` burned when the
/// loser is a challenger, and `bond + bond / 2` / `bond - bond / 2` when the
/// loser is Ingrid (the challenger also recovers their own bond).
fn settlement_script(s: &mut StackScript, winner: DisputeWinner) {
    let winner_item = match winner {
        DisputeWinner::Ingrid => "ingrid_pk",
        DisputeWinner::Challenger => "challenger_pk",
    };
    s.ccv(
        Source::None,
        0,
        Source::Item(winner_item),
        Source::None,
        CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
    );
    s.ccv(
        Source::None,
        1,
        Source::Const(mattrs::nums_key().serialize()),
        Source::None,
        CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
    );
    match winner {
        DisputeWinner::Ingrid => s.ccv(
            Source::Item("resume"),
            2,
            Source::None,
            Source::Item("pe_taptree"),
            0,
        ),
        DisputeWinner::Challenger => s.ccv(
            Source::Item("r"),
            2,
            Source::None,
            Source::Item("unwind_taptree"),
            0,
        ),
    }
}

/// The forfait witness: the state's plain leaves (the carry leaf omitted at
/// `carry_index`) followed by the expanded carry components — the layout of
/// every clause that re-expands the carry in-script.
fn carry_expanded_witness(
    leaves: &[[u8; 32]],
    carry_index: usize,
    ctx: &ChallengeContext,
) -> Vec<Vec<u8>> {
    let mut witness: Vec<Vec<u8>> = leaves
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != carry_index)
        .map(|(_, l)| l.to_vec())
        .collect();
    witness.extend(ctx.carry_witness());
    witness
}

const B1_ITEMS: [&str; 5] = ["h_start", "h_end_i", "h_end_c", "trace_i", "trace_c"];
const B2_ITEMS: [&str; 8] = [
    "h_start", "h_end_i", "h_end_c", "trace_i", "trace_c", "h_mid_i", "t_left_i", "t_right_i",
];

/// The committed-leaves name list of a bisection state: `items` with the
/// carry leaf inserted at position 5 (after the endpoint/trace leaves).
fn with_carry(items: &[&'static str]) -> Vec<&'static str> {
    let mut leaves = items[..5].to_vec();
    leaves.push("carry");
    leaves.extend(&items[5..]);
    leaves
}

// ============================================================================
// ExitBisect1 — Ingrid's turn
// ============================================================================

contract! {
    /// Ingrid must reveal her claimed midpoint and half-traces for `[i, j]`
    /// (bound to her committed trace) within the response timeout, or the
    /// challenger collects by `forfait`.
    contract ExitBisect1 {
        params BisectRangeParams;
        state ExitBisect1State;

        // witness: <h_start> <h_end_i> <h_end_c> <trace_i> <trace_c> <carry>
        //          <h_mid_i> <t_left_i> <t_right_i>
        clause ingrid_reveal {
            args raw |_p| ExitBisect1::ingrid_reveal_specs();
            script ExitBisect1::ingrid_reveal_script;
            next(p, a, s) {
                ExitBisect1::ingrid_reveal_outputs(p, &a.0, s)
            }
        }

        // witness: <h_start> <h_end_i> <h_end_c> <trace_i> <trace_c>
        //          <carry components x 7>
        clause forfait {
            args raw |_p| ExitBisect1::forfait_specs();
            script ExitBisect1::forfait_script;
            timelock |p| p.pool.response_timeout;
            next(p, a, s) {
                ExitBisect1::forfait_outputs(p, &a.0, s)
            }
        }

        tree [ingrid_reveal, forfait];
    }
}

impl ExitBisect1 {
    fn ingrid_reveal_specs() -> Vec<ArgSpec> {
        let mut specs: Vec<ArgSpec> = with_carry(&B1_ITEMS).iter().map(|n| spec(n)).collect();
        specs.extend([spec("h_mid_i"), spec("t_left_i"), spec("t_right_i")]);
        specs
    }

    fn ingrid_reveal_script(p: &BisectRangeParams) -> ScriptBuf {
        let mut s = StackScript::from_specs(&Self::ingrid_reveal_specs());

        s.merkle_of(&with_carry(&B1_ITEMS), "state");
        s.ccv(
            Source::Item("state"),
            -1,
            Source::None,
            Source::Current,
            CCV_FLAG_CHECK_INPUT,
        );

        // t[i,j] = H(h_i || h_{j+1} || t_left || t_right), against her
        // committed trace: the reveal cannot be forged.
        s.sha_cat(&["h_start", "h_end_i", "t_left_i", "t_right_i"], "t");
        s.expect_equal("t", "trace_i");

        s.merkle_of(&with_carry(&B2_ITEMS), "b2_state");
        let b2_root = ExitBisect2::new(p.clone()).taptree_root();
        s.ccv(Source::Item("b2_state"), -1, Source::None, Source::Const(b2_root), 0);
        s.into_script()
    }

    fn ingrid_reveal_outputs(
        p: &BisectRangeParams,
        witness: &[Vec<u8>],
        state: Option<&ExitBisect1State>,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = state.ok_or_else(|| {
            ClauseError::Other("ingrid_reveal needs the bisection state".to_string())
        })?;
        let next = ExitBisect2State {
            h_start: state.h_start,
            h_end_i: state.h_end_i,
            h_end_c: state.h_end_c,
            trace_i: state.trace_i,
            trace_c: state.trace_c,
            h_mid_i: w32(witness, 6)?,
            trace_left_i: w32(witness, 7)?,
            trace_right_i: w32(witness, 8)?,
            ctx: state.ctx.clone(),
        };
        Ok(vec![ClauseOutput::at_same_index()
            .to(ExitBisect2::new(p.clone()).as_erased())
            .with_state(&next)
            .preserve_amount()
            .build()])
    }

    fn forfait_specs() -> Vec<ArgSpec> {
        B1_ITEMS
            .iter()
            .chain(CARRY_ITEMS.iter())
            .map(|n| spec(n))
            .collect()
    }

    fn forfait_script(_p: &BisectRangeParams) -> ScriptBuf {
        let mut s = StackScript::from_specs(&Self::forfait_specs());
        s.sha_cat(&CARRY_ITEMS, "carry");
        s.merkle_of(&with_carry(&B1_ITEMS), "state");
        s.ccv(
            Source::Item("state"),
            -1,
            Source::None,
            Source::Current,
            CCV_FLAG_CHECK_INPUT,
        );
        settlement_script(&mut s, DisputeWinner::Challenger);
        s.into_script()
    }

    fn forfait_outputs(
        p: &BisectRangeParams,
        _witness: &[Vec<u8>],
        state: Option<&ExitBisect1State>,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = state.ok_or_else(|| {
            ClauseError::Other("forfait needs the bisection state".to_string())
        })?;
        settlement_outputs(&p.pool, &state.ctx, DisputeWinner::Challenger)
    }
}

impl ExitBisect1Handle {
    fn bisect_state(&self) -> ExitBisect1State {
        self.state().expect("ExitBisect1 instances carry their state")
    }

    /// Ingrid reveals her midpoint/half-traces for this range, from her
    /// claimed step commitments `hs`.
    pub fn ingrid_reveal(&self, hs: &[[u8; 32]]) -> SpendBuilder {
        let p = self.params();
        let (h_mid, t_left, t_right) = reveal_mids(hs, p.i as usize, p.j as usize);
        let mut witness = self.bisect_state().to_witness();
        witness.extend([h_mid.to_vec(), t_left.to_vec(), t_right.to_vec()]);
        self.0.spend_clause("ingrid_reveal", witness)
    }

    /// The challenger collects after Ingrid's response timeout. The caller
    /// must set the slash amounts (`.output_amount(0, bond + bond / 2)`,
    /// `.output_amount(1, bond - bond / 2)`); the clause's `timelock` sets
    /// the CSV sequence.
    pub fn forfait(&self) -> SpendBuilder {
        let state = self.bisect_state();
        let witness = carry_expanded_witness(&state.leaves(), 5, &state.ctx);
        self.0.spend_clause("forfait", witness)
    }
}

// ============================================================================
// ExitBisect2 — the challenger's turn
// ============================================================================

contract! {
    /// The challenger reveals their own midpoint/half-traces and recurses into
    /// the half where the claims diverge: *left* if the midpoints differ,
    /// *right* if they agree (a fresh [`ExitBisect1`], or [`ExitLeaf`] once
    /// the half is a single step). Stalling forfaits to Ingrid.
    contract ExitBisect2 {
        params BisectRangeParams;
        state ExitBisect2State;

        // witness: <state leaves x 9-with-carry> <h_mid_c> <t_left_c> <t_right_c>
        clause challenger_left {
            args raw |_p| ExitBisect2::reveal_specs();
            script |p| ExitBisect2::reveal_script(p, Side::Left);
            next(p, a, s) {
                ExitBisect2::reveal_outputs(p, &a.0, s, Side::Left)
            }
        }

        clause challenger_right {
            args raw |_p| ExitBisect2::reveal_specs();
            script |p| ExitBisect2::reveal_script(p, Side::Right);
            next(p, a, s) {
                ExitBisect2::reveal_outputs(p, &a.0, s, Side::Right)
            }
        }

        // witness: <plain leaves x 8> <carry components x 7>
        clause forfait {
            args raw |_p| ExitBisect2::forfait_specs();
            script ExitBisect2::forfait_script;
            timelock |p| p.pool.response_timeout;
            next(p, a, s) {
                ExitBisect2::forfait_outputs(p, &a.0, s)
            }
        }

        tree [[challenger_left, challenger_right], forfait];
    }
}

/// Which half a challenger reveal recurses into.
#[derive(Debug, Clone, Copy)]
enum Side {
    Left,
    Right,
}

impl ExitBisect2 {
    fn reveal_specs() -> Vec<ArgSpec> {
        let mut specs: Vec<ArgSpec> = with_carry(&B2_ITEMS).iter().map(|n| spec(n)).collect();
        specs.extend([spec("h_mid_c"), spec("t_left_c"), spec("t_right_c")]);
        specs
    }

    fn reveal_script(p: &BisectRangeParams, side: Side) -> ScriptBuf {
        let mut s = StackScript::from_specs(&Self::reveal_specs());

        s.merkle_of(&with_carry(&B2_ITEMS), "state");
        s.ccv(
            Source::Item("state"),
            -1,
            Source::None,
            Source::Current,
            CCV_FLAG_CHECK_INPUT,
        );

        // The challenger's reveal, bound to *their* committed trace.
        s.sha_cat(&["h_start", "h_end_c", "t_left_c", "t_right_c"], "t");
        s.expect_equal("t", "trace_c");

        // Left: the midpoints differ; right: they agree.
        s.pick("h_mid_i");
        s.pick("h_mid_c");
        match side {
            Side::Left => s.raw(script! { OP_EQUAL OP_NOT OP_VERIFY }, 2, &[]),
            Side::Right => s.equal_verify(),
        }

        // The child's endpoints/traces are the revealed values of the chosen
        // half; the carry rides through unchanged.
        let child_leaves: Vec<&str> = match (side, p.children_are_leaves()) {
            (Side::Left, true) => vec!["h_start", "h_mid_i", "h_mid_c", "carry"],
            (Side::Left, false) => {
                vec!["h_start", "h_mid_i", "h_mid_c", "t_left_i", "t_left_c", "carry"]
            }
            (Side::Right, true) => vec!["h_mid_i", "h_end_i", "h_end_c", "carry"],
            (Side::Right, false) => {
                vec!["h_mid_i", "h_end_i", "h_end_c", "t_right_i", "t_right_c", "carry"]
            }
        };
        s.merkle_of(&child_leaves, "child_state");
        s.ccv(
            Source::Item("child_state"),
            -1,
            Source::None,
            Source::Const(Self::child_root(p, side)),
            0,
        );
        s.into_script()
    }

    fn child_range(p: &BisectRangeParams, side: Side) -> (i64, i64) {
        let m = p.m();
        match side {
            Side::Left => (p.i, p.i + m - 1),
            Side::Right => (p.i + m, p.j),
        }
    }

    fn child_root(p: &BisectRangeParams, side: Side) -> [u8; 32] {
        let (i, j) = Self::child_range(p, side);
        if p.children_are_leaves() {
            ExitLeaf::new(LeafStepParams {
                pool: p.pool.clone(),
                k: i,
            })
            .taptree_root()
        } else {
            ExitBisect1::new(BisectRangeParams {
                pool: p.pool.clone(),
                i,
                j,
            })
            .taptree_root()
        }
    }

    fn reveal_outputs(
        p: &BisectRangeParams,
        witness: &[Vec<u8>],
        state: Option<&ExitBisect2State>,
        side: Side,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = state.ok_or_else(|| {
            ClauseError::Other("challenger reveal needs the bisection state".to_string())
        })?;
        let h_mid_c = w32(witness, 9)?;
        let t_left_c = w32(witness, 10)?;
        let t_right_c = w32(witness, 11)?;

        let (h_start, h_end_i, h_end_c, trace_i, trace_c) = match side {
            Side::Left => (
                state.h_start,
                state.h_mid_i,
                h_mid_c,
                state.trace_left_i,
                t_left_c,
            ),
            Side::Right => (
                state.h_mid_i,
                state.h_end_i,
                state.h_end_c,
                state.trace_right_i,
                t_right_c,
            ),
        };
        let (i, j) = Self::child_range(p, side);
        let output = if p.children_are_leaves() {
            ClauseOutput::at_same_index()
                .to(ExitLeaf::new(LeafStepParams {
                    pool: p.pool.clone(),
                    k: i,
                })
                .as_erased())
                .with_state(&ExitLeafState {
                    h_start,
                    h_end_i,
                    h_end_c,
                    ctx: state.ctx.clone(),
                })
        } else {
            ClauseOutput::at_same_index()
                .to(ExitBisect1::new(BisectRangeParams {
                    pool: p.pool.clone(),
                    i,
                    j,
                })
                .as_erased())
                .with_state(&ExitBisect1State {
                    h_start,
                    h_end_i,
                    h_end_c,
                    trace_i,
                    trace_c,
                    ctx: state.ctx.clone(),
                })
        };
        Ok(vec![output.preserve_amount().build()])
    }

    fn forfait_specs() -> Vec<ArgSpec> {
        B2_ITEMS
            .iter()
            .chain(CARRY_ITEMS.iter())
            .map(|n| spec(n))
            .collect()
    }

    fn forfait_script(_p: &BisectRangeParams) -> ScriptBuf {
        let mut s = StackScript::from_specs(&Self::forfait_specs());
        s.sha_cat(&CARRY_ITEMS, "carry");
        s.merkle_of(&with_carry(&B2_ITEMS), "state");
        s.ccv(
            Source::Item("state"),
            -1,
            Source::None,
            Source::Current,
            CCV_FLAG_CHECK_INPUT,
        );
        settlement_script(&mut s, DisputeWinner::Ingrid);
        s.into_script()
    }

    fn forfait_outputs(
        p: &BisectRangeParams,
        _witness: &[Vec<u8>],
        state: Option<&ExitBisect2State>,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = state.ok_or_else(|| {
            ClauseError::Other("forfait needs the bisection state".to_string())
        })?;
        settlement_outputs(&p.pool, &state.ctx, DisputeWinner::Ingrid)
    }
}

impl ExitBisect2Handle {
    fn bisect_state(&self) -> ExitBisect2State {
        self.state().expect("ExitBisect2 instances carry their state")
    }

    /// The challenger reveals their midpoint/half-traces from their claimed
    /// step commitments `hs`, recursing into the diverging half.
    pub fn challenger_reveal(&self, hs: &[[u8; 32]]) -> SpendBuilder {
        let p = self.params();
        let state = self.bisect_state();
        let (h_mid, t_left, t_right) = reveal_mids(hs, p.i as usize, p.j as usize);
        let clause = if h_mid == state.h_mid_i {
            "challenger_right"
        } else {
            "challenger_left"
        };
        let mut witness = state.to_witness();
        witness.extend([h_mid.to_vec(), t_left.to_vec(), t_right.to_vec()]);
        self.0.spend_clause(clause, witness)
    }

    /// Ingrid collects after the challenger's response timeout. The caller
    /// must set the slash amounts (`.output_amount(0, bond / 2)`,
    /// `.output_amount(1, bond - bond / 2)`); the clause's `timelock` sets
    /// the CSV sequence.
    pub fn forfait(&self) -> SpendBuilder {
        let state = self.bisect_state();
        let witness = carry_expanded_witness(&state.leaves(), 5, &state.ctx);
        self.0.spend_clause("forfait", witness)
    }
}

// ============================================================================
// ExitLeaf — the disputed step, re-run on-chain
// ============================================================================

/// What actually happens at the disputed step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepCase {
    /// The step's exit bit is 0: the state is unchanged.
    Noop,
    /// The bit is 1 but the slot is already zeroed (or padding): unchanged.
    Nil,
    /// The bit is 1 and the slot holds an account: zero it, add its balance.
    Spend,
}

contract! {
    /// The disputed single step `k`, re-run on-chain with fixed-index Merkle
    /// proofs (the directions for `k` are script constants). One clause per
    /// (winner, step-case) pair keeps each script straight-line; whichever
    /// party's committed ending matches the recomputed one wins, and the
    /// settlement mirrors the forfait clauses.
    contract ExitLeaf {
        params LeafStepParams;
        state ExitLeafState;

        clause ingrid_noop {
            args raw |p| ExitLeaf::case_specs(p, StepCase::Noop);
            script |p| ExitLeaf::case_script(p, StepCase::Noop, DisputeWinner::Ingrid);
            next(p, _a, s) { ExitLeaf::case_outputs(p, s, DisputeWinner::Ingrid) }
        }
        clause ingrid_nil {
            args raw |p| ExitLeaf::case_specs(p, StepCase::Nil);
            script |p| ExitLeaf::case_script(p, StepCase::Nil, DisputeWinner::Ingrid);
            next(p, _a, s) { ExitLeaf::case_outputs(p, s, DisputeWinner::Ingrid) }
        }
        clause ingrid_spend {
            args raw |p| ExitLeaf::case_specs(p, StepCase::Spend);
            script |p| ExitLeaf::case_script(p, StepCase::Spend, DisputeWinner::Ingrid);
            next(p, _a, s) { ExitLeaf::case_outputs(p, s, DisputeWinner::Ingrid) }
        }
        clause challenger_noop {
            args raw |p| ExitLeaf::case_specs(p, StepCase::Noop);
            script |p| ExitLeaf::case_script(p, StepCase::Noop, DisputeWinner::Challenger);
            next(p, _a, s) { ExitLeaf::case_outputs(p, s, DisputeWinner::Challenger) }
        }
        clause challenger_nil {
            args raw |p| ExitLeaf::case_specs(p, StepCase::Nil);
            script |p| ExitLeaf::case_script(p, StepCase::Nil, DisputeWinner::Challenger);
            next(p, _a, s) { ExitLeaf::case_outputs(p, s, DisputeWinner::Challenger) }
        }
        clause challenger_spend {
            args raw |p| ExitLeaf::case_specs(p, StepCase::Spend);
            script |p| ExitLeaf::case_script(p, StepCase::Spend, DisputeWinner::Challenger);
            next(p, _a, s) { ExitLeaf::case_outputs(p, s, DisputeWinner::Challenger) }
        }

        tree [[[ingrid_noop, ingrid_nil], ingrid_spend],
              [[challenger_noop, challenger_nil], challenger_spend]];
    }
}

/// Walk a fixed-index Merkle path from `start` up to the root: `k` is a script
/// constant, so each level's concatenation order is baked in.
fn fixed_walk(
    s: &mut StackScript,
    start: &str,
    sib_prefix: &str,
    directions: &[u8],
    out: &str,
) {
    s.pick(start);
    s.rename_top(out);
    for (l, d) in directions.iter().enumerate().rev() {
        s.pick(&format!("{sib_prefix}_{l}"));
        if *d == 1 {
            // The node is a right child: parent = H(sibling || node).
            s.raw(script! { OP_SWAP OP_CAT OP_SHA256 }, 2, &[out]);
        } else {
            s.raw(script! { OP_CAT OP_SHA256 }, 2, &[out]);
        }
    }
}

impl ExitLeaf {
    fn directions(p: &LeafStepParams) -> Vec<u8> {
        get_directions(p.pool.padded_size(), p.k as usize)
    }

    fn case_specs(p: &LeafStepParams, case: StepCase) -> Vec<ArgSpec> {
        let depth = p.pool.depth();
        let mut specs: Vec<ArgSpec> = ["h_start", "h_end_i", "h_end_c"]
            .iter()
            .chain(CARRY_ITEMS.iter())
            .map(|n| spec(n))
            .collect();
        match case {
            StepCase::Noop => {}
            StepCase::Nil => {
                specs.extend([spec("root_k"), spec_num("sum")]);
            }
            StepCase::Spend => {
                specs.extend([spec("root_k"), spec_num("sum"), spec("user_pk"), spec_num("bal")]);
            }
        }
        for l in 0..depth {
            specs.push(spec(&format!("s_sib_{l}")));
        }
        if case != StepCase::Noop {
            for l in 0..depth {
                specs.push(spec(&format!("r_sib_{l}")));
            }
        }
        specs
    }

    fn case_script(p: &LeafStepParams, case: StepCase, winner: DisputeWinner) -> ScriptBuf {
        let dirs = Self::directions(p);
        let mut s = StackScript::from_specs(&Self::case_specs(p, case));

        // Reveal the state (expanding the carry) and bind it to the input.
        s.sha_cat(&CARRY_ITEMS, "carry");
        s.merkle_of(&["h_start", "h_end_i", "h_end_c", "carry"], "state");
        s.ccv(
            Source::Item("state"),
            -1,
            Source::None,
            Source::Current,
            CCV_FLAG_CHECK_INPUT,
        );

        // Prove step k's exit bit against the committed set.
        let claimed_bit = if case == StepCase::Noop { 0 } else { 1 };
        s.push_const("bit_leaf", commit_int(claimed_bit));
        fixed_walk(&mut s, "bit_leaf", "s_sib", &dirs, "bit_root");
        s.expect_equal("bit_root", "s_root");

        // Re-run the step on the revealed (root, sum) preimage of h_start.
        let h_end_item: &str = match case {
            StepCase::Noop => {
                // Nothing changes: the honest ending is h_start itself.
                "h_start"
            }
            StepCase::Nil => {
                s.sha_cat(&["root_k", "sum"], "h_check");
                s.expect_equal("h_check", "h_start");
                // The slot is already NIL: zeroing it changes nothing.
                s.push_const("nil_leaf", NIL);
                fixed_walk(&mut s, "nil_leaf", "r_sib", &dirs, "nil_root");
                s.expect_equal("nil_root", "root_k");
                "h_start"
            }
            StepCase::Spend => {
                s.sha_cat(&["root_k", "sum"], "h_check");
                s.expect_equal("h_check", "h_start");
                // The slot holds (user_pk, bal): prove it, zero it, add bal.
                s.sha_cat(&["user_pk", "bal"], "account_leaf");
                fixed_walk(&mut s, "account_leaf", "r_sib", &dirs, "root_check");
                s.expect_equal("root_check", "root_k");
                s.push_const("nil_leaf", NIL);
                fixed_walk(&mut s, "nil_leaf", "r_sib", &dirs, "root_new");
                // NOTE: OP_ADD is 32-bit script arithmetic; real amounts need
                // 64-bit arithmetic opcodes (the demo keeps sums < 2^31).
                s.pick("sum");
                s.pick("bal");
                s.raw(script! { OP_ADD }, 2, &["sum_new"]);
                s.sha_cat(&["root_new", "sum_new"], "h_end");
                "h_end"
            }
        };

        // Whoever's committed ending matches the recomputed one wins.
        let winner_end = match winner {
            DisputeWinner::Ingrid => "h_end_i",
            DisputeWinner::Challenger => "h_end_c",
        };
        s.expect_equal(h_end_item, winner_end);

        settlement_script(&mut s, winner);
        s.into_script()
    }

    fn case_outputs(
        p: &LeafStepParams,
        state: Option<&ExitLeafState>,
        winner: DisputeWinner,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = state.ok_or_else(|| {
            ClauseError::Other("leaf settlement needs the dispute state".to_string())
        })?;
        settlement_outputs(&p.pool, &state.ctx, winner)
    }
}

/// The pool as it stands *before* step `k` of a claimed run: slots exited by
/// earlier steps are zeroed.
pub fn pool_at_step(pool: &PoolTree, bits: &[bool], k: usize) -> PoolTree {
    let mut working = pool.clone();
    for u in 0..k {
        if bits[u] {
            working.zero(u);
        }
    }
    working
}

impl ExitLeafHandle {
    /// Re-run the disputed step as `winner`, using that party's claimed step
    /// values from `claim` and the (public) pool contents. The caller must set
    /// the slash amounts (see the forfait methods).
    pub fn reveal(
        &self,
        winner: DisputeWinner,
        claim: &ExitClaim,
        pool: &PoolTree,
    ) -> SpendBuilder {
        let p = self.params();
        let k = p.k as usize;
        let state: ExitLeafState =
            self.state().expect("ExitLeaf instances carry their state");

        let working = pool_at_step(pool, &claim.bits, k);
        let case = if !claim.bits[k] {
            StepCase::Noop
        } else if working.accounts[k].is_some() {
            StepCase::Spend
        } else {
            StepCase::Nil
        };
        let clause = match (winner, case) {
            (DisputeWinner::Ingrid, StepCase::Noop) => "ingrid_noop",
            (DisputeWinner::Ingrid, StepCase::Nil) => "ingrid_nil",
            (DisputeWinner::Ingrid, StepCase::Spend) => "ingrid_spend",
            (DisputeWinner::Challenger, StepCase::Noop) => "challenger_noop",
            (DisputeWinner::Challenger, StepCase::Nil) => "challenger_nil",
            (DisputeWinner::Challenger, StepCase::Spend) => "challenger_spend",
        };

        let mut witness = carry_expanded_witness(&state.leaves(), 3, &state.ctx);
        match case {
            StepCase::Noop => {}
            StepCase::Nil => {
                witness.push(claim.roots[k].to_vec());
                witness.push(bn2vch(claim.sums[k]));
            }
            StepCase::Spend => {
                let (user_pk, bal) = working.accounts[k].expect("spend case has an account");
                witness.push(claim.roots[k].to_vec());
                witness.push(bn2vch(claim.sums[k]));
                witness.push(user_pk.serialize().to_vec());
                witness.push(bn2vch(bal));
            }
        }
        let bit_tree =
            MerkleTree::new(claim.bits.iter().map(|b| super::bit_leaf(*b)).collect());
        for sib in bit_tree.prove_leaf(k).hashes {
            witness.push(sib.to_vec());
        }
        if case != StepCase::Noop {
            for sib in working.prove(k).hashes {
                witness.push(sib.to_vec());
            }
        }
        self.0.spend_clause(clause, witness)
    }
}
