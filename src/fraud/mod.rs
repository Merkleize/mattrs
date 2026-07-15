//! Generic bisection fraud-proof contracts, ported from pymatt's `hub/fraud.py`.
//!
//! # The protocol
//!
//! Alice claims that an `n`-step computation (`n` a power of two) starting from
//! `x` ends in `y`; Bob disagrees. Writing the intermediate values as
//! `x = x_0 => x_1 => ... => x_n = y` and their commitments as `h_i` (the
//! [`Computer::encoder`]'s output for `x_i`), define the *trace* of a step range
//! `[i, j]` as
//!
//! ```text
//! t[i,j] = sha256(h_i || h_{j+1})                          if i == j
//! t[i,j] = sha256(h_i || h_{j+1} || t[i,i+m-1] || t[i+m,j])  otherwise, m = (j-i+1)/2
//! ```
//!
//! Starting from the full range, the parties alternate turns maintaining the
//! *bisection invariant* — they agree on the range's starting commitment but
//! disagree on its ending one:
//!
//! - [`Bisect1`] (Alice's turn): Alice reveals her mid-state commitment and
//!   sub-traces (checked against her committed trace), moving to [`Bisect2`].
//! - [`Bisect2`] (Bob's turn): Bob reveals his; if the mid-states differ the
//!   dispute recurses into the *left* half, else into the *right* half — a
//!   fresh [`Bisect1`], or a [`Leaf`] once the range is a single step.
//! - [`Leaf`]: the disputed single step is re-run on-chain: whoever's claimed
//!   ending commitment matches the [`Computer::func`]'s actual output takes the
//!   funds.
//!
//! Each `Bisect` stage also has a `forfait` clause letting the counterparty
//! collect after a timeout if the party holding the turn stalls.
//!
//! The computation being adjudicated is abstracted by [`Computer`] (its step
//! function and value-commitment as script fragments, plus the witness specs of
//! one value) and by a [`LeafFactory`] producing the per-step [`Leaf`] contract.
//! The three contracts are `contract!` DSL definitions; the non-encodable parts
//! of their construction — the [`Computer`], and the [`LeafFactory`] plus
//! forfait timeout (as [`BisectCtx`]) — ride in each contract's `ctx`. See
//! `tests/support/game256.rs` for a complete instantiation (`f(x) = 2x`, values
//! committed as `sha256(x)`).
//!
//! As in the pymatt reference, bonds/slashing are not implemented.
//!
//! The tapscripts here count `OP_PICK` depths by hand instead of using the
//! [`crate::stack`] tracker: the game256 tests pin these scripts (and thus the
//! taptree roots) byte-for-byte against pymatt, and a tracker rewrite would
//! change the emitted bytes. New scripts should prefer [`crate::stack`].

pub mod roles;

use std::sync::Arc;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};

use crate::Signature;
use crate::argtypes::{BytesType, SignerType};
use crate::contracts::{
    ArgSpec, ClauseError, ClauseOutput, ContractParams as ContractParamsTrait, ParamEncodable,
    WitnessError,
};
pub use crate::manager::MissingStateError;
use crate::manager::SpendBuilder;
use crate::merkle::is_power_of_2;
use crate::script_helpers::{
    check_input_contract, check_output_contract, concat, drop as script_drop, dup, merkle_root,
    timeout_sig_script,
};
use mattrs_derive::{ContractParams, ContractState, contract};

define_pushable!();

/// Invalid public input to the generic fraud-proof construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FraudError {
    /// A bisection must cover at least two non-negative steps, and its size
    /// must be a power of two.
    InvalidBisectRange { i: i64, j: i64 },
    /// A trace range is not backed by endpoint commitments in the supplied slice.
    InvalidTraceRange {
        i: usize,
        j: usize,
        commitments: usize,
    },
    /// A trace range's number of steps must be a power of two.
    TraceRangeNotPowerOfTwo { i: usize, j: usize },
    /// A forfait must require at least one confirmation block.
    ZeroForfaitTimeout,
}

impl std::fmt::Display for FraudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBisectRange { i, j } => write!(
                f,
                "a bisection range must cover 2+ non-negative steps and have power-of-two size (got [{i}, {j}])"
            ),
            Self::InvalidTraceRange { i, j, commitments } => write!(
                f,
                "trace range [{i}, {j}] is invalid for {commitments} commitment(s)"
            ),
            Self::TraceRangeNotPowerOfTwo { i, j } => {
                write!(f, "trace range [{i}, {j}] does not have power-of-two size")
            }
            Self::ZeroForfaitTimeout => write!(f, "forfait timeout must be at least one block"),
        }
    }
}

impl std::error::Error for FraudError {}

// ============================================================================
// The computation being adjudicated
// ============================================================================

/// The single computational step a fraud proof adjudicates, as script fragments.
///
/// Mirrors pymatt's `Computer`: everything else in this module is generic over it.
#[derive(Debug, Clone)]
pub struct Computer {
    /// Maps a step value `x...` on the stack to its commitment `h_x`
    /// (e.g. `OP_SHA256`).
    pub encoder: ScriptBuf,
    /// Maps a step value `x...` on the stack to the next value `y...`
    /// (e.g. `OP_DUP OP_ADD` for `y = 2x`).
    pub func: ScriptBuf,
    /// The witness layout of one step value (one [`ArgSpec`] per stack element).
    pub specs: Vec<ArgSpec>,
}

/// Produces the [`Leaf`] contract adjudicating step `i`. Most computations use
/// the same leaf for every step and ignore the index.
pub type LeafFactory = Arc<dyn Fn(i64) -> Leaf + Send + Sync>;

/// The construction context of the `Bisect` contracts: everything they need
/// beyond their (encodable) [`BisectParams`].
#[derive(Clone)]
pub struct BisectCtx {
    /// Produces the [`Leaf`] contract adjudicating a given step.
    leaf_factory: LeafFactory,
    /// The blocks after which a stalled turn forfaits the pot.
    forfait_timeout: u32,
}

impl BisectCtx {
    /// Construct a bisection context with a non-zero forfait timeout.
    pub fn new(leaf_factory: LeafFactory, forfait_timeout: u32) -> Result<Self, FraudError> {
        if forfait_timeout == 0 {
            return Err(FraudError::ZeroForfaitTimeout);
        }
        Ok(Self {
            leaf_factory,
            forfait_timeout,
        })
    }

    /// The configured forfait timeout in blocks.
    pub fn forfait_timeout(&self) -> u32 {
        self.forfait_timeout
    }

    /// Build the leaf contract adjudicating `step`.
    pub fn leaf(&self, step: i64) -> Leaf {
        (self.leaf_factory)(step)
    }
}

/// The trace commitment `t[i,j]` over the hashed step states `hs`, where
/// `hs[k]` commits the value before step `k` (so `hs` has `n + 1` entries for
/// an `n`-step computation):
///
/// ```text
/// t[i,j] = sha256(h_i || h_{j+1})                             if i == j
/// t[i,j] = sha256(h_i || h_{j+1} || t[i,i+m-1] || t[i+m,j])   otherwise
/// ```
///
/// with `m = (j - i + 1) / 2`. This is the off-chain half of the equation the
/// `Bisect` reveal clauses re-check on-chain; each party derives the reveal
/// arguments for range `[i, j]` from its own claimed `hs`.
///
pub fn trace(hs: &[[u8; 32]], i: usize, j: usize) -> Result<[u8; 32], FraudError> {
    let endpoint = j.checked_add(1);
    if i > j || endpoint.is_none_or(|end| end >= hs.len()) {
        return Err(FraudError::InvalidTraceRange {
            i,
            j,
            commitments: hs.len(),
        });
    }
    let size = j - i + 1;
    if !is_power_of_2(size) {
        return Err(FraudError::TraceRangeNotPowerOfTwo { i, j });
    }

    let mut preimage = Vec::with_capacity(128);
    preimage.extend_from_slice(&hs[i]);
    preimage.extend_from_slice(&hs[j + 1]);
    if i != j {
        let m = size / 2;
        preimage.extend_from_slice(&trace(hs, i, i + m - 1)?);
        preimage.extend_from_slice(&trace(hs, i + m, j)?);
    }
    Ok(sha256::Hash::hash(&preimage).to_byte_array())
}

// ============================================================================
// Leaf — the disputed single step, re-run on-chain
// ============================================================================

/// The two parties of a [`Leaf`] adjudication.
#[derive(Debug, Clone, ContractParams)]
pub struct LeafParams {
    pub alice_pk: XOnlyPublicKey,
    pub bob_pk: XOnlyPublicKey,
}

/// The disputed step's commitment: the starting hash and each party's claimed
/// ending hash. Committed on-chain as the Merkle root of the three.
#[derive(Debug, Clone, ContractState)]
#[commit(merkle)]
pub struct LeafState {
    pub h_start: [u8; 32],
    pub h_end_alice: [u8; 32],
    pub h_end_bob: [u8; 32],
}

/// Which party's reveal clause a leaf script is built for; they differ only in
/// where the honest ending hash lands among the three state leaves.
enum RevealSide {
    Alice,
    Bob,
}

contract! {
    /// The base case of the bisection: both clauses re-run the disputed step
    /// with the [`Computer`]'s fragments and pay the party whose claimed ending
    /// commitment matches the actual output. Clauses are terminal. The witness
    /// layout depends on the [`Computer`]'s specs, so both clauses use raw args;
    /// [`LeafHandle`] adds the typed reveal methods.
    contract Leaf {
        params LeafParams;
        ctx Computer;
        state LeafState;

        // witness: <sig> <x...> <h_y_b>
        clause alice_reveal {
            args raw |p, c| Leaf::reveal_specs(p.alice_pk, c, "h_y_b");
            script |p, c| Leaf::reveal_script(p.alice_pk, c, RevealSide::Alice);
        }

        // witness: <sig> <x...> <h_y_a>
        clause bob_reveal {
            args raw |p, c| Leaf::reveal_specs(p.bob_pk, c, "h_y_a");
            script |p, c| Leaf::reveal_script(p.bob_pk, c, RevealSide::Bob);
        }

        tree [alice_reveal, bob_reveal];
    }
}

impl Leaf {
    /// `[sig, <one spec per step-value element>, h_y_<other party>]`.
    fn reveal_specs(pk: XOnlyPublicKey, computer: &Computer, other_hash: &str) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec {
            name: "sig".to_string(),
            arg_type: Arc::new(SignerType::new(pk.serialize())),
        }];
        specs.extend(computer.specs.iter().cloned());
        specs.push(ArgSpec {
            name: other_hash.to_string(),
            arg_type: Arc::new(BytesType),
        });
        specs
    }

    // witness: <sig> <x...> <h_y_other>
    fn reveal_script(pk: XOnlyPublicKey, computer: &Computer, side: RevealSide) -> ScriptBuf {
        // Reassemble the three state leaves in [h_start, h_end_alice, h_end_bob]
        // order: the revealing party's recomputed h_y is the honest ending hash.
        let reorder = match side {
            RevealSide::Alice => script! { OP_FROMALTSTACK OP_SWAP OP_FROMALTSTACK },
            RevealSide::Bob => script! { OP_FROMALTSTACK OP_SWAP OP_FROMALTSTACK OP_SWAP },
        };
        concat(&[
            script! { OP_TOALTSTACK },
            dup(computer.specs.len()),
            computer.encoder.clone(), // h_x
            script! { OP_TOALTSTACK },
            computer.func.clone(),    // y
            computer.encoder.clone(), // h_y
            reorder,
            merkle_root(3),
            check_input_contract(-1, None),
            script! { { pk } OP_CHECKSIG },
        ])
    }
}

impl LeafHandle {
    /// Alice re-runs the disputed step, revealing the step value `x` (its
    /// witness elements, one per [`Computer`] spec). The counterparty's claimed
    /// ending commitment comes from the instance state.
    pub fn alice_reveal(&self, x: Vec<Vec<u8>>) -> Result<SpendBuilder, MissingStateError> {
        self.reveal("alice_reveal", x, |s| s.h_end_bob)
    }

    /// Bob re-runs the disputed step, revealing the step value `x` (its witness
    /// elements, one per [`Computer`] spec). The counterparty's claimed ending
    /// commitment comes from the instance state.
    pub fn bob_reveal(&self, x: Vec<Vec<u8>>) -> Result<SpendBuilder, MissingStateError> {
        self.reveal("bob_reveal", x, |s| s.h_end_alice)
    }

    fn reveal(
        &self,
        clause: &'static str,
        x: Vec<Vec<u8>>,
        other_hash: fn(&LeafState) -> [u8; 32],
    ) -> Result<SpendBuilder, MissingStateError> {
        let state = self.state().ok_or(MissingStateError { contract: "Leaf" })?;
        // The signature element stays empty; the manager fills it at spend time.
        let mut witness = vec![Vec::new()];
        witness.extend(x);
        witness.push(other_hash(&state).to_vec());
        Ok(self.0.spend_clause(clause, witness))
    }
}

// ============================================================================
// Bisect_1 / Bisect_2 — the recursive core, over any step range [i, j]
// ============================================================================

/// The two parties of a bisection stage and the step range it disputes.
#[derive(Debug, Clone)]
pub struct BisectParams {
    pub alice_pk: XOnlyPublicKey,
    pub bob_pk: XOnlyPublicKey,
    /// The disputed step range [i, j] (inclusive), `n = j - i + 1` a power of two.
    i: i64,
    j: i64,
}

impl BisectParams {
    /// Construct a validated bisection range.
    pub fn new(
        alice_pk: XOnlyPublicKey,
        bob_pk: XOnlyPublicKey,
        i: i64,
        j: i64,
    ) -> Result<Self, FraudError> {
        let size = j
            .checked_sub(i)
            .and_then(|difference| difference.checked_add(1))
            .and_then(|size| usize::try_from(size).ok());
        if i < 0 || j <= i || size.is_none_or(|size| !is_power_of_2(size)) {
            return Err(FraudError::InvalidBisectRange { i, j });
        }
        Ok(Self {
            alice_pk,
            bob_pk,
            i,
            j,
        })
    }

    /// First disputed step (inclusive).
    pub fn i(&self) -> i64 {
        self.i
    }

    /// Last disputed step (inclusive).
    pub fn j(&self) -> i64 {
        self.j
    }

    /// Half the range size, `m = n/2`. The children cover [i, i+m-1] and [i+m, j].
    pub fn m(&self) -> i64 {
        (self.j - self.i + 1) / 2
    }

    /// Whether the two children are single steps (Leaves) rather than sub-Bisects.
    pub fn children_are_leaves(&self) -> bool {
        self.m() == 1
    }
}

// The derived codec handles framing; the public wrapper validates decoded
// ranges before they can re-enter contract construction.
#[derive(Debug, Clone, ContractParams)]
struct EncodedBisectParams {
    alice_pk: XOnlyPublicKey,
    bob_pk: XOnlyPublicKey,
    i: i64,
    j: i64,
}

impl From<&BisectParams> for EncodedBisectParams {
    fn from(params: &BisectParams) -> Self {
        Self {
            alice_pk: params.alice_pk,
            bob_pk: params.bob_pk,
            i: params.i,
            j: params.j,
        }
    }
}

impl TryFrom<EncodedBisectParams> for BisectParams {
    type Error = FraudError;

    fn try_from(params: EncodedBisectParams) -> Result<Self, Self::Error> {
        Self::new(params.alice_pk, params.bob_pk, params.i, params.j)
    }
}

impl ParamEncodable for BisectParams {
    fn encode_param(&self) -> Vec<Vec<u8>> {
        ParamEncodable::encode_param(&EncodedBisectParams::from(self))
    }

    fn decode_param(elements: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        let (params, consumed) = EncodedBisectParams::decode_param(elements)?;
        let params = params
            .try_into()
            .map_err(|error: FraudError| WitnessError::InvalidValue(error.to_string()))?;
        Ok((params, consumed))
    }
}

impl ContractParamsTrait for BisectParams {
    fn encode(&self) -> Vec<u8> {
        ContractParamsTrait::encode(&EncodedBisectParams::from(self))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        EncodedBisectParams::decode(bytes)?
            .try_into()
            .map_err(|error: FraudError| WitnessError::InvalidValue(error.to_string()))
    }
}

/// Bisect_1 state: {h_start, h_end_a, h_end_b, trace_a, trace_b}.
#[derive(Debug, Clone, ContractState)]
#[commit(merkle)]
pub struct Bisect1State {
    pub h_start: [u8; 32],
    pub h_end_a: [u8; 32],
    pub h_end_b: [u8; 32],
    pub trace_a: [u8; 32],
    pub trace_b: [u8; 32],
}

/// Bisect_2 state: the Bisect_1 fields plus Alice's revealed midstate/traces.
#[derive(Debug, Clone, ContractState)]
#[commit(merkle)]
pub struct Bisect2State {
    pub h_start: [u8; 32],
    pub h_end_a: [u8; 32],
    pub h_end_b: [u8; 32],
    pub trace_a: [u8; 32],
    pub trace_b: [u8; 32],
    pub h_mid_a: [u8; 32],
    pub trace_left_a: [u8; 32],
    pub trace_right_a: [u8; 32],
}

/// Alice's reveal moves the whole (verified) reveal to the Bisect_2 commitment.
impl From<&Bisect1AliceRevealArgs> for Bisect2State {
    fn from(a: &Bisect1AliceRevealArgs) -> Self {
        Bisect2State {
            h_start: a.h_start,
            h_end_a: a.h_end_a,
            h_end_b: a.h_end_b,
            trace_a: a.trace_a,
            trace_b: a.trace_b,
            h_mid_a: a.h_mid_a,
            trace_left_a: a.trace_left_a,
            trace_right_a: a.trace_right_a,
        }
    }
}

contract! {
    /// Alice's turn of the bisection over [i, j]: `alice_reveal` moves to
    /// [`Bisect2`] with the same range, `forfait` pays Bob after the timeout.
    contract Bisect1 {
        params BisectParams;
        ctx BisectCtx;
        state Bisect1State;

        // Alice's reveal: the midstate and child traces backing her committed
        // trace (the `#[from_state]` fields re-reveal the commitment).
        clause alice_reveal {
            args {
                #[signer(p.alice_pk)]
                alice_sig: Signature,
                #[from_state] h_start: [u8; 32],
                #[from_state] h_end_a: [u8; 32],
                #[from_state] h_end_b: [u8; 32],
                #[from_state] trace_a: [u8; 32],
                #[from_state] trace_b: [u8; 32],
                h_mid_a: [u8; 32],
                trace_left_a: [u8; 32],
                trace_right_a: [u8; 32],
            }
            script |p, c| Bisect1::alice_reveal_script(
                p.alice_pk,
                Bisect2::new(p.clone(), c.clone())
                    .expect("Bisect2 contract definition is valid")
                    .taptree_root(),
            );
            next(p, a) {
                Ok(vec![ClauseOutput::at_same_index()
                    .to(Bisect2::new(p.clone(), ctx.clone())?.as_erased())
                    .with_state(&Bisect2State::from(a))
                    .preserve_amount()
                    .build()])
            }
        }

        // Bob claims the pot if Alice abandons the challenge.
        clause forfait {
            args {
                #[signer(p.bob_pk)]
                bob_sig: Signature,
            }
            script |p, c| timeout_sig_script(c.forfait_timeout(), p.bob_pk);
        }

        tree [alice_reveal, forfait];
    }
}

impl Bisect1 {
    /// Script fragment handing a spend off into this bisection: consumes the
    /// five entry-state leaves from the stack (`h_start`, `h_end_alice`,
    /// `h_end_bob`, `trace_alice`, `trace_bob`, with `trace_bob` on top) and
    /// verifies that output `index` (`-1` = same as the input) pays this
    /// [`Bisect1`] committing to them. The `next`-side counterpart is
    /// [`entry_output`](Bisect1::entry_output); embedding contracts use the
    /// pair without knowing the bisection state's layout.
    pub fn state_output_script(&self, index: i64) -> ScriptBuf {
        concat(&[
            merkle_root(5),
            check_output_contract(self.taptree_root(), index, None),
        ])
    }

    /// The [`ClauseOutput`] entering this bisection with the given endpoint
    /// and trace commitments (the `next`-side counterpart of
    /// [`state_output_script`](Bisect1::state_output_script)).
    pub fn entry_output(
        &self,
        h_start: [u8; 32],
        h_end_alice: [u8; 32],
        h_end_bob: [u8; 32],
        trace_alice: [u8; 32],
        trace_bob: [u8; 32],
    ) -> ClauseOutput {
        ClauseOutput::at_same_index()
            .to(self.as_erased())
            .with_state(&Bisect1State {
                h_start,
                h_end_a: h_end_alice,
                h_end_b: h_end_bob,
                trace_a: trace_alice,
                trace_b: trace_bob,
            })
            .preserve_amount()
            .build()
    }

    // witness: <alice_sig> <h_start> <h_end_a> <h_end_b> <trace_a> <trace_b>
    // <h_mid_a> <trace_left_a> <trace_right_a>
    fn alice_reveal_script(alice_pk: XOnlyPublicKey, bisect2_root: [u8; 32]) -> ScriptBuf {
        script! {
            OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
            { dup(5) }
            { merkle_root(5) }
            { check_input_contract(-1, None) }
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            // t_{i,j;a} = H(h_i || h_{j+1;a} || t_left_a || t_right_a)
            7 OP_PICK 7 OP_PICK OP_CAT 2 OP_PICK OP_CAT 1 OP_PICK OP_CAT OP_SHA256
            5 OP_PICK OP_EQUALVERIFY
            // output: the top 8 elements -> Bisect_2
            { merkle_root(8) }
            { check_output_contract(bisect2_root, -1, None) }
            { alice_pk }
            OP_CHECKSIG
        }
    }
}

/// Which half of the disputed range Bob's reveal recurses into.
#[derive(Debug, Clone, Copy)]
enum Side {
    Left,
    Right,
}

/// A valid half of a bisection is either its single-step base case or another
/// bisection range. Keeping those cases distinct prevents constructing a
/// `Bisect1` with a one-step range.
enum ChildRange {
    Leaf(i64),
    Bisect(BisectParams),
}

contract! {
    /// Bob's turn of the bisection over [i, j]: `bob_reveal_left`/
    /// `bob_reveal_right` recurse into the disputed half (a [`Leaf`] at a
    /// single step, else a fresh [`Bisect1`]); `forfait` pays Alice after the
    /// timeout.
    contract Bisect2 {
        params BisectParams;
        ctx BisectCtx;
        state Bisect2State;

        // Bob's reveal when the parties' midstates DIFFER: his midstate and
        // child traces, recursing into the left half.
        clause bob_reveal_left {
            args {
                #[signer(p.bob_pk)]
                bob_sig: Signature,
                #[from_state] h_start: [u8; 32],
                #[from_state] h_end_a: [u8; 32],
                #[from_state] h_end_b: [u8; 32],
                #[from_state] trace_a: [u8; 32],
                #[from_state] trace_b: [u8; 32],
                #[from_state] h_mid_a: [u8; 32],
                #[from_state] trace_left_a: [u8; 32],
                #[from_state] trace_right_a: [u8; 32],
                h_mid_b: [u8; 32],
                trace_left_b: [u8; 32],
                trace_right_b: [u8; 32],
            }
            script |p, c| Bisect2::bob_reveal_script(
                p.bob_pk,
                p.children_are_leaves(),
                Side::Left,
                Bisect2::child_root(p, Side::Left, c),
            );
            next(p, a) {
                Bisect2::child_output(
                    p, ctx, Side::Left,
                    a.h_start, a.h_mid_a, a.h_mid_b, a.trace_left_a, a.trace_left_b,
                )
            }
        }

        // Bob's reveal when the parties' midstates AGREE: recurse into the
        // right half.
        clause bob_reveal_right {
            args {
                #[signer(p.bob_pk)]
                bob_sig: Signature,
                #[from_state] h_start: [u8; 32],
                #[from_state] h_end_a: [u8; 32],
                #[from_state] h_end_b: [u8; 32],
                #[from_state] trace_a: [u8; 32],
                #[from_state] trace_b: [u8; 32],
                #[from_state] h_mid_a: [u8; 32],
                #[from_state] trace_left_a: [u8; 32],
                #[from_state] trace_right_a: [u8; 32],
                h_mid_b: [u8; 32],
                trace_left_b: [u8; 32],
                trace_right_b: [u8; 32],
            }
            script |p, c| Bisect2::bob_reveal_script(
                p.bob_pk,
                p.children_are_leaves(),
                Side::Right,
                Bisect2::child_root(p, Side::Right, c),
            );
            next(p, a) {
                Bisect2::child_output(
                    p, ctx, Side::Right,
                    a.h_mid_a, a.h_end_a, a.h_end_b, a.trace_right_a, a.trace_right_b,
                )
            }
        }

        // Alice claims the pot if Bob abandons the challenge.
        clause forfait {
            args {
                #[signer(p.alice_pk)]
                alice_sig: Signature,
            }
            script |p, c| timeout_sig_script(c.forfait_timeout(), p.alice_pk);
        }

        tree [[bob_reveal_left, bob_reveal_right], forfait];
    }
}

impl Bisect2 {
    /// The child range Bob's reveal on `side` recurses into.
    fn child_range(params: &BisectParams, side: Side) -> ChildRange {
        let m = params.m();
        let (i, j) = match side {
            Side::Left => (params.i(), params.i() + m - 1),
            Side::Right => (params.i() + m, params.j()),
        };
        if i == j {
            ChildRange::Leaf(i)
        } else {
            ChildRange::Bisect(
                BisectParams::new(params.alice_pk, params.bob_pk, i, j)
                    .expect("a non-leaf half of a valid bisection range is valid"),
            )
        }
    }

    /// The taptree root committed for `side`'s child (a [`Leaf`] at a single
    /// step, else a sub-[`Bisect1`]).
    fn child_root(params: &BisectParams, side: Side, ctx: &BisectCtx) -> [u8; 32] {
        match Self::child_range(params, side) {
            ChildRange::Leaf(step) => ctx.leaf(step).taptree_root(),
            ChildRange::Bisect(child) => Bisect1::new(child, ctx.clone())
                .expect("Bisect1 contract definition is valid")
                .taptree_root(),
        }
    }

    /// The single output a `bob_reveal_*` clause produces: the dispute
    /// continues on `side`'s half, whose endpoints and traces are the given
    /// revealed values (a [`Leaf`] at a single step, else a sub-[`Bisect1`]).
    #[allow(clippy::too_many_arguments)]
    fn child_output(
        params: &BisectParams,
        ctx: &BisectCtx,
        side: Side,
        h_start: [u8; 32],
        h_end_alice: [u8; 32],
        h_end_bob: [u8; 32],
        trace_alice: [u8; 32],
        trace_bob: [u8; 32],
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let output = match Self::child_range(params, side) {
            ChildRange::Leaf(step) => ClauseOutput::at_same_index()
                .to(ctx.leaf(step).as_erased())
                .with_state(&LeafState {
                    h_start,
                    h_end_alice,
                    h_end_bob,
                }),
            ChildRange::Bisect(child) => ClauseOutput::at_same_index()
                .to(Bisect1::new(child, ctx.clone())?.as_erased())
                .with_state(&Bisect1State {
                    h_start,
                    h_end_a: h_end_alice,
                    h_end_b: h_end_bob,
                    trace_a: trace_alice,
                    trace_b: trace_bob,
                }),
        };
        Ok(vec![output.preserve_amount().build()])
    }

    // witness: <bob_sig> <h_start> <h_end_a> <h_end_b> <trace_a> <trace_b>
    // <h_mid_a> <trace_left_a> <trace_right_a> <h_mid_b> <trace_left_b> <trace_right_b>
    fn bob_reveal_script(
        bob_pk: XOnlyPublicKey,
        children_are_leaves: bool,
        side: Side,
        child_root: [u8; 32],
    ) -> ScriptBuf {
        // The output construction differs by side (which revealed values form the
        // child's state) and by child kind (a Leaf's state has 3 fields, a
        // sub-Bisect_1's has 5): pick them, then commit to the child's root.
        let (picks, encoder) = match (side, children_are_leaves) {
            (Side::Left, true) => (script! { 10 OP_PICK 6 OP_PICK 4 OP_PICK }, merkle_root(3)),
            (Side::Left, false) => (
                script! { 10 OP_PICK 6 OP_PICK 4 OP_PICK 7 OP_PICK 5 OP_PICK },
                merkle_root(5),
            ),
            (Side::Right, true) => (script! { 5 OP_PICK 10 OP_PICK 10 OP_PICK }, merkle_root(3)),
            (Side::Right, false) => (
                script! { 5 OP_PICK 10 OP_PICK 10 OP_PICK 6 OP_PICK 4 OP_PICK },
                merkle_root(5),
            ),
        };
        // The midstate comparison routing the dispute: Bob recurses LEFT when the
        // parties' midstates differ, RIGHT when they agree.
        let mid_check = match side {
            Side::Left => script! { OP_EQUAL OP_NOT OP_VERIFY },
            Side::Right => script! { OP_EQUALVERIFY },
        };
        script! {
            OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
            { dup(8) }
            { merkle_root(8) }
            { check_input_contract(-1, None) }
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            // t_{i,j;b} = H(h_i || h_{j+1;b} || t_left_b || t_right_b)
            10 OP_PICK 9 OP_PICK OP_CAT 2 OP_PICK OP_CAT 1 OP_PICK OP_CAT OP_SHA256
            7 OP_PICK OP_EQUALVERIFY
            5 OP_PICK 3 OP_PICK
            { mid_check }
            { picks }
            { encoder }
            { check_output_contract(child_root, -1, None) }
            { script_drop(11) }
            { bob_pk }
            OP_CHECKSIG
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bp(i: i64, j: i64) -> BisectParams {
        BisectParams::new(crate::nums_key(), crate::nums_key(), i, j).unwrap()
    }

    #[test]
    fn m_halves_the_range() {
        assert_eq!(bp(0, 7).m(), 4);
        assert_eq!(bp(4, 5).m(), 1);
        assert!(bp(4, 5).children_are_leaves());
        assert!(!bp(0, 7).children_are_leaves());
    }

    #[test]
    fn invalid_bisect_ranges_are_rejected() {
        let key = crate::nums_key();
        for (i, j) in [(0, 5), (3, 3), (-1, 2), (i64::MIN, i64::MAX)] {
            assert!(matches!(
                BisectParams::new(key, key, i, j),
                Err(FraudError::InvalidBisectRange { .. })
            ));
        }
    }

    #[test]
    fn invalid_trace_ranges_are_rejected() {
        let hs = [[0u8; 32]; 5];
        assert!(matches!(
            trace(&hs, 3, 2),
            Err(FraudError::InvalidTraceRange { .. })
        ));
        assert!(matches!(
            trace(&hs, 0, usize::MAX),
            Err(FraudError::InvalidTraceRange { .. })
        ));
        assert!(matches!(
            trace(&hs, 0, 2),
            Err(FraudError::TraceRangeNotPowerOfTwo { .. })
        ));
        assert!(trace(&hs, 0, 3).is_ok());
    }

    #[test]
    fn decoded_bisect_ranges_are_validated() {
        let key = crate::nums_key();
        let invalid = EncodedBisectParams {
            alice_pk: key,
            bob_pk: key,
            i: 0,
            j: 2,
        };
        let bytes = ContractParamsTrait::encode(&invalid);
        assert!(BisectParams::decode(&bytes).is_err());
    }

    #[test]
    fn zero_forfait_timeout_is_rejected() {
        let factory: LeafFactory = Arc::new(|_| panic!("factory is not called"));
        assert!(matches!(
            BisectCtx::new(factory, 0),
            Err(FraudError::ZeroForfaitTimeout)
        ));
    }
}
