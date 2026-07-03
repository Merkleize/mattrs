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
//! See `tests/support/game256.rs` for a complete instantiation (`f(x) = 2x`,
//! values committed as `sha256(x)`).
//!
//! As in the pymatt reference, bonds/slashing are not implemented.

use std::sync::Arc;

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};

use crate::argtypes::{BytesType, SignerType};
use crate::contracts::{
    ArgSpec, ClauseArgs, ClauseOutput, ClauseTree, ErasedClause, ErasedContract, NextOutputs,
    NextOutputsFn, RawArgs, StandardAugmentedP2TR, StandardClause,
};
use crate::manager::{InstanceHandle, SpendBuilder, WrongContractType};
use crate::script_helpers::{
    check_input_contract, check_output_contract, concat, drop as script_drop, dup, merkle_root,
    timeout_sig_script,
};
use crate::{nums_key, Signature};
use mattrs_derive::{ClauseArgs, ContractParams, ContractState};

define_pushable!();

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
/// # Panics
///
/// Panics if the range falls outside `hs` (`j + 1 >= hs.len()`) or its size
/// `j - i + 1` is not a power of two — both protocol invariants of the ranges
/// the bisection visits.
pub fn trace(hs: &[[u8; 32]], i: usize, j: usize) -> [u8; 32] {
    assert!(i <= j && j + 1 < hs.len(), "trace range out of bounds");
    let size = j - i + 1;
    assert!(size & (size - 1) == 0, "trace range must be a power of two");

    let mut preimage = Vec::with_capacity(128);
    preimage.extend_from_slice(&hs[i]);
    preimage.extend_from_slice(&hs[j + 1]);
    if i != j {
        let m = size / 2;
        preimage.extend_from_slice(&trace(hs, i, i + m - 1));
        preimage.extend_from_slice(&trace(hs, i + m, j));
    }
    bitcoin::hashes::Hash::to_byte_array(
        <bitcoin::hashes::sha256::Hash as bitcoin::hashes::Hash>::hash(&preimage),
    )
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

/// The base case of the bisection: both clauses re-run the disputed step with the
/// [`Computer`]'s fragments and pay the party whose claimed ending commitment
/// matches the actual output. Clauses are terminal.
pub struct Leaf {
    pub params: LeafParams,
    pub contract: StandardAugmentedP2TR<LeafParams, LeafState>,
}

/// Which party's reveal clause a leaf script is built for; they differ only in
/// where the honest ending hash lands among the three state leaves.
enum RevealSide {
    Alice,
    Bob,
}

impl Leaf {
    /// Build the single-step adjudication contract for `computer`'s step
    /// function, between `params`' two parties.
    pub fn new(params: LeafParams, computer: &Computer) -> Self {
        let alice_reveal: Arc<dyn ErasedClause> =
            Arc::new(StandardClause::<LeafParams, LeafState, RawArgs>::new(
                "alice_reveal".to_string(),
                Self::reveal_script(params.alice_pk, computer, RevealSide::Alice),
                Self::reveal_specs(params.alice_pk, computer, "h_y_b"),
                None,
            ));
        let bob_reveal: Arc<dyn ErasedClause> =
            Arc::new(StandardClause::<LeafParams, LeafState, RawArgs>::new(
                "bob_reveal".to_string(),
                Self::reveal_script(params.bob_pk, computer, RevealSide::Bob),
                Self::reveal_specs(params.bob_pk, computer, "h_y_a"),
                None,
            ));

        let tree = ClauseTree::branch(ClauseTree::leaf(alice_reveal), ClauseTree::leaf(bob_reveal));
        let contract = StandardAugmentedP2TR::new("fraud::Leaf", nums_key(), &params, tree);
        Self { params, contract }
    }

    /// The contract as a type-erased `ErasedContract`.
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        Arc::new(self.contract.clone())
    }

    /// The merkle root of the contract's script taptree.
    pub fn taptree_root(&self) -> [u8; 32] {
        self.contract.taptree().root_hash()
    }

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

// ============================================================================
// Bisect_1 / Bisect_2 — the recursive core, over any step range [i, j]
// ============================================================================

/// The two parties of a bisection stage and the step range it disputes.
#[derive(Debug, Clone, ContractParams)]
pub struct BisectParams {
    pub alice_pk: XOnlyPublicKey,
    pub bob_pk: XOnlyPublicKey,
    /// The disputed step range [i, j] (inclusive), `n = j - i + 1` a power of two.
    pub i: i64,
    pub j: i64,
}

impl BisectParams {
    /// Half the range size, `m = n/2`. The children cover [i, i+m-1] and [i+m, j].
    pub fn m(&self) -> i64 {
        (self.j - self.i + 1) / 2
    }

    /// Whether the two children are single steps (Leaves) rather than sub-Bisects.
    pub fn children_are_leaves(&self) -> bool {
        self.m() == 1
    }

    /// The same keys over the sub-range [i, j].
    pub fn child(&self, i: i64, j: i64) -> BisectParams {
        BisectParams {
            alice_pk: self.alice_pk,
            bob_pk: self.bob_pk,
            i,
            j,
        }
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

/// Alice's reveal: the midstate and child traces backing her committed trace.
#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = BisectParams)]
pub struct Bisect1AliceRevealArgs {
    #[signer(|p| p.alice_pk.serialize())]
    pub alice_sig: Signature,
    pub h_start: [u8; 32],
    pub h_end_a: [u8; 32],
    pub h_end_b: [u8; 32],
    pub trace_a: [u8; 32],
    pub trace_b: [u8; 32],
    pub h_mid_a: [u8; 32],
    pub trace_left_a: [u8; 32],
    pub trace_right_a: [u8; 32],
}

/// Bob claims the pot if Alice abandons the challenge.
#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = BisectParams)]
pub struct Bisect1ForfaitArgs {
    #[signer(|p| p.bob_pk.serialize())]
    pub bob_sig: Signature,
}

/// Bob's reveal: the Bisect_2 state fields plus his own midstate and child traces.
#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = BisectParams)]
pub struct Bisect2BobRevealArgs {
    #[signer(|p| p.bob_pk.serialize())]
    pub bob_sig: Signature,
    pub h_start: [u8; 32],
    pub h_end_a: [u8; 32],
    pub h_end_b: [u8; 32],
    pub trace_a: [u8; 32],
    pub trace_b: [u8; 32],
    pub h_mid_a: [u8; 32],
    pub trace_left_a: [u8; 32],
    pub trace_right_a: [u8; 32],
    pub h_mid_b: [u8; 32],
    pub trace_left_b: [u8; 32],
    pub trace_right_b: [u8; 32],
}

/// Alice claims the pot if Bob abandons the challenge.
#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = BisectParams)]
pub struct Bisect2ForfaitArgs {
    #[signer(|p| p.alice_pk.serialize())]
    pub alice_sig: Signature,
}

/// Alice's turn of the bisection over [i, j]: `alice_reveal` moves to [`Bisect2`]
/// with the same range, `forfait` pays Bob after the timeout.
pub struct Bisect1 {
    pub params: BisectParams,
    pub contract: StandardAugmentedP2TR<BisectParams, Bisect1State>,
}

impl Bisect1 {
    /// Build Alice's bisection stage over `params`' step range, recursing (via
    /// [`Bisect2`]) into `leaf_factory` leaves or sub-`Bisect1`s, and letting
    /// Bob collect via `forfait` after `forfait_timeout` blocks.
    pub fn new(params: BisectParams, leaf_factory: &LeafFactory, forfait_timeout: u32) -> Self {
        let bisect2_root =
            Bisect2::new(params.clone(), leaf_factory, forfait_timeout).taptree_root();

        let lf = leaf_factory.clone();
        let next: NextOutputsFn<BisectParams, Bisect1State, Bisect1AliceRevealArgs> =
            Arc::new(move |p, a, _s| {
                Ok(NextOutputs::Contracts(vec![ClauseOutput::at_same_index()
                    .to(Bisect2::new(p.clone(), &lf, forfait_timeout).as_erased())
                    .with_state(&Bisect2State {
                        h_start: a.h_start,
                        h_end_a: a.h_end_a,
                        h_end_b: a.h_end_b,
                        trace_a: a.trace_a,
                        trace_b: a.trace_b,
                        h_mid_a: a.h_mid_a,
                        trace_left_a: a.trace_left_a,
                        trace_right_a: a.trace_right_a,
                    })
                    .preserve_amount()
                    .build()]))
            });

        let alice_reveal: Arc<dyn ErasedClause> = Arc::new(StandardClause::new(
            "alice_reveal".to_string(),
            Self::alice_reveal_script(params.alice_pk, bisect2_root),
            Bisect1AliceRevealArgs::arg_specs_for_params(&params),
            Some(next),
        ));
        let forfait: Arc<dyn ErasedClause> =
            Arc::new(StandardClause::<BisectParams, Bisect1State, Bisect1ForfaitArgs>::new(
                "forfait".to_string(),
                timeout_sig_script(forfait_timeout, params.bob_pk),
                Bisect1ForfaitArgs::arg_specs_for_params(&params),
                None,
            ));

        let tree = ClauseTree::branch(ClauseTree::leaf(alice_reveal), ClauseTree::leaf(forfait));
        let contract = StandardAugmentedP2TR::new("fraud::Bisect1", nums_key(), &params, tree);
        Self { params, contract }
    }

    /// The contract as a type-erased `ErasedContract`.
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        Arc::new(self.contract.clone())
    }

    /// The merkle root of the contract's script taptree.
    pub fn taptree_root(&self) -> [u8; 32] {
        self.contract.taptree().root_hash()
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

/// Bob's turn of the bisection over [i, j]: `bob_reveal_left`/`bob_reveal_right`
/// recurse into the disputed half (a [`Leaf`] at a single step, else a fresh
/// [`Bisect1`]); `forfait` pays Alice after the timeout.
pub struct Bisect2 {
    pub params: BisectParams,
    pub contract: StandardAugmentedP2TR<BisectParams, Bisect2State>,
}

/// Which half of the disputed range Bob's reveal recurses into.
#[derive(Debug, Clone, Copy)]
enum Side {
    Left,
    Right,
}

impl Bisect2 {
    /// Build Bob's bisection stage over `params`' step range, recursing into
    /// `leaf_factory` leaves (or sub-[`Bisect1`]s) and letting Alice collect
    /// via `forfait` after `forfait_timeout` blocks.
    pub fn new(params: BisectParams, leaf_factory: &LeafFactory, forfait_timeout: u32) -> Self {
        let bob_reveal_left = Self::bob_reveal_clause(&params, Side::Left, leaf_factory, forfait_timeout);
        let bob_reveal_right =
            Self::bob_reveal_clause(&params, Side::Right, leaf_factory, forfait_timeout);
        let forfait: Arc<dyn ErasedClause> =
            Arc::new(StandardClause::<BisectParams, Bisect2State, Bisect2ForfaitArgs>::new(
                "forfait".to_string(),
                timeout_sig_script(forfait_timeout, params.alice_pk),
                Bisect2ForfaitArgs::arg_specs_for_params(&params),
                None,
            ));

        // [[bob_reveal_left, bob_reveal_right], forfait]
        let tree = ClauseTree::branch(
            ClauseTree::branch(
                ClauseTree::leaf(bob_reveal_left),
                ClauseTree::leaf(bob_reveal_right),
            ),
            ClauseTree::leaf(forfait),
        );
        let contract = StandardAugmentedP2TR::new("fraud::Bisect2", nums_key(), &params, tree);
        Self { params, contract }
    }

    /// The contract as a type-erased `ErasedContract`.
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        Arc::new(self.contract.clone())
    }

    /// The merkle root of the contract's script taptree.
    pub fn taptree_root(&self) -> [u8; 32] {
        self.contract.taptree().root_hash()
    }

    /// The child range Bob's reveal on `side` recurses into.
    fn child_params(params: &BisectParams, side: Side) -> BisectParams {
        let m = params.m();
        match side {
            Side::Left => params.child(params.i, params.i + m - 1),
            Side::Right => params.child(params.i + m, params.j),
        }
    }

    /// One of the two `bob_reveal_*` clauses; they differ only in which half of
    /// the range they recurse into.
    fn bob_reveal_clause(
        params: &BisectParams,
        side: Side,
        leaf_factory: &LeafFactory,
        forfait_timeout: u32,
    ) -> Arc<dyn ErasedClause> {
        let child = Self::child_params(params, side);
        let child_root = if params.children_are_leaves() {
            leaf_factory(child.i).taptree_root()
        } else {
            Bisect1::new(child, leaf_factory, forfait_timeout).taptree_root()
        };
        let name = match side {
            Side::Left => "bob_reveal_left",
            Side::Right => "bob_reveal_right",
        };
        Arc::new(StandardClause::new(
            name.to_string(),
            Self::bob_reveal_script(params.bob_pk, params.children_are_leaves(), side, child_root),
            Bisect2BobRevealArgs::arg_specs_for_params(params),
            Some(Self::bob_reveal_next(side, leaf_factory.clone(), forfait_timeout)),
        ))
    }

    /// The next-outputs function of a `bob_reveal_*` clause: the dispute
    /// continues on `side`'s half, whose endpoints and traces come from the
    /// revealed values (a [`Leaf`] at a single step, else a sub-[`Bisect1`]).
    fn bob_reveal_next(
        side: Side,
        lf: LeafFactory,
        forfait_timeout: u32,
    ) -> NextOutputsFn<BisectParams, Bisect2State, Bisect2BobRevealArgs> {
        Arc::new(move |p, a, _s| {
            // The child range's start/end commitments and per-party sub-traces.
            let (h_start, h_end_alice, h_end_bob, trace_alice, trace_bob) = match side {
                Side::Left => (a.h_start, a.h_mid_a, a.h_mid_b, a.trace_left_a, a.trace_left_b),
                Side::Right => (a.h_mid_a, a.h_end_a, a.h_end_b, a.trace_right_a, a.trace_right_b),
            };
            let child = Self::child_params(p, side);
            let output = if p.children_are_leaves() {
                ClauseOutput::at_same_index()
                    .to(lf(child.i).as_erased())
                    .with_state(&LeafState {
                        h_start,
                        h_end_alice,
                        h_end_bob,
                    })
            } else {
                ClauseOutput::at_same_index()
                    .to(Bisect1::new(child, &lf, forfait_timeout).as_erased())
                    .with_state(&Bisect1State {
                        h_start,
                        h_end_a: h_end_alice,
                        h_end_b: h_end_bob,
                        trace_a: trace_alice,
                        trace_b: trace_bob,
                    })
            };
            Ok(NextOutputs::Contracts(vec![
                output.preserve_amount().build(),
            ]))
        })
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

// ============================================================================
// Typed handles (mirroring the shape the `contract!` DSL generates)
// ============================================================================

/// The reveal's state-bound witness fields could not be derived because the
/// instance carries no (or a differently-typed) logical state.
///
/// The fraud handles' reveal methods read the committed state fields from the
/// instance's expanded state — which the framework materializes on every
/// executed or observed transition — so this only occurs on instances that
/// were constructed by hand without their state.
#[derive(Debug, Clone)]
pub struct MissingStateError {
    /// The contract whose state was needed.
    pub contract: &'static str,
}

impl std::fmt::Display for MissingStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the {} instance carries no logical state to derive the reveal from",
            self.contract
        )
    }
}

impl std::error::Error for MissingStateError {}

/// Convert an untyped [`InstanceHandle`] into the given typed handle after
/// checking the underlying contract type.
macro_rules! impl_handle_try_from {
    ($handle:ident, $contract:ty, $name:literal) => {
        impl TryFrom<InstanceHandle> for $handle {
            type Error = WrongContractType;

            fn try_from(handle: InstanceHandle) -> Result<Self, Self::Error> {
                if handle.contract_type_id() == std::any::TypeId::of::<$contract>() {
                    Ok($handle(handle))
                } else {
                    Err(WrongContractType { expected: $name })
                }
            }
        }
    };
}

/// Typed handle to a funded [`Leaf`] instance.
#[derive(Clone)]
pub struct LeafHandle(InstanceHandle);

impl LeafHandle {
    /// The underlying generic instance handle.
    pub fn handle(&self) -> &InstanceHandle {
        &self.0
    }

    /// This instance's typed state, if available.
    pub fn state(&self) -> Option<LeafState> {
        self.0.state::<LeafState>()
    }

    fn state_or_err(&self) -> Result<LeafState, MissingStateError> {
        self.state().ok_or(MissingStateError {
            contract: "fraud::Leaf",
        })
    }

    /// Alice re-runs the disputed step, revealing the step value `x` (its
    /// witness elements, one per [`Computer`] spec). The counterparty's claimed
    /// ending commitment comes from the instance state.
    pub fn alice_reveal(&self, x: Vec<Vec<u8>>) -> Result<SpendBuilder, MissingStateError> {
        let state = self.state_or_err()?;
        Ok(self
            .0
            .spend_clause("alice_reveal", Self::reveal_witness(x, state.h_end_bob)))
    }

    /// Bob re-runs the disputed step, revealing the step value `x` (its witness
    /// elements, one per [`Computer`] spec). The counterparty's claimed ending
    /// commitment comes from the instance state.
    pub fn bob_reveal(&self, x: Vec<Vec<u8>>) -> Result<SpendBuilder, MissingStateError> {
        let state = self.state_or_err()?;
        Ok(self
            .0
            .spend_clause("bob_reveal", Self::reveal_witness(x, state.h_end_alice)))
    }

    fn reveal_witness(x: Vec<Vec<u8>>, other_hash: [u8; 32]) -> Vec<Vec<u8>> {
        // The signature element stays empty; the manager fills it at spend time.
        let mut witness = vec![Vec::new()];
        witness.extend(x);
        witness.push(other_hash.to_vec());
        witness
    }
}

impl_handle_try_from!(
    LeafHandle,
    StandardAugmentedP2TR<LeafParams, LeafState>,
    "fraud::Leaf"
);

/// Typed handle to a funded [`Bisect1`] instance.
#[derive(Clone)]
pub struct Bisect1Handle(InstanceHandle);

impl Bisect1Handle {
    /// The underlying generic instance handle.
    pub fn handle(&self) -> &InstanceHandle {
        &self.0
    }

    /// This instance's typed state, if available.
    pub fn state(&self) -> Option<Bisect1State> {
        self.0.state::<Bisect1State>()
    }

    /// Alice's turn: reveal her midstate commitment and the two sub-traces
    /// backing her committed trace. The committed range endpoints and traces
    /// come from the instance state, so the witness always matches it.
    pub fn alice_reveal(
        &self,
        h_mid_a: [u8; 32],
        trace_left_a: [u8; 32],
        trace_right_a: [u8; 32],
    ) -> Result<SpendBuilder, MissingStateError> {
        let s = self.state().ok_or(MissingStateError {
            contract: "fraud::Bisect1",
        })?;
        let args = Bisect1AliceRevealArgs::new(
            s.h_start,
            s.h_end_a,
            s.h_end_b,
            s.trace_a,
            s.trace_b,
            h_mid_a,
            trace_left_a,
            trace_right_a,
        );
        Ok(self
            .0
            .spend_clause("alice_reveal", ClauseArgs::encode_to_witness(&args)))
    }

    /// Bob claims the pot after the forfait timeout (Alice stalled).
    pub fn forfait(&self) -> SpendBuilder {
        let args = Bisect1ForfaitArgs::new();
        self.0
            .spend_clause("forfait", ClauseArgs::encode_to_witness(&args))
    }
}

impl_handle_try_from!(
    Bisect1Handle,
    StandardAugmentedP2TR<BisectParams, Bisect1State>,
    "fraud::Bisect1"
);

/// Typed handle to a funded [`Bisect2`] instance.
#[derive(Clone)]
pub struct Bisect2Handle(InstanceHandle);

impl Bisect2Handle {
    /// The underlying generic instance handle.
    pub fn handle(&self) -> &InstanceHandle {
        &self.0
    }

    /// This instance's typed state, if available.
    pub fn state(&self) -> Option<Bisect2State> {
        self.0.state::<Bisect2State>()
    }

    /// Bob's turn, disputing the LEFT half (the parties' midstates differ):
    /// reveal his midstate commitment and sub-traces. The committed fields come
    /// from the instance state, so the witness always matches it.
    pub fn bob_reveal_left(
        &self,
        h_mid_b: [u8; 32],
        trace_left_b: [u8; 32],
        trace_right_b: [u8; 32],
    ) -> Result<SpendBuilder, MissingStateError> {
        self.bob_reveal("bob_reveal_left", h_mid_b, trace_left_b, trace_right_b)
    }

    /// Bob's turn, disputing the RIGHT half (the parties' midstates agree):
    /// reveal his midstate commitment and sub-traces. The committed fields come
    /// from the instance state, so the witness always matches it.
    pub fn bob_reveal_right(
        &self,
        h_mid_b: [u8; 32],
        trace_left_b: [u8; 32],
        trace_right_b: [u8; 32],
    ) -> Result<SpendBuilder, MissingStateError> {
        self.bob_reveal("bob_reveal_right", h_mid_b, trace_left_b, trace_right_b)
    }

    /// Alice claims the pot after the forfait timeout (Bob stalled).
    pub fn forfait(&self) -> SpendBuilder {
        let args = Bisect2ForfaitArgs::new();
        self.0
            .spend_clause("forfait", ClauseArgs::encode_to_witness(&args))
    }

    fn bob_reveal(
        &self,
        clause: &'static str,
        h_mid_b: [u8; 32],
        trace_left_b: [u8; 32],
        trace_right_b: [u8; 32],
    ) -> Result<SpendBuilder, MissingStateError> {
        let s = self.state().ok_or(MissingStateError {
            contract: "fraud::Bisect2",
        })?;
        let args = Bisect2BobRevealArgs::new(
            s.h_start,
            s.h_end_a,
            s.h_end_b,
            s.trace_a,
            s.trace_b,
            s.h_mid_a,
            s.trace_left_a,
            s.trace_right_a,
            h_mid_b,
            trace_left_b,
            trace_right_b,
        );
        Ok(self.0.spend_clause(clause, ClauseArgs::encode_to_witness(&args)))
    }
}

impl_handle_try_from!(
    Bisect2Handle,
    StandardAugmentedP2TR<BisectParams, Bisect2State>,
    "fraud::Bisect2"
);
