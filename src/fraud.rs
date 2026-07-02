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
    ArgSpec, ClauseArgs, ClauseOutput, ClauseTree, ContractParams, ContractState, ErasedClause,
    ErasedContract, NextOutputs, NextOutputsFn, RawArgs, StandardAugmentedP2TR, StandardClause,
    WitnessEncodable, WitnessError,
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

// ============================================================================
// Leaf — the disputed single step, re-run on-chain
// ============================================================================

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
        let contract = StandardAugmentedP2TR::new(nums_key(), &params, tree);
        Self { params, contract }
    }

    /// The contract as a type-erased `ErasedContract`.
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        Arc::new(self.contract.clone())
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
    pub fn new(params: BisectParams, leaf_factory: &LeafFactory, forfait_timeout: u32) -> Self {
        let bisect2_root = Bisect2::new(params.clone(), leaf_factory, forfait_timeout)
            .contract
            .taptree()
            .root_hash();

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
        let contract = StandardAugmentedP2TR::new(nums_key(), &params, tree);
        Self { params, contract }
    }

    /// The contract as a type-erased `ErasedContract`.
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        Arc::new(self.contract.clone())
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

impl Bisect2 {
    pub fn new(params: BisectParams, leaf_factory: &LeafFactory, forfait_timeout: u32) -> Self {
        let m = params.m();
        let (left_root, right_root) = if params.children_are_leaves() {
            (
                leaf_factory(params.i).contract.taptree().root_hash(),
                leaf_factory(params.i + m).contract.taptree().root_hash(),
            )
        } else {
            (
                Bisect1::new(
                    params.child(params.i, params.i + m - 1),
                    leaf_factory,
                    forfait_timeout,
                )
                .contract
                .taptree()
                .root_hash(),
                Bisect1::new(params.child(params.i + m, params.j), leaf_factory, forfait_timeout)
                    .contract
                    .taptree()
                    .root_hash(),
            )
        };

        let lf = leaf_factory.clone();
        let next_left: NextOutputsFn<BisectParams, Bisect2State, Bisect2BobRevealArgs> =
            Arc::new(move |p, a, _s| {
                let output = if p.children_are_leaves() {
                    ClauseOutput::at_same_index()
                        .to(lf(p.i).as_erased())
                        .with_state(&LeafState {
                            h_start: a.h_start,
                            h_end_alice: a.h_mid_a,
                            h_end_bob: a.h_mid_b,
                        })
                } else {
                    let m = p.m();
                    ClauseOutput::at_same_index()
                        .to(Bisect1::new(p.child(p.i, p.i + m - 1), &lf, forfait_timeout)
                            .as_erased())
                        .with_state(&Bisect1State {
                            h_start: a.h_start,
                            h_end_a: a.h_mid_a,
                            h_end_b: a.h_mid_b,
                            trace_a: a.trace_left_a,
                            trace_b: a.trace_left_b,
                        })
                };
                Ok(NextOutputs::Contracts(vec![
                    output.preserve_amount().build(),
                ]))
            });

        let lf = leaf_factory.clone();
        let next_right: NextOutputsFn<BisectParams, Bisect2State, Bisect2BobRevealArgs> =
            Arc::new(move |p, a, _s| {
                let m = p.m();
                let output = if p.children_are_leaves() {
                    ClauseOutput::at_same_index()
                        .to(lf(p.i + m).as_erased())
                        .with_state(&LeafState {
                            h_start: a.h_mid_a,
                            h_end_alice: a.h_end_a,
                            h_end_bob: a.h_end_b,
                        })
                } else {
                    ClauseOutput::at_same_index()
                        .to(Bisect1::new(p.child(p.i + m, p.j), &lf, forfait_timeout).as_erased())
                        .with_state(&Bisect1State {
                            h_start: a.h_mid_a,
                            h_end_a: a.h_end_a,
                            h_end_b: a.h_end_b,
                            trace_a: a.trace_right_a,
                            trace_b: a.trace_right_b,
                        })
                };
                Ok(NextOutputs::Contracts(vec![
                    output.preserve_amount().build(),
                ]))
            });

        let bob_reveal_left: Arc<dyn ErasedClause> = Arc::new(StandardClause::new(
            "bob_reveal_left".to_string(),
            Self::bob_reveal_left_script(params.bob_pk, params.children_are_leaves(), left_root),
            Bisect2BobRevealArgs::arg_specs_for_params(&params),
            Some(next_left),
        ));
        let bob_reveal_right: Arc<dyn ErasedClause> = Arc::new(StandardClause::new(
            "bob_reveal_right".to_string(),
            Self::bob_reveal_right_script(params.bob_pk, params.children_are_leaves(), right_root),
            Bisect2BobRevealArgs::arg_specs_for_params(&params),
            Some(next_right),
        ));
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
        let contract = StandardAugmentedP2TR::new(nums_key(), &params, tree);
        Self { params, contract }
    }

    /// The contract as a type-erased `ErasedContract`.
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        Arc::new(self.contract.clone())
    }

    // witness: <bob_sig> <h_start> <h_end_a> <h_end_b> <trace_a> <trace_b>
    // <h_mid_a> <trace_left_a> <trace_right_a> <h_mid_b> <trace_left_b> <trace_right_b>
    fn bob_reveal_left_script(
        bob_pk: XOnlyPublicKey,
        children_are_leaves: bool,
        child_root: [u8; 32],
    ) -> ScriptBuf {
        // The output construction differs when the child is a Leaf vs a sub-Bisect_1:
        // it pushes its state fields (3 vs 5) then commits to the child's root.
        let (picks, encoder) = if children_are_leaves {
            (script! { 10 OP_PICK 6 OP_PICK 4 OP_PICK }, merkle_root(3))
        } else {
            (
                script! { 10 OP_PICK 6 OP_PICK 4 OP_PICK 7 OP_PICK 5 OP_PICK },
                merkle_root(5),
            )
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
            // h_mid_a != h_mid_b (Bob iterates on the LEFT child)
            5 OP_PICK 3 OP_PICK OP_EQUAL OP_NOT OP_VERIFY
            { picks }
            { encoder }
            { check_output_contract(child_root, -1, None) }
            { script_drop(11) }
            { bob_pk }
            OP_CHECKSIG
        }
    }

    // Same witness layout as `bob_reveal_left`.
    fn bob_reveal_right_script(
        bob_pk: XOnlyPublicKey,
        children_are_leaves: bool,
        child_root: [u8; 32],
    ) -> ScriptBuf {
        let (picks, encoder) = if children_are_leaves {
            (script! { 5 OP_PICK 10 OP_PICK 10 OP_PICK }, merkle_root(3))
        } else {
            (
                script! { 5 OP_PICK 10 OP_PICK 10 OP_PICK 6 OP_PICK 4 OP_PICK },
                merkle_root(5),
            )
        };
        script! {
            OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
            { dup(8) }
            { merkle_root(8) }
            { check_input_contract(-1, None) }
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            10 OP_PICK 9 OP_PICK OP_CAT 2 OP_PICK OP_CAT 1 OP_PICK OP_CAT OP_SHA256
            7 OP_PICK OP_EQUALVERIFY
            // h_mid_a == h_mid_b (Bob iterates on the RIGHT child)
            5 OP_PICK 3 OP_PICK OP_EQUALVERIFY
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
pub struct LeafHandle(pub InstanceHandle);

impl LeafHandle {
    /// Alice re-runs the disputed step. `x` is the step value's witness elements
    /// (one per [`Computer`] spec); `h_y_b` is Bob's claimed ending commitment.
    pub fn alice_reveal(&self, x: Vec<Vec<u8>>, h_y_b: [u8; 32]) -> SpendBuilder {
        self.0.spend_clause("alice_reveal", Self::reveal_witness(x, h_y_b))
    }

    /// Bob re-runs the disputed step; `h_y_a` is Alice's claimed ending commitment.
    pub fn bob_reveal(&self, x: Vec<Vec<u8>>, h_y_a: [u8; 32]) -> SpendBuilder {
        self.0.spend_clause("bob_reveal", Self::reveal_witness(x, h_y_a))
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
pub struct Bisect1Handle(pub InstanceHandle);

impl Bisect1Handle {
    #[allow(clippy::too_many_arguments)]
    pub fn alice_reveal(
        &self,
        h_start: [u8; 32],
        h_end_a: [u8; 32],
        h_end_b: [u8; 32],
        trace_a: [u8; 32],
        trace_b: [u8; 32],
        h_mid_a: [u8; 32],
        trace_left_a: [u8; 32],
        trace_right_a: [u8; 32],
    ) -> SpendBuilder {
        let args = Bisect1AliceRevealArgs::new(
            h_start,
            h_end_a,
            h_end_b,
            trace_a,
            trace_b,
            h_mid_a,
            trace_left_a,
            trace_right_a,
        );
        self.0
            .spend_clause("alice_reveal", ClauseArgs::encode_to_witness(&args))
    }

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
pub struct Bisect2Handle(pub InstanceHandle);

impl Bisect2Handle {
    #[allow(clippy::too_many_arguments)]
    pub fn bob_reveal_left(
        &self,
        h_start: [u8; 32],
        h_end_a: [u8; 32],
        h_end_b: [u8; 32],
        trace_a: [u8; 32],
        trace_b: [u8; 32],
        h_mid_a: [u8; 32],
        trace_left_a: [u8; 32],
        trace_right_a: [u8; 32],
        h_mid_b: [u8; 32],
        trace_left_b: [u8; 32],
        trace_right_b: [u8; 32],
    ) -> SpendBuilder {
        self.0.spend_clause(
            "bob_reveal_left",
            Self::reveal_witness(
                h_start,
                h_end_a,
                h_end_b,
                trace_a,
                trace_b,
                h_mid_a,
                trace_left_a,
                trace_right_a,
                h_mid_b,
                trace_left_b,
                trace_right_b,
            ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bob_reveal_right(
        &self,
        h_start: [u8; 32],
        h_end_a: [u8; 32],
        h_end_b: [u8; 32],
        trace_a: [u8; 32],
        trace_b: [u8; 32],
        h_mid_a: [u8; 32],
        trace_left_a: [u8; 32],
        trace_right_a: [u8; 32],
        h_mid_b: [u8; 32],
        trace_left_b: [u8; 32],
        trace_right_b: [u8; 32],
    ) -> SpendBuilder {
        self.0.spend_clause(
            "bob_reveal_right",
            Self::reveal_witness(
                h_start,
                h_end_a,
                h_end_b,
                trace_a,
                trace_b,
                h_mid_a,
                trace_left_a,
                trace_right_a,
                h_mid_b,
                trace_left_b,
                trace_right_b,
            ),
        )
    }

    pub fn forfait(&self) -> SpendBuilder {
        let args = Bisect2ForfaitArgs::new();
        self.0
            .spend_clause("forfait", ClauseArgs::encode_to_witness(&args))
    }

    #[allow(clippy::too_many_arguments)]
    fn reveal_witness(
        h_start: [u8; 32],
        h_end_a: [u8; 32],
        h_end_b: [u8; 32],
        trace_a: [u8; 32],
        trace_b: [u8; 32],
        h_mid_a: [u8; 32],
        trace_left_a: [u8; 32],
        trace_right_a: [u8; 32],
        h_mid_b: [u8; 32],
        trace_left_b: [u8; 32],
        trace_right_b: [u8; 32],
    ) -> Vec<Vec<u8>> {
        let args = Bisect2BobRevealArgs::new(
            h_start,
            h_end_a,
            h_end_b,
            trace_a,
            trace_b,
            h_mid_a,
            trace_left_a,
            trace_right_a,
            h_mid_b,
            trace_left_b,
            trace_right_b,
        );
        ClauseArgs::encode_to_witness(&args)
    }
}

impl_handle_try_from!(
    Bisect2Handle,
    StandardAugmentedP2TR<BisectParams, Bisect2State>,
    "fraud::Bisect2"
);
