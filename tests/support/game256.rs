//! game256 example (ported from pymatt's `examples/game256`).
//!
//! A fraud-proof game: Alice claims `f^n(x) = y` for a step function `f`; if Bob
//! disagrees they bisect the computation trace down to a single disputed step,
//! which is adjudicated by re-running that one step on-chain.
//!
//! The whole bisection machinery is the generic [`mattrs::fraud`] module; the
//! only computation-specific code here is [`compute2x`] (the step function
//! `f(x) = 2x` with values committed as `sha256(x)`) plus the three top-level
//! game stages `G256S0`/`S1`/`S2`. The taptrees are byte-verified against the
//! pymatt references, and each clause's `next_outputs` drives the game state
//! machine (choose -> S1 -> S2 -> Bisect_1(0,7) -> Bisect_2 -> Leaf/sub-Bisect_1),
//! so a spend produces the correct child contract and committed state (see
//! `test_game256_state_transitions`).

use std::sync::Arc;

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs::argtypes::IntType;
use mattrs::contracts::{ArgSpec, ClauseOutput};
use mattrs::{ContractParams, ContractState, Signature, contract};

// Re-exported so tests can import the whole game through this module; each test
// binary uses a subset, so per-binary "unused import" warnings are structural.
#[allow(unused_imports)]
pub use mattrs::fraud::{
    Bisect1, Bisect1Handle, Bisect1State, Bisect2, Bisect2Handle, Bisect2State, BisectCtx,
    BisectParams, Computer, Leaf, LeafFactory, LeafHandle, LeafParams, LeafState,
};
use mattrs::script_helpers::{
    check_input_contract, check_output_contract, dup, merkle_root, timeout_sig_script,
};

define_pushable!();

/// The challenge timeout (blocks) for the bisection's forfait clauses.
pub const FORFAIT_TIMEOUT: u32 = 10;

/// game256's step function: `f(x) = 2x`, values committed as `sha256(x)`.
pub fn compute2x() -> Computer {
    Computer {
        encoder: script! { OP_SHA256 },
        func: script! { OP_DUP OP_ADD },
        specs: vec![ArgSpec {
            name: "x".to_string(),
            arg_type: Arc::new(IntType),
        }],
    }
}

/// The per-step [`Leaf`] contract: every step re-runs [`compute2x`], so the step
/// index is ignored.
pub fn leaf_factory(alice_pk: XOnlyPublicKey, bob_pk: XOnlyPublicKey) -> LeafFactory {
    Arc::new(move |_i| {
        Leaf::new(LeafParams { alice_pk, bob_pk }, compute2x())
            .expect("Leaf contract definition is valid")
    })
}

/// A game256 [`Leaf`] (the single disputed step).
pub fn leaf(alice_pk: XOnlyPublicKey, bob_pk: XOnlyPublicKey) -> Leaf {
    Leaf::new(LeafParams { alice_pk, bob_pk }, compute2x())
        .expect("Leaf contract definition is valid")
}

/// The game256 [`BisectCtx`]: [`leaf_factory`] leaves and the standard timeout.
fn bisect_ctx(alice_pk: XOnlyPublicKey, bob_pk: XOnlyPublicKey) -> BisectCtx {
    BisectCtx::new(leaf_factory(alice_pk, bob_pk), FORFAIT_TIMEOUT)
        .expect("the game256 forfait timeout is non-zero")
}

/// A game256 [`Bisect1`] over the given step range.
pub fn bisect1(params: BisectParams) -> Bisect1 {
    let ctx = bisect_ctx(params.alice_pk, params.bob_pk);
    Bisect1::new(params, ctx).expect("Bisect1 contract definition is valid")
}

/// A game256 [`Bisect2`] over the given step range.
pub fn bisect2(params: BisectParams) -> Bisect2 {
    let ctx = bisect_ctx(params.alice_pk, params.bob_pk);
    Bisect2::new(params, ctx).expect("Bisect2 contract definition is valid")
}

// ============================================================================
// G256 game stages (top-level), for the computation y = f^n(x) with f = 2x.
//
// G256S0: Bob picks the input x, committing to G256S1.
// G256S1: Alice reveals y = f^n(x), committing to G256S2.
// G256S2: Alice can withdraw after a timeout, or Bob starts a challenge, which
//         hands off to Bisect_1(0, 7) — the 8-step fraud proof.
// ============================================================================

#[derive(Debug, Clone, ContractParams)]
pub struct G256Params {
    pub alice_pk: XOnlyPublicKey,
    pub bob_pk: XOnlyPublicKey,
}

impl G256Params {
    fn bisect(&self) -> BisectParams {
        BisectParams::new(self.alice_pk, self.bob_pk, 0, 7).expect("game256 disputes eight steps")
    }
}

/// G256S1 state: the input x, committed as sha256(x).
#[derive(Debug, Clone, ContractState)]
#[commit(merkle)]
pub struct G256S1State {
    #[leaf(sha256)]
    pub x: i64,
}

/// G256S2 state: {t_a, y, x}, committed as merkle_root([t_a, sha256(y), sha256(x)]).
#[derive(Debug, Clone, ContractState)]
#[commit(merkle)]
pub struct G256S2State {
    pub t_a: [u8; 32],
    #[leaf(sha256)]
    pub y: i64,
    #[leaf(sha256)]
    pub x: i64,
}

/// The on-chain encoder for G256S2 state: given <t_a> <y> <x>, compute its
/// commitment merkle_root([t_a, sha256(y), sha256(x)]).
fn g256_s2_state_encoder() -> ScriptBuf {
    script! {
        OP_TOALTSTACK OP_SHA256 OP_FROMALTSTACK OP_SHA256
        { merkle_root(3) }
    }
}

contract! {
    contract G256S0 {
        params G256Params;

        // <bob_sig> <x>
        clause choose {
            args {
                #[signer(p.bob_pk)]
                bob_sig: Signature,
                x: i64,
            }
            script G256S0::choose_script;
            next(p, a) {
                Ok(vec![ClauseOutput::at_same_index()
                    .to(G256S1::new(p.clone())?.as_erased())
                    .with_state(&G256S1State { x: a.x })
                    .preserve_amount()
                    .build()])
            }
        }

        tree [choose];
    }
}

impl G256S0 {
    fn choose_script(p: &G256Params) -> ScriptBuf {
        let s1_root = G256S1::new(p.clone())
            .expect("G256S1 contract definition is valid")
            .taptree_root();
        script! {
            OP_SHA256
            { check_output_contract(s1_root, -1, None) }
            { p.bob_pk }
            OP_CHECKSIG
        }
    }
}

contract! {
    contract G256S1 {
        params G256Params;
        state G256S1State;

        // <alice_sig> <t_a> <y> <sha256(x)>
        clause reveal {
            args {
                #[signer(p.alice_pk)]
                alice_sig: Signature,
                t_a: [u8; 32],
                y: i64,
                x: i64,
            }
            script G256S1::reveal_script;
            next(p, a) {
                Ok(vec![ClauseOutput::at_same_index()
                    .to(G256S2::new(p.clone())?.as_erased())
                    .with_state(&G256S2State {
                        t_a: a.t_a,
                        y: a.y,
                        x: a.x,
                    })
                    .preserve_amount()
                    .build()])
            }
        }

        tree [reveal];
    }
}

impl G256S1 {
    fn reveal_script(p: &G256Params) -> ScriptBuf {
        let s2_root = G256S2::new(p.clone())
            .expect("G256S2 contract definition is valid")
            .taptree_root();
        script! {
            OP_DUP
            OP_SHA256
            { check_input_contract(-1, None) }
            { g256_s2_state_encoder() }
            { check_output_contract(s2_root, -1, None) }
            { p.alice_pk }
            OP_CHECKSIG
        }
    }
}

contract! {
    contract G256S2 {
        params G256Params;
        state G256S2State;

        clause withdraw {
            args {
                #[signer(p.alice_pk)]
                alice_sig: Signature,
            }
            script G256S2::withdraw_script;
        }

        // <bob_sig> <t_a> <y> <x> <z> <t_b>
        clause start_challenge {
            args {
                #[signer(p.bob_pk)]
                bob_sig: Signature,
                t_a: [u8; 32],
                y: i64,
                x: i64,
                z: i64,
                t_b: [u8; 32],
            }
            script G256S2::start_challenge_script;
            next(p, a) {
                let commit = mattrs::script_utils::commit_int;
                Ok(vec![bisect1(p.bisect()).entry_output(
                    commit(a.x),
                    commit(a.y),
                    commit(a.z),
                    a.t_a,
                    a.t_b,
                )])
            }
        }

        tree [withdraw, start_challenge];
    }
}

impl G256S2 {
    fn withdraw_script(p: &G256Params) -> ScriptBuf {
        timeout_sig_script(FORFAIT_TIMEOUT, p.alice_pk)
    }

    fn start_challenge_script(p: &G256Params) -> ScriptBuf {
        script! {
            OP_TOALTSTACK
            // y != z
            OP_DUP 3 OP_PICK OP_EQUAL OP_NOT OP_VERIFY
            OP_TOALTSTACK
            { dup(3) }
            { g256_s2_state_encoder() }
            { check_input_contract(-1, None) }
            OP_SHA256 OP_SWAP OP_SHA256
            OP_ROT
            OP_FROMALTSTACK OP_SHA256
            OP_SWAP
            OP_FROMALTSTACK
            // hand [sha256(x), sha256(y), sha256(z), t_a, t_b] off to Bisect_1
            { bisect1(p.bisect()).state_output_script(-1) }
            { p.bob_pk }
            OP_CHECKSIG
        }
    }
}
