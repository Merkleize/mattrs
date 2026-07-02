//! game256 example (ported from pymatt's `examples/game256`).
//!
//! A fraud-proof game: Alice claims `f^n(x) = y` for a step function `f`; if Bob
//! disagrees they bisect the computation trace down to a single disputed step,
//! which the `Leaf` contract adjudicates by re-running that one step on-chain.
//!
//! This ports the whole example: the `Leaf` base case, the recursive `Bisect_1`/
//! `Bisect_2` (over any [i, j] range), and the `G256S0`/`S1`/`S2` game stages — the
//! taptrees are byte-verified against the pymatt references, and each clause's
//! `next_outputs` drives the game state machine (choose -> S1 -> S2 ->
//! Bisect_1(0,7) -> Bisect_2 -> Leaf/sub-Bisect_1), so a spend produces the correct
//! child contract and committed state (see `test_game256_state_transitions`).
//!
//! The step function is game256's `Compute2x`: `y = 2*x`, values committed as
//! `sha256(x)` (encoder `OP_SHA256`, func `OP_DUP OP_ADD`).
#![allow(dead_code)]

use bitcoin::ScriptBuf;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::XOnlyPublicKey;
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{
    ClauseArgs, ClauseOutput, ContractParams, ContractState, WitnessEncodable, WitnessError,
};
use mattrs::script_utils::bn2vch;
use mattrs::{contract, nums_key, Signature};
use mattrs_derive::ContractParams;

use mattrs::merkle::MerkleTree;
use mattrs::script_helpers::{check_input_contract, dup, merkle_root, older};

define_pushable!();

#[derive(Debug, Clone, ContractParams)]
pub struct LeafParams {
    pub alice_pk: bitcoin::XOnlyPublicKey,
    pub bob_pk: bitcoin::XOnlyPublicKey,
}

/// The disputed step's commitment: the starting hash and each party's claimed
/// ending hash. Committed on-chain as the Merkle root of the three.
#[derive(Debug, Clone)]
pub struct LeafState {
    pub h_start: [u8; 32],
    pub h_end_alice: [u8; 32],
    pub h_end_bob: [u8; 32],
}

impl ContractState for LeafState {
    fn encode(&self) -> Vec<u8> {
        MerkleTree::new(vec![self.h_start, self.h_end_alice, self.h_end_bob])
            .root()
            .to_vec()
    }

    fn decode(_bytes: &[u8]) -> Result<Self, WitnessError> {
        Err(WitnessError::InvalidData(
            "Leaf state cannot be recovered from its Merkle-root commitment".to_string(),
        ))
    }
}

contract! {
    contract Leaf {
        params LeafParams;
        state LeafState;
        internal_key |_p| nums_key();

        // Alice re-runs the disputed step: <alice_sig> <x> <h_y_b>
        clause alice_reveal {
            args {
                #[signer(|p| p.alice_pk.serialize())]
                alice_sig: Signature,
                x: i64,
                h_y_b: [u8; 32],
            }
            script Leaf::alice_reveal_script;
        }

        // Bob re-runs the disputed step: <bob_sig> <x> <h_y_a>
        clause bob_reveal {
            args {
                #[signer(|p| p.bob_pk.serialize())]
                bob_sig: Signature,
                x: i64,
                h_y_a: [u8; 32],
            }
            script Leaf::bob_reveal_script;
        }

        tree [alice_reveal, bob_reveal];
    }
}

impl Leaf {
    fn alice_reveal_script(p: &LeafParams) -> ScriptBuf {
        script! {
            OP_TOALTSTACK
            { dup(1) }          // dup(len(specs)); Compute2x has one spec
            OP_SHA256            // computer.encoder -> h_x
            OP_TOALTSTACK
            OP_DUP OP_ADD        // computer.func -> y = 2x
            OP_SHA256            // computer.encoder -> h_y
            OP_FROMALTSTACK OP_SWAP OP_FROMALTSTACK
            { merkle_root(3) }
            { check_input_contract(-1, None) }
            { p.alice_pk }
            OP_CHECKSIG
        }
    }

    fn bob_reveal_script(p: &LeafParams) -> ScriptBuf {
        script! {
            OP_TOALTSTACK
            { dup(1) }
            OP_SHA256
            OP_TOALTSTACK
            OP_DUP OP_ADD
            OP_SHA256
            OP_FROMALTSTACK OP_SWAP OP_FROMALTSTACK OP_SWAP
            { merkle_root(3) }
            { check_input_contract(-1, None) }
            { p.bob_pk }
            OP_CHECKSIG
        }
    }
}

// ============================================================================
// Bisect contracts (recursive core), over any range [i, j]. The two children are
// Leaves when the sub-range is a single step, otherwise sub-Bisect_1s; the
// bob_reveal scripts and next_outputs branch on this. next_outputs produces the
// disputed child (Leaf or Bisect_1) with its committed state.
// ============================================================================

use mattrs::script_helpers::{check_output_contract, drop as script_drop};

#[derive(Debug, Clone, ContractParams)]
pub struct BisectParams {
    pub alice_pk: bitcoin::XOnlyPublicKey,
    pub bob_pk: bitcoin::XOnlyPublicKey,
    /// The disputed step range [i, j] (inclusive), `n = j - i + 1` a power of two.
    pub i: i64,
    pub j: i64,
}

impl BisectParams {
    /// Half the range size, `m = n/2`. The children cover [i, i+m-1] and [i+m, j].
    fn m(&self) -> i64 {
        (self.j - self.i + 1) / 2
    }

    /// Whether the two children are single steps (Leaves) rather than sub-Bisects.
    fn children_are_leaves(&self) -> bool {
        self.m() == 1
    }

    fn leaf(&self) -> Leaf {
        Leaf::new(LeafParams {
            alice_pk: self.alice_pk,
            bob_pk: self.bob_pk,
        })
    }

    fn leaf_root(&self) -> [u8; 32] {
        self.leaf().contract.taptree().root_hash()
    }

    fn child(&self, i: i64, j: i64) -> BisectParams {
        BisectParams {
            alice_pk: self.alice_pk,
            bob_pk: self.bob_pk,
            i,
            j,
        }
    }

    /// The taptree root of the left child (a Leaf, or Bisect_1 on [i, i+m-1]).
    fn left_child_root(&self) -> [u8; 32] {
        if self.children_are_leaves() {
            self.leaf_root()
        } else {
            let m = self.m();
            Bisect1::new(self.child(self.i, self.i + m - 1))
                .contract
                .taptree()
                .root_hash()
        }
    }

    /// The taptree root of the right child (a Leaf, or Bisect_1 on [i+m, j]).
    fn right_child_root(&self) -> [u8; 32] {
        if self.children_are_leaves() {
            self.leaf_root()
        } else {
            let m = self.m();
            Bisect1::new(self.child(self.i + m, self.j))
                .contract
                .taptree()
                .root_hash()
        }
    }
}

/// Bisect_1 state: {h_start, h_end_a, h_end_b, trace_a, trace_b} (commit = Merkle root).
#[derive(Debug, Clone)]
pub struct Bisect1State {
    pub h_start: [u8; 32],
    pub h_end_a: [u8; 32],
    pub h_end_b: [u8; 32],
    pub trace_a: [u8; 32],
    pub trace_b: [u8; 32],
}
impl ContractState for Bisect1State {
    fn encode(&self) -> Vec<u8> {
        MerkleTree::new(vec![
            self.h_start,
            self.h_end_a,
            self.h_end_b,
            self.trace_a,
            self.trace_b,
        ])
        .root()
        .to_vec()
    }
    fn decode(_bytes: &[u8]) -> Result<Self, WitnessError> {
        Err(WitnessError::InvalidData(
            "Bisect1 state cannot be recovered from its commitment".to_string(),
        ))
    }
}

/// Bisect_2 state: the Bisect_1 fields plus Alice's revealed midstate/traces.
#[derive(Debug, Clone)]
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
impl ContractState for Bisect2State {
    fn encode(&self) -> Vec<u8> {
        MerkleTree::new(vec![
            self.h_start,
            self.h_end_a,
            self.h_end_b,
            self.trace_a,
            self.trace_b,
            self.h_mid_a,
            self.trace_left_a,
            self.trace_right_a,
        ])
        .root()
        .to_vec()
    }
    fn decode(_bytes: &[u8]) -> Result<Self, WitnessError> {
        Err(WitnessError::InvalidData(
            "Bisect2 state cannot be recovered from its commitment".to_string(),
        ))
    }
}

contract! {
    contract Bisect2 {
        params BisectParams;
        state Bisect2State;
        internal_key |_p| nums_key();

        // Bob disputes the LEFT child: <bob_sig> <h_start> <h_end_a> <h_end_b>
        // <trace_a> <trace_b> <h_mid_a> <trace_left_a> <trace_right_a>
        // <h_mid_b> <trace_left_b> <trace_right_b>
        clause bob_reveal_left {
            args {
                #[signer(|p| p.bob_pk.serialize())]
                bob_sig: Signature,
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
            }
            script Bisect2::bob_reveal_left_script;
            next(p, a) {
                if p.children_are_leaves() {
                    Ok(vec![ClauseOutput::at_same_index()
                        .to(p.leaf().as_erased())
                        .with_state(&LeafState {
                            h_start: a.h_start,
                            h_end_alice: a.h_mid_a,
                            h_end_bob: a.h_mid_b,
                        })
                        .preserve_amount()
                        .build()])
                } else {
                    let m = p.m();
                    Ok(vec![ClauseOutput::at_same_index()
                        .to(Bisect1::new(p.child(p.i, p.i + m - 1)).as_erased())
                        .with_state(&Bisect1State {
                            h_start: a.h_start,
                            h_end_a: a.h_mid_a,
                            h_end_b: a.h_mid_b,
                            trace_a: a.trace_left_a,
                            trace_b: a.trace_left_b,
                        })
                        .preserve_amount()
                        .build()])
                }
            }
        }
        // Bob disputes the RIGHT child (same witness layout).
        clause bob_reveal_right {
            args {
                #[signer(|p| p.bob_pk.serialize())]
                bob_sig: Signature,
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
            }
            script Bisect2::bob_reveal_right_script;
            next(p, a) {
                if p.children_are_leaves() {
                    Ok(vec![ClauseOutput::at_same_index()
                        .to(p.leaf().as_erased())
                        .with_state(&LeafState {
                            h_start: a.h_mid_a,
                            h_end_alice: a.h_end_a,
                            h_end_bob: a.h_end_b,
                        })
                        .preserve_amount()
                        .build()])
                } else {
                    let m = p.m();
                    Ok(vec![ClauseOutput::at_same_index()
                        .to(Bisect1::new(p.child(p.i + m, p.j)).as_erased())
                        .with_state(&Bisect1State {
                            h_start: a.h_mid_a,
                            h_end_a: a.h_end_a,
                            h_end_b: a.h_end_b,
                            trace_a: a.trace_right_a,
                            trace_b: a.trace_right_b,
                        })
                        .preserve_amount()
                        .build()])
                }
            }
        }
        // Alice can claim the pot if Bob abandons the challenge.
        clause forfait {
            args {
                #[signer(|p| p.alice_pk.serialize())]
                alice_sig: Signature,
            }
            script Bisect2::forfait_script;
        }

        tree [[bob_reveal_left, bob_reveal_right], forfait];
    }
}

impl Bisect2 {
    fn bob_reveal_left_script(p: &BisectParams) -> ScriptBuf {
        // The output construction differs when the child is a Leaf vs a sub-Bisect_1:
        // it pushes its state fields (3 vs 5) then commits to the child's root.
        let (picks, encoder, child_root) = if p.children_are_leaves() {
            (
                script! { 10 OP_PICK 6 OP_PICK 4 OP_PICK },
                merkle_root(3),
                p.leaf_root(),
            )
        } else {
            (
                script! { 10 OP_PICK 6 OP_PICK 4 OP_PICK 7 OP_PICK 5 OP_PICK },
                merkle_root(5),
                p.left_child_root(),
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
            { p.bob_pk }
            OP_CHECKSIG
        }
    }

    fn bob_reveal_right_script(p: &BisectParams) -> ScriptBuf {
        let (picks, encoder, child_root) = if p.children_are_leaves() {
            (
                script! { 5 OP_PICK 10 OP_PICK 10 OP_PICK },
                merkle_root(3),
                p.leaf_root(),
            )
        } else {
            (
                script! { 5 OP_PICK 10 OP_PICK 10 OP_PICK 6 OP_PICK 4 OP_PICK },
                merkle_root(5),
                p.right_child_root(),
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
            { p.bob_pk }
            OP_CHECKSIG
        }
    }

    fn forfait_script(p: &BisectParams) -> ScriptBuf {
        script! {
            { mattrs::script_helpers::older(10) }
            { p.alice_pk }
            OP_CHECKSIG
        }
    }
}

contract! {
    contract Bisect1 {
        params BisectParams;
        state Bisect1State;
        internal_key |_p| nums_key();

        // Alice reveals the midstate and child traces: <alice_sig> <h_start>
        // <h_end_a> <h_end_b> <trace_a> <trace_b> <h_mid_a> <trace_left_a>
        // <trace_right_a>
        clause alice_reveal {
            args {
                #[signer(|p| p.alice_pk.serialize())]
                alice_sig: Signature,
                h_start: [u8; 32],
                h_end_a: [u8; 32],
                h_end_b: [u8; 32],
                trace_a: [u8; 32],
                trace_b: [u8; 32],
                h_mid_a: [u8; 32],
                trace_left_a: [u8; 32],
                trace_right_a: [u8; 32],
            }
            script Bisect1::alice_reveal_script;
            next(p, a) {
                Ok(vec![ClauseOutput::at_same_index()
                    .to(Bisect2::new(p.clone()).as_erased())
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
                    .build()])
            }
        }
        // Bob can claim the pot if Alice abandons the challenge.
        clause forfait {
            args {
                #[signer(|p| p.bob_pk.serialize())]
                bob_sig: Signature,
            }
            script Bisect1::forfait_script;
        }

        tree [alice_reveal, forfait];
    }
}

impl Bisect1 {
    fn bisect2_root(p: &BisectParams) -> [u8; 32] {
        Bisect2::new(p.clone()).contract.taptree().root_hash()
    }

    fn alice_reveal_script(p: &BisectParams) -> ScriptBuf {
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
            { check_output_contract(Self::bisect2_root(p), -1, None) }
            { p.alice_pk }
            OP_CHECKSIG
        }
    }

    fn forfait_script(p: &BisectParams) -> ScriptBuf {
        script! {
            { mattrs::script_helpers::older(10) }
            { p.bob_pk }
            OP_CHECKSIG
        }
    }
}

// ============================================================================
// G256 game stages (top-level), for the computation y = f^n(x) with f = 2x.
//
// G256S0: Bob picks the input x, committing to G256S1.
// G256S1: Alice reveals y = f^n(x), committing to G256S2.
// G256S2: Alice can withdraw after a timeout, or Bob starts a challenge, which
//         hands off to Bisect_1(0, 7) — the 8-step fraud proof ported above.
//
// As with the Bisect contracts this ports the byte-exact taptrees; clauses are
// terminal with signer-carrying args, and next_outputs / spendability are
// follow-ups.
// ============================================================================

#[derive(Debug, Clone, ContractParams)]
pub struct G256Params {
    pub alice_pk: XOnlyPublicKey,
    pub bob_pk: XOnlyPublicKey,
}

impl G256Params {
    fn bisect(&self) -> BisectParams {
        BisectParams {
            alice_pk: self.alice_pk,
            bob_pk: self.bob_pk,
            i: 0,
            j: 7,
        }
    }
}

/// G256S1 state: the input x, committed as sha256(x).
#[derive(Debug, Clone)]
pub struct G256S1State {
    pub x: i64,
}
impl ContractState for G256S1State {
    fn encode(&self) -> Vec<u8> {
        sha256::Hash::hash(&bn2vch(self.x)).to_byte_array().to_vec()
    }
    fn decode(_bytes: &[u8]) -> Result<Self, WitnessError> {
        Err(WitnessError::InvalidData("G256S1 state is a commitment".to_string()))
    }
}

/// G256S2 state: {t_a, y, x}, committed as merkle_root([t_a, sha256(y), sha256(x)]).
#[derive(Debug, Clone)]
pub struct G256S2State {
    pub t_a: [u8; 32],
    pub y: i64,
    pub x: i64,
}
impl ContractState for G256S2State {
    fn encode(&self) -> Vec<u8> {
        MerkleTree::new(vec![
            self.t_a,
            sha256::Hash::hash(&bn2vch(self.y)).to_byte_array(),
            sha256::Hash::hash(&bn2vch(self.x)).to_byte_array(),
        ])
        .root()
        .to_vec()
    }
    fn decode(_bytes: &[u8]) -> Result<Self, WitnessError> {
        Err(WitnessError::InvalidData("G256S2 state is a commitment".to_string()))
    }
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
        internal_key |_p| nums_key();

        // <bob_sig> <x>
        clause choose {
            args {
                #[signer(|p| p.bob_pk.serialize())]
                bob_sig: Signature,
                x: i64,
            }
            script G256S0::choose_script;
            next(p, a) {
                Ok(vec![ClauseOutput::at_same_index()
                    .to(G256S1::new(p.clone()).as_erased())
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
        let s1_root = G256S1::new(p.clone()).contract.taptree().root_hash();
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
        internal_key |_p| nums_key();

        // <alice_sig> <t_a> <y> <sha256(x)>
        clause reveal {
            args {
                #[signer(|p| p.alice_pk.serialize())]
                alice_sig: Signature,
                t_a: [u8; 32],
                y: i64,
                x: i64,
            }
            script G256S1::reveal_script;
            next(p, a) {
                Ok(vec![ClauseOutput::at_same_index()
                    .to(G256S2::new(p.clone()).as_erased())
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
        let s2_root = G256S2::new(p.clone()).contract.taptree().root_hash();
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
        internal_key |_p| nums_key();

        clause withdraw {
            args {
                #[signer(|p| p.alice_pk.serialize())]
                alice_sig: Signature,
            }
            script G256S2::withdraw_script;
        }

        // <bob_sig> <t_a> <y> <x> <z> <t_b>
        clause start_challenge {
            args {
                #[signer(|p| p.bob_pk.serialize())]
                bob_sig: Signature,
                t_a: [u8; 32],
                y: i64,
                x: i64,
                z: i64,
                t_b: [u8; 32],
            }
            script G256S2::start_challenge_script;
            next(p, a) {
                let commit = |v: i64| sha256::Hash::hash(&bn2vch(v)).to_byte_array();
                Ok(vec![ClauseOutput::at_same_index()
                    .to(Bisect1::new(p.bisect()).as_erased())
                    .with_state(&Bisect1State {
                        h_start: commit(a.x),
                        h_end_a: commit(a.y),
                        h_end_b: commit(a.z),
                        trace_a: a.t_a,
                        trace_b: a.t_b,
                    })
                    .preserve_amount()
                    .build()])
            }
        }

        tree [withdraw, start_challenge];
    }
}

impl G256S2 {
    fn withdraw_script(p: &G256Params) -> ScriptBuf {
        script! {
            { older(10) }
            { p.alice_pk }
            OP_CHECKSIG
        }
    }

    fn start_challenge_script(p: &G256Params) -> ScriptBuf {
        let bisect_root = Bisect1::new(p.bisect()).contract.taptree().root_hash();
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
            // commit [sha256(x), sha256(y), sha256(z), t_a, t_b] as Bisect_1 state
            { merkle_root(5) }
            { check_output_contract(bisect_root, -1, None) }
            { p.bob_pk }
            OP_CHECKSIG
        }
    }
}
