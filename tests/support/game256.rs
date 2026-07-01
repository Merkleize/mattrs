//! game256 example (ported from pymatt's `examples/game256`).
//!
//! A fraud-proof game: Alice claims `f^n(x) = y` for a step function `f`; if Bob
//! disagrees they bisect the computation trace down to a single disputed step,
//! which the `Leaf` contract adjudicates by re-running that one step on-chain.
//!
//! This module currently ports the base case — the `Leaf` contract — plus the
//! reusable `merkle_root`/`dup` script fragments it needs. The recursive `Bisect_1`
//! / `Bisect_2` contracts and the `G256_S*` game stages are follow-ups.
//!
//! The step function is game256's `Compute2x`: `y = 2*x`, values committed as
//! `sha256(x)` (encoder `OP_SHA256`, func `OP_DUP OP_ADD`).
#![allow(dead_code)]

use bitcoin::ScriptBuf;
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{
    ClauseArgs, ContractParams, ContractState, WitnessEncodable, WitnessError,
};
use mattrs::{contract, nums_key, Signature};
use mattrs_derive::ContractParams;

use super::merkle::MerkleTree;
use super::script_helpers::{check_input_contract, dup, merkle_root};

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
// Bisect contracts (recursive core), ported at the base range i=0, j=1 — where
// both children are Leaves (are_children_leaves).
//
// This ports the byte-exact tapscripts (and thus taptrees); the clauses carry
// signer-only args and are terminal here. Full args, the next_outputs that drive
// the recursion, and the general (i, j) range are follow-ups.
// ============================================================================

use super::script_helpers::{check_output_contract, drop as script_drop};

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
        self.leaf().contract.taptree.root_hash()
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
                .taptree
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
                .taptree
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

        clause bob_reveal_left {
            args {
                #[signer(|p| p.bob_pk.serialize())]
                bob_sig: Signature,
            }
            script Bisect2::bob_reveal_left_script;
        }
        clause bob_reveal_right {
            args {
                #[signer(|p| p.bob_pk.serialize())]
                bob_sig: Signature,
            }
            script Bisect2::bob_reveal_right_script;
        }
        clause forfait {
            args {
                #[signer(|p| p.bob_pk.serialize())]
                bob_sig: Signature,
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
            { super::script_helpers::older(10) }
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

        clause alice_reveal {
            args {
                #[signer(|p| p.alice_pk.serialize())]
                alice_sig: Signature,
            }
            script Bisect1::alice_reveal_script;
        }
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
        Bisect2::new(p.clone()).contract.taptree.root_hash()
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
            { super::script_helpers::older(10) }
            { p.bob_pk }
            OP_CHECKSIG
        }
    }
}
