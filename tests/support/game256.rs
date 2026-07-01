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
