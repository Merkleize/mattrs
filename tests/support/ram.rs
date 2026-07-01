//! RAM example (ported from pymatt's `examples/ram`).
//!
//! An augmented contract holding a fixed-size vector of 32-byte cells, committed
//! on-chain as a Merkle root. `withdraw` proves a cell's value; `write` proves a
//! cell and commits an updated root to the next output. The tapscripts recompute
//! the Merkle root from a proof revealed in the witness.
//!
//! NOTE: this ports the *contract* (its byte-exact taptree). Actually *spending* it
//! additionally needs a multi-element `MerkleProofType` witness arg and an
//! "expanded state" (the manager must carry the leaves, not just the committed
//! root); both are tracked as follow-ups. The clauses are terminal here, and the
//! args are a placeholder — neither affects the taptree.
#![allow(dead_code)]

use bitcoin::ScriptBuf;
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{
    ClauseArgs, ContractParams, ContractState, WitnessEncodable, WitnessError,
};
use mattrs::{contract, nums_key};
use mattrs_derive::{ContractParams, ContractState};

use super::merkle::floor_lg;
use super::script_helpers::check_input_contract;

define_pushable!();

#[derive(Debug, Clone, ContractParams)]
pub struct RamParams {
    /// The number of cells; must be a power of two.
    pub size: i64,
}

/// The committed state: the Merkle root over the cells.
#[derive(Debug, Clone, ContractState)]
pub struct RamState {
    pub root: [u8; 32],
}

contract! {
    contract Ram {
        params RamParams;
        state RamState;
        internal_key |_p| nums_key();

        // witness: <h_1> <d_1> ... <h_n> <d_n> <x> <root>
        clause withdraw {
            args { merkle_root: [u8; 32], }
            script Ram::withdraw_script;
        }

        // witness: <h_1> <d_1> ... <h_n> <d_n> <x_old> <x_new> <root>
        clause write {
            args { merkle_root: [u8; 32], }
            script Ram::write_script;
        }

        tree [withdraw, write];
    }
}

/// Concatenate script fragments (byte-for-byte, like embedding each with `{ .. }`).
fn concat(parts: &[ScriptBuf]) -> ScriptBuf {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part.as_bytes());
    }
    ScriptBuf::from_bytes(bytes)
}

impl Ram {
    fn levels(p: &RamParams) -> u32 {
        floor_lg(p.size as usize)
    }

    fn withdraw_script(p: &RamParams) -> ScriptBuf {
        let head = script! {
            OP_DUP
            OP_TOALTSTACK
            { check_input_contract(-1, None) }
        };
        // One Merkle-layer reduction, repeated once per level.
        let layer = script! {
            OP_SWAP
            OP_NOTIF
                OP_SWAP
            OP_ENDIF
            OP_CAT
            OP_SHA256
        };
        let tail = script! {
            OP_FROMALTSTACK
            OP_EQUAL
        };

        let mut parts = vec![head];
        parts.extend(std::iter::repeat_n(layer, Self::levels(p) as usize));
        parts.push(tail);
        concat(&parts)
    }

    fn write_script(p: &RamParams) -> ScriptBuf {
        let head = script! {
            OP_DUP
            OP_TOALTSTACK
            { check_input_contract(-1, None) }
        };
        // Recompute both the old and new roots one layer at a time.
        let layer = script! {
            2 OP_ROLL
            OP_IF
                2 OP_PICK
                OP_SWAP OP_CAT OP_SHA256
                OP_SWAP
                OP_ROT
                OP_SWAP
            OP_ELSE
                2 OP_PICK
                OP_CAT OP_SHA256
                OP_SWAP OP_ROT
            OP_ENDIF
            OP_CAT OP_SHA256 OP_SWAP
        };
        let tail = script! {
            OP_SWAP
            OP_FROMALTSTACK
            OP_EQUALVERIFY

            // commit the new root to the same contract at the same output index
            -1 0 -1 0 CHECKCONTRACTVERIFY

            OP_TRUE
        };

        let mut parts = vec![head];
        parts.extend(std::iter::repeat_n(layer, Self::levels(p) as usize));
        parts.push(tail);
        concat(&parts)
    }
}
