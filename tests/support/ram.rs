//! RAM example (ported from pymatt's `examples/ram`).
//!
//! An augmented contract holding a fixed-size vector of 32-byte cells, committed
//! on-chain as a Merkle root. `withdraw` proves a cell's value; `write` proves a
//! cell and commits an updated root to the next output. The tapscripts recompute
//! the Merkle root from a proof revealed in the witness.
//!
//! The cell vector (`RamState.leaves`) is the instance's *logical* state; its
//! on-chain commitment is only the Merkle root, so it rides along as expanded state
//! (see `ErasedState`) and `write`'s `next_outputs` reads it to compute the update.
//!
//! Fixed to a depth-2 tree (`size = 4`) via the const `WitProof<2>` proof arg.

use bitcoin::ScriptBuf;
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{ClauseError, ClauseOutput};
use mattrs::{ContractParams, ContractState, contract};

use mattrs::merkle::{WitProof, floor_lg};
use mattrs::script_helpers::{check_input_contract, concat};

define_pushable!();

#[derive(Debug, Clone, ContractParams)]
pub struct RamParams {
    /// The number of cells; must be a power of two. (This port fixes it to 4.)
    pub size: i64,
}

/// The RAM cells. Committed on-chain only as their Merkle root, so instances carry
/// this as expanded state and recover it by downcast (never by decoding the root).
#[derive(Debug, Clone, ContractState)]
#[commit(merkle)]
pub struct RamState {
    #[leaf(each)]
    pub leaves: Vec<[u8; 32]>,
}

contract! {
    contract Ram {
        params RamParams;
        state RamState;

        // witness: <h_1> <d_1> <h_2> <d_2> <x> <root>
        clause withdraw {
            args {
                proof: WitProof<2>,
                merkle_root: [u8; 32],
            }
            script Ram::withdraw_script;
        }

        // witness: <h_1> <d_1> <h_2> <d_2> <x_old> <x_new> <root>
        clause write {
            args {
                proof: WitProof<2>,
                new_value: [u8; 32],
                merkle_root: [u8; 32],
            }
            script Ram::write_script;
            next(p, a, s) {
                let state = s.ok_or_else(|| {
                    ClauseError::Other("RAM write needs the cell state".to_string())
                })?;
                let index = a
                    .proof
                    .leaf_index()
                    .map_err(|e| ClauseError::Other(e.to_string()))?;
                let mut leaves = state.leaves.clone();
                if index >= leaves.len() {
                    return Err(ClauseError::Other("leaf index out of range".to_string()));
                }
                leaves[index] = a.new_value;
                Ok(vec![ClauseOutput::at_same_index()
                    .to(Ram::new(p.clone())?.as_erased())
                    .with_state(&RamState { leaves })
                    .preserve_amount()
                    .build()])
            }
        }

        tree [withdraw, write];
    }
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
