use bitcoin::opcodes::all::*;
use bitcoin::ScriptBuf;

use crate::ccv::{CCV_FLAG_CHECK_INPUT, OP_CHECKCONTRACTVERIFY};
use crate::contracts::Contract;
use crate::merkle::merkle_root_script;

/// Duplicates the top n elements of the stack.
pub fn dup_script(n: usize) -> ScriptBuf {
    assert!(n >= 1);
    let mut bytes = Vec::new();
    match n {
        1 => bytes.push(OP_DUP.to_u8()),
        2 => bytes.push(OP_2DUP.to_u8()),
        3 => bytes.push(OP_3DUP.to_u8()),
        4 => {
            bytes.push(OP_2OVER.to_u8());
            bytes.push(OP_2OVER.to_u8());
        }
        _ => {
            // Generic: [n-1 PICK] * n
            for _ in 0..n {
                push_number(&mut bytes, (n - 1) as i64);
                bytes.push(OP_PICK.to_u8());
            }
        }
    }
    ScriptBuf::from(bytes)
}

/// Drops n elements from the stack.
pub fn drop_script(n: usize) -> ScriptBuf {
    let mut bytes = Vec::new();
    for _ in 0..(n / 2) {
        bytes.push(OP_2DROP.to_u8());
    }
    if n % 2 == 1 {
        bytes.push(OP_DROP.to_u8());
    }
    ScriptBuf::from(bytes)
}

/// Verifies the input contract state: data is on top of stack and consumed.
///
/// Script: -1 0 -1 CCV_FLAG_CHECK_INPUT CHECKCONTRACTVERIFY
pub fn check_input_contract() -> ScriptBuf {
    let mut bytes = Vec::new();
    push_number(&mut bytes, -1); // index
    bytes.push(OP_PUSHBYTES_0.to_u8()); // pubkey = 0 (none)
    push_number(&mut bytes, -1); // taptree = -1
    push_number(&mut bytes, CCV_FLAG_CHECK_INPUT as i64);
    bytes.push(OP_CHECKCONTRACTVERIFY);
    ScriptBuf::from(bytes)
}

/// Verifies the output contract: data is on top of stack and consumed.
///
/// Script: -1 0 <taptree_merkle_root> 0 CHECKCONTRACTVERIFY
pub fn check_output_contract(contract: &Contract) -> ScriptBuf {
    let taptree_root = contract.get_taptree_merkle_root();
    let mut bytes = Vec::new();
    push_number(&mut bytes, -1); // index
    bytes.push(OP_PUSHBYTES_0.to_u8()); // pubkey = 0 (none)
    // Push 32-byte taptree root
    bytes.push(OP_PUSHBYTES_32.to_u8());
    bytes.extend_from_slice(&taptree_root);
    bytes.push(OP_PUSHBYTES_0.to_u8()); // flags = 0
    bytes.push(OP_CHECKCONTRACTVERIFY);
    ScriptBuf::from(bytes)
}

/// CSV timelock: n CSV DROP
pub fn older_script(n: u32) -> ScriptBuf {
    let mut bytes = Vec::new();
    push_number(&mut bytes, n as i64);
    bytes.push(OP_CSV.to_u8());
    bytes.push(OP_DROP.to_u8());
    ScriptBuf::from(bytes)
}

/// Build the encoder script for a merkle root of n leaves.
/// This is just `merkle_root_script(n)`.
pub fn encoder_script(n: usize) -> ScriptBuf {
    merkle_root_script(n)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Push a script integer to the byte vector (minimal encoding).
fn push_number(bytes: &mut Vec<u8>, n: i64) {
    match n {
        -1 => bytes.push(OP_PUSHNUM_NEG1.to_u8()),
        0 => bytes.push(OP_PUSHBYTES_0.to_u8()),
        1..=16 => bytes.push((OP_PUSHNUM_1.to_u8() as i64 + n - 1) as u8),
        _ => {
            // Use bitcoin's minimal scriptint encoding
            let mut buf = [0u8; 8];
            let len = bitcoin::script::write_scriptint(&mut buf, n);
            bytes.push(len as u8); // OP_PUSHBYTESn
            bytes.extend_from_slice(&buf[..len]);
        }
    }
}

/// Convenience: concatenate multiple ScriptBuf fragments.
pub fn cat_scripts(scripts: &[ScriptBuf]) -> ScriptBuf {
    let mut bytes = Vec::new();
    for s in scripts {
        bytes.extend_from_slice(s.as_bytes());
    }
    ScriptBuf::from(bytes)
}
