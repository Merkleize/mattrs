use bitcoin::opcodes::all::*;
use bitcoin::ScriptBuf;

use bitcoin_script::{define_pushable, script};

use crate::ccv::CCV_FLAG_CHECK_INPUT;
use crate::contracts::Contract;
pub use crate::merkle::merkle_root_script;

define_pushable!();

/// Duplicates the top n elements of the stack.
pub fn dup(n: usize) -> ScriptBuf {
    assert!(n >= 1);
    match n {
        1 => script! { OP_DUP },
        2 => script! { OP_2DUP },
        3 => script! { OP_3DUP },
        4 => script! { OP_2OVER OP_2OVER },
        _ => {
            // Generic: [n-1 PICK] * n
            let mut bytes = Vec::new();
            for _ in 0..n {
                push_number(&mut bytes, (n - 1) as i64);
                bytes.push(OP_PICK.to_u8());
            }
            ScriptBuf::from(bytes)
        }
    }
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
    script! { -1 0 -1 <CCV_FLAG_CHECK_INPUT> CHECKCONTRACTVERIFY }
}

/// Verifies the output contract: data is on top of stack and consumed.
///
/// Script: -1 0 <taptree_merkle_root> 0 CHECKCONTRACTVERIFY
pub fn check_output_contract(contract: &Contract) -> ScriptBuf {
    let taptree_root = contract.get_taptree_merkle_root();
    script! { -1 0 <taptree_root> 0 CHECKCONTRACTVERIFY }
}

/// CSV timelock: n CSV DROP
pub fn older_script(n: u32) -> ScriptBuf {
    script! { <n> CSV DROP }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Push a script integer to the byte vector (minimal encoding).
pub fn push_number(bytes: &mut Vec<u8>, n: i64) {
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
