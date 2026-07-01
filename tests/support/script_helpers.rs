//! Reusable `CHECKCONTRACTVERIFY` / timelock script fragments, ported from
//! pymatt's `matt/script_helpers.py`. These build the small CCV/CSV building
//! blocks that MATT contracts assemble their tapscripts from.
#![allow(dead_code)]

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs::{contracts::CCV_FLAG_CHECK_INPUT, optional_key_script};

define_pushable!();

/// CCV fragment that constrains the *current input's* contract (the committed
/// data is expected on the stack). `index = -1` means "this input"; `pubkey`
/// is the alternate internal key, or `None` for the NUMS default.
pub fn check_input_contract(index: i64, pubkey: Option<XOnlyPublicKey>) -> ScriptBuf {
    script! {
        { index }
        { optional_key_script(pubkey) }
        -1
        { CCV_FLAG_CHECK_INPUT }
        CHECKCONTRACTVERIFY
    }
}

/// CCV fragment that constrains an *output's* contract to `taptree_root` (the
/// committed data is expected on the stack). `index = -1` means "same index as
/// this input".
pub fn check_output_contract(
    taptree_root: [u8; 32],
    index: i64,
    pubkey: Option<XOnlyPublicKey>,
) -> ScriptBuf {
    script! {
        { index }
        { optional_key_script(pubkey) }
        { taptree_root }
        0
        CHECKCONTRACTVERIFY
    }
}

/// A relative-timelock (`CHECKSEQUENCEVERIFY`) fragment, like miniscript's `older`.
pub fn older(n: u32) -> ScriptBuf {
    script! {
        { n }
        CSV
        DROP
    }
}

/// Concatenate script fragments (byte-for-byte).
fn concat(parts: Vec<ScriptBuf>) -> ScriptBuf {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part.as_bytes());
    }
    ScriptBuf::from_bytes(bytes)
}

// x_0, x_1, ..., x_{n-1} -- sha256(x_0 || x_1), sha256(x_2 || x_3), ...
// (odd n copies the last element through unchanged)
fn reduce_merkle_layer(n: usize) -> ScriptBuf {
    if n <= 1 {
        script! {}
    } else if n == 2 {
        script! { OP_CAT OP_SHA256 }
    } else if n % 2 == 1 {
        concat(vec![
            script! { OP_TOALTSTACK },
            reduce_merkle_layer(n - 1),
            script! { OP_FROMALTSTACK },
        ])
    } else {
        concat(vec![
            script! { OP_CAT OP_SHA256 OP_TOALTSTACK },
            reduce_merkle_layer(n - 2),
            script! { OP_FROMALTSTACK },
        ])
    }
}

/// Script that reduces `n_leaves` stack elements to the root of the Merkle tree
/// built on top of them (leaves are not hashed here). Mirrors pymatt's
/// `script_helpers.merkle_root`.
pub fn merkle_root(n_leaves: usize) -> ScriptBuf {
    let mut parts = Vec::new();
    let mut n = n_leaves;
    while n > 1 {
        parts.push(reduce_merkle_layer(n));
        n = n.div_ceil(2);
    }
    concat(parts)
}

/// Script that duplicates the top `n` stack elements. Mirrors pymatt's
/// `script_helpers.dup`.
pub fn dup(n: usize) -> ScriptBuf {
    match n {
        0 => script! {},
        1 => script! { OP_DUP },
        2 => script! { OP_2DUP },
        3 => script! { OP_3DUP },
        4 => script! { OP_2OVER OP_2OVER },
        _ => {
            let mut parts = Vec::new();
            for _ in 0..n {
                parts.push(script! { { (n as i64) - 1 } OP_PICK });
            }
            concat(parts)
        }
    }
}
