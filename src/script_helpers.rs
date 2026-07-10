//! Reusable `CHECKCONTRACTVERIFY` / timelock script fragments, ported from
//! pymatt's `matt/script_helpers.py`. These build the small CCV/CSV building
//! blocks that MATT contracts assemble their tapscripts from.

use bitcoin::key::TweakedPublicKey;
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use crate::{contracts::CCV_FLAG_CHECK_INPUT, optional_key_script};

define_pushable!();

/// The P2TR scriptPubKey (`OP_1 <key>`) that pays `key` *directly as the witness
/// program*, with no key tweak or script path.
///
/// This is pymatt's `OpaqueP2TR`: it is what a `CHECKCONTRACTVERIFY` with empty
/// data and an empty taptree constrains an output to (the recovery outputs of the
/// vault, for instance). Because `key` is used verbatim, it must already be the
/// final output key — hence the internal `dangerous_assume_tweaked`, which is
/// safe precisely here.
pub fn opaque_p2tr(key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key))
}

/// A standard key-path P2TR scriptPubKey for `key` (BIP341-tweaked, no script
/// tree) — where a party simply gets paid (payouts, pots).
///
/// Contrast [`opaque_p2tr`], which uses `key` verbatim as the output key: the
/// two look alike but produce different scripts, and only `opaque_p2tr`
/// satisfies a CCV constraint on a bare key.
pub fn key_path_p2tr(key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr(&bitcoin::key::Secp256k1::verification_only(), key, None)
}

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

/// `older(delay) <pk> OP_CHECKSIG`: spendable by `pk` after a relative timelock.
/// The building block of timeout/forfait clauses.
pub fn timeout_sig_script(delay: u32, pk: XOnlyPublicKey) -> ScriptBuf {
    script! {
        { older(delay) }
        { pk }
        OP_CHECKSIG
    }
}

/// Concatenate script fragments (byte-for-byte, like embedding each fragment
/// with `{ .. }` in a `script!` block).
pub fn concat(parts: &[ScriptBuf]) -> ScriptBuf {
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
        concat(&[
            script! { OP_TOALTSTACK },
            reduce_merkle_layer(n - 1),
            script! { OP_FROMALTSTACK },
        ])
    } else {
        concat(&[
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
    concat(&parts)
}

/// Script that drops the top `n` stack elements. Mirrors pymatt's
/// `script_helpers.drop`.
pub fn drop(n: usize) -> ScriptBuf {
    let mut parts = Vec::new();
    for _ in 0..(n / 2) {
        parts.push(script! { OP_2DROP });
    }
    if n % 2 == 1 {
        parts.push(script! { OP_DROP });
    }
    concat(&parts)
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
            concat(&parts)
        }
    }
}
