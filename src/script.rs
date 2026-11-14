//! Everything for writing tapscripts: the [`script!`](crate::script!) macro,
//! reusable `CHECKCONTRACTVERIFY` / timelock / Merkle fragments (ported from
//! pymatt's `matt/script_helpers.py`), output scripts, and script-number
//! encoding.
//!
//! ```
//! use mattrs::script;
//! use mattrs::script::older;
//!
//! let key = mattrs::nums_key();
//! let after_a_day = script! {
//!     { older(144) }
//!     { key }
//!     OP_CHECKSIG
//! };
//! assert_eq!(after_a_day.len(), 3 + 1 + 1 + 33 + 1);
//! ```

mod num;

pub use num::{bn2vch, commit_int, vch2bn};

use crate::ccv::{CcvIndex, CcvMode};
use bitcoin::key::TweakedPublicKey;
use bitcoin::{ScriptBuf, XOnlyPublicKey};

// The builder `script!` expands to. Public because the expansion names it
// from the caller's crate; not meant to be used directly.
bitcoin_script::define_pushable!();

/// Build a [`ScriptBuf`] inline: opcodes (`OP_DUP`, or without the prefix),
/// integer and `0x` hex literals, and Rust expressions in `{ .. }` — integers,
/// byte vectors and 32-byte arrays, keys, other scripts (spliced in
/// byte-for-byte), and `Vec`s of those.
///
/// ```
/// use mattrs::script;
///
/// let digest = [7u8; 32];
/// let s = script! { OP_SHA256 { digest } OP_EQUALVERIFY 1 };
/// assert_eq!(s.len(), 1 + 33 + 1 + 1);
/// ```
#[macro_export]
macro_rules! script {
    ($($tokens:tt)*) => {{
        #[allow(unused_imports)]
        use $crate::script::pushable;
        $crate::__bitcoin_script!($($tokens)*)
    }};
}

/// Returns a script fragment that pushes the x-only key if `Some`, or `OP_0` if
/// `None`. Used inside `script!` blocks for CHECKCONTRACTVERIFY key arguments.
pub fn optional_key_script(maybe_pk: Option<XOnlyPublicKey>) -> ScriptBuf {
    let builder = bitcoin::script::Builder::new();
    let builder = if let Some(pk) = maybe_pk {
        builder.push_x_only_key(&pk)
    } else {
        builder.push_int(0)
    };
    builder.into_script()
}

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

/// CCV fragment that constrains an input's contract, using the executing
/// input's taptree (the committed data is expected on the stack).
/// [`CcvIndex::CURRENT`] selects the executing input; `pubkey` is the naked key
/// before the data tweak, or `None` for the NUMS default.
pub fn check_input_contract(
    index: impl Into<CcvIndex>,
    pubkey: Option<XOnlyPublicKey>,
) -> ScriptBuf {
    let index = index.into();
    script! {
        { index.as_i64() }
        { optional_key_script(pubkey) }
        -1
        { CcvMode::CheckInput.as_i32() }
        CHECKCONTRACTVERIFY
    }
}

/// CCV fragment that constrains an *output's* contract to `taptree_root` (the
/// committed data is expected on the stack). [`CcvIndex::CURRENT`] means
/// "same index as this input".
pub fn check_output_contract(
    taptree_root: [u8; 32],
    index: impl Into<CcvIndex>,
    pubkey: Option<XOnlyPublicKey>,
) -> ScriptBuf {
    let index = index.into();
    script! {
        { index.as_i64() }
        { optional_key_script(pubkey) }
        { taptree_root }
        { CcvMode::Preserve.as_i32() }
        CHECKCONTRACTVERIFY
    }
}

/// CCV fragment that constrains an output to *this same contract* (the
/// executing input's taptree), carrying the data expected on the stack and
/// the input's amount: the step of a contract that updates its own state.
pub fn check_output_same_contract(
    index: impl Into<CcvIndex>,
    pubkey: Option<XOnlyPublicKey>,
) -> ScriptBuf {
    let index = index.into();
    script! {
        { index.as_i64() }
        { optional_key_script(pubkey) }
        -1
        { CcvMode::Preserve.as_i32() }
        CHECKCONTRACTVERIFY
    }
}

/// CCV fragment that sends the input's amount to `key` itself (an
/// [`opaque_p2tr`] output: no data, no taptree), at the output whose index is
/// on top of the stack. The usual body of a `recover(out_i)` clause.
pub fn check_output_pays_key(key: XOnlyPublicKey) -> ScriptBuf {
    script! {
        0
        OP_SWAP
        { key }
        0
        { CcvMode::Preserve.as_i32() }
        CHECKCONTRACTVERIFY
    }
}

/// A raw `CHECKSEQUENCEVERIFY` fragment, like miniscript's `older`.
///
/// `n` is a sequence operand, including its flags, not a validated block count.
/// For block-based delays use [`crate::BlockDelay::script`] or the `contract!`
/// DSL's validated `timelock` section.
pub fn older(n: u32) -> ScriptBuf {
    script! {
        { n }
        CSV
        DROP
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_indices_preserve_ccv_helper_scripts() {
        for number in [-1, 0, 128, i64::from(i32::MAX)] {
            for key in [None, Some(crate::nums_key())] {
                let index = CcvIndex::try_from(number).unwrap();
                let root = [0x42; 32];
                assert_eq!(
                    check_input_contract(index, key),
                    script! {
                        { number } { optional_key_script(key) } -1 -1 CHECKCONTRACTVERIFY
                    }
                );
                assert_eq!(
                    check_output_contract(root, index, key),
                    script! {
                        { number } { optional_key_script(key) } { root } 0 CHECKCONTRACTVERIFY
                    }
                );
            }
        }
    }
}
