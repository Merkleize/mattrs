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
