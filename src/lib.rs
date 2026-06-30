use bitcoin::{ScriptBuf, XOnlyPublicKey};

pub mod argtypes;
pub mod contracts;
pub mod ctv;
#[macro_use]
pub mod macros;
pub mod manager;
pub mod script_utils;
pub mod signer;
pub mod vault;

/// Returns a script that pushes the XOnlyPublicKey if Some, or 0 if None
pub fn optional_key(maybe_pk: Option<XOnlyPublicKey>) -> ScriptBuf {
    let builder = bitcoin::script::Builder::new();
    let builder = if let Some(pk) = maybe_pk {
        builder.push_x_only_key(&pk)
    } else {
        builder.push_int(0)
    };
    builder.into_script()
}
