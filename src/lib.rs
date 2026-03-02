use bitcoin::{ScriptBuf, XOnlyPublicKey};

pub mod ccv;
pub mod contracts;
pub mod ctv;
pub mod hub;
pub mod macros;
pub mod manager;
pub mod signer;
pub mod taproot;
pub mod tx;

/// Returns a script that pushes the pubkey or 0 on the stack.
pub fn optional_key(maybe_pk: Option<XOnlyPublicKey>) -> ScriptBuf {
    let builder = bitcoin::script::Builder::new();
    let builder = if let Some(pk) = maybe_pk {
        builder.push_x_only_key(&pk)
    } else {
        builder.push_int(0)
    };
    builder.into_script()
}
