use bitcoin::{ScriptBuf, XOnlyPublicKey};

pub mod ccv;
pub mod report;
pub mod contracts;
pub mod ctv;
pub mod hub;
pub mod macros;
pub mod manager;
pub mod merkle;
pub mod script_helpers;
pub mod signer;
pub mod taproot;
pub mod tx;

/// Compute SHA256 of arbitrary data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    sha256::Hash::hash(data).to_byte_array()
}

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
