//! `mattrs` — a Rust toolkit for building MATT (Merkleize-All-The-Things) Bitcoin
//! covenant contracts using `CHECKCONTRACTVERIFY` and `CHECKTEMPLATEVERIFY`.
//!
//! # Overview
//!
//! A contract is a taproot output whose tapscript leaves are *clauses*. Each
//! clause has a name, a script, typed arguments, and a function computing the
//! contract outputs it produces when spent.
//!
//! The central design rule is **one source of truth**: a
//! [`ClauseTree`](contracts::ClauseTree) of clauses is built once, and the
//! address-bearing script taptree, the spend-time clause lookup, and the witness
//! layout are all *derived* from it — they cannot drift apart.
//!
//! # Defining a contract
//!
//! - Declare params/state/args structs and derive [`macro@ContractParams`],
//!   [`macro@ContractState`], and [`macro@ClauseArgs`] (re-exported here from
//!   `mattrs-derive`).
//! - Build clauses with the `clause!` macro and assemble them with the
//!   `clause_tree!` macro, then hand the tree to
//!   [`StandardP2TR::new`](contracts::StandardP2TR::new) or
//!   [`StandardAugmentedP2TR::new`](contracts::StandardAugmentedP2TR::new).
//! - Drive funding/spending on-chain with [`ContractManager`](manager::ContractManager).
//!
//! See `tests/support/vault.rs` for a complete worked example (a two-stage vault).

// Lets the `mattrs-derive` macros refer to this crate as `::mattrs::...` even when
// the deriving type lives inside this crate (e.g. examples/tests), so the derives
// work identically inside and outside the crate.
extern crate self as mattrs;

use bitcoin::{ScriptBuf, XOnlyPublicKey};

/// Derive macros, re-exported so users can `use mattrs::{ContractParams, ..}`.
pub use mattrs_derive::{ClauseArgs, ContractParams, ContractState};

/// The `contract!` DSL macro, re-exported so users can `use mattrs::contract`.
pub use mattrs_derive::contract;

/// A signature witness element, re-exported for use in clause `*Args` structs.
pub use contracts::Signature;

pub mod argtypes;
pub mod contracts;
pub mod ctv;
#[macro_use]
pub mod macros;
pub mod manager;
pub mod script_utils;
pub mod signer;

/// NUMS ("nothing-up-my-sleeve") x-only public key, used as a taproot internal key
/// when a contract has no key-spend path.
pub const NUMS_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// The NUMS point as an [`XOnlyPublicKey`].
pub fn nums_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&NUMS_KEY).expect("valid NUMS key")
}

/// Resolve a contract's taproot internal key: the provided alternate key, or the
/// [`nums_key`] when there is no key-spend path.
pub fn internal_key_or_nums(maybe_pk: Option<XOnlyPublicKey>) -> XOnlyPublicKey {
    maybe_pk.unwrap_or_else(nums_key)
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
