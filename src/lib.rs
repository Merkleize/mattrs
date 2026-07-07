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
//! - Declare params/state structs and derive [`macro@ContractParams`] /
//!   [`macro@ContractState`] (re-exported here from `mattrs-derive`).
//! - Write one [`macro@contract`]`! { .. }` block: it generates the per-clause
//!   `*Args` structs, the clause tree, the contract struct (`new`/`fund`/
//!   `as_erased`), and a typed handle with one spend method per clause.
//! - Drive funding/spending on-chain with [`ContractManager`](manager::ContractManager).
//!
//! Contracts whose clause layout is only known at runtime bypass the DSL and use
//! the same primitives directly ([`StandardClause::new`](contracts::StandardClause::new)
//! and the [`clause_tree!`](macro@clause_tree) macro) — see [`fraud`] for a worked
//! example (the generic bisection fraud proof).
//!
//! Start with `examples/getting_started.rs` (runs offline); `tests/support/vault.rs`
//! is a complete two-stage vault.

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
pub mod fraud;
#[cfg(feature = "inspector")]
pub mod inspector;
#[macro_use]
pub mod macros;
pub mod manager;
pub mod merkle;
pub mod protocol;
pub mod report;
pub mod script_helpers;
pub mod script_utils;
pub mod signer;
pub mod testutil;

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
