//! Core contract model: typed clauses, taproot trees, and contract templates.
//!
//! The types here layer as follows:
//!
//! - **Witness encoding** — [`WitnessEncodable`] turns values into script-facing
//!   witness-stack elements; a clause's [`ClauseArgs`] and a state's
//!   [`ContractState`] leaves use it (so their bytes are exactly what the covenant
//!   reads). Contracts declare these per-role encodings via the derive macros.
//!   [`ContractParams`] are never serialized: a contract holds its params as a
//!   plain Rust value, so they may be of any type. [`ErasedState`] carries a
//!   *logical* state on an instance even when its on-chain commitment is lossy
//!   (e.g. a Merkle root).
//! - **Clauses** — a [`StandardClause`] is one tapscript spending path: a name,
//!   a script, [`ArgSpec`]s describing its witness layout, and an optional
//!   function computing the [`NextOutputs`] it produces when spent (covenant
//!   [`ClauseOutput`]s or a fixed [`CtvTemplate`]). [`ErasedClause`] is its
//!   type-erased view for runtime dispatch.
//! - **Trees** — a [`ClauseTree`] arranges clauses into the taproot tree shape;
//!   the address-bearing script [`TapTree`], the spend-time clause lookup, and
//!   the witness layout are all *derived* from it, so they cannot drift apart.
//! - **Contracts** — a [`StandardP2TR`] wraps a clause tree plus its params;
//!   its internal key is tweaked with each instance's state commitment (empty,
//!   hence no tweak, for a stateless contract). [`ErasedContract`] is its
//!   type-erased view.
//! - **Instances** — a [`ContractInstance`] is one UTXO of a contract: funded
//!   from creation, and later carrying the [`SpendRecord`] of the transaction
//!   that consumed it (driven by the
//!   [`ContractManager`](crate::manager::ContractManager)).

mod clause;
mod contract;
mod error;
mod instance;
mod output;
mod state;
mod taptree;
mod witness;

pub use crate::ccv::{AmountMode, CcvIndex};
pub use clause::*;
pub use contract::*;
pub use error::*;
pub use instance::*;
pub use output::*;
pub use state::*;
pub use taptree::*;
pub use witness::*;
