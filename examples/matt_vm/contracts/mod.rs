//! MATT-VM: optimistic execution of a tiny CPU, adjudicated by the generic
//! [`mattrs::fraud`] bisection.
//!
//! A prover claims what a committed program computes; a verifier can dispute
//! the claim, and the dispute bisects the execution trace down to a single
//! instruction that is re-run on-chain — including its instruction fetch
//! (Merkle-proven against the program commitment, path-bound to `pc`) and its
//! memory access (`ram`-style Merkle walks, path-bound to the operand).
//!
//! - [`vm`]: the machine model, interpreter, and trace builder.
//! - [`computer`]: the single-step script fragments (the
//!   [`fraud::Computer`](mattrs::fraud::Computer)) and their off-chain mirror.
//! - [`stages`]: the two on-chain game stages in front of the bisection.
//! - [`roles`]: both parties as composable protocol roles.

pub mod computer;
pub mod roles;
pub mod stages;
pub mod vm;
