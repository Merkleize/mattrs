//! Shared support code for integration tests: example contracts that exercise
//! the `mattrs` framework the way a downstream user would.
//!
//! These modules are compiled once per test binary, and each binary exercises
//! only a subset of them, so per-binary dead-code warnings are structural, not
//! real (nothing here is dead across *all* binaries). Hence the targeted
//! `allow(dead_code)` on each module.

#[allow(dead_code)]
pub mod game256;
#[allow(dead_code)]
pub mod ram;
// The RPS contract lives with its two-player demo (examples/rps/); the tests
// compile the same single source.
#[allow(dead_code)]
#[path = "../../examples/rps/contracts.rs"]
pub mod rps;
#[allow(dead_code)]
pub mod testkit;
#[allow(dead_code)]
pub mod vault;
