//! Shared support code for integration tests: example contracts that exercise
//! the `mattrs` framework the way a downstream user would.
//!
//! These modules are compiled once per test binary, and each binary exercises
//! only a subset of them, so per-binary dead-code warnings are structural, not
//! real (nothing here is dead across *all* binaries). Hence the targeted
//! `allow(dead_code)` on each module.

// The aggregate-exits contracts live with their demo (examples/aggregate_exits/);
// the tests compile the same single source.
#[allow(dead_code, unused_imports)]
#[path = "../../examples/aggregate_exits/contracts/mod.rs"]
pub mod aggregate_exits;
#[allow(dead_code)]
pub mod game256;
#[allow(dead_code)]
pub mod game256_roles;
#[allow(dead_code)]
pub mod minivault;
#[allow(dead_code)]
pub mod ram;
// The RPS contract lives with its two-player demo (examples/rps/); the tests
// compile the same single source.
#[allow(dead_code)]
#[path = "../../examples/rps/contracts.rs"]
pub mod rps;
#[allow(dead_code)]
pub mod testkit;
// The tic-tac-toe contract lives with its two-player demo (examples/tictactoe/);
// the tests compile the same single source.
#[allow(dead_code)]
#[path = "../../examples/tictactoe/contracts.rs"]
pub mod tictactoe;
// The vault contract lives with its REPL demo (examples/vault/); the tests
// compile the same single source.
#[allow(dead_code)]
#[path = "../../examples/vault/contracts.rs"]
pub mod vault;
#[allow(dead_code)]
pub mod vault_roles;
