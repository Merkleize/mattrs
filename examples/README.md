# mattrs examples

Smart contracts and interactive CLIs built with the mattrs framework. Each example is a standalone crate with its own contract definitions, tests, and (where applicable) a CLI.

| Crate | What it demonstrates |
|---|---|
| [vault/](vault/) | BIP-345-style vaults using `OP_CCV` + `OP_CTV` -- trigger, recover, and time-locked withdrawal flows. Interactive CLI. |
| [minivault/](minivault/) | Stripped-down vault using only `OP_CCV`. |
| [rps/](rps/) | Two-player Rock-Paper-Scissors - with interactive CLI. |
| [ram/](ram/) | On-chain key-value store backed by Merkle proofs -- read, write, and withdraw operations on a vector of arbitrary length. |
| [game256/](game256/) | End-to-end fraud proof via interactive bisection -- resolves a computation dispute down to a single step. |
| [test-utils/](test-utils/) | Shared test utilities: RPC client setup, key generation, wallet helpers. |

## Getting started

All examples require a running CCV-enabled regtest node. See the [root README](../README.md) for prerequisites and node setup instructions.

Each example's own README covers its specific usage, CLI commands, and contract design.
