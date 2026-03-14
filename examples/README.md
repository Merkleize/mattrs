# mattrs examples

Example smart contracts and interactive CLIs built with the mattrs framework.
Each example lives in its own sub-crate with its contract code, tests, and CLI (if any).

| Crate | Description |
|---|---|
| [vault/](vault/) | BIP-345-style vaults with `OP_CCV` + `OP_CTV` - with interactive CLI |
| [minivault/](minivault/) | Simplified vaults using only OP_CCV |
| [rps/](rps/) | Rock-Paper-Scissors - with interactive CLI |
| [ram/](ram/) | Merkle proof-based RAM contract |
| [game256/](game256/) | Demo of fraud proof via bisection protocol |
| [test-utils/](test-utils/) | Shared test utilities (RPC client, key helpers) |

See the [root README](../README.md) for prerequisites and node setup.
See each example's own README for usage details.
