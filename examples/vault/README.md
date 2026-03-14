# mattrs-vault

BIP-345-compatible vault contracts built with the mattrs framework.

## Overview

Implements a vault with trigger, recover, and withdraw flows, largely compatible with [OP_VAULT BIP-0345](https://github.com/bitcoin/bips/blob/master/bip-0345.mediawiki). Triggering a vault moves funds into a time-locked unvaulting state; after the delay, the owner can withdraw to pre-committed outputs. Recovery is possible at any point before withdrawal.

## CLI

Interactive REPL for managing vault instances on regtest.

```bash
cargo run -p mattrs-vault --bin vault-cli -- -m
```

Options:
- `-m`, `--mine-automatically` -- Mine a block after each operation
- `-s`, `--script <FILE>` -- Execute commands from a script file
- `--inspector` -- Enable inspector server (port 34443)
- `--inspector-port <PORT>` -- Enable inspector server on a custom port

### Commands

| Command | Description |
|---|---|
| `fund amount=<sats>` | Fund a new vault instance |
| `list` | List all contract instances |
| `mine [n]` | Mine n blocks (default 1) |
| `trigger items="[i,...]" outputs="['addr:amt',...]"` | Trigger vault(s) into unvaulting state |
| `recover item=<idx>` | Recover from a funded vault or unvaulting instance |
| `withdraw item=<idx>` | Withdraw from a funded unvaulting instance |
| `printall` | Print markdown details of all spending txs |

## Tests

```bash
cargo test -p mattrs-vault
```
