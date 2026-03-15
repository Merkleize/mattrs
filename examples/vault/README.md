# mattrs-vault

BIP-345-compatible vault contracts built with the mattrs framework.

## What is a vault?

A vault is a Bitcoin custody mechanism that adds a **time delay** between initiating a withdrawal and actually moving funds. During this delay, the owner (or a watchtower) can recover the funds to a pre-committed safe address if the withdrawal was unauthorized.

This makes vaults a powerful defense against key theft: even if an attacker steals the hot key, they cannot silently drain funds -- the legitimate owner has a window to react.

## How it works

The vault is modeled as a finite state machine with two contracts:

```
 VAULT ──trigger──> UNVAULTING ──(wait)──> withdraw
   │                    │
   └──recover──>  recovery address  <──recover──┘
```

- **Vault** -- The initial state. Funds sit here until the owner decides to spend them.
  - `trigger` -- Moves funds into the Unvaulting state, committing to a set of withdrawal outputs via `OP_CTV`.
  - `trigger_and_revault` -- Triggers a partial withdrawal, sending the remainder back into a new Vault.
  - `recover` -- Sends all funds to the pre-committed recovery address (no delay).

- **Unvaulting** -- The time-locked intermediate state.
  - `withdraw` -- After the spend delay expires, releases funds to the outputs committed during trigger.
  - `recover` -- Cancels the withdrawal and sends funds to the recovery address.

The implementation is largely compatible with [OP_VAULT BIP-0345](https://github.com/bitcoin/bips/blob/master/bip-0345.mediawiki).

## CLI

Interactive REPL for managing vault instances on regtest:

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
| `list` | List all contract instances and their current state |
| `mine [n]` | Mine n blocks (default 1) |
| `trigger items="[i,...]" outputs="['addr:amt',...]"` | Trigger vault(s) into the unvaulting state |
| `recover item=<idx>` | Recover from a funded vault or unvaulting instance |
| `withdraw item=<idx>` | Withdraw from a matured unvaulting instance |
| `printall` | Print markdown details of all spending transactions |

## Tests

```bash
cargo test -p mattrs-vault
```

Test reports are generated in the `reports/` folder, showing detailed transaction breakdowns for each flow.
