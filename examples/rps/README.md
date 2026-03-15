# mattrs-rps

Rock-Paper-Scissors over Bitcoin, settled entirely on-chain using MATT smart contracts.

## How it works

Two players wager bitcoin on a game of Rock-Paper-Scissors. The protocol uses a **commit-reveal** scheme to prevent cheating:

1. **Alice commits** -- Alice picks a move, hashes it with a random nonce, and funds the contract with the hash as embedded state.
2. **Bob plays** -- Bob sees Alice's commitment (but not her move) and plays his own move openly.
3. **Alice reveals** -- Alice reveals her move and nonce. The contract verifies they match her original commitment.
4. **Settlement** -- The contract adjudicates the outcome on-chain:
   - Winner takes both stakes.
   - On a tie, each player reclaims their own stake.

If Alice never reveals (trying to dodge a loss), Bob can claim victory after a timeout.

Players coordinate off-chain over **TCP**: Alice starts a listener, Bob connects. The connection is used to exchange commitments and public keys before any on-chain transactions.

## CLI

Run each player in a separate terminal:

```bash
# Terminal 1 -- Alice
cargo run -p mattrs-rps --bin rps-cli -- --alice -m

# Terminal 2 -- Bob
cargo run -p mattrs-rps --bin rps-cli -- --bob -m
```

Options:
- `--alice` / `--bob` -- Choose player role (required)
- `--rock` / `--paper` / `--scissors` -- Pre-select a move (prompted interactively if omitted)
- `-m`, `--mine-automatically` -- Mine blocks automatically after each operation
- `--host <HOST>` -- TCP host for coordination (default: `localhost`)
- `--port <PORT>` -- TCP port for coordination (default: `12345`)
- `--inspector` -- Enable inspector server (port 34443)
- `--inspector-port <PORT>` -- Enable inspector server on a custom port

## Tests

```bash
cargo test -p mattrs-rps
```
