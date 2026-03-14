# mattrs-rps

Rock-Paper-Scissors over Bitcoin using MATT smart contracts.

## Overview

Two-player game where Alice commits to a move, Bob plays, then Alice reveals. The outcome is adjudicated on-chain using `OP_CHECKCONTRACTVERIFY`. Players coordinate over TCP: Alice listens for a connection, Bob connects.

## CLI

```bash
# Terminal 1 (Alice)
cargo run -p mattrs-rps --bin rps-cli -- --alice -m

# Terminal 2 (Bob)
cargo run -p mattrs-rps --bin rps-cli -- --bob -m
```

Options:
- `--alice` / `--bob` -- Choose player role (required)
- `--rock` / `--paper` / `--scissors` -- Choose move (prompted interactively if omitted)
- `-m`, `--mine-automatically` -- Mine blocks automatically
- `--host <HOST>` -- TCP host (default: `localhost`)
- `--port <PORT>` -- TCP port (default: `12345`)
- `--inspector` -- Enable inspector server (port 34443)
- `--inspector-port <PORT>` -- Enable inspector server on a custom port

## Tests

```bash
cargo test -p mattrs-rps
```
