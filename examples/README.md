# mattrs examples

Example smart contracts and interactive CLIs built with the mattrs framework.
Each example lives in its own sub-crate with its contract code, tests, CLI (if any), and reports.

| Crate | Description |
|---|---|
| [vault/](vault/) | BIP-345 vault contracts with interactive CLI |
| [minivault/](minivault/) | Simplified vault with configurable features |
| [rps/](rps/) | Rock-Paper-Scissors over Bitcoin with interactive CLI |
| [ram/](ram/) | Merkle proof-based RAM contract |
| [game256/](game256/) | Fraud proof via bisection protocol |
| [test-utils/](test-utils/) | Shared test utilities (RPC client, key helpers) |

## Prerequisites

* [Rust](https://www.rust-lang.org) (stable)
* [docker](https://www.docker.com)

## Run bitcoin-inquisition + `OP_CHECKCONTRACTVERIFY` in regtest mode

```bash
docker pull bigspider/bitcoin_matt
docker run -d -p 18443:18443 bigspider/bitcoin_matt
```

The examples use the `BITCOIN_RPC_URL`, `BITCOIN_RPC_USER`, `BITCOIN_RPC_PASS` and `WALLET_NAME`
environment variables to connect to the regtest node. The defaults match the docker container above:

```
BITCOIN_RPC_URL=http://localhost:18443
BITCOIN_RPC_USER=rpcuser
BITCOIN_RPC_PASS=rpcpass
WALLET_NAME=testwallet
```

## Run end-to-end tests

The test suite requires a running CCV-enabled bitcoin-inquisition node (see above).

```bash
# Run all example tests
cargo test --workspace

# Run tests for a specific example
cargo test -p mattrs-vault
cargo test -p mattrs-minivault
cargo test -p mattrs-rps
cargo test -p mattrs-ram
cargo test -p mattrs-game256
```

## Run vault-cli

Interactive CLI for [BIP-345](https://github.com/bitcoin/bips/blob/master/bip-0345.mediawiki)-compatible vault contracts.

```bash
cargo run -p mattrs-vault --bin vault-cli -- -m
```

Options:
- `-m`, `--mine-automatically` - Mine a block after each operation
- `-s`, `--script <FILE>` - Execute commands from a script file

Available commands: `fund`, `list`, `mine`, `trigger`, `recover`, `withdraw`, `printall`.

## Run rps-cli

Interactive CLI for Rock-Paper-Scissors over Bitcoin. Two players coordinate
over TCP: Alice listens, Bob connects.

In one terminal, start Alice:

```bash
cargo run -p mattrs-rps --bin rps-cli -- --alice --rock -m
```

In another terminal, start Bob:

```bash
cargo run -p mattrs-rps --bin rps-cli -- --bob --paper -m
```

Options:
- `--alice` / `--bob` - Choose player role (required)
- `--rock` / `--paper` / `--scissors` - Choose move (random if omitted)
- `-m`, `--mine-automatically` - Mine blocks automatically
- `--host <HOST>` - TCP host (default: `localhost`)
- `--port <PORT>` - TCP port (default: `12345`)
