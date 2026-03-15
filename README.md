# mattrs

A Rust framework for building and testing smart contracts using the [MATT](https://merkle.fun) (_Merkleize All The Things_) approach on Bitcoin, powered by the `OP_CHECKCONTRACTVERIFY` (CCV) opcode.

mattrs is the Rust port of [pymatt](https://github.com/Merkleize/pymatt). It provides the building blocks to define contract state machines, construct taproot spend transactions with CCV validation, and manage contract instance lifecycles against a regtest node.

## What is MATT?

MATT enables general-purpose smart contracts on Bitcoin through three simple ideas:

1. **Merkleize the data** -- Compress arbitrary contract state into a single 32-byte hash committed in a UTXO, using Merkle trees.
2. **Merkleize the scripts** -- Represent all possible state transitions as leaves of a taproot tree (already possible since the Taproot soft fork).
3. **Merkleize the execution** -- For computations too complex for Bitcoin Script, use fraud proofs: let parties assert results off-chain, then resolve disputes on-chain via interactive bisection.

These three ingredients, combined with the `OP_CHECKCONTRACTVERIFY` opcode, are enough to express a surprisingly wide range of protocols.

## Core library

The `mattrs` crate provides:

- **Contract model** -- Define contracts as taproot trees of spending clauses. Each clause specifies a script, typed arguments, and the next outputs it produces. The `contract!` macro generates the boilerplate.
- **State management** -- Embed arbitrary state data in UTXOs via internal pubkey tweaking. The `define_state!` macro generates typed encode/decode helpers.
- **CCV integration** -- Constants, flags, and script helpers for `OP_CHECKCONTRACTVERIFY` (opcode `0xbb`), including `CCV_FLAG_CHECK_INPUT`, `CCV_FLAG_DEDUCT_OUTPUT_AMOUNT`, and more.
- **Transaction building** -- Constructs fully-signed spend transactions with proper witness layout, control blocks, and CCV output validation.
- **Contract manager** -- Drives contract instances through their lifecycle (Abstract -> Funded -> Spent) by polling a Bitcoin Core RPC node, handling funding, spending, and automatic output tracking.
- **Taproot utilities** -- Recursive `TapTree` type with merkle root computation, proof generation, and address derivation.
- **Merkle trees** -- Left-complete binary Merkle trees (matching pymatt's convention) for state commitments.
- **Signing** -- `SchnorrSigner` trait with a `HotSigner` implementation for test/dev use.
- **Fraud proofs** -- Reusable bisection protocol for off-chain computation disputes, settled on-chain.
- **Inspector** -- Optional feature (`inspector`) that exposes manager state over TCP for real-time visualization with the companion TUI.

## Repository structure

```
mattrs/
  src/               Core library
  inspector/         TUI binary for real-time contract instance visualization
  examples/
    vault/           BIP-345 vault contracts with interactive CLI
    minivault/       Simplified vault with configurable features
    rps/             Rock-Paper-Scissors over Bitcoin with interactive CLI
    ram/             Merkle proof-based RAM contract
    game256/         Fraud proof via bisection protocol
    test-utils/      Shared test utilities (RPC client, key helpers)
```

## Prerequisites

- [Rust](https://www.rust-lang.org) (stable)
- [Docker](https://www.docker.com) (for running a CCV-enabled Bitcoin node)

## Running a CCV-enabled regtest node

The examples and tests require a bitcoin-inquisition node with `OP_CHECKCONTRACTVERIFY` support. The fastest way to get one running:

```bash
docker pull bigspider/bitcoin_matt
docker run -d -p 18443:18443 bigspider/bitcoin_matt
```

Alternatively, build from the [inq-ccv branch](https://github.com/Merkleize/bitcoin/tree/inq-ccv) with the following `bitcoin.conf`:

<details>
  <summary><tt>bitcoin.conf</tt></summary>

  ```
  regtest=1
  server=1
  txindex=1
  fallbackfee=0.00001
  minrelaytxfee=0
  blockmintxfee=0

  [regtest]
  rpcbind=0.0.0.0
  rpcallowip=0.0.0.0/0
  rpcuser=rpcuser
  rpcpassword=rpcpass
  ```
</details>

## Environment variables

The CLIs and tests use these environment variables to connect to the regtest node (defaults match the docker container):

```
BITCOIN_RPC_URL=http://localhost:18443
BITCOIN_RPC_USER=rpcuser
BITCOIN_RPC_PASS=rpcpass
WALLET_NAME=testwallet
```

## Building

```bash
# Build the core library
cargo build -p mattrs

# Build everything (library + all examples + inspector)
cargo build --workspace
```

## Running the tests

The test suite requires a running CCV-enabled node (see above).

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific example
cargo test -p mattrs-vault
cargo test -p mattrs-minivault
cargo test -p mattrs-rps
cargo test -p mattrs-ram
cargo test -p mattrs-game256
```

## Examples

See the [examples/](examples/) folder for smart contract implementations and interactive CLIs. Each example has its own README with usage details.

### Inspector

The inspector is a real-time TUI that visualizes contract instance state as it changes. Enable the inspector server in any CLI with the `--inspector` flag, then connect with the TUI:

```bash
# In one terminal, run a CLI with inspector enabled
cargo run -p mattrs-vault --bin vault-cli -- -m --inspector

# In another terminal, launch the TUI
cargo run -p mattrs-inspector --bin inspector
```

## Related

- [pymatt](https://github.com/Merkleize/pymatt) -- The original Python framework
- [bitcoin-inquisition (inq-ccv)](https://github.com/Merkleize/bitcoin/tree/inq-ccv) -- Bitcoin Core fork with CCV support
- [OP_CHECKCONTRACTVERIFY](https://github.com/bitcoin/bips/pull/1793) -- BIP draft
