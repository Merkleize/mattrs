# mattrs-ram

An on-chain RAM (random-access memory) contract that stores a vector of arbitrary length using a Merkle tree commitment, with transitions for reading, writing, and withdrawing.

## How it works

The contract maintains a **Merkle tree** whose root is embedded as the UTXO's state. Each leaf of the tree holds a 32-byte value, and the tree's size is fixed at creation time (must be a power of 2).

State transitions use **Merkle proofs** to verify and update individual elements without revealing the entire tree:

- **write** -- Updates a single leaf. The spender provides a Merkle proof for the old value and the new value. The script verifies the proof against the current root, computes the new root, and enforces (via `OP_CCV` with `taptree=-1`) that the output carries the updated root. The contract loops back to itself.
- **withdraw** -- Terminal spend. The spender proves membership of a leaf via Merkle proof, and the funds are released. No covenant constraint on the output.

Because the `write` clause uses `taptree=-1` (reuse the current input's taptree) and `index=-1` (same-index output), multiple RAM contracts can coexist in a single transaction, each updating independently.

## Contract structure

```
RAM_N[merkle_root]:
  write(proof, new_value, root) => RAM_N[new_root]
  withdraw(proof, root) => (unconstrained)
```

Where `N` is the number of leaves (e.g., `RAM_8` for an 8-element vector).

## Tests

```bash
cargo test -p mattrs-ram
```
