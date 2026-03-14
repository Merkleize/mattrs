# mattrs-ram

Merkle proof-based RAM contract allowing on-chain read and write operations with Merkle tree state verification.

Stores a vector of arbitrary length on-chain using a Merkle tree commitment, with transitions that modify one element at a time via Merkle proofs.

## Tests

```bash
cargo test -p mattrs-ram
```
