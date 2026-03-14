# mattrs-game256

Fraud proof via bisection protocol.

Implements an end-to-end execution of the toy example for fraud proofs [drafted on bitcoin-dev](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-November/021205.html). Two parties narrow down a computation disagreement to a single step through interactive bisection, then resolve it on-chain.

## Tests

```bash
cargo test -p mattrs-game256
```
