# mattrs-game256

End-to-end fraud proof via interactive bisection protocol.

## Background

This example implements the toy fraud-proof scenario [drafted on bitcoin-dev](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-November/021205.html). It demonstrates how MATT enables on-chain dispute resolution for computations that are too complex to verify directly in Bitcoin Script.

The "game" is simple: given an input _x_, compute _f(f(f(...f(x)...)))_ (8 iterations of a simple function _f_ that doulbes the given number). Two parties might disagree on the result. The fraud proof protocol resolves the disagreement by narrowing it down to a single step of _f_, which _is_ small enough to verify on-chain.

## Protocol flow

The protocol proceeds through three contracts and then into a generic bisection phase:

**G256_S0** -- Bob picks the initial value _x_.

**G256_S1** -- Alice reveals her claimed result _y_ = _f^256(x)_, along with her trace commitment _t_a_ (a Merkle root of all 257 intermediate values).

**G256_S2** -- Two possible outcomes:
- **withdraw**: If Bob does not challenge within the timeout, Alice takes the funds. Her claim is accepted.
- **start_challenge**: Bob disagrees with Alice's result. He provides his own claimed result _z_ and trace commitment _t_b_, and the contract transitions to the bisection phase.

**Bisection** -- Alice and Bob take turns halving the range of disagreement. At each step, the challenged party reveals the midpoint value from their trace. After log2(8) = 3 rounds, the dispute is narrowed to a single computation step _f(v) = w_. A leaf contract verifies this step directly in Script:
- If Alice was wrong, Bob takes the funds.
- If Alice was right, Alice takes the funds.

The bisection machinery is generic and reusable -- see the `hub::fraud` module in the core library.

## Tests

```bash
cargo test -p mattrs-game256
```

Test reports in the `reports/` folder show the full transaction chain for both honest and fraudulent scenarios.
