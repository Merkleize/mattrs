# mattrs-minivault

A stripped-down vault implementation using only `OP_CHECKCONTRACTVERIFY`, with configurable features for testing specific vault behaviors in isolation.

## How it differs from the full vault

The full [vault](../vault/) example uses both `OP_CCV` and `OP_CTV` and targets BIP-345 compatibility. The minivault simplifies this by:

- Using only `OP_CCV` for all covenant logic (no `OP_CTV`)
- Making features individually toggleable at construction time
- Serving as a testbed for experimenting with vault variations

## Configurable features

The `MiniVaultParams` struct controls which clauses are included in the contract's taptree:

| Parameter | Effect when enabled |
|---|---|
| `has_partial_revault` | Adds the `trigger_and_revault` clause, allowing partial withdrawals that send the remainder back into a new vault |
| `has_early_recover` | Adds the `recover` clause to the vault state, allowing immediate recovery without first triggering |

When both are disabled, the vault has only the `trigger` clause. This produces the simplest possible vault: trigger into unvaulting, then either withdraw (after the delay) or recover.

## Contract structure

**MiniVault** -- The funded state. Clauses depend on configuration:
- `trigger` -- Always present. Moves funds to MiniUnvaulting with a committed withdrawal pubkey.
- `trigger_and_revault` -- Optional. Partial withdrawal: deducts an amount for unvaulting, sends the rest back to a new MiniVault.
- `recover` -- Optional. Immediate recovery to the pre-committed recovery address.

**MiniUnvaulting** -- The time-locked state. Always has two clauses:
- `withdraw` -- After `spend_delay` blocks, sends funds to the committed withdrawal pubkey.
- `recover` -- Sends funds to the recovery address at any time.

## Tests

```bash
cargo test -p mattrs-minivault
```

The tests cover all four feature combinations and produce transaction reports in the `reports/` folder.
