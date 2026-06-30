# mattrs

A Rust toolkit for building **MATT** (Merkleize-All-The-Things) Bitcoin covenant
contracts using `CHECKCONTRACTVERIFY` (CCV) and `CHECKTEMPLATEVERIFY` (CTV).

It provides witness (de)serialization, typed clauses with type-erased runtime
dispatch, P2TR / augmented-P2TR contract templates, a taproot tree, derive macros
(`mattrs-derive`), declarative macros (`clause!`, `clause_tree!`), and an
RPC-driven `ContractManager` for funding and spending instances on regtest.

## Design: one source of truth

A contract is a taproot output whose tapscript leaves are *clauses* (name +
script + typed args + a function computing the next outputs). A
[`ClauseTree`] is built **once**, and everything else is derived from it:

- the address-bearing script taptree,
- the spend-time `name → clause` lookup,
- the witness layout (argument order).

Because they are all derived from the same tree, a contract's address can never
drift from the witness that spends it. Contracts are also *self-describing*: each
carries its encoded params, so child instances recover their params from the
contract rather than from a parallel field.

## Defining a contract

```rust
#[derive(Debug, Clone, ContractParams)]
struct VaultParams { /* ... */ }

#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = VaultParams)]
struct TriggerArgs {
    #[signer(|p| p.unvault_pk.serialize())]
    sig: Vec<u8>,
    ctv_hash: [u8; 32],
    out_i: i64,
}

let trigger = clause!("trigger", TriggerArgs, script, &params, next_outputs_fn);
let contract = StandardP2TR::new(internal_key, &params, clause_tree![trigger, [a, b]]);
```

A complete worked example (a two-stage vault) lives in `tests/support/vault.rs`.

## Testing

```sh
cargo test          # unit + integration tests (no node required)
cargo test -- --ignored   # also runs the end-to-end test against a regtest bitcoind
```

The integration test in `tests/test_vault.rs` is `#[ignore]`d by default because
it needs a configured regtest `bitcoind`.

[`ClauseTree`]: src/contracts.rs
