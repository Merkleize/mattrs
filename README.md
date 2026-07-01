# mattrs

A Rust toolkit for building **MATT** (Merkleize-All-The-Things) Bitcoin covenant
contracts using `CHECKCONTRACTVERIFY` (CCV) and `CHECKTEMPLATEVERIFY` (CTV).

It provides witness (de)serialization, typed clauses with type-erased runtime
dispatch, P2TR / augmented-P2TR contract templates, a taproot tree, derive macros
(`mattrs-derive`), a `contract!` DSL that generates a typed handle with one spend
method per clause, and an RPC-driven `ContractManager` for funding and spending
instances on regtest.

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

A single `contract! { .. }` block generates the per-clause `*Args` structs, the
clause objects and taptree, a contract struct (`new` / `fund` / `as_erased`), and a
typed handle with **one spend method per clause**. Params/state stay ordinary
derived structs; the tapscripts stay as reviewable functions the DSL references.

```rust
#[derive(Debug, Clone, ContractParams)]
struct VaultParams { /* ... */ }

contract! {
    contract Vault {
        params VaultParams;
        internal_key |p| internal_key_or_nums(p.alternate_pk);

        clause trigger {
            args {
                #[signer(|p| p.unvault_pk.serialize())] sig: Signature,
                ctv_hash: [u8; 32],
                out_i: i64,
            }
            script Vault::trigger_script;          // fn(&VaultParams) -> ScriptBuf
            next(p, a) { /* -> Result<Vec<ClauseOutput>, ClauseError> */ }
        }
        // ... more clauses ...
        tree [trigger, [trigger_and_revault, recover]];
    }
}
```

## Spending: a clause is a typed method call

```rust
let vault = Vault::fund(&mut manager, amount, params)?;      // VaultHandle

// trigger: signed, exactly one child, returned typed
let unvaulting: UnvaultingHandle = vault
    .trigger(ctv_hash, 0)
    .sign(HotSigner::new(unvault_key))
    .exec_one(&mut manager)?
    .try_into()?;

// withdraw: terminal CTV spend with explicit outputs
unvaulting
    .withdraw(ctv_hash)
    .outputs(withdraw_outputs)
    .sequence(10)
    .exec_none(&mut manager)?;
```

Signatures are never hand-built: a `#[signer]` field stays in the `*Args` struct
(so the struct alone is the witness layout), the generated `new()` omits it, and
`.sign(..)` fills it by matching the clause's required pubkey — or the spend fails
with `MissingSigner`.

A complete worked example (a two-stage vault) lives in `tests/support/vault.rs`.

## Testing

```sh
cargo test          # unit + integration tests (no node required)
cargo test -- --ignored   # also runs the end-to-end test against a regtest bitcoind
```

The integration test in `tests/test_vault.rs` is `#[ignore]`d by default because
it needs a configured regtest `bitcoind`.

[`ClauseTree`]: src/contracts.rs
