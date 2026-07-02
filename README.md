# mattrs

A Rust toolkit for building **MATT** (Merkleize-All-The-Things) Bitcoin covenant
contracts using `CHECKCONTRACTVERIFY` (CCV) and `CHECKTEMPLATEVERIFY` (CTV).

It provides witness (de)serialization, typed clauses with type-erased runtime
dispatch, P2TR / augmented-P2TR contract templates, a taproot tree, derive macros
(`mattrs-derive`), a `contract!` DSL that generates a typed handle with one spend
method per clause, a generic bisection fraud-proof module (`mattrs::fraud`), and
an RPC-driven `ContractManager` for funding and spending instances on regtest.

## Getting started

The crate is unpublished; use it as a path dependency:

```toml
[dependencies]
mattrs = { path = "../mattrs2" }
bitcoin = "0.32"
bitcoin-script = { path = "../mattrs2/bitcoin-script" }   # patched vendor, see below
```

Then run the offline example — it defines a two-clause contract with the
`contract!` DSL, derives its address, and builds a signed spend without a node:

```sh
cargo run --example getting_started
```

> **Note on `bitcoin-script/`**: this repository vendors a *patched* copy of
> [BitVM/rust-bitcoin-script](https://github.com/BitVM/rust-bitcoin-script) v0.2.0.
> The patch (`bitcoin-script/src/parse.rs`) teaches the `script!` macro the MATT
> opcodes `OP_CHECKTEMPLATEVERIFY` (0xb3) and `OP_CHECKCONTRACTVERIFY` (0xbb),
> which upstream does not know. Do not "upgrade" it back to upstream.

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
        // optional; defaults to the NUMS key (no key-spend path)
        internal_key |p| internal_key_or_nums(p.alternate_pk);

        clause trigger {
            args {
                #[signer(p.unvault_pk)] sig: Signature,   // auto-filled at spend time
                ctv_hash: [u8; 32],
                out_i: i64,
            }
            script Vault::trigger_script;          // fn(&VaultParams) -> ScriptBuf
            // The body yields Result<T, ClauseError> where T is anything
            // Into<NextOutputs>: Vec<ClauseOutput>, CtvTemplate, or NextOutputs.
            next(p, a) { /* ... */ }
        }
        // ... more clauses ...
        tree [trigger, [trigger_and_revault, recover]];
    }
}
```

Multi-field contract state commits with a derive instead of a manual impl:

```rust
#[derive(Debug, Clone, ContractState)]
#[commit(merkle)]                  // encode() = Merkle root of the fields' leaves
pub struct G256S2State {
    pub t_a: [u8; 32],             // a raw 32-byte leaf
    #[leaf(sha256)] pub y: i64,    // leaf = sha256 of the field's witness encoding
    #[leaf(sha256)] pub x: i64,
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

## Fraud proofs: `mattrs::fraud`

The generic bisection fraud-proof protocol (pymatt's `hub/fraud.py`) is a library
module: Alice claims an `n`-step computation's result, Bob disputes it, and the
`Bisect_1`/`Bisect_2` contracts bisect the execution trace down to one step, which
the `Leaf` contract re-runs on-chain. The whole machinery is generic over a
`Computer` — the step function and value-commitment as script fragments plus the
witness specs of one value:

```rust
let compute2x = Computer {
    encoder: script! { OP_SHA256 },     // value commitment
    func:    script! { OP_DUP OP_ADD }, // one step: y = 2x
    specs:   vec![ArgSpec { name: "x".into(), arg_type: Arc::new(IntType) }],
};
let leaf_factory: LeafFactory =
    Arc::new(move |_i| Leaf::new(LeafParams { alice_pk, bob_pk }, &compute2x));
let challenge = Bisect1::new(BisectParams { alice_pk, bob_pk, i: 0, j: 7 },
                             &leaf_factory, /*forfait_timeout=*/10);
```

`tests/support/game256.rs` instantiates it for the game256 example in ~30 lines.

## Ported examples

The examples from the Python reference framework (`pymatt`) are ported under
`tests/support/`, each with tests asserting **byte-for-byte** taproot compatibility
(the taptree root / address matches pymatt's) and, where applicable, the spend:

| Example | Demonstrates | Status |
| --- | --- | --- |
| **vault** (`vault.rs`) | two-stage vault; CCV + CTV; augmented state; multi-input trigger-with-revault | address matches; spendable (regtest e2e) |
| **rps** (`examples/rps/contracts.rs`) | hashed state; clause-owned **CTV templates** for payouts; `check_in/out_contract` | roots match; regtest e2e; two-player demo |
| **ram** (`ram.rs`) | a Merkle-committed cell vector; the `WitProof<N>` witness arg; **expanded state** | root matches; `write` spends |
| **game256** (`game256.rs`) | the **bisection fraud proof** (`mattrs::fraud`) driven by the `G256S0/1/2` game stages | all taptrees match; the full state machine spends |

Supporting MATT infrastructure lives in the library for downstream reuse: the
generic fraud-proof contracts (`mattrs::fraud`), a data `MerkleTree` /
`MerkleProof` / `WitProof` / `MerkleProofType` (`mattrs::merkle`), and the
`merkle_root(n)` / `dup(n)` / `drop(n)` / `check_input_contract` /
`check_output_contract` / `older` / `timeout_sig_script` script fragments
(`mattrs::script_helpers`), plus `commit_int` (`mattrs::script_utils`).

## Two-player demo

`examples/rps/` plays a Rock-Paper-Scissors game between two *separate
processes*, negotiated over a TCP socket and played entirely on-chain: Alice
funds the game behind a hiding move commitment, Bob reveals his move with a
typed spend, and each side follows the other's turn with chain observation.
Against a regtest node with a funded `testwallet`, in two terminals:

```sh
cargo run --example rps -- --alice --rock
cargo run --example rps -- --bob --paper
```

Omit the move flag to play a random move; `--addr host:port` and
`--wallet name` override the defaults.

## Spend-API features

- **CTV templates as clause outputs** — a clause's `next` may return a
  `CtvTemplate`, which fixes the transaction outputs and `nSequence` (see rps).
- **Multi-input batch spends** — `ContractManager::spend_batch(..)` merges several
  instances' outputs by index (pymatt's `get_spend_tx` semantics).
- **Expanded state** — an instance can carry logical state richer than its on-chain
  commitment (e.g. RAM's cells vs their Merkle root), recovered by `next_outputs`.
- **Chain observation** — follow a covenant driven by someone else:
  `track_instance(..)` registers an externally funded instance, and
  `wait_for_spend(..)` (mempool + block scan; or the RPC-free
  `observe_spend(..)`) decodes the spending witness back into the clause and its
  typed arguments and materializes the child instances
  (see `tests/test_observe.rs`).

## Testing

```sh
cargo test                # unit + integration tests (no node required)
cargo test -- --ignored   # also runs the end-to-end tests against a regtest bitcoind
```

The end-to-end tests are `#[ignore]`d by default because they need a configured
regtest `bitcoind` with a funded `testwallet` (cookie or env-var RPC auth; see
`tests/support/testkit.rs`).

[`ClauseTree`]: src/contracts.rs
