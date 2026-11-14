# mattrs

A Rust toolkit for building **MATT** (Merkleize-All-The-Things) Bitcoin covenant
contracts using `CHECKCONTRACTVERIFY` (CCV) and `CHECKTEMPLATEVERIFY` (CTV).

It provides witness (de)serialization, typed clauses with type-erased runtime
dispatch, P2TR / augmented-P2TR contract templates, a taproot tree, derive macros
(`mattrs-derive`), a `contract!` DSL that generates a typed handle with one spend
method per clause, a generic bisection fraud-proof module (`mattrs::fraud`), and
an RPC-driven `ContractManager` for funding and spending instances on regtest.

For the conceptual model behind all of this — programs, clauses, merkleized
state, and the `Contract{params}[vars]` notation used to specify protocols as
finite state machines — see [Designing contracts](docs/README.md).

## Getting started

The crate is unpublished; use it as a path dependency:

```toml
[dependencies]
mattrs = { path = "../mattrs" }
bitcoin = "0.32"
```

`use mattrs::prelude::*;` brings in the names nearly every contract file needs,
including `contract!`, `script!` and the `script` module of reusable fragments.

Then run the offline example — it defines a two-clause contract with the
`contract!` DSL, derives its address, then funds and spends it on an in-memory
chain, without a node:

```sh
cargo run --example getting_started
```

The next step is `examples/counter.rs`: a contract with state, a `next`
function, and a protocol role playing it, also without a node (or against one,
with `--regtest`):

```sh
cargo run --example counter
```

> **Note on `bitcoin-script/`**: `mattrs::script!` is built on a *patched* copy of
> [BitVM/rust-bitcoin-script](https://github.com/BitVM/rust-bitcoin-script) v0.2.0,
> vendored in this repository (you do not depend on it directly).
> The patch (`bitcoin-script/src/parse.rs`) teaches the `script!` macro the MATT
> opcodes `OP_CHECKTEMPLATEVERIFY` (0xb3), `OP_CHECKCONTRACTVERIFY` (0xbb), and
> `OP_CHECKSIGFROMSTACK` (0xcc),
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
carries its params as a typed value, so child instances recover their params
from the contract rather than from a parallel field.

## Defining a contract

A single `contract! { .. }` block generates the per-clause `*Args` structs, the
clause objects and taptree, a contract struct (`new` / `fund` / `track` /
`output` / `address` / `taptree_root` / `as_erased`), and a typed handle with **one spend method per
clause**. Params are any ordinary `Debug + Clone` struct (nothing to derive, any
field types); state is a struct deriving `ContractState`; the tapscripts stay as
reviewable functions the DSL references.

```rust
#[derive(Debug, Clone)]
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
                out_i: CcvIndex,                          // an output index, as CCV reads it
            }
            // fn(&VaultParams) -> ScriptBuf, or Result<ScriptBuf, ContractError>
            script Vault::trigger_script;
            // The body yields Result<T, ClauseError> where T is anything
            // Into<NextOutputs>: Vec<ClauseOutput>, CtvTemplate, or NextOutputs.
            next(p, a) { /* ... */ }
        }
        // ... more clauses ...
        tree [trigger, [trigger_and_revault, recover]];
    }
}
```

Besides the per-clause spend methods, each contract gets a small typed surface:

```rust
let vault = Vault::new(params)?;
let funded  = vault.fund(&mut manager, amount)?;       // create and track
let tracked = vault.track(&mut manager, outpoint)?;    // track an existing UTXO
let output  = unvaulting.output(0, UnvaultingState { ctv_hash });  // in a `next` body

// What a recorded spend revealed, decoded: no clause-name strings, no manual
// witness decoding.
match tracked.spent() {
    Some(VaultSpend::Trigger(args)) => println!("unvaulting to {:?}", args.ctv_hash),
    Some(VaultSpend::Recover(_)) => println!("recovered"),
    Some(VaultSpend::TriggerAndRevault(args)) => println!("revault at {:?}", args.revault_out_i),
    None => println!("unspent"),
}
```

Multi-field contract state commits with a derive instead of a manual impl:

```rust
#[derive(Debug, Clone, ContractState)]
#[commit(merkle)]                  // commitment() = Merkle root of the fields' leaves
pub struct G256S2State {
    pub t_a: [u8; 32],             // a raw 32-byte leaf
    #[leaf(sha256)] pub y: i64,    // leaf = sha256 of the field's witness encoding
    #[leaf(sha256)] pub x: i64,
}
```

## Spending: a clause is a typed method call

```rust
// A party's keys are registered once; every spend the manager executes is
// then signed without further ceremony.
manager.add_signer(HotSigner::new(unvault_key));

let vault = Vault::new(params)?.fund(&mut manager, amount)?;  // VaultHandle
// (augmented contracts take the initial state too: `.fund(&mut manager, amount, state)`)

// trigger: signed, exactly one child, returned typed
let unvaulting: UnvaultingHandle = vault.trigger(ctv_hash, 0).exec_one(&mut manager)?;

// withdraw: terminal CTV spend with explicit outputs
unvaulting
    .withdraw()
    .outputs(withdraw_outputs)
    .exec_none(&mut manager)?;
```

Signatures are never hand-built: a `#[signer]` field stays in the `*Args` struct
(so the struct alone is the witness layout), the generated `new()` omits it, and
the manager fills it by matching the clause's required pubkey to one of its
standing signers — or the spend fails with `MissingSigner`. `.sign(signer)` on
a builder supplies a signer for that one spend (it wins over a standing one),
and is what `build_tx()` uses, since building needs no manager.

A complete worked example (a two-stage vault) lives in `examples/vault/contracts.rs`.

`exec_one` and `exec_none` check the number of children before anything is
signed or broadcast. A childless spend is still constrained by what its clause
declares: see [the reference notes](docs/reference.md#childless-does-not-mean-unconstrained).

## Protocols: what each party does

A contract says what the chain allows; a *role* says what one party does at
each state, and a `Runner` plays it — sending the party's spends, following
the counterparty's, and firing timeout fallbacks:

```rust
let owner: Role<OwnerData, VaultOutcome> = Role::new()
    // My turn: send this spend and follow its child.
    .on::<Vault, _>(|d, vault, _cx| Ok(Action::Send(vault.trigger(d.ctv_hash, 0))))
    // Wait out the delay the `withdraw` clause declares, then withdraw.
    .on::<Unvaulting, _>(|d, unvaulting, _cx| {
        Action::wait_or((
            unvaulting.withdraw().outputs(d.outputs.clone()),
            VaultOutcome::Withdrawn,
        ))
    })
    // Somebody else ended it: say how, from the typed spend record.
    .on_settled::<Unvaulting, _>(|_d, _unvaulting, spend, _cx| {
        Ok(match spend {
            UnvaultingSpend::Withdraw(_) => VaultOutcome::Withdrawn,
            UnvaultingSpend::Recover(_) => VaultOutcome::Recovered,
        })
    });

let outcome = Runner::new(manager, owner, data, vault).run_one()?;
```

The same role runs against a node or the in-memory chain. Roles compose
(`Role::embed` mounts a whole sub-protocol, such as the fraud proof) and follow
spends that fork into several children. See
[Designing contracts](docs/README.md#protocols-and-roles), `examples/rps/` for a
complete two-party protocol, and `tests/support/vault_roles.rs` for the vault's.

## Chain backends and features

The manager and the protocol runner reach the chain through one trait,
`mattrs::chain::ChainView`:

```rust
// A Bitcoin Core node over RPC (the `rpc` feature, on by default).
let mut manager = ContractManager::new(client, Network::Regtest);

// The deterministic in-memory chain: no node, no scripts executed.
let chain = Rc::new(LocalChain::new());
let mut manager = ContractManager::on(chain.clone(), Network::Regtest);

// No chain at all: build, sign and observe only.
let mut manager = ContractManager::offline(Network::Regtest);
```

`fund`, `exec`, `track`, `wait_for_spend` and `mine_blocks` behave the same on
every backend, so a contract's tests can run its real spend path on a
`LocalChain` and reserve the node for consensus checks. Several managers on one
shared `Rc` are several parties on the same chain. A `Runner` uses its
manager's chain.

| Feature | Default | Adds |
|---|---|---|
| `rpc` | yes | `RpcChain`, `ContractManager::new`, `regtest_rpc_client` (pulls in `bitcoincore-rpc`) |
| `inspector` | no | the live JSON snapshot server |
| `test-util` | no | `mattrs::testutil`, `mattrs::report` |

## Examples

The examples from the Python reference framework (`pymatt`) are ported under
`examples/` (vault, rps) and `tests/support/` (ram, game256, minivault), with
pinned taptrees and spend-path tests. Tests assert
**byte-for-byte** compatibility where the Rust contract retains pymatt's exact
script layout:

| Example | Demonstrates | Status |
| --- | --- | --- |
| **vault** (`examples/vault/contracts.rs`) | two-stage vault; CCV + CTV; augmented state; multi-input trigger-with-revault | address pinned; regtest e2e; interactive REPL |
| **rps** (`examples/rps/contracts.rs`) | hashed state; clause-owned **CTV templates** for payouts; `check_in/out_contract` | roots match; regtest e2e; two-player demo |
| **ram** (`ram.rs`) | a Merkle-committed cell vector; the `WitProof<N>` witness arg; **expanded state** | root matches; `write` spends |
| **game256** (`game256.rs`) | the **bisection fraud proof** (`mattrs::fraud`) driven by the `G256S0/1/2` game stages | all taptrees match; full challenge regtest e2e |
| **minivault** (`minivault.rs`) | CCV-only vault with feature-toggled clauses: a **runtime-shaped taptree** via the `StandardClause`/`ClauseTree` escape hatch | all 4 feature combos regtest e2e |

## Demos

Both demos run against a regtest node with a funded `testwallet` (cookie auth
or `BITCOIN_RPC_*` env vars).

**Two-player RPS** (`examples/rps/`) plays a Rock-Paper-Scissors game between
two *separate processes*, negotiated over a TCP socket and played entirely
on-chain: Alice funds the game behind a hiding move commitment, Bob reveals his
move with a typed spend, and each side follows the other's turn with chain
observation. In two terminals:

```sh
cargo run --example rps -- --alice --rock
cargo run --example rps -- --bob --paper
```

Omit the move flag to be prompted for one; `--addr host:port` and
`--wallet name` override the defaults.

**Vault REPL** (`examples/vault/`) drives the two-stage vault interactively:
fund vaults, trigger several at once towards a CTV withdrawal template (with
the leftover revaulted in the same transaction), then `withdraw` after the
timelock — or `recover` to sweep to the recovery key at any time. Sample
scripts live in `examples/vault/scripts/`:

```sh
cargo run --example vault                                    # interactive
cargo run --example vault -- --script examples/vault/scripts/revault.txt
```

**Aggregate exits** (`examples/aggregate_exits/`) is an incomplete regtest
experiment: exact amount checks are missing, permitting over-withdrawal and
omitted bonds. It does not enforce pool safety (see the gaps in `SPEC.md`).
It demonstrates optimistic
aggregated withdrawals from a pooled UTXO (the protocol of
`examples/aggregate_exits/aggregate_exits.md`; concrete spec in `SPEC.md`):
direct Merkle-proof exits, plus an intermediary who withdraws a set of small
balances at once behind a bond and a challenge period, adjudicated by
delegation challenges (OP_CHECKSIGFROMSTACK) and a bisection fraud proof whose
settlements route the pot back into the covenant. One scenario per execution
path, against a MATT-enabled regtest node:

```sh
cargo run --example aggregate_exits                          # all scenarios
cargo run --example aggregate_exits -- --scenario fraud
```

**Live inspector** — the rps and vault demos take `--inspector` (or `--inspector-port <P>`)
when built with the `inspector` feature: the manager then serves a JSON snapshot
of every tracked instance over TCP on each state change, and the
`mattrs-inspector` workspace crate renders it as a live TUI (instance table +
detail pane). In two terminals:

```sh
cargo run --example vault --features inspector -- --inspector
cargo run -p mattrs-inspector       # or: nc localhost 34443
```

## Testing

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
cargo test --all-targets --all-features
```

The end-to-end tests are `#[ignore]`d by default because they need a
MATT-enabled regtest node. One command runs them against a throwaway one: it
starts the node on a temporary datadir, creates and funds `testwallet`, runs
the ignored tests, and stops the node again.

```sh
BITCOIND=/path/to/bitcoind scripts/regtest-tests.sh              # all of them
BITCOIND=/path/to/bitcoind scripts/regtest-tests.sh test_vault   # a subset
```

CI runs the same script in the `bigspider/bitcoin_matt` container.

To use a node you manage yourself instead, the tests need a
regtest `bitcoind` with a funded `testwallet` (cookie or env-var RPC auth; see
`tests/support/testkit.rs`). They also write markdown reports of every
transaction they broadcast (inputs, outputs, per-input witness breakdown with
sizes) to `reports/` — see `mattrs::report`.

Run the end-to-end tests serially so that they do not interfere with each
other's chain state:

```sh
cargo test --tests -- --ignored --test-threads=1
```

## Going further

- [Designing contracts](docs/README.md) — the conceptual model: clauses,
  merkleized state, protocols as finite state machines.
- [Reference notes](docs/reference.md) — state commitments, the rules the
  manager enforces on outputs, typed CCV arguments, batch observation, funding
  spends from an external wallet, the fraud-proof module, and the supporting
  infrastructure in the library.
- [Manager architecture](src/manager/README.md) — component boundaries and
  failure semantics.

[`ClauseTree`]: src/contracts/taptree.rs
