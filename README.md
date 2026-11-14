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
bitcoin-script = { path = "../mattrs/bitcoin-script" }   # patched vendor, see below
```

Then run the offline example — it defines a two-clause contract with the
`contract!` DSL, derives its address, then funds and spends it on an in-memory
chain, without a node:

```sh
cargo run --example getting_started
```

> **Note on `bitcoin-script/`**: this repository vendors a *patched* copy of
> [BitVM/rust-bitcoin-script](https://github.com/BitVM/rust-bitcoin-script) v0.2.0.
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
                out_i: i64,
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
    Some(VaultSpend::TriggerAndRevault(args)) => println!("revault at {}", args.revault_out_i),
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

### State commitments and serialization

Every `ContractState` explicitly implements `commitment() -> StateCommitment`.
This is the exact data operand supplied to CCV, not a serialization to decode.
The derive requires a commitment strategy:

- `#[commit(identity)]`: commit a single field's witness element verbatim.
- `#[commit(sha256)]`: hash that element, regardless of its length.
- `#[commit(merkle)]`: commit the Merkle root of the declared leaves.

The first two also implement `StateCodec` for lossless `encode`/`decode` of the
single field. Merkle states and `opaque_merkle_state!` do not pretend their roots
can be decoded; implement an application codec separately if persistence is
needed. Instances retain expanded logical state, and `handle.state::<S>()`
only returns it when its type matches — there is no commitment-decoding fallback.

For manual implementations, use `StateCommitment::identity(bytes)` for raw data
or an existing hash/root, and `StateCommitment::sha256(preimage)` to explicitly
hash a preimage. No length-dependent hashing takes place during addressing.
Empty commitment bytes omit the data tweak; they are not SHA256 of empty data.
Type-erased `script_pubkey` and `control_block_internal_key` take a
`&StateCommitment`; pass `&state.commitment()`, not `state.encode()`.

Every contract has a state type. A stateless contract is one whose state is the
unit type `()`, whose commitment is empty; a `state <Type>;` section names a
real one. An instance therefore always holds a state of its contract's type
(checked when the instance is created), so a typed handle's `state()` returns
it directly and a clause's `next(p, a, s)` receives `s: &State`.

Choose the strategy to match what the script does: a 32-byte value the script
re-reveals verbatim is `identity`; a value the script hashes first is `sha256`
(tic-tac-toe commits the hash of its 10-byte serialization this way). An
augmented contract with unit state `()` has an empty commitment, hence no data
tweak.

## Spending: a clause is a typed method call

```rust
// A party's keys are registered once; every spend the manager executes is
// then signed without further ceremony.
manager.add_signer(HotSigner::new(unvault_key));

let vault = Vault::new(params)?.fund(&mut manager, amount)?;  // VaultHandle
// (augmented contracts take the initial state too: `.fund(&mut manager, amount, state)`)

// trigger: signed, exactly one child, returned typed
let unvaulting: UnvaultingHandle = vault
    .trigger(ctv_hash, 0)
    .exec_one(&mut manager)?
    .try_into()?;

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

Contract-wide checks can run before any keys or nested scripts are built:
`validate |p| mattrs::BlockDelay::new(p.spend_delay).map(|_| ());`.
The validator returns `Result<(), ContractError>` and receives `&params`
(and `&ctx` if declared), like script builders. Use it for constraints shared
with child contracts so invalid configuration returns an error at the entry
constructor. The `timelock` section validates its own block delay automatically.

Every builder section (`script`, `timelock`, `args raw`, `internal_key`, and a
computed `tree`) may return either its value or `Result<_, ContractError>`. A
script that embeds a child contract's taptree root therefore propagates the
child's construction error with `?` instead of panicking:

```rust
fn trigger_script(p: &VaultParams) -> Result<ScriptBuf, ContractError> {
    let unvaulting = Unvaulting::new(Self::unvaulting_params(p))?;
    Ok(script! { /* ... */ { unvaulting.taptree_root().to_vec() } /* ... */ })
}
```

For hand-written scripts, `BlockDelay::new(blocks)?.script()` supplies a checked
block delay; `older(u32)` remains the low-level helper for raw sequence operands.

`exec_one` and `exec_none` resolve outputs and check child counts before asking
for signatures. A successful execution signs once and records the actual
broadcast witness, including filled signature arguments.

### Childless does not mean unconstrained

`exec_none` asserts that a spend creates no *tracked contract instances*, not
that its transaction outputs are unrestricted. Declare CTV constraints in `next`
even for a terminal withdrawal:

- `NextOutputs::Template(CtvTemplate)` supplies the exact outputs and sequence.
- `NextOutputs::TemplateHash([u8; 32])` supplies only the commitment. The caller
  provides `.outputs(...)` and, if needed, `.sequence(...)`; the manager checks
  the resulting transaction against the hash before signing.

Both forms create no children and use the same commitment check when observing
a spend. The vault's `Unvaulting::withdraw` demonstrates a hash committed in
state. A wrong payment, sequence, or revealed state hash fails locally.
Construction supports single-input CTV transactions with version 2 and locktime
0; `compute_ctv_hash_for_tx` also hashes general transactions for observation.

A clause output goes either to a contract — `child.output(index, state)` (or
`child.output(index)` for a stateless one), generated per contract so the state
type is checked at compile time, and tracked as a child — or to an exact script — `ClauseOutput::at(index).pay(script_pubkey)`,
constrained the same way but not tracked. One clause may return both, e.g. a
payout next to the continuing contract (`ClauseOutput::pay_key` and
`ClauseOutput::burn` are shorthands for bare-key and unspendable payouts). A
payment preserves the input's residual amount by default; deduct and ignore
modes use the same accounting rules as contract outputs, including requiring
`.output_amount(index, amount)` when building them. The metadata must match the
clause's script checks.

The vault's two recovery clauses declare these payments, so
`vault.recover(0).exec_none(&mut manager)?` derives the recovery output without
the caller repeating its script or amount. Explicit `.outputs(...)` still works
for single-input payment spends, but the supplied outputs must satisfy the
declared destinations and amount constraints. Recovery calls with index `-1`
use the spending input's index, matching CCV's same-index convention.

Payment-only spends can aggregate into one output or pay distinct indices in a
batch. They can also share a transaction with tracked contract outputs at other
indices. The builder rejects mixing tracked and untracked destinations at the
same index, and `Join` still requires a tracked child target.

Omitting `next` (or returning `ClauseOutput::terminal()`) declares **no host-side
output checks**. It does not make a script unconstrained. Output metadata does
not generate script checks, and observation is not full consensus/script
validation. Use a validating node to establish consensus validity of external
transactions.

### Typed CCV script arguments

Use `mattrs::ccv` with `StackScript::ccv` to spell out each operand's meaning:

```rust
use mattrs::ccv::{CcvData, CcvIndex, CcvKey, CcvMode, CcvTaptree};
use mattrs::stack::StackScript;

let mut script = StackScript::with_witness(&["state"]);
script.ccv(
    CcvData::Item("state"),
    CcvIndex::CURRENT,
    CcvKey::Nums,
    CcvTaptree::Current,
    CcvMode::CheckInput,
);
let script = script.into_script();
```

`CcvIndex::at(n)?` validates an explicit index's Script-number range;
`CcvIndex::try_from(n)?` also accepts the current-input sentinel `-1`.
`CcvMode::{CheckInput, Preserve, IgnoreAmount, DeductAmount}` are alternatives,
not bit flags. `CcvMode::try_from(n)?` rejects undefined modes, which would
otherwise bypass input validation under
[BIP-443](https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki).

`CcvData::Empty`, `CcvKey::Nums`, and `CcvTaptree::None` are the respective
empty operands. The key sentinel is `CcvKey::CurrentInternalKey`: it reuses the
current **internal** key, not the untweaked naked key. Constant keys use `XOnlyPublicKey`; constant data may be
32 bytes (`Const`) or arbitrary pushed bytes (`Bytes`), passed without hashing.
Named stack items still require script-side validation. These types do not
generate or validate the clause's host-side `next` metadata.

The shared `check_input_contract`, `check_output_contract`, and bisection
`state_output_script` helpers also take `CcvIndex`. For intentionally
unchecked operands, use `StackScript::ccv_raw` with `RawCcvSource`, or raw
`script!` assembly (interpolate `CcvMode::DeductAmount.as_i32()` and friends;
modes are alternatives, never flags to combine).

Host-side `next` metadata uses the same vocabulary: an output's index is a
`CcvIndex` (`ClauseOutput::at(0)`, or `CcvIndex::try_from(a.out_i)?` for a
witness-supplied script number, where `-1` means the input's own index) and
its amount rule is an `AmountMode`.

### Observing a whole batch

The manager keeps preparation, signing, constraint validation, chain I/O, and
lifecycle updates in separate internal components while preserving the public
API. Ordinary execution and strict batch observation share validated, staged
child/link updates: execution checks them before broadcast and commits only
after broadcast succeeds. See the [manager architecture guide](src/manager/README.md)
for component boundaries and failure semantics.

`manager.observe_batch(&[&first, &second], &tx)?` checks all supplied input
contexts together before recording any spend or registering any child. Supply
one handle for **every** transaction input, in any order. It rejects missing or
duplicate contexts, combined preserve underpayments, cross-input deduct
conflicts, incompatible child identities, and unfunded join contributions.
Children are returned once, in output-index order; joins link in the same call.

`wait_for_batch(&[&first, &second])?` discovers the spending transaction through
the node and performs that same strict observation. The offline `apply_batch`
test helper calls `observe_batch` directly, without the node lookup.

`observe_spend` and `wait_for_spend` remain useful for partial views, but only
check individual inputs. Two independent lower-bound checks are not equivalent
to checking a combined contribution. For ordinary wallet/fee inputs, use
`observe_batch_with_external_inputs(&handles, &external_inputs, &tx)` instead.
Supply an `ExternalInput { outpoint, prevout }` from a trusted source for each
wallet input. Contexts are matched by outpoint, not by their order in the list.
The result contains deduplicated `children` and the transaction's absolute `fee`.
Wallet value pays fees/change but never increases a contract's CCV contribution.
Native P2WPKH and Taproot key-path spends (including annexes) are supported;
external tapscripts, legacy inputs, and unknown input contexts are rejected.
`wait_for_batch_with_external_inputs` accepts a caller-supplied prevout resolver;
use funding transactions or a trusted cache, since the outputs are already spent
and may no longer be available through `gettxout`. Neither observation API
executes arbitrary scripts or verifies signatures; declared metadata must match
the script. Re-observing a transaction authenticates its witness again, even
when its transaction ID and children were cached.

### Funding contract spends with an external wallet

`prepare_wallet_spend(builders)` produces an unsigned transaction and the
contract input weights needed by a wallet. Register contract signers on those
builders, leaving signature arguments empty; preparation never invokes them.

1. Let the wallet fund `prepared.transaction()`, appending fee inputs and change.
2. Resolve the added inputs' prevouts from a trusted wallet/node.
3. Call `prepared.sign_funded(&manager, funded_tx, external_inputs, maximum_fee)`.
   This validates the funded transaction, its fee, and all required signers
   before generating default-sighash contract signatures against **all** prevouts.
4. Let the wallet sign its own inputs, then call `signed.validate_final(&tx)`
   before broadcasting. Only external witnesses may change at this stage.
5. After node acceptance, call `signed.observe_final(&mut manager, &tx)` to record
   the final transaction atomically. Preparation/signing never marks parents spent.

Existing inputs, sequences, outputs, version, and locktime must stay unchanged.
No automatic input/output remapping, fee subtraction from contract outputs,
PSBT transport, or coin selection is imposed by the library. CTV is rechecked:
an exact template may prohibit adding fee inputs or change. Fee bumps require a
fresh authorized transaction and fresh signatures; there is no implicit switch
to `ANYONECANPAY`. Applications remain responsible for wallet coin locking,
change ownership, authenticating prevouts, and node acceptance/confirmation policy.

See [`examples/wallet_funding.rs`](examples/wallet_funding.rs) for a complete
Bitcoin Core `fundrawtransaction` / `signrawtransactionwithwallet` adapter and a
separate passive observer. Run `cargo run --example wallet_funding` against a
CCV-enabled regtest node with a funded `testwallet` (broadcasts and mines blocks).
It passes contract weights via `input_weights` and appends change via
`changePosition`, following the [Core funding RPC documentation](https://bitcoincore.org/en/doc/30.0.0/rpc/rawtransactions/fundrawtransaction/).
The separation of contract contributions and fee funding follows
[BIP-443](https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki);
the native Taproot witness classification follows
[BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).

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
    Arc::new(move |_i| Leaf::new(LeafParams { alice_pk, bob_pk }, compute2x.clone()));
let params = BisectParams::new(alice_pk, bob_pk, 0, 7)?;
let context = BisectCtx::new(leaf_factory, /* forfait_timeout = */ 10)?;
let challenge = Bisect1::new(params, context)?;
```

`tests/support/game256.rs` instantiates it for the game256 example in ~30 lines.

## Ported examples

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

Supporting MATT infrastructure lives in the library for downstream reuse: the
generic fraud-proof contracts (`mattrs::fraud`), a data `MerkleTree` /
`MerkleProof` / `WitProof` / `MerkleProofType` (`mattrs::merkle`), a symbolic
stack tracker for assembling tapscripts against *named* witness elements
instead of hand-counted `OP_PICK` depths (`mattrs::stack`), the
`merkle_root(n)` / `dup(n)` / `drop(n)` / `check_input_contract` /
`check_output_contract` / `older` / `timeout_sig_script` / `opaque_p2tr` script
fragments (`mattrs::script_helpers`), `commit_int` (`mattrs::script_utils`),
bare-key payout and burn outputs (the `ClauseOutput::pay_key` /
`ClauseOutput::burn` constructors), a `WitnessReader`
for parsing raw-args witnesses sequentially, the `opaque_merkle_state!` macro
for expanded states committed as a Merkle root, and `local_manager()` /
`apply_batch(..)` for funding and applying spends without a node
(`mattrs::testutil`, behind the `test-util` feature; used by the examples and
fixtures, together with
`ContractManager::offline(network)`).

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

## Spend-API features

- **CTV templates as clause outputs** — a clause's `next` may return a
  `CtvTemplate`, which fixes the transaction outputs and `nSequence` (see rps).
- **Multi-input batch spends** — `ContractManager::spend_batch(..)` merges several
  instances' outputs by index (pymatt's `get_spend_tx` semantics).
- **Join contributions** — a clause's `next` may return
  `NextOutputs::Join { index }`: the input's whole amount joins an output
  *another* input's clause defines (the aggregate-exits bond stakes itself into
  a pot with nothing but a signature).
- **Declared timelocks** — a clause's `timelock |p| ..;` section prepends the
  CSV `older()` fragment to its script *and* seeds the spend's `nSequence`, so
  both use the same validated delay (1 through 65,535 blocks). Sequence
  overrides are checked against the declared delay before signing.
- **Typed handles** — spends return `Children` (`.at::<H>(vout)?` / `.one()`),
  and a handle's `params()` / `state()` read the typed values directly.
- **Expanded state** — an instance can carry logical state richer than its on-chain
  commitment (e.g. RAM's cells vs their Merkle root), recovered by `next_outputs`.
- **Chain observation** — follow a covenant driven by someone else:
  `track_instance(..)` registers an externally funded instance, and
  `wait_for_spend(..)` (mempool + block scan; or the RPC-free
  `observe_spend(..)`) decodes the spending witness back into the clause and its
  typed arguments and materializes the child instances
  (see `tests/test_observe.rs`).

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

[`ClauseTree`]: src/contracts.rs
