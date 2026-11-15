# Manager architecture

`mattrs::manager` is the public entry point; its types are re-exported from
private modules. `ContractManager` owns the chain backend (a `ChainView`, or
none for an offline manager), the instance registry, the standing signers, the
network, and the optional inspector projection; its facade composes the
following components.

| Component | Responsibility | Side effects |
| --- | --- | --- |
| `transaction.rs` | Unsigned preparation, output derivation, child-count checks | None in the manager; no signer or RPC access |
| `signing.rs` | Fill witnesses using the final transaction and all prevouts | Invokes registered signers; no RPC or lifecycle mutation |
| `validation.rs` | Witness schemas, CTV, output identities, local and batch amount constraints | None |
| `observation.rs` | Authenticate witnesses, resolve metadata, validate complete input context | No RPC; delegates recording to lifecycle staging |
| `lifecycle.rs` | Register funding, stage children/links, commit validated batches | Registry and instance updates |
| `chain.rs` | Funding, mining, spend discovery and polling, through the `ChainView` backend | Chain I/O (node/wallet RPC on `RpcChain`, whose block scans live in `src/chain/rpc.rs`); delegates observation and registration |
| `wallet.rs` | External-wallet funding authorization and finalization | Explicit signing and observation phases; no wallet RPC |
| `inspection.rs` | Project and publish manager snapshots | Inspector server and notifications |

`builder.rs`, `handles.rs`, and `error.rs` contain the public intent/handle/error
types. Production modules import their dependencies explicitly; the preparation,
signing, and validation functions do not receive a manager or RPC client.
Contract metadata and signer implementations are application callbacks, so
these boundaries describe framework behavior, not a sandbox for callbacks.

## Execution and observation share recording

```text
ordinary execution: prepare → sign → validate/stage (dropped) → broadcast
                   → wait for a settled spend → validate/stage → commit
batch observation:                              validate/stage → commit
wallet workflow:   prepare → external funding → validate/sign → external signing
                   → application broadcast → final validation/stage → commit
```

`StagedBatch` privately owns candidate children and parent-link updates. Staging
checks the final signed witness, output constraints, and existing child registry
before any mutation. Ordinary execution stages once before submitting the
transaction, purely as a check: a registry conflict prevents broadcast, and the
staged changes are dropped either way. Broadcasting records nothing. When a
transaction spending the same inputs has the manager's confirmations, it is
staged and committed like any observed spend, whether or not it is the one
that was broadcast (`ManagerError::SpentByAnother` when it is not). `commit`
consumes the staged batch and returns children without a fallible validation
step. It also publishes the final inspector snapshot.

Keep staging and commit adjacent; do not expose staged updates to callers or
run user callbacks between staging and commit.
Network acceptance and local state cannot be a distributed atomic transaction:
an RPC error can be ambiguous after node acceptance. The manager leaves local
state unchanged on RPC errors; callers can reconcile through chain observation.

Execution and strict observation use
the same child deduplication, input-index resolution, join linking, and final
witness recording. `observe_spend` deliberately retains partial-input semantics:
it cannot establish aggregate accounting without the other inputs and may retry
a join after its defining input has been observed.

## Shared validation data

Batch amount checks consume borrowed `InputConstraints`, not `ObservedInput`
handles. Preparation/funding code can therefore validate the same accounting
rules without manufacturing lifecycle records. Wallet input value stays outside
CCV contribution accounting; all trusted prevouts still contribute to fee and
sighash computation. Model validation is not script execution or consensus
validation.

## Tests

`tests.rs` and `observation_tests.rs` retain the existing regressions;
`tests/architecture_tests.rs` covers the component and side-effect boundaries:
preparation/signing without a manager, dropped staging, pre-broadcast registry
conflicts, rejected broadcasts, and equivalent execution/observation results.
`tests/wallet_tests.rs` continues exercising the wallet workflow against the
shared validation and lifecycle components. Mock-RPC tests need permission to
bind a loopback socket, but do not require a Bitcoin node.
