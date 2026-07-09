# Designing contracts

MATT enables on-chain protocols in Bitcoin's UTXO model using covenant encumbrances. The UTXOs themselves carry the **state** of the contract, and state transitions happen by spending UTXOs and producing new ones -- with rules encoded in the UTXO itself.

This page documents the framework used across all the examples in this repository.

See [BIP-443](https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki) for the semantics of `OP_CHECKCONTRACTVERIFY`

## Contracts, programs, and clauses

The combination of a naked internal pubkey and a taptree constitutes the **program** of a contract. It encodes every possible spending condition.

Thanks to the semantics of `OP_CHECKCONTRACTVERIFY`, we can consider UTXOs as being *augmented* with some data, in the sense that they contain a cryptographic commitment to it.

All contracts in this framework can be thought as _augmented_ P2TR contracts. For stateless contracts, the embedded data is simply empty (`b""`), which leaves the internal pubkey unchanged.

A concrete UTXO whose `scriptPubKey` matches a program -- possibly with specified embedded data -- is a **contract instance**.

Each spending condition in the taptree is called a **clause**. A clause may also define state-transition rules by specifying the program and data of one or more outputs. The keypath spend (when the internal key is not a NUMS point) acts as an additional implicit clause with no covenant constraints on outputs.

## Merkleized data

While the embedded data slot is a single 32-byte value, it can represent arbitrarily complex state through commitments:

| State shape | Encoding |
|-------------|----------|
| Single 32-byte value | Stored directly |
| Single value of other size | SHA256 hash |
| Multiple values | Merkle tree root of the individual (hashed) values |

> **Note**: Other commitment schemes are possible. For example, hashing the concatenation of individual hashes is more efficient when all values must be revealed anyway. Care is needed -- not all hash-concatenation schemes are collision-resistant.

## Smart contracts as finite state machines

Because clauses can constrain the program and data of their outputs, UTXO-based protocols naturally form **finite state machines**: each node is a contract, and its clauses define transitions to other contracts.

For many protocols, spending a UTXO produces one or more pre-determined contracts as outputs, making the resulting diagram a **directed acyclic graph** (DAG). Some contracts may produce an output with the _same_ contract as the input -- creating a self-loop -- but cross-contract loops are impossible because they would require hash cycles.

Here is the state machine for the [vault](../examples/vault/) contract:

```mermaid
graph LR
    VAULT -->|recover| R["recovery<br>address"]
    VAULT -->|"trigger<br>(ctv_hash)"| UNVAULTING
    VAULT ---|"trigger_and_revault<br>(ctv_hash)"| X( )
    X --> VAULT
    X --> UNVAULTING
    style X display: none;

    UNVAULTING("UNVAULTING<br>[ctv_hash]")
    UNVAULTING -->|recover| R["recovery<br>address"]
    UNVAULTING -->|withdraw| D["ctv outputs<br>(possibly several)"]

    classDef contract stroke:#333,stroke-width:2px;
    class VAULT,UNVAULTING contract
```

> **Note**: This diagram represents a _single UTXO's_ possible states and transitions. Some protocols span multiple UTXOs that interact through shared transaction inputs.

## Protocols and roles

A contract's state machine defines what the chain *allows*; a **protocol** defines what each party *does* with it — which transaction to send when a state is reached, what to watch for, and when to fall back to a timeout path. In this framework that strategy layer lives in [`mattrs::protocol`](../src/protocol/mod.rs), separate from the contracts themselves (so one contract can be played by different strategies: honest party, watchtower, test adversary).

Each party is declared as a **role**: a table mapping contract types to handlers. When the protocol's live UTXO (its *token*) arrives at a state, the party's handler decides an **action**:

| Action | Meaning |
|--------|---------|
| `Send(spend)` | My turn: broadcast this spend and follow its child |
| `SendFinal(spend, outcome)` | My terminal spend; the protocol resolves |
| `Wait` | Counterparty's turn: watch the UTXO for its spend |
| `WaitWithTimeout{blocks, fallback}` | Watch, but act (e.g. `forfait`) once the UTXO sits unspent for `blocks` |
| `Finish(outcome)` | Resolved with no transaction from us |

A separate `on_settled` handler classifies *terminal* spends made by the counterparty (e.g. a CTV payout) into the protocol's outcome type.

A **runner** drives a role from an entry instance to its outcome: it dispatches handlers, builds and broadcasts the spends they return, follows the counterparty by observing the chain, and fires timeout fallbacks. All chain I/O goes through one seam (`ChainView`), so the same roles run unchanged against a real node (`RpcChain`) or the deterministic in-memory chain used by offline tests (`LocalChain`), where timeout paths are exercised by mining explicitly.

**Protocols compose.** A whole protocol — its contracts, roles, and outcome type — is a reusable component: `Role::embed` mounts a sub-protocol's role inside a larger protocol's, mapping its outcomes into the outer outcome type. The embedder never handles the sub-protocol's internal states. The bisection fraud proof ([`mattrs::fraud::roles`](../src/fraud/roles.rs)) ships this way: the game256 protocol ([`tests/support/game256_roles.rs`](../tests/support/game256_roles.rs)) hands off on-chain with `Bisect1::state_output_script` / `entry_output` and mounts `fraud::roles::{alice,bob}_role` — the whole dispute below `start_challenge` runs without the game code naming a single bisection state.

**Protocols fork.** A clause can produce several covenant children — the vault's `trigger_and_revault` splits off a revaulted `Vault` next to the `Unvaulting` — and the runner then follows each child as its own token, with its own turn-taking and timeout deadline, resolving one outcome per token (`run()` returns them all; `outcomes()` peeks at partial results mid-run). Every child of a spend must be either handled or explicitly `ignore`d by the role: an unexpected contract is a loud error, never a silently orphaned branch. The vault roles ([`tests/support/vault_roles.rs`](../tests/support/vault_roles.rs)) drive this — an owner withdrawing both branches of a split, and a keyless watchtower sweeping unsanctioned unvaultings while its other tokens keep watching.

A complete two-party example is the RPS demo ([`examples/rps/`](../examples/rps/)): the roles live next to the contracts, the demo drives them over RPC, and the offline tests replay the very same roles over a `LocalChain`.

> **Scope**: each action spends a single token's UTXO; transactions batching several tokens as inputs are a future extension of the runner.

## Notation

We represent a contract as:

```
ContractName{params}[vars]
```

where:
- **ContractName** (CamelCase) is the contract's name
- **params** are compile-time parameters, hardcoded in the Script
- **vars** are state variables, stored in the UTXO's data commitment

Both `params` and `vars` are omitted when empty. Global parameters (shared across all contracts in a protocol) are listed separately for brevity.

### Terminology

| Term | Meaning |
|------|---------|
| _Parameters_ | Fixed at contract creation time, baked into the Script |
| _Variables_ | State stored in the UTXO, accessible via `OP_CHECKCONTRACTVERIFY` |
| _Arguments_ | Passed by the spender in the witness at spend time |

### Clause transitions

A clause that produces a single output:

```
clause_name(args) => out_i: Contract{params}[vars]
```

A clause that produces multiple outputs:

```
clause_name(args) => [
    out1_i: Contract1{params1}[vars1],
    out2_i: Contract2{params2}[vars2]
]
```

`out_i` is the index of the output that must match the contract. When omitted (allowed for at most one output), it defaults to the current input's index.

The destination contract's `params` can only depend on the current contract's `params`. The destination `vars` can depend on `params`, `vars`, and the clause's `args`.

A clause with no `=>` output specification has no covenant constraints -- it is an unconditional spend.

## Example: Vault

Using the notation above, we can model the vault's state machine:

```
global unvault_pk    -- public key that can trigger a withdrawal
global recover_pk    -- public key for the recovery address
global spend_delay   -- blocks to wait before final withdrawal


Vault:
  trigger(ctv_hash, out_i) => [out_i: Unvaulting[ctv_hash]]:
    checksig(unvault_pk)

  trigger_and_revault(ctv_hash, revault_out_i, trigger_out_i) => [
    deduct revault_out_i: Vault,
    trigger_out_i: Unvaulting[ctv_hash]
  ]:
    checksig(unvault_pk)

  recover => P2TR{recover_pk}:
    pass


Unvaulting[ctv_hash]:
  withdraw:
    older(spend_delay)
    ctv(ctv_hash)

  recover => P2TR{recover_pk}:
    pass
```

A matching Rust implementation can be found in [`examples/vault/contracts.rs`](../examples/vault/contracts.rs).
