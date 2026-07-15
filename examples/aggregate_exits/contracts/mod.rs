//! Aggregate exits: optimistic aggregated withdrawals from a shared UTXO.
//!
//! Implements the protocol sketched in `../aggregate_exits.md` (see `../SPEC.md`
//! for the concrete specification). A pooled UTXO in its *unwind* phase commits
//! to a vector of `(pubkey, balance)` accounts as a Merkle root. Users may exit
//! directly with a Merkle proof, or — when individual balances are too small to
//! be worth a proof — delegate to an intermediary ("Ingrid") who withdraws their
//! aggregate balance optimistically:
//!
//! - [`Unwind`]: the pool. `withdraw_direct` pays one account and zeroes its
//!   leaf; `start_exit` posts Ingrid's claim (exit set S, aggregate X, new root
//!   R', a trace commitment) plus her bond, moving to [`PendingExit`].
//! - [`PendingExit`]: the claim under its challenge period. `finalize` (after
//!   the CSV delay) pays Ingrid X + bond and continues the pool at R'.
//!   `challenge_state` starts the bisection game on the claimed amount/root;
//!   `challenge_delegation` disputes one user's delegation.
//! - [`DelegationChallenge`]: Ingrid `defend`s by revealing the user's
//!   delegation signature (OP_CHECKSIGFROMSTACK), pocketing half the
//!   challenger's bond; or the challenger wins by timeout, reverting the
//!   withdrawal and slashing Ingrid.
//! - [`ExitBisect1`]/[`ExitBisect2`]/[`ExitLeaf`]: the bisection fraud proof on
//!   Ingrid's claimed `(R, 0) => (R', X)` computation, modeled on the generic
//!   `mattrs::fraud` module but with dynamic parties (their keys live in
//!   committed state, not params) and terminal clauses that route the pot back
//!   into the covenant: a failed challenge resumes [`PendingExit`], a proven
//!   fraud reverts to [`Unwind`], and the loser's bond is half-slashed,
//!   half-burned.
//! - [`ExitBond`]: a helper UTXO whose owner co-signs it into a claim or
//!   challenge transaction, so bonds join the pot via a batched spend.
//!
//! Every pool-chain clause is *permissionless*: reveals are data-bound to the
//! upfront trace commitments and every output is covenant-fixed, so no sighash
//! signature is needed anywhere in the chain. The only signatures are bond
//! owners spending their own money and the off-chain delegation signatures
//! verified with OP_CHECKSIGFROMSTACK.
//!
//! Exact output *amounts* (bonds, payouts, burns) cannot be enforced by script
//! today; every such check is marked `TODO(OP_AMOUNT)` and would be filled by
//! an opcode introspecting an output's amount.

pub mod bond;
pub mod delegation;
pub mod dispute;
pub mod fixture;
pub mod pending_exit;
pub mod unwind;

pub use bond::{ExitBond, ExitBondHandle, ExitBondParams};
pub use delegation::{DelegationChallenge, DelegationChallengeHandle, DelegationChallengeState};
pub use dispute::{
    BisectRangeParams, DisputeWinner, ExitBisect1, ExitBisect1Handle, ExitBisect1State,
    ExitBisect2, ExitBisect2Handle, ExitBisect2State, ExitLeaf, ExitLeafHandle, ExitLeafState,
    LeafStepParams, StepCase,
};
pub use pending_exit::{PendingExit, PendingExitHandle, PendingExitState};
pub use unwind::{Unwind, UnwindHandle, UnwindState};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::Message;
use bitcoin::XOnlyPublicKey;
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{ClauseError, WitnessError};
use mattrs::fraud::trace;
use mattrs::merkle::{ceil_lg, MerkleProof, MerkleTree, NIL};
use mattrs::script_utils::{bn2vch, commit_int};
use mattrs::ContractParams;

define_pushable!();

// ============================================================================
// Pool parameters
// ============================================================================

/// The pool's immutable parameters, shared by every contract in the chain.
#[derive(Debug, Clone, ContractParams)]
pub struct PoolParams {
    /// Identifies this pool in delegation messages (domain separation), e.g. a
    /// hash of the pool's genesis. Random in the demo.
    pub pool_id: [u8; 32],
    /// The number of user slots, fixed at pool creation (any size; the account
    /// tree is padded with NIL leaves to the next power of two).
    pub n_users: u32,
    /// Blocks Ingrid's claim must mature before `finalize` (CSV).
    pub challenge_period: u32,
    /// Blocks a party holding a turn (defend, reveal) has before forfaiting.
    pub response_timeout: u32,
    /// The bond posted with a claim or challenge, in sats. Until OP_AMOUNT
    /// exists this is documentation: scripts cannot verify it was posted.
    pub bond: i64,
}

impl PoolParams {
    /// The padded account-tree size: `n_users` rounded up to a power of two
    /// (minimum 2, so there is always a tree).
    pub fn padded_size(&self) -> usize {
        1usize << ceil_lg((self.n_users as usize).max(2))
    }

    /// The account/bit tree depth, `log2(padded_size)`.
    pub fn depth(&self) -> usize {
        ceil_lg(self.padded_size()) as usize
    }
}

// ============================================================================
// The pool's account tree (off-chain model)
// ============================================================================

/// The pool's full account vector — the logical state behind the [`Unwind`]
/// root. `None` slots are zeroed accounts (withdrawn) or padding.
#[derive(Debug, Clone)]
pub struct PoolTree {
    pub accounts: Vec<Option<(XOnlyPublicKey, i64)>>,
}

/// `sha256(pk || bn2vch(balance))`, the account leaf.
pub fn balance_leaf(pk: &XOnlyPublicKey, balance: i64) -> [u8; 32] {
    let mut preimage = pk.serialize().to_vec();
    preimage.extend(bn2vch(balance));
    sha256::Hash::hash(&preimage).to_byte_array()
}

/// `commit_int(0|1)`, the exit-set bit leaf.
pub fn bit_leaf(bit: bool) -> [u8; 32] {
    commit_int(bit as i64)
}

impl PoolTree {
    /// Build the pool over `accounts`, padding to `params.padded_size()`.
    pub fn new(params: &PoolParams, accounts: &[(XOnlyPublicKey, i64)]) -> Self {
        assert!(accounts.len() <= params.n_users as usize, "too many accounts");
        let mut slots: Vec<Option<(XOnlyPublicKey, i64)>> =
            accounts.iter().map(|a| Some(*a)).collect();
        slots.resize(params.padded_size(), None);
        Self { accounts: slots }
    }

    /// The account leaves (NIL for zeroed/padding slots).
    pub fn leaves(&self) -> Vec<[u8; 32]> {
        self.accounts
            .iter()
            .map(|slot| match slot {
                Some((pk, balance)) => balance_leaf(pk, *balance),
                None => NIL,
            })
            .collect()
    }

    /// The account Merkle tree.
    pub fn tree(&self) -> MerkleTree {
        MerkleTree::new(self.leaves())
    }

    /// The committed root.
    pub fn root(&self) -> [u8; 32] {
        self.tree().root()
    }

    /// A membership proof for slot `index`.
    pub fn prove(&self, index: usize) -> MerkleProof {
        self.tree()
            .prove_leaf(index)
            .expect("pool proof index is within the padded tree")
    }

    /// Zero slot `index` (a completed withdrawal).
    pub fn zero(&mut self, index: usize) {
        self.accounts[index] = None;
    }
}

/// The Merkle root of the exit-set bit tree for `bits` (padded length).
pub fn bit_root(bits: &[bool]) -> [u8; 32] {
    MerkleTree::new(bits.iter().map(|b| bit_leaf(*b)).collect()).root()
}

// ============================================================================
// Claims and traces
// ============================================================================

/// The step-state commitment `h = sha256(root || bn2vch(sum))`. With `sum = 0`
/// this degenerates to `sha256(root)` (`bn2vch(0)` is empty).
pub fn step_h(root: &[u8; 32], sum: i64) -> [u8; 32] {
    let mut preimage = root.to_vec();
    preimage.extend(bn2vch(sum));
    sha256::Hash::hash(&preimage).to_byte_array()
}

/// An aggregate-exit claim: the exit set, the claimed aggregate and post-exit
/// root, and the full step trace backing them. [`compute_claim`] produces the
/// honest one; a fraudulent claimant fabricates a self-consistent `hs` for a
/// lie (see [`compute_claim_with_lie`]).
#[derive(Debug, Clone)]
pub struct ExitClaim {
    /// The exit set, one bit per (padded) slot. Public: `start_exit` posts the
    /// bits on-chain and binds them to `s_root` in-script.
    pub bits: Vec<bool>,
    /// The pool root the claim starts from.
    pub r: [u8; 32],
    /// The claimed post-exit root.
    pub r_prime: [u8; 32],
    /// The claimed aggregate balance of the exit set.
    pub x: i64,
    /// The bit-tree root committing `bits`.
    pub s_root: [u8; 32],
    /// The claimed per-step roots `root_0 .. root_N` (`hs` preimages).
    pub roots: Vec<[u8; 32]>,
    /// The claimed per-step running sums `sum_0 .. sum_N` (`hs` preimages).
    pub sums: Vec<i64>,
    /// The N+1 step-state commitments `h_0 .. h_N`.
    pub hs: Vec<[u8; 32]>,
    /// The trace commitment `trace(hs, 0, N-1)`.
    pub trace: [u8; 32],
}

/// Run the N-step exit computation over `pool` honestly: step `u` zeroes leaf
/// `u` and adds its balance to the running sum iff `bits[u]` (a set bit on a
/// zeroed/padding slot contributes nothing and leaves the root unchanged).
pub fn compute_claim(pool: &PoolTree, bits: &[bool]) -> ExitClaim {
    compute_claim_with_lie(pool, bits, None)
}

/// Like [`compute_claim`], but if `lie` is `Some((step, delta))` the claimed
/// running sum is inflated by `delta` from step `step` on — a self-consistent
/// trace for a false aggregate, for exercising the fraud proof. The roots stay
/// honest (zeroing a leaf does not depend on the claimed balance), so the lie
/// is exactly one bad step.
pub fn compute_claim_with_lie(
    pool: &PoolTree,
    bits: &[bool],
    lie: Option<(usize, i64)>,
) -> ExitClaim {
    let n = pool.accounts.len();
    assert_eq!(bits.len(), n, "one bit per padded slot");

    let mut working = pool.clone();
    let mut sum: i64 = 0;
    let r = working.root();
    let mut roots = vec![r];
    let mut sums = vec![sum];
    let mut hs = Vec::with_capacity(n + 1);
    hs.push(step_h(&r, sum));
    for (u, bit) in bits.iter().enumerate() {
        if *bit {
            if let Some((_, balance)) = working.accounts[u] {
                sum += balance;
            }
            working.zero(u);
        }
        if let Some((step, delta)) = lie
            && u == step
        {
            sum += delta;
        }
        roots.push(working.root());
        sums.push(sum);
        hs.push(step_h(&working.root(), sum));
    }

    let trace = trace(&hs, 0, n - 1);
    ExitClaim {
        bits: bits.to_vec(),
        r,
        r_prime: working.root(),
        x: sum,
        s_root: bit_root(bits),
        roots,
        sums,
        hs,
        trace,
    }
}

/// A party's reveal arguments for bisection range `[i, j]`, derived from its
/// claimed `hs`: the midpoint commitment and the two half traces.
pub fn reveal_mids(hs: &[[u8; 32]], i: usize, j: usize) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let midpoint_offset = (j - i).div_ceil(2);
    (
        hs[i + midpoint_offset],
        trace(hs, i, i + midpoint_offset - 1),
        trace(hs, i + midpoint_offset, j),
    )
}

// ============================================================================
// Delegations
// ============================================================================

/// The message a user signs to delegate their exit to Ingrid:
/// `sha256(pool_id || ingrid_pk)`. The pool id gives domain separation; a
/// production protocol may also want to bind an expiry or a payout descriptor
/// (see "Non-custodial Ingrid" in the blueprint).
pub fn delegation_msg(pool_id: &[u8; 32], ingrid_pk: &XOnlyPublicKey) -> [u8; 32] {
    let mut preimage = pool_id.to_vec();
    preimage.extend(ingrid_pk.serialize());
    sha256::Hash::hash(&preimage).to_byte_array()
}

/// BIP340-sign the delegation message (verified in-script with
/// OP_CHECKSIGFROMSTACK by [`DelegationChallenge`]'s `defend`).
pub fn sign_delegation(
    keypair: &Keypair,
    pool_id: &[u8; 32],
    ingrid_pk: &XOnlyPublicKey,
) -> [u8; 64] {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(delegation_msg(pool_id, ingrid_pk));
    *secp.sign_schnorr(&msg, keypair).as_ref()
}

// ============================================================================
// The challenge carry: dispute-chain context
// ============================================================================

/// Everything a dispute (bisection or delegation challenge) must remember to
/// settle: the claim under dispute (to resume it), the revert root, the party
/// keys, and the taptrees of the contracts it re-enters.
///
/// The taptrees travel as *data* because they cannot be script constants: the
/// dispute contracts' scripts are referenced (hashed) by [`PendingExit`]'s
/// challenge clauses, so embedding PendingExit's taptree in them would be
/// circular. Instead the challenge clause verifies the witness-supplied
/// taptree against its own input via `CHECKCONTRACTVERIFY` and commits it
/// forward; `Unwind`'s taptree is bound the same way by `start_exit`.
///
/// The bisection states commit all seven fields as a single leaf, the *carry*
/// (`sha256` of their concatenation); terminal clauses re-expand it from the
/// witness.
#[derive(Debug, Clone)]
pub struct ChallengeContext {
    /// The full claim state being disputed (its hash resumes [`PendingExit`]).
    pub resume_state: PendingExitState,
    /// [`PendingExit`]'s taptree root.
    pub pe_taptree: [u8; 32],
    /// The challenger's payout key.
    pub challenger_pk: [u8; 32],
}

impl ChallengeContext {
    /// The seven carry components, in commitment order.
    pub fn carry_fields(&self) -> [[u8; 32]; 7] {
        [
            self.resume_state.ingrid_pk,
            self.challenger_pk,
            self.resume_state.s_root,
            self.resume_state.r,
            self.resume_state.hash(),
            self.pe_taptree,
            self.resume_state.unwind_taptree,
        ]
    }

    /// The carry leaf: `sha256` of the concatenated components.
    pub fn carry(&self) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(7 * 32);
        for field in self.carry_fields() {
            preimage.extend_from_slice(&field);
        }
        sha256::Hash::hash(&preimage).to_byte_array()
    }

    /// The carry components as witness elements.
    pub fn carry_witness(&self) -> Vec<Vec<u8>> {
        self.carry_fields().iter().map(|f| f.to_vec()).collect()
    }
}

/// The tracked-stack item names of the expanded carry, in witness order
/// (matching [`ChallengeContext::carry_fields`]). Scripts that consume an
/// expanded carry share this layout.
pub(crate) const CARRY_ITEMS: [&str; 7] = [
    "ingrid_pk",
    "challenger_pk",
    "s_root",
    "r",
    "resume",
    "pe_taptree",
    "unwind_taptree",
];

// ============================================================================
// Shared script fragments
// ============================================================================

/// One level of a shared-direction dual Merkle walk: advances two leaf→root
/// walks with the same in-tree position at once. Expects
/// `<a> <b> <sib_a> <sib_b> <direction>` on top; leaves `<a'> <b'>`.
/// `direction = 1` means the current nodes are right children.
pub(crate) fn dual_proof_layer() -> bitcoin::ScriptBuf {
    script! {
        OP_IF
            OP_TOALTSTACK
            OP_ROT OP_CAT OP_SHA256
            OP_SWAP OP_FROMALTSTACK OP_SWAP OP_CAT OP_SHA256
        OP_ELSE
            OP_TOALTSTACK
            OP_ROT OP_SWAP OP_CAT OP_SHA256
            OP_SWAP OP_FROMALTSTACK OP_CAT OP_SHA256
        OP_ENDIF
    }
}

// ============================================================================
// ArgSpec helpers
// ============================================================================

/// A named single-element bytes argument.
pub(crate) fn spec(name: &str) -> mattrs::contracts::ArgSpec {
    mattrs::contracts::ArgSpec {
        name: name.to_string(),
        arg_type: std::sync::Arc::new(mattrs::argtypes::BytesType),
    }
}

/// A named script-number argument.
pub(crate) fn spec_num(name: &str) -> mattrs::contracts::ArgSpec {
    mattrs::contracts::ArgSpec {
        name: name.to_string(),
        arg_type: std::sync::Arc::new(mattrs::argtypes::IntType),
    }
}
