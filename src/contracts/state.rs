//! Contract params, state, and the data commitment a state contributes to its UTXO.

use std::fmt::Debug;

use super::WitnessError;
use bitcoin::{hashes::Hash, hashes::sha256};

/// Contract parameters: the per-instance configuration a contract's scripts
/// are built from.
///
/// Params are held as a plain Rust value and never serialized, so any
/// `Debug + Clone + Send + Sync` type qualifies automatically — there is
/// nothing to derive or implement.
pub trait ContractParams: Debug + Clone + Send + Sync {}

impl<T: Debug + Clone + Send + Sync> ContractParams for T {}

/// The exact CCV data operand, distinct from a logical state's serialization.
///
/// Bytes are never implicitly hashed based on their length. Empty data omits
/// the state tweak; nonempty data is incorporated as `SHA256(naked_key || data)`.
/// These are the data semantics of
/// [BIP-443](https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki).
/// The script must supply these same bytes to CCV. A commitment need not be
/// invertible; instances retain their expanded logical state separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateCommitment(Vec<u8>);

impl StateCommitment {
    /// The empty commitment: no data tweak. This is what a stateless contract
    /// (state type `()`) commits to.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Whether this is the empty commitment (no data tweak).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Commit to these bytes verbatim, including an already-computed hash/root.
    /// Empty bytes explicitly mean no data tweak. Script element-size limits
    /// still apply to data supplied to CCV.
    pub fn identity(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Explicitly hash a preimage, regardless of its length (including 32 bytes).
    pub fn sha256(preimage: &[u8]) -> Self {
        Self(sha256::Hash::hash(preimage).to_byte_array().to_vec())
    }

    /// The exact bytes passed to CCV and used for addressing.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Take ownership of the exact commitment bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for StateCommitment {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Expanded logical contract state and its explicit on-chain commitment.
///
/// Serialization, when needed, belongs to [`StateCodec`] or an application
/// codec. It is never used implicitly for addressing or state recovery.
///
/// ```
/// use mattrs::contracts::{ContractState, StateCodec};
/// #[derive(Debug, Clone, mattrs::ContractState)]
/// #[commit(sha256)]
/// struct Counter { value: i64 }
/// let state = Counter { value: 7 };
/// assert_eq!(state.encode(), vec![7]);
/// assert_eq!(state.commitment().as_bytes().len(), 32);
/// assert_eq!(Counter::decode(&state.encode()).unwrap().value, 7);
/// ```
///
/// Omitting the commitment strategy is a compile-time error:
/// ```compile_fail
/// #[derive(Debug, Clone, mattrs::ContractState)]
/// struct Ambiguous { bytes: Vec<u8> }
/// ```
pub trait ContractState: Debug + Clone + Send + Sync {
    /// Compute the exact data operand the contract's script supplies to CCV.
    fn commitment(&self) -> StateCommitment;
}

/// Optional, lossless serialization of logical state. Not a consensus format.
///
/// `decode(encode(state))` should recover the logical state. Merkle-root-only
/// states need not implement this trait: a root is not a serialization of its
/// leaves. The manager never calls this codec to recover state from a commitment.
///
/// A Merkle-root commitment does not generate a codec for its leaves:
/// ```compile_fail
/// use mattrs::StateCodec;
/// #[derive(Debug, Clone, mattrs::ContractState)]
/// #[commit(merkle)]
/// struct Leaves { first: [u8; 32] }
/// let serialized = Leaves { first: [0; 32] }.encode();
/// ```
pub trait StateCodec: ContractState {
    /// Serialize the full logical state, independently of its commitment.
    fn encode(&self) -> Vec<u8>;

    /// Recover logical state from its serialization, not from a commitment.
    fn decode(bytes: &[u8]) -> Result<Self, WitnessError>
    where
        Self: Sized;
}

impl ContractState for () {
    fn commitment(&self) -> StateCommitment {
        StateCommitment::empty()
    }
}

impl StateCodec for () {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.is_empty() {
            Ok(())
        } else {
            Err(WitnessError::Invalid(
                "stateless contract has trailing data".to_string(),
            ))
        }
    }
}

/// Type-erased *logical* contract state carried on an instance.
///
/// A contract's on-chain commitment is [`ContractState::commitment`], but its
/// *logical* state can be richer than that
/// commitment — e.g. a RAM cell vector committed only as a Merkle root. Since the
/// commitment is generally not invertible, an instance keeps the full typed state
/// here (in erased form) so a clause's `next_outputs` can read it.
/// `as_any` recovers the concrete `ContractState`; commitments are never decoded.
pub trait ErasedState: Debug + Send + Sync {
    /// The explicit CCV data commitment of the logical state.
    fn state_commitment(&self) -> StateCommitment;

    /// Downcast handle to the concrete state type.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Clone into a box.
    fn clone_boxed(&self) -> Box<dyn ErasedState>;
}

impl<S: ContractState + 'static> ErasedState for S {
    fn state_commitment(&self) -> StateCommitment {
        <Self as ContractState>::commitment(self)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_boxed(&self) -> Box<dyn ErasedState> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn ErasedState> {
    fn clone(&self) -> Self {
        self.clone_boxed()
    }
}
