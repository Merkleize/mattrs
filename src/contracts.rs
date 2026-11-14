//! Core contract model: typed clauses, taproot trees, and contract templates.
//!
//! The types here layer as follows:
//!
//! - **Witness encoding** — [`WitnessEncodable`] turns values into script-facing
//!   witness-stack elements; a clause's [`ClauseArgs`] and a state's
//!   [`ContractState`] leaves use it (so their bytes are exactly what the covenant
//!   reads). Contracts declare these per-role encodings via the derive macros.
//!   [`ContractParams`] are never serialized: a contract holds its params as a
//!   plain Rust value, so they may be of any type. [`ErasedState`] carries a
//!   *logical* state on an instance even when its on-chain commitment is lossy
//!   (e.g. a Merkle root).
//! - **Clauses** — a [`StandardClause`] is one tapscript spending path: a name,
//!   a script, [`ArgSpec`]s describing its witness layout, and an optional
//!   function computing the [`NextOutputs`] it produces when spent (covenant
//!   [`ClauseOutput`]s or a fixed [`CtvTemplate`]). [`ErasedClause`] is its
//!   type-erased view for runtime dispatch.
//! - **Trees** — a [`ClauseTree`] arranges clauses into the taproot tree shape;
//!   the address-bearing script [`TapTree`], the spend-time clause lookup, and
//!   the witness layout are all *derived* from it, so they cannot drift apart.
//! - **Contracts** — a [`StandardP2TR`] wraps a clause tree plus its params;
//!   its internal key is tweaked with each instance's state commitment (empty,
//!   hence no tweak, for a stateless contract). [`ErasedContract`] is its
//!   type-erased view.
//! - **Instances** — a [`ContractInstance`] is one UTXO of a contract: funded
//!   from creation, and later carrying the [`SpendRecord`] of the transaction
//!   that consumed it (driven by the
//!   [`ContractManager`](crate::manager::ContractManager)).

use std::{cell::RefCell, fmt, fmt::Debug, marker::PhantomData, rc::Rc, sync::Arc};

pub use crate::ccv::{AmountMode, CcvIndex};

use bitcoin::{
    OutPoint, ScriptBuf, Sequence, TapTweakHash, Transaction, TxOut, Txid, XOnlyPublicKey,
    hashes::{Hash, sha256},
    key::Secp256k1,
    taproot::{LeafVersion, TapLeafHash, TapNodeHash},
};

// ============================================================================
// Error Types
// ============================================================================

/// Errors from encoding/decoding values to and from the witness stack.
#[derive(Debug)]
pub enum WitnessError {
    /// The witness stack (or a value's bytes) ended before a complete value
    /// could be decoded.
    Missing,
    /// The data is there but is not a valid encoding of the expected type
    /// (wrong length, a non-minimal integer, an out-of-range value, ...).
    Invalid(String),
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WitnessError::Missing => write!(f, "the witness ends before the value does"),
            WitnessError::Invalid(msg) => write!(f, "invalid witness data: {}", msg),
        }
    }
}

impl std::error::Error for WitnessError {}

/// Errors from executing a clause (computing its next outputs).
#[derive(Debug)]
#[non_exhaustive]
pub enum ClauseError {
    /// The spend's witness stack could not be decoded into the clause's arguments.
    Witness(WitnessError),
    /// Constructing a child contract exposed an invalid contract definition.
    Contract(ContractError),
    /// Any other clause-specific failure.
    Other(String),
}

impl fmt::Display for ClauseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClauseError::Witness(e) => write!(f, "Witness error: {}", e),
            ClauseError::Contract(e) => write!(f, "Contract error: {}", e),
            ClauseError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ClauseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClauseError::Witness(e) => Some(e),
            ClauseError::Contract(e) => Some(e),
            ClauseError::Other(_) => None,
        }
    }
}

impl ClauseError {
    /// An [`Other`](ClauseError::Other) failure, from anything printable: the
    /// way a `next` block rejects arguments its script would reject.
    pub fn other(message: impl fmt::Display) -> Self {
        ClauseError::Other(message.to_string())
    }
}

impl From<WitnessError> for ClauseError {
    fn from(e: WitnessError) -> Self {
        ClauseError::Witness(e)
    }
}

impl From<crate::ccv::InvalidCcvIndex> for ClauseError {
    fn from(e: crate::ccv::InvalidCcvIndex) -> Self {
        ClauseError::Other(e.to_string())
    }
}

impl From<ContractError> for ClauseError {
    fn from(e: ContractError) -> Self {
        ClauseError::Contract(e)
    }
}

/// Errors from contract address / key-derivation operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum ContractError {
    /// A block-based CSV delay is outside 1..=65,535.
    InvalidBlockDelay { blocks: u32 },
    /// The logical state has a different concrete type from the contract's
    /// declared state type (`()` for a stateless contract).
    WrongStateType,
    /// A clause was executed against params of a different concrete type from
    /// the one its contract was built with.
    WrongParamsType,
    /// An instance was placed at an output its funding transaction does not
    /// have.
    MissingFundingOutput(OutPoint),
    /// Failed to decode the contract state.
    StateDecoding(WitnessError),
    /// A taproot / secp256k1 key operation failed (tweak, parse, ...).
    Key(String),
    /// Two clauses in one contract have the same lookup name.
    DuplicateClauseName(String),
    /// Two clauses in one contract have the same tapscript and cannot be
    /// distinguished when observing a spend.
    DuplicateClauseScript {
        /// The first clause with this script.
        first: String,
        /// The second clause with this script.
        second: String,
    },
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::InvalidBlockDelay { blocks } => {
                write!(
                    f,
                    "CSV block delay must be between 1 and 65535, got {blocks}"
                )
            }
            ContractError::WrongStateType => {
                write!(f, "logical state type does not match the contract")
            }
            ContractError::WrongParamsType => {
                write!(f, "params type does not match the contract")
            }
            ContractError::MissingFundingOutput(outpoint) => {
                write!(f, "the funding transaction has no output {outpoint}")
            }
            ContractError::StateDecoding(e) => write!(f, "failed to decode state: {}", e),
            ContractError::Key(msg) => write!(f, "key operation failed: {}", msg),
            ContractError::DuplicateClauseName(name) => {
                write!(f, "duplicate clause name in contract: {name}")
            }
            ContractError::DuplicateClauseScript { first, second } => write!(
                f,
                "clauses '{first}' and '{second}' have the same tapscript"
            ),
        }
    }
}

impl std::error::Error for ContractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ContractError::StateDecoding(e) => Some(e),
            _ => None,
        }
    }
}

impl From<WitnessError> for ContractError {
    fn from(e: WitnessError) -> Self {
        ContractError::StateDecoding(e)
    }
}

/// What a contract-construction step may evaluate to: the value itself, or a
/// `Result<_, ContractError>` of it.
///
/// The `contract!` sections that build part of a contract (`script`,
/// `timelock`, `args raw`, `internal_key`, a dynamic `tree`) accept either
/// form, so a builder that constructs a child contract can propagate its
/// failure with `?` instead of panicking:
///
/// ```
/// use bitcoin::ScriptBuf;
/// use mattrs::contracts::{ContractError, IntoContractResult};
/// fn plain() -> ScriptBuf { ScriptBuf::new() }
/// fn fallible() -> Result<ScriptBuf, ContractError> { Ok(ScriptBuf::new()) }
/// let a: Result<ScriptBuf, ContractError> = plain().into_contract_result();
/// let b: Result<ScriptBuf, ContractError> = fallible().into_contract_result();
/// assert_eq!(a.unwrap(), b.unwrap());
/// ```
pub trait IntoContractResult<T> {
    /// The value, or the error that prevented building it.
    fn into_contract_result(self) -> Result<T, ContractError>;
}

impl<T> IntoContractResult<T> for T {
    fn into_contract_result(self) -> Result<T, ContractError> {
        Ok(self)
    }
}

// The error type is fixed, not generic: a builder closure mixing `?` with a
// bare `Ok(..)` then has its error type inferred from this impl.
impl<T> IntoContractResult<T> for Result<T, ContractError> {
    fn into_contract_result(self) -> Result<T, ContractError> {
        self
    }
}

/// Call a `contract!` builder expression (a closure or `fn` taking `&params`).
/// Taking it as a generic argument, rather than calling it in place, is what
/// lets a closure's parameter type be inferred.
#[doc(hidden)]
pub fn __call_builder<P, T, R: IntoContractResult<T>>(
    builder: impl FnOnce(&P) -> R,
    params: &P,
) -> Result<T, ContractError> {
    builder(params).into_contract_result()
}

/// [`__call_builder`] for a contract with a `ctx` section: the builder also
/// receives `&ctx`.
#[doc(hidden)]
pub fn __call_builder_with_ctx<P, C, T, R: IntoContractResult<T>>(
    builder: impl FnOnce(&P, &C) -> R,
    params: &P,
    ctx: &C,
) -> Result<T, ContractError> {
    builder(params, ctx).into_contract_result()
}

// ============================================================================
// Constants
// ============================================================================

/// Opcode for CHECKTEMPLATEVERIFY
pub const OP_CHECKTEMPLATEVERIFY: u8 = 0xb3;

// ============================================================================
// Core Traits
// ============================================================================

/// Encoding of a value as one or more **witness-stack elements** — the
/// script-facing, consensus-relevant format a tapscript actually reads.
///
/// This is the role for a clause's arguments ([`ClauseArgs`]) and for a state
/// commitment's Merkle leaves ([`ContractState`]): the bytes produced here are the
/// bytes the covenant sees. Signed integers therefore use Bitcoin Script's number
/// format (`bn2vch`), so scripts can do arithmetic on them; other types map to the
/// bytes a script would push (a 32-byte hash, an x-only key, ...).
pub trait WitnessEncodable {
    /// The number of witness elements every value of this type occupies, or
    /// `None` when it varies with the value (e.g. `Option<T>`). Symbolic
    /// script builders lay out a witness from this before any value exists.
    const ELEMENTS: Option<usize>;

    /// Encodes the value into one or more witness stack elements.
    ///
    /// # Returns
    ///
    /// A vector of byte vectors, where each inner vector represents a single
    /// witness element. The elements should be ordered as they would appear
    /// on the witness stack.
    fn encode_to_witness(&self) -> Vec<Vec<u8>>;

    /// Decodes a value from the witness stack.
    ///
    /// # Arguments
    ///
    /// * `witness` - A slice of witness elements to decode from
    ///
    /// # Returns
    ///
    /// * `Ok((value, consumed))` - The decoded value and the number of witness
    ///   elements consumed from the input slice
    /// * `Err(e)` - An error if decoding fails (e.g., invalid format, insufficient elements)
    ///
    /// # Errors
    ///
    /// This method should return an error if:
    /// - The witness stack doesn't contain enough elements
    /// - The witness elements have invalid format or size
    /// - The data cannot be properly decoded
    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError>
    where
        Self: Sized;
}

/// The combined [`WitnessEncodable::ELEMENTS`] of a sequence of fields: their
/// sum, or `None` if any field's count varies. Used by the derives.
#[doc(hidden)]
pub const fn __sum_elements(parts: &[Option<usize>]) -> Option<usize> {
    let mut total = 0;
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            Some(n) => total += n,
            None => return None,
        }
        i += 1;
    }
    Some(total)
}

/// Marker for values whose [`WitnessEncodable`] representation is always
/// exactly one element.
///
/// Identity [`ContractState`] commitments use that element's bytes directly,
/// because covenant scripts re-reveal those same bytes as the Taproot state
/// tweak. Variable- or multi-element encodings cannot be flattened without
/// losing their element boundaries and therefore must not implement this trait.
///
/// Implementors opt into identity-state use. The checked helpers verify that
/// the underlying codec actually produces and consumes exactly one element,
/// so an incorrect implementation is an ordinary decoding error rather than
/// an unsafe-code contract.
///
/// Types with variable-width witness layouts cannot be used as identity state:
///
/// ```compile_fail
/// use mattrs::ContractState;
///
/// #[derive(Debug, Clone, ContractState)]
/// #[commit(identity)]
/// struct InvalidState {
///     value: Option<[u8; 32]>,
/// }
/// ```
pub trait SingleWitnessElement: WitnessEncodable {
    /// Encode and verify that exactly one element was produced.
    fn encode_single(&self) -> Result<Vec<u8>, WitnessError> {
        let mut elements = self.encode_to_witness();
        if elements.len() != 1 {
            return Err(WitnessError::Invalid(format!(
                "single-element codec produced {} elements",
                elements.len()
            )));
        }
        Ok(elements.pop().expect("length checked"))
    }

    /// Decode and verify that exactly one element was consumed.
    fn decode_single(element: Vec<u8>) -> Result<Self, WitnessError>
    where
        Self: Sized,
    {
        let (value, consumed) = Self::decode_from_witness(&[element])?;
        if consumed != 1 {
            return Err(WitnessError::Invalid(format!(
                "single-element codec consumed {consumed} elements"
            )));
        }
        Ok(value)
    }
}

// ============================================================================
// WitnessEncodable implementations for common types
// ============================================================================

/// Signed integers use Bitcoin Script's number format (`bn2vch`), one element.
macro_rules! impl_scriptnum_witness {
    ($($t:ty),+ $(,)?) => {$(
        impl WitnessEncodable for $t {
            const ELEMENTS: Option<usize> = Some(1);

            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                vec![crate::script::bn2vch(*self as i64)]
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
                if witness.is_empty() {
                    return Err(WitnessError::Missing);
                }
                let val = crate::script::vch2bn(&witness[0])
                    .map_err(|e| WitnessError::Invalid(e.to_string()))?;
                let value = <$t>::try_from(val).map_err(|_| {
                    WitnessError::Invalid(format!(
                        "Script number {val} is out of range for {}",
                        stringify!($t),
                    ))
                })?;
                Ok((value, 1))
            }
        }
    )+};
}

impl_scriptnum_witness!(i32, i64);

impl SingleWitnessElement for i32 {}
impl SingleWitnessElement for i64 {}

impl<const N: usize> WitnessEncodable for [u8; N] {
    const ELEMENTS: Option<usize> = Some(1);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.to_vec()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::Missing);
        }
        if witness[0].len() != N {
            return Err(WitnessError::Invalid(format!(
                "Expected array of length {}, got {}",
                N,
                witness[0].len()
            )));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&witness[0]);
        Ok((arr, 1))
    }
}

impl<const N: usize> SingleWitnessElement for [u8; N] {}

impl WitnessEncodable for Vec<u8> {
    const ELEMENTS: Option<usize> = Some(1);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.clone()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::Missing);
        }
        Ok((witness[0].clone(), 1))
    }
}

impl SingleWitnessElement for Vec<u8> {}

/// Booleans use the *canonical* script encoding — `[]` for false, `[0x01]` for
/// true — the only values tapscript's consensus `MINIMALIF` accepts as `OP_IF`
/// operands (a `[0x00]` false would be invalid on-chain).
impl WitnessEncodable for bool {
    const ELEMENTS: Option<usize> = Some(1);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![if *self { vec![1] } else { Vec::new() }]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        match witness.first().ok_or(WitnessError::Missing)?.as_slice() {
            [] => Ok((false, 1)),
            [1] => Ok((true, 1)),
            other => Err(WitnessError::Invalid(format!(
                "not a canonical bool encoding: {other:02x?}"
            ))),
        }
    }
}

impl SingleWitnessElement for bool {}

impl WitnessEncodable for XOnlyPublicKey {
    const ELEMENTS: Option<usize> = Some(1);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.serialize().to_vec()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::Missing);
        }
        if witness[0].len() != 32 {
            return Err(WitnessError::Invalid(format!(
                "Expected 32 bytes for XOnlyPublicKey, got {}",
                witness[0].len()
            )));
        }
        let key = XOnlyPublicKey::from_slice(&witness[0])
            .map_err(|e| WitnessError::Invalid(e.to_string()))?;
        Ok((key, 1))
    }
}

impl SingleWitnessElement for XOnlyPublicKey {}

impl<T: WitnessEncodable> WitnessEncodable for Option<T> {
    /// One flag element, plus the value's elements when present.
    const ELEMENTS: Option<usize> = None;

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        match self {
            Some(value) => {
                let mut result = vec![vec![1u8]]; // presence flag
                result.extend(value.encode_to_witness());
                result
            }
            None => vec![Vec::new()], // canonical false / absence flag
        }
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::Missing);
        }

        match witness[0].as_slice() {
            [] => Ok((None, 1)),
            [1] => {
                let (value, consumed) = T::decode_from_witness(&witness[1..])?;
                Ok((Some(value), consumed + 1))
            }
            other => Err(WitnessError::Invalid(format!(
                "not a canonical option flag: {other:02x?}",
            ))),
        }
    }
}

/// A Schnorr signature witness element.
///
/// Signature fields in a clause's `*Args` struct use this type. It defaults to
/// empty (unsigned): the manager fills it in at spend time by matching the
/// clause's `SignerType` pubkey against the registered signers, so callers never
/// build a placeholder signature by hand. It occupies exactly one witness element.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Wrap raw signature bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, WitnessError> {
        if !bytes.is_empty() && !matches!(bytes.len(), 64 | 65) {
            return Err(WitnessError::Invalid(format!(
                "taproot signature must be 64 or 65 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Signature(bytes))
    }

    /// The signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether the signature is unset (the default, to be filled by the manager).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = WitnessError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Signature::new(bytes)
    }
}

impl WitnessEncodable for Signature {
    const ELEMENTS: Option<usize> = Some(1);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.0.clone()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        let first = witness.first().ok_or(WitnessError::Missing)?;
        Ok((Signature::new(first.clone())?, 1))
    }
}

impl SingleWitnessElement for Signature {}

// ============================================================================
// Marker Trait Implementations
// ============================================================================
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

/// Trait for clause arguments.
pub trait ClauseArgs: Debug + Clone + Send + Sync {
    /// Encode arguments to witness stack elements.
    fn encode_to_witness(&self) -> Vec<Vec<u8>>;

    /// Decode arguments from witness stack elements.
    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError>
    where
        Self: Sized;
}

/// Raw, untyped clause arguments: the witness stack itself.
///
/// For clauses whose argument layout is only known at runtime — e.g. the generic
/// fraud-proof [`Leaf`](crate::fraud::Leaf), whose arguments depend on a
/// [`Computer`](crate::fraud::Computer)'s specs. The clause's `arg_specs` still
/// describe the layout, so the manager can locate signature slots.
#[derive(Debug, Clone)]
pub struct RawArgs(pub Vec<Vec<u8>>);

impl ClauseArgs for RawArgs {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        self.0.clone()
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError> {
        Ok(RawArgs(witness.to_vec()))
    }
}

/// A sequential reader over a clause's witness elements, for raw-args clauses'
/// `next()` bodies: each read consumes elements in order, so argument
/// extraction follows the clause's `ArgSpec` order by construction instead of
/// hand-counted indices, and errors name the failing element's position.
///
/// ```ignore
/// let mut r = WitnessReader::new(witness);
/// let taptree = r.bytes32()?;
/// let root = r.bytes32()?;
/// let x = r.num()?;
/// ```
#[derive(Debug)]
pub struct WitnessReader<'a> {
    witness: &'a [Vec<u8>],
    pos: usize,
}

impl<'a> WitnessReader<'a> {
    /// Start reading at the first element.
    pub fn new(witness: &'a [Vec<u8>]) -> Self {
        WitnessReader { witness, pos: 0 }
    }

    fn take(&mut self) -> Result<&'a [u8], WitnessError> {
        let element = self.witness.get(self.pos).ok_or_else(|| {
            WitnessError::Invalid(format!(
                "witness element {} requested, but the stack has {}",
                self.pos,
                self.witness.len()
            ))
        })?;
        self.pos += 1;
        Ok(element)
    }

    /// The next element, as raw bytes.
    pub fn bytes(&mut self) -> Result<&'a [u8], WitnessError> {
        self.take()
    }

    /// The next element, as exactly 32 bytes.
    pub fn bytes32(&mut self) -> Result<[u8; 32], WitnessError> {
        let pos = self.pos;
        self.take()?
            .try_into()
            .map_err(|_| WitnessError::Invalid(format!("witness element {pos} is not 32 bytes")))
    }

    /// The next element, as a Bitcoin script number.
    pub fn num(&mut self) -> Result<i64, WitnessError> {
        let pos = self.pos;
        crate::script::vch2bn(self.take()?)
            .map_err(|e| WitnessError::Invalid(format!("witness element {pos}: {e}")))
    }

    /// The next element, as an x-only public key.
    pub fn xonly(&mut self) -> Result<XOnlyPublicKey, WitnessError> {
        let pos = self.pos;
        XOnlyPublicKey::from_slice(&self.bytes32()?).map_err(|e| {
            WitnessError::Invalid(format!("witness element {pos} is not an x-only key: {e}"))
        })
    }

    /// Skip the next `n` elements.
    pub fn skip(&mut self, n: usize) -> Result<(), WitnessError> {
        for _ in 0..n {
            self.take()?;
        }
        Ok(())
    }

    /// How many elements are left.
    pub fn remaining(&self) -> usize {
        self.witness.len().saturating_sub(self.pos)
    }

    /// Assert every element was consumed.
    pub fn expect_end(&self) -> Result<(), WitnessError> {
        if self.remaining() != 0 {
            return Err(WitnessError::Invalid(format!(
                "{} unread witness elements past position {}",
                self.remaining(),
                self.pos
            )));
        }
        Ok(())
    }
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

impl WitnessEncodable for () {
    const ELEMENTS: Option<usize> = Some(0);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn decode_from_witness(_witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        Ok(((), 0))
    }
}

// ============================================================================
// Clause Output Types
// ============================================================================

/// Where a clause output goes.
#[derive(Debug, Clone)]
pub enum OutputTarget {
    /// A contract instance, which the manager tracks as a child. The contract
    /// carries its own params (see [`ErasedContract::params_any`]); `state` is
    /// the instance's logical state (`()` for a stateless contract), from
    /// which its commitment — and so its address — derives.
    Contract {
        /// The contract of this output.
        contract: Arc<dyn ErasedContract>,
        /// The new instance's logical state.
        state: Box<dyn ErasedState>,
    },
    /// An exact destination script (including any key tweaks). Constrained
    /// like any other output, but not tracked: it creates no child instance.
    Script(ScriptBuf),
}

/// One transaction output a clause constrains: which output, where it goes,
/// and how its amount relates to the spending input.
///
/// A clause may freely mix contract outputs and plain payments. This is
/// host-side metadata: it adds no script checks, so the clause's script must
/// enforce the same destination and amount mode.
///
/// ```
/// use mattrs::contracts::{ClauseOutput, NextOutputs};
/// let payment = ClauseOutput::at(0).pay(mattrs::script::opaque_p2tr(mattrs::nums_key()));
/// let next: NextOutputs = payment.into();
/// ```
#[derive(Debug, Clone)]
pub struct ClauseOutput {
    /// Which transaction output this refers to.
    pub index: CcvIndex,
    /// Where the output goes.
    pub target: OutputTarget,
    /// How the output's amount relates to the input's residual amount.
    pub amount: AmountMode,
}

impl ClauseOutput {
    /// Start building a clause output at an explicit output index.
    ///
    /// # Example
    /// ```ignore
    /// let output = ClauseOutput::at(0)
    ///     .to(contract)
    ///     .with_state(&state)
    ///     .preserve_amount()
    ///     .build();
    /// ```
    pub fn at(index: impl Into<CcvIndex>) -> ClauseOutputTo {
        ClauseOutputTo(index.into())
    }

    /// Start building a clause output whose index matches the spending input.
    pub fn at_same_index() -> ClauseOutputTo {
        ClauseOutputTo(CcvIndex::CURRENT)
    }

    /// Declare no output constraints in the host-side model (and no children).
    ///
    /// This does not mean the script is unconstrained. For a childless CTV
    /// withdrawal, use [`NextOutputs::Template`] or [`NextOutputs::TemplateHash`].
    /// For a script-constrained payment, use [`ClauseOutputTo::pay`]. These let
    /// the manager validate the transaction even though no children are tracked.
    pub fn terminal() -> Vec<ClauseOutput> {
        Vec::new()
    }

    /// A deduct-amount payout to `pk` at output `index`: the key is the
    /// *output* key, used verbatim (see
    /// [`opaque_p2tr`](crate::script::opaque_p2tr)). The spender
    /// supplies the amount via
    /// [`SpendBuilder::output_amount`](crate::manager::SpendBuilder::output_amount).
    pub fn pay_key(index: impl Into<CcvIndex>, pk: XOnlyPublicKey) -> ClauseOutput {
        ClauseOutput::at(index)
            .pay(crate::script::opaque_p2tr(pk))
            .deduct_amount()
    }

    /// A deduct-amount, provably unspendable (NUMS-key) output at `index`.
    pub fn burn(index: impl Into<CcvIndex>) -> ClauseOutput {
        ClauseOutput::pay_key(index, crate::nums_key())
    }

    /// The output's contract and state, when it is a tracked contract output.
    pub fn contract(&self) -> Option<(&Arc<dyn ErasedContract>, &dyn ErasedState)> {
        match &self.target {
            OutputTarget::Contract { contract, state } => Some((contract, state.as_ref())),
            OutputTarget::Script(_) => None,
        }
    }

    /// The output's explicit CCV data commitment: its contract state's, or
    /// empty for a stateless contract and for a plain payment.
    pub fn state_commitment(&self) -> StateCommitment {
        match &self.target {
            OutputTarget::Contract { state, .. } => state.state_commitment(),
            OutputTarget::Script(_) => StateCommitment::empty(),
        }
    }

    /// The exact scriptPubKey this output must carry.
    pub fn script_pubkey(&self) -> Result<ScriptBuf, ContractError> {
        match &self.target {
            OutputTarget::Contract { contract, state } => {
                contract.script_pubkey(&state.state_commitment())
            }
            OutputTarget::Script(script_pubkey) => Ok(script_pubkey.clone()),
        }
    }

    /// The output receives the input's residual amount (the default).
    pub fn preserve_amount(mut self) -> Self {
        self.amount = AmountMode::Preserve;
        self
    }

    /// The output's amount is not constrained. This does not protect the
    /// input's value.
    pub fn ignore_amount(mut self) -> Self {
        self.amount = AmountMode::Ignore;
        self
    }

    /// The output's amount is deducted from the input's residual amount.
    pub fn deduct_amount(mut self) -> Self {
        self.amount = AmountMode::Deduct;
        self
    }
}

/// First stage of the [`ClauseOutput`] builder: the output's destination must
/// be set (with [`to`](Self::to) or [`pay`](Self::pay)) before anything else,
/// so a finished output can never lack one.
pub struct ClauseOutputTo(CcvIndex);

impl ClauseOutputTo {
    /// Send this output to a contract, creating a tracked child instance.
    pub fn to(self, contract: Arc<dyn ErasedContract>) -> ClauseOutputBuilder {
        ClauseOutputBuilder {
            index: self.0,
            contract,
            state: Box::new(()),
            amount: AmountMode::Preserve,
        }
    }

    /// Pay this output to an exact script, preserving the input's residual
    /// amount unless changed with [`ClauseOutput::deduct_amount`] or
    /// [`ClauseOutput::ignore_amount`]. No child instance is tracked.
    pub fn pay(self, script_pubkey: ScriptBuf) -> ClauseOutput {
        ClauseOutput {
            index: self.0,
            target: OutputTarget::Script(script_pubkey),
            amount: AmountMode::Preserve,
        }
    }
}

/// Builder for a contract [`ClauseOutput`] with a fluent API.
pub struct ClauseOutputBuilder {
    index: CcvIndex,
    contract: Arc<dyn ErasedContract>,
    state: Box<dyn ErasedState>,
    amount: AmountMode,
}

impl ClauseOutputBuilder {
    /// Set the state for the next contract. The committed bytes (for addressing)
    /// derive from it, and the child instance carries it for its own future spends.
    pub fn with_state<S: ContractState + 'static>(mut self, state: &S) -> Self {
        self.state = Box::new(state.clone());
        self
    }

    /// Set amount behaviour to preserve output (default).
    pub fn preserve_amount(mut self) -> Self {
        self.amount = AmountMode::Preserve;
        self
    }

    /// Set amount behaviour to ignore output.
    pub fn ignore_amount(mut self) -> Self {
        self.amount = AmountMode::Ignore;
        self
    }

    /// Set amount behaviour to deduct from input.
    pub fn deduct_amount(mut self) -> Self {
        self.amount = AmountMode::Deduct;
        self
    }

    /// Build the [`ClauseOutput`].
    pub fn build(self) -> ClauseOutput {
        ClauseOutput {
            index: self.index,
            target: OutputTarget::Contract {
                contract: self.contract,
                state: self.state,
            },
            amount: self.amount,
        }
    }
}

/// A CTV (`CHECKTEMPLATEVERIFY`) transaction template: the exact outputs and input
/// sequence that a clause commits its spending transaction to.
///
/// A clause whose `next_outputs` returns [`NextOutputs::Template`] fixes the whole
/// spending transaction (its outputs and `nSequence`), rather than declaring
/// per-output child contracts. Such a spend is terminal — it creates no tracked
/// child instances.
#[derive(Debug, Clone)]
pub struct CtvTemplate {
    /// The transaction outputs the template commits to.
    pub outputs: Vec<TxOut>,
    /// The `nSequence` of the (single) spending input the template commits to.
    pub sequence: Sequence,
}

impl CtvTemplate {
    /// Build a template from its outputs and input sequence.
    pub fn new(outputs: Vec<TxOut>, sequence: Sequence) -> Self {
        Self { outputs, sequence }
    }

    /// The BIP-119 standard template hash for this template (single-input spend).
    pub fn ctv_hash(&self) -> [u8; 32] {
        crate::ctv::compute_ctv_hash(&self.outputs, self.sequence)
    }
}

/// What a clause produces when spent.
///
/// Output constraints and child tracking are distinct: payments and CTV spends
/// have no tracked children but still constrain their transactions. A clause with no
/// next-outputs function yields `Outputs(vec![])`, which declares no
/// host-side output checks; it does not imply its script is unconstrained.
#[derive(Debug, Clone)]
pub enum NextOutputs {
    /// `CHECKCONTRACTVERIFY` outputs with CCV amount semantics: (possibly
    /// stateful) contracts, which become tracked children, and plain payments,
    /// which do not. Payments can aggregate with other payments to the same
    /// script and index, but the builder rejects a payment sharing an index
    /// with a contract output or a `Join`, because the output's tracking
    /// identity would be ambiguous.
    Outputs(Vec<ClauseOutput>),
    /// A fixed `CHECKTEMPLATEVERIFY` template — terminal (no child instances).
    Template(CtvTemplate),
    /// A CTV commitment whose outputs are supplied at spending time, e.g. a
    /// template hash stored in contract state. Creates no child instances.
    ///
    /// The builder requires explicit `.outputs(...)` and supports single-input
    /// spends (version 2, locktime 0). The final transaction must match this
    /// BIP-119 hash before signing. Observation checks the actual transaction's
    /// hash, including its input index. The script must enforce the same hash;
    /// this metadata alone adds no on-chain constraint.
    TemplateHash([u8; 32]),
    /// Contribute this input's whole amount to the transaction output at
    /// `index`, whose contract and state must be defined by *another input's*
    /// clause in the same batch spend — the "bond joins the pot" pattern: the
    /// joining input's script typically just checks its owner's signature
    /// (which covers the whole transaction), so nothing about the target needs
    /// to be re-declared or carried in its witness.
    Join {
        /// The transaction output index the amount joins.
        index: u32,
    },
}

impl NextOutputs {
    /// A [`Join`](NextOutputs::Join) contribution to output `index`.
    pub fn join(index: u32) -> Self {
        NextOutputs::Join { index }
    }
}

impl From<Vec<ClauseOutput>> for NextOutputs {
    fn from(outputs: Vec<ClauseOutput>) -> Self {
        NextOutputs::Outputs(outputs)
    }
}

impl From<CtvTemplate> for NextOutputs {
    fn from(template: CtvTemplate) -> Self {
        NextOutputs::Template(template)
    }
}

impl From<ClauseOutput> for NextOutputs {
    fn from(output: ClauseOutput) -> Self {
        Self::Outputs(vec![output])
    }
}

// ============================================================================
// TapTree Structure
// ============================================================================

/// A single leaf in a taproot tree.
#[derive(Debug, Clone, PartialEq)]
pub struct TapLeaf {
    /// The clause name this leaf belongs to (not consensus-visible).
    pub name: String,
    /// The leaf's tapscript.
    pub script: ScriptBuf,
}

/// Recursive taproot tree structure.
#[derive(Debug, Clone)]
pub enum TapTree {
    Leaf(TapLeaf),
    Branch {
        left: Arc<TapTree>,
        right: Arc<TapTree>,
    },
}

impl TapTree {
    /// Create a new leaf node.
    pub fn leaf(name: impl Into<String>, script: ScriptBuf) -> Self {
        TapTree::Leaf(TapLeaf {
            name: name.into(),
            script,
        })
    }

    /// Create a new branch node.
    pub fn branch(left: TapTree, right: TapTree) -> Self {
        TapTree::Branch {
            left: Arc::new(left),
            right: Arc::new(right),
        }
    }

    /// Compute the merkle root hash of this tree.
    pub fn root_hash(&self) -> [u8; 32] {
        match self {
            TapTree::Leaf(TapLeaf { name: _, script }) => {
                let leaf_hash =
                    TapLeafHash::from_script(script.as_script(), LeafVersion::TapScript);
                *leaf_hash.as_byte_array()
            }
            TapTree::Branch { left, right } => {
                let left_hash = TapNodeHash::from_byte_array(left.root_hash());
                let right_hash = TapNodeHash::from_byte_array(right.root_hash());
                let node_hash = TapNodeHash::from_node_hashes(left_hash, right_hash);
                *node_hash.as_byte_array()
            }
        }
    }

    /// Get the merkle proof for a specific leaf: the sibling hashes ordered
    /// leaf-to-root (deepest sibling first), as a BIP341 control block expects.
    pub fn merkle_proof(&self, target_leaf: &TapLeaf) -> Option<Vec<[u8; 32]>> {
        match self {
            TapTree::Leaf(leaf) => {
                if leaf == target_leaf {
                    Some(Vec::new())
                } else {
                    None
                }
            }
            TapTree::Branch { left, right } => {
                if let Some(mut proof) = left.merkle_proof(target_leaf) {
                    proof.push(right.root_hash());
                    Some(proof)
                } else if let Some(mut proof) = right.merkle_proof(target_leaf) {
                    proof.push(left.root_hash());
                    Some(proof)
                } else {
                    None
                }
            }
        }
    }

    /// Find a specific leaf by name.
    pub fn find_leaf(&self, name: &str) -> Option<&TapLeaf> {
        match self {
            TapTree::Leaf(leaf) => {
                if leaf.name == name {
                    Some(leaf)
                } else {
                    None
                }
            }
            TapTree::Branch { left, right } => {
                left.find_leaf(name).or_else(|| right.find_leaf(name))
            }
        }
    }

    /// Get all leaves in the tree (in order).
    pub fn leaves(&self) -> Vec<&TapLeaf> {
        match self {
            TapTree::Leaf(leaf) => vec![leaf],
            TapTree::Branch { left, right } => {
                let mut result = left.leaves();
                result.extend(right.leaves());
                result
            }
        }
    }

    /// Generate a control block for spending a specific clause.
    pub fn control_block(
        &self,
        internal_pubkey: &XOnlyPublicKey,
        clause_name: &str,
    ) -> Option<Vec<u8>> {
        let tapleaf = self.find_leaf(clause_name)?;
        let merkle_root = TapNodeHash::from_byte_array(self.root_hash());
        let tweak =
            TapTweakHash::from_key_and_tweak(*internal_pubkey, Some(merkle_root)).to_scalar();

        let secp = Secp256k1::new();
        let (_, parity) = internal_pubkey
            .add_tweak(&secp, &tweak)
            .expect("Taproot tweak should never fail");

        let c0 = 0xC0u8 | parity.to_u8();
        let xonly_bytes = internal_pubkey.serialize();

        let mut control_block = Vec::new();
        control_block.push(c0);
        control_block.extend_from_slice(&xonly_bytes);

        let merkle_proof = self.merkle_proof(tapleaf)?;
        for hash in merkle_proof {
            control_block.extend_from_slice(&hash);
        }

        Some(control_block)
    }
}

// ============================================================================
// Clause Tree
// ============================================================================

/// A taproot tree whose leaves are clauses.
///
/// This is the single source of truth for a contract's tapscript layout: both
/// the script [`TapTree`] (and therefore the address) and the `name -> clause`
/// lookup used when spending are *derived* from the same `ClauseTree`, so they
/// can never drift apart. Build one with the `clause_tree!` macro and hand it to
/// `StandardP2TR::new`.
pub enum ClauseTree {
    Leaf(Arc<dyn ErasedClause>),
    Branch(Arc<ClauseTree>, Arc<ClauseTree>),
}

impl ClauseTree {
    /// Create a leaf from a clause.
    pub fn leaf(clause: Arc<dyn ErasedClause>) -> Self {
        ClauseTree::Leaf(clause)
    }

    /// Create a branch from two subtrees.
    pub fn branch(left: ClauseTree, right: ClauseTree) -> Self {
        ClauseTree::Branch(Arc::new(left), Arc::new(right))
    }

    /// Derive the script taptree (each leaf carries the clause name + script).
    pub fn to_script_tree(&self) -> TapTree {
        match self {
            ClauseTree::Leaf(clause) => TapTree::Leaf(TapLeaf {
                name: clause.name().to_string(),
                script: clause.script().clone(),
            }),
            ClauseTree::Branch(left, right) => {
                TapTree::branch(left.to_script_tree(), right.to_script_tree())
            }
        }
    }

    /// Collect all clauses, left-to-right (witness/spec order).
    pub fn clauses(&self) -> Vec<Arc<dyn ErasedClause>> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }

    fn collect(&self, out: &mut Vec<Arc<dyn ErasedClause>>) {
        match self {
            ClauseTree::Leaf(clause) => out.push(clause.clone()),
            ClauseTree::Branch(left, right) => {
                left.collect(out);
                right.collect(out);
            }
        }
    }
}

impl Debug for ClauseTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClauseTree::Leaf(clause) => f.debug_tuple("Leaf").field(&clause.name()).finish(),
            ClauseTree::Branch(left, right) => {
                f.debug_tuple("Branch").field(left).field(right).finish()
            }
        }
    }
}

/// Reject ambiguous clause lookup and spend observation in every build mode.
fn validate_unique_clauses(clauses: &[Arc<dyn ErasedClause>]) -> Result<(), ContractError> {
    let mut seen_names = std::collections::HashSet::new();
    let mut seen_scripts = std::collections::HashMap::new();
    for clause in clauses {
        if !seen_names.insert(clause.name()) {
            return Err(ContractError::DuplicateClauseName(
                clause.name().to_string(),
            ));
        }
        if let Some(first) = seen_scripts.insert(clause.script().clone(), clause.name()) {
            return Err(ContractError::DuplicateClauseScript {
                first: first.to_string(),
                second: clause.name().to_string(),
            });
        }
    }
    Ok(())
}

// ============================================================================
// Key Tweaking Utilities
// ============================================================================

/// Compute a tweaked key for augmented contracts with state commitment.
/// Uses SHA256(naked_key || data) for a nonempty CCV data operand. There is no
/// length-dependent prehash. [`apply_state_tweak`] skips the tweak for empty data.
pub fn compute_state_tweak(naked_key: &[u8; 32], commitment: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + commitment.len());
    data.extend_from_slice(naked_key);
    data.extend_from_slice(commitment);
    let hash = sha256::Hash::hash(&data);
    *hash.as_byte_array()
}

/// Apply the CCV data tweak using the exact commitment bytes. Empty data leaves
/// the naked key unchanged; all nonempty lengths use the same algorithm.
pub fn apply_state_tweak(
    naked_key: &XOnlyPublicKey,
    commitment: &[u8],
) -> Result<XOnlyPublicKey, ContractError> {
    if commitment.is_empty() {
        return Ok(*naked_key);
    }
    let tweak_bytes = compute_state_tweak(&naked_key.serialize(), commitment);

    let secp = Secp256k1::new();
    let scalar = bitcoin::secp256k1::Scalar::from_be_bytes(tweak_bytes)
        .map_err(|e| ContractError::Key(format!("invalid scalar: {}", e)))?;

    naked_key
        .add_tweak(&secp, &scalar)
        .map(|(tweaked, _parity)| tweaked)
        .map_err(|e| ContractError::Key(format!("failed to apply tweak: {}", e)))
}

/// Compute the final taproot output key from internal key and taptree.
pub fn compute_taproot_output_key(
    internal_key: &XOnlyPublicKey,
    taptree: Option<&TapTree>,
) -> XOnlyPublicKey {
    let merkle_root = taptree.map(|tree| TapNodeHash::from_byte_array(tree.root_hash()));
    let tweak = TapTweakHash::from_key_and_tweak(*internal_key, merkle_root).to_scalar();

    let secp = Secp256k1::new();
    internal_key
        .add_tweak(&secp, &tweak)
        .expect("Taproot tweak should never fail")
        .0
}

// ============================================================================
// Type-Erased Clause Trait (for runtime polymorphism)
// ============================================================================

/// Type-erased view of a [`StandardClause`] for dynamic dispatch.
/// This allows the manager to work with clauses without knowing their concrete types.
pub trait ErasedClause: Debug + Send + Sync {
    /// Get the clause name.
    fn name(&self) -> &str;

    /// Get the clause script.
    fn script(&self) -> &ScriptBuf;

    /// Get the argument specifications, in witness order.
    fn arg_specs(&self) -> &[ArgSpec];

    /// The CSV timelock (in blocks) this clause's script enforces, if it
    /// declared one: the manager seeds the spending input's `nSequence` from
    /// it (an explicit `SpendBuilder::sequence` still overrides).
    fn csv_blocks(&self) -> Option<u32> {
        None
    }

    /// Compute next outputs from the spend's witness stack (args in witness order).
    ///
    /// The witness stack is the ordered argument encoding. Params and the
    /// expanded logical state are downcast to the clause's exact state type
    /// (`()` for a stateless contract). Commitments are never used as
    /// serialized state.
    fn next_outputs_from_witness(
        &self,
        params: &dyn std::any::Any,
        witness: &[Vec<u8>],
        state: &dyn ErasedState,
    ) -> Result<NextOutputs, ClauseError>;
}

// ============================================================================
// ArgType Trait (for argument type specifications)
// ============================================================================

/// Describes one argument's slot(s) in a clause's witness layout.
///
/// Values themselves flow through the typed `*Args` struct
/// ([`ClauseArgs::encode_to_witness`]); an `ArgType` only *accounts* for the
/// witness elements an argument occupies (and, for signatures, names the key
/// that must sign), so the manager can walk a witness stack spec by spec.
pub trait ArgType: Debug + Send + Sync {
    /// Validate the argument at the head of `witness` and return the number of
    /// witness elements it occupies.
    fn consume(&self, witness: &[Vec<u8>]) -> Result<usize, WitnessError>;

    /// Static number of witness elements represented by this argument, or
    /// `None` when it depends on the value. This is used by symbolic script
    /// builders before an actual witness exists.
    fn witness_elements(&self) -> Option<usize> {
        Some(1)
    }

    /// If this argument is a signature, the x-only pubkey expected to sign it.
    ///
    /// Returns `Some(pubkey)` for signature arguments (so the manager knows which
    /// key must sign this witness element) and `None` for all other types. The
    /// element is assumed to be a single witness item.
    fn signer_pubkey(&self) -> Option<XOnlyPublicKey> {
        None
    }
}

// ============================================================================
// Argument Specification
// ============================================================================

/// Specification for a single clause argument.
#[derive(Clone)]
pub struct ArgSpec {
    /// The argument name (matches the `*Args` struct field).
    pub name: String,
    /// How many witness elements the argument occupies, and whether it is a
    /// signature (see [`ArgType`]).
    pub arg_type: Arc<dyn ArgType>,
}

impl Debug for ArgSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArgSpec")
            .field("name", &self.name)
            .field("arg_type", &"<dyn ArgType>")
            .finish()
    }
}

// ============================================================================
// Standard Clause Implementation
// ============================================================================

/// Type-safe function for computing next outputs.
pub type NextOutputsFn<P, S, A> =
    Arc<dyn Fn(&P, &A, &S) -> Result<NextOutputs, ClauseError> + Send + Sync>;

/// Standard implementation of a clause.
pub struct StandardClause<P, S, A>
where
    P: ContractParams,
    S: ContractState,
    A: ClauseArgs,
{
    name: String,
    script: ScriptBuf,
    arg_specs: Vec<ArgSpec>,
    next_outputs_fn: Option<NextOutputsFn<P, S, A>>,
    /// The clause's CSV timelock, when declared (see
    /// [`ErasedClause::csv_blocks`]).
    csv_blocks: Option<u32>,
    _phantom: PhantomData<(P, S, A)>,
}

impl<P, S, A> StandardClause<P, S, A>
where
    P: ContractParams + 'static,
    S: ContractState + 'static,
    A: ClauseArgs + 'static,
{
    /// Build a clause from its name, tapscript, witness-layout specs, and the
    /// optional function computing its output constraints (`None` declares no
    /// host-side output checks and no children).
    /// `arg_specs` must describe exactly the witness layout `A` encodes to.
    pub fn new(
        name: String,
        script: ScriptBuf,
        arg_specs: Vec<ArgSpec>,
        next_outputs_fn: Option<NextOutputsFn<P, S, A>>,
    ) -> Self {
        Self {
            name,
            script,
            arg_specs,
            next_outputs_fn,
            csv_blocks: None,
            _phantom: PhantomData,
        }
    }

    /// Record the clause's CSV timelock (1..=65,535 blocks). Contract construction
    /// rejects invalid metadata, and the manager checks the final `nSequence`
    /// against this delay before signing.
    ///
    /// This only records metadata: direct callers must put a matching CSV check
    /// in their script. The `contract!` DSL's `timelock` section does both.
    pub fn with_csv_blocks(mut self, blocks: u32) -> Self {
        self.csv_blocks = Some(blocks);
        self
    }

    /// Compute next outputs from typed parameters, arguments and state. A clause
    /// without a next-outputs function declares no host-side output constraints
    /// and no children; it still needs transaction outputs when spent.
    pub fn next_outputs(
        &self,
        params: &P,
        args: &A,
        state: &S,
    ) -> Result<NextOutputs, ClauseError> {
        if let Some(ref f) = self.next_outputs_fn {
            f(params, args, state)
        } else {
            Ok(NextOutputs::Outputs(Vec::new()))
        }
    }
}

impl<P, S, A> Debug for StandardClause<P, S, A>
where
    P: ContractParams,
    S: ContractState,
    A: ClauseArgs,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StandardClause")
            .field("name", &self.name)
            .field("script", &self.script)
            .field("arg_specs", &self.arg_specs)
            .finish()
    }
}

impl<P, S, A> Clone for StandardClause<P, S, A>
where
    P: ContractParams,
    S: ContractState,
    A: ClauseArgs,
{
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            script: self.script.clone(),
            arg_specs: self.arg_specs.clone(),
            next_outputs_fn: self.next_outputs_fn.clone(),
            csv_blocks: self.csv_blocks,
            _phantom: PhantomData,
        }
    }
}

// Implement the type-erased ErasedClause trait
impl<P, S, A> ErasedClause for StandardClause<P, S, A>
where
    P: ContractParams + 'static,
    S: ContractState + 'static,
    A: ClauseArgs + 'static,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn script(&self) -> &ScriptBuf {
        &self.script
    }

    fn arg_specs(&self) -> &[ArgSpec] {
        &self.arg_specs
    }

    fn csv_blocks(&self) -> Option<u32> {
        self.csv_blocks
    }

    fn next_outputs_from_witness(
        &self,
        params: &dyn std::any::Any,
        witness: &[Vec<u8>],
        state: &dyn ErasedState,
    ) -> Result<NextOutputs, ClauseError> {
        let params = params
            .downcast_ref::<P>()
            .ok_or(ContractError::WrongParamsType)?;

        // Only the expanded logical state can recover S. A commitment is not
        // serialized state and must never be decoded as a different state type.
        let state = state
            .as_any()
            .downcast_ref::<S>()
            .ok_or(ContractError::WrongStateType)?;

        // The witness stack is already the ordered argument encoding; decode it
        // straight into the concrete Args type (no HashMap round-trip).
        let concrete_args = A::decode_from_witness(witness)?;

        // Call the typed version
        self.next_outputs(params, &concrete_args, state)
    }
}

// ============================================================================
// Contract Traits
// ============================================================================

/// Type-erased contract for runtime polymorphism.
pub trait ErasedContract: Debug + Send + Sync {
    /// Get all clauses (type-erased).
    fn clauses(&self) -> &[Arc<dyn ErasedClause>];

    /// The contract's typed params value. A contract is self-describing, so
    /// clauses and typed handles recover their params from here by downcast.
    fn params_any(&self) -> &dyn std::any::Any;

    /// Get a clause by name.
    fn get_clause(&self, name: &str) -> Option<&Arc<dyn ErasedClause>>;

    /// Execute a clause (selected by name) against a spend's witness stack and
    /// return the next outputs. The contract's own params are used.
    fn execute_clause_from_witness(
        &self,
        clause_name: &str,
        witness: &[Vec<u8>],
        state: &dyn ErasedState,
    ) -> Result<NextOutputs, ClauseError>;

    /// The `TypeId` of the concrete contract type, used to check that a
    /// type-erased instance is the contract a typed handle expects.
    fn contract_type_id(&self) -> std::any::TypeId;

    /// A human-readable contract name (e.g. `"Vault"`), for introspection and
    /// display; not consensus-visible.
    fn contract_name(&self) -> &'static str;

    /// Concrete logical-state type of this contract's instances: the unit type
    /// `()` for a stateless contract.
    fn state_type_id(&self) -> std::any::TypeId;

    /// Get the script pubkey from an explicit commitment, not serialized state.
    /// An empty commitment (a stateless contract's) omits the data tweak. Bytes
    /// are never implicitly prehashed.
    ///
    /// ```compile_fail
    /// use mattrs::contracts::ErasedContract;
    /// fn address(contract: &dyn ErasedContract, serialized: Vec<u8>) {
    ///     contract.script_pubkey(&serialized);
    /// }
    /// ```
    fn script_pubkey(&self, commitment: &StateCommitment) -> Result<ScriptBuf, ContractError>;

    /// Get the internal pubkey to use for control block generation: the naked
    /// key, tweaked with the commitment when it is not empty.
    fn control_block_internal_key(
        &self,
        commitment: &StateCommitment,
    ) -> Result<XOnlyPublicKey, ContractError>;

    /// Get the taptree for this contract.
    fn taptree(&self) -> &Arc<TapTree>;
}

// ============================================================================
// Standard P2TR Contracts
// ============================================================================

/// The clause/taptree/params core of a [`StandardP2TR`], independent of its
/// params and state types.
#[derive(Clone)]
struct P2trContractCore {
    /// A human-readable contract name (e.g. `"Vault"`), for introspection and
    /// display; not consensus-visible.
    name: &'static str,
    /// Nominal identity supplied by the contract definition. Generated
    /// contracts use a fresh private marker type, so definitions cannot collide
    /// merely because they share params/state types or a display name.
    kind_id: std::any::TypeId,
    taptree: Arc<TapTree>,
    clauses: Vec<Arc<dyn ErasedClause>>,
    /// The typed params value (see [`ErasedContract::params_any`]).
    params_any: Arc<dyn std::any::Any + Send + Sync>,
}

impl P2trContractCore {
    /// Derive the script taptree and the clause list from one `clause_tree`, so
    /// they cannot drift apart.
    fn new<P: ContractParams + 'static, I: 'static>(
        name: &'static str,
        params: &P,
        clause_tree: ClauseTree,
    ) -> Result<Self, ContractError> {
        let clauses = clause_tree.clauses();
        validate_unique_clauses(&clauses)?;
        for clause in &clauses {
            if let Some(blocks) = clause.csv_blocks() {
                crate::BlockDelay::new(blocks)?;
            }
        }
        let taptree = Arc::new(clause_tree.to_script_tree());
        Ok(Self {
            name,
            kind_id: std::any::TypeId::of::<I>(),
            taptree,
            clauses,
            params_any: Arc::new(params.clone()),
        })
    }

    fn get_clause(&self, name: &str) -> Option<&Arc<dyn ErasedClause>> {
        self.clauses.iter().find(|c| c.name() == name)
    }

    fn execute_clause_from_witness(
        &self,
        clause_name: &str,
        witness: &[Vec<u8>],
        state: &dyn ErasedState,
    ) -> Result<NextOutputs, ClauseError> {
        let clause = self
            .get_clause(clause_name)
            .ok_or_else(|| ClauseError::Other(format!("Clause {} not found", clause_name)))?;

        clause.next_outputs_from_witness(self.params_any.as_ref(), witness, state)
    }
}

/// A P2TR contract: a taproot output whose leaves are clauses, with the
/// instance's state committed as a tweak of the internal key.
///
/// Every contract has a state type `S`. A *stateless* contract is simply one
/// whose state is the unit type `()` (the default): its commitment is empty, so
/// the internal key is used untweaked. An *augmented* contract names a real
/// state type, and each instance's address commits to that state's
/// [`commitment`](ContractState::commitment).
pub struct StandardP2TR<P: ContractParams, S: ContractState = ()> {
    naked_internal_pubkey: XOnlyPublicKey,
    core: P2trContractCore,
    _phantom: PhantomData<(P, S)>,
}

impl<P: ContractParams + 'static, S: ContractState + 'static> StandardP2TR<P, S> {
    /// Build a contract from its params and a clause tree. The script taptree and
    /// the clause list are both derived from `clause_tree`, so they cannot drift
    /// apart; the params are stored so the contract is self-describing.
    pub fn new(
        name: &'static str,
        naked_internal_pubkey: XOnlyPublicKey,
        params: &P,
        clause_tree: ClauseTree,
    ) -> Result<Self, ContractError> {
        Self::new_with_identity::<Self>(name, naked_internal_pubkey, params, clause_tree)
    }

    /// Build a contract with nominal identity `I`.
    ///
    /// This is used by `contract!`, which supplies a fresh private marker for
    /// every definition. Direct users normally want [`Self::new`].
    #[doc(hidden)]
    pub fn new_with_identity<I: 'static>(
        name: &'static str,
        naked_internal_pubkey: XOnlyPublicKey,
        params: &P,
        clause_tree: ClauseTree,
    ) -> Result<Self, ContractError> {
        Ok(Self {
            naked_internal_pubkey,
            core: P2trContractCore::new::<P, I>(name, params, clause_tree)?,
            _phantom: PhantomData,
        })
    }

    /// The taproot internal key before the state tweak (for a stateless
    /// contract, the internal key itself).
    pub fn naked_internal_pubkey(&self) -> XOnlyPublicKey {
        self.naked_internal_pubkey
    }

    /// The contract's script taptree.
    pub fn taptree(&self) -> &Arc<TapTree> {
        &self.core.taptree
    }

    /// The taproot internal key of an instance holding `state`: the naked key
    /// tweaked with the state's commitment.
    pub fn internal_key(&self, state: &S) -> Result<XOnlyPublicKey, ContractError> {
        self.internal_key_from_committed(state.commitment().as_bytes())
    }

    /// The state-tweaked internal key from the *committed* state bytes directly.
    /// This also works when the logical state is not recoverable from its
    /// commitment (e.g. a Merkle root).
    fn internal_key_from_committed(
        &self,
        committed: &[u8],
    ) -> Result<XOnlyPublicKey, ContractError> {
        apply_state_tweak(&self.naked_internal_pubkey, committed)
    }

    /// The taproot output key of an instance holding `state`.
    pub fn output_key(&self, state: &S) -> Result<XOnlyPublicKey, ContractError> {
        let internal_key = self.internal_key(state)?;
        Ok(compute_taproot_output_key(
            &internal_key,
            Some(&self.core.taptree),
        ))
    }

    /// The scriptPubKey of an instance holding `state` (pass `&()` for a
    /// stateless contract).
    pub fn script_pubkey(&self, state: &S) -> Result<ScriptBuf, ContractError> {
        let output_key = self.output_key(state)?;
        Ok(crate::script::opaque_p2tr(output_key))
    }
}

impl<P: ContractParams, S: ContractState> Debug for StandardP2TR<P, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StandardP2TR")
            .field("name", &self.core.name)
            .field("naked_internal_pubkey", &self.naked_internal_pubkey)
            .field("taptree", &"<TapTree>")
            .field("clauses", &self.core.clauses.len())
            .finish()
    }
}

impl<P: ContractParams, S: ContractState> Clone for StandardP2TR<P, S> {
    fn clone(&self) -> Self {
        Self {
            naked_internal_pubkey: self.naked_internal_pubkey,
            core: self.core.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<P: ContractParams + 'static, S: ContractState + 'static> ErasedContract
    for StandardP2TR<P, S>
{
    fn clauses(&self) -> &[Arc<dyn ErasedClause>] {
        &self.core.clauses
    }

    fn params_any(&self) -> &dyn std::any::Any {
        self.core.params_any.as_ref()
    }

    fn get_clause(&self, name: &str) -> Option<&Arc<dyn ErasedClause>> {
        self.core.get_clause(name)
    }

    fn execute_clause_from_witness(
        &self,
        clause_name: &str,
        witness: &[Vec<u8>],
        state: &dyn ErasedState,
    ) -> Result<NextOutputs, ClauseError> {
        self.core
            .execute_clause_from_witness(clause_name, witness, state)
    }

    fn contract_type_id(&self) -> std::any::TypeId {
        self.core.kind_id
    }

    fn contract_name(&self) -> &'static str {
        self.core.name
    }

    fn state_type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<S>()
    }

    fn script_pubkey(&self, commitment: &StateCommitment) -> Result<ScriptBuf, ContractError> {
        let internal_key = self.internal_key_from_committed(commitment.as_bytes())?;
        let output_key = compute_taproot_output_key(&internal_key, Some(&self.core.taptree));
        Ok(crate::script::opaque_p2tr(output_key))
    }

    fn control_block_internal_key(
        &self,
        commitment: &StateCommitment,
    ) -> Result<XOnlyPublicKey, ContractError> {
        self.internal_key_from_committed(commitment.as_bytes())
    }

    fn taptree(&self) -> &Arc<TapTree> {
        &self.core.taptree
    }
}

// ============================================================================
// Contract Instance Management
// ============================================================================

/// Status of a contract instance in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceStatus {
    /// The instance's UTXO exists and is available to spend.
    Funded,
    /// The instance has been spent in a transaction.
    Spent,
}

/// How an instance was spent: recorded once, when the manager executes or
/// observes the spending transaction.
#[derive(Debug, Clone)]
pub struct SpendRecord {
    tx: Arc<Transaction>,
    vin: usize,
    clause_name: String,
    args: Vec<Vec<u8>>,
}

impl SpendRecord {
    pub(crate) fn new(
        tx: Arc<Transaction>,
        vin: usize,
        clause_name: String,
        args: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            tx,
            vin,
            clause_name,
            args,
        }
    }

    /// The spending transaction.
    pub fn tx(&self) -> &Arc<Transaction> {
        &self.tx
    }

    /// The input of [`tx`](Self::tx) that consumed the instance.
    pub fn vin(&self) -> usize {
        self.vin
    }

    /// Name of the clause the spend went through.
    pub fn clause_name(&self) -> &str {
        &self.clause_name
    }

    /// The clause's witness arguments (the witness stack minus the tapscript
    /// and control block), in witness order. Decode them with the clause's
    /// typed `*Args` struct ([`ClauseArgs::decode_from_witness`]).
    pub fn args(&self) -> &[Vec<u8>] {
        &self.args
    }
}

/// Reject a logical state whose concrete type is not the contract's declared
/// state type (`()` for a stateless contract).
pub(crate) fn check_state_type(
    contract: &dyn ErasedContract,
    state: &dyn ErasedState,
) -> Result<(), ContractError> {
    if state.as_any().type_id() != contract.state_type_id() {
        return Err(ContractError::WrongStateType);
    }
    Ok(())
}

/// A contract instance: one UTXO, the contract it belongs to, and the state it
/// holds.
///
/// An instance always refers to an existing output: it is created funded, and
/// later either stays so or records the spend that consumed it together with
/// the child instances that spend created. Fields are private so these
/// invariants cannot be corrupted; callers inspect instances through the public
/// accessors, while the manager owns the transition to spent.
#[derive(Debug)]
pub struct ContractInstance {
    /// The contract template (type-erased for runtime polymorphism).
    contract: Arc<dyn ErasedContract>,

    /// The instance's logical state (`()` for a stateless contract). Its
    /// commitment, used for addressing, derives from it (see [`ErasedState`]).
    state: Box<dyn ErasedState>,

    /// The outpoint identifying this instance on-chain.
    outpoint: OutPoint,

    /// The transaction whose output `outpoint.vout` is this instance.
    funding_tx: Arc<Transaction>,

    /// The spend that consumed this instance (`None` while funded).
    spend: Option<SpendRecord>,

    /// Child instances created when this instance was spent.
    outputs: Vec<Rc<RefCell<ContractInstance>>>,
}

impl ContractInstance {
    /// An instance of `contract` holding `state`, at output `outpoint.vout` of
    /// `funding_tx`. The params are taken from the contract, which is
    /// self-describing.
    ///
    /// Fails if `state` is not of the contract's state type, or if the funding
    /// transaction has no such output. The caller establishes that the output
    /// pays the contract's script (see [`script_pubkey`](Self::script_pubkey)).
    pub(crate) fn funded(
        contract: Arc<dyn ErasedContract>,
        state: Box<dyn ErasedState>,
        outpoint: OutPoint,
        funding_tx: Arc<Transaction>,
    ) -> Result<Self, ContractError> {
        check_state_type(contract.as_ref(), state.as_ref())?;
        if funding_tx.output.get(outpoint.vout as usize).is_none() {
            return Err(ContractError::MissingFundingOutput(outpoint));
        }
        Ok(Self {
            contract,
            state,
            outpoint,
            funding_tx,
            spend: None,
            outputs: Vec::new(),
        })
    }

    /// The contract template.
    pub fn contract(&self) -> &Arc<dyn ErasedContract> {
        &self.contract
    }

    /// The instance's logical state (`()` for a stateless contract).
    pub fn state(&self) -> &dyn ErasedState {
        self.state.as_ref()
    }

    /// The state's explicit CCV data commitment (empty for a stateless
    /// contract).
    pub fn state_commitment(&self) -> StateCommitment {
        self.state.state_commitment()
    }

    /// The script pubkey this instance pays (the contract's, for the
    /// instance's committed state).
    pub fn script_pubkey(&self) -> Result<ScriptBuf, ContractError> {
        self.contract.script_pubkey(&self.state_commitment())
    }

    /// Current status in the instance lifecycle.
    pub fn status(&self) -> InstanceStatus {
        match self.spend {
            None => InstanceStatus::Funded,
            Some(_) => InstanceStatus::Spent,
        }
    }

    /// The outpoint identifying this instance on-chain.
    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// The UTXO this instance controls (its funding output).
    pub fn prevout(&self) -> &TxOut {
        // Checked by `funded`, the only constructor.
        &self.funding_tx.output[self.outpoint.vout as usize]
    }

    /// The amount this instance's UTXO holds.
    pub fn amount(&self) -> bitcoin::Amount {
        self.prevout().value
    }

    /// The transaction that funded this instance.
    pub fn funding_tx(&self) -> &Arc<Transaction> {
        &self.funding_tx
    }

    /// The spend that consumed this instance (`None` while funded).
    pub fn spend(&self) -> Option<&SpendRecord> {
        self.spend.as_ref()
    }

    /// The transaction that spent this instance (None until spent).
    pub fn spending_tx(&self) -> Option<&Arc<Transaction>> {
        self.spend.as_ref().map(SpendRecord::tx)
    }

    /// Transaction ID that spent this instance (None until spent).
    pub fn spent_in_tx(&self) -> Option<Txid> {
        self.spend.as_ref().map(|spend| spend.tx.compute_txid())
    }

    /// The input index of the spending transaction that consumed this instance
    /// (None until spent).
    pub fn spending_vin(&self) -> Option<usize> {
        self.spend.as_ref().map(SpendRecord::vin)
    }

    /// Name of the clause used to spend this instance (None until spent).
    pub fn clause_name(&self) -> Option<&str> {
        self.spend.as_ref().map(SpendRecord::clause_name)
    }

    /// The clause's witness arguments used by the spend, in witness order (None
    /// until spent). Decode them with the clause's typed `*Args` struct
    /// ([`ClauseArgs::decode_from_witness`]).
    pub fn spending_args(&self) -> Option<&[Vec<u8>]> {
        self.spend.as_ref().map(SpendRecord::args)
    }

    /// Child instances created when this instance was spent.
    pub fn outputs(&self) -> &[Rc<RefCell<ContractInstance>>] {
        &self.outputs
    }

    /// Record the spend that consumed this instance.
    pub(crate) fn mark_spent(&mut self, spend: SpendRecord) {
        self.spend = Some(spend);
    }

    /// Add a child instance created from spending this instance.
    pub(crate) fn add_output(&mut self, instance: Rc<RefCell<ContractInstance>>) {
        if !self
            .outputs
            .iter()
            .any(|existing| Rc::ptr_eq(existing, &instance))
        {
            self.outputs.push(instance);
        }
    }
}
