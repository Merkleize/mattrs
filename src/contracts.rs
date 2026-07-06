//! Core contract model: typed clauses, taproot trees, and contract templates.
//!
//! The types here layer as follows:
//!
//! - **Witness encoding** — [`WitnessEncodable`] turns values into script-facing
//!   witness-stack elements; a clause's [`ClauseArgs`] and a state's
//!   [`ContractState`] leaves use it (so their bytes are exactly what the covenant
//!   reads). [`ParamEncodable`] is the separate *internal* serialization for
//!   [`ContractParams`] — a superset that also covers the fixed-width unsigned
//!   integers, which are deliberately not valid witness elements. Contracts declare
//!   these per-role encodings via the derive macros. [`ErasedState`] carries a
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
//! - **Contracts** — [`StandardP2TR`] (plain internal key) and
//!   [`StandardAugmentedP2TR`] (state-tweaked internal key) wrap a clause tree
//!   plus encoded params; [`ErasedContract`] is their type-erased view.
//! - **Instances** — a [`ContractInstance`] tracks one UTXO of a contract
//!   through its funded/spent lifecycle (driven by the
//!   [`ContractManager`](crate::manager::ContractManager)).

use std::{cell::RefCell, fmt, fmt::Debug, marker::PhantomData, rc::Rc, sync::Arc};

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
    /// Data has the wrong shape or content for the type being decoded.
    InvalidData(String),
    /// The input ended before a complete value could be decoded.
    InsufficientData,
    /// A lower-level decoding step failed.
    DecodingFailed(String),
    /// The witness stack doesn't have enough elements to deserialize.
    StackUnderflow,
    /// A value is invalid for its type (e.g., oversized integer, wrong-length pubkey).
    InvalidValue(String),
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WitnessError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            WitnessError::InsufficientData => write!(f, "Insufficient data in witness"),
            WitnessError::DecodingFailed(msg) => write!(f, "Decoding failed: {}", msg),
            WitnessError::StackUnderflow => write!(f, "Witness stack underflow"),
            WitnessError::InvalidValue(msg) => write!(f, "Invalid value: {}", msg),
        }
    }
}

impl std::error::Error for WitnessError {}

/// Errors from executing a clause (computing its next outputs).
#[derive(Debug)]
pub enum ClauseError {
    /// The spend's witness stack could not be decoded into the clause's arguments.
    Witness(WitnessError),
    /// Any other clause-specific failure.
    Other(String),
}

impl fmt::Display for ClauseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClauseError::Witness(e) => write!(f, "Witness error: {}", e),
            ClauseError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ClauseError {}

impl From<WitnessError> for ClauseError {
    fn from(e: WitnessError) -> Self {
        ClauseError::Witness(e)
    }
}

/// Errors from contract address / key-derivation operations.
#[derive(Debug)]
pub enum ContractError {
    /// An augmented-contract operation needs state but none was provided.
    MissingState,
    /// Failed to decode the contract state.
    StateDecoding(WitnessError),
    /// A taproot / secp256k1 key operation failed (tweak, parse, ...).
    Key(String),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::MissingState => write!(f, "state required for augmented contract"),
            ContractError::StateDecoding(e) => write!(f, "failed to decode state: {}", e),
            ContractError::Key(msg) => write!(f, "key operation failed: {}", msg),
        }
    }
}

impl std::error::Error for ContractError {}

impl From<WitnessError> for ContractError {
    fn from(e: WitnessError) -> Self {
        ContractError::StateDecoding(e)
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Opcode for CHECKTEMPLATEVERIFY
pub const OP_CHECKTEMPLATEVERIFY: u8 = 0xb3;

/// CCV flag: Check the input (validate introspection)
pub const CCV_FLAG_CHECK_INPUT: i32 = -1;

/// CCV flag: Ignore output amount
pub const CCV_FLAG_IGNORE_OUTPUT_AMOUNT: i32 = 1;

/// CCV flag: Deduct output amount from current input
pub const CCV_FLAG_DEDUCT_OUTPUT_AMOUNT: i32 = 2;

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
///
/// The *internal*, non-consensus serialization used to carry a contract's params
/// is a separate trait, [`ParamEncodable`] — which every `WitnessEncodable` type
/// satisfies for free, plus the fixed-width unsigned integers that are deliberately
/// **not** valid witness elements. Keeping the two apart means a value whose
/// encoding is not a valid script element (e.g. a little-endian `u32`) cannot reach
/// a clause argument or a state commitment; use `i64` for anything a script reads.
///
/// # Witness Stack Format
///
/// The witness stack is represented as a vector of byte vectors (`Vec<Vec<u8>>`),
/// where each inner `Vec<u8>` represents a single witness element.
pub trait WitnessEncodable {
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

/// Serialization of a **contract-params field** — the internal, round-trippable
/// encoding the `#[derive(ContractParams)]` codec frames to carry a contract's
/// params on its instance. It is *not* a consensus/witness format.
///
/// Every [`WitnessEncodable`] type is `ParamEncodable` for free (via the blanket
/// impl below), so params can hold hashes, keys, and script-number integers. In
/// addition, the fixed-width **unsigned** integers (`u8`/`u16`/`u32`/`u64`) are
/// `ParamEncodable` *only*: their little-endian bytes are not a valid Bitcoin
/// script number, so they must never be a witness element. That exclusion is the
/// point of the split — it is a compile error to use a `u32` as a clause argument
/// or a state leaf; use `i64` for anything a script reads.
pub trait ParamEncodable {
    /// Encode into the framed-serialization elements the params codec wraps.
    fn encode_param(&self) -> Vec<Vec<u8>>;

    /// Decode from those elements, returning the value and the number consumed.
    fn decode_param(elements: &[Vec<u8>]) -> Result<(Self, usize), WitnessError>
    where
        Self: Sized;
}

/// Every witness element is trivially usable as a params field (same encoding).
/// The fixed-width unsigned integers add their own `ParamEncodable` impls below,
/// and are the only `ParamEncodable` types that are *not* `WitnessEncodable`.
impl<T: WitnessEncodable> ParamEncodable for T {
    fn encode_param(&self) -> Vec<Vec<u8>> {
        self.encode_to_witness()
    }

    fn decode_param(elements: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        Self::decode_from_witness(elements)
    }
}

// ============================================================================
// WitnessEncodable implementations for common types
// ============================================================================

/// Signed integers use Bitcoin Script's number format (`bn2vch`), one element.
macro_rules! impl_scriptnum_witness {
    ($($t:ty),+ $(,)?) => {$(
        impl WitnessEncodable for $t {
            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                vec![crate::script_utils::bn2vch(*self as i64)]
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
                if witness.is_empty() {
                    return Err(WitnessError::StackUnderflow);
                }
                let val = crate::script_utils::vch2bn(&witness[0])
                    .map_err(|e| WitnessError::DecodingFailed(e.to_string()))?;
                Ok((val as $t, 1))
            }
        }
    )+};
}

impl_scriptnum_witness!(i32, i64);

impl<const N: usize> WitnessEncodable for [u8; N] {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.to_vec()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        if witness[0].len() != N {
            return Err(WitnessError::InvalidValue(format!(
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

impl WitnessEncodable for Vec<u8> {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.clone()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        Ok((witness[0].clone(), 1))
    }
}

/// Unsigned integers serialize as their fixed-width little-endian bytes, one
/// element. They are [`ParamEncodable`] only — deliberately *not* witness elements,
/// since a fixed-width LE encoding is not a valid Bitcoin script number.
macro_rules! impl_le_param {
    ($($t:ty),+ $(,)?) => {$(
        impl ParamEncodable for $t {
            fn encode_param(&self) -> Vec<Vec<u8>> {
                vec![self.to_le_bytes().to_vec()]
            }

            fn decode_param(elements: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
                let first = elements.first().ok_or(WitnessError::StackUnderflow)?;
                let bytes: [u8; std::mem::size_of::<$t>()] =
                    first.as_slice().try_into().map_err(|_| {
                        WitnessError::InvalidValue(format!(
                            "Expected {} bytes for {}, got {}",
                            std::mem::size_of::<$t>(),
                            stringify!($t),
                            first.len()
                        ))
                    })?;
                Ok((<$t>::from_le_bytes(bytes), 1))
            }
        }
    )+};
}

impl_le_param!(u8, u16, u32, u64);

impl WitnessEncodable for bool {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![vec![if *self { 1 } else { 0 }]]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        if witness[0].len() != 1 {
            return Err(WitnessError::InvalidValue(format!(
                "Expected 1 byte for bool, got {}",
                witness[0].len()
            )));
        }
        Ok((witness[0][0] != 0, 1))
    }
}

impl WitnessEncodable for XOnlyPublicKey {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.serialize().to_vec()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        if witness[0].len() != 32 {
            return Err(WitnessError::InvalidValue(format!(
                "Expected 32 bytes for XOnlyPublicKey, got {}",
                witness[0].len()
            )));
        }
        let key = XOnlyPublicKey::from_slice(&witness[0])
            .map_err(|e| WitnessError::DecodingFailed(e.to_string()))?;
        Ok((key, 1))
    }
}

impl<T: WitnessEncodable> WitnessEncodable for Option<T> {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        match self {
            Some(value) => {
                let mut result = vec![vec![1u8]]; // presence flag
                result.extend(value.encode_to_witness());
                result
            }
            None => vec![vec![0u8]], // absence flag
        }
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }

        if witness[0].is_empty() || witness[0][0] == 0 {
            Ok((None, 1))
        } else {
            let (value, consumed) = T::decode_from_witness(&witness[1..])?;
            Ok((Some(value), consumed + 1))
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
pub struct Signature(pub Vec<u8>);

impl Signature {
    /// Wrap raw signature bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Signature(bytes)
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

impl From<Vec<u8>> for Signature {
    fn from(bytes: Vec<u8>) -> Self {
        Signature(bytes)
    }
}

impl WitnessEncodable for Signature {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.0.clone()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        let first = witness.first().ok_or(WitnessError::StackUnderflow)?;
        Ok((Signature(first.clone()), 1))
    }
}

// ============================================================================
// Marker Trait Implementations
// ============================================================================
/// Contract parameters.
///
/// `encode`/`decode` are an internal, round-trippable serialization used to carry
/// params alongside a contract instance (it is *not* a consensus format). The
/// `#[derive(ContractParams)]` implementation frames each field so it can be
/// decoded back: for every field it writes the field's witness elements as
/// `u32-LE element_count`, then for each element `u32-LE length` followed by the
/// element bytes. Decoding reverses this, field by field.
pub trait ContractParams: Debug + Clone + Send + Sync {
    /// Encode parameters to bytes.
    fn encode(&self) -> Vec<u8>;

    /// Decode parameters from bytes.
    fn decode(bytes: &[u8]) -> Result<Self, WitnessError>
    where
        Self: Sized;
}

/// Trait for contract state.
pub trait ContractState: Debug + Clone + Send + Sync {
    /// Encode the state to bytes (typically 32 bytes for hash commitment).
    fn encode(&self) -> Vec<u8>;

    /// Decode state from bytes.
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

// Implement ContractParams/ContractState for () to support stateless, paramless
// contracts (e.g. terminal clauses that never compute next outputs).
impl ContractParams for () {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode(_bytes: &[u8]) -> Result<Self, WitnessError> {
        Ok(())
    }
}

impl ContractState for () {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode(_bytes: &[u8]) -> Result<Self, WitnessError> {
        Ok(())
    }
}

/// Type-erased *logical* contract state carried on an instance.
///
/// A contract's on-chain commitment is `ContractState::encode` (a fixed-size
/// taproot state tweak), but its *logical* state can be richer than that
/// commitment — e.g. a RAM cell vector committed only as a Merkle root. Since the
/// commitment is generally not invertible, an instance keeps the full typed state
/// here (in erased form) so a clause's `next_outputs` can read it. `encode` still
/// yields the committed bytes; `as_any` recovers the concrete `ContractState`.
pub trait ErasedState: Debug + Send + Sync {
    /// The committed state bytes (same as [`ContractState::encode`]). Named
    /// distinctly to avoid clashing with `ContractState::encode` on types that
    /// implement both.
    fn committed_bytes(&self) -> Vec<u8>;

    /// Downcast handle to the concrete state type.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Clone into a box.
    fn clone_boxed(&self) -> Box<dyn ErasedState>;
}

impl<S: ContractState + 'static> ErasedState for S {
    fn committed_bytes(&self) -> Vec<u8> {
        <Self as ContractState>::encode(self)
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

/// Defines the semantic of a clause with respect to an output's amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClauseOutputAmountBehaviour {
    /// The output should be at least as large as the input.
    PreserveOutput,
    /// The output amount is not checked.
    IgnoreOutput,
    /// The output amount is subtracted from the input.
    DeductOutput,
}

/// Which transaction output a clause output refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputIndex {
    /// The output index equals the spending input's index.
    Same,
    /// An explicit output index.
    Explicit(u32),
}

/// Represents a specific output defined by a contract clause.
///
/// The next contract carries its own params (see [`ErasedContract::params_bytes`]),
/// so a clause output only needs to name the output, its (optional) state, and how
/// its amount relates to the input.
#[derive(Debug, Clone)]
pub struct ClauseOutput {
    /// Which transaction output this refers to.
    pub index: OutputIndex,
    /// The contract of this output.
    pub next_contract: Arc<dyn ErasedContract>,
    /// The next instance's logical state; its committed bytes (the taproot state
    /// commitment used for addressing) derive from it (see [`ErasedState`]).
    pub next_state: Option<Box<dyn ErasedState>>,
    /// Determines the semantic of the output amount.
    pub next_amount: ClauseOutputAmountBehaviour,
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
    pub fn at(index: u32) -> ClauseOutputTo {
        ClauseOutputTo(OutputIndex::Explicit(index))
    }

    /// Start building a clause output whose index matches the spending input.
    pub fn at_same_index() -> ClauseOutputTo {
        ClauseOutputTo(OutputIndex::Same)
    }

    /// Create a terminal output set (no next contract).
    /// Useful for recovery or withdrawal clauses that don't constrain the output.
    pub fn terminal() -> Vec<ClauseOutput> {
        Vec::new()
    }

    /// The committed state bytes of the next instance (its taproot commitment).
    pub fn committed_state_bytes(&self) -> Option<Vec<u8>> {
        self.next_state.as_ref().map(|s| s.committed_bytes())
    }
}

/// First stage of the [`ClauseOutput`] builder: the output's contract must be set
/// (with [`to`](Self::to)) before anything else, so a finished builder can never
/// lack one.
pub struct ClauseOutputTo(OutputIndex);

impl ClauseOutputTo {
    /// Set the next contract for this output.
    pub fn to(self, contract: Arc<dyn ErasedContract>) -> ClauseOutputBuilder {
        ClauseOutputBuilder {
            index: self.0,
            next_contract: contract,
            next_state: None,
            next_amount: ClauseOutputAmountBehaviour::PreserveOutput,
        }
    }
}

/// Builder for [`ClauseOutput`] with a fluent API.
pub struct ClauseOutputBuilder {
    index: OutputIndex,
    next_contract: Arc<dyn ErasedContract>,
    next_state: Option<Box<dyn ErasedState>>,
    next_amount: ClauseOutputAmountBehaviour,
}

impl ClauseOutputBuilder {
    /// Set the state for the next contract. The committed bytes (for addressing)
    /// derive from it, and the child instance carries it for its own future spends.
    pub fn with_state<S: ContractState + 'static>(mut self, state: &S) -> Self {
        self.next_state = Some(Box::new(state.clone()));
        self
    }

    /// Set amount behaviour to preserve output (default).
    pub fn preserve_amount(mut self) -> Self {
        self.next_amount = ClauseOutputAmountBehaviour::PreserveOutput;
        self
    }

    /// Set amount behaviour to ignore output.
    pub fn ignore_amount(mut self) -> Self {
        self.next_amount = ClauseOutputAmountBehaviour::IgnoreOutput;
        self
    }

    /// Set amount behaviour to deduct from input.
    pub fn deduct_amount(mut self) -> Self {
        self.next_amount = ClauseOutputAmountBehaviour::DeductOutput;
        self
    }

    /// Build the [`ClauseOutput`].
    pub fn build(self) -> ClauseOutput {
        ClauseOutput {
            index: self.index,
            next_contract: self.next_contract,
            next_state: self.next_state,
            next_amount: self.next_amount,
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
/// Either a set of covenant ([`ClauseOutput`]) outputs whose amounts are derived
/// from the input, or a fixed CTV [`CtvTemplate`]. A clause with no next-outputs
/// function is terminal and yields `Contracts(vec![])`.
#[derive(Debug, Clone)]
pub enum NextOutputs {
    /// `CHECKCONTRACTVERIFY` outputs — (possibly stateful) contracts, amounts derived.
    Contracts(Vec<ClauseOutput>),
    /// A fixed `CHECKTEMPLATEVERIFY` template — terminal (no child instances).
    Template(CtvTemplate),
}

impl From<Vec<ClauseOutput>> for NextOutputs {
    fn from(outputs: Vec<ClauseOutput>) -> Self {
        NextOutputs::Contracts(outputs)
    }
}

impl From<CtvTemplate> for NextOutputs {
    fn from(template: CtvTemplate) -> Self {
        NextOutputs::Template(template)
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
/// `StandardP2TR::new` / `StandardAugmentedP2TR::new`.
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

/// Debug-only check that clause names within a contract are unique. Duplicate
/// names would make `get_clause` ambiguous and almost certainly indicate a bug.
fn debug_assert_no_duplicate_clauses(clauses: &[Arc<dyn ErasedClause>]) {
    if cfg!(debug_assertions) {
        let mut seen = std::collections::HashSet::new();
        for clause in clauses {
            debug_assert!(
                seen.insert(clause.name()),
                "duplicate clause name in contract: {}",
                clause.name()
            );
        }
    }
}

// ============================================================================
// Key Tweaking Utilities
// ============================================================================

/// Compute a tweaked key for augmented contracts with state commitment.
/// Uses SHA256(naked_key || state_hash) to derive the tweak.
pub fn compute_state_tweak(naked_key: &[u8; 32], state_hash: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(naked_key);
    data.extend_from_slice(state_hash);
    let hash = sha256::Hash::hash(&data);
    *hash.as_byte_array()
}

/// Apply a state tweak to a public key.
pub fn apply_state_tweak(
    naked_key: &XOnlyPublicKey,
    state_hash: &[u8; 32],
) -> Result<XOnlyPublicKey, ContractError> {
    let tweak_bytes = compute_state_tweak(&naked_key.serialize(), state_hash);

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

    /// Compute next outputs from the spend's witness stack (args in witness order).
    ///
    /// The witness stack is the authoritative, ordered argument encoding; params and
    /// state are the instance's encoded bytes. This decodes them into the clause's
    /// concrete types and runs the typed `next_outputs`.
    fn next_outputs_from_witness(
        &self,
        params_bytes: &[u8],
        witness: &[Vec<u8>],
        state: Option<&dyn ErasedState>,
    ) -> Result<NextOutputs, ClauseError>;

    /// Clone into a Box.
    fn clone_boxed(&self) -> Box<dyn ErasedClause>;
}

impl Clone for Box<dyn ErasedClause> {
    fn clone(&self) -> Self {
        self.clone_boxed()
    }
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

    /// If this argument is a signature, the x-only pubkey expected to sign it.
    ///
    /// Returns `Some(pubkey)` for signature arguments (so the manager knows which
    /// key must sign this witness element) and `None` for all other types. The
    /// element is assumed to be a single witness item.
    fn signer_pubkey(&self) -> Option<[u8; 32]> {
        None
    }

    /// Clone into a Box.
    fn clone_boxed(&self) -> Box<dyn ArgType>;
}

impl Clone for Box<dyn ArgType> {
    fn clone(&self) -> Self {
        self.clone_boxed()
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
    Arc<dyn Fn(&P, &A, Option<&S>) -> Result<NextOutputs, ClauseError> + Send + Sync>;

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
    _phantom: PhantomData<(P, S, A)>,
}

impl<P, S, A> StandardClause<P, S, A>
where
    P: ContractParams + 'static,
    S: ContractState + 'static,
    A: ClauseArgs + 'static,
{
    /// Build a clause from its name, tapscript, witness-layout specs, and the
    /// optional function computing its next outputs (`None` = terminal clause).
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
            _phantom: PhantomData,
        }
    }

    /// Compute next outputs from typed parameters, arguments and state. A clause
    /// without a next-outputs function is terminal and yields no outputs.
    pub fn next_outputs(
        &self,
        params: &P,
        args: &A,
        state: Option<&S>,
    ) -> Result<NextOutputs, ClauseError> {
        if let Some(ref f) = self.next_outputs_fn {
            f(params, args, state)
        } else {
            Ok(NextOutputs::Contracts(Vec::new()))
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

    fn next_outputs_from_witness(
        &self,
        params_bytes: &[u8],
        witness: &[Vec<u8>],
        state: Option<&dyn ErasedState>,
    ) -> Result<NextOutputs, ClauseError> {
        // Decode params
        let params = P::decode(params_bytes)
            .map_err(|e| ClauseError::Other(format!("Failed to decode params: {}", e)))?;

        // Recover the typed state: prefer the instance's logical state (downcast),
        // falling back to decoding the committed bytes for round-tripping states.
        let state: Option<S> = match state {
            Some(erased) => match erased.as_any().downcast_ref::<S>() {
                Some(typed) => Some(typed.clone()),
                None => Some(S::decode(&erased.committed_bytes())?),
            },
            None => None,
        };

        // The witness stack is already the ordered argument encoding; decode it
        // straight into the concrete Args type (no HashMap round-trip).
        let concrete_args = A::decode_from_witness(witness)?;

        // Call the typed version
        self.next_outputs(&params, &concrete_args, state.as_ref())
    }

    fn clone_boxed(&self) -> Box<dyn ErasedClause> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Contract Traits
// ============================================================================

/// Type-erased contract for runtime polymorphism.
pub trait ErasedContract: Debug + Send + Sync {
    /// Get all clauses (type-erased).
    fn clauses(&self) -> &[Arc<dyn ErasedClause>];

    /// The contract's encoded params. A contract is self-describing, so child
    /// instances created by a clause can recover their params from here.
    fn params_bytes(&self) -> &[u8];

    /// Get a clause by name.
    fn get_clause(&self, name: &str) -> Option<&Arc<dyn ErasedClause>>;

    /// Execute a clause (selected by name) against a spend's witness stack and
    /// return the next outputs. The contract's own (encoded) params are used.
    fn execute_clause_from_witness(
        &self,
        clause_name: &str,
        witness: &[Vec<u8>],
        state: Option<&dyn ErasedState>,
    ) -> Result<NextOutputs, ClauseError>;

    /// The `TypeId` of the concrete contract type, used to check that a
    /// type-erased instance is the contract a typed handle expects.
    fn contract_type_id(&self) -> std::any::TypeId;

    /// A human-readable contract name (e.g. `"Vault"`), for introspection and
    /// display; not consensus-visible.
    fn contract_name(&self) -> &'static str;

    /// Get the script pubkey for this contract (with optional state).
    fn script_pubkey(&self, state_bytes: Option<&[u8]>) -> Result<ScriptBuf, ContractError>;

    /// Get the internal pubkey to use for control block generation.
    /// For augmented contracts with state, this may be state-tweaked.
    fn control_block_internal_key(
        &self,
        state_bytes: Option<&[u8]>,
    ) -> Result<XOnlyPublicKey, ContractError>;

    /// Get the taptree for this contract.
    fn taptree(&self) -> &Arc<TapTree>;

    /// Clone into a Box.
    fn clone_boxed(&self) -> Box<dyn ErasedContract>;
}

impl Clone for Box<dyn ErasedContract> {
    fn clone(&self) -> Self {
        self.clone_boxed()
    }
}

// ============================================================================
// Standard P2TR Contracts
// ============================================================================

/// The clause/taptree/params core shared by [`StandardP2TR`] and
/// [`StandardAugmentedP2TR`]. The two wrappers differ only in how the taproot
/// internal key is derived (plain vs. state-tweaked).
#[derive(Clone)]
struct P2trContractCore {
    /// A human-readable contract name (e.g. `"Vault"`), for introspection and
    /// display; not consensus-visible.
    name: &'static str,
    taptree: Arc<TapTree>,
    clauses: Vec<Arc<dyn ErasedClause>>,
    /// Encoded params, so the contract is self-describing and child instances can
    /// recover their params without a separate `next_params` carrier.
    params_bytes: Vec<u8>,
}

impl P2trContractCore {
    /// Derive the script taptree and the clause list from one `clause_tree`, so
    /// they cannot drift apart.
    fn new<P: ContractParams>(name: &'static str, params: &P, clause_tree: ClauseTree) -> Self {
        let taptree = Arc::new(clause_tree.to_script_tree());
        let clauses = clause_tree.clauses();
        debug_assert_no_duplicate_clauses(&clauses);
        Self {
            name,
            taptree,
            clauses,
            params_bytes: params.encode(),
        }
    }

    fn get_clause(&self, name: &str) -> Option<&Arc<dyn ErasedClause>> {
        self.clauses.iter().find(|c| c.name() == name)
    }

    fn execute_clause_from_witness(
        &self,
        clause_name: &str,
        witness: &[Vec<u8>],
        state: Option<&dyn ErasedState>,
    ) -> Result<NextOutputs, ClauseError> {
        let clause = self
            .get_clause(clause_name)
            .ok_or_else(|| ClauseError::Other(format!("Clause {} not found", clause_name)))?;

        clause.next_outputs_from_witness(&self.params_bytes, witness, state)
    }
}

/// Standard P2TR contract with clauses.
pub struct StandardP2TR<P: ContractParams> {
    internal_pubkey: XOnlyPublicKey,
    core: P2trContractCore,
    _phantom: PhantomData<P>,
}

impl<P: ContractParams> StandardP2TR<P> {
    /// Build a contract from its params and a clause tree. The script taptree and
    /// the clause list are both derived from `clause_tree`, so they cannot drift
    /// apart; the encoded params are stored so the contract is self-describing.
    pub fn new(
        name: &'static str,
        internal_pubkey: XOnlyPublicKey,
        params: &P,
        clause_tree: ClauseTree,
    ) -> Self {
        Self {
            internal_pubkey,
            core: P2trContractCore::new(name, params, clause_tree),
            _phantom: PhantomData,
        }
    }

    /// The taproot internal key.
    pub fn internal_pubkey(&self) -> XOnlyPublicKey {
        self.internal_pubkey
    }

    /// The contract's script taptree.
    pub fn taptree(&self) -> &Arc<TapTree> {
        &self.core.taptree
    }

    /// Get the taproot output key for this contract.
    pub fn output_key(&self) -> XOnlyPublicKey {
        compute_taproot_output_key(&self.internal_pubkey, Some(&self.core.taptree))
    }

    /// Get the scriptPubKey for this contract (OP_1 <output_key>).
    pub fn script_pubkey(&self) -> ScriptBuf {
        crate::script_helpers::opaque_p2tr(self.output_key())
    }
}

impl<P: ContractParams> Debug for StandardP2TR<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StandardP2TR")
            .field("internal_pubkey", &self.internal_pubkey)
            .field("taptree", &"<TapTree>")
            .field("clauses", &self.core.clauses.len())
            .finish()
    }
}

impl<P: ContractParams> Clone for StandardP2TR<P> {
    fn clone(&self) -> Self {
        Self {
            internal_pubkey: self.internal_pubkey,
            core: self.core.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<P: ContractParams + 'static> ErasedContract for StandardP2TR<P> {
    fn clauses(&self) -> &[Arc<dyn ErasedClause>] {
        &self.core.clauses
    }

    fn params_bytes(&self) -> &[u8] {
        &self.core.params_bytes
    }

    fn get_clause(&self, name: &str) -> Option<&Arc<dyn ErasedClause>> {
        self.core.get_clause(name)
    }

    fn execute_clause_from_witness(
        &self,
        clause_name: &str,
        witness: &[Vec<u8>],
        state: Option<&dyn ErasedState>,
    ) -> Result<NextOutputs, ClauseError> {
        self.core
            .execute_clause_from_witness(clause_name, witness, state)
    }

    fn contract_type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<Self>()
    }

    fn contract_name(&self) -> &'static str {
        self.core.name
    }

    fn script_pubkey(&self, _state_bytes: Option<&[u8]>) -> Result<ScriptBuf, ContractError> {
        Ok(self.script_pubkey())
    }

    fn control_block_internal_key(
        &self,
        _state_bytes: Option<&[u8]>,
    ) -> Result<XOnlyPublicKey, ContractError> {
        Ok(self.internal_pubkey)
    }

    fn taptree(&self) -> &Arc<TapTree> {
        &self.core.taptree
    }

    fn clone_boxed(&self) -> Box<dyn ErasedContract> {
        Box::new(self.clone())
    }
}

/// The 32-byte value an augmented internal key is tweaked with: the committed
/// state bytes themselves when exactly 32 bytes, else their sha256.
fn state_hash(committed: &[u8]) -> [u8; 32] {
    match committed.try_into() {
        Ok(arr) => arr,
        Err(_) => *sha256::Hash::hash(committed).as_byte_array(),
    }
}

/// Standard Augmented P2TR contract with state.
pub struct StandardAugmentedP2TR<P: ContractParams, S: ContractState> {
    naked_internal_pubkey: XOnlyPublicKey,
    core: P2trContractCore,
    _phantom: PhantomData<(P, S)>,
}

impl<P: ContractParams, S: ContractState> StandardAugmentedP2TR<P, S> {
    /// Build an augmented contract from its params and a clause tree. The script
    /// taptree and the clause list are both derived from `clause_tree`, so they
    /// cannot drift apart; the encoded params are stored to be self-describing.
    pub fn new(
        name: &'static str,
        naked_internal_pubkey: XOnlyPublicKey,
        params: &P,
        clause_tree: ClauseTree,
    ) -> Self {
        Self {
            naked_internal_pubkey,
            core: P2trContractCore::new(name, params, clause_tree),
            _phantom: PhantomData,
        }
    }

    /// The taproot internal key before the state tweak.
    pub fn naked_internal_pubkey(&self) -> XOnlyPublicKey {
        self.naked_internal_pubkey
    }

    /// The contract's script taptree.
    pub fn taptree(&self) -> &Arc<TapTree> {
        &self.core.taptree
    }

    /// Compute the internal pubkey tweaked with the state.
    pub fn compute_internal_key(&self, state: &S) -> Result<XOnlyPublicKey, ContractError> {
        self.internal_key_from_committed(&state.encode())
    }

    /// The state-tweaked internal key from the *committed* state bytes directly,
    /// without decoding to `S`. This also works when the logical state is not
    /// recoverable from its commitment (e.g. a Merkle root).
    fn internal_key_from_committed(
        &self,
        committed: &[u8],
    ) -> Result<XOnlyPublicKey, ContractError> {
        apply_state_tweak(&self.naked_internal_pubkey, &state_hash(committed))
    }

    /// Get the taproot output key for this contract with the given state.
    pub fn output_key(&self, state: &S) -> Result<XOnlyPublicKey, ContractError> {
        let internal_key = self.compute_internal_key(state)?;
        Ok(compute_taproot_output_key(
            &internal_key,
            Some(&self.core.taptree),
        ))
    }

    /// Get the scriptPubKey for this contract with the given state.
    pub fn script_pubkey(&self, state: &S) -> Result<ScriptBuf, ContractError> {
        let output_key = self.output_key(state)?;
        Ok(crate::script_helpers::opaque_p2tr(output_key))
    }
}

impl<P: ContractParams, S: ContractState> Debug for StandardAugmentedP2TR<P, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StandardAugmentedP2TR")
            .field("naked_internal_pubkey", &self.naked_internal_pubkey)
            .field("taptree", &"<TapTree>")
            .field("clauses", &self.core.clauses.len())
            .finish()
    }
}

impl<P: ContractParams, S: ContractState> Clone for StandardAugmentedP2TR<P, S> {
    fn clone(&self) -> Self {
        Self {
            naked_internal_pubkey: self.naked_internal_pubkey,
            core: self.core.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<P: ContractParams + 'static, S: ContractState + 'static> ErasedContract
    for StandardAugmentedP2TR<P, S>
{
    fn clauses(&self) -> &[Arc<dyn ErasedClause>] {
        &self.core.clauses
    }

    fn params_bytes(&self) -> &[u8] {
        &self.core.params_bytes
    }

    fn get_clause(&self, name: &str) -> Option<&Arc<dyn ErasedClause>> {
        self.core.get_clause(name)
    }

    fn execute_clause_from_witness(
        &self,
        clause_name: &str,
        witness: &[Vec<u8>],
        state: Option<&dyn ErasedState>,
    ) -> Result<NextOutputs, ClauseError> {
        self.core
            .execute_clause_from_witness(clause_name, witness, state)
    }

    fn contract_type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<Self>()
    }

    fn contract_name(&self) -> &'static str {
        self.core.name
    }

    fn script_pubkey(&self, state_bytes: Option<&[u8]>) -> Result<ScriptBuf, ContractError> {
        let committed = state_bytes.ok_or(ContractError::MissingState)?;
        let internal_key = self.internal_key_from_committed(committed)?;
        let output_key = compute_taproot_output_key(&internal_key, Some(&self.core.taptree));
        Ok(crate::script_helpers::opaque_p2tr(output_key))
    }

    fn control_block_internal_key(
        &self,
        state_bytes: Option<&[u8]>,
    ) -> Result<XOnlyPublicKey, ContractError> {
        let committed = state_bytes.ok_or(ContractError::MissingState)?;
        self.internal_key_from_committed(committed)
    }

    fn taptree(&self) -> &Arc<TapTree> {
        &self.core.taptree
    }

    fn clone_boxed(&self) -> Box<dyn ErasedContract> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Contract Instance Management
// ============================================================================

/// Status of a contract instance in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceStatus {
    /// Instance has been created but not yet funded on-chain.
    Unfunded,
    /// Instance has been funded and is available to spend.
    Funded,
    /// Instance has been spent in a transaction.
    Spent,
}

/// A contract instance representing a specific UTXO with associated contract and state.
///
/// Instances track the lifecycle of a contract from creation through funding to spending,
/// and maintain references to child instances created when spent. Fields are private so
/// the lifecycle invariants (status vs. outpoint/funding tx) cannot be corrupted; use
/// the accessors and [`mark_funded`](Self::mark_funded) / [`mark_spent`](Self::mark_spent).
#[derive(Debug)]
pub struct ContractInstance {
    /// The contract template (type-erased for runtime polymorphism).
    contract: Arc<dyn ErasedContract>,

    /// The instance's logical state (None for non-augmented contracts). Its
    /// committed bytes — the taproot state commitment used for addressing —
    /// derive from it (see [`ErasedState`]).
    state: Option<Box<dyn ErasedState>>,

    /// The outpoint identifying this instance on-chain (None until funded).
    outpoint: Option<OutPoint>,

    /// The transaction that funded this instance (None until funded).
    funding_tx: Option<Transaction>,

    /// Current status in the instance lifecycle.
    status: InstanceStatus,

    /// Transaction ID that spent this instance (None until spent).
    spent_in_tx: Option<Txid>,

    /// The input index of the spending transaction that consumed this instance
    /// (None until spent).
    spending_vin: Option<usize>,

    /// Name of the clause used to spend this instance (None until spent).
    clause_name: Option<String>,

    /// The clause's witness arguments used by the spend (the witness stack minus
    /// the tapscript/control block), in witness order (None until spent). Decode
    /// them with the clause's typed `*Args` struct.
    spending_args: Option<Vec<Vec<u8>>>,

    /// Child instances created when this instance was spent.
    outputs: Vec<Rc<RefCell<ContractInstance>>>,
}

impl ContractInstance {
    /// Create a new unfunded instance. The params are taken from the contract,
    /// which is self-describing; the committed state bytes derive from `state`.
    pub fn new(contract: Arc<dyn ErasedContract>, state: Option<Box<dyn ErasedState>>) -> Self {
        Self {
            contract,
            state,
            outpoint: None,
            funding_tx: None,
            status: InstanceStatus::Unfunded,
            spent_in_tx: None,
            spending_vin: None,
            clause_name: None,
            spending_args: None,
            outputs: Vec::new(),
        }
    }

    /// The contract template.
    pub fn contract(&self) -> &Arc<dyn ErasedContract> {
        &self.contract
    }

    /// The instance's logical state, if any.
    pub fn state(&self) -> Option<&dyn ErasedState> {
        self.state.as_deref()
    }

    /// The committed state bytes (the taproot state commitment used for
    /// addressing), if the instance has state.
    pub fn committed_state_bytes(&self) -> Option<Vec<u8>> {
        self.state.as_ref().map(|s| s.committed_bytes())
    }

    /// Current status in the instance lifecycle.
    pub fn status(&self) -> InstanceStatus {
        self.status
    }

    /// The outpoint identifying this instance on-chain (None until funded).
    pub fn outpoint(&self) -> Option<OutPoint> {
        self.outpoint
    }

    /// The UTXO this instance controls (its funding output), once funded.
    pub fn prevout(&self) -> Option<TxOut> {
        let outpoint = self.outpoint?;
        self.funding_tx
            .as_ref()?
            .output
            .get(outpoint.vout as usize)
            .cloned()
    }

    /// The transaction that funded this instance (None until funded).
    pub fn funding_tx(&self) -> Option<&Transaction> {
        self.funding_tx.as_ref()
    }

    /// Transaction ID that spent this instance (None until spent).
    pub fn spent_in_tx(&self) -> Option<Txid> {
        self.spent_in_tx
    }

    /// The input index of the spending transaction that consumed this instance
    /// (None until spent).
    pub fn spending_vin(&self) -> Option<usize> {
        self.spending_vin
    }

    /// Name of the clause used to spend this instance (None until spent).
    pub fn clause_name(&self) -> Option<&str> {
        self.clause_name.as_deref()
    }

    /// The clause's witness arguments used by the spend, in witness order (None
    /// until spent). Decode them with the clause's typed `*Args` struct
    /// ([`ClauseArgs::decode_from_witness`]).
    pub fn spending_args(&self) -> Option<&[Vec<u8>]> {
        self.spending_args.as_deref()
    }

    /// Child instances created when this instance was spent.
    pub fn outputs(&self) -> &[Rc<RefCell<ContractInstance>>] {
        &self.outputs
    }

    /// Mark the instance as funded with the given outpoint and transaction.
    pub fn mark_funded(&mut self, outpoint: OutPoint, funding_tx: Transaction) {
        self.outpoint = Some(outpoint);
        self.funding_tx = Some(funding_tx);
        self.status = InstanceStatus::Funded;
    }

    /// Mark the instance as spent: by which transaction (and input index within
    /// it), through which clause, and with which witness arguments.
    pub fn mark_spent(
        &mut self,
        txid: Txid,
        vin: usize,
        clause_name: String,
        spending_args: Vec<Vec<u8>>,
    ) {
        self.spent_in_tx = Some(txid);
        self.spending_vin = Some(vin);
        self.clause_name = Some(clause_name);
        self.spending_args = Some(spending_args);
        self.status = InstanceStatus::Spent;
    }

    /// Add a child instance created from spending this instance.
    pub fn add_output(&mut self, instance: Rc<RefCell<ContractInstance>>) {
        self.outputs.push(instance);
    }
}

#[cfg(test)]
mod encoding_role_tests {
    use super::*;

    #[test]
    fn unsigned_ints_are_param_only_fixed_width_le() {
        // 300 = 0x012C -> fixed-width little-endian (not a script number).
        assert_eq!(300u32.encode_param(), vec![vec![0x2c, 0x01, 0x00, 0x00]]);
        let (v, consumed) = u32::decode_param(&[vec![0x2c, 0x01, 0x00, 0x00]]).unwrap();
        assert_eq!((v, consumed), (300u32, 1));

        // The full u64 range survives — it would overflow a script number.
        let big = u64::MAX;
        let (v, _) = u64::decode_param(&big.encode_param()).unwrap();
        assert_eq!(v, big);
    }

    #[test]
    fn witness_types_are_param_encodable_via_the_blanket() {
        // The blanket delegates to the script-facing encoding, unchanged:
        // a signed int is a minimal script number (bn2vch), a hash stays raw.
        assert_eq!(
            ParamEncodable::encode_param(&1i64),
            WitnessEncodable::encode_to_witness(&1i64),
        );
        assert_eq!(ParamEncodable::encode_param(&1i64), vec![vec![0x01]]);

        let hash = [0xabu8; 32];
        assert_eq!(ParamEncodable::encode_param(&hash), vec![hash.to_vec()]);
    }
}
