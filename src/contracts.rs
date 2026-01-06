use std::{cell::RefCell, collections::HashMap, fmt, fmt::Debug, marker::PhantomData, rc::Rc, sync::Arc};

use bitcoin::{
    OutPoint, ScriptBuf, TapTweakHash, Transaction, Txid, XOnlyPublicKey,
    hashes::{Hash, sha256},
    key::{Secp256k1, TweakedPublicKey},
    taproot::{LeafVersion, TapLeafHash, TapNodeHash},
};

use crate::argtypes::ArgValue;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug)]
pub enum WitnessError {
    InvalidData(String),
    InsufficientData,
    DecodingFailed(String),
    /// A required argument is missing from the arguments map.
    MissingArgument(String),
    /// An argument value has a type that doesn't match the expected ArgType.
    TypeMismatch {
        expected: String,
        got: String,
    },
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
            WitnessError::MissingArgument(name) => write!(f, "Missing required argument: {}", name),
            WitnessError::TypeMismatch { expected, got } => {
                write!(f, "Type mismatch: expected {}, got {}", expected, got)
            }
            WitnessError::StackUnderflow => write!(f, "Witness stack underflow"),
            WitnessError::InvalidValue(msg) => write!(f, "Invalid value: {}", msg),
        }
    }
}

impl std::error::Error for WitnessError {}

#[derive(Debug)]
pub enum ClauseError {
    Witness(WitnessError),
    InvalidArguments(String),
    StateDecodingError(String),
    Other(String),
}

impl fmt::Display for ClauseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClauseError::Witness(e) => write!(f, "Witness error: {}", e),
            ClauseError::InvalidArguments(msg) => write!(f, "Invalid arguments: {}", msg),
            ClauseError::StateDecodingError(msg) => write!(f, "State decoding error: {}", msg),
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

/// Trait for types that can be encoded/decoded to/from a Bitcoin witness stack.
///
/// This trait provides a standardized interface for serializing and deserializing
/// types to and from the witness stack format used in Bitcoin transactions.
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

// ============================================================================
// WitnessEncodable implementations for common types
// ============================================================================

impl WitnessEncodable for i32 {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![crate::script_utils::bn2vch(*self as i64)]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        let val = crate::script_utils::vch2bn(&witness[0])
            .map_err(|e| WitnessError::DecodingFailed(e.to_string()))?;
        Ok((val as i32, 1))
    }
}

impl WitnessEncodable for i64 {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![crate::script_utils::bn2vch(*self)]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        let val = crate::script_utils::vch2bn(&witness[0])
            .map_err(|e| WitnessError::DecodingFailed(e.to_string()))?;
        Ok((val, 1))
    }
}

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

// ============================================================================
// Marker Trait Implementations
// ============================================================================
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

    /// Get the script that computes the state commitment on-chain.
    fn encoder_script(&self) -> ScriptBuf {
        ScriptBuf::new() // Default: no encoder script needed
    }
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

/// Represents a specific output defined by a contract clause.
#[derive(Debug, Clone)]
pub struct ClauseOutput {
    /// The index of the output. A value of -1 implies the output's index equals the current input's index.
    pub n: i32,
    /// The contract of this output.
    pub next_contract: Arc<dyn ErasedContract>,
    /// The params data for the next contract instance (encoded bytes).
    pub next_params: Option<Vec<u8>>,
    /// The state data for the next contract instance (encoded bytes).
    pub next_state: Option<Vec<u8>>,
    /// Determines the semantic of the output amount.
    pub next_amount: ClauseOutputAmountBehaviour,
}

// ============================================================================
// TapTree Structure
// ============================================================================

/// A single leaf in a taproot tree.
#[derive(Debug, Clone, PartialEq)]
pub struct TapLeaf {
    pub name: String,
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

    /// Get the merkle proof for a specific leaf.
    /// Returns the sibling hashes from bottom to top.
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
                    proof.insert(0, right.root_hash());
                    Some(proof)
                } else if let Some(mut proof) = right.merkle_proof(target_leaf) {
                    proof.insert(0, left.root_hash());
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

    /// Find a clause name by its script bytes.
    pub fn find_clause_by_script(&self, script_bytes: &[u8]) -> Option<String> {
        match self {
            TapTree::Leaf(leaf) => {
                if leaf.script.as_bytes() == script_bytes {
                    Some(leaf.name.clone())
                } else {
                    None
                }
            }
            TapTree::Branch { left, right } => left
                .find_clause_by_script(script_bytes)
                .or_else(|| right.find_clause_by_script(script_bytes)),
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
) -> Result<XOnlyPublicKey, String> {
    let tweak_bytes = compute_state_tweak(&naked_key.serialize(), state_hash);

    let secp = Secp256k1::new();
    let scalar = bitcoin::secp256k1::Scalar::from_be_bytes(tweak_bytes)
        .map_err(|e| format!("Invalid scalar: {}", e))?;

    naked_key
        .add_tweak(&secp, &scalar)
        .map(|(tweaked, _parity)| tweaked)
        .map_err(|e| format!("Failed to apply tweak: {}", e))
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
// Generic Clause Trait (for compile-time usage)
// ============================================================================

/// Generic trait for clauses with specific type parameters.
/// This is used when defining contracts with known types.
pub trait Clause {
    type Params: ContractParams;
    type State: ContractState;
    type Args: ClauseArgs;

    /// Get the clause name.
    fn name(&self) -> &str;

    /// Get the clause script.
    fn script(&self) -> &ScriptBuf;

    /// Compute next outputs from parameters, arguments and state.
    fn next_outputs(
        &self,
        params: &Self::Params,
        args: &Self::Args,
        state: Option<&Self::State>,
    ) -> Result<Vec<ClauseOutput>, ClauseError>;
}

// ============================================================================
// Type-Erased Clause Trait (for runtime polymorphism)
// ============================================================================

/// Type-erased version of Clause for dynamic dispatch.
/// This allows the manager to work with clauses without knowing their concrete types.
pub trait ErasedClause: Debug + Send + Sync {
    /// Get the clause name.
    fn name(&self) -> &str;

    /// Get the clause script.
    fn script(&self) -> &ScriptBuf;

    /// Encode arguments from a generic argument map to witness stack.
    fn encode_args_to_witness(
        &self,
        args: &HashMap<String, ArgValue>,
    ) -> Result<Vec<Vec<u8>>, WitnessError>;

    /// Decode witness stack back to argument map.
    fn decode_witness_to_args(
        &self,
        witness: &[Vec<u8>],
    ) -> Result<HashMap<String, ArgValue>, WitnessError>;

    /// Compute next outputs (with erased state as bytes).
    fn next_outputs_erased(
        &self,
        params_bytes: &[u8],
        args: &HashMap<String, ArgValue>,
        state_bytes: Option<&[u8]>,
    ) -> Result<Vec<ClauseOutput>, ClauseError>;

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

/// Trait for argument types that can be serialized/deserialized to/from witness.
pub trait ArgType: Debug + Send + Sync {
    /// Encode an ArgValue to witness stack elements.
    fn encode_to_witness(&self, value: &ArgValue) -> Result<Vec<Vec<u8>>, WitnessError>;

    /// Decode witness stack elements to an ArgValue.
    /// Returns (ArgValue, number of elements consumed).
    fn decode_from_witness(&self, witness: &[Vec<u8>]) -> Result<(ArgValue, usize), WitnessError>;

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
    pub name: String,
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
    Arc<dyn Fn(&P, &A, Option<&S>) -> Result<Vec<ClauseOutput>, ClauseError> + Send + Sync>;

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

// Implement the generic Clause trait
impl<P, S, A> Clause for StandardClause<P, S, A>
where
    P: ContractParams + 'static,
    S: ContractState + 'static,
    A: ClauseArgs + 'static,
{
    type Params = P;
    type State = S;
    type Args = A;

    fn name(&self) -> &str {
        &self.name
    }

    fn script(&self) -> &ScriptBuf {
        &self.script
    }

    fn next_outputs(
        &self,
        params: &Self::Params,
        args: &Self::Args,
        state: Option<&Self::State>,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        if let Some(ref f) = self.next_outputs_fn {
            f(params, args, state)
        } else {
            Ok(Vec::new())
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

    fn encode_args_to_witness(
        &self,
        args: &HashMap<String, ArgValue>,
    ) -> Result<Vec<Vec<u8>>, WitnessError> {
        let mut result = Vec::new();

        for spec in &self.arg_specs {
            let arg_value = args
                .get(&spec.name)
                .ok_or_else(|| WitnessError::MissingArgument(spec.name.clone()))?;

            let encoded = spec.arg_type.encode_to_witness(arg_value)?;
            result.extend(encoded);
        }

        Ok(result)
    }

    fn decode_witness_to_args(
        &self,
        witness: &[Vec<u8>],
    ) -> Result<HashMap<String, ArgValue>, WitnessError> {
        let mut result = HashMap::new();
        let mut offset = 0;

        for spec in &self.arg_specs {
            if offset >= witness.len() {
                return Err(WitnessError::InsufficientData);
            }

            let (value, consumed) = spec.arg_type.decode_from_witness(&witness[offset..])?;
            result.insert(spec.name.clone(), value);
            offset += consumed;
        }

        if offset != witness.len() {
            return Err(WitnessError::InvalidData(format!(
                "Expected {} witness elements, got {}",
                offset,
                witness.len()
            )));
        }

        Ok(result)
    }

    fn next_outputs_erased(
        &self,
        params_bytes: &[u8],
        args: &HashMap<String, ArgValue>,
        state_bytes: Option<&[u8]>,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        // Decode params
        let params = P::decode(params_bytes)
            .map_err(|e| ClauseError::Other(format!("Failed to decode params: {}", e)))?;

        // Decode state if provided
        let state: Option<S> = if let Some(bytes) = state_bytes {
            Some(S::decode(bytes)?)
        } else {
            None
        };

        // Decode args from HashMap to concrete Args type
        // We build a witness stack from the args map and then decode it
        let witness_stack = self.encode_args_to_witness(args)?;
        let concrete_args = A::decode_from_witness(&witness_stack)?;

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

    /// Get a clause by name.
    fn get_clause(&self, name: &str) -> Option<&Arc<dyn ErasedClause>>;
    
    /// Execute a clause and get the next outputs.
    fn execute_clause_erased(
        &self,
        clause_name: &str,
        params_bytes: &[u8],
        args: HashMap<String, ArgValue>,
        state_bytes: Option<&[u8]>,
    ) -> Result<Option<Vec<ClauseOutput>>, ClauseError>;
    
    /// Build the witness stack for spending with a specific clause.
    fn build_witness_stack(
        &self,
        clause_name: &str,
        params_bytes: &[u8],
        args: &HashMap<String, ArgValue>,
        state_bytes: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>, ClauseError>;
    
    /// Get the script pubkey for this contract (with optional state).
    fn script_pubkey(&self, state_bytes: Option<&[u8]>) -> Result<ScriptBuf, String>;

    /// Get the internal pubkey for this contract.
    fn internal_pubkey(&self) -> XOnlyPublicKey;

    /// Get the internal pubkey to use for control block generation.
    /// For augmented contracts with state, this may be state-tweaked.
    fn control_block_internal_key(&self, state_bytes: Option<&[u8]>) -> Result<XOnlyPublicKey, String>;

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
// Standard P2TR Contract
// ============================================================================

/// Standard P2TR contract with clauses.
pub struct StandardP2TR<P: ContractParams> {
    pub internal_pubkey: XOnlyPublicKey,
    pub taptree: Arc<TapTree>,
    pub clauses: Vec<Arc<dyn ErasedClause>>,
    _phantom: PhantomData<P>,
}

impl<P: ContractParams> StandardP2TR<P> {
    pub fn new(
        internal_pubkey: XOnlyPublicKey,
        taptree: Arc<TapTree>,
        clauses: Vec<Arc<dyn ErasedClause>>,
    ) -> Self {
        Self {
            internal_pubkey,
            taptree,
            clauses,
            _phantom: PhantomData,
        }
    }

    /// Get the taproot output key for this contract.
    pub fn output_key(&self) -> XOnlyPublicKey {
        compute_taproot_output_key(&self.internal_pubkey, Some(&self.taptree))
    }

    /// Get the scriptPubKey for this contract (OP_1 <output_key>).
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
            self.output_key(),
        ))
    }
}

impl<P: ContractParams> Debug for StandardP2TR<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StandardP2TR")
            .field("internal_pubkey", &self.internal_pubkey)
            .field("taptree", &"<TapTree>")
            .field("clauses", &self.clauses.len())
            .finish()
    }
}

impl<P: ContractParams> Clone for StandardP2TR<P> {
    fn clone(&self) -> Self {
        Self {
            internal_pubkey: self.internal_pubkey,
            taptree: self.taptree.clone(),
            clauses: self.clauses.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<P: ContractParams + 'static> ErasedContract for StandardP2TR<P> {
    fn clauses(&self) -> &[Arc<dyn ErasedClause>] {
        &self.clauses
    }

    fn get_clause(&self, name: &str) -> Option<&Arc<dyn ErasedClause>> {
        self.clauses.iter().find(|c| c.name() == name)
    }
    
    fn execute_clause_erased(
        &self,
        clause_name: &str,
        params_bytes: &[u8],
        args: HashMap<String, ArgValue>,
        state_bytes: Option<&[u8]>,
    ) -> Result<Option<Vec<ClauseOutput>>, ClauseError> {
        let clause = self.get_clause(clause_name)
            .ok_or_else(|| ClauseError::Other(format!("Clause {} not found", clause_name)))?;
        
        clause.next_outputs_erased(params_bytes, &args, state_bytes)
            .map(Some)
    }
    
    fn build_witness_stack(
        &self,
        clause_name: &str,
        _params_bytes: &[u8],
        args: &HashMap<String, ArgValue>,
        _state_bytes: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>, ClauseError> {
        let clause = self.get_clause(clause_name)
            .ok_or_else(|| ClauseError::Other(format!("Clause {} not found", clause_name)))?;
        
        let witness_elements = clause.encode_args_to_witness(args)?;
        Ok(witness_elements)
    }
    
    fn script_pubkey(&self, _state_bytes: Option<&[u8]>) -> Result<ScriptBuf, String> {
        Ok(ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
            self.output_key(),
        )))
    }

    fn internal_pubkey(&self) -> XOnlyPublicKey {
        self.internal_pubkey
    }

    fn control_block_internal_key(&self, _state_bytes: Option<&[u8]>) -> Result<XOnlyPublicKey, String> {
        Ok(self.internal_pubkey)
    }

    fn taptree(&self) -> &Arc<TapTree> {
        &self.taptree
    }

    fn clone_boxed(&self) -> Box<dyn ErasedContract> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Standard Augmented P2TR Contract
// ============================================================================

/// Standard Augmented P2TR contract with state.
pub struct StandardAugmentedP2TR<P: ContractParams, S: ContractState> {
    pub naked_internal_pubkey: XOnlyPublicKey,
    pub taptree: Arc<TapTree>,
    pub clauses: Vec<Arc<dyn ErasedClause>>,
    _phantom: PhantomData<(P, S)>,
}

impl<P: ContractParams, S: ContractState> StandardAugmentedP2TR<P, S> {
    pub fn new(
        naked_internal_pubkey: XOnlyPublicKey,
        taptree: Arc<TapTree>,
        clauses: Vec<Arc<dyn ErasedClause>>,
    ) -> Self {
        Self {
            naked_internal_pubkey,
            taptree,
            clauses,
            _phantom: PhantomData,
        }
    }

    /// Compute the internal pubkey tweaked with the state.
    pub fn compute_internal_key(&self, state: &S) -> Result<XOnlyPublicKey, String> {
        let state_bytes = state.encode();

        // For state commitment, we typically hash the state to get a 32-byte value
        let state_hash = if state_bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&state_bytes);
            arr
        } else {
            // Hash the state if it's not exactly 32 bytes
            let hash = sha256::Hash::hash(&state_bytes);
            *hash.as_byte_array()
        };

        apply_state_tweak(&self.naked_internal_pubkey, &state_hash)
    }

    /// Get the taproot output key for this contract with the given state.
    pub fn output_key(&self, state: &S) -> Result<XOnlyPublicKey, String> {
        let internal_key = self.compute_internal_key(state)?;
        Ok(compute_taproot_output_key(
            &internal_key,
            Some(&self.taptree),
        ))
    }

    /// Get the scriptPubKey for this contract with the given state.
    pub fn script_pubkey(&self, state: &S) -> Result<ScriptBuf, String> {
        let output_key = self.output_key(state)?;
        Ok(ScriptBuf::new_p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(output_key),
        ))
    }
}

impl<P: ContractParams, S: ContractState> Debug for StandardAugmentedP2TR<P, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StandardAugmentedP2TR")
            .field("naked_internal_pubkey", &self.naked_internal_pubkey)
            .field("taptree", &"<TapTree>")
            .field("clauses", &self.clauses.len())
            .finish()
    }
}

impl<P: ContractParams, S: ContractState> Clone for StandardAugmentedP2TR<P, S> {
    fn clone(&self) -> Self {
        Self {
            naked_internal_pubkey: self.naked_internal_pubkey,
            taptree: self.taptree.clone(),
            clauses: self.clauses.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<P: ContractParams + 'static, S: ContractState + 'static> ErasedContract
    for StandardAugmentedP2TR<P, S>
{
    fn clauses(&self) -> &[Arc<dyn ErasedClause>] {
        &self.clauses
    }

    fn get_clause(&self, name: &str) -> Option<&Arc<dyn ErasedClause>> {
        self.clauses.iter().find(|c| c.name() == name)
    }
    
    fn execute_clause_erased(
        &self,
        clause_name: &str,
        params_bytes: &[u8],
        args: HashMap<String, ArgValue>,
        state_bytes: Option<&[u8]>,
    ) -> Result<Option<Vec<ClauseOutput>>, ClauseError> {
        let clause = self.get_clause(clause_name)
            .ok_or_else(|| ClauseError::Other(format!("Clause {} not found", clause_name)))?;
        
        clause.next_outputs_erased(params_bytes, &args, state_bytes)
            .map(Some)
    }
    
    fn build_witness_stack(
        &self,
        clause_name: &str,
        _params_bytes: &[u8],
        args: &HashMap<String, ArgValue>,
        _state_bytes: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>, ClauseError> {
        let clause = self.get_clause(clause_name)
            .ok_or_else(|| ClauseError::Other(format!("Clause {} not found", clause_name)))?;
        
        let witness_elements = clause.encode_args_to_witness(args)?;
        Ok(witness_elements)
    }
    
    fn script_pubkey(&self, state_bytes: Option<&[u8]>) -> Result<ScriptBuf, String> {
        let state_bytes = state_bytes.ok_or("State required for augmented contract")?;
        let state = S::decode(state_bytes)
            .map_err(|e| format!("Failed to decode state: {}", e))?;
        let output_key = self.output_key(&state)?;
        Ok(ScriptBuf::new_p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(output_key),
        ))
    }

    fn internal_pubkey(&self) -> XOnlyPublicKey {
        // For augmented contracts, we need to return the naked key
        // Note: This may not be correct for all use cases, but it's what we have
        self.naked_internal_pubkey
    }

    fn control_block_internal_key(&self, state_bytes: Option<&[u8]>) -> Result<XOnlyPublicKey, String> {
        let state_bytes = state_bytes.ok_or("State required for augmented contract")?;
        let state = S::decode(state_bytes)
            .map_err(|e| format!("Failed to decode state: {}", e))?;
        self.compute_internal_key(&state)
    }

    fn taptree(&self) -> &Arc<TapTree> {
        &self.taptree
    }

    fn clone_boxed(&self) -> Box<dyn ErasedContract> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Builder Patterns
// ============================================================================

/// Builder for creating StandardClause instances.
pub struct StandardClauseBuilder<P, S, A>
where
    P: ContractParams + 'static,
    S: ContractState + 'static,
    A: ClauseArgs + 'static,
{
    name: Option<String>,
    script: Option<ScriptBuf>,
    arg_specs: Vec<ArgSpec>,
    next_outputs_fn: Option<NextOutputsFn<P, S, A>>,
    _phantom: PhantomData<(P, S, A)>,
}

impl<P, S, A> StandardClauseBuilder<P, S, A>
where
    P: ContractParams + 'static,
    S: ContractState + 'static,
    A: ClauseArgs + 'static,
{
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            name: None,
            script: None,
            arg_specs: Vec::new(),
            next_outputs_fn: None,
            _phantom: PhantomData,
        }
    }

    /// Set the clause name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the clause script.
    pub fn script(mut self, script: ScriptBuf) -> Self {
        self.script = Some(script);
        self
    }

    /// Add an argument specification.
    pub fn arg(mut self, name: impl Into<String>, arg_type: Arc<dyn ArgType>) -> Self {
        self.arg_specs.push(ArgSpec {
            name: name.into(),
            arg_type,
        });
        self
    }

    /// Add multiple argument specifications.
    pub fn args(mut self, specs: Vec<ArgSpec>) -> Self {
        self.arg_specs.extend(specs);
        self
    }

    /// Set the next_outputs function.
    pub fn next_outputs(
        mut self,
        f: impl Fn(&P, &A, Option<&S>) -> Result<Vec<ClauseOutput>, ClauseError> + Send + Sync + 'static,
    ) -> Self {
        self.next_outputs_fn = Some(Arc::new(f));
        self
    }

    /// Build the StandardClause.
    pub fn build(self) -> Result<StandardClause<P, S, A>, String> {
        let name = self.name.ok_or("Clause name is required")?;
        let script = self.script.ok_or("Clause script is required")?;

        Ok(StandardClause::new(
            name,
            script,
            self.arg_specs,
            self.next_outputs_fn,
        ))
    }
}

impl<P, S, A> Default for StandardClauseBuilder<P, S, A>
where
    P: ContractParams + 'static,
    S: ContractState + 'static,
    A: ClauseArgs + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating StandardP2TR contracts.
pub struct StandardP2TRBuilder<P: ContractParams + 'static> {
    internal_pubkey: Option<XOnlyPublicKey>,
    taptree: Option<Arc<TapTree>>,
    clauses: Vec<Arc<dyn ErasedClause>>,
    _phantom: PhantomData<P>,
}

impl<P: ContractParams + 'static> StandardP2TRBuilder<P> {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            internal_pubkey: None,
            taptree: None,
            clauses: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Set the internal pubkey.
    pub fn internal_pubkey(mut self, key: XOnlyPublicKey) -> Self {
        self.internal_pubkey = Some(key);
        self
    }

    /// Set the taptree.
    pub fn taptree(mut self, tree: Arc<TapTree>) -> Self {
        self.taptree = Some(tree);
        self
    }

    /// Add a clause.
    pub fn clause(mut self, clause: Arc<dyn ErasedClause>) -> Self {
        self.clauses.push(clause);
        self
    }

    /// Add multiple clauses.
    pub fn clauses(mut self, clauses: Vec<Arc<dyn ErasedClause>>) -> Self {
        self.clauses.extend(clauses);
        self
    }

    /// Build the StandardP2TR contract.
    pub fn build(self) -> Result<StandardP2TR<P>, String> {
        let internal_pubkey = self.internal_pubkey.ok_or("Internal pubkey is required")?;
        let taptree = self.taptree.ok_or("Taptree is required")?;

        Ok(StandardP2TR::new(internal_pubkey, taptree, self.clauses))
    }
}

impl<P: ContractParams + 'static> Default for StandardP2TRBuilder<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating StandardAugmentedP2TR contracts.
pub struct StandardAugmentedP2TRBuilder<P: ContractParams + 'static, S: ContractState + 'static> {
    naked_internal_pubkey: Option<XOnlyPublicKey>,
    taptree: Option<Arc<TapTree>>,
    clauses: Vec<Arc<dyn ErasedClause>>,
    _phantom: PhantomData<(P, S)>,
}

impl<P: ContractParams + 'static, S: ContractState + 'static> StandardAugmentedP2TRBuilder<P, S> {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            naked_internal_pubkey: None,
            taptree: None,
            clauses: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Set the naked internal pubkey.
    pub fn naked_internal_pubkey(mut self, key: XOnlyPublicKey) -> Self {
        self.naked_internal_pubkey = Some(key);
        self
    }

    /// Set the taptree.
    pub fn taptree(mut self, tree: Arc<TapTree>) -> Self {
        self.taptree = Some(tree);
        self
    }

    /// Add a clause.
    pub fn clause(mut self, clause: Arc<dyn ErasedClause>) -> Self {
        self.clauses.push(clause);
        self
    }

    /// Add multiple clauses.
    pub fn clauses(mut self, clauses: Vec<Arc<dyn ErasedClause>>) -> Self {
        self.clauses.extend(clauses);
        self
    }

    /// Build the StandardAugmentedP2TR contract.
    pub fn build(self) -> Result<StandardAugmentedP2TR<P, S>, String> {
        let naked_internal_pubkey = self
            .naked_internal_pubkey
            .ok_or("Naked internal pubkey is required")?;
        let taptree = self.taptree.ok_or("Taptree is required")?;

        Ok(StandardAugmentedP2TR::new(
            naked_internal_pubkey,
            taptree,
            self.clauses,
        ))
    }
}

impl<P: ContractParams + 'static, S: ContractState + 'static> Default
    for StandardAugmentedP2TRBuilder<P, S>
{
    fn default() -> Self {
        Self::new()
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
/// and maintain references to child instances created when spent.
#[derive(Debug)]
pub struct ContractInstance {
    /// The contract template (type-erased for runtime polymorphism).
    pub contract: Arc<dyn ErasedContract>,
    
    /// Serialized contract parameters.
    pub params_bytes: Vec<u8>,
    
    /// Serialized contract state (None for non-augmented contracts).
    pub state_bytes: Option<Vec<u8>>,
    
    /// The outpoint identifying this instance on-chain (None until funded).
    pub outpoint: Option<OutPoint>,
    
    /// The transaction that funded this instance (None until funded).
    pub funding_tx: Option<Transaction>,
    
    /// Current status in the instance lifecycle.
    pub status: InstanceStatus,
    
    /// Transaction ID that spent this instance (None until spent).
    pub spent_in_tx: Option<Txid>,
    
    /// Name of the clause used to spend this instance (None until spent).
    pub clause_name: Option<String>,
    
    /// Child instances created when this instance was spent.
    pub outputs: Vec<Rc<RefCell<ContractInstance>>>,
}

impl ContractInstance {
    /// Create a new unfunded instance.
    pub fn new(
        contract: Arc<dyn ErasedContract>,
        params_bytes: Vec<u8>,
        state_bytes: Option<Vec<u8>>,
    ) -> Self {
        Self {
            contract,
            params_bytes,
            state_bytes,
            outpoint: None,
            funding_tx: None,
            status: InstanceStatus::Unfunded,
            spent_in_tx: None,
            clause_name: None,
            outputs: Vec::new(),
        }
    }
    
    /// Mark the instance as funded with the given outpoint and transaction.
    pub fn mark_funded(&mut self, outpoint: OutPoint, funding_tx: Transaction) {
        self.outpoint = Some(outpoint);
        self.funding_tx = Some(funding_tx);
        self.status = InstanceStatus::Funded;
    }
    
    /// Mark the instance as spent with the given transaction and clause.
    pub fn mark_spent(&mut self, txid: Txid, clause_name: String) {
        self.spent_in_tx = Some(txid);
        self.clause_name = Some(clause_name);
        self.status = InstanceStatus::Spent;
    }
    
    /// Add a child instance created from spending this instance.
    pub fn add_output(&mut self, instance: Rc<RefCell<ContractInstance>>) {
        self.outputs.push(instance);
    }
}
