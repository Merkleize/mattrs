use std::{collections::HashMap, fmt, fmt::Debug, marker::PhantomData, sync::Arc};

use bitcoin::ScriptBuf;

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

/// Marker trait for contract parameters.
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
    /// The state data for the next contract instance (encoded bytes).
    pub next_state: Option<Vec<u8>>,
    /// Determines the semantic of the output amount.
    pub next_amount: ClauseOutputAmountBehaviour,
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
            return Err(WitnessError::InvalidData(
                format!("Expected {} witness elements, got {}", offset, witness.len())
            ));
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
    pub internal_pubkey: [u8; 32],
    pub clauses: Vec<Arc<dyn ErasedClause>>,
    _phantom: PhantomData<P>,
}

impl<P: ContractParams> StandardP2TR<P> {
    pub fn new(internal_pubkey: [u8; 32], clauses: Vec<Arc<dyn ErasedClause>>) -> Self {
        Self {
            internal_pubkey,
            clauses,
            _phantom: PhantomData,
        }
    }
}

impl<P: ContractParams> Debug for StandardP2TR<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StandardP2TR")
            .field("internal_pubkey", &format!("{:02x?}", self.internal_pubkey))
            .field("clauses", &self.clauses.len())
            .finish()
    }
}

impl<P: ContractParams> Clone for StandardP2TR<P> {
    fn clone(&self) -> Self {
        Self {
            internal_pubkey: self.internal_pubkey,
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
    
    fn clone_boxed(&self) -> Box<dyn ErasedContract> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Standard Augmented P2TR Contract
// ============================================================================

/// Standard Augmented P2TR contract with state.
pub struct StandardAugmentedP2TR<P: ContractParams, S: ContractState> {
    pub naked_internal_pubkey: [u8; 32],
    pub clauses: Vec<Arc<dyn ErasedClause>>,
    _phantom: PhantomData<(P, S)>,
}

impl<P: ContractParams, S: ContractState> StandardAugmentedP2TR<P, S> {
    pub fn new(
        naked_internal_pubkey: [u8; 32],
        clauses: Vec<Arc<dyn ErasedClause>>,
    ) -> Self {
        Self {
            naked_internal_pubkey,
            clauses,
            _phantom: PhantomData,
        }
    }
}

impl<P: ContractParams, S: ContractState> Debug for StandardAugmentedP2TR<P, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StandardAugmentedP2TR")
            .field("naked_internal_pubkey", &format!("{:02x?}", self.naked_internal_pubkey))
            .field("clauses", &self.clauses.len())
            .finish()
    }
}

impl<P: ContractParams, S: ContractState> Clone for StandardAugmentedP2TR<P, S> {
    fn clone(&self) -> Self {
        Self {
            naked_internal_pubkey: self.naked_internal_pubkey,
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
    
    fn clone_boxed(&self) -> Box<dyn ErasedContract> {
        Box::new(self.clone())
    }
}
