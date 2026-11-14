//! Clauses: one tapscript spending path with its typed arguments and output function.

use std::{fmt, fmt::Debug, marker::PhantomData, sync::Arc};

use super::{
    ClauseError, ContractError, ContractParams, ContractState, ErasedState, NextOutputs,
    WitnessError,
};
use bitcoin::{ScriptBuf, XOnlyPublicKey};

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
