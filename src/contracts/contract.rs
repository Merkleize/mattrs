//! Contracts: a clause tree plus params, as a taproot output template.

use std::{fmt, fmt::Debug, marker::PhantomData, sync::Arc};

use super::{
    ClauseError, ClauseTree, ContractError, ContractParams, ContractState, ErasedClause,
    ErasedState, NextOutputs, StateCommitment, TapTree, apply_state_tweak,
    compute_taproot_output_key,
};
use bitcoin::{ScriptBuf, XOnlyPublicKey};

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
