//! Instances: one UTXO of a contract, from funding to its recorded spend.

use std::{cell::RefCell, rc::Rc, sync::Arc};

use super::{ContractError, ErasedContract, ErasedState, StateCommitment};
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// The spending transaction's id.
    pub fn txid(&self) -> Txid {
        self.tx.compute_txid()
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
    /// typed `*Args` struct ([`ClauseArgs::decode_from_witness`](super::ClauseArgs::decode_from_witness)).
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
