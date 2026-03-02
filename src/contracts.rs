use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::{Address, OutPoint, Transaction, XOnlyPublicKey};

use crate::taproot::{get_taproot_address, tweak_embed_data, TapTree};

/// Raw data embedded in the UTXO (the "state").
/// Empty vec means stateless (no tweak).
pub type StateData = Vec<u8>;

/// Clause arguments are named byte buffers.
pub type ClauseArgs = HashMap<String, Vec<u8>>;

/// How an output's amount is handled by CCV.
#[derive(Debug, Clone, PartialEq)]
pub enum CcvAmountBehaviour {
    Preserve,
    Ignore,
    Deduct,
}

/// Describes one output produced by a clause.
pub struct ClauseOutput {
    pub n: i32,
    pub next_contract: Contract,
    pub next_state: StateData,
    pub amount_behaviour: CcvAmountBehaviour,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ArgsToWitnessFn = dyn Fn(&ClauseArgs) -> Result<Vec<Vec<u8>>, BoxError> + Send + Sync;
type WitnessToArgsFn = dyn Fn(&[Vec<u8>]) -> Result<ClauseArgs, BoxError> + Send + Sync;
type NextOutputsFn =
    dyn Fn(&ClauseArgs, &StateData) -> Result<Vec<ClauseOutput>, BoxError> + Send + Sync;

/// A spending condition in the taptree.
/// Stores closures for the three key operations, like pymatt's StandardClause.
pub struct Clause {
    pub name: String,
    pub script: bitcoin::ScriptBuf,
    /// Maps arg names that require signatures to the pubkey that should sign.
    /// The manager fills these args with signature bytes before calling args_to_witness.
    pub signer_args: HashMap<String, XOnlyPublicKey>,
    pub args_to_witness: Box<ArgsToWitnessFn>,
    pub witness_to_args: Box<WitnessToArgsFn>,
    pub next_outputs: Box<NextOutputsFn>,
}

impl std::fmt::Debug for Clause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Clause")
            .field("name", &self.name)
            .field("script", &self.script)
            .finish_non_exhaustive()
    }
}

struct ContractInner {
    name: String,
    naked_internal_pubkey: XOnlyPublicKey,
    taptree: TapTree,
}

/// A contract "template" -- the program of the state machine.
/// Concrete struct, not a trait. Cheaply cloneable via Arc.
#[derive(Clone)]
pub struct Contract(Arc<ContractInner>);

impl std::fmt::Debug for Contract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contract")
            .field("name", &self.0.name)
            .finish_non_exhaustive()
    }
}

impl Contract {
    pub fn new(name: impl Into<String>, naked_internal_pubkey: XOnlyPublicKey, taptree: TapTree) -> Self {
        Contract(Arc::new(ContractInner {
            name: name.into(),
            naked_internal_pubkey,
            taptree,
        }))
    }

    pub fn name(&self) -> &str {
        &self.0.name
    }

    pub fn naked_internal_pubkey(&self) -> &XOnlyPublicKey {
        &self.0.naked_internal_pubkey
    }

    pub fn taptree(&self) -> &TapTree {
        &self.0.taptree
    }

    /// Get the internal pubkey for a specific state (data embedded in the UTXO).
    /// If data is empty, the naked key is used as-is.
    pub fn get_internal_pubkey(&self, data: &StateData) -> XOnlyPublicKey {
        if data.is_empty() {
            self.0.naked_internal_pubkey
        } else {
            tweak_embed_data(&self.0.naked_internal_pubkey, data)
        }
    }

    /// Get the taproot address for a specific state.
    pub fn get_address(&self, data: &StateData) -> Address {
        let internal_pk = self.get_internal_pubkey(data);
        get_taproot_address(&internal_pk, &self.0.taptree)
    }

    /// Get the taptree merkle root hash.
    pub fn get_taptree_merkle_root(&self) -> [u8; 32] {
        self.0.taptree.get_root_hash()
    }

    /// Find a clause by name (searches taptree leaves).
    pub fn get_clause(&self, name: &str) -> Option<&Clause> {
        self.0.taptree.get_clause(name)
    }

    /// Get all leaf names.
    pub fn clause_names(&self) -> Vec<&str> {
        self.0.taptree.get_clause_names()
    }

    /// Get the control block for a specific clause and state.
    pub fn get_control_block(&self, clause_name: &str, data: &StateData) -> Vec<u8> {
        let internal_pk = self.get_internal_pubkey(data);
        self.0.taptree.get_control_block(&internal_pk, clause_name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractInstanceStatus {
    Abstract,
    Funded,
    Spent,
}

/// A live instance of a contract, tracking its lifecycle.
#[derive(Debug)]
pub struct ContractInstance {
    pub contract: Contract,
    pub status: ContractInstanceStatus,
    pub data: StateData,

    pub outpoint: Option<OutPoint>,
    pub funding_tx: Option<Transaction>,

    pub spending_tx: Option<Transaction>,
    pub spending_vin: Option<usize>,
    pub spending_clause: Option<String>,
    pub spending_args: Option<ClauseArgs>,
    pub next: Option<Vec<ContractInstance>>,
    pub last_height: Option<u64>,
}

impl ContractInstance {
    pub fn new(contract: Contract, data: StateData) -> Self {
        ContractInstance {
            contract,
            status: ContractInstanceStatus::Abstract,
            data,
            outpoint: None,
            funding_tx: None,
            spending_tx: None,
            spending_vin: None,
            spending_clause: None,
            spending_args: None,
            next: None,
            last_height: None,
        }
    }

    pub fn get_address(&self) -> Address {
        self.contract.get_address(&self.data)
    }

    pub fn get_internal_pubkey(&self) -> XOnlyPublicKey {
        self.contract.get_internal_pubkey(&self.data)
    }
}
