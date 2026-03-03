use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::{Address, OutPoint, ScriptBuf, Transaction, XOnlyPublicKey};

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
    taptree: Option<TapTree>,
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
            taptree: Some(taptree),
        }))
    }

    /// Creates an opaque P2TR contract (key-only, no script tree).
    /// Used for outputs that are not tracked by the contract manager.
    pub fn new_opaque_p2tr(pubkey: XOnlyPublicKey) -> Self {
        Contract(Arc::new(ContractInner {
            name: "OpaqueP2TR".into(),
            naked_internal_pubkey: pubkey,
            taptree: None,
        }))
    }

    pub fn name(&self) -> &str {
        &self.0.name
    }

    pub fn naked_internal_pubkey(&self) -> &XOnlyPublicKey {
        &self.0.naked_internal_pubkey
    }

    pub fn taptree(&self) -> &TapTree {
        self.0.taptree.as_ref().expect("Contract has no taptree (opaque P2TR)")
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
        match &self.0.taptree {
            Some(taptree) => get_taproot_address(&internal_pk, taptree),
            None => {
                // OpaqueP2TR: raw witness v1 output with untweaked pubkey.
                // This matches pymatt's OpaqueP2TR which skips the taproot tweak.
                let script = bitcoin::ScriptBuf::new_witness_program(
                    &bitcoin::WitnessProgram::new(
                        bitcoin::WitnessVersion::V1,
                        &internal_pk.serialize(),
                    ).expect("valid witness program"),
                );
                Address::from_script(&script, bitcoin::Network::Regtest)
                    .expect("valid address")
            }
        }
    }

    /// Get the taptree merkle root hash.
    pub fn get_taptree_merkle_root(&self) -> [u8; 32] {
        self.taptree().get_root_hash()
    }

    /// Find a clause by name (searches taptree leaves).
    pub fn get_clause(&self, name: &str) -> Option<&Clause> {
        self.0.taptree.as_ref().and_then(|t| t.get_clause(name))
    }

    /// Get all leaf names.
    pub fn clause_names(&self) -> Vec<&str> {
        match &self.0.taptree {
            Some(t) => t.get_clause_names(),
            None => vec![],
        }
    }

    /// Get the control block for a specific clause and state.
    pub fn get_control_block(&self, clause_name: &str, data: &StateData) -> Vec<u8> {
        let internal_pk = self.get_internal_pubkey(data);
        self.taptree().get_control_block(&internal_pk, clause_name)
    }
}

// ---------------------------------------------------------------------------
// Layer 1: standard_clause() + ArgType
// ---------------------------------------------------------------------------

/// Describes the type of a clause argument for automatic witness encoding/decoding.
#[derive(Debug, Clone)]
pub enum ArgType {
    /// Fixed-size byte array.
    Bytes(usize),
    /// Script integer (encoded via bitcoin's scriptint).
    Int,
    /// 64-byte Schnorr signature; auto-populates `signer_args`.
    Signer(XOnlyPublicKey),
}

/// Build a `Clause` from argument type descriptors, auto-generating
/// `args_to_witness`, `witness_to_args`, and `signer_args`.
/// Only `next_outputs` remains manual.
pub fn standard_clause(
    name: impl Into<String>,
    script: ScriptBuf,
    arg_specs: Vec<(&'static str, ArgType)>,
    next_outputs: impl Fn(&ClauseArgs, &StateData) -> Result<Vec<ClauseOutput>, BoxError> + Send + Sync + 'static,
) -> Clause {
    let name = name.into();

    // Build signer_args from Signer specs
    let mut signer_args = HashMap::new();
    for (arg_name, arg_type) in &arg_specs {
        if let ArgType::Signer(pk) = arg_type {
            signer_args.insert((*arg_name).to_string(), *pk);
        }
    }

    let specs_for_a2w = arg_specs.clone();
    let clause_name_for_w2a = name.clone();
    let specs_for_w2a = arg_specs;

    Clause {
        name,
        script,
        signer_args,
        args_to_witness: Box::new(move |args| {
            let mut witness = Vec::with_capacity(specs_for_a2w.len());
            for (arg_name, arg_type) in &specs_for_a2w {
                let val = args
                    .get(*arg_name)
                    .ok_or_else(|| format!("Missing arg '{}'", arg_name))?;
                match arg_type {
                    ArgType::Bytes(_) | ArgType::Signer(_) => {
                        witness.push(val.clone());
                    }
                    ArgType::Int => {
                        // Already encoded as scriptint bytes in ClauseArgs
                        witness.push(val.clone());
                    }
                }
            }
            Ok(witness)
        }),
        witness_to_args: Box::new(move |stack| {
            if stack.len() != specs_for_w2a.len() {
                return Err(format!(
                    "{}: expected {} witness elements, got {}",
                    clause_name_for_w2a,
                    specs_for_w2a.len(),
                    stack.len()
                )
                .into());
            }
            let mut args = HashMap::new();
            for (i, (arg_name, _arg_type)) in specs_for_w2a.iter().enumerate() {
                args.insert((*arg_name).to_string(), stack[i].clone());
            }
            Ok(args)
        }),
        next_outputs: Box::new(next_outputs),
    }
}

/// Extract an i32 from clause args (scriptint-encoded).
pub fn arg_as_int(args: &ClauseArgs, name: &str) -> Result<i32, BoxError> {
    let v = args.get(name).ok_or_else(|| format!("Missing arg '{}'", name))?;
    let val = bitcoin::script::read_scriptint(v)
        .map_err(|e| -> BoxError { format!("Arg '{}': {}", name, e).into() })?;
    Ok(val as i32)
}

/// Extract a byte-vec reference from clause args.
pub fn arg_as_bytes<'a>(args: &'a ClauseArgs, name: &str) -> Result<&'a Vec<u8>, BoxError> {
    args.get(name)
        .ok_or_else(|| format!("Missing arg '{}'", name).into())
}

// ---------------------------------------------------------------------------
// ClauseArg trait: extensible type support for contract!/define_clause_args!
// ---------------------------------------------------------------------------

/// Trait for types that can be used as clause arguments.
/// Implement this for new types to use them in `contract!` and `define_clause_args!`
/// without modifying the macros.
pub trait ClauseArg: Sized {
    fn arg_type() -> ArgType;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(data: &[u8]) -> Result<Self, BoxError>;
}

impl<const N: usize> ClauseArg for [u8; N] {
    fn arg_type() -> ArgType { ArgType::Bytes(N) }
    fn to_bytes(&self) -> Vec<u8> { self.to_vec() }
    fn from_bytes(data: &[u8]) -> Result<Self, BoxError> {
        data.try_into().map_err(|_| format!("expected {} bytes, got {}", N, data.len()).into())
    }
}

impl ClauseArg for i32 {
    fn arg_type() -> ArgType { ArgType::Int }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut buf, *self as i64);
        buf[..len].to_vec()
    }
    fn from_bytes(data: &[u8]) -> Result<Self, BoxError> {
        Ok(bitcoin::script::read_scriptint(data)
            .map_err(|e| -> BoxError { e.to_string().into() })? as i32)
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
