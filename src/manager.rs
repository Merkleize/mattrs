//! Contract Manager
//!
//! Manages the lifecycle of contract instances from funding through spending,
//! with automatic output tracking and witness decoding.
//!
//! Spending goes through the fluent [`SpendBuilder`]: a clause is invoked with its
//! typed arguments (already encoded to a witness stack), signers are registered by
//! public key, and `exec`/`exec_one`/`exec_none` build, sign, broadcast and
//! materialize the resulting child instances.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
    thread::sleep,
    time::Duration,
};

use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey};
use bitcoincore_rpc::{Client, RpcApi};

use crate::{
    contracts::{
        ClauseError, ClauseOutput, ClauseOutputAmountBehaviour, ContractError, ContractInstance,
        ContractState, ErasedContract, InstanceStatus, OutputIndex,
    },
    signer::Signer,
};

/// Type alias for a map of signers keyed by public key.
pub type SignerMap = HashMap<XOnlyPublicKey, Box<dyn Signer>>;

/// Error type for manager operations.
#[derive(Debug)]
pub enum ManagerError {
    RpcError(bitcoincore_rpc::Error),
    ClauseError(ClauseError),
    ContractError(ContractError),
    InvalidInstance(String),
    OutputNotFound,
    TransactionBuildError(String),
    /// A clause requires a signature from this key, but no signer was registered
    /// and no signature was pre-filled.
    MissingSigner(XOnlyPublicKey),
    /// A spend produced a different number of child instances than the caller
    /// asserted via `exec_one` / `exec_none`.
    UnexpectedOutputCount { expected: usize, got: usize },
    Other(String),
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerError::RpcError(e) => write!(f, "RPC error: {}", e),
            ManagerError::ClauseError(e) => write!(f, "Clause error: {}", e),
            ManagerError::ContractError(e) => write!(f, "Contract error: {}", e),
            ManagerError::InvalidInstance(msg) => write!(f, "Invalid instance: {}", msg),
            ManagerError::OutputNotFound => write!(f, "Output not found on blockchain"),
            ManagerError::TransactionBuildError(msg) => {
                write!(f, "Transaction build error: {}", msg)
            }
            ManagerError::MissingSigner(pk) => {
                write!(f, "No signer registered for required key {}", pk)
            }
            ManagerError::UnexpectedOutputCount { expected, got } => write!(
                f,
                "Unexpected number of spend outputs: expected {}, got {}",
                expected, got
            ),
            ManagerError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ManagerError {}

impl From<bitcoincore_rpc::Error> for ManagerError {
    fn from(e: bitcoincore_rpc::Error) -> Self {
        ManagerError::RpcError(e)
    }
}

impl From<ClauseError> for ManagerError {
    fn from(e: ClauseError) -> Self {
        ManagerError::ClauseError(e)
    }
}

impl From<ContractError> for ManagerError {
    fn from(e: ContractError) -> Self {
        ManagerError::ContractError(e)
    }
}

/// Manages contract instances and their lifecycle.
pub struct ContractManager<'a> {
    /// RPC client for blockchain interaction.
    rpc: &'a Client,

    /// All instances managed by this manager.
    instances: Vec<Rc<RefCell<ContractInstance>>>,
}

impl<'a> ContractManager<'a> {
    /// Create a new contract manager.
    pub fn new(rpc: &'a Client) -> Self {
        Self {
            rpc,
            instances: Vec::new(),
        }
    }

    /// The RPC client, for callers that need direct access (e.g. mining or funding).
    pub fn rpc(&self) -> &Client {
        self.rpc
    }

    /// Add an existing instance to the manager and return a handle to it.
    pub fn add_instance(&mut self, instance: Rc<RefCell<ContractInstance>>) -> InstanceHandle {
        self.instances.push(instance.clone());
        InstanceHandle { instance }
    }

    /// Create and fund a new contract instance. Params are taken from the
    /// (self-describing) contract.
    pub fn fund_instance(
        &mut self,
        contract: std::sync::Arc<dyn ErasedContract>,
        state_bytes: Option<Vec<u8>>,
        amount: Amount,
    ) -> Result<InstanceHandle, ManagerError> {
        // Create the instance
        let instance = Rc::new(RefCell::new(ContractInstance::new(contract, state_bytes)));

        // Get the script pubkey for this instance
        let script_pubkey = self.get_instance_script_pubkey(&instance)?;

        // Fund it using RPC
        let params = bitcoin::Network::Regtest.params();
        let address = bitcoin::Address::from_script(&script_pubkey, params)
            .map_err(|e| ManagerError::Other(format!("Failed to create address: {}", e)))?;

        let txid = self
            .rpc
            .send_to_address(&address, amount, None, None, None, None, None, None)?;

        // Wait for the transaction to appear
        let tx = self.wait_for_transaction(txid)?;

        // Find the output index
        let vout = tx
            .output
            .iter()
            .position(|output| output.script_pubkey == script_pubkey)
            .ok_or(ManagerError::OutputNotFound)?;

        let outpoint = OutPoint {
            txid,
            vout: vout as u32,
        };

        // Mark as funded
        instance.borrow_mut().mark_funded(outpoint, tx);

        // Add to managed instances
        self.instances.push(instance.clone());

        Ok(InstanceHandle { instance })
    }

    /// Mine blocks (for regtest).
    pub fn mine_blocks(&self, n: u64) -> Result<(), ManagerError> {
        let address = self.rpc.get_new_address(None, None)?.assume_checked();
        self.rpc.generate_to_address(n, &address)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Spend execution (driven by SpendBuilder)
    // ------------------------------------------------------------------

    /// Build (and sign) the spending transaction for `builder`, without
    /// broadcasting. Also returns the clause's next outputs (for child creation).
    fn build_spend_tx(
        &self,
        builder: &SpendBuilder,
    ) -> Result<(Transaction, Vec<ClauseOutput>), ManagerError> {
        let inst = builder.instance.borrow();
        if inst.status != InstanceStatus::Funded {
            return Err(ManagerError::InvalidInstance(
                "Instance is not funded".to_string(),
            ));
        }
        let outpoint = inst
            .outpoint
            .ok_or_else(|| ManagerError::InvalidInstance("No outpoint".to_string()))?;

        let clause_outputs = inst.contract.execute_clause_from_witness(
            builder.clause_name,
            &inst.params_bytes,
            &builder.witness_args,
            inst.state_bytes.as_deref(),
        )?;
        drop(inst);

        let tx = self.build_transaction(outpoint, builder, &clause_outputs)?;
        Ok((tx, clause_outputs))
    }

    /// Execute a spend: build, sign, broadcast, and materialize child instances.
    fn execute_spend(&mut self, builder: SpendBuilder) -> Result<Vec<InstanceHandle>, ManagerError> {
        let (tx, clause_outputs) = self.build_spend_tx(&builder)?;

        // Broadcast
        let txid = self.rpc.send_raw_transaction(&tx)?;

        // Mark the spent instance
        builder
            .instance
            .borrow_mut()
            .mark_spent(txid, builder.clause_name.to_string());

        // Materialize children
        let child_instances = self.create_output_instances(&builder.instance, clause_outputs)?;
        for child in &child_instances {
            builder.instance.borrow_mut().add_output(child.clone());
        }

        Ok(child_instances
            .into_iter()
            .map(|instance| InstanceHandle { instance })
            .collect())
    }

    // Helper methods

    fn get_instance_script_pubkey(
        &self,
        instance: &Rc<RefCell<ContractInstance>>,
    ) -> Result<bitcoin::ScriptBuf, ManagerError> {
        let inst = instance.borrow();
        Ok(inst.contract.script_pubkey(inst.state_bytes.as_deref())?)
    }

    fn wait_for_transaction(&self, txid: Txid) -> Result<Transaction, ManagerError> {
        // Poll for transaction
        for _ in 0..30 {
            if let Ok(_tx_info) = self.rpc.get_raw_transaction_info(&txid, None) {
                let tx_hex = self.rpc.get_raw_transaction(&txid, None)?;
                return Ok(tx_hex);
            }
            sleep(Duration::from_millis(100));
        }
        Err(ManagerError::Other(
            "Transaction not found after polling".to_string(),
        ))
    }

    /// Build the (single-input) spending transaction for `builder`, deriving
    /// outputs from the clause outputs (or the caller's explicit outputs), filling
    /// signature witness elements, and appending the tapscript + control block.
    fn build_transaction(
        &self,
        outpoint: OutPoint,
        builder: &SpendBuilder,
        clause_outputs: &[ClauseOutput],
    ) -> Result<Transaction, ManagerError> {
        let seq = builder.sequence.unwrap_or(Sequence::ZERO);
        let tx_inputs = vec![TxIn {
            previous_output: outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: seq,
            witness: bitcoin::Witness::new(),
        }];

        let tx_outputs = if let Some(outputs) = &builder.explicit_outputs {
            outputs.clone()
        } else {
            self.derive_outputs(builder, clause_outputs)?
        };

        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        // The witness starts as the (already-encoded) clause arguments.
        let mut witness_stack = builder.witness_args.clone();

        // Fill signature elements, then append the leaf script and control block.
        let inst = builder.instance.borrow();
        let clause = inst
            .contract
            .get_clause(builder.clause_name)
            .ok_or_else(|| {
                ManagerError::TransactionBuildError(format!(
                    "Clause '{}' not found",
                    builder.clause_name
                ))
            })?;
        let leaf_script = clause.script().clone();

        // Only compute a sighash / sign when the clause actually has signature args.
        let needs_signature = clause
            .arg_specs()
            .iter()
            .any(|spec| spec.arg_type.signer_pubkey().is_some());

        if needs_signature {
            let prevout = inst
                .funding_tx
                .as_ref()
                .and_then(|ftx| {
                    inst.outpoint
                        .as_ref()
                        .map(|op| ftx.output[op.vout as usize].clone())
                })
                .ok_or_else(|| {
                    ManagerError::TransactionBuildError("No prevout available".to_string())
                })?;

            let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
                &leaf_script,
                bitcoin::taproot::LeafVersion::TapScript,
            );

            let sighash = crate::signer::compute_tap_sighash(
                &tx,
                0,
                &[prevout],
                Some(leaf_hash),
                bitcoin::sighash::TapSighashType::Default,
            )
            .map_err(|e| ManagerError::TransactionBuildError(e.to_string()))?;

            // Walk arg specs in witness order. A signature arg names the x-only key
            // that must sign its (single) witness element; sign with the registered
            // signer, or error if the element is empty and no signer is available.
            let mut offset = 0usize;
            for spec in clause.arg_specs() {
                let (_value, consumed) = spec
                    .arg_type
                    .decode_from_witness(&witness_stack[offset..])
                    .map_err(|e| ManagerError::TransactionBuildError(e.to_string()))?;

                if let Some(pubkey) = spec.arg_type.signer_pubkey() {
                    let xonly = XOnlyPublicKey::from_slice(&pubkey).map_err(|e| {
                        ManagerError::TransactionBuildError(format!(
                            "Invalid signer pubkey for argument '{}': {}",
                            spec.name, e
                        ))
                    })?;
                    if let Some(signer) = builder.signers.get(&xonly) {
                        witness_stack[offset] = signer.sign(&sighash);
                    } else if witness_stack[offset].is_empty() {
                        // No signer and no pre-filled signature: fail loudly instead
                        // of broadcasting an invalid witness.
                        return Err(ManagerError::MissingSigner(xonly));
                    }
                }

                offset += consumed;
            }
        }

        // Append the leaf script and control block (state-tweaked key for augmented).
        let internal_key = inst
            .contract
            .control_block_internal_key(inst.state_bytes.as_deref())?;
        let taptree = inst.contract.taptree();
        let control_block = taptree
            .control_block(&internal_key, builder.clause_name)
            .ok_or_else(|| {
                ManagerError::TransactionBuildError(format!(
                    "Could not generate control block for clause '{}'",
                    builder.clause_name
                ))
            })?;
        drop(inst);

        witness_stack.push(leaf_script.to_bytes());
        witness_stack.push(control_block);

        tx.input[0].witness = bitcoin::Witness::from_slice(&witness_stack);
        Ok(tx)
    }

    /// Derive the transaction outputs from a clause's outputs, honoring each
    /// output's index and amount behaviour. `PreserveOutput`s receive the input
    /// amount minus any `DeductOutput` amounts (which must be supplied via
    /// [`SpendBuilder::output_amount`]).
    fn derive_outputs(
        &self,
        builder: &SpendBuilder,
        clause_outputs: &[ClauseOutput],
    ) -> Result<Vec<TxOut>, ManagerError> {
        // The spending input index (single input => 0), used to resolve `Same`.
        let input_index = 0u32;

        let input_amount = {
            let inst = builder.instance.borrow();
            inst.funding_tx
                .as_ref()
                .and_then(|ftx| {
                    inst.outpoint
                        .as_ref()
                        .map(|op| ftx.output[op.vout as usize].value)
                })
                .unwrap_or(Amount::ZERO)
        };

        let index_of = |co: &ClauseOutput| -> u32 {
            match co.index {
                OutputIndex::Same => input_index,
                OutputIndex::Explicit(n) => n,
            }
        };

        // Sum the explicitly-deducted amounts; the preserved output gets the rest.
        let mut total_deduct = Amount::ZERO;
        for co in clause_outputs {
            if co.next_amount == ClauseOutputAmountBehaviour::DeductOutput {
                let idx = index_of(co);
                let amt = builder.output_amounts.get(&idx).ok_or_else(|| {
                    ManagerError::TransactionBuildError(format!(
                        "DeductOutput at index {} needs an amount (SpendBuilder::output_amount)",
                        idx
                    ))
                })?;
                total_deduct += *amt;
            }
        }
        let preserve_value = input_amount.checked_sub(total_deduct).ok_or_else(|| {
            ManagerError::TransactionBuildError(
                "Deducted output amounts exceed the input amount".to_string(),
            )
        })?;

        let mut outputs_map: BTreeMap<u32, TxOut> = BTreeMap::new();
        for co in clause_outputs {
            let idx = index_of(co);
            let script_pubkey = co
                .next_contract
                .script_pubkey(co.next_state.as_deref())?;
            let value = match co.next_amount {
                ClauseOutputAmountBehaviour::PreserveOutput => preserve_value,
                ClauseOutputAmountBehaviour::IgnoreOutput => Amount::ZERO,
                ClauseOutputAmountBehaviour::DeductOutput => *builder
                    .output_amounts
                    .get(&idx)
                    .expect("checked above"),
            };
            outputs_map.insert(idx, TxOut { script_pubkey, value });
        }

        // Flatten into a contiguous 0..n vector.
        let mut outputs = Vec::with_capacity(outputs_map.len());
        for i in 0..outputs_map.len() as u32 {
            let out = outputs_map.remove(&i).ok_or_else(|| {
                ManagerError::TransactionBuildError(format!(
                    "Clause outputs are not contiguous (missing index {})",
                    i
                ))
            })?;
            outputs.push(out);
        }
        Ok(outputs)
    }

    fn create_output_instances(
        &mut self,
        parent: &Rc<RefCell<ContractInstance>>,
        outputs: Vec<ClauseOutput>,
    ) -> Result<Vec<Rc<RefCell<ContractInstance>>>, ManagerError> {
        let mut instances = Vec::new();

        // Get parent's transaction info
        let parent_ref = parent.borrow();
        let parent_txid = parent_ref
            .spent_in_tx
            .ok_or_else(|| ManagerError::InvalidInstance("Parent not spent yet".to_string()))?;
        drop(parent_ref);

        // Wait for the spending transaction
        let spending_tx = self.wait_for_transaction(parent_txid)?;

        // Create instances for each output
        for clause_out in outputs.iter() {
            let vout = match clause_out.index {
                OutputIndex::Same => {
                    let parent_ref = parent.borrow();
                    parent_ref
                        .outpoint
                        .ok_or_else(|| {
                            ManagerError::InvalidInstance("No parent outpoint".to_string())
                        })?
                        .vout
                }
                OutputIndex::Explicit(n) => n,
            };

            // The child contract is self-describing, so its params come from it.
            let instance = Rc::new(RefCell::new(ContractInstance::new(
                clause_out.next_contract.clone(),
                clause_out.next_state.clone(),
            )));

            let outpoint = OutPoint {
                txid: parent_txid,
                vout,
            };
            instance
                .borrow_mut()
                .mark_funded(outpoint, spending_tx.clone());

            self.instances.push(instance.clone());
            instances.push(instance);
        }

        Ok(instances)
    }
}

/// Error returned when converting an [`InstanceHandle`] into a typed per-contract
/// handle whose contract does not match the instance's actual contract.
#[derive(Debug, Clone)]
pub struct WrongContractType {
    /// The contract type the conversion expected.
    pub expected: &'static str,
}

impl std::fmt::Display for WrongContractType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "instance is not a `{}` contract",
            self.expected
        )
    }
}

impl std::error::Error for WrongContractType {}

/// A handle to a contract instance.
///
/// Cheap to clone (it is an `Rc` inside). Unlike the old design it does not borrow
/// the manager, so callers can hold handles across spends and chain naturally. The
/// `contract!` macro wraps this in a typed per-contract handle whose methods return
/// a [`SpendBuilder`]; drop down to [`InstanceHandle::spend_clause`] for advanced use.
#[derive(Clone)]
pub struct InstanceHandle {
    pub instance: Rc<RefCell<ContractInstance>>,
}

impl InstanceHandle {
    /// Wrap a raw instance pointer.
    pub fn new(instance: Rc<RefCell<ContractInstance>>) -> Self {
        Self { instance }
    }

    /// Get the instance status.
    pub fn status(&self) -> InstanceStatus {
        self.instance.borrow().status
    }

    /// Get the outpoint (if funded).
    pub fn outpoint(&self) -> Option<OutPoint> {
        self.instance.borrow().outpoint
    }

    /// The `TypeId` of the underlying contract (for typed-handle conversions).
    pub fn contract_type_id(&self) -> std::any::TypeId {
        self.instance.borrow().contract.contract_type_id()
    }

    /// Decode this instance's state as `S`, if it has any.
    pub fn state<S: ContractState>(&self) -> Option<S> {
        let inst = self.instance.borrow();
        inst.state_bytes
            .as_deref()
            .and_then(|bytes| S::decode(bytes).ok())
    }

    /// Get the child instances created from spending this instance.
    pub fn outputs(&self) -> Vec<InstanceHandle> {
        self.instance
            .borrow()
            .outputs
            .iter()
            .cloned()
            .map(|instance| InstanceHandle { instance })
            .collect()
    }

    /// Begin a spend of `clause_name` with the given (already-encoded) witness
    /// arguments. The `contract!`-generated per-clause methods call this; most code
    /// should prefer those typed methods.
    pub fn spend_clause(
        &self,
        clause_name: &'static str,
        witness_args: Vec<Vec<u8>>,
    ) -> SpendBuilder {
        SpendBuilder {
            instance: self.instance.clone(),
            clause_name,
            witness_args,
            signers: HashMap::new(),
            explicit_outputs: None,
            output_amounts: BTreeMap::new(),
            sequence: None,
        }
    }
}

/// A fluent builder for spending a single contract instance through one clause.
///
/// Created by the `contract!`-generated per-clause methods (or
/// [`InstanceHandle::spend_clause`]). Register signers with [`SpendBuilder::sign`],
/// then finish with [`SpendBuilder::exec`] / [`exec_one`](SpendBuilder::exec_one) /
/// [`exec_none`](SpendBuilder::exec_none).
pub struct SpendBuilder {
    instance: Rc<RefCell<ContractInstance>>,
    clause_name: &'static str,
    witness_args: Vec<Vec<u8>>,
    signers: SignerMap,
    explicit_outputs: Option<Vec<TxOut>>,
    output_amounts: BTreeMap<u32, Amount>,
    sequence: Option<Sequence>,
}

impl SpendBuilder {
    /// Register a signer (matched to the clause's signature args by public key).
    pub fn sign(mut self, signer: impl Signer + 'static) -> Self {
        self.signers.insert(signer.public_key(), Box::new(signer));
        self
    }

    /// Register a boxed signer.
    pub fn signer(mut self, signer: Box<dyn Signer>) -> Self {
        self.signers.insert(signer.public_key(), signer);
        self
    }

    /// Provide the transaction outputs explicitly (e.g. a CTV template), instead of
    /// deriving them from the clause's outputs.
    pub fn outputs(mut self, outputs: Vec<TxOut>) -> Self {
        self.explicit_outputs = Some(outputs);
        self
    }

    /// Set the amount for a `DeductOutput` clause output at `index` (e.g. a revault).
    pub fn output_amount(mut self, index: u32, amount: Amount) -> Self {
        self.output_amounts.insert(index, amount);
        self
    }

    /// Set the input's `nSequence` (e.g. to satisfy a CSV timelock / CTV template).
    pub fn sequence(mut self, sequence: u32) -> Self {
        self.sequence = Some(Sequence(sequence));
        self
    }

    /// Build and sign the spending transaction without broadcasting it.
    pub fn build_tx(&self, manager: &ContractManager) -> Result<Transaction, ManagerError> {
        Ok(manager.build_spend_tx(self)?.0)
    }

    /// Build, sign, broadcast, and return handles to all child instances.
    pub fn exec(self, manager: &mut ContractManager) -> Result<Vec<InstanceHandle>, ManagerError> {
        manager.execute_spend(self)
    }

    /// Like [`exec`](Self::exec) but asserts exactly one child instance is produced.
    pub fn exec_one(self, manager: &mut ContractManager) -> Result<InstanceHandle, ManagerError> {
        let mut outputs = self.exec(manager)?;
        if outputs.len() != 1 {
            return Err(ManagerError::UnexpectedOutputCount {
                expected: 1,
                got: outputs.len(),
            });
        }
        Ok(outputs.pop().expect("length checked"))
    }

    /// Like [`exec`](Self::exec) but asserts the clause is terminal (no children).
    pub fn exec_none(self, manager: &mut ContractManager) -> Result<(), ManagerError> {
        let outputs = self.exec(manager)?;
        if !outputs.is_empty() {
            return Err(ManagerError::UnexpectedOutputCount {
                expected: 0,
                got: outputs.len(),
            });
        }
        Ok(())
    }
}
