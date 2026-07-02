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
        ContractState, ErasedContract, ErasedState, InstanceStatus, NextOutputs, OutputIndex,
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
    /// The instance being spent is not funded (or lacks its funding data).
    NotFunded,
    /// The named clause does not exist on the contract being spent.
    ClauseNotFound(String),
    /// A `DeductOutput` at this index needs an amount, supplied via
    /// [`SpendBuilder::output_amount`].
    MissingDeductAmount { index: u32 },
    /// The merged clause outputs skip a transaction output index.
    NonContiguousOutputs { missing_index: u32 },
    /// Deducted output amounts exceed the input amount.
    DeductExceedsInput,
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
            ManagerError::NotFunded => write!(f, "Instance is not funded"),
            ManagerError::ClauseNotFound(name) => write!(f, "Clause '{}' not found", name),
            ManagerError::MissingDeductAmount { index } => write!(
                f,
                "DeductOutput at index {} needs an amount (SpendBuilder::output_amount)",
                index
            ),
            ManagerError::NonContiguousOutputs { missing_index } => write!(
                f,
                "Clause outputs are not contiguous (missing index {})",
                missing_index
            ),
            ManagerError::DeductExceedsInput => {
                write!(f, "Deducted output amounts exceed the input amount")
            }
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

    /// Create and fund a new contract instance. Params are taken from the
    /// (self-describing) contract.
    pub fn fund_instance(
        &mut self,
        contract: std::sync::Arc<dyn ErasedContract>,
        state: Option<Box<dyn ErasedState>>,
        amount: Amount,
    ) -> Result<InstanceHandle, ManagerError> {
        // Create the instance (its committed bytes derive from the logical state).
        let instance = Rc::new(RefCell::new(ContractInstance::new(contract, state)));

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
    ) -> Result<(Transaction, NextOutputs), ManagerError> {
        let (tx, mut nexts) = self.assemble(std::slice::from_ref(builder))?;
        Ok((tx, nexts.pop().expect("one builder yields one next")))
    }

    /// Execute a spend: build, sign, broadcast, and materialize child instances.
    fn execute_spend(&mut self, builder: SpendBuilder) -> Result<Vec<InstanceHandle>, ManagerError> {
        let (tx, next) = self.build_spend_tx(&builder)?;

        // Broadcast
        let txid = self.rpc.send_raw_transaction(&tx)?;

        // Mark the spent instance
        builder
            .instance
            .borrow_mut()
            .mark_spent(txid, builder.clause_name.to_string());

        // Materialize children (a CTV template spend is terminal).
        let child_instances = match next {
            NextOutputs::Contracts(outputs) => {
                self.create_output_instances(&builder.instance, outputs)?
            }
            NextOutputs::Template(_) => Vec::new(),
        };
        for child in &child_instances {
            builder.instance.borrow_mut().add_output(child.clone());
        }

        Ok(child_instances
            .into_iter()
            .map(|instance| InstanceHandle { instance })
            .collect())
    }

    /// Build (without broadcasting) a single transaction that spends several
    /// instances at once, merging their clause outputs by index. Useful for
    /// inspection/tests; [`spend_batch`](Self::spend_batch) also broadcasts.
    pub fn build_batch_tx(&self, builders: &[SpendBuilder]) -> Result<Transaction, ManagerError> {
        Ok(self.assemble(builders)?.0)
    }

    /// Spend several instances in one transaction (build, sign, broadcast), and
    /// return handles to the child instances created — one per merged output index.
    ///
    /// Mirrors pymatt's multi-input `get_spend_tx`: within each input the
    /// `DeductOutput`s must precede its `PreserveOutput`s, and a `PreserveOutput` at
    /// a shared index accumulates each contributing input's remaining amount (so N
    /// vaults triggering to the same next contract merge into one output). CTV
    /// template clauses are single-input only and are rejected here.
    pub fn spend_batch(
        &mut self,
        builders: Vec<SpendBuilder>,
    ) -> Result<Vec<InstanceHandle>, ManagerError> {
        let (tx, nexts) = self.assemble(&builders)?;

        let txid = self.rpc.send_raw_transaction(&tx)?;
        for builder in &builders {
            builder
                .instance
                .borrow_mut()
                .mark_spent(txid, builder.clause_name.to_string());
        }

        let spending_tx = self.wait_for_transaction(txid)?;

        // One child instance per unique merged output index that carries a contract.
        let mut by_index: BTreeMap<u32, ClauseOutput> = BTreeMap::new();
        for (input_index, next) in nexts.iter().enumerate() {
            if let NextOutputs::Contracts(clause_outputs) = next {
                for clause_output in clause_outputs {
                    let idx = match clause_output.index {
                        OutputIndex::Same => input_index as u32,
                        OutputIndex::Explicit(n) => n,
                    };
                    by_index.entry(idx).or_insert_with(|| clause_output.clone());
                }
            }
        }

        let mut handles = Vec::new();
        for (idx, clause_output) in by_index {
            let instance = Rc::new(RefCell::new(ContractInstance::new(
                clause_output.next_contract.clone(),
                clause_output.next_state.clone(),
            )));
            instance
                .borrow_mut()
                .mark_funded(OutPoint { txid, vout: idx }, spending_tx.clone());
            self.instances.push(instance.clone());
            handles.push(InstanceHandle { instance });
        }

        Ok(handles)
    }

    /// Shared core of every spend (a single spend is a batch of one): build the
    /// merged, signed transaction and return it alongside each input's
    /// [`NextOutputs`] (for child creation).
    fn assemble(
        &self,
        builders: &[SpendBuilder],
    ) -> Result<(Transaction, Vec<NextOutputs>), ManagerError> {
        if builders.is_empty() {
            return Err(ManagerError::TransactionBuildError(
                "empty batch spend".to_string(),
            ));
        }

        // Collect each input, its prevout, and its clause's next outputs.
        let mut prevouts = Vec::with_capacity(builders.len());
        let mut tx_inputs = Vec::with_capacity(builders.len());
        let mut nexts = Vec::with_capacity(builders.len());

        for builder in builders {
            let inst = builder.instance.borrow();
            if inst.status() != InstanceStatus::Funded {
                return Err(ManagerError::NotFunded);
            }
            let outpoint = inst.outpoint().ok_or(ManagerError::NotFunded)?;
            let prevout = inst.prevout().ok_or(ManagerError::NotFunded)?;
            prevouts.push(prevout);
            tx_inputs.push(TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: builder.sequence.unwrap_or(Sequence::ZERO),
                witness: bitcoin::Witness::new(),
            });
            let next = inst.contract().execute_clause_from_witness(
                builder.clause_name,
                &builder.witness_args,
                inst.state(),
            )?;
            nexts.push(next);
        }

        let (outputs, template_sequence) = Self::derive_tx_outputs(builders, &nexts, &prevouts)?;

        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: tx_inputs,
            output: outputs,
        };
        if let Some(sequence) = template_sequence {
            // A CTV template commits to the input's nSequence, so it wins.
            tx.input[0].sequence = sequence;
        }

        // Fill + finalize each input's witness (every sighash sees all prevouts).
        for (input_index, builder) in builders.iter().enumerate() {
            tx.input[input_index].witness =
                self.input_witness(builder, &tx, input_index, &prevouts)?;
        }

        Ok((tx, nexts))
    }

    /// Derive the transaction outputs for a spend, and the `nSequence` a CTV
    /// template fixes, if any.
    ///
    /// Caller-supplied explicit outputs win; otherwise a CTV template fixes the
    /// whole transaction; otherwise the covenant outputs are merged by index
    /// across all inputs (each `PreserveOutput` accumulates its input's amount
    /// net of that input's earlier `DeductOutput`s). Explicit outputs and CTV
    /// templates are single-input only.
    fn derive_tx_outputs(
        builders: &[SpendBuilder],
        nexts: &[NextOutputs],
        prevouts: &[TxOut],
    ) -> Result<(Vec<TxOut>, Option<Sequence>), ManagerError> {
        let single = builders.len() == 1;

        if let Some(explicit) = builders.iter().find_map(|b| b.explicit_outputs.as_ref()) {
            if !single {
                return Err(ManagerError::TransactionBuildError(
                    "explicit outputs are single-input only; not supported in a batch"
                        .to_string(),
                ));
            }
            return Ok((explicit.clone(), None));
        }

        if let Some(template) = nexts.iter().find_map(|next| match next {
            NextOutputs::Template(template) => Some(template),
            NextOutputs::Contracts(_) => None,
        }) {
            if !single {
                return Err(ManagerError::TransactionBuildError(
                    "CTV template clauses are single-input only; not supported in a batch"
                        .to_string(),
                ));
            }
            return Ok((template.outputs.clone(), Some(template.sequence)));
        }

        // Pool the per-builder DeductOutput amounts.
        let mut output_amounts: BTreeMap<u32, Amount> = BTreeMap::new();
        for builder in builders {
            for (idx, amount) in &builder.output_amounts {
                output_amounts.insert(*idx, *amount);
            }
        }

        // Merge clause outputs by index across all inputs.
        let mut outputs_map: BTreeMap<u32, TxOut> = BTreeMap::new();
        for (input_index, next) in nexts.iter().enumerate() {
            let clause_outputs = match next {
                NextOutputs::Contracts(clause_outputs) => clause_outputs,
                NextOutputs::Template(_) => unreachable!("templates are handled above"),
            };

            let mut remaining = prevouts[input_index].value;
            let mut preserve_used = false;
            for clause_output in clause_outputs {
                let idx = match clause_output.index {
                    OutputIndex::Same => input_index as u32,
                    OutputIndex::Explicit(n) => n,
                };
                let script_pubkey = clause_output
                    .next_contract
                    .script_pubkey(clause_output.committed_state_bytes().as_deref())?;
                let entry = outputs_map.entry(idx).or_insert_with(|| TxOut {
                    script_pubkey: script_pubkey.clone(),
                    value: Amount::ZERO,
                });
                if entry.script_pubkey != script_pubkey {
                    return Err(ManagerError::TransactionBuildError(format!(
                        "Clashing output script at index {}",
                        idx
                    )));
                }
                match clause_output.next_amount {
                    ClauseOutputAmountBehaviour::PreserveOutput => {
                        entry.value += remaining;
                        preserve_used = true;
                    }
                    ClauseOutputAmountBehaviour::DeductOutput => {
                        if preserve_used {
                            return Err(ManagerError::TransactionBuildError(
                                "DeductOutput must be declared before PreserveOutput".to_string(),
                            ));
                        }
                        let amount = *output_amounts
                            .get(&idx)
                            .ok_or(ManagerError::MissingDeductAmount { index: idx })?;
                        entry.value = amount;
                        remaining = remaining
                            .checked_sub(amount)
                            .ok_or(ManagerError::DeductExceedsInput)?;
                    }
                    ClauseOutputAmountBehaviour::IgnoreOutput => {}
                }
            }
        }

        // Flatten into a contiguous 0..n output vector.
        let mut outputs = Vec::with_capacity(outputs_map.len());
        for i in 0..outputs_map.len() as u32 {
            let out = outputs_map
                .remove(&i)
                .ok_or(ManagerError::NonContiguousOutputs { missing_index: i })?;
            outputs.push(out);
        }
        Ok((outputs, None))
    }

    // Helper methods

    fn get_instance_script_pubkey(
        &self,
        instance: &Rc<RefCell<ContractInstance>>,
    ) -> Result<bitcoin::ScriptBuf, ManagerError> {
        let inst = instance.borrow();
        Ok(inst
            .contract()
            .script_pubkey(inst.committed_state_bytes().as_deref())?)
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

    /// Build the full script-path witness for one input: the clause arguments with
    /// signature elements filled (by matching each `SignerType` pubkey to a
    /// registered signer), followed by the leaf script and its control block.
    fn input_witness(
        &self,
        builder: &SpendBuilder,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
    ) -> Result<bitcoin::Witness, ManagerError> {
        let clause_name = builder.clause_name;
        let signers = &builder.signers;
        let inst = builder.instance.borrow();
        let clause = inst
            .contract()
            .get_clause(clause_name)
            .ok_or_else(|| ManagerError::ClauseNotFound(clause_name.to_string()))?;
        let leaf_script = clause.script().clone();

        let mut witness_stack = builder.witness_args.to_vec();

        // Only compute a sighash / sign when the clause has signature args.
        let needs_signature = clause
            .arg_specs()
            .iter()
            .any(|spec| spec.arg_type.signer_pubkey().is_some());

        if needs_signature {
            let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
                &leaf_script,
                bitcoin::taproot::LeafVersion::TapScript,
            );
            let sighash = crate::signer::compute_tap_sighash(
                tx,
                input_index,
                prevouts,
                Some(leaf_hash),
                bitcoin::sighash::TapSighashType::Default,
            )
            .map_err(|e| ManagerError::TransactionBuildError(e.to_string()))?;

            // Walk arg specs in witness order. A signature arg names the x-only key
            // that must sign its (single) witness element; sign with the registered
            // signer, or error if the element is empty and no signer is available.
            let mut offset = 0usize;
            for spec in clause.arg_specs() {
                let consumed = spec
                    .arg_type
                    .consume(&witness_stack[offset..])
                    .map_err(|e| ManagerError::TransactionBuildError(e.to_string()))?;

                if let Some(pubkey) = spec.arg_type.signer_pubkey() {
                    let xonly = XOnlyPublicKey::from_slice(&pubkey).map_err(|e| {
                        ManagerError::TransactionBuildError(format!(
                            "Invalid signer pubkey for argument '{}': {}",
                            spec.name, e
                        ))
                    })?;
                    if let Some(signer) = signers.get(&xonly) {
                        witness_stack[offset] = signer.sign(&sighash);
                    } else if witness_stack[offset].is_empty() {
                        return Err(ManagerError::MissingSigner(xonly));
                    }
                }

                offset += consumed;
            }
        }

        // Append the leaf script and control block (state-tweaked key for augmented).
        let internal_key = inst
            .contract()
            .control_block_internal_key(inst.committed_state_bytes().as_deref())?;
        let control_block = inst
            .contract()
            .taptree()
            .control_block(&internal_key, clause_name)
            .ok_or_else(|| {
                ManagerError::TransactionBuildError(format!(
                    "Could not generate control block for clause '{}'",
                    clause_name
                ))
            })?;

        witness_stack.push(leaf_script.to_bytes());
        witness_stack.push(control_block);

        Ok(bitcoin::Witness::from_slice(&witness_stack))
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
            .spent_in_tx()
            .ok_or_else(|| ManagerError::InvalidInstance("Parent not spent yet".to_string()))?;
        drop(parent_ref);

        // Wait for the spending transaction
        let spending_tx = self.wait_for_transaction(parent_txid)?;

        // Create instances for each output
        for clause_out in outputs.iter() {
            let vout = match clause_out.index {
                // `Same` means "same as the spending input's index"; this path is
                // only reached from single-input spends, whose input index is 0
                // (matching how the transaction's outputs were derived).
                OutputIndex::Same => 0,
                OutputIndex::Explicit(n) => n,
            };

            // The child contract is self-describing, so its params come from it;
            // it also carries the logical state for its own future spends.
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
    instance: Rc<RefCell<ContractInstance>>,
}

impl InstanceHandle {
    /// Wrap a raw instance pointer.
    pub fn new(instance: Rc<RefCell<ContractInstance>>) -> Self {
        Self { instance }
    }

    /// Get the instance status.
    pub fn status(&self) -> InstanceStatus {
        self.instance.borrow().status()
    }

    /// Get the outpoint (if funded).
    pub fn outpoint(&self) -> Option<OutPoint> {
        self.instance.borrow().outpoint()
    }

    /// The `TypeId` of the underlying contract (for typed-handle conversions).
    pub fn contract_type_id(&self) -> std::any::TypeId {
        self.instance.borrow().contract().contract_type_id()
    }

    /// This instance's state as `S`, if it has any: the logical state when it is
    /// an `S` (by downcast), else whatever `S::decode` recovers from the committed
    /// bytes (for round-tripping states).
    pub fn state<S: ContractState + 'static>(&self) -> Option<S> {
        let inst = self.instance.borrow();
        let erased = inst.state()?;
        if let Some(typed) = erased.as_any().downcast_ref::<S>() {
            return Some(typed.clone());
        }
        S::decode(&erased.committed_bytes()).ok()
    }

    /// Get the child instances created from spending this instance.
    pub fn outputs(&self) -> Vec<InstanceHandle> {
        self.instance
            .borrow()
            .outputs()
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
