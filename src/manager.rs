//! Contract Manager
//!
//! Manages the lifecycle of contract instances from funding through spending,
//! with automatic output tracking and witness decoding.
//!
//! Spending goes through the fluent [`SpendBuilder`]: a clause is invoked with its
//! typed arguments (already encoded to a witness stack), signers are registered by
//! public key, and `exec`/`exec_one`/`exec_none` build, sign, broadcast and
//! materialize the resulting child instances.
//!
//! Covenants driven by *someone else* are followed with chain observation:
//! [`ContractManager::track_instance`] registers an externally funded instance,
//! and [`ContractManager::wait_for_spend`] (or the RPC-free
//! [`ContractManager::observe_spend`]) detects its spend, decodes the witness
//! back into the clause and its arguments, and materializes the child instances
//! — so both parties of a protocol hold the same view of the contract's state.

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

/// How many 100ms polls [`ContractManager::wait_for_spend`] performs before
/// giving up (30 seconds).
const POLL_ATTEMPTS: usize = 300;

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
    /// An observed spending transaction could not be decoded back into a clause
    /// (key-path spend, unknown tapscript, or a witness/spec mismatch).
    UnrecognizedSpend(String),
    /// No transaction spending this outpoint was found within the polling window.
    SpendNotFound(OutPoint),
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
            ManagerError::UnrecognizedSpend(msg) => {
                write!(f, "Cannot decode the observed spend: {}", msg)
            }
            ManagerError::SpendNotFound(outpoint) => {
                write!(f, "No transaction spending {} found while polling", outpoint)
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
        builder.instance.borrow_mut().mark_spent(
            txid,
            0,
            builder.clause_name.to_string(),
            builder.witness_args.clone(),
        );

        // Materialize children (a CTV template spend is terminal).
        let child_instances = match &next {
            NextOutputs::Contracts(outputs) => {
                self.materialize_outputs(&builder.instance, outputs, &tx, 0)?
            }
            NextOutputs::Template(_) => Vec::new(),
        };

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
        for (vin, builder) in builders.iter().enumerate() {
            builder.instance.borrow_mut().mark_spent(
                txid,
                vin,
                builder.clause_name.to_string(),
                builder.witness_args.clone(),
            );
        }

        // Materialize the children; outputs merged across inputs (a shared
        // `PreserveOutput` index) yield one child instance, linked to each parent.
        let mut handles = Vec::new();
        for (vin, (builder, next)) in builders.iter().zip(&nexts).enumerate() {
            if let NextOutputs::Contracts(outputs) = next {
                let children = self.materialize_outputs(&builder.instance, outputs, &tx, vin)?;
                for child in children {
                    if !handles
                        .iter()
                        .any(|h: &InstanceHandle| Rc::ptr_eq(&h.instance, &child))
                    {
                        handles.push(InstanceHandle { instance: child });
                    }
                }
            }
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

    /// A managed instance funded at `outpoint`, if any. Used to deduplicate
    /// children when several parents' clause outputs merge into one transaction
    /// output (each parent then links to the same child instance).
    fn find_instance_by_outpoint(&self, outpoint: OutPoint) -> Option<Rc<RefCell<ContractInstance>>> {
        self.instances
            .iter()
            .find(|inst| inst.borrow().outpoint() == Some(outpoint))
            .cloned()
    }

    /// Materialize (and register) the child instances a spent parent's clause
    /// outputs define, linking them to the parent. `vin` is the parent's input
    /// index within `spending_tx` (which resolves [`OutputIndex::Same`]). A child
    /// already materialized at the same outpoint — e.g. a batch output merged
    /// across inputs — is reused, not duplicated.
    fn materialize_outputs(
        &mut self,
        parent: &Rc<RefCell<ContractInstance>>,
        outputs: &[ClauseOutput],
        spending_tx: &Transaction,
        vin: usize,
    ) -> Result<Vec<Rc<RefCell<ContractInstance>>>, ManagerError> {
        let txid = spending_tx.compute_txid();
        let mut children = Vec::new();

        for clause_out in outputs {
            let vout = match clause_out.index {
                OutputIndex::Same => vin as u32,
                OutputIndex::Explicit(n) => n,
            };
            let outpoint = OutPoint { txid, vout };

            let child = match self.find_instance_by_outpoint(outpoint) {
                Some(existing) => existing,
                None => {
                    // The child contract is self-describing, so its params come
                    // from it; it also carries the logical state for its own
                    // future spends.
                    let instance = Rc::new(RefCell::new(ContractInstance::new(
                        clause_out.next_contract.clone(),
                        clause_out.next_state.clone(),
                    )));
                    instance
                        .borrow_mut()
                        .mark_funded(outpoint, spending_tx.clone());
                    self.instances.push(instance.clone());
                    instance
                }
            };

            parent.borrow_mut().add_output(child.clone());
            children.push(child);
        }

        Ok(children)
    }

    // ------------------------------------------------------------------
    // Chain observation: following spends made by others
    // ------------------------------------------------------------------

    /// Start tracking a contract instance that was funded externally (e.g. by a
    /// counterparty): fetch the funding transaction, verify that `outpoint` pays
    /// the contract's address (for the given state), and register the funded
    /// instance.
    ///
    /// This is the observer-side entry point of a multi-party protocol: the
    /// funder shares the outpoint, both sides construct the same contract, and
    /// the observer then follows it with [`wait_for_spend`](Self::wait_for_spend).
    pub fn track_instance(
        &mut self,
        contract: std::sync::Arc<dyn ErasedContract>,
        state: Option<Box<dyn ErasedState>>,
        outpoint: OutPoint,
    ) -> Result<InstanceHandle, ManagerError> {
        let instance = Rc::new(RefCell::new(ContractInstance::new(contract, state)));

        let expected_spk = self.get_instance_script_pubkey(&instance)?;
        let funding_tx = self.rpc.get_raw_transaction(&outpoint.txid, None)?;
        let paid = funding_tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(ManagerError::OutputNotFound)?;
        if paid.script_pubkey != expected_spk {
            return Err(ManagerError::OutputNotFound);
        }

        instance.borrow_mut().mark_funded(outpoint, funding_tx);
        self.instances.push(instance.clone());
        Ok(InstanceHandle { instance })
    }

    /// Decode an already-known transaction that spends `handle`'s instance:
    /// identify the clause from the tapscript in the witness, record the spend
    /// (clause name + witness arguments) on the instance, execute the clause's
    /// `next_outputs` against the decoded arguments, and materialize the child
    /// instances. Performs no RPC.
    ///
    /// Returns the child handles (empty for terminal and CTV-template clauses).
    /// If the instance is already marked spent by this same transaction, the
    /// previously materialized children are returned.
    pub fn observe_spend(
        &mut self,
        handle: &InstanceHandle,
        spending_tx: &Transaction,
    ) -> Result<Vec<InstanceHandle>, ManagerError> {
        let txid = spending_tx.compute_txid();

        {
            let inst = handle.instance.borrow();
            if inst.status() == InstanceStatus::Spent {
                if inst.spent_in_tx() == Some(txid) {
                    return Ok(handle.outputs());
                }
                return Err(ManagerError::InvalidInstance(
                    "Instance already spent by a different transaction".to_string(),
                ));
            }
            if inst.status() != InstanceStatus::Funded {
                return Err(ManagerError::NotFunded);
            }
        }
        let outpoint = handle
            .instance
            .borrow()
            .outpoint()
            .ok_or(ManagerError::NotFunded)?;

        // Which input of `spending_tx` consumes this instance?
        let vin = spending_tx
            .input
            .iter()
            .position(|input| input.previous_output == outpoint)
            .ok_or_else(|| {
                ManagerError::UnrecognizedSpend(format!(
                    "transaction {} does not spend {}",
                    txid, outpoint
                ))
            })?;

        // Split the script-path witness and identify the clause by its tapscript.
        let (witness_args, leaf_script) =
            parse_script_path_witness(&spending_tx.input[vin].witness)?;
        let (clause_name, next) = {
            let inst = handle.instance.borrow();
            let clause = inst
                .contract()
                .clauses()
                .iter()
                .find(|c| c.script().as_bytes() == leaf_script.as_slice())
                .cloned()
                .ok_or_else(|| {
                    ManagerError::UnrecognizedSpend(
                        "the spending tapscript matches no clause of this contract".to_string(),
                    )
                })?;

            // The witness must match the clause's declared layout exactly.
            let mut offset = 0usize;
            for spec in clause.arg_specs() {
                offset += spec
                    .arg_type
                    .consume(&witness_args[offset..])
                    .map_err(|e| ManagerError::UnrecognizedSpend(e.to_string()))?;
            }
            if offset != witness_args.len() {
                return Err(ManagerError::UnrecognizedSpend(format!(
                    "clause '{}' expects {} witness argument elements, the spend has {}",
                    clause.name(),
                    offset,
                    witness_args.len()
                )));
            }

            let next = inst.contract().execute_clause_from_witness(
                clause.name(),
                &witness_args,
                inst.state(),
            )?;
            (clause.name().to_string(), next)
        };

        handle
            .instance
            .borrow_mut()
            .mark_spent(txid, vin, clause_name, witness_args);

        let children = match &next {
            NextOutputs::Contracts(outputs) => {
                self.materialize_outputs(&handle.instance, outputs, spending_tx, vin)?
            }
            NextOutputs::Template(_) => Vec::new(),
        };

        Ok(children
            .into_iter()
            .map(|instance| InstanceHandle { instance })
            .collect())
    }

    /// Wait until `handle`'s instance is spent on-chain (watching the mempool and
    /// new blocks), then decode the spend and materialize the child instances via
    /// [`observe_spend`](Self::observe_spend).
    ///
    /// This is how a party follows a covenant driven by someone else: the
    /// returned children carry their contracts and logical state, ready for
    /// further spends or waits. The clause and its witness arguments are recorded
    /// on the instance ([`InstanceHandle::clause_name`] /
    /// [`InstanceHandle::spending_args`]).
    pub fn wait_for_spend(
        &mut self,
        handle: &InstanceHandle,
    ) -> Result<Vec<InstanceHandle>, ManagerError> {
        if handle.status() == InstanceStatus::Spent {
            return Ok(handle.outputs());
        }
        let outpoint = handle.outpoint().ok_or(ManagerError::NotFunded)?;
        let spending_tx = self.wait_for_spending_tx(outpoint)?;
        self.observe_spend(handle, &spending_tx)
    }

    /// [`wait_for_spend`](Self::wait_for_spend) for several instances (possibly
    /// spent by one batch transaction). Children merged across inputs are
    /// materialized once and returned once.
    pub fn wait_for_spends(
        &mut self,
        handles: &[InstanceHandle],
    ) -> Result<Vec<InstanceHandle>, ManagerError> {
        let mut result: Vec<InstanceHandle> = Vec::new();
        for handle in handles {
            for child in self.wait_for_spend(handle)? {
                if !result
                    .iter()
                    .any(|h| Rc::ptr_eq(&h.instance, &child.instance))
                {
                    result.push(child);
                }
            }
        }
        Ok(result)
    }

    /// Poll until a transaction spending `outpoint` appears, in the mempool
    /// (`gettxspendingprevout`) or in a block (scanned from the funding
    /// transaction's height onward).
    fn wait_for_spending_tx(&self, outpoint: OutPoint) -> Result<Transaction, ManagerError> {
        // Scan blocks starting where the funding transaction confirmed (or the
        // next block, if it is still unconfirmed).
        let mut next_height = {
            let info = self.rpc.get_raw_transaction_info(&outpoint.txid, None)?;
            match info.blockhash {
                Some(hash) => self.rpc.get_block_header_info(&hash)?.height as u64,
                None => self.rpc.get_block_count()? + 1,
            }
        };

        for _ in 0..POLL_ATTEMPTS {
            // 1. The mempool.
            let query = serde_json::json!([{
                "txid": outpoint.txid.to_string(),
                "vout": outpoint.vout,
            }]);
            let res: serde_json::Value = self.rpc.call("gettxspendingprevout", &[query])?;
            if let Some(txid_str) = res
                .get(0)
                .and_then(|entry| entry.get("spendingtxid"))
                .and_then(|v| v.as_str())
            {
                let txid: Txid = txid_str
                    .parse()
                    .map_err(|e| ManagerError::Other(format!("bad spendingtxid: {}", e)))?;
                return Ok(self.rpc.get_raw_transaction(&txid, None)?);
            }

            // 2. Blocks mined since the last look.
            let tip = self.rpc.get_block_count()?;
            while next_height <= tip {
                let hash = self.rpc.get_block_hash(next_height)?;
                let block = self.rpc.get_block(&hash)?;
                if let Some(tx) = block
                    .txdata
                    .iter()
                    .find(|tx| tx.input.iter().any(|i| i.previous_output == outpoint))
                {
                    return Ok(tx.clone());
                }
                next_height += 1;
            }

            sleep(Duration::from_millis(100));
        }

        Err(ManagerError::SpendNotFound(outpoint))
    }
}

/// An RPC client for a local regtest node, for tests, examples and demos. The
/// `wallet_name` wallet must be already loaded and funded.
///
/// # Environment variables
///
/// - `BITCOIN_RPC_URL`: the node's URL (default `http://localhost:18443`).
/// - `BITCOIN_RPC_USER` / `BITCOIN_RPC_PASSWORD`: RPC credentials. When unset,
///   falls back to cookie authentication with `BITCOIN_RPC_COOKIE` (default
///   `~/.bitcoin/regtest/.cookie`) — a stock regtest `bitcoind` works with no
///   configuration at all.
pub fn regtest_rpc_client(wallet_name: &str) -> Client {
    let rpc_url =
        std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_url_full = format!("{}/wallet/{}", rpc_url, wallet_name);

    let auth = match (
        std::env::var("BITCOIN_RPC_USER"),
        std::env::var("BITCOIN_RPC_PASSWORD"),
    ) {
        (Ok(user), Ok(password)) => bitcoincore_rpc::Auth::UserPass(user, password),
        _ => {
            let cookie = std::env::var("BITCOIN_RPC_COOKIE")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    let home = std::env::var("HOME").expect("HOME not set");
                    std::path::PathBuf::from(home).join(".bitcoin/regtest/.cookie")
                });
            bitcoincore_rpc::Auth::CookieFile(cookie)
        }
    };

    Client::new(&rpc_url_full, auth).expect("Failed to create RPC client")
}

/// Split a taproot script-path witness into its clause arguments and the leaf
/// script, dropping the annex (if present) and the control block.
fn parse_script_path_witness(
    witness: &bitcoin::Witness,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), ManagerError> {
    let elements: Vec<Vec<u8>> = witness.iter().map(|e| e.to_vec()).collect();
    let mut n = elements.len();
    // BIP341: with at least two elements, a last element starting with 0x50 is
    // the annex.
    if n >= 2 && elements[n - 1].first() == Some(&0x50) {
        n -= 1;
    }
    if n < 2 {
        return Err(ManagerError::UnrecognizedSpend(
            "key-path spend (no tapscript in the witness)".to_string(),
        ));
    }
    let leaf_script = elements[n - 2].clone();
    let args = elements[..n - 2].to_vec();
    Ok((args, leaf_script))
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

    /// The UTXO this instance controls (its funding output), once funded.
    pub fn prevout(&self) -> Option<TxOut> {
        self.instance.borrow().prevout()
    }

    /// The `TypeId` of the underlying contract (for typed-handle conversions).
    pub fn contract_type_id(&self) -> std::any::TypeId {
        self.instance.borrow().contract().contract_type_id()
    }

    /// The name of the clause that spent this instance (None until spent).
    pub fn clause_name(&self) -> Option<String> {
        self.instance.borrow().clause_name().map(str::to_string)
    }

    /// Transaction ID that spent this instance (None until spent).
    pub fn spent_in_tx(&self) -> Option<Txid> {
        self.instance.borrow().spent_in_tx()
    }

    /// The witness arguments of the spend, in witness order (None until spent).
    /// Decode them with the clause's typed `*Args` struct
    /// ([`ClauseArgs::decode_from_witness`](crate::contracts::ClauseArgs::decode_from_witness)).
    pub fn spending_args(&self) -> Option<Vec<Vec<u8>>> {
        self.instance
            .borrow()
            .spending_args()
            .map(|args| args.to_vec())
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
