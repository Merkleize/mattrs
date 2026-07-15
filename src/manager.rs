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
        ContractState, ErasedClause, ErasedContract, ErasedState, InstanceStatus, NextOutputs,
    },
    signer::Signer,
};

/// The interval between chain polls.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The default polling window of [`ContractManager::wait_for_spend`] and
/// [`ContractManager::wait_for_transaction`]; see
/// [`ContractManager::wait_for_spend_within`] to override it.
const DEFAULT_POLL_WINDOW: Duration = Duration::from_secs(30);

/// Poll `check` every [`POLL_INTERVAL`] until it yields a value or `window`
/// elapses (`None` = poll forever). Returns `Ok(None)` on timeout.
fn poll_until<T>(
    window: Option<Duration>,
    mut check: impl FnMut() -> Result<Option<T>, ManagerError>,
) -> Result<Option<T>, ManagerError> {
    let deadline = window.map(|w| std::time::Instant::now() + w);
    loop {
        if let Some(value) = check()? {
            return Ok(Some(value));
        }
        if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            return Ok(None);
        }
        sleep(POLL_INTERVAL);
    }
}

#[derive(PartialEq, Eq)]
struct ContractOutputIdentity {
    contract_type: std::any::TypeId,
    params: Vec<u8>,
    state: Option<Vec<u8>>,
}

impl ContractOutputIdentity {
    fn from_clause_output(output: &ClauseOutput) -> Self {
        Self {
            contract_type: output.next_contract.contract_type_id(),
            params: output.next_contract.params_bytes().to_vec(),
            state: output.committed_state_bytes(),
        }
    }

    fn from_instance(instance: &ContractInstance) -> Self {
        Self {
            contract_type: instance.contract().contract_type_id(),
            params: instance.contract().params_bytes().to_vec(),
            state: instance.committed_state_bytes(),
        }
    }
}

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
    MissingDeductAmount {
        index: u32,
    },
    /// An `IgnoreOutput` needs an explicit amount; silently using zero would
    /// donate the input value to fees.
    MissingIgnoredAmount {
        index: u32,
    },
    /// The merged clause outputs skip a transaction output index.
    NonContiguousOutputs {
        missing_index: u32,
    },
    /// Deducted output amounts exceed the input amount.
    DeductExceedsInput,
    /// An observed spending transaction could not be decoded back into a clause
    /// (key-path spend, unknown tapscript, or a witness/spec mismatch).
    UnrecognizedSpend(String),
    /// No transaction spending this outpoint was found within the polling window.
    SpendNotFound(OutPoint),
    /// The transaction did not appear on the node within the polling window.
    TransactionNotFound(Txid),
    /// The outpoint given to [`ContractManager::track_instance`] does not pay
    /// the contract's expected script (wrong contract, params, or state).
    WrongFundingScript(OutPoint),
    /// The spend produces no transaction outputs: a terminal clause constrains
    /// none, so they must be supplied with [`SpendBuilder::outputs`].
    NoOutputs,
    /// Two spends of a batch set a different amount for the same output index.
    ConflictingOutputAmount {
        index: u32,
    },
    /// An output index receives both `PreserveOutput` and `DeductOutput`
    /// contributions (from the same or different inputs); the two amount
    /// semantics cannot hold for one output.
    MixedOutputSemantics {
        index: u32,
    },
    /// An amount was supplied via [`SpendBuilder::output_amount`] for an output
    /// index that no `DeductOutput` uses.
    UnusedOutputAmount {
        index: u32,
    },
    /// Contributions merged at one output index describe different nominal
    /// contracts, parameters, or committed states.
    ConflictingOutputContract {
        index: u32,
    },
    /// A clause describes a child at an output that the observed transaction
    /// does not contain.
    MissingContractOutput(OutPoint),
    /// A clause's derived child script does not match the corresponding output
    /// in the observed transaction.
    WrongContractOutput(OutPoint),
    TransactionBuildError(String),
    /// A clause requires a signature from this key, but no signer was registered
    /// and no signature was pre-filled.
    MissingSigner(XOnlyPublicKey),
    /// A spend produced a different number of child instances than the caller
    /// asserted via `exec_one` / `exec_none`.
    UnexpectedOutputCount {
        expected: usize,
        got: usize,
    },
    /// A child instance was not of the requested contract type
    /// ([`Children::typed`] / [`Children::one`]).
    WrongContract(WrongContractType),
    /// A `NextOutputs::Join` contribution targets an output index no other
    /// input's clause defines.
    JoinWithoutTarget {
        index: u32,
    },
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
            ManagerError::MissingIgnoredAmount { index } => write!(
                f,
                "IgnoreOutput at index {} needs an explicit amount \
                 (SpendBuilder::output_amount)",
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
                write!(
                    f,
                    "No transaction spending {} found while polling",
                    outpoint
                )
            }
            ManagerError::TransactionNotFound(txid) => {
                write!(f, "Transaction {} not found while polling", txid)
            }
            ManagerError::WrongFundingScript(outpoint) => write!(
                f,
                "Outpoint {} does not pay the contract's expected script \
                 (wrong contract, params, or state?)",
                outpoint
            ),
            ManagerError::NoOutputs => write!(
                f,
                "The spend produces no outputs; terminal clauses need explicit \
                 outputs (SpendBuilder::outputs)"
            ),
            ManagerError::ConflictingOutputAmount { index } => {
                write!(f, "Conflicting amounts were set for output index {}", index)
            }
            ManagerError::MixedOutputSemantics { index } => write!(
                f,
                "Output index {} mixes PreserveOutput and DeductOutput contributions",
                index
            ),
            ManagerError::UnusedOutputAmount { index } => write!(
                f,
                "An amount was set for output index {}, but no DeductOutput uses it",
                index
            ),
            ManagerError::ConflictingOutputContract { index } => write!(
                f,
                "Output index {} merges different contracts, parameters, or states",
                index
            ),
            ManagerError::MissingContractOutput(outpoint) => write!(
                f,
                "The observed transaction has no contract output at {}",
                outpoint
            ),
            ManagerError::WrongContractOutput(outpoint) => write!(
                f,
                "The observed output at {} does not pay the clause's child contract",
                outpoint
            ),
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
            ManagerError::WrongContract(e) => write!(f, "{}", e),
            ManagerError::JoinWithoutTarget { index } => write!(
                f,
                "a Join contribution targets output index {}, which no other input defines",
                index
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

impl From<WrongContractType> for ManagerError {
    fn from(e: WrongContractType) -> Self {
        ManagerError::WrongContract(e)
    }
}

/// Manages contract instances and their lifecycle.
pub struct ContractManager {
    /// RPC client for blockchain interaction.
    rpc: Client,

    /// The network the node runs on (used to derive contract addresses).
    network: bitcoin::Network,

    /// All instances managed by this manager.
    instances: Vec<Rc<RefCell<ContractInstance>>>,

    /// The snapshot shared with the inspector server, if enabled.
    #[cfg(feature = "inspector")]
    inspector_state: Option<std::sync::Arc<std::sync::Mutex<crate::inspector::ManagerSnapshot>>>,
    /// Wakes the inspector server's client threads after a snapshot update.
    #[cfg(feature = "inspector")]
    inspector_notify: Option<std::sync::Arc<std::sync::Condvar>>,
}

impl ContractManager {
    /// Create a new contract manager owning the RPC client (use
    /// [`rpc`](Self::rpc) for direct access to it) and talking to a node on
    /// `network` (used to derive contract addresses).
    pub fn new(rpc: Client, network: bitcoin::Network) -> Self {
        Self {
            rpc,
            network,
            instances: Vec::new(),
            #[cfg(feature = "inspector")]
            inspector_state: None,
            #[cfg(feature = "inspector")]
            inspector_notify: None,
        }
    }

    /// The RPC client, for callers that need direct access (e.g. mining or funding).
    pub fn rpc(&self) -> &Client {
        &self.rpc
    }

    /// Start the inspector server on `127.0.0.1:port` (see [`crate::inspector`]):
    /// it pushes a JSON snapshot of every managed instance to each connected
    /// client on every state change.
    ///
    /// # Errors
    ///
    /// Returns an error if the inspector cannot bind its loopback TCP listener.
    #[cfg(feature = "inspector")]
    pub fn enable_inspector(&mut self, port: u16) -> std::io::Result<()> {
        let state = std::sync::Arc::new(std::sync::Mutex::new(self.build_snapshot()));
        let notify = std::sync::Arc::new(std::sync::Condvar::new());
        crate::inspector::start_inspector_server(
            std::sync::Arc::clone(&state),
            std::sync::Arc::clone(&notify),
            port,
        )?;
        self.inspector_state = Some(state);
        self.inspector_notify = Some(notify);
        Ok(())
    }

    #[cfg(feature = "inspector")]
    fn build_snapshot(&self) -> crate::inspector::ManagerSnapshot {
        crate::inspector::snapshot_instances(&self.instances, self.network)
    }

    /// Refresh the shared snapshot and wake the inspector's client threads.
    /// Called after every instance-state mutation; a no-op unless enabled.
    #[cfg(feature = "inspector")]
    fn notify_inspector(&self) {
        if let (Some(state), Some(notify)) = (&self.inspector_state, &self.inspector_notify) {
            let snapshot = self.build_snapshot();
            *state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = snapshot;
            notify.notify_all();
        }
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
        let instance = Rc::new(RefCell::new(ContractInstance::new(contract, state)?));
        let script_pubkey = instance.borrow().script_pubkey()?;

        // Fund it using RPC
        let address = bitcoin::Address::from_script(&script_pubkey, self.network.params())
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

        instance.borrow_mut().mark_funded(outpoint, tx);
        Ok(self.register_instance(instance))
    }

    /// Register a freshly funded instance with the manager (and the inspector,
    /// if enabled), handing out its handle.
    fn register_instance(&mut self, instance: Rc<RefCell<ContractInstance>>) -> InstanceHandle {
        self.instances.push(instance.clone());

        #[cfg(feature = "inspector")]
        self.notify_inspector();

        InstanceHandle { instance }
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
    /// A single spend is a batch of one.
    fn execute_spend(&mut self, builder: SpendBuilder) -> Result<Children, ManagerError> {
        self.spend_batch(std::slice::from_ref(&builder))
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
    pub fn spend_batch(&mut self, builders: &[SpendBuilder]) -> Result<Children, ManagerError> {
        let (tx, nexts) = self.assemble(builders)?;

        self.rpc.send_raw_transaction(&tx)?;
        for (vin, builder) in builders.iter().enumerate() {
            builder.instance.borrow_mut().mark_spent(
                tx.clone(),
                vin,
                builder.clause_name.to_string(),
                builder.witness_args.clone(),
            );
        }

        // Materialize the children; outputs merged across inputs (a shared
        // `PreserveOutput` index) yield one child instance, linked to each parent.
        // Contract outputs first: a `Join` references a child another input defines.
        let mut handles: Vec<InstanceHandle> = Vec::new();
        for (vin, (builder, next)) in builders.iter().zip(&nexts).enumerate() {
            if let NextOutputs::Contracts(outputs) = next {
                for child in self.materialize_outputs(&builder.instance, outputs, &tx, vin)? {
                    let handle = InstanceHandle { instance: child };
                    if !handles.contains(&handle) {
                        handles.push(handle);
                    }
                }
            }
        }
        let txid = tx.compute_txid();
        for (builder, next) in builders.iter().zip(&nexts) {
            if let NextOutputs::Join { index } = next {
                let outpoint = OutPoint { txid, vout: *index };
                let child = self
                    .find_instance_by_outpoint(outpoint)
                    .ok_or(ManagerError::JoinWithoutTarget { index: *index })?;
                builder.instance.borrow_mut().add_output(child.clone());
                let handle = InstanceHandle { instance: child };
                if !handles.contains(&handle) {
                    handles.push(handle);
                }
            }
        }

        #[cfg(feature = "inspector")]
        self.notify_inspector();

        Ok(Children::new(handles))
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
            if tx_inputs
                .iter()
                .any(|input: &TxIn| input.previous_output == outpoint)
            {
                return Err(ManagerError::TransactionBuildError(format!(
                    "duplicate input: {} is spent twice in the batch",
                    outpoint
                )));
            }
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
            if let NextOutputs::Contracts(outputs) = &next {
                for output in outputs {
                    // Validate state presence and concrete type before a
                    // transaction can be broadcast.
                    ContractInstance::new(output.next_contract.clone(), output.next_state.clone())?;
                }
            }
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
    /// Caller-supplied explicit outputs and CTV templates fix the outputs (each
    /// single-input only, and mutually exclusive); otherwise the covenant outputs
    /// are merged by index across all inputs, mirroring the CCV deferred amount
    /// checks: each `PreserveOutput` moves its input's whole remaining amount
    /// (net of that input's earlier `DeductOutput`s) into its output, and a
    /// `DeductOutput` sets its output to the caller-supplied amount. An output
    /// index must not mix the two semantics. Note that an `IgnoreOutput` index
    /// no other input funds ends up as a zero-value output.
    fn derive_tx_outputs(
        builders: &[SpendBuilder],
        nexts: &[NextOutputs],
        prevouts: &[TxOut],
    ) -> Result<(Vec<TxOut>, Option<Sequence>), ManagerError> {
        let single = builders.len() == 1;

        let template = nexts.iter().find_map(|next| match next {
            NextOutputs::Template(template) => Some(template),
            NextOutputs::Contracts(_) | NextOutputs::Join { .. } => None,
        });

        if let Some(explicit) = builders.iter().find_map(|b| b.explicit_outputs.as_ref()) {
            if !single {
                return Err(ManagerError::TransactionBuildError(
                    "explicit outputs are single-input only; not supported in a batch".to_string(),
                ));
            }
            if template.is_some() {
                return Err(ManagerError::TransactionBuildError(
                    "a CTV template clause fixes the whole transaction; explicit outputs \
                     cannot override it"
                        .to_string(),
                ));
            }
            if !matches!(nexts.first(), Some(NextOutputs::Contracts(outputs)) if outputs.is_empty())
            {
                return Err(ManagerError::TransactionBuildError(
                    "explicit outputs are only valid for a terminal unconstrained clause"
                        .to_string(),
                ));
            }
            return Ok((explicit.clone(), None));
        }

        if let Some(template) = template {
            if !single {
                return Err(ManagerError::TransactionBuildError(
                    "CTV template clauses are single-input only; not supported in a batch"
                        .to_string(),
                ));
            }
            match builders[0].sequence {
                Some(sequence) if sequence != template.sequence => {
                    return Err(ManagerError::TransactionBuildError(format!(
                        "the CTV template commits to nSequence {}, conflicting with the \
                         caller's {}",
                        template.sequence, sequence
                    )));
                }
                _ => {}
            }
            return Ok((template.outputs.clone(), Some(template.sequence)));
        }

        // Pool the per-builder DeductOutput amounts; setting the same index to
        // two different amounts is a caller bug, not a merge.
        let mut output_amounts: BTreeMap<u32, Amount> = BTreeMap::new();
        for builder in builders {
            for (idx, amount) in &builder.output_amounts {
                match output_amounts.insert(*idx, *amount) {
                    Some(previous) if previous != *amount => {
                        return Err(ManagerError::ConflictingOutputAmount { index: *idx });
                    }
                    _ => {}
                }
            }
        }

        // Merge clause outputs by index across all inputs. Each index must
        // stick to one amount semantics: preserves accumulate, a deduct sets
        // the caller-supplied amount — mixing them cannot satisfy both.
        #[derive(PartialEq, Clone, Copy)]
        enum Semantics {
            Preserve,
            Deduct,
            Ignore,
        }
        let mut semantics: BTreeMap<u32, Semantics> = BTreeMap::new();
        let mut identities: BTreeMap<u32, ContractOutputIdentity> = BTreeMap::new();
        let mut outputs_map: BTreeMap<u32, TxOut> = BTreeMap::new();
        for (input_index, next) in nexts.iter().enumerate() {
            let clause_outputs = match next {
                NextOutputs::Contracts(clause_outputs) => clause_outputs,
                // Joins contribute to outputs other inputs define; second pass.
                NextOutputs::Join { .. } => continue,
                NextOutputs::Template(_) => unreachable!("templates are handled above"),
            };

            let mut remaining = prevouts[input_index].value;
            let mut preserve_used = false;
            for clause_output in clause_outputs {
                let idx = clause_output.index.resolve(input_index);
                let identity = ContractOutputIdentity::from_clause_output(clause_output);
                if identities
                    .get(&idx)
                    .is_some_and(|previous| previous != &identity)
                {
                    return Err(ManagerError::ConflictingOutputContract { index: idx });
                }
                identities.entry(idx).or_insert(identity);
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
                        if preserve_used {
                            return Err(ManagerError::TransactionBuildError(
                                "multiple PreserveOutput outputs in one input (its remaining \
                                 amount can only be preserved once)"
                                    .to_string(),
                            ));
                        }
                        if semantics
                            .get(&idx)
                            .is_some_and(|kind| *kind != Semantics::Preserve)
                        {
                            return Err(ManagerError::MixedOutputSemantics { index: idx });
                        }
                        semantics.insert(idx, Semantics::Preserve);
                        entry.value += remaining;
                        preserve_used = true;
                    }
                    ClauseOutputAmountBehaviour::DeductOutput => {
                        if preserve_used {
                            return Err(ManagerError::TransactionBuildError(
                                "DeductOutput must be declared before PreserveOutput".to_string(),
                            ));
                        }
                        if semantics.contains_key(&idx) {
                            return Err(ManagerError::MixedOutputSemantics { index: idx });
                        }
                        semantics.insert(idx, Semantics::Deduct);
                        let amount = *output_amounts
                            .get(&idx)
                            .ok_or(ManagerError::MissingDeductAmount { index: idx })?;
                        entry.value = amount;
                        remaining = remaining
                            .checked_sub(amount)
                            .ok_or(ManagerError::DeductExceedsInput)?;
                    }
                    ClauseOutputAmountBehaviour::IgnoreOutput => {
                        if semantics.insert(idx, Semantics::Ignore).is_some() {
                            return Err(ManagerError::MixedOutputSemantics { index: idx });
                        }
                        entry.value = *output_amounts
                            .get(&idx)
                            .ok_or(ManagerError::MissingIgnoredAmount { index: idx })?;
                    }
                }
            }
        }

        // Second pass: each Join adds its input's whole amount to an output some
        // other input defined. A join is preserve-like — it cannot fund a
        // caller-amounted (deduct) output.
        for (input_index, next) in nexts.iter().enumerate() {
            let NextOutputs::Join { index } = next else {
                continue;
            };
            let entry = outputs_map
                .get_mut(index)
                .ok_or(ManagerError::JoinWithoutTarget { index: *index })?;
            if matches!(
                semantics.get(index),
                Some(Semantics::Deduct | Semantics::Ignore)
            ) {
                return Err(ManagerError::MixedOutputSemantics { index: *index });
            }
            entry.value += prevouts[input_index].value;
        }

        // Every caller-supplied amount must have been used by a DeductOutput;
        // a stray index would silently change the transaction.
        if let Some(idx) = output_amounts.keys().find(|idx| {
            !matches!(
                semantics.get(idx),
                Some(Semantics::Deduct | Semantics::Ignore)
            )
        }) {
            return Err(ManagerError::UnusedOutputAmount { index: *idx });
        }

        // A transaction with no outputs is never valid: the clause is terminal
        // and the caller forgot to supply outputs explicitly.
        if outputs_map.is_empty() {
            return Err(ManagerError::NoOutputs);
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

    fn wait_for_transaction(&self, txid: Txid) -> Result<Transaction, ManagerError> {
        poll_until(Some(DEFAULT_POLL_WINDOW), || {
            match self.rpc.get_raw_transaction(&txid, None) {
                Ok(tx) => Ok(Some(tx)),
                Err(e) if is_tx_not_found(&e) => Ok(None), // not (yet) known to the node
                Err(e) => Err(e.into()),
            }
        })?
        .ok_or(ManagerError::TransactionNotFound(txid))
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

        // Validate the complete declared layout even for unsigned/raw clauses.
        validate_clause_witness(clause.as_ref(), &witness_stack, true)
            .map_err(|e| ManagerError::TransactionBuildError(e.to_string()))?;

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
                        witness_stack[offset] = signer
                            .sign(&sighash)
                            .map_err(|e| ManagerError::TransactionBuildError(e.to_string()))?
                            .as_bytes()
                            .to_vec();
                    } else if witness_stack[offset].is_empty() {
                        return Err(ManagerError::MissingSigner(xonly));
                    }
                }

                offset += consumed;
            }
        }

        validate_clause_witness(clause.as_ref(), &witness_stack, false)
            .map_err(|e| ManagerError::TransactionBuildError(e.to_string()))?;

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
    fn find_instance_by_outpoint(
        &self,
        outpoint: OutPoint,
    ) -> Option<Rc<RefCell<ContractInstance>>> {
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
        let mut resolved = Vec::with_capacity(outputs.len());
        let mut identities = BTreeMap::new();

        for clause_out in outputs {
            let vout = clause_out.index.resolve(vin);
            let outpoint = OutPoint { txid, vout };
            let identity = ContractOutputIdentity::from_clause_output(clause_out);
            if identities
                .get(&vout)
                .is_some_and(|previous| previous != &identity)
            {
                return Err(ManagerError::ConflictingOutputContract { index: vout });
            }
            identities.entry(vout).or_insert(identity);
            let actual = spending_tx
                .output
                .get(vout as usize)
                .ok_or(ManagerError::MissingContractOutput(outpoint))?;
            let expected_script = clause_out
                .next_contract
                .script_pubkey(clause_out.committed_state_bytes().as_deref())?;
            if actual.script_pubkey != expected_script {
                return Err(ManagerError::WrongContractOutput(outpoint));
            }

            if let Some(existing) = self.find_instance_by_outpoint(outpoint) {
                let existing = existing.borrow();
                if ContractOutputIdentity::from_instance(&existing)
                    != ContractOutputIdentity::from_clause_output(clause_out)
                {
                    return Err(ManagerError::ConflictingOutputContract { index: vout });
                }
            }
            resolved.push((clause_out, outpoint));
        }

        let mut children = Vec::with_capacity(resolved.len());
        for (clause_out, outpoint) in resolved {
            let child = match self.find_instance_by_outpoint(outpoint) {
                Some(existing) => existing,
                None => {
                    // The child contract is self-describing, so its params come
                    // from it; it also carries the logical state for its own
                    // future spends.
                    let instance = Rc::new(RefCell::new(ContractInstance::new(
                        clause_out.next_contract.clone(),
                        clause_out.next_state.clone(),
                    )?));
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
        let instance = Rc::new(RefCell::new(ContractInstance::new(contract, state)?));

        let expected_spk = instance.borrow().script_pubkey()?;
        let funding_tx = self.rpc.get_raw_transaction(&outpoint.txid, None)?;
        let paid = funding_tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(ManagerError::OutputNotFound)?;
        if paid.script_pubkey != expected_spk {
            return Err(ManagerError::WrongFundingScript(outpoint));
        }

        instance.borrow_mut().mark_funded(outpoint, funding_tx);
        Ok(self.register_instance(instance))
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
    ///
    /// A `NextOutputs::Join` input's child is defined by *another* input of the
    /// same transaction: observing the joining input before the defining one
    /// yields no children yet — re-observe it after the defining input to link
    /// and return the shared child ([`crate::testutil::apply_batch`] does this).
    pub fn observe_spend(
        &mut self,
        handle: &InstanceHandle,
        spending_tx: &Transaction,
    ) -> Result<Children, ManagerError> {
        let txid = spending_tx.compute_txid();

        let already_spent = {
            let inst = handle.instance.borrow();
            if inst.status() == InstanceStatus::Spent {
                if inst.spent_in_tx() != Some(txid) {
                    return Err(ManagerError::InvalidInstance(
                        "Instance already spent by a different transaction".to_string(),
                    ));
                }
                // Re-observation: return the cached children — unless there are
                // none, which for a joining input observed before its defining
                // input means the link may still be missing; fall through and
                // retry it (a no-op for genuinely childless clauses).
                let outputs = handle.outputs();
                if !outputs.is_empty() {
                    return Ok(outputs);
                }
                true
            } else if inst.status() != InstanceStatus::Funded {
                return Err(ManagerError::NotFunded);
            } else {
                false
            }
        };
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
        let ParsedScriptPathWitness {
            args: witness_args,
            leaf_script,
            control_block,
        } = parse_script_path_witness(&spending_tx.input[vin].witness)?;
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

            let internal_key = inst
                .contract()
                .control_block_internal_key(inst.committed_state_bytes().as_deref())?;
            let expected_control = inst
                .contract()
                .taptree()
                .control_block(&internal_key, clause.name())
                .ok_or_else(|| {
                    ManagerError::UnrecognizedSpend(
                        "failed to derive the clause's control block".to_string(),
                    )
                })?;
            if control_block != expected_control {
                return Err(ManagerError::UnrecognizedSpend(
                    "witness control block does not authenticate this contract leaf".to_string(),
                ));
            }

            // The witness must match the clause's declared layout exactly.
            validate_clause_witness(clause.as_ref(), &witness_args, false)
                .map_err(|e| ManagerError::UnrecognizedSpend(e.to_string()))?;

            let next = inst.contract().execute_clause_from_witness(
                clause.name(),
                &witness_args,
                inst.state(),
            )?;
            (clause.name().to_string(), next)
        };

        if let NextOutputs::Contracts(outputs) = &next {
            validate_observed_contract_amounts(handle, outputs, spending_tx, vin)?;
        }

        let children = match &next {
            // A re-observed instance with no cached children got here only to
            // retry a join link; its (childless) non-join clause has nothing
            // to re-materialize.
            NextOutputs::Contracts(_) if already_spent => Vec::new(),
            NextOutputs::Contracts(outputs) => {
                self.materialize_outputs(&handle.instance, outputs, spending_tx, vin)?
            }
            NextOutputs::Template(template) => {
                if spending_tx.version != bitcoin::transaction::Version::TWO
                    || spending_tx.lock_time != bitcoin::absolute::LockTime::ZERO
                    || spending_tx.input.len() != 1
                    || vin != 0
                    || spending_tx.input[0].sequence != template.sequence
                    || spending_tx.output != template.outputs
                {
                    return Err(ManagerError::UnrecognizedSpend(
                        "transaction does not match the clause's CTV template".to_string(),
                    ));
                }
                Vec::new()
            }
            // A joining input contributes to a child another input's clause
            // defines: link it when that input's observation already
            // materialized the child; otherwise return nothing (a later
            // re-observation — after the defining input's — repairs the link).
            NextOutputs::Join { index } => {
                let outpoint = OutPoint { txid, vout: *index };
                match self.find_instance_by_outpoint(outpoint) {
                    Some(child) => {
                        handle.instance.borrow_mut().add_output(child.clone());
                        vec![child]
                    }
                    None => Vec::new(),
                }
            }
        };

        if !already_spent {
            handle.instance.borrow_mut().mark_spent(
                spending_tx.clone(),
                vin,
                clause_name,
                witness_args,
            );
        }

        #[cfg(feature = "inspector")]
        self.notify_inspector();

        Ok(Children::new(
            children
                .into_iter()
                .map(|instance| InstanceHandle { instance })
                .collect(),
        ))
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
    pub fn wait_for_spend(&mut self, handle: &InstanceHandle) -> Result<Children, ManagerError> {
        self.wait_for_spend_within(handle, Some(DEFAULT_POLL_WINDOW))
    }

    /// [`wait_for_spend`](Self::wait_for_spend) with an explicit polling window:
    /// give up with [`ManagerError::SpendNotFound`] after `window`, or poll
    /// forever when `window` is `None` (e.g. waiting on a human counterparty).
    pub fn wait_for_spend_within(
        &mut self,
        handle: &InstanceHandle,
        window: Option<Duration>,
    ) -> Result<Children, ManagerError> {
        if handle.status() == InstanceStatus::Spent {
            return Ok(handle.outputs());
        }
        let outpoint = handle.outpoint().ok_or(ManagerError::NotFunded)?;
        let spending_tx = self.wait_for_spending_tx(outpoint, window)?;
        self.observe_spend(handle, &spending_tx)
    }

    /// [`wait_for_spend`](Self::wait_for_spend) for several instances (possibly
    /// spent by one batch transaction). Children merged across inputs are
    /// materialized once and returned once.
    pub fn wait_for_spends(
        &mut self,
        handles: &[InstanceHandle],
    ) -> Result<Children, ManagerError> {
        let mut result: Vec<InstanceHandle> = Vec::new();
        // First discover/observe every spend, then revisit every handle so a
        // Join seen before its defining input can link to the shared child.
        for _ in 0..2 {
            for handle in handles {
                let children = if handle.status() == InstanceStatus::Spent {
                    let tx = handle.spending_tx().ok_or_else(|| {
                        ManagerError::InvalidInstance(
                            "spent instance has no spending transaction".to_string(),
                        )
                    })?;
                    self.observe_spend(handle, &tx)?
                } else {
                    self.wait_for_spend(handle)?
                };
                for child in children {
                    if !result.contains(&child) {
                        result.push(child);
                    }
                }
            }
        }
        Ok(Children::new(result))
    }

    /// Poll (within `window`; `None` = forever) until a transaction spending
    /// `outpoint` appears, in the mempool (`gettxspendingprevout`) or in a
    /// block (scanned from the funding transaction's height onward).
    fn wait_for_spending_tx(
        &self,
        outpoint: OutPoint,
        window: Option<Duration>,
    ) -> Result<Transaction, ManagerError> {
        let mut next_height = spend_scan_start(&self.rpc, outpoint)?;
        let mut blocks = BlockCache::default();
        poll_until(window, || {
            let found = find_spending_tx_once(&self.rpc, outpoint, &mut next_height, &mut blocks);
            // A single cursor never re-reads a scanned block.
            blocks.retain_from(next_height);
            found
        })?
        .ok_or(ManagerError::SpendNotFound(outpoint))
    }
}

/// The height `txid` confirmed at (`None` while it sits in the mempool).
/// Requires the node to know the transaction (wallet, mempool, or `txindex`);
/// an unknown `txid` is an error ([`is_tx_not_found`] tells it apart).
pub(crate) fn tx_confirmation_height(
    rpc: &Client,
    txid: &Txid,
) -> Result<Option<u64>, ManagerError> {
    let info = rpc.get_raw_transaction_info(txid, None)?;
    Ok(match info.blockhash {
        Some(hash) => Some(rpc.get_block_header_info(&hash)?.height as u64),
        None => None,
    })
}

/// The block height where a scan for spends of `outpoint` should start: where
/// the funding transaction confirmed (or the next block, if it is still
/// unconfirmed).
pub(crate) fn spend_scan_start(rpc: &Client, outpoint: OutPoint) -> Result<u64, ManagerError> {
    Ok(match tx_confirmation_height(rpc, &outpoint.txid)? {
        Some(height) => height,
        None => rpc.get_block_count()? + 1,
    })
}

/// A cache of fetched blocks, shared between the spend scans of several
/// outpoints so each new block is downloaded once even when many cursors walk
/// the same range. Evict with [`retain_from`](BlockCache::retain_from) once
/// every cursor has passed a height.
#[derive(Default)]
pub(crate) struct BlockCache(HashMap<u64, bitcoin::Block>);

impl BlockCache {
    fn get(&mut self, rpc: &Client, height: u64) -> Result<&bitcoin::Block, ManagerError> {
        match self.0.entry(height) {
            std::collections::hash_map::Entry::Occupied(e) => Ok(e.into_mut()),
            std::collections::hash_map::Entry::Vacant(e) => {
                let hash = rpc.get_block_hash(height)?;
                Ok(e.insert(rpc.get_block(&hash)?))
            }
        }
    }

    /// Drop every cached block below `height`.
    pub(crate) fn retain_from(&mut self, height: u64) {
        self.0.retain(|h, _| *h >= height);
    }
}

/// A single, non-blocking look for a transaction spending `outpoint`: the
/// mempool first (`gettxspendingprevout`), then the blocks from `*next_height`
/// to the tip (the cursor advances past the blocks already scanned; seed it
/// with [`spend_scan_start`], and share one `blocks` cache between the scans
/// of concurrent outpoints).
pub(crate) fn find_spending_tx_once(
    rpc: &Client,
    outpoint: OutPoint,
    next_height: &mut u64,
    blocks: &mut BlockCache,
) -> Result<Option<Transaction>, ManagerError> {
    // 1. The mempool.
    let query = serde_json::json!([{
        "txid": outpoint.txid.to_string(),
        "vout": outpoint.vout,
    }]);
    let res: serde_json::Value = rpc.call("gettxspendingprevout", &[query])?;
    if let Some(txid_str) = res
        .get(0)
        .and_then(|entry| entry.get("spendingtxid"))
        .and_then(|v| v.as_str())
    {
        let txid: Txid = txid_str
            .parse()
            .map_err(|e| ManagerError::Other(format!("bad spendingtxid: {}", e)))?;
        return Ok(Some(rpc.get_raw_transaction(&txid, None)?));
    }

    // 2. Blocks mined since the last look.
    let tip = rpc.get_block_count()?;
    while *next_height <= tip {
        let block = blocks.get(rpc, *next_height)?;
        if let Some(tx) = block
            .txdata
            .iter()
            .find(|tx| tx.input.iter().any(|i| i.previous_output == outpoint))
        {
            return Ok(Some(tx.clone()));
        }
        *next_height += 1;
    }

    Ok(None)
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

/// Whether an RPC error is Core's "No such mempool or blockchain transaction"
/// (code -5), i.e. the transaction is not (yet) known to the node — as opposed
/// to a real failure (node unreachable, bad credentials, ...).
pub(crate) fn is_tx_not_found(e: &bitcoincore_rpc::Error) -> bool {
    matches!(
        e,
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(rpc_err))
            if rpc_err.code == -5
    )
}

/// Validate a clause's witness against every declared argument specification,
/// including exact consumption. Empty signature slots are accepted only while
/// constructing a witness before registered signers have filled them.
fn validate_clause_witness(
    clause: &dyn ErasedClause,
    witness: &[Vec<u8>],
    allow_empty_signatures: bool,
) -> Result<(), crate::contracts::WitnessError> {
    let mut offset = 0usize;
    for spec in clause.arg_specs() {
        let tail = witness
            .get(offset..)
            .ok_or(crate::contracts::WitnessError::StackUnderflow)?;
        let consumed = spec.arg_type.consume(tail)?;
        if consumed == 0 {
            return Err(crate::contracts::WitnessError::InvalidData(format!(
                "argument '{}' consumes no witness elements",
                spec.name
            )));
        }
        if spec.arg_type.signer_pubkey().is_some() {
            let signature = witness
                .get(offset)
                .ok_or(crate::contracts::WitnessError::StackUnderflow)?;
            if signature.is_empty() {
                if !allow_empty_signatures {
                    return Err(crate::contracts::WitnessError::InvalidValue(format!(
                        "signature argument '{}' is empty",
                        spec.name
                    )));
                }
            } else if !matches!(signature.len(), 64 | 65) {
                return Err(crate::contracts::WitnessError::InvalidValue(format!(
                    "signature argument '{}' is {} bytes; expected 64 or 65",
                    spec.name,
                    signature.len()
                )));
            }
        }
        offset = offset.checked_add(consumed).ok_or_else(|| {
            crate::contracts::WitnessError::InvalidData(
                "witness element count overflow".to_string(),
            )
        })?;
    }
    if offset != witness.len() {
        return Err(crate::contracts::WitnessError::InvalidData(format!(
            "clause '{}' consumes {} witness elements, but {} were supplied",
            clause.name(),
            offset,
            witness.len()
        )));
    }
    Ok(())
}

/// Mirror the per-input CCV amount rules when following an offline/remote
/// transaction. Cross-input preserve contributions may make the actual output
/// larger, so preserve checks a lower bound; deduct uses the actual output
/// amount exactly as consensus does.
fn validate_observed_contract_amounts(
    handle: &InstanceHandle,
    outputs: &[ClauseOutput],
    spending_tx: &Transaction,
    vin: usize,
) -> Result<(), ManagerError> {
    let mut remaining = handle.prevout().ok_or(ManagerError::NotFunded)?.value;
    let mut preserve_used = false;
    let mut seen: BTreeMap<u32, ClauseOutputAmountBehaviour> = BTreeMap::new();
    for output in outputs {
        let index = output.index.resolve(vin);
        let actual =
            spending_tx
                .output
                .get(index as usize)
                .ok_or(ManagerError::MissingContractOutput(OutPoint {
                    txid: spending_tx.compute_txid(),
                    vout: index,
                }))?;
        match output.next_amount {
            ClauseOutputAmountBehaviour::PreserveOutput => {
                if preserve_used
                    || seen
                        .get(&index)
                        .is_some_and(|kind| *kind != ClauseOutputAmountBehaviour::PreserveOutput)
                {
                    return Err(ManagerError::MixedOutputSemantics { index });
                }
                if actual.value < remaining {
                    return Err(ManagerError::UnrecognizedSpend(format!(
                        "preserve output {index} has {}, below the input residual {remaining}",
                        actual.value
                    )));
                }
                seen.insert(index, ClauseOutputAmountBehaviour::PreserveOutput);
                remaining = Amount::ZERO;
                preserve_used = true;
            }
            ClauseOutputAmountBehaviour::DeductOutput => {
                if preserve_used || seen.contains_key(&index) {
                    return Err(ManagerError::MixedOutputSemantics { index });
                }
                remaining = remaining
                    .checked_sub(actual.value)
                    .ok_or(ManagerError::DeductExceedsInput)?;
                seen.insert(index, ClauseOutputAmountBehaviour::DeductOutput);
            }
            ClauseOutputAmountBehaviour::IgnoreOutput => {
                // This mode intentionally imposes no amount relationship. Its
                // presence still participates in duplicate/mixed-mode checks.
                if seen
                    .insert(index, ClauseOutputAmountBehaviour::IgnoreOutput)
                    .is_some()
                {
                    return Err(ManagerError::MixedOutputSemantics { index });
                }
            }
        }
    }
    Ok(())
}

/// Split a taproot script-path witness into its clause arguments and the leaf
/// script and control block, dropping the annex if present.
#[derive(Debug, PartialEq, Eq)]
struct ParsedScriptPathWitness {
    args: Vec<Vec<u8>>,
    leaf_script: Vec<u8>,
    control_block: Vec<u8>,
}

fn parse_script_path_witness(
    witness: &bitcoin::Witness,
) -> Result<ParsedScriptPathWitness, ManagerError> {
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
    let control_block = elements[n - 1].clone();
    let args = elements[..n - 2].to_vec();
    Ok(ParsedScriptPathWitness {
        args,
        leaf_script,
        control_block,
    })
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
        write!(f, "instance is not a `{}` contract", self.expected)
    }
}

impl std::error::Error for WrongContractType {}

/// A spend's state-bound witness fields could not be derived because the
/// instance carries no (or a differently-typed) logical state.
///
/// Returned by typed-handle methods that fill part of their clause's witness
/// from the instance's expanded state (e.g. the `contract!` DSL's
/// `#[from_state]` args) — which the framework materializes on every executed
/// or observed transition — so this only occurs on instances that were
/// constructed by hand without their state.
#[derive(Debug, Clone)]
pub struct MissingStateError {
    /// The contract whose state was needed.
    pub contract: &'static str,
}

impl std::fmt::Display for MissingStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the {} instance carries no logical state to derive the spend from",
            self.contract
        )
    }
}

impl std::error::Error for MissingStateError {}

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

impl std::fmt::Debug for InstanceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.instance.borrow().fmt(f)
    }
}

/// Handles compare by *instance identity* — two handles are equal when they
/// point to the same tracked instance, regardless of its contents.
impl PartialEq for InstanceHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.instance, &other.instance)
    }
}

impl Eq for InstanceHandle {}

impl InstanceHandle {
    /// Wrap a raw instance pointer.
    pub(crate) fn new(instance: Rc<RefCell<ContractInstance>>) -> Self {
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

    /// The underlying contract's human-readable name (e.g. `"Vault"`), for
    /// introspection and display.
    pub fn contract_name(&self) -> &'static str {
        self.instance.borrow().contract().contract_name()
    }

    /// The contract's encoded parameters (contracts are self-describing).
    /// Decode them with the contract's typed params struct
    /// ([`ContractParams::decode`](crate::contracts::ContractParams::decode));
    /// the `contract!`-generated handles expose this as a typed `params()`.
    pub fn params_bytes(&self) -> Vec<u8> {
        self.instance.borrow().contract().params_bytes().to_vec()
    }

    /// The instance's typed params `P`: read back by downcast when the contract
    /// carries them (every contract built from a typed `P` does — see
    /// [`ErasedContract::params_any`]),
    /// else decoded from the encoded bytes. `None` only if `P` is the wrong
    /// type *and* the bytes don't decode as a `P`.
    pub fn params<P: crate::contracts::ContractParams + 'static>(&self) -> Option<P> {
        let inst = self.instance.borrow();
        if let Some(typed) = inst
            .contract()
            .params_any()
            .and_then(|any| any.downcast_ref::<P>())
        {
            return Some(typed.clone());
        }
        P::decode(inst.contract().params_bytes()).ok()
    }

    /// The name of the clause that spent this instance (None until spent).
    pub fn clause_name(&self) -> Option<String> {
        self.instance.borrow().clause_name().map(str::to_string)
    }

    /// The transaction that funded this instance (None until funded).
    pub fn funding_tx(&self) -> Option<Transaction> {
        self.instance.borrow().funding_tx().cloned()
    }

    /// The transaction that spent this instance (None until spent).
    pub fn spending_tx(&self) -> Option<Transaction> {
        self.instance.borrow().spending_tx().cloned()
    }

    /// Transaction ID that spent this instance (None until spent).
    pub fn spent_in_tx(&self) -> Option<Txid> {
        self.instance.borrow().spent_in_tx()
    }

    /// The input index of the spending transaction that consumed this instance
    /// (None until spent).
    pub fn spending_vin(&self) -> Option<usize> {
        self.instance.borrow().spending_vin()
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
    pub fn outputs(&self) -> Children {
        Children::new(
            self.instance
                .borrow()
                .outputs()
                .iter()
                .cloned()
                .map(|instance| InstanceHandle { instance })
                .collect(),
        )
    }

    /// Begin a spend of `clause_name` with the given (already-encoded) witness
    /// arguments. The `contract!`-generated per-clause methods call this; most code
    /// should prefer those typed methods.
    ///
    /// If the clause declares a CSV timelock (the `contract!` DSL's `timelock`
    /// section), the builder's `nSequence` is seeded from it, so the script's
    /// `OP_CHECKSEQUENCEVERIFY` and the transaction cannot disagree; an
    /// explicit [`SpendBuilder::sequence`] still overrides.
    pub fn spend_clause(
        &self,
        clause_name: &'static str,
        witness_args: Vec<Vec<u8>>,
    ) -> SpendBuilder {
        let sequence = self
            .instance
            .borrow()
            .contract()
            .get_clause(clause_name)
            .and_then(|clause| clause.csv_blocks())
            .map(Sequence);
        SpendBuilder {
            instance: self.instance.clone(),
            clause_name,
            witness_args,
            signers: HashMap::new(),
            explicit_outputs: None,
            output_amounts: BTreeMap::new(),
            sequence,
        }
    }
}

/// The child instances a spend produced (or an observation materialized), in
/// merged-output order. Derefs to a slice of [`InstanceHandle`]s for
/// positional access; [`typed`](Children::typed) / [`one`](Children::one)
/// convert children into their `contract!`-generated typed handles.
#[derive(Debug, Clone)]
pub struct Children(Vec<InstanceHandle>);

impl Children {
    pub(crate) fn new(handles: Vec<InstanceHandle>) -> Self {
        Children(handles)
    }

    /// The child at `index`, as the typed handle `H`.
    pub fn typed<H>(&self, index: usize) -> Result<H, ManagerError>
    where
        H: TryFrom<InstanceHandle, Error = WrongContractType>,
    {
        let handle = self
            .0
            .get(index)
            .cloned()
            .ok_or(ManagerError::UnexpectedOutputCount {
                expected: index + 1,
                got: self.0.len(),
            })?;
        Ok(H::try_from(handle)?)
    }

    /// The single child, typed; errors unless exactly one child was produced.
    pub fn one<H>(self) -> Result<H, ManagerError>
    where
        H: TryFrom<InstanceHandle, Error = WrongContractType>,
    {
        if self.0.len() != 1 {
            return Err(ManagerError::UnexpectedOutputCount {
                expected: 1,
                got: self.0.len(),
            });
        }
        self.typed(0)
    }

    /// The untyped handles.
    pub fn into_vec(self) -> Vec<InstanceHandle> {
        self.0
    }
}

impl std::ops::Deref for Children {
    type Target = [InstanceHandle];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for Children {
    type Item = InstanceHandle;
    type IntoIter = std::vec::IntoIter<InstanceHandle>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Children {
    type Item = &'a InstanceHandle;
    type IntoIter = std::slice::Iter<'a, InstanceHandle>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
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
    signers: HashMap<XOnlyPublicKey, Box<dyn Signer>>,
    explicit_outputs: Option<Vec<TxOut>>,
    output_amounts: BTreeMap<u32, Amount>,
    sequence: Option<Sequence>,
}

impl SpendBuilder {
    /// Whether this builder spends `handle`'s exact tracked instance.
    pub(crate) fn spends(&self, handle: &InstanceHandle) -> bool {
        Rc::ptr_eq(&self.instance, &handle.instance)
    }

    fn expected_children(&self, manager: &ContractManager) -> Result<usize, ManagerError> {
        let (_, next) = manager.build_spend_tx(self)?;
        Ok(match next {
            NextOutputs::Contracts(outputs) => {
                let mut indices = std::collections::BTreeSet::new();
                for output in outputs {
                    indices.insert(output.index.resolve(0));
                }
                indices.len()
            }
            NextOutputs::Template(_) => 0,
            NextOutputs::Join { .. } => 1,
        })
    }

    /// Register a signer (matched to the clause's signature args by public key).
    /// A `Box<dyn Signer>` works too, via the blanket [`Signer`] impl for boxes.
    pub fn sign(mut self, signer: impl Signer + 'static) -> Self {
        self.signers.insert(signer.public_key(), Box::new(signer));
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
    pub fn exec(self, manager: &mut ContractManager) -> Result<Children, ManagerError> {
        manager.execute_spend(self)
    }

    /// Like [`exec`](Self::exec) but asserts exactly one child instance is produced.
    pub fn exec_one(self, manager: &mut ContractManager) -> Result<InstanceHandle, ManagerError> {
        let expected = self.expected_children(manager)?;
        if expected != 1 {
            return Err(ManagerError::UnexpectedOutputCount {
                expected: 1,
                got: expected,
            });
        }
        let mut outputs = self.exec(manager)?.into_vec();
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
        let expected = self.expected_children(manager)?;
        if expected != 0 {
            return Err(ManagerError::UnexpectedOutputCount {
                expected: 0,
                got: expected,
            });
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{
        ClauseOutput, ClauseTree, CtvTemplate, NextOutputsFn, RawArgs, StandardClause, StandardP2TR,
    };
    use crate::testutil::{fund_fake, offline_client};
    use bitcoin::ScriptBuf;
    use std::sync::Arc;

    fn offline_manager() -> ContractManager {
        ContractManager::new(offline_client(), bitcoin::Network::Regtest)
    }

    fn sat(n: u64) -> Amount {
        Amount::from_sat(n)
    }

    /// A single-clause (`"spend"`) contract for exercising the output derivation:
    /// the clause takes no arguments and yields `next_outputs_fn`'s result when
    /// spent (terminal when `None`). `tag` differentiates the script — and thus
    /// the address — of otherwise identical contracts.
    fn test_contract(
        tag: i64,
        next_outputs_fn: Option<NextOutputsFn<(), (), RawArgs>>,
    ) -> Arc<dyn ErasedContract> {
        test_contract_with_identity::<StandardP2TR<()>>(tag, next_outputs_fn)
    }

    fn test_contract_with_identity<I: 'static>(
        tag: i64,
        next_outputs_fn: Option<NextOutputsFn<(), (), RawArgs>>,
    ) -> Arc<dyn ErasedContract> {
        let script = bitcoin::script::Builder::new()
            .push_int(tag)
            .push_opcode(bitcoin::opcodes::all::OP_DROP)
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script();
        let clause = StandardClause::<(), (), RawArgs>::new(
            "spend".to_string(),
            script,
            vec![],
            next_outputs_fn,
        );
        Arc::new(
            StandardP2TR::new_with_identity::<I>(
                "Test",
                crate::nums_key(),
                &(),
                ClauseTree::leaf(Arc::new(clause)),
            )
            .expect("test contract is valid"),
        )
    }

    /// A contract whose clause produces exactly `outputs` when spent.
    fn contract_yielding(tag: i64, outputs: Vec<ClauseOutput>) -> Arc<dyn ErasedContract> {
        test_contract(
            tag,
            Some(Arc::new(move |_: &(), _: &RawArgs, _: Option<&()>| {
                Ok(NextOutputs::Contracts(outputs.clone()))
            })),
        )
    }

    /// A contract whose clause fixes the spending transaction via a CTV template.
    fn contract_with_template(tag: i64, template: CtvTemplate) -> Arc<dyn ErasedContract> {
        test_contract(
            tag,
            Some(Arc::new(move |_: &(), _: &RawArgs, _: Option<&()>| {
                Ok(NextOutputs::Template(template.clone()))
            })),
        )
    }

    /// Begin a spend of the (only) clause of a [`test_contract`] instance.
    fn spend(handle: &InstanceHandle) -> SpendBuilder {
        handle.spend_clause("spend", vec![])
    }

    fn spk_of(contract: &Arc<dyn ErasedContract>) -> ScriptBuf {
        contract.script_pubkey(None).unwrap()
    }

    // ------------------------------------------------------------------
    // Output derivation (merging preserves/deducts across batch inputs)
    // ------------------------------------------------------------------

    #[test]
    fn merges_preserves_and_deducts_across_inputs() {
        let unvault = test_contract(90, None);
        let revault = test_contract(91, None);
        // Input 0 revaults 30k (deduct at index 1) and preserves the rest into
        // index 0; input 1 preserves its whole amount into the same index 0.
        let c1 = contract_yielding(
            1,
            vec![
                ClauseOutput::at(1)
                    .to(revault.clone())
                    .deduct_amount()
                    .build(),
                ClauseOutput::at(0)
                    .to(unvault.clone())
                    .preserve_amount()
                    .build(),
            ],
        );
        let c2 = contract_yielding(
            2,
            vec![
                ClauseOutput::at(0)
                    .to(unvault.clone())
                    .preserve_amount()
                    .build(),
            ],
        );
        let h1 = fund_fake(c1, None, sat(100_000), 1);
        let h2 = fund_fake(c2, None, sat(60_000), 2);

        let tx = offline_manager()
            .build_batch_tx(&[spend(&h1).output_amount(1, sat(30_000)), spend(&h2)])
            .unwrap();

        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 2);
        // index 0: (100k - 30k) + 60k merged; index 1: the deducted revault.
        assert_eq!(tx.output[0].value, sat(130_000));
        assert_eq!(tx.output[0].script_pubkey, spk_of(&unvault));
        assert_eq!(tx.output[1].value, sat(30_000));
        assert_eq!(tx.output[1].script_pubkey, spk_of(&revault));
    }

    #[test]
    fn join_contributes_to_another_inputs_output() {
        let dest = test_contract(90, None);
        let defining = contract_yielding(
            1,
            vec![
                ClauseOutput::at(0)
                    .to(dest.clone())
                    .preserve_amount()
                    .build(),
            ],
        );
        let joining = test_contract(
            2,
            Some(Arc::new(|_: &(), _: &RawArgs, _: Option<&()>| {
                Ok(NextOutputs::join(0))
            })),
        );
        let hd = fund_fake(defining, None, sat(100_000), 1);
        let hj = fund_fake(joining, None, sat(60_000), 2);

        // Both orders: the join is resolved after all defining inputs.
        for builders in [[spend(&hd), spend(&hj)], [spend(&hj), spend(&hd)]] {
            let tx = offline_manager().build_batch_tx(&builders).unwrap();
            assert_eq!(tx.output.len(), 1);
            assert_eq!(tx.output[0].value, sat(160_000));
            assert_eq!(tx.output[0].script_pubkey, spk_of(&dest));
        }
    }

    #[test]
    fn join_without_target_errors() {
        let joining = test_contract(
            1,
            Some(Arc::new(|_: &(), _: &RawArgs, _: Option<&()>| {
                Ok(NextOutputs::join(0))
            })),
        );
        let h = fund_fake(joining, None, sat(60_000), 1);
        let err = offline_manager().build_batch_tx(&[spend(&h)]).unwrap_err();
        assert!(matches!(err, ManagerError::JoinWithoutTarget { index: 0 }));
    }

    #[test]
    fn join_into_a_deduct_output_errors() {
        let dest = test_contract(90, None);
        let deducting = contract_yielding(
            1,
            vec![ClauseOutput::at(0).to(dest.clone()).deduct_amount().build()],
        );
        let joining = test_contract(
            2,
            Some(Arc::new(|_: &(), _: &RawArgs, _: Option<&()>| {
                Ok(NextOutputs::join(0))
            })),
        );
        let hd = fund_fake(deducting, None, sat(100_000), 1);
        let hj = fund_fake(joining, None, sat(60_000), 2);
        let err = offline_manager()
            .build_batch_tx(&[spend(&hd).output_amount(0, sat(10_000)), spend(&hj)])
            .unwrap_err();
        assert!(matches!(
            err,
            ManagerError::MixedOutputSemantics { index: 0 }
        ));
    }

    /// A defining input and a joining input funded and batched, for the
    /// observation-order tests.
    fn join_fixture() -> (InstanceHandle, InstanceHandle) {
        let dest = test_contract(90, None);
        let defining = contract_yielding(
            1,
            vec![ClauseOutput::at(0).to(dest).preserve_amount().build()],
        );
        let joining = test_contract(
            2,
            Some(Arc::new(|_: &(), _: &RawArgs, _: Option<&()>| {
                Ok(NextOutputs::join(0))
            })),
        );
        (
            fund_fake(defining, None, sat(100_000), 1),
            fund_fake(joining, None, sat(60_000), 2),
        )
    }

    #[test]
    fn join_link_survives_observation_order() {
        let (hd, hj) = join_fixture();
        let mut manager = offline_manager();
        let tx = manager.build_batch_tx(&[spend(&hd), spend(&hj)]).unwrap();

        // The joining input observed first: the shared child does not exist yet.
        assert!(manager.observe_spend(&hj, &tx).unwrap().is_empty());
        // The defining input's observation materializes it...
        let children = manager.observe_spend(&hd, &tx).unwrap();
        assert_eq!(children.len(), 1);
        // ...and re-observing the joining input repairs its link.
        let relinked = manager.observe_spend(&hj, &tx).unwrap();
        assert_eq!(relinked.len(), 1);
        assert_eq!(relinked[0], children[0]);
        assert_eq!(hj.outputs().len(), 1);
        // A further re-observation serves the cached link, without duplicating it.
        assert_eq!(manager.observe_spend(&hj, &tx).unwrap().len(), 1);
        assert_eq!(hj.outputs().len(), 1);
    }

    #[test]
    fn apply_batch_links_joins_regardless_of_parent_order() {
        let (hd, hj) = join_fixture();
        let mut manager = offline_manager();
        // The joining parent listed first must not lose its link to the child.
        let (_, children) =
            crate::testutil::apply_batch(&mut manager, &[&hj, &hd], &[spend(&hd), spend(&hj)])
                .unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(hd.outputs().len(), 1);
        assert_eq!(hj.outputs().len(), 1);
    }

    #[test]
    fn second_preserve_in_one_input_errors() {
        let dest_a = test_contract(90, None);
        let dest_b = test_contract(91, None);
        // One input cannot preserve its remaining amount into two outputs.
        let c = contract_yielding(
            1,
            vec![
                ClauseOutput::at(0).to(dest_a).preserve_amount().build(),
                ClauseOutput::at(1).to(dest_b).preserve_amount().build(),
            ],
        );
        let h = fund_fake(c, None, sat(100_000), 1);

        let err = offline_manager().build_batch_tx(&[spend(&h)]).unwrap_err();
        assert!(
            matches!(&err, ManagerError::TransactionBuildError(msg) if msg.contains("PreserveOutput")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn mixing_preserve_and_deduct_at_same_index_errors() {
        let dest = test_contract(90, None);
        let preserving = contract_yielding(
            1,
            vec![
                ClauseOutput::at(0)
                    .to(dest.clone())
                    .preserve_amount()
                    .build(),
            ],
        );
        let deducting = contract_yielding(
            2,
            vec![ClauseOutput::at(0).to(dest.clone()).deduct_amount().build()],
        );
        let hp = fund_fake(preserving, None, sat(100_000), 1);
        let hd = fund_fake(deducting, None, sat(50_000), 2);

        // Preserve first, deduct second — and the other way around.
        let err = offline_manager()
            .build_batch_tx(&[spend(&hp), spend(&hd).output_amount(0, sat(10_000))])
            .unwrap_err();
        assert!(matches!(
            err,
            ManagerError::MixedOutputSemantics { index: 0 }
        ));

        let err = offline_manager()
            .build_batch_tx(&[spend(&hd).output_amount(0, sat(10_000)), spend(&hp)])
            .unwrap_err();
        assert!(matches!(
            err,
            ManagerError::MixedOutputSemantics { index: 0 }
        ));
    }

    #[test]
    fn merged_output_requires_one_contract_identity() {
        struct First;
        struct Second;

        let first = test_contract_with_identity::<First>(90, None);
        let second = test_contract_with_identity::<Second>(90, None);
        assert_eq!(spk_of(&first), spk_of(&second));

        let c1 = contract_yielding(
            1,
            vec![ClauseOutput::at(0).to(first).preserve_amount().build()],
        );
        let c2 = contract_yielding(
            2,
            vec![ClauseOutput::at(0).to(second).preserve_amount().build()],
        );
        let h1 = fund_fake(c1, None, sat(50_000), 1);
        let h2 = fund_fake(c2, None, sat(50_000), 2);

        let err = offline_manager()
            .build_batch_tx(&[spend(&h1), spend(&h2)])
            .unwrap_err();
        assert!(matches!(
            err,
            ManagerError::ConflictingOutputContract { index: 0 }
        ));
    }

    #[test]
    fn observation_validates_child_outputs_before_marking_spent() {
        let destination = test_contract(90, None);
        let parent = contract_yielding(
            1,
            vec![
                ClauseOutput::at(0)
                    .to(destination)
                    .preserve_amount()
                    .build(),
            ],
        );
        let handle = fund_fake(parent, None, sat(50_000), 1);
        let mut manager = offline_manager();
        let valid = spend(&handle).build_tx(&manager).unwrap();

        let mut wrong_script = valid.clone();
        wrong_script.output[0].script_pubkey = ScriptBuf::new();
        let err = manager.observe_spend(&handle, &wrong_script).unwrap_err();
        assert!(matches!(err, ManagerError::WrongContractOutput(_)));
        assert_eq!(handle.status(), InstanceStatus::Funded);
        assert!(handle.outputs().is_empty());

        let mut missing = valid;
        missing.output.clear();
        let err = manager.observe_spend(&handle, &missing).unwrap_err();
        assert!(matches!(err, ManagerError::MissingContractOutput(_)));
        assert_eq!(handle.status(), InstanceStatus::Funded);
        assert!(handle.outputs().is_empty());
    }

    #[test]
    fn child_state_must_match_the_destination_contract() {
        let stateless = test_contract(90, None);
        let parent = contract_yielding(
            1,
            vec![
                ClauseOutput::at(0)
                    .to(stateless)
                    .with_state(&())
                    .preserve_amount()
                    .build(),
            ],
        );
        let handle = fund_fake(parent, None, sat(50_000), 1);

        let err = spend(&handle).build_tx(&offline_manager()).unwrap_err();
        assert!(matches!(
            err,
            ManagerError::ContractError(ContractError::UnexpectedState)
        ));
    }

    #[test]
    fn unused_output_amount_errors() {
        let dest = test_contract(90, None);
        let c = contract_yielding(
            1,
            vec![ClauseOutput::at(0).to(dest).preserve_amount().build()],
        );
        let h = fund_fake(c, None, sat(100_000), 1);

        let err = offline_manager()
            .build_batch_tx(&[spend(&h).output_amount(1, sat(10_000))])
            .unwrap_err();
        assert!(matches!(err, ManagerError::UnusedOutputAmount { index: 1 }));
    }

    #[test]
    fn missing_deduct_amount_errors() {
        let dest = test_contract(90, None);
        let c = contract_yielding(
            1,
            vec![ClauseOutput::at(0).to(dest).deduct_amount().build()],
        );
        let h = fund_fake(c, None, sat(100_000), 1);

        let err = offline_manager().build_batch_tx(&[spend(&h)]).unwrap_err();
        assert!(matches!(
            err,
            ManagerError::MissingDeductAmount { index: 0 }
        ));
    }

    #[test]
    fn ignore_output_requires_an_explicit_amount() {
        let dest = test_contract(90, None);
        let c = contract_yielding(
            1,
            vec![ClauseOutput::at(0).to(dest).ignore_amount().build()],
        );
        let h = fund_fake(c, None, sat(100_000), 1);

        let err = offline_manager().build_batch_tx(&[spend(&h)]).unwrap_err();
        assert!(matches!(
            err,
            ManagerError::MissingIgnoredAmount { index: 0 }
        ));

        let tx = offline_manager()
            .build_batch_tx(&[spend(&h).output_amount(0, sat(25_000))])
            .unwrap();
        assert_eq!(tx.output[0].value, sat(25_000));
    }

    #[test]
    fn deduct_exceeding_input_errors() {
        let dest = test_contract(90, None);
        let c = contract_yielding(
            1,
            vec![ClauseOutput::at(0).to(dest).deduct_amount().build()],
        );
        let h = fund_fake(c, None, sat(50_000), 1);

        let err = offline_manager()
            .build_batch_tx(&[spend(&h).output_amount(0, sat(60_000))])
            .unwrap_err();
        assert!(matches!(err, ManagerError::DeductExceedsInput));
    }

    #[test]
    fn conflicting_output_amounts_error() {
        let dest = test_contract(90, None);
        let deducting = |tag, seed| {
            let c = contract_yielding(
                tag,
                vec![ClauseOutput::at(0).to(dest.clone()).deduct_amount().build()],
            );
            fund_fake(c, None, sat(100_000), seed)
        };
        let h1 = deducting(1, 1);
        let h2 = deducting(2, 2);

        let err = offline_manager()
            .build_batch_tx(&[
                spend(&h1).output_amount(0, sat(10_000)),
                spend(&h2).output_amount(0, sat(20_000)),
            ])
            .unwrap_err();
        assert!(matches!(
            err,
            ManagerError::ConflictingOutputAmount { index: 0 }
        ));
    }

    #[test]
    fn non_contiguous_outputs_error() {
        let dest = test_contract(90, None);
        let c = contract_yielding(
            1,
            vec![ClauseOutput::at(1).to(dest).preserve_amount().build()],
        );
        let h = fund_fake(c, None, sat(100_000), 1);

        let err = offline_manager().build_batch_tx(&[spend(&h)]).unwrap_err();
        assert!(matches!(
            err,
            ManagerError::NonContiguousOutputs { missing_index: 0 }
        ));
    }

    #[test]
    fn terminal_clause_without_explicit_outputs_errors() {
        let c = test_contract(1, None);
        let h = fund_fake(c, None, sat(100_000), 1);

        let err = offline_manager().build_batch_tx(&[spend(&h)]).unwrap_err();
        assert!(matches!(err, ManagerError::NoOutputs));
    }

    // ------------------------------------------------------------------
    // CTV templates and explicit outputs
    // ------------------------------------------------------------------

    fn template_to(dest: &Arc<dyn ErasedContract>, amount: Amount, sequence: u32) -> CtvTemplate {
        CtvTemplate::new(
            vec![TxOut {
                script_pubkey: spk_of(dest),
                value: amount,
            }],
            Sequence(sequence),
        )
    }

    #[test]
    fn template_fixes_outputs_and_sequence() {
        let dest = test_contract(90, None);
        let template = template_to(&dest, sat(50_000), 5);
        let c = contract_with_template(1, template.clone());
        let h = fund_fake(c, None, sat(50_000), 1);
        let manager = offline_manager();

        let tx = spend(&h).build_tx(&manager).unwrap();
        assert_eq!(tx.output, template.outputs);
        assert_eq!(tx.input[0].sequence, Sequence(5));

        // A caller-set sequence must agree with the template's...
        let tx = spend(&h).sequence(5).build_tx(&manager).unwrap();
        assert_eq!(tx.input[0].sequence, Sequence(5));

        // ...or the build is rejected.
        let err = spend(&h).sequence(6).build_tx(&manager).unwrap_err();
        assert!(matches!(err, ManagerError::TransactionBuildError(_)));
    }

    #[test]
    fn template_in_batch_errors() {
        let dest = test_contract(90, None);
        let templated = contract_with_template(1, template_to(&dest, sat(50_000), 0));
        let preserving = contract_yielding(
            2,
            vec![
                ClauseOutput::at(0)
                    .to(dest.clone())
                    .preserve_amount()
                    .build(),
            ],
        );
        let h1 = fund_fake(templated, None, sat(50_000), 1);
        let h2 = fund_fake(preserving, None, sat(60_000), 2);

        let err = offline_manager()
            .build_batch_tx(&[spend(&h1), spend(&h2)])
            .unwrap_err();
        assert!(matches!(err, ManagerError::TransactionBuildError(_)));
    }

    #[test]
    fn explicit_outputs_in_batch_error() {
        let dest = test_contract(90, None);
        let preserving = |tag, seed| {
            let c = contract_yielding(
                tag,
                vec![
                    ClauseOutput::at(0)
                        .to(dest.clone())
                        .preserve_amount()
                        .build(),
                ],
            );
            fund_fake(c, None, sat(100_000), seed)
        };
        let h1 = preserving(1, 1);
        let h2 = preserving(2, 2);
        let outputs = vec![TxOut {
            script_pubkey: spk_of(&dest),
            value: sat(100_000),
        }];

        let err = offline_manager()
            .build_batch_tx(&[spend(&h1).outputs(outputs), spend(&h2)])
            .unwrap_err();
        assert!(matches!(err, ManagerError::TransactionBuildError(_)));
    }

    #[test]
    fn explicit_outputs_cannot_override_a_template() {
        let dest = test_contract(90, None);
        let c = contract_with_template(1, template_to(&dest, sat(50_000), 0));
        let h = fund_fake(c, None, sat(50_000), 1);

        let err = offline_manager()
            .build_batch_tx(&[spend(&h).outputs(vec![TxOut {
                script_pubkey: spk_of(&dest),
                value: sat(40_000),
            }])])
            .unwrap_err();
        assert!(matches!(err, ManagerError::TransactionBuildError(_)));
    }

    #[test]
    fn explicit_outputs_cannot_override_contract_outputs() {
        let dest = test_contract(90, None);
        let c = contract_yielding(
            1,
            vec![
                ClauseOutput::at(0)
                    .to(dest.clone())
                    .preserve_amount()
                    .build(),
            ],
        );
        let h = fund_fake(c, None, sat(50_000), 1);

        let err = offline_manager()
            .build_batch_tx(&[spend(&h).outputs(vec![TxOut {
                script_pubkey: spk_of(&dest),
                value: sat(1),
            }])])
            .unwrap_err();
        assert!(matches!(err, ManagerError::TransactionBuildError(_)));
    }

    #[test]
    fn observation_rejects_a_ctv_template_mismatch() {
        let dest = test_contract(90, None);
        let c = contract_with_template(1, template_to(&dest, sat(50_000), 5));
        let h = fund_fake(c, None, sat(50_000), 1);
        let mut manager = offline_manager();
        let mut tx = spend(&h).build_tx(&manager).unwrap();
        tx.output[0].value = sat(49_999);

        let err = manager.observe_spend(&h, &tx).unwrap_err();
        assert!(matches!(err, ManagerError::UnrecognizedSpend(_)));
        assert_eq!(h.status(), InstanceStatus::Funded);
    }

    #[test]
    fn raw_witness_layout_is_checked_when_no_signer_exists() {
        let c = test_contract(1, None);
        let h = fund_fake(c, None, sat(50_000), 1);
        let err = h
            .spend_clause("spend", vec![vec![1]])
            .outputs(vec![TxOut {
                script_pubkey: ScriptBuf::new(),
                value: sat(50_000),
            }])
            .build_tx(&offline_manager())
            .unwrap_err();
        assert!(matches!(err, ManagerError::TransactionBuildError(_)));
    }

    #[test]
    fn duplicate_instance_in_batch_errors() {
        let dest = test_contract(90, None);
        let c = contract_yielding(
            1,
            vec![ClauseOutput::at(0).to(dest).preserve_amount().build()],
        );
        let h = fund_fake(c, None, sat(100_000), 1);

        let err = offline_manager()
            .build_batch_tx(&[spend(&h), spend(&h)])
            .unwrap_err();
        assert!(
            matches!(&err, ManagerError::TransactionBuildError(msg) if msg.contains("duplicate")),
            "unexpected error: {err:?}"
        );
    }

    // ------------------------------------------------------------------
    // Witness parsing and polling
    // ------------------------------------------------------------------

    #[test]
    fn parses_script_path_witness() {
        let arg = vec![1u8, 2, 3];
        let script = vec![0x51u8];
        let control_block = vec![0xc0u8; 33];

        // args + script + control block
        let witness =
            bitcoin::Witness::from_slice(&[arg.clone(), script.clone(), control_block.clone()]);
        let parsed = parse_script_path_witness(&witness).unwrap();
        assert_eq!(parsed.args, vec![arg.clone()]);
        assert_eq!(parsed.leaf_script, script);
        assert_eq!(parsed.control_block, control_block);

        // ... with a trailing annex: the annex is dropped.
        let annex = vec![0x50u8, 0xff];
        let witness = bitcoin::Witness::from_slice(&[
            arg.clone(),
            script.clone(),
            control_block.clone(),
            annex.clone(),
        ]);
        let parsed = parse_script_path_witness(&witness).unwrap();
        assert_eq!(parsed.args, vec![arg]);
        assert_eq!(parsed.leaf_script, script);
        assert_eq!(parsed.control_block, control_block);

        // a zero-argument clause: just script + control block.
        let witness = bitcoin::Witness::from_slice(&[script.clone(), control_block]);
        let parsed = parse_script_path_witness(&witness).unwrap();
        assert!(parsed.args.is_empty());
        assert_eq!(parsed.leaf_script, script);

        // Key-path spends (with or without an annex) carry no tapscript.
        let sig = vec![0xaau8; 64];
        for elements in [vec![sig.clone()], vec![sig, annex]] {
            let witness = bitcoin::Witness::from_slice(&elements);
            let err = parse_script_path_witness(&witness).unwrap_err();
            assert!(matches!(err, ManagerError::UnrecognizedSpend(_)));
        }
    }

    #[test]
    fn poll_until_returns_hit_or_times_out() {
        // An immediate hit is returned without waiting for the window.
        let hit = poll_until(Some(Duration::ZERO), || Ok(Some(42))).unwrap();
        assert_eq!(hit, Some(42));

        // A never-satisfied check times out with Ok(None).
        let miss = poll_until(Some(Duration::ZERO), || Ok(None::<i32>)).unwrap();
        assert_eq!(miss, None);

        // Errors from the check propagate immediately.
        let err = poll_until(Some(Duration::ZERO), || {
            Err::<Option<i32>, _>(ManagerError::Other("boom".to_string()))
        })
        .unwrap_err();
        assert!(matches!(err, ManagerError::Other(_)));
    }
}
