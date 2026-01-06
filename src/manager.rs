//! Contract Manager
//!
//! Manages the lifecycle of contract instances from funding through spending,
//! with automatic output tracking and witness decoding.

use std::{cell::RefCell, collections::HashMap, rc::Rc, thread::sleep, time::Duration};

use bitcoin::{Amount, OutPoint, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey};
use bitcoincore_rpc::{Client, RpcApi};

use crate::{
    argtypes::ArgValue,
    contracts::{ClauseError, ContractInstance, ErasedContract, InstanceStatus},
    signer::Signer,
};

/// Type alias for a map of signers keyed by public key.
pub type SignerMap = HashMap<XOnlyPublicKey, Box<dyn Signer>>;

/// Error type for manager operations.
#[derive(Debug)]
pub enum ManagerError {
    RpcError(bitcoincore_rpc::Error),
    ClauseError(ClauseError),
    InvalidInstance(String),
    OutputNotFound,
    TransactionBuildError(String),
    Other(String),
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerError::RpcError(e) => write!(f, "RPC error: {}", e),
            ManagerError::ClauseError(e) => write!(f, "Clause error: {}", e),
            ManagerError::InvalidInstance(msg) => write!(f, "Invalid instance: {}", msg),
            ManagerError::OutputNotFound => write!(f, "Output not found on blockchain"),
            ManagerError::TransactionBuildError(msg) => {
                write!(f, "Transaction build error: {}", msg)
            }
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

    /// Add an existing instance to the manager.
    ///
    /// Note: This returns a handle with lifetime tied to this borrow of the manager.
    pub fn add_instance<'b>(
        &'b mut self,
        instance: Rc<RefCell<ContractInstance>>,
    ) -> InstanceHandle<'b>
    where
        'a: 'b,
    {
        self.instances.push(instance.clone());
        InstanceHandle {
            instance,
            manager: self,
        }
    }

    /// Create and fund a new contract instance.
    pub fn fund_instance<'b>(
        &'b mut self,
        contract: std::sync::Arc<dyn ErasedContract>,
        params_bytes: Vec<u8>,
        state_bytes: Option<Vec<u8>>,
        amount: Amount,
    ) -> Result<InstanceHandle<'b>, ManagerError>
    where
        'a: 'b,
    {
        // Create the instance
        let instance = Rc::new(RefCell::new(ContractInstance::new(
            contract,
            params_bytes,
            state_bytes,
        )));

        // Get the script pubkey for this instance
        let script_pubkey = self.get_instance_script_pubkey(&instance)?;

        // Fund it using RPC
        let params = bitcoin::Network::Regtest.params();
        let address = bitcoin::Address::from_script(&script_pubkey, &params)
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

        Ok(InstanceHandle {
            instance,
            manager: self,
        })
    }

    /// Spend a contract instance using the specified clause.
    pub fn spend_instance<'b>(
        &'b mut self,
        instance: Rc<RefCell<ContractInstance>>,
        clause_name: &str,
        args: HashMap<String, ArgValue>,
        explicit_outputs: Option<Vec<TxOut>>,
        signers: Option<&SignerMap>,
        sequence: Option<bitcoin::Sequence>,
    ) -> Result<Vec<InstanceHandle<'b>>, ManagerError>
    where
        'a: 'b,
    {
        // Verify instance is funded
        let inst = instance.borrow();
        if inst.status != InstanceStatus::Funded {
            return Err(ManagerError::InvalidInstance(
                "Instance is not funded".to_string(),
            ));
        }

        let outpoint = inst
            .outpoint
            .ok_or(ManagerError::InvalidInstance("No outpoint".to_string()))?;

        // Get the clause outputs
        let clause_outputs = inst.contract.execute_clause_erased(
            clause_name,
            &inst.params_bytes,
            args.clone(),
            inst.state_bytes.as_deref(),
        )?;

        drop(inst);

        // Build the transaction
        let tx = self.build_transaction(
            vec![outpoint],
            explicit_outputs,
            clause_outputs.as_ref(),
            &instance,
            clause_name,
            &args,
            signers,
            sequence,
        )?;

        // Broadcast it
        let txid = self.rpc.send_raw_transaction(&tx)?;

        // Mark instance as spent
        instance
            .borrow_mut()
            .mark_spent(txid, clause_name.to_string());

        // Create child instances from outputs
        let child_instances = if let Some(outputs) = clause_outputs {
            self.create_output_instances(&instance, outputs)?
        } else {
            Vec::new()
        };

        // Add children to parent
        for child in &child_instances {
            instance.borrow_mut().add_output(child.clone());
        }

        // Return handles to child instances
        Ok(child_instances
            .into_iter()
            .map(|inst| InstanceHandle {
                instance: inst,
                manager: self,
            })
            .collect())
    }

    /// Mine blocks (for regtest).
    pub fn mine_blocks(&self, n: u64) -> Result<(), ManagerError> {
        let address = self.rpc.get_new_address(None, None)?.assume_checked();
        self.rpc.generate_to_address(n, &address)?;
        Ok(())
    }

    // Helper methods

    fn get_instance_script_pubkey(
        &self,
        instance: &Rc<RefCell<ContractInstance>>,
    ) -> Result<bitcoin::ScriptBuf, ManagerError> {
        let inst = instance.borrow();
        inst.contract
            .script_pubkey(inst.state_bytes.as_deref())
            .map_err(|e| ManagerError::Other(e))
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

    fn build_transaction(
        &self,
        inputs: Vec<OutPoint>,
        explicit_outputs: Option<Vec<TxOut>>,
        clause_outputs: Option<&Vec<crate::contracts::ClauseOutput>>,
        instance: &Rc<RefCell<ContractInstance>>,
        clause_name: &str,
        args: &HashMap<String, ArgValue>,
        signers: Option<&SignerMap>,
        sequence: Option<bitcoin::Sequence>,
    ) -> Result<Transaction, ManagerError> {
        // Build unsigned transaction
        let seq = sequence.unwrap_or(bitcoin::Sequence::ZERO);
        let tx_inputs: Vec<TxIn> = inputs
            .iter()
            .map(|outpoint| TxIn {
                previous_output: *outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: seq,
                witness: bitcoin::Witness::new(),
            })
            .collect();

        let tx_outputs = if let Some(outputs) = explicit_outputs {
            outputs
        } else if let Some(clause_outs) = clause_outputs {
            // Generate outputs from clause execution
            let mut outputs = Vec::new();
            let inst = instance.borrow();
            let input_amount = inst
                .funding_tx
                .as_ref()
                .and_then(|tx| {
                    inst.outpoint
                        .as_ref()
                        .map(|op| &tx.output[op.vout as usize])
                })
                .map(|out| out.value)
                .unwrap_or(Amount::ZERO);
            drop(inst);

            for clause_out in clause_outs {
                let script_pubkey = clause_out
                    .next_contract
                    .script_pubkey(clause_out.next_state.as_deref())
                    .map_err(|e| ManagerError::TransactionBuildError(e))?;

                let value = match clause_out.next_amount {
                    crate::contracts::ClauseOutputAmountBehaviour::PreserveOutput => input_amount,
                    crate::contracts::ClauseOutputAmountBehaviour::IgnoreOutput => Amount::ZERO,
                    crate::contracts::ClauseOutputAmountBehaviour::DeductOutput => {
                        // DeductOutput requires explicit amounts to be provided
                        // This should not be reached when explicit_outputs is Some
                        return Err(ManagerError::TransactionBuildError(
                            "DeductOutput requires explicit outputs to be provided".to_string(),
                        ));
                    }
                };

                outputs.push(TxOut {
                    script_pubkey,
                    value,
                });
            }
            outputs
        } else {
            Vec::new()
        };

        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        // Build witness
        let inst = instance.borrow();
        let mut witness_stack = inst.contract.build_witness_stack(
            clause_name,
            &inst.params_bytes,
            args,
            inst.state_bytes.as_deref(),
        )?;
        drop(inst);

        // Sign if signers provided
        if let Some(signer_map) = signers {
            // Get the prevout for sighash computation
            let inst = instance.borrow();
            let prevout = inst
                .funding_tx
                .as_ref()
                .and_then(|tx| {
                    inst.outpoint
                        .as_ref()
                        .map(|op| tx.output[op.vout as usize].clone())
                })
                .ok_or_else(|| {
                    ManagerError::TransactionBuildError("No prevout available".to_string())
                })?;

            // Get the clause to access its script
            let clause = inst.contract.get_clause(clause_name).ok_or_else(|| {
                ManagerError::TransactionBuildError(format!("Clause '{}' not found", clause_name))
            })?;
            let leaf_script = clause.script().clone();
            drop(inst);

            // Compute the sighash for signing
            let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
                &leaf_script,
                bitcoin::taproot::LeafVersion::TapScript,
            );

            let sighash = crate::signer::compute_tap_sighash(
                &tx,
                0, // first input
                &[prevout],
                Some(leaf_hash),
                bitcoin::sighash::TapSighashType::Default,
            )
            .map_err(|e| ManagerError::TransactionBuildError(e))?;

            // Replace placeholder signatures (64 bytes of zeros) with real signatures
            for elem in witness_stack.iter_mut() {
                if elem.len() == 64 && elem.iter().all(|&b| b == 0) {
                    // This is a placeholder signature - find a signer and sign
                    for (_pubkey, signer) in signer_map.iter() {
                        let sig = signer.sign(&sighash);
                        *elem = sig;
                        break; // Use first available signer for this placeholder
                    }
                }
            }
        }

        // Add the script and control block to complete the tapscript witness
        {
            let inst = instance.borrow();
            let clause = inst.contract.get_clause(clause_name).ok_or_else(|| {
                ManagerError::TransactionBuildError(format!("Clause '{}' not found", clause_name))
            })?;
            let leaf_script = clause.script().clone();

            // Get the internal key for control block generation
            // For augmented contracts, this is the state-tweaked key
            let internal_key = inst
                .contract
                .control_block_internal_key(inst.state_bytes.as_deref())
                .map_err(|e| ManagerError::TransactionBuildError(e))?;
            let taptree = inst.contract.taptree();

            // Generate the control block
            let control_block = taptree
                .control_block(&internal_key, clause_name)
                .ok_or_else(|| {
                    ManagerError::TransactionBuildError(format!(
                        "Could not generate control block for clause '{}'",
                        clause_name
                    ))
                })?;

            // Append script and control block to witness
            witness_stack.push(leaf_script.to_bytes());
            witness_stack.push(control_block);
        }

        // Attach witness to first input
        if !tx.input.is_empty() {
            tx.input[0].witness = bitcoin::Witness::from_slice(&witness_stack);
        }

        Ok(tx)
    }

    fn create_output_instances(
        &mut self,
        parent: &Rc<RefCell<ContractInstance>>,
        outputs: Vec<crate::contracts::ClauseOutput>,
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
        for (_idx, clause_out) in outputs.iter().enumerate() {
            let vout = if clause_out.n == -1 {
                // Use same index as parent's input
                let parent_ref = parent.borrow();
                parent_ref
                    .outpoint
                    .ok_or_else(|| ManagerError::InvalidInstance("No parent outpoint".to_string()))?
                    .vout
            } else {
                clause_out.n as u32
            };

            // Use next_params if provided, otherwise use parent's params
            let params_bytes = if let Some(ref next_params) = clause_out.next_params {
                next_params.clone()
            } else {
                let parent_ref = parent.borrow();
                let params = parent_ref.params_bytes.clone();
                drop(parent_ref);
                params
            };

            let instance = Rc::new(RefCell::new(ContractInstance::new(
                clause_out.next_contract.clone(),
                params_bytes,
                clause_out.next_state.clone(),
            )));

            // Mark as funded
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

/// A handle to a contract instance that provides access to both the instance and the manager.
///
/// This allows clause methods generated by the `#[clause]` macro to access the manager
/// for spending operations.
pub struct InstanceHandle<'a> {
    pub instance: Rc<RefCell<ContractInstance>>,
    pub manager: &'a ContractManager<'a>,
}

impl<'a> InstanceHandle<'a> {
    /// Get the instance status.
    pub fn status(&self) -> InstanceStatus {
        self.instance.borrow().status
    }

    /// Get the outpoint (if funded).
    pub fn outpoint(&self) -> Option<OutPoint> {
        self.instance.borrow().outpoint
    }

    /// Get the child instances created from spending this instance.
    pub fn outputs(&self) -> Vec<Rc<RefCell<ContractInstance>>> {
        self.instance.borrow().outputs.clone()
    }
}
