use std::{cell::RefCell, collections::HashMap, rc::Rc, thread::sleep, time::Duration};

use bitcoin::{
    hashes::Hash, hex::DisplayHex, key::Secp256k1, secp256k1::Scalar, sighash::SighashCache,
    taproot::LeafVersion, transaction::Version, Address, Amount, KnownHrp, OutPoint, Script,
    ScriptBuf, Sequence, TapLeafHash, TapNodeHash, Transaction, TxIn, TxOut, Txid, Witness,
    XOnlyPublicKey,
};
use bitcoincore_rpc::{Client, RawTx, RpcApi};

use thiserror::Error;

use crate::{
    contracts::{
        CcvClauseOutputAmountBehaviour, ClauseArguments, ClauseOutputs, Contract, ContractState,
        WitnessStackElement,
    },
    signer::SchnorrSigner,
};

/// Waits for a specific output on the Bitcoin blockchain.
///
/// # Arguments
///
/// * `rpc_connection` - An authenticated RPC client to interact with Bitcoin Core.
/// * `script_pub_key` - The scriptPubKey to search for in transaction outputs.
/// * `poll_interval` - Time in seconds between each poll of the blockchain.
/// * `starting_height` - Optional starting block height. If `None`, starts from the current block height.
/// * `txid` - Optional transaction ID to filter transactions. If `None`, all transactions are considered.
/// * `min_amount` - Optional minimum amount in satoshis that the output must have.
///
/// # Returns
///
/// A tuple containing the found `OutPoint` and the block height where it was found.
///
/// # Errors
///
/// Returns an error if there are issues communicating with the RPC or processing the data.
pub async fn wait_for_output(
    rpc_connection: &Client,
    script_pub_key: &Script,
    poll_interval: f64,
    starting_height: Option<u64>,
    txid: Option<Txid>,
    min_amount: Option<u64>,
) -> Result<(OutPoint, u64), Box<dyn std::error::Error>> {
    // Initialize the last block height
    let mut last_block_height = if let Some(height) = starting_height {
        height.saturating_sub(1)
    } else {
        rpc_connection
            .get_block_count()
            .expect("Failed to retrieve current block count")
    };

    loop {
        // Retrieve the current block height
        let current_block_height = match rpc_connection.get_block_count() {
            Ok(height) => height,
            Err(e) => {
                eprintln!("Error fetching block count: {}", e);
                sleep(Duration::from_secs_f64(poll_interval));
                continue;
            }
        };

        // If the last checked block is ahead of the current, wait and retry
        if last_block_height > current_block_height {
            sleep(Duration::from_secs_f64(poll_interval));
            continue;
        }

        // Fetch the block hash for the current height
        let block_hash = match rpc_connection.get_block_hash(last_block_height) {
            Ok(hash) => hash,
            Err(e) => {
                eprintln!(
                    "Error fetching block hash at height {}: {}",
                    last_block_height, e
                );
                sleep(Duration::from_secs_f64(poll_interval));
                continue;
            }
        };

        // Retrieve verbose block information
        let block = match rpc_connection.get_block(&block_hash) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Error fetching block data for hash {}: {}", block_hash, e);
                sleep(Duration::from_secs_f64(poll_interval));
                continue;
            }
        };

        // Iterate through each transaction in the block
        for tx in block.txdata {
            // If a specific txid is provided, skip transactions that don't match
            if let Some(ref target_txid) = txid {
                if tx.compute_txid() != *target_txid {
                    continue;
                }
            }

            // Iterate through each output in the transaction
            for (vout_index, vout) in tx.output.iter().enumerate() {
                // If a minimum amount is specified, skip outputs below this threshold
                if let Some(min_amt) = min_amount {
                    // Convert BTC to satoshis
                    let value_sats = vout.value.to_sat();
                    if value_sats < min_amt {
                        continue;
                    }
                }

                let spk = &vout.script_pubkey;

                // Check if the scriptPubKey matches
                if *spk == *script_pub_key {
                    // Create the OutPoint
                    let outpoint = OutPoint {
                        txid: tx.compute_txid(),
                        vout: vout_index as u32,
                    };
                    return Ok((outpoint, last_block_height));
                }
            }
        }

        // Move to the next block
        last_block_height += 1;

        // Sleep before the next poll
        sleep(Duration::from_secs_f64(poll_interval));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractInstanceStatus {
    Abstract,
    Funded,
    Spent,
}

// TODO: we might want to use types to enforce the state machine
// (that is, AbstractContractInstance ==> FundedContractInstance ==> SpentContractInstance)
pub struct ContractInstance {
    pub contract: Box<dyn Contract>,
    pub status: ContractInstanceStatus,

    pub state: Option<Box<dyn ContractState>>,
    pub state_hash: Option<[u8; 32]>,

    pub outpoint: Option<OutPoint>,
    pub funding_tx: Option<Transaction>,

    pub spending_tx: Option<Transaction>,
    pub spending_vin: Option<usize>,
    pub spending_clause_name: Option<String>,
    pub spending_args: Option<Box<dyn ClauseArguments>>,

    pub next: Option<Rc<RefCell<ContractInstance>>>,
}

impl ContractInstance {
    pub fn new(contract: Box<dyn Contract>) -> Self {
        ContractInstance {
            contract,
            status: ContractInstanceStatus::Abstract,
            state: None,
            state_hash: None,
            outpoint: None,
            funding_tx: None,
            spending_tx: None,
            spending_vin: None,
            spending_clause_name: None,
            spending_args: None,
            next: None,
        }
    }

    pub fn set_state(&mut self, state: Box<dyn ContractState>) {
        if !self.contract.is_augmented() {
            panic!("Can only set the state for augmented contracts");
        }

        if self.state.is_some() {
            panic!("State was already set");
        }

        self.state_hash = Some(state.encode());
        self.state = Some(state);
    }

    pub fn get_script(&self) -> ScriptBuf {
        ScriptBuf::from(self.get_address())
    }

    pub fn get_internal_pubkey(&self) -> XOnlyPublicKey {
        let naked_key = self.contract.get_naked_internal_key();
        let secp = Secp256k1::new();

        if self.contract.is_augmented() {
            let data = self.state_hash.unwrap();
            // tweak with the state hash
            let (pk, _) = naked_key
                .add_tweak(&secp, &Scalar::from_be_bytes(data).unwrap())
                .unwrap();
            pk
        } else {
            naked_key
        }
    }

    pub fn get_address(&self) -> Address {
        if self.contract.is_augmented() && self.state_hash.is_none() {
            panic!("Can't get the address of a stateful contract if the state is not set")
        }

        let taptree_hash = self.contract.get_taptree().get_root_hash();
        let secp = Secp256k1::new();

        Address::p2tr(
            &secp,
            self.get_internal_pubkey(),
            Some(TapNodeHash::from_slice(&taptree_hash).unwrap()),
            KnownHrp::Regtest,
        )
    }
}

/// Represents errors that can occur while constructing the spend transaction.
#[derive(Error, Debug)]
pub enum SpendTxError {
    #[error("Both output_amounts and outputs are provided, which is not allowed.")]
    MixedOutputSpecifications,
    #[error("Clause '{0}' not found in contract.")]
    ClauseNotFound(String),
    #[error("CTV clauses are only supported for single-input spends.")]
    CtvClauseUnsupported,
    #[error("Unsupported contract type encountered.")]
    UnsupportedContractType,
    #[error("Missing data for augmented output.")]
    MissingAugmentedOutputData,
    #[error("Clashing output script for output {0}: specifications for input {1} don't match a previous one.")]
    ClashingOutputScript(usize, usize),
    #[error(
        "DEDUCT_OUTPUT clause outputs must be declared before PRESERVE_OUTPUT clause outputs."
    )]
    DeductBeforePreserve,
    #[error("The output amount must be specified for clause outputs using DEDUCT_AMOUNT.")]
    MissingOutputAmount(usize),
    #[error("Only PRESERVE_OUTPUT and DEDUCT_OUTPUT clause outputs are supported.")]
    UnsupportedClauseOutputBehavior,
    #[error("Some outputs are not correctly specified.")]
    IncorrectOutputSpecification,
    #[error("Failed to compute sighash: {0}")]
    SighashComputationFailed(String),
    #[error("Other error: {0}")]
    Other(String),
}

pub struct ContractManager<'a> {
    rpc: &'a Client,
    instances: Vec<Rc<RefCell<ContractInstance>>>,
}

impl<'a> ContractManager<'a> {
    pub fn new(rpc: &'a Client) -> Self {
        Self {
            rpc,
            instances: vec![],
        }
    }

    pub fn get_instances(&self) -> Vec<Rc<RefCell<ContractInstance>>> {
        self.instances.clone()
    }

    pub fn add_instance(&mut self, ci: Rc<RefCell<ContractInstance>>) {
        self.instances.push(ci);
    }

    pub async fn fund_instance(
        &mut self,
        contract: Box<dyn Contract>,
        state: Option<Box<dyn ContractState>>,
        amount: u64,
    ) -> Result<Rc<RefCell<ContractInstance>>, Box<dyn std::error::Error>> {
        // Create a new contract instance
        let mut inst = ContractInstance::new(contract);
        if let Some(st) = state {
            inst.set_state(st);
        }
        let rc_inst = Rc::new(RefCell::new(inst));

        // Add the new contract instance to the manager
        self.add_instance(Rc::clone(&rc_inst));

        // 1) send transaction funding the instance
        let address = rc_inst.borrow().get_address();

        // Send the specified amount to the address
        let amount_btc = Amount::from_sat(amount);
        let txid = self
            .rpc
            .send_to_address(&address, amount_btc, None, None, None, None, None, None)?;

        let (outpoint, _) = wait_for_output(
            self.rpc,
            &rc_inst.borrow().get_script().as_script(),
            0.1,
            None,
            Some(txid),
            Some(amount_btc.to_sat()),
        )
        .await?;

        println!("Funded contract instance at {:?}", outpoint); // TODO: remove

        let tx = self.rpc.get_raw_transaction(&txid, None)?;

        // Update the contract instance
        {
            let mut inst_mut = rc_inst.borrow_mut();
            inst_mut.outpoint = Some(outpoint);
            inst_mut.status = ContractInstanceStatus::Funded;
            inst_mut.funding_tx = Some(tx);
        }

        // Return the Rc pointer to the newly created ContractInstance
        Ok(rc_inst)
    }

    pub fn get_spend_witness(
        &self,
        instance: &ContractInstance,
        clause_name: &str,
        args: &dyn ClauseArguments,
        sighash: &[u8; 32],
        signers: Option<&HashMap<XOnlyPublicKey, Box<dyn SchnorrSigner>>>,
    ) -> Result<Witness, SpendTxError> {
        let wit_stack: Vec<WitnessStackElement> = instance
            .contract
            .stack_elements_from_args(clause_name, args)
            .unwrap();

        let mut wit: Vec<Vec<u8>> = wit_stack
            .iter()
            .map(|el| match el {
                WitnessStackElement::Bytes(buf) => Ok(buf.clone()),
                WitnessStackElement::Signature { pk } => {
                    let signer = signers
                        .as_ref()
                        .ok_or_else(|| SpendTxError::Other("No signers provided".to_string()))?
                        .get(pk)
                        .ok_or_else(|| {
                            SpendTxError::Other("Signer not found for pubkey".to_string())
                        })?;
                    Ok(signer.sign(sighash.clone()).serialize().to_vec())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // add leaf script
        wit.push(
            instance
                .contract
                .get_taptree()
                .get_tapleaf(clause_name)
                .unwrap()
                .script
                .as_bytes()
                .to_vec(),
        );

        // add control block
        let internal_pk: XOnlyPublicKey = instance.get_internal_pubkey();

        wit.push(
            instance
                .contract
                .get_taptree()
                .get_control_block(&internal_pk, clause_name),
        );

        Ok(Witness::from(wit))
    }

    pub fn create_spend_tx<I>(
        &self,
        spends: I,
        output_amounts: HashMap<usize, u64>,
        outputs: Vec<TxOut>,
    ) -> Result<(Transaction, Vec<[u8; 32]>), SpendTxError>
    where
        I: IntoIterator<
            Item = (
                Rc<RefCell<ContractInstance>>,
                String,
                &'a dyn ClauseArguments,
            ),
        >,
    {
        // 1. Ensure that output_amounts and outputs are not both provided
        if !output_amounts.is_empty() && !outputs.is_empty() {
            return Err(SpendTxError::MixedOutputSpecifications);
        }

        // 2. Normalize spends to a Vec for indexing
        let spends_vec: Vec<(Rc<RefCell<ContractInstance>>, String, &dyn ClauseArguments)> =
            spends.into_iter().collect();

        // 3. Initialize the transaction
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: outputs.clone(),
        };

        // 4. Initialize outputs_map
        let mut outputs_map: HashMap<usize, TxOut> = HashMap::new();

        // 5. Populate transaction inputs
        for (instance, _, _) in &spends_vec {
            let Some(outpoint) = instance.borrow().outpoint else {
                return Err(SpendTxError::Other("Instance has no outpoint".to_string()));
            };
            tx.input.push(TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::default(),
            });
        }

        let mut has_ctv_clause = false;

        // map of input index to script
        let mut leaf_scripts: HashMap<usize, ScriptBuf> = HashMap::new();

        // 6. Iterate over each spend to process clauses and generate outputs
        for (input_index, (instance_rc, clause_name, args)) in spends_vec.iter().enumerate() {
            let instance = instance_rc.borrow();
            let contract = &instance.contract;

            // Retrieve the clause
            let leaves = contract.get_taptree().get_leaves();
            let clause = leaves
                .iter()
                .find(|&leaf| leaf.name == *clause_name)
                .ok_or_else(|| SpendTxError::ClauseNotFound(clause_name.clone()))?;

            leaf_scripts.insert(input_index, clause.clone().script.clone());

            // Generate next outputs based on the clause
            // if instance.state.as_ref() is None, we pass () as the state
            let state = if let Some(st) = instance.state.as_ref() {
                st.as_ref()
            } else {
                &()
            };

            let next_outputs =
                contract.next_outputs(clause_name, *contract.get_params(), &**args, state);

            match next_outputs {
                ClauseOutputs::CtvTemplate => {
                    has_ctv_clause = true;
                    todo!()
                }
                ClauseOutputs::CcvList(ccv_outputs) => {
                    let instance_outpoint = instance
                        .outpoint
                        .as_ref()
                        .expect("Can only spend from instances if the outpoint is set");
                    let funding_tx = instance
                        .funding_tx
                        .as_ref()
                        .expect("Can only spend from instances if the fundng tx is set");
                    let funding_amount = funding_tx.output[instance_outpoint.vout as usize].value;

                    let mut preserve_output_used = false;
                    let mut ccv_amount = funding_amount;

                    for ccv_out in ccv_outputs {
                        let out_contract = ccv_out.next_contract;
                        // cast out_contract to Contract

                        let next_state = ccv_out.next_state;
                        let next_state_hash: Option<[u8; 32]> = if let Some(state) = next_state {
                            Some(state.encode())
                        } else {
                            None
                        };

                        // TODO: the logic to compute the final script should move elsewhere
                        let secp = Secp256k1::new();
                        let naked_internal_key = out_contract.get_naked_internal_key();
                        let taptree_hash = out_contract.get_taptree().get_root_hash();
                        let internal_pubkey = if let Some(next_state_hash) = next_state_hash {
                            let (internal_pk, _) = naked_internal_key
                                .add_tweak(&secp, &Scalar::from_be_bytes(next_state_hash).unwrap())
                                .unwrap();
                            internal_pk
                        } else {
                            naked_internal_key
                        };

                        let address = Address::p2tr(
                            &secp,
                            internal_pubkey,
                            Some(TapNodeHash::from_slice(&taptree_hash).unwrap()),
                            KnownHrp::Regtest,
                        );

                        let out_script = address.script_pubkey();

                        let out_index = if ccv_out.n == -1 {
                            input_index
                        } else {
                            ccv_out.n as usize
                        };

                        // fail if output_map already has an entry for out_index
                        if let Some(existing_out) = outputs_map.get(&out_index) {
                            if existing_out.script_pubkey != out_script {
                                return Err(SpendTxError::ClashingOutputScript(
                                    out_index,
                                    input_index,
                                ));
                            }
                        } else {
                            outputs_map.insert(
                                out_index,
                                TxOut {
                                    value: Amount::ZERO,
                                    script_pubkey: out_script.clone(),
                                },
                            );
                        }

                        match ccv_out.behaviour {
                            CcvClauseOutputAmountBehaviour::PreserveOutput => {
                                if let Some(existing_out) = outputs_map.get_mut(&out_index) {
                                    existing_out.value += funding_amount;
                                }
                                preserve_output_used = true;
                            }
                            CcvClauseOutputAmountBehaviour::DeductOutput => {
                                if preserve_output_used {
                                    return Err(SpendTxError::DeductBeforePreserve);
                                }
                                if !output_amounts.contains_key(&out_index) {
                                    return Err(SpendTxError::MissingOutputAmount(out_index));
                                }
                                let out_amount = *output_amounts.get(&out_index).unwrap();
                                //set the value in outputs_map

                                let existing_out = outputs_map.get_mut(&out_index).unwrap();
                                existing_out.value = Amount::from_sat(out_amount);
                                ccv_amount -= Amount::from_sat(out_amount);
                            }
                            CcvClauseOutputAmountBehaviour::IgnoreOutput => {
                                // TODO: generalize to clauses with IGNORE behaviour
                                return Err(SpendTxError::UnsupportedClauseOutputBehavior);
                            }
                        }
                    }
                }
            }
        }

        // 7. If not a CTV clause, populate the transaction outputs from outputs_map
        if !has_ctv_clause && !outputs_map.is_empty() {
            // Ensure that output indices are contiguous and start from 0
            let expected_keys: HashMap<usize, ()> =
                (0..outputs_map.len()).map(|i| (i, ())).collect();
            let actual_keys: HashMap<usize, ()> = outputs_map.keys().map(|k| (*k, ())).collect();
            if expected_keys != actual_keys {
                return Err(SpendTxError::IncorrectOutputSpecification);
            }

            // Populate transaction outputs in order
            let mut ordered_outputs = Vec::new();
            for i in 0..outputs_map.len() {
                if let Some(tx_out) = outputs_map.get(&i) {
                    ordered_outputs.push(tx_out.clone());
                } else {
                    return Err(SpendTxError::IncorrectOutputSpecification);
                }
            }
            tx.output = ordered_outputs;
        }

        // 8. Compute sighashes for each input
        let mut sighashes: Vec<[u8; 32]> = Vec::new();

        // Placeholder: Collect spent UTXOs (This should include all necessary information for sighash computation)
        let spent_utxos: Vec<TxOut> = spends_vec
            .iter()
            .map(|(instance_rc, _, _)| {
                let instance = instance_rc.borrow();
                let funding_tx = instance.funding_tx.as_ref().unwrap();
                let outpoint = instance.outpoint.as_ref().unwrap();
                funding_tx.output[outpoint.vout as usize].clone()
            })
            .collect();

        let mut sighash_cache = SighashCache::new(tx.clone());

        for (input_index, (instance_rc, clause_name, _)) in spends_vec.iter().enumerate() {
            let leaf_script = leaf_scripts.get(&input_index).unwrap();
            let sighash = sighash_cache
                .taproot_script_spend_signature_hash(
                    input_index,
                    &bitcoin::sighash::Prevouts::All(&spent_utxos),
                    TapLeafHash::from_script(leaf_script, LeafVersion::TapScript),
                    bitcoin::TapSighashType::Default,
                )
                .map(|h| h.to_byte_array())
                .map_err(|e| SpendTxError::SighashComputationFailed(e.to_string()))?;

            sighashes.push(sighash);
        }

        Ok((tx, sighashes))
    }

    pub async fn spend_instance(
        &mut self,
        instance: Rc<RefCell<ContractInstance>>,
        clause_name: &str,
        clause_args: Box<dyn ClauseArguments>,
        outputs: Option<Vec<TxOut>>,
        signers: Option<&HashMap<XOnlyPublicKey, Box<dyn SchnorrSigner>>>,
    ) -> Result<Vec<Rc<RefCell<ContractInstance>>>, Box<dyn std::error::Error>> {
        // Implementation will depend on how spending is handled.
        // 1. Ensure the instance is in the Funded state
        let inst = instance.borrow();
        if inst.status != ContractInstanceStatus::Funded {
            return Err("Contract instance is not in a Funded state".into());
        }

        // 2. Get the contract and clause details
        let contract = &inst.contract;
        let outpoint = inst
            .outpoint
            .as_ref()
            .ok_or("Funded instance has no outpoint")?;

        let outputs = outputs.unwrap_or_else(|| vec![]);
        // 3. Construct the spend transaction
        // This will depend on how your Contract trait defines transaction creation
        // For example purposes, we'll assume there's a method to create the spend transaction
        let spends = vec![(Rc::clone(&instance), clause_name.to_string(), &*clause_args)];
        let (mut spend_tx, sighashes) = self.create_spend_tx(spends, HashMap::new(), outputs)?;

        if sighashes.len() != 1 {
            return Err("Expected exactly one sighash".into());
        }
        let sighash = sighashes[0];

        println!("{:?}", spend_tx);
        println!("{:?}", sighash);

        spend_tx.input[0].witness =
            self.get_spend_witness(&inst, clause_name, &*clause_args, &sighash, signers)?;

        println!("{:?}", spend_tx.input[0].witness);

        for wit_el in spend_tx.input[0].witness.iter() {
            println!("{} ({} bytes)", wit_el.as_hex(), wit_el.len());
        }

        println!("Sending transaction: {:?}", spend_tx);
        println!("Serialized: {:?}", spend_tx.raw_hex());
        // send transaction
        let txid = self.rpc.send_raw_transaction(&spend_tx)?;
        println!("Sent transaction: {}", txid);

        // wait for transaction to confirm

        // wait for confirmation
        let (outpoint, _) = wait_for_output(
            self.rpc,
            &spend_tx.output[0].script_pubkey,
            0.1,
            None,
            Some(txid),
            None,
        )
        .await
        .unwrap();

        // compute the next outputs

        self.wait_for_spend(vec![Rc::clone(&instance)]).await
    }

    pub async fn wait_for_spend(
        &mut self,
        instances: Vec<Rc<RefCell<ContractInstance>>>,
    ) -> Result<Vec<Rc<RefCell<ContractInstance>>>, Box<dyn std::error::Error>> {
        todo!()
    }
}
