use std::collections::HashMap;

use bitcoin::{
    hashes::Hash,
    sighash::SighashCache,
    taproot::LeafVersion,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut, Witness,
};

use thiserror::Error;

use crate::{
    contracts::{CcvAmountBehaviour, ClauseArgs, ContractInstance, ContractInstanceStatus},
    signer::SignerMap,
};

#[derive(Error, Debug)]
pub enum SpendTxError {
    #[error("Both output_amounts and outputs are provided, which is not allowed.")]
    MixedOutputSpecifications,
    #[error("Clause '{0}' not found in contract.")]
    ClauseNotFound(String),
    #[error("Instance has no outpoint")]
    NoOutpoint,
    #[error("Instance has no funding transaction")]
    NoFundingTx,
    #[error("Contract instance is not in FUNDED state")]
    NotFunded,
    #[error("Clashing output script for output {0}: specifications for input {1} don't match a previous one.")]
    ClashingOutputScript(usize, usize),
    #[error("DEDUCT_OUTPUT clause outputs must be declared before PRESERVE_OUTPUT clause outputs.")]
    DeductBeforePreserve,
    #[error("The output amount must be specified for clause outputs using DEDUCT_AMOUNT (output {0}).")]
    MissingOutputAmount(usize),
    #[error("Only PRESERVE_OUTPUT and DEDUCT_OUTPUT clause outputs are supported.")]
    UnsupportedClauseOutputBehavior,
    #[error("Some outputs are not correctly specified.")]
    IncorrectOutputSpecification,
    #[error("Failed to compute sighash: {0}")]
    SighashComputationFailed(String),
    #[error("Signer not found for pubkey {0}")]
    SignerNotFound(String),
    #[error("No signers provided, but the clause requires a signature")]
    NoSigners,
    #[error("{0}")]
    Other(String),
}

/// A single spend specification: instance index, clause name, clause args.
pub struct SpendSpec {
    pub instance_idx: usize,
    pub clause_name: String,
    pub args: ClauseArgs,
    pub sequence: Sequence,
}

/// Constructs a spend transaction from one or more spend specifications.
///
/// Returns the unsigned transaction (with empty witnesses) and sighashes for each input.
pub fn create_spend_tx(
    instances: &[ContractInstance],
    spends: &[SpendSpec],
    output_amounts: &HashMap<usize, u64>,
    extra_outputs: &[TxOut],
) -> Result<(Transaction, Vec<[u8; 32]>), SpendTxError> {
    if !output_amounts.is_empty() && !extra_outputs.is_empty() {
        return Err(SpendTxError::MixedOutputSpecifications);
    }

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: extra_outputs.to_vec(),
    };

    let mut outputs_map: HashMap<usize, TxOut> = HashMap::new();
    let mut leaf_scripts: HashMap<usize, ScriptBuf> = HashMap::new();

    // Populate inputs
    for spend in spends {
        let instance = &instances[spend.instance_idx];
        let outpoint = instance.outpoint.ok_or(SpendTxError::NoOutpoint)?;
        tx.input.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: spend.sequence,
            witness: Witness::default(),
        });
    }

    // Process each spend to generate outputs
    for (input_index, spend) in spends.iter().enumerate() {
        let instance = &instances[spend.instance_idx];
        let contract = &instance.contract;

        let clause = contract
            .get_clause(&spend.clause_name)
            .ok_or_else(|| SpendTxError::ClauseNotFound(spend.clause_name.clone()))?;

        leaf_scripts.insert(input_index, clause.script.clone());

        // Compute next outputs
        let next_outputs = (clause.next_outputs)(&spend.args, &instance.data)
            .map_err(|e| SpendTxError::Other(e.to_string()))?;

        let funding_tx = instance.funding_tx.as_ref().ok_or(SpendTxError::NoFundingTx)?;
        let outpoint = instance.outpoint.ok_or(SpendTxError::NoOutpoint)?;
        let funding_amount = funding_tx.output[outpoint.vout as usize].value;

        let mut preserve_output_used = false;
        let mut ccv_amount = funding_amount;

        for clause_output in next_outputs {
            let out_contract = &clause_output.next_contract;
            let out_address = out_contract.get_address(&clause_output.next_state);
            let out_script = out_address.script_pubkey();

            let out_index = if clause_output.n == -1 {
                input_index
            } else {
                clause_output.n as usize
            };

            if let Some(existing_out) = outputs_map.get(&out_index) {
                if existing_out.script_pubkey != out_script {
                    return Err(SpendTxError::ClashingOutputScript(out_index, input_index));
                }
            } else {
                outputs_map.insert(
                    out_index,
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: out_script,
                    },
                );
            }

            match clause_output.amount_behaviour {
                CcvAmountBehaviour::Preserve => {
                    if let Some(existing_out) = outputs_map.get_mut(&out_index) {
                        existing_out.value += funding_amount;
                    }
                    preserve_output_used = true;
                }
                CcvAmountBehaviour::Deduct => {
                    if preserve_output_used {
                        return Err(SpendTxError::DeductBeforePreserve);
                    }
                    let out_amount = output_amounts
                        .get(&out_index)
                        .ok_or(SpendTxError::MissingOutputAmount(out_index))?;
                    let existing_out = outputs_map.get_mut(&out_index).unwrap();
                    existing_out.value = Amount::from_sat(*out_amount);
                    ccv_amount -= Amount::from_sat(*out_amount);
                }
                CcvAmountBehaviour::Ignore => {
                    return Err(SpendTxError::UnsupportedClauseOutputBehavior);
                }
            }
        }
    }

    // Populate transaction outputs from outputs_map
    if !outputs_map.is_empty() && extra_outputs.is_empty() {
        let expected: Vec<usize> = (0..outputs_map.len()).collect();
        let mut actual: Vec<usize> = outputs_map.keys().copied().collect();
        actual.sort();
        if expected != actual {
            return Err(SpendTxError::IncorrectOutputSpecification);
        }

        tx.output = (0..outputs_map.len())
            .map(|i| outputs_map.remove(&i).unwrap())
            .collect();
    }

    // Compute sighashes
    let spent_utxos: Vec<TxOut> = spends
        .iter()
        .map(|spend| {
            let instance = &instances[spend.instance_idx];
            let funding_tx = instance.funding_tx.as_ref().unwrap();
            let outpoint = instance.outpoint.unwrap();
            funding_tx.output[outpoint.vout as usize].clone()
        })
        .collect();

    let mut sighash_cache = SighashCache::new(tx.clone());
    let mut sighashes = Vec::new();

    for input_index in 0..spends.len() {
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

/// Builds the witness for a single input.
///
/// Signs any signer_args in the clause using the provided signers, fills them into
/// clause_args, then calls args_to_witness to get the witness stack elements.
/// Appends the leaf script and control block.
pub fn build_witness(
    instance: &ContractInstance,
    clause_name: &str,
    args: &mut ClauseArgs,
    sighash: &[u8; 32],
    signers: Option<&SignerMap>,
) -> Result<Witness, SpendTxError> {
    let clause = instance
        .contract
        .get_clause(clause_name)
        .ok_or_else(|| SpendTxError::ClauseNotFound(clause_name.to_string()))?;

    // Fill in signature args by evaluating the pubkey closures
    for (arg_name, pk_fn) in &clause.signer_args {
        let pk = pk_fn(args, &instance.data);
        let signer = signers
            .ok_or(SpendTxError::NoSigners)?
            .get(&pk)
            .ok_or_else(|| SpendTxError::SignerNotFound(pk.to_string()))?;
        let sig = signer.sign(*sighash);
        args.insert(arg_name.clone(), sig.serialize().to_vec());
    }

    // Build witness stack from args
    let mut wit: Vec<Vec<u8>> = (clause.args_to_witness)(args)
        .map_err(|e| SpendTxError::Other(e.to_string()))?;

    // Append leaf script
    wit.push(clause.script.as_bytes().to_vec());

    // Append control block
    let internal_pk = instance.get_internal_pubkey();
    wit.push(
        instance
            .contract
            .taptree()
            .get_control_block(&internal_pk, clause_name),
    );

    Ok(Witness::from(wit))
}

/// High-level helper: constructs a fully-signed spend transaction for a single instance.
pub fn get_spend_tx(
    instances: &[ContractInstance],
    instance_idx: usize,
    clause_name: &str,
    mut args: ClauseArgs,
    extra_outputs: Option<&[TxOut]>,
    signers: Option<&SignerMap>,
    sequence: Sequence,
) -> Result<Transaction, SpendTxError> {
    let instance = &instances[instance_idx];
    if instance.status != ContractInstanceStatus::Funded {
        return Err(SpendTxError::NotFunded);
    }

    let spend = SpendSpec {
        instance_idx,
        clause_name: clause_name.to_string(),
        args: args.clone(),
        sequence,
    };

    let (mut tx, sighashes) = create_spend_tx(
        instances,
        &[spend],
        &HashMap::new(),
        extra_outputs.unwrap_or(&[]),
    )?;

    assert_eq!(sighashes.len(), 1);
    tx.input[0].witness = build_witness(
        instance,
        clause_name,
        &mut args,
        &sighashes[0],
        signers,
    )?;

    Ok(tx)
}

/// Processes a spending transaction to decode witness data, update the spent instance,
/// and create new funded instances from the clause outputs.
///
/// Returns new ContractInstances sorted by output index.
pub fn process_spending_transaction(
    instances: &mut [ContractInstance],
    spent_indices: &[usize],
    tx: &Transaction,
    last_height: u64,
) -> Result<Vec<ContractInstance>, Box<dyn std::error::Error>> {
    let mut out_contracts: HashMap<usize, ContractInstance> = HashMap::new();

    for &idx in spent_indices {
        let instance = &mut instances[idx];

        if instance.status != ContractInstanceStatus::Funded {
            return Err("Contract instance is not in FUNDED state".into());
        }

        // Find the vin that spends this instance
        let vin_index = tx
            .input
            .iter()
            .position(|vin| vin.previous_output == instance.outpoint.unwrap())
            .ok_or("Transaction does not spend the expected outpoint")?;

        // Update instance to SPENT
        instance.spending_tx = Some(tx.clone());
        instance.spending_vin = Some(vin_index);
        instance.status = ContractInstanceStatus::Spent;
        instance.last_height = Some(last_height);

        // Decode witness stack
        let witness_stack: Vec<Vec<u8>> = tx.input[vin_index].witness.to_vec();
        if witness_stack.len() < 2 {
            return Err("Witness stack too short".into());
        }

        // Extract script (second-to-last) and find clause
        let script_bytes = &witness_stack[witness_stack.len() - 2];
        let script = ScriptBuf::from(script_bytes.clone());
        let clause = instance
            .contract
            .taptree()
            .get_clause_by_script(&script)
            .ok_or("Clause not found for script in witness")?;
        let clause_name = clause.name.clone();

        // Decode args from witness elements (everything except script + control block)
        let stack_elements = &witness_stack[..witness_stack.len() - 2];
        let decoded_args = (clause.witness_to_args)(stack_elements)
            .map_err(|e| format!("Failed to decode witness args: {}", e))?;

        instance.spending_clause = Some(clause_name.clone());
        instance.spending_args = Some(decoded_args.clone());

        // Get next outputs
        let next_outputs = (clause.next_outputs)(&decoded_args, &instance.data)
            .map_err(|e| format!("Failed to compute next outputs: {}", e))?;

        for clause_output in next_outputs {
            let output_index = if clause_output.n == -1 {
                vin_index
            } else {
                clause_output.n as usize
            };

            if out_contracts.contains_key(&output_index) {
                continue; // already specified by another input
            }

            let mut new_instance =
                ContractInstance::new(clause_output.next_contract, clause_output.next_state);
            new_instance.last_height = Some(last_height);
            new_instance.outpoint = Some(OutPoint {
                txid: tx.compute_txid(),
                vout: output_index as u32,
            });
            new_instance.funding_tx = Some(tx.clone());
            new_instance.status = ContractInstanceStatus::Funded;

            out_contracts.insert(output_index, new_instance);
        }
    }

    let mut result: Vec<(usize, ContractInstance)> = out_contracts.into_iter().collect();
    result.sort_by_key(|(idx, _)| *idx);
    Ok(result.into_iter().map(|(_, inst)| inst).collect())
}
