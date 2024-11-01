use std::{cell::RefCell, collections::HashMap, rc::Rc};

use bitcoin::{
    hashes::Hash, key::Secp256k1, secp256k1::Scalar, sighash::SighashCache, taproot::LeafVersion,
    transaction::Version, Address, Amount, KnownHrp, OutPoint, ScriptBuf, Sequence, TapLeafHash,
    TapNodeHash, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};

use thiserror::Error;

use crate::{
    contract_instance::{ContractInstance, ContractInstanceStatus},
    contracts::{
        CcvClauseOutputAmountBehaviour, ClauseArguments, ClauseOutputs, WitnessStackElement,
    },
    signer::SchnorrSigner,
};

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

pub fn create_spend_tx<'a, I>(
    spends: I,
    output_amounts: HashMap<usize, u64>,
    outputs: Vec<TxOut>,
) -> Result<(Transaction, Vec<[u8; 32]>), SpendTxError>
where
    I: IntoIterator<
        Item = (
            &'a Rc<RefCell<ContractInstance>>,
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
    let spends_vec: Vec<(&Rc<RefCell<ContractInstance>>, String, &dyn ClauseArguments)> =
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
                            return Err(SpendTxError::ClashingOutputScript(out_index, input_index));
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
        let expected_keys: HashMap<usize, ()> = (0..outputs_map.len()).map(|i| (i, ())).collect();
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

    for input_index in 0..spends_vec.len() {
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

pub fn get_spend_witness(
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

    let taptree = instance.contract.get_taptree();

    // add leaf script
    wit.push(
        taptree
            .get_tapleaf(clause_name)
            .unwrap()
            .script
            .as_bytes()
            .to_vec(),
    );

    // add control block
    let internal_pk: XOnlyPublicKey = instance.get_internal_pubkey();

    wit.push(taptree.get_control_block(&internal_pk, clause_name));

    Ok(Witness::from(wit))
}

pub fn get_spend_tx(
    instance: &Rc<RefCell<ContractInstance>>,
    clause_name: &str,
    clause_args: Box<dyn ClauseArguments>,
    outputs: Option<Vec<TxOut>>,
    signers: Option<&HashMap<XOnlyPublicKey, Box<dyn SchnorrSigner>>>,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    // Ensure the instance is in the Funded state
    let inst = instance.borrow();
    if inst.status != ContractInstanceStatus::Funded {
        return Err("Contract instance is not in a Funded state".into());
    }

    let outputs = outputs.unwrap_or_else(|| vec![]);

    // Construct the spend transaction
    let spends = vec![(instance, clause_name.to_string(), &*clause_args)];
    let (mut spend_tx, sighashes) = create_spend_tx(spends, HashMap::new(), outputs)?;

    if sighashes.len() != 1 {
        return Err("Expected exactly one sighash".into());
    }
    let sighash = sighashes[0];

    println!("{:?}", spend_tx);
    println!("{:?}", sighash);

    spend_tx.input[0].witness =
        get_spend_witness(&inst, clause_name, &*clause_args, &sighash, signers)?;

    Ok(spend_tx)
}

/// Processes a spending transaction to update contract instances and create new ones.
///
/// # Arguments
/// - `instances`: A slice of contract instances that were spent.
/// - `tx`: The transaction that spent the instances.
/// - `last_height`: The block height where the transaction was found.
///
/// # Returns
/// A vector of new `ContractInstance`s created as a result of the spending transaction.
///
/// # Errors
/// Returns an error if any issues occur while processing the transaction.
pub fn process_spending_transaction(
    instances: &[&Rc<RefCell<ContractInstance>>],
    tx: &Transaction,
    last_height: u64,
) -> Result<Vec<Rc<RefCell<ContractInstance>>>, Box<dyn std::error::Error>> {
    let mut out_contracts: HashMap<usize, Rc<RefCell<ContractInstance>>> = HashMap::new();

    for instance_rc in instances {
        let mut instance = instance_rc.borrow_mut();

        // Check that the instance is in the FUNDED state
        if instance.status != ContractInstanceStatus::Funded {
            return Err("Contract instance is not in FUNDED state".into());
        }

        // Update the instance with spending transaction details and change status to SPENT
        instance.spending_tx = Some(tx.clone());

        // Find the vin_index where this instance was spent
        let vin_index = tx
            .input
            .iter()
            .position(|vin| vin.previous_output == *instance.outpoint.as_ref().unwrap())
            .ok_or("Transaction does not spend the expected outpoint")?;
        instance.spending_vin = Some(vin_index);
        instance.status = ContractInstanceStatus::Spent;
        instance.last_height = Some(last_height);

        // Decode the witness stack to get the clause name and arguments
        let in_witness = &tx.input[vin_index].witness;
        let witness_stack: Vec<Vec<u8>> = in_witness.to_vec();

        // Ensure the witness stack has at least two elements (script and control block)
        if witness_stack.len() < 2 {
            return Err("Witness stack too short".into());
        }

        // Extract the script from the witness stack
        let script_bytes = &witness_stack[witness_stack.len() - 2];
        let script = ScriptBuf::from(script_bytes.clone());

        // Find the clause corresponding to the script
        let taptree = instance.contract.get_taptree();
        let clause = taptree
            .get_tapleaf_by_script(&script)
            .ok_or("Clause not found for script")?;

        let clause_name = clause.name.clone();

        // Extract the stack elements (excluding the last two, script and control block)
        let stack_elements = &witness_stack[..witness_stack.len() - 2];

        // Decode the arguments from the stack elements
        let args = instance
            .contract
            .args_from_stack_elements(&clause_name, stack_elements)?;

        // Update instance with clause name and arguments
        instance.spending_clause_name = Some(clause_name.clone());
        instance.spending_args = Some(args);

        // Retrieve the state (if any) of the instance
        let state = if let Some(st) = instance.state.as_ref() {
            st.as_ref()
        } else {
            &()
        };

        // Get the next outputs based on the clause execution
        let next_outputs = instance.contract.next_outputs(
            &clause_name,
            *instance.contract.get_params(),
            instance.spending_args.as_ref().unwrap().as_ref(),
            state,
        );

        // Process the next outputs to create new contract instances
        match next_outputs {
            ClauseOutputs::CtvTemplate => {
                // For now, we assume CTV clauses are terminal
                // This might be generalized in the future to support tracking known output contracts in a CTV template
            }
            ClauseOutputs::CcvList(ccv_outputs) => {
                let mut next_instances = Vec::new();
                // We go through each of the outputs specified in the clause, and create
                // a list of instances
                for clause_output in ccv_outputs {
                    let output_index = if clause_output.n == -1 {
                        vin_index
                    } else {
                        clause_output.n as usize
                    };

                    if out_contracts.contains_key(&output_index) {
                        // CCV output already specified by another input
                        next_instances.push(out_contracts.get(&output_index).unwrap().clone());
                        continue;
                    }

                    let out_contract = clause_output.next_contract;
                    let mut new_instance = ContractInstance::new(out_contract);

                    // If the contract is stateful, set the state
                    if new_instance.contract.is_augmented() {
                        if clause_output.next_state.is_none() {
                            return Err("Missing data for augmented output".into());
                        }
                        new_instance.set_state(clause_output.next_state.unwrap());
                    }

                    // Set the last_height
                    new_instance.last_height = Some(last_height);

                    // Set the outpoint to the output of tx at output_index
                    let outpoint = OutPoint {
                        txid: tx.compute_txid(),
                        vout: output_index as u32,
                    };

                    new_instance.outpoint = Some(outpoint);
                    new_instance.funding_tx = Some(tx.clone());
                    new_instance.status = ContractInstanceStatus::Funded;

                    let rc_new_instance = Rc::new(RefCell::new(new_instance));

                    out_contracts.insert(output_index, rc_new_instance.clone());

                    next_instances.push(rc_new_instance);
                }
                // Assign next_instances to instance.next
                instance.next = Some(next_instances);
            }
        }
    }

    // Collect the new contract instances into a result list, sorted by output index
    let mut result: Vec<Rc<RefCell<ContractInstance>>> =
        out_contracts.into_iter().map(|(_, inst)| inst).collect();

    result.sort_by_key(|inst| {
        inst.borrow()
            .outpoint
            .as_ref()
            .map(|op| op.vout)
            .unwrap_or(0)
    });

    Ok(result)
}
