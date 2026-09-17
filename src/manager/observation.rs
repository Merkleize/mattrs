//! RPC-free observation: decode witnesses, validate complete batches, and stage lifecycle updates.
use super::validation::{
    ParsedScriptPathWitness, ResolvedOutput, parse_script_path_witness, resolve_outputs,
    validate_batch_constraints, validate_clause_witness, validate_ctv_commitment,
    validate_output_constraints,
};
use super::{Children, ContractManager, ExternalInput, InstanceHandle, ManagerError};
use crate::contracts::{InstanceStatus, NextOutputs};
use bitcoin::{Amount, OutPoint, Transaction};
use std::collections::BTreeMap;

/// Read-only result of authenticating a known input and resolving its metadata.
pub(super) struct ObservedInput {
    pub(super) handle: InstanceHandle,
    pub(super) vin: usize,
    pub(super) value: Amount,
    pub(super) clause_name: String,
    pub(super) witness_args: Vec<Vec<u8>>,
    pub(super) next: NextOutputs,
    pub(super) outputs: Vec<ResolvedOutput>,
    pub(super) already_spent: bool,
}

impl ObservedInput {
    fn constraints(&self) -> super::validation::InputConstraints<'_> {
        super::validation::InputConstraints {
            vin: self.vin,
            value: self.value,
            outputs: &self.outputs,
            join: match self.next {
                NextOutputs::Join { index } => Some(index),
                _ => None,
            },
        }
    }
}
/// Authenticate the witness and resolve one input's declared constraints.
/// Does not record the spend, create children, or perform RPC.
pub(super) fn decode_observation(
    handle: &InstanceHandle,
    spending_tx: &Transaction,
) -> Result<ObservedInput, ManagerError> {
    let txid = spending_tx.compute_txid();

    let already_spent = {
        let inst = handle.instance.borrow();
        if inst.status() == InstanceStatus::Spent {
            if inst.spent_in_tx() != Some(txid) {
                return Err(ManagerError::InvalidInstance(
                    "Instance already spent by a different transaction".to_string(),
                ));
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
            .control_block_internal_key(inst.state_commitment().as_ref())?;
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

    let value = handle.prevout().ok_or(ManagerError::NotFunded)?.value;
    let outputs = resolve_outputs(&next)?;
    validate_output_constraints(value, &outputs, spending_tx, vin)?;
    validate_ctv_commitment(&next, spending_tx, vin)?;

    Ok(ObservedInput {
        handle: handle.clone(),
        vin,
        value,
        clause_name,
        witness_args,
        next,
        outputs,
        already_spent,
    })
}

impl ContractManager {
    /// Observe one input's declared constraints, not transaction-wide accounting.
    ///
    /// Use [`observe_batch`](Self::observe_batch) when all input contexts are
    /// available. This RPC-free method does not execute scripts, verify
    /// signatures, or establish confirmation/consensus validity. Re-observing a
    /// spend validates its witness again before returning cached children.
    /// A join whose defining input has not been observed yet can be retried.
    pub fn observe_spend(
        &mut self,
        handle: &InstanceHandle,
        spending_tx: &Transaction,
    ) -> Result<Children, ManagerError> {
        let ObservedInput {
            vin,
            clause_name,
            witness_args,
            next,
            already_spent,
            ..
        } = decode_observation(handle, spending_tx)?;
        let txid = spending_tx.compute_txid();
        if already_spent && !handle.outputs().is_empty() {
            return Ok(handle.outputs());
        }

        let children = match &next {
            // A re-observed instance with no cached children got here only to
            // retry a join link; its (childless) non-join clause has nothing
            // to re-materialize.
            NextOutputs::Contracts(_) if already_spent => Vec::new(),
            NextOutputs::Contracts(outputs) => {
                self.materialize_outputs(&handle.instance, outputs, spending_tx, vin)?
            }
            NextOutputs::Payments(_) | NextOutputs::Template(_) | NextOutputs::TemplateHash(_) => {
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

    /// Validate and observe a complete batch of contract inputs, without RPC.
    ///
    /// `handles` must cover every transaction input exactly once, in any order.
    /// Missing co-input context is an error, never an implicit unconstrained
    /// input. For ordinary wallet/fee inputs, use
    /// [`observe_batch_with_external_inputs`](Self::observe_batch_with_external_inputs).
    ///
    /// Validates witnesses, declared output scripts, CTV commitments, aggregate
    /// preserve amounts, cross-input deduct conflicts, and join contributions.
    /// All checks and child construction finish before any parent or registry is
    /// changed. Children are deduplicated and returned in output-index order;
    /// joins are linked in the same call regardless of input/handle ordering.
    ///
    /// This validates the declared model, not arbitrary script execution,
    /// signatures, UTXO availability, confirmations, or full consensus validity.
    pub fn observe_batch(
        &mut self,
        handles: &[&InstanceHandle],
        spending_tx: &Transaction,
    ) -> Result<Children, ManagerError> {
        self.observe_batch_inner(handles, &[], spending_tx)
    }

    pub(super) fn observe_batch_inner(
        &mut self,
        handles: &[&InstanceHandle],
        external: &[ExternalInput],
        spending_tx: &Transaction,
    ) -> Result<Children, ManagerError> {
        let staged = self.stage_batch(handles, external, spending_tx)?;
        Ok(staged.commit(self))
    }

    // Nonempty external context must first be validated by external_contexts.
    pub(super) fn stage_batch(
        &self,
        handles: &[&InstanceHandle],
        external: &[ExternalInput],
        spending_tx: &Transaction,
    ) -> Result<super::lifecycle::StagedBatch, ManagerError> {
        if spending_tx.input.is_empty() {
            return Err(ManagerError::InvalidInstance(
                "cannot observe an empty input set".into(),
            ));
        }
        if spending_tx.output.is_empty() {
            return Err(ManagerError::NoOutputs);
        }
        let mut input_indices = BTreeMap::new();
        for (vin, input) in spending_tx.input.iter().enumerate() {
            if input_indices.insert(input.previous_output, vin).is_some() {
                return Err(ManagerError::InvalidInstance(
                    "transaction spends an outpoint more than once".into(),
                ));
            }
        }
        let mut supplied = BTreeMap::new();
        for handle in handles {
            let outpoint = handle.outpoint().ok_or(ManagerError::NotFunded)?;
            let vin = *input_indices.get(&outpoint).ok_or_else(|| {
                ManagerError::InvalidInstance(format!(
                    "observation context {outpoint} is not an input of this transaction"
                ))
            })?;
            if supplied.insert(vin, *handle).is_some() {
                return Err(ManagerError::InvalidInstance(
                    "duplicate input context in observation".into(),
                ));
            }
        }
        let missing: Vec<_> = spending_tx
            .input
            .iter()
            .enumerate()
            .filter(|(vin, input)| {
                !supplied.contains_key(vin)
                    && !external.iter().any(|e| e.outpoint == input.previous_output)
            })
            .map(|(_, input)| input.previous_output)
            .collect();
        if !missing.is_empty() {
            return Err(ManagerError::IncompleteObservation { missing });
        }
        let observed: Vec<_> = supplied
            .values()
            .map(|handle| decode_observation(handle, spending_tx))
            .collect::<Result<_, _>>()?;
        let constraints: Vec<_> = observed.iter().map(ObservedInput::constraints).collect();
        validate_batch_constraints(&constraints, spending_tx)?;

        self.stage_batch_update(observed, spending_tx)
    }
}
