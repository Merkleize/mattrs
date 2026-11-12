//! RPC-free unsigned transaction preparation and output derivation.
//! This component never invokes signers or mutates the instance registry.
use super::validation::{
    OutputIdentity, resolve_outputs, validate_clause_witness, validate_ctv_commitment,
    validate_output_constraints,
};
use super::{ManagerError, SpendBuilder};
use crate::contracts::{AmountMode, InstanceStatus, NextOutputs, check_state_type};
use bitcoin::{Amount, Sequence, Transaction, TxIn, TxOut};
use std::collections::BTreeMap;

/// An unsigned batch whose outputs and input constraints have been resolved.
/// Kept separate from signing so validation never prompts a signer.
pub(super) struct PreparedBatch {
    pub(super) tx: Transaction,
    pub(super) prevouts: Vec<TxOut>,
    pub(super) nexts: Vec<NextOutputs>,
}

impl PreparedBatch {
    pub(super) fn child_count(&self) -> usize {
        let mut indices = std::collections::BTreeSet::new();
        for (vin, next) in self.nexts.iter().enumerate() {
            match next {
                NextOutputs::Contracts(outputs) => {
                    indices.extend(outputs.iter().map(|output| output.index.resolve(vin)));
                }
                NextOutputs::Join { index } => {
                    indices.insert(*index);
                }
                NextOutputs::Payments(_)
                | NextOutputs::Template(_)
                | NextOutputs::TemplateHash(_) => {}
            }
        }
        indices.len()
    }
}
pub(super) fn prepare(builders: &[SpendBuilder]) -> Result<PreparedBatch, ManagerError> {
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
        let outpoint = inst.outpoint();
        if inst.status() == InstanceStatus::Spent {
            return Err(ManagerError::AlreadySpent(outpoint));
        }
        if tx_inputs
            .iter()
            .any(|input: &TxIn| input.previous_output == outpoint)
        {
            return Err(ManagerError::TransactionBuildError(format!(
                "duplicate input: {} is spent twice in the batch",
                outpoint
            )));
        }
        let prevout = inst.prevout().clone();
        let clause = inst
            .contract()
            .get_clause(builder.clause_name)
            .ok_or_else(|| ManagerError::ClauseNotFound(builder.clause_name.to_string()))?;
        validate_clause_witness(clause.as_ref(), &builder.witness_args, true)
            .map_err(|e| ManagerError::TransactionBuildError(e.to_string()))?;
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
                // Validate the state's concrete type before a transaction
                // can be broadcast.
                check_state_type(output.next_contract.as_ref(), output.next_state.as_ref())?;
            }
        }
        nexts.push(next);
    }

    let (outputs, template_sequence) = derive_tx_outputs(builders, &nexts, &prevouts)?;
    if outputs.is_empty() {
        return Err(ManagerError::NoOutputs);
    }

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

    // Check CTV commitments and the final sequence before signing. A caller
    // may lengthen a CSV delay only if any exact CTV commitment still matches.
    for (vin, builder) in builders.iter().enumerate() {
        validate_ctv_commitment(&nexts[vin], &tx, vin)?;
        if matches!(nexts[vin], NextOutputs::Payments(_)) {
            validate_output_constraints(
                prevouts[vin].value,
                &resolve_outputs(&nexts[vin])?,
                &tx,
                vin,
            )?;
        }
        let inst = builder.instance.borrow();
        if let Some(blocks) = inst
            .contract()
            .get_clause(builder.clause_name)
            .and_then(|clause| clause.csv_blocks())
        {
            let delay = crate::BlockDelay::new(blocks)?;
            if !delay.is_satisfied_by(tx.input[vin].sequence) {
                return Err(ManagerError::TransactionBuildError(format!(
                    "clause '{}' requires at least {blocks} CSV blocks; nSequence {} does not satisfy it",
                    builder.clause_name, tx.input[vin].sequence,
                )));
            }
        }
    }

    Ok(PreparedBatch {
        tx,
        prevouts,
        nexts,
    })
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
/// index must not mix the two semantics. `IgnoreOutput` also requires an
/// explicit amount, but imposes no input/output value relationship.
fn derive_tx_outputs(
    builders: &[SpendBuilder],
    nexts: &[NextOutputs],
    prevouts: &[TxOut],
) -> Result<(Vec<TxOut>, Option<Sequence>), ManagerError> {
    let single = builders.len() == 1;

    let template = nexts.iter().find_map(|next| match next {
        NextOutputs::Template(template) => Some(template),
        _ => None,
    });
    let committed_hash = nexts
        .iter()
        .any(|next| matches!(next, NextOutputs::TemplateHash(_)));
    if committed_hash && !single {
        return Err(ManagerError::TransactionBuildError(
            "CTV template-hash clauses are single-input only; not supported in a batch".into(),
        ));
    }

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
            && !committed_hash
            && !matches!(nexts.first(), Some(NextOutputs::Payments(_)))
        {
            return Err(ManagerError::TransactionBuildError(
                "explicit outputs require an unconstrained clause, payments, or a CTV template hash"
                    .to_string(),
            ));
        }
        if matches!(nexts.first(), Some(NextOutputs::Payments(_)))
            && !builders[0].output_amounts.is_empty()
        {
            return Err(ManagerError::TransactionBuildError(
                "explicit payment outputs already supply amounts; do not also set output_amount"
                    .into(),
            ));
        }
        return Ok((explicit.clone(), None));
    }

    if let Some(template) = template {
        if !single {
            return Err(ManagerError::TransactionBuildError(
                "CTV template clauses are single-input only; not supported in a batch".to_string(),
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
    if committed_hash {
        return Err(ManagerError::TransactionBuildError(
            "a CTV template-hash clause requires explicit outputs (SpendBuilder::outputs)".into(),
        ));
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
    let mut identities: BTreeMap<u32, OutputIdentity> = BTreeMap::new();
    let mut outputs_map: BTreeMap<u32, TxOut> = BTreeMap::new();
    for (input_index, next) in nexts.iter().enumerate() {
        let clause_outputs = resolve_outputs(next)?;

        let mut remaining = prevouts[input_index].value;
        let mut preserve_used = false;
        for clause_output in clause_outputs {
            let idx = clause_output.index.resolve(input_index);
            let identity = clause_output.identity;
            if identities
                .get(&idx)
                .is_some_and(|previous| previous != &identity)
            {
                return Err(ManagerError::ConflictingOutputContract { index: idx });
            }
            identities.entry(idx).or_insert(identity);
            let script_pubkey = clause_output.script_pubkey;
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
            match clause_output.amount {
                AmountMode::Preserve => {
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
                AmountMode::Deduct => {
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
                AmountMode::Ignore => {
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
        if !matches!(identities.get(index), Some(OutputIdentity::Contract(_))) {
            return Err(ManagerError::JoinWithoutTarget { index: *index });
        }
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
