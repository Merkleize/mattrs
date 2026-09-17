//! RPC-free witness, template, output-identity, and CCV amount validation.
use super::ManagerError;
use crate::contracts::{
    ClauseOutput, ClauseOutputAmountBehaviour, ContractInstance, ErasedClause, NextOutputs,
    OutputIndex,
};
use bitcoin::{Amount, OutPoint, Transaction};
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct ContractOutputIdentity {
    pub(super) contract_type: std::any::TypeId,
    pub(super) params: Vec<u8>,
    pub(super) state: Option<Vec<u8>>,
}

impl ContractOutputIdentity {
    pub(super) fn from_clause_output(output: &ClauseOutput) -> Self {
        Self {
            contract_type: output.next_contract.contract_type_id(),
            params: output.next_contract.params_bytes().to_vec(),
            state: output.committed_state_bytes(),
        }
    }

    pub(super) fn from_instance(instance: &ContractInstance) -> Self {
        Self {
            contract_type: instance.contract().contract_type_id(),
            params: instance.contract().params_bytes().to_vec(),
            state: instance.committed_state_bytes(),
        }
    }
}

/// Preserve tracking identity separately from the script being paid.
#[derive(Clone, PartialEq, Eq)]
pub(super) enum OutputIdentity {
    Contract(ContractOutputIdentity),
    Payment(bitcoin::ScriptBuf),
}

/// Shared representation for amount accounting; only contract outputs are
/// materialized as children. Keep payments out of the instance registry.
pub(super) struct ResolvedOutput {
    pub(super) index: OutputIndex,
    pub(super) script_pubkey: bitcoin::ScriptBuf,
    pub(super) amount: ClauseOutputAmountBehaviour,
    pub(super) identity: OutputIdentity,
}
pub(super) fn resolve_outputs(next: &NextOutputs) -> Result<Vec<ResolvedOutput>, ManagerError> {
    match next {
        NextOutputs::Contracts(outputs) => outputs
            .iter()
            .map(|output| {
                Ok(ResolvedOutput {
                    index: output.index,
                    script_pubkey: output
                        .next_contract
                        .script_pubkey(output.state_commitment().as_ref())?,
                    amount: output.next_amount,
                    identity: OutputIdentity::Contract(ContractOutputIdentity::from_clause_output(
                        output,
                    )),
                })
            })
            .collect(),
        NextOutputs::Payments(outputs) => Ok(outputs
            .iter()
            .map(|output| ResolvedOutput {
                index: output.index,
                script_pubkey: output.script_pubkey.clone(),
                amount: output.amount,
                identity: OutputIdentity::Payment(output.script_pubkey.clone()),
            })
            .collect()),
        _ => Ok(Vec::new()),
    }
}
/// Apply the same CTV commitment check before signing and during observation.
pub(super) fn validate_ctv_commitment(
    next: &NextOutputs,
    tx: &Transaction,
    input_index: usize,
) -> Result<(), ManagerError> {
    let expected = match next {
        NextOutputs::Template(template) => template.ctv_hash(),
        NextOutputs::TemplateHash(hash) => *hash,
        _ => return Ok(()),
    };
    if crate::ctv::compute_ctv_hash_for_tx(tx, input_index as u32) != expected {
        return Err(ManagerError::CtvTemplateMismatch { input_index });
    }
    Ok(())
}

/// Validate a clause's witness against every declared argument specification,
/// including exact consumption. Empty signature slots are accepted only while
/// constructing a witness before registered signers have filled them.
pub(super) fn validate_clause_witness(
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

/// Borrowed accounting data, independent of handles, lifecycle state, and RPC.
/// Signers and observers both validate this same representation.
pub(super) struct InputConstraints<'a> {
    pub(super) vin: usize,
    pub(super) value: Amount,
    pub(super) outputs: &'a [ResolvedOutput],
    pub(super) join: Option<u32>,
}

/// Cross-input accounting, after every input's scripts and local constraints
/// have been checked. Ignore mode does not participate in BIP-443 accounting.
pub(super) fn validate_batch_constraints(
    inputs: &[InputConstraints<'_>],
    tx: &Transaction,
) -> Result<(), ManagerError> {
    let mut identities: BTreeMap<u32, OutputIdentity> = BTreeMap::new();
    let mut minimum: BTreeMap<u32, Amount> = BTreeMap::new();
    let mut deducted = std::collections::BTreeSet::new();
    for input in inputs {
        let mut residual = input.value;
        for output in input.outputs {
            let index = output.index.resolve(input.vin);
            if identities
                .get(&index)
                .is_some_and(|previous| previous != &output.identity)
            {
                return Err(ManagerError::ConflictingOutputContract { index });
            }
            identities
                .entry(index)
                .or_insert_with(|| output.identity.clone());
            match output.amount {
                ClauseOutputAmountBehaviour::PreserveOutput => {
                    if deducted.contains(&index) {
                        return Err(ManagerError::MixedOutputSemantics { index });
                    }
                    let total = minimum.entry(index).or_insert(Amount::ZERO);
                    *total = total
                        .checked_add(residual)
                        .ok_or(ManagerError::AmountOverflow)?;
                    residual = Amount::ZERO;
                }
                ClauseOutputAmountBehaviour::DeductOutput => {
                    if minimum.contains_key(&index) || !deducted.insert(index) {
                        return Err(ManagerError::MixedOutputSemantics { index });
                    }
                    residual = residual
                        .checked_sub(tx.output[index as usize].value)
                        .ok_or(ManagerError::DeductExceedsInput)?;
                }
                ClauseOutputAmountBehaviour::IgnoreOutput => {}
            }
        }
    }
    for input in inputs {
        if let Some(index) = input.join {
            if !matches!(identities.get(&index), Some(OutputIdentity::Contract(_))) {
                return Err(ManagerError::JoinWithoutTarget { index });
            }
            let total = minimum
                .get_mut(&index)
                .ok_or(ManagerError::MixedOutputSemantics { index })?;
            *total = total
                .checked_add(input.value)
                .ok_or(ManagerError::AmountOverflow)?;
        }
    }
    for (index, required) in minimum {
        let actual = tx.output[index as usize].value;
        if actual < required {
            return Err(ManagerError::InsufficientOutputAmount {
                index,
                required,
                actual,
            });
        }
    }
    Ok(())
}

/// Check scripts and per-input CCV amounts for resolved outputs. Cross-input
/// preserve contributions may make the actual output larger, so preserve checks
/// a lower bound; deduct uses the actual output amount. This is not a
/// transaction-wide accounting check across other inputs.
pub(super) fn validate_output_constraints(
    input_value: Amount,
    outputs: &[ResolvedOutput],
    spending_tx: &Transaction,
    vin: usize,
) -> Result<(), ManagerError> {
    let mut remaining = input_value;
    let mut preserve_used = false;
    let mut seen: BTreeMap<u32, ClauseOutputAmountBehaviour> = BTreeMap::new();
    for output in outputs {
        let index = output.index.resolve(vin);
        let payment = matches!(output.identity, OutputIdentity::Payment(_));
        let outpoint = OutPoint {
            txid: spending_tx.compute_txid(),
            vout: index,
        };
        let actual = spending_tx.output.get(index as usize).ok_or_else(|| {
            if payment {
                ManagerError::PaymentOutputMismatch { index }
            } else {
                ManagerError::MissingContractOutput(outpoint)
            }
        })?;
        if actual.script_pubkey != output.script_pubkey {
            return Err(if payment {
                ManagerError::PaymentOutputMismatch { index }
            } else {
                ManagerError::WrongContractOutput(outpoint)
            });
        }
        match output.amount {
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
pub(super) struct ParsedScriptPathWitness {
    pub(super) args: Vec<Vec<u8>>,
    pub(super) leaf_script: Vec<u8>,
    pub(super) control_block: Vec<u8>,
}

pub(super) fn parse_script_path_witness(
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
