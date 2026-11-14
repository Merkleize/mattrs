//! RPC-free signing: all prevouts must be resolved before invoking signers.
use super::validation::validate_clause_witness;
use super::{ManagerError, SpendBuilder, transaction::PreparedBatch};
use bitcoin::{Transaction, TxOut};

/// Signers by the x-only key they sign for.
pub(super) type Signers =
    std::collections::HashMap<bitcoin::XOnlyPublicKey, std::rc::Rc<dyn crate::signer::Signer>>;

/// `standing` are the manager's own signers, used for any key a builder
/// registered no signer for.
pub(super) fn sign_prepared(
    builders: &[SpendBuilder],
    prepared: PreparedBatch,
    standing: &Signers,
) -> Result<Transaction, ManagerError> {
    let PreparedBatch {
        mut tx, prevouts, ..
    } = prepared;
    // Fill + finalize each input's witness (every sighash sees all prevouts).
    for (input_index, builder) in builders.iter().enumerate() {
        tx.input[input_index].witness =
            input_witness(builder, &tx, input_index, &prevouts, standing)?;
    }

    Ok(tx)
}
/// Build the full script-path witness for one input: the clause arguments with
/// signature elements filled (by matching each `SignerType` pubkey to a
/// signer registered on the builder, else to one of the `standing` signers),
/// followed by the leaf script and its control block.
pub(super) fn input_witness(
    builder: &SpendBuilder,
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    standing: &Signers,
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

            if let Some(xonly) = spec.arg_type.signer_pubkey() {
                // A signer given for this spend wins over a standing one.
                let signer: Option<&dyn crate::signer::Signer> = match signers.get(&xonly) {
                    Some(signer) => Some(signer.as_ref()),
                    None => standing.get(&xonly).map(|signer| signer.as_ref()),
                };
                if let Some(signer) = signer {
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
        .control_block_internal_key(&inst.state_commitment())?;
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
