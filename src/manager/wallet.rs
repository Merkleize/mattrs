//! External-wallet funding without weakening contract accounting.

use super::validation::{
    InputConstraints, resolve_outputs, validate_batch_constraints, validate_ctv_commitment,
    validate_output_constraints,
};
use super::{Children, ContractManager, InstanceHandle, ManagerError, SpendBuilder};
use super::{
    signing::input_witness,
    transaction::{PreparedBatch, prepare},
};
use crate::contracts::{InstanceStatus, NextOutputs};
use bitcoin::hashes::{Hash, hash160};
use bitcoin::{Amount, OutPoint, Transaction, TxIn, TxOut, XOnlyPublicKey};
use std::collections::BTreeMap;

/// Prevout context for a non-contract input, to be authenticated by the caller.
///
/// Obtain this from a trusted node, wallet, or verified funding transaction.
/// The manager cannot authenticate a bare `TxOut`. Supported spends are native
/// P2WPKH and Taproot key-path only: external tapscripts could themselves run CCV.
#[derive(Clone, Debug)]
pub struct ExternalInput {
    pub outpoint: OutPoint,
    pub prevout: TxOut,
}

impl ExternalInput {
    /// Bind an output to the supplied transaction's txid. The caller still
    /// establishes whether that transaction is genuine and spendable.
    pub fn from_transaction(tx: &Transaction, vout: u32) -> Result<Self, ManagerError> {
        let prevout = tx.output.get(vout as usize).cloned().ok_or_else(|| {
            ManagerError::InvalidInputContext(
                "external prevout index is outside the funding transaction".into(),
            )
        })?;
        Ok(Self {
            outpoint: OutPoint {
                txid: tx.compute_txid(),
                vout,
            },
            prevout,
        })
    }
}

/// Atomically observed contract children and the whole transaction's absolute fee.
#[derive(Debug)]
pub struct BatchObservation {
    pub children: Children,
    pub fee: Amount,
}

/// Unsigned contract transaction ready for an external wallet to fund.
///
/// The wallet may append inputs and outputs, but must preserve the original
/// input positions, sequences, outputs, version, and locktime. CTV commitments
/// are rechecked after funding and may disallow these additions altogether.
/// Signatures use the existing default sighash, committing to every prevout.
pub struct WalletSpend {
    builders: Vec<SpendBuilder>,
    prepared: PreparedBatch,
    input_weights: Vec<u64>,
}

impl WalletSpend {
    pub fn transaction(&self) -> &Transaction {
        &self.prepared.tx
    }

    /// Maximum signed weights of the original inputs, in transaction order.
    /// Includes each input's base serialization and full witness (64-byte
    /// default-sighash signatures). Suitable for Core's `input_weights` option;
    /// the wallet must also account for transaction overhead and its own inputs.
    pub fn input_weights(&self) -> &[u64] {
        &self.input_weights
    }

    /// Validate wallet funding and its absolute fee, then sign contract inputs.
    /// Does not broadcast or change instance state. No signer is invoked until
    /// transaction/context checks and signer availability checks have passed.
    ///
    /// `external` must cover every added input exactly once, using trusted
    /// prevouts. Unsigned external witnesses are allowed at this stage. The
    /// wallet must subsequently sign without changing the transaction body;
    /// call [`SignedWalletSpend::validate_final`] before submitting it.
    pub fn sign_funded(
        &self,
        manager: &ContractManager,
        mut funded: Transaction,
        external: Vec<ExternalInput>,
        maximum_fee: Amount,
    ) -> Result<SignedWalletSpend, ManagerError> {
        let original = &self.prepared.tx;
        if funded.version != original.version
            || funded.lock_time != original.lock_time
            || !funded.input.starts_with(&original.input)
            || !funded.output.starts_with(&original.output)
        {
            return Err(invalid(
                "preserve the transaction header, original inputs (unsigned), and original outputs; append funding inputs and change only",
            ));
        }
        let handles: Vec<_> = self
            .builders
            .iter()
            .map(|b| InstanceHandle {
                instance: b.instance.clone(),
            })
            .collect();
        let refs: Vec<_> = handles.iter().collect();
        let (prevouts, fee) = external_contexts(manager, &refs, &external, &funded, false)?;
        if fee > maximum_fee {
            return Err(ManagerError::FeeTooHigh {
                fee,
                maximum: maximum_fee,
            });
        }

        let resolved: Vec<_> = self
            .prepared
            .nexts
            .iter()
            .map(resolve_outputs)
            .collect::<Result<_, _>>()?;
        let mut constraints = Vec::with_capacity(handles.len());
        for (vin, (builder, handle)) in self.builders.iter().zip(&handles).enumerate() {
            if handle.status() != InstanceStatus::Funded
                || prevouts[vin] != self.prepared.prevouts[vin]
            {
                return Err(invalid(
                    "a prepared contract input is no longer funded as expected",
                ));
            }
            let next = &self.prepared.nexts[vin];
            let outputs = &resolved[vin];
            validate_output_constraints(prevouts[vin].value, outputs, &funded, vin)?;
            validate_ctv_commitment(next, &funded, vin)?;
            constraints.push(InputConstraints {
                vin,
                value: prevouts[vin].value,
                outputs,
                join: match next {
                    NextOutputs::Join { index } => Some(*index),
                    _ => None,
                },
            });
            let inst = builder.instance.borrow();
            let clause = inst
                .contract()
                .get_clause(builder.clause_name)
                .ok_or_else(|| ManagerError::ClauseNotFound(builder.clause_name.into()))?;
            for spec in clause.arg_specs() {
                if let Some(key) = spec.arg_type.signer_pubkey() {
                    let key =
                        XOnlyPublicKey::from_slice(&key).map_err(|e| invalid(&e.to_string()))?;
                    if !builder.signers.contains_key(&key) {
                        return Err(ManagerError::MissingSigner(key));
                    }
                }
            }
        }
        // Only the contract inputs contribute to these CCV checks.
        validate_batch_constraints(&constraints, &funded)?;
        for (vin, builder) in self.builders.iter().enumerate() {
            let witness = input_witness(builder, &funded, vin, &prevouts)?;
            // The signer receives a default sighash. Do not accept a different
            // sighash suffix or silently exceed the weight advertised to wallets.
            if 164 + witness.size() as u64 != self.input_weights[vin] {
                return Err(invalid(
                    "contract signers must return 64-byte default-sighash signatures",
                ));
            }
            funded.input[vin].witness = witness;
        }
        Ok(SignedWalletSpend {
            tx: funded,
            handles,
            external,
            fee,
        })
    }
}

/// Contract-signed transaction awaiting external wallet signatures.
/// This object retains the authorized transaction for finalization checks.
pub struct SignedWalletSpend {
    tx: Transaction,
    handles: Vec<InstanceHandle>,
    external: Vec<ExternalInput>,
    fee: Amount,
}

impl SignedWalletSpend {
    pub fn transaction(&self) -> &Transaction {
        &self.tx
    }
    pub fn fee(&self) -> Amount {
        self.fee
    }

    /// Require the exact authorized body and contract witnesses; only external
    /// witnesses may change. Check supported wallet witness shapes, not script
    /// execution or signature validity. A node must validate before acceptance.
    pub fn validate_final(&self, final_tx: &Transaction) -> Result<(), ManagerError> {
        let without_witness = |tx: &Transaction| {
            let mut tx = tx.clone();
            for input in &mut tx.input {
                input.witness = bitcoin::Witness::new();
            }
            tx
        };
        if without_witness(final_tx) != without_witness(&self.tx) {
            return Err(invalid(
                "wallet changed the transaction body after contract signing",
            ));
        }
        for vin in 0..self.handles.len() {
            if final_tx.input[vin].witness != self.tx.input[vin].witness {
                return Err(invalid("wallet changed a contract witness"));
            }
        }
        for external in &self.external {
            let input = final_tx
                .input
                .iter()
                .find(|i| i.previous_output == external.outpoint)
                .ok_or_else(|| invalid("missing external input"))?;
            check_external_input(external, input, true)?;
        }
        Ok(())
    }

    /// Validate finalization, then atomically record the final transaction.
    /// Call after node acceptance or apply your own chain-observation policy.
    /// This method does not broadcast or establish consensus validity.
    pub fn observe_final(
        &self,
        manager: &mut ContractManager,
        final_tx: &Transaction,
    ) -> Result<BatchObservation, ManagerError> {
        self.validate_final(final_tx)?;
        manager.observe_batch_with_external_inputs(
            &self.handles.iter().collect::<Vec<_>>(),
            &self.external,
            final_tx,
        )
    }
}

impl ContractManager {
    /// Prepare a wallet-fundable transaction without invoking signers. Signature
    /// arguments must be empty; register signers on the builders before passing
    /// them here. Prefilled signatures would be invalidated by wallet funding.
    pub fn prepare_wallet_spend(
        &self,
        builders: Vec<SpendBuilder>,
    ) -> Result<WalletSpend, ManagerError> {
        let prepared = prepare(&builders)?;
        let mut input_weights = Vec::with_capacity(builders.len());
        for builder in &builders {
            let inst = builder.instance.borrow();
            let clause = inst
                .contract()
                .get_clause(builder.clause_name)
                .ok_or_else(|| ManagerError::ClauseNotFound(builder.clause_name.into()))?;
            let mut stack = builder.witness_args.clone();
            let mut offset = 0;
            for spec in clause.arg_specs() {
                let consumed = spec
                    .arg_type
                    .consume(&stack[offset..])
                    .map_err(|e| invalid(&e.to_string()))?;
                if spec.arg_type.signer_pubkey().is_some() {
                    if !stack[offset].is_empty() {
                        return Err(invalid(
                            "leave signature arguments empty until after wallet funding",
                        ));
                    }
                    stack[offset] = vec![0; 64];
                }
                offset += consumed;
            }
            let key = inst
                .contract()
                .control_block_internal_key(inst.state_commitment().as_ref())?;
            let control = inst
                .contract()
                .taptree()
                .control_block(&key, builder.clause_name)
                .ok_or_else(|| invalid("cannot derive contract control block"))?;
            stack.push(clause.script().to_bytes());
            stack.push(control);
            input_weights.push(164 + bitcoin::Witness::from_slice(&stack).size() as u64);
        }
        Ok(WalletSpend {
            builders,
            prepared,
            input_weights,
        })
    }

    /// Strict, atomic observation with explicit context for native wallet inputs.
    /// Context order is irrelevant: outpoints determine real transaction indices.
    /// Every input needs exactly one context. Wallet inputs are excluded from CCV
    /// contribution accounting; all prevouts count toward the reported fee.
    /// Unknown inputs, external tapscripts, and managed inputs mislabeled as
    /// external are rejected before any state change.
    ///
    /// Prevouts must be authenticated by the caller. This checks the declared
    /// contract model and wallet witness shape, not signatures or consensus.
    pub fn observe_batch_with_external_inputs(
        &mut self,
        handles: &[&InstanceHandle],
        external: &[ExternalInput],
        spending_tx: &Transaction,
    ) -> Result<BatchObservation, ManagerError> {
        let (_, fee) = external_contexts(self, handles, external, spending_tx, true)?;
        let children = self.observe_batch_inner(handles, external, spending_tx)?;
        Ok(BatchObservation { children, fee })
    }

    /// Discover the first handle's spend, resolve unmatched prevouts with the
    /// caller's trusted node/wallet/cache, then perform strict mixed observation.
    /// The resolver must support already-spent prevouts (e.g. funding transactions,
    /// not just `gettxout`). Resolution errors leave every instance untouched.
    pub fn wait_for_batch_with_external_inputs(
        &mut self,
        handles: &[&InstanceHandle],
        mut resolve_prevout: impl FnMut(OutPoint) -> Result<TxOut, ManagerError>,
    ) -> Result<BatchObservation, ManagerError> {
        let tx = self.wait_for_batch_tx(handles)?;
        let mut external = Vec::new();
        for input in &tx.input {
            if !handles
                .iter()
                .any(|h| h.outpoint() == Some(input.previous_output))
            {
                external.push(ExternalInput {
                    outpoint: input.previous_output,
                    prevout: resolve_prevout(input.previous_output)?,
                });
            }
        }
        self.observe_batch_with_external_inputs(handles, &external, &tx)
    }
}

fn invalid(message: &str) -> ManagerError {
    ManagerError::InvalidWalletFunding(message.to_owned())
}

fn external_contexts(
    manager: &ContractManager,
    handles: &[&InstanceHandle],
    external: &[ExternalInput],
    tx: &Transaction,
    finalized: bool,
) -> Result<(Vec<TxOut>, Amount), ManagerError> {
    let invalid = |message: &str| ManagerError::InvalidInputContext(message.to_owned());
    if handles.is_empty() {
        return Err(invalid("at least one contract input is required"));
    }
    if tx.output.is_empty() {
        return Err(ManagerError::NoOutputs);
    }
    let mut inputs = BTreeMap::new();
    for input in &tx.input {
        if inputs.insert(input.previous_output, input).is_some() {
            return Err(invalid("duplicate transaction input"));
        }
    }
    let mut contexts = BTreeMap::new();
    for handle in handles {
        let outpoint = handle.outpoint().ok_or(ManagerError::NotFunded)?;
        if !inputs.contains_key(&outpoint)
            || contexts
                .insert(outpoint, handle.prevout().ok_or(ManagerError::NotFunded)?)
                .is_some()
        {
            return Err(invalid("duplicate or unrelated contract input context"));
        }
    }
    for ext in external {
        let input = inputs
            .get(&ext.outpoint)
            .ok_or_else(|| invalid("unrelated external input context"))?;
        if manager.find_instance_by_outpoint(ext.outpoint).is_some()
            || contexts.insert(ext.outpoint, ext.prevout.clone()).is_some()
        {
            return Err(invalid(
                "duplicate input context or managed contract labeled external",
            ));
        }
        check_external_input(ext, input, finalized)?;
    }
    let missing: Vec<_> = tx
        .input
        .iter()
        .filter(|i| !contexts.contains_key(&i.previous_output))
        .map(|i| i.previous_output)
        .collect();
    if !missing.is_empty() {
        return Err(ManagerError::IncompleteObservation { missing });
    }
    let prevouts: Vec<_> = tx
        .input
        .iter()
        .map(|i| contexts[&i.previous_output].clone())
        .collect();
    let add = |sum: u64, output: &TxOut| {
        sum.checked_add(output.value.to_sat())
            .ok_or(ManagerError::AmountOverflow)
    };
    let input_value = prevouts.iter().try_fold(0, add)?;
    let output_value = tx.output.iter().try_fold(0, add)?;
    let fee = input_value
        .checked_sub(output_value)
        .ok_or(ManagerError::OutputsExceedInputs)?;
    Ok((prevouts, Amount::from_sat(fee)))
}

fn check_external_input(
    ext: &ExternalInput,
    input: &TxIn,
    finalized: bool,
) -> Result<(), ManagerError> {
    let unsupported = || ManagerError::UnsupportedExternalInput {
        outpoint: ext.outpoint,
    };
    let script = &ext.prevout.script_pubkey;
    if !input.script_sig.is_empty() || !(script.is_p2wpkh() || script.is_p2tr()) {
        return Err(unsupported());
    }
    if !finalized && input.witness.is_empty() {
        return Ok(());
    }
    let mut stack: Vec<_> = input.witness.iter().collect();
    if script.is_p2tr() {
        // BIP341 removes a final annex before distinguishing key and script paths.
        if stack.len() >= 2 && stack.last().is_some_and(|item| item.first() == Some(&0x50)) {
            stack.pop();
        }
        if stack.len() != 1 || !matches!(stack[0].len(), 64 | 65) {
            return Err(unsupported());
        }
    } else if stack.len() != 2
        || !(9..=73).contains(&stack[0].len())
        || stack[1].len() != 33
        || bitcoin::secp256k1::PublicKey::from_slice(stack[1]).is_err()
        || hash160::Hash::hash(stack[1]).as_byte_array().as_slice() != &script.as_bytes()[2..]
    {
        return Err(unsupported());
    }
    Ok(())
}
