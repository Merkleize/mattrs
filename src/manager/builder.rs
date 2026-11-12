//! Fluent spend intent and execution entry points.
use super::{Children, ContractManager, InstanceHandle, ManagerError};
use crate::{contracts::ContractInstance, signer::Signer};
use bitcoin::{Amount, Sequence, Transaction, TxOut, XOnlyPublicKey};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
};

/// A fluent builder for spending a single contract instance through one clause.
///
/// Created by the `contract!`-generated per-clause methods (or
/// [`InstanceHandle::spend_clause`]). Register signers with [`SpendBuilder::sign`],
/// then finish with [`SpendBuilder::exec`] / [`exec_one`](SpendBuilder::exec_one) /
/// [`exec_none`](SpendBuilder::exec_none).
pub struct SpendBuilder {
    pub(super) instance: Rc<RefCell<ContractInstance>>,
    pub(super) clause_name: &'static str,
    pub(super) witness_args: Vec<Vec<u8>>,
    pub(super) signers: HashMap<XOnlyPublicKey, Box<dyn Signer>>,
    pub(super) explicit_outputs: Option<Vec<TxOut>>,
    pub(super) output_amounts: BTreeMap<u32, Amount>,
    pub(super) sequence: Option<Sequence>,
}

impl SpendBuilder {
    /// Whether this builder spends `handle`'s exact tracked instance.
    pub(crate) fn spends(&self, handle: &InstanceHandle) -> bool {
        Rc::ptr_eq(&self.instance, &handle.instance)
    }

    fn exec_with_child_count(
        self,
        manager: &mut ContractManager,
        expected: usize,
    ) -> Result<Children, ManagerError> {
        let builders = std::slice::from_ref(&self);
        let prepared = super::transaction::prepare(builders)?;
        let got = prepared.child_count();
        if got != expected {
            return Err(ManagerError::UnexpectedOutputCount { expected, got });
        }
        manager.execute_prepared(builders, prepared)
    }

    /// Register a signer (matched to the clause's signature args by public key).
    /// A `Box<dyn Signer>` works too, via the blanket [`Signer`] impl for boxes.
    pub fn sign(mut self, signer: impl Signer + 'static) -> Self {
        self.signers.insert(signer.public_key(), Box::new(signer));
        self
    }

    /// Supply outputs for a clause with no declared output constraints, one
    /// whose outputs are all plain payments
    /// ([`ClauseOutputTo::pay`](crate::contracts::ClauseOutputTo::pay)), or a
    /// [`NextOutputs::TemplateHash`](crate::contracts::NextOutputs::TemplateHash) commitment.
    /// Single-input spends only. Payment destinations and amount relationships
    /// are validated; amounts already supplied here cannot also be set with
    /// [`output_amount`](Self::output_amount).
    ///
    /// A hash commitment validates these outputs and the final sequence before
    /// signing. This cannot override tracked contract outputs or a
    /// full [`NextOutputs::Template`](crate::contracts::NextOutputs::Template).
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
        manager.build_batch_tx(std::slice::from_ref(self))
    }

    /// Build, sign, broadcast, and return handles to all child instances.
    pub fn exec(self, manager: &mut ContractManager) -> Result<Children, ManagerError> {
        manager.spend_batch(std::slice::from_ref(&self))
    }

    /// Like [`exec`](Self::exec) but asserts exactly one child instance is produced.
    pub fn exec_one(self, manager: &mut ContractManager) -> Result<InstanceHandle, ManagerError> {
        let mut outputs = self.exec_with_child_count(manager, 1)?.into_vec();
        if outputs.len() != 1 {
            return Err(ManagerError::UnexpectedOutputCount {
                expected: 1,
                got: outputs.len(),
            });
        }
        Ok(outputs.pop().expect("length checked"))
    }

    /// Like [`exec`](Self::exec) but asserts no tracked children are produced.
    /// Output constraints (including CTV commitments) are still checked.
    pub fn exec_none(self, manager: &mut ContractManager) -> Result<(), ManagerError> {
        let outputs = self.exec_with_child_count(manager, 0)?;
        if !outputs.is_empty() {
            return Err(ManagerError::UnexpectedOutputCount {
                expected: 0,
                got: outputs.len(),
            });
        }
        Ok(())
    }
}
