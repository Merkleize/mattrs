//! Stable public handles and typed child access; no RPC or transaction planning.
use super::{ManagerError, SpendBuilder};
use crate::contracts::{ContractInstance, ContractState, InstanceStatus, SpendRecord};
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxOut};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
    sync::Arc,
};

/// A handle to a contract instance.
///
/// Cheap to clone (it is an `Rc` inside). It does not borrow the manager, so
/// callers can hold handles across spends and chain naturally. The
/// `contract!` macro wraps this in a typed per-contract handle whose methods return
/// a [`SpendBuilder`]; drop down to [`InstanceHandle::spend_clause`] for advanced use.
#[derive(Clone)]
pub struct InstanceHandle {
    pub(super) instance: Rc<RefCell<ContractInstance>>,
}

impl std::fmt::Debug for InstanceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.instance.borrow().fmt(f)
    }
}

/// Handles compare by *instance identity* — two handles are equal when they
/// point to the same tracked instance, regardless of its contents.
impl PartialEq for InstanceHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.instance, &other.instance)
    }
}

impl Eq for InstanceHandle {}

impl InstanceHandle {
    /// Wrap a raw instance pointer (fake funding in the crate's unit tests).
    #[cfg(test)]
    pub(crate) fn new(instance: Rc<RefCell<ContractInstance>>) -> Self {
        Self { instance }
    }

    /// Get the instance status.
    pub fn status(&self) -> InstanceStatus {
        self.instance.borrow().status()
    }

    /// The outpoint identifying this instance on-chain.
    pub fn outpoint(&self) -> OutPoint {
        self.instance.borrow().outpoint()
    }

    /// The UTXO this instance controls (its funding output).
    pub fn prevout(&self) -> TxOut {
        self.instance.borrow().prevout().clone()
    }

    /// The amount this instance's UTXO holds.
    pub fn amount(&self) -> Amount {
        self.instance.borrow().amount()
    }

    /// The `TypeId` of the underlying contract (for typed-handle conversions).
    pub fn contract_type_id(&self) -> std::any::TypeId {
        self.instance.borrow().contract().contract_type_id()
    }

    /// The underlying contract's human-readable name (e.g. `"Vault"`), for
    /// introspection and display.
    pub fn contract_name(&self) -> &'static str {
        self.instance.borrow().contract().contract_name()
    }

    /// The instance's typed params `P`, when `P` is the type the contract was
    /// built from; `None` for any other type.
    pub fn params<P: crate::contracts::ContractParams + 'static>(&self) -> Option<P> {
        self.instance
            .borrow()
            .contract()
            .params_any()
            .downcast_ref::<P>()
            .cloned()
    }

    /// The transaction that funded this instance.
    pub fn funding_tx(&self) -> Arc<Transaction> {
        self.instance.borrow().funding_tx().clone()
    }

    /// How this instance was spent (`None` until spent): the transaction, the
    /// input that consumed it, the clause, and the clause's witness arguments.
    /// A typed handle's `spent()` decodes the same record into the clause's
    /// typed arguments.
    pub fn spend_record(&self) -> Option<SpendRecord> {
        self.instance.borrow().spend().cloned()
    }

    /// The transaction that spent this instance (None until spent).
    pub fn spending_tx(&self) -> Option<Arc<Transaction>> {
        self.instance
            .borrow()
            .spend()
            .map(|spend| spend.tx().clone())
    }

    /// The name of the clause that spent this instance (None until spent).
    pub fn clause_name(&self) -> Option<String> {
        self.instance
            .borrow()
            .spend()
            .map(|spend| spend.clause_name().to_string())
    }

    /// This instance's expanded logical state as `S`, if its type matches.
    /// Commitments are never decoded or reinterpreted as another state type.
    pub fn state<S: ContractState + 'static>(&self) -> Option<S> {
        let inst = self.instance.borrow();
        inst.state().as_any().downcast_ref::<S>().cloned()
    }

    /// Get the child instances created from spending this instance.
    pub fn outputs(&self) -> Children {
        Children::new(
            self.instance
                .borrow()
                .outputs()
                .iter()
                .cloned()
                .map(|instance| InstanceHandle { instance })
                .collect(),
        )
    }

    /// Begin a spend of `clause_name` with the given (already-encoded) witness
    /// arguments. The `contract!`-generated per-clause methods call this; most code
    /// should prefer those typed methods.
    ///
    /// If the clause declares a CSV timelock (the `contract!` DSL's `timelock`
    /// section), the builder's `nSequence` is seeded from it, so the script's
    /// `OP_CHECKSEQUENCEVERIFY` and the transaction cannot disagree; an
    /// explicit [`SpendBuilder::sequence`] still overrides.
    pub fn spend_clause(
        &self,
        clause_name: &'static str,
        witness_args: Vec<Vec<u8>>,
    ) -> SpendBuilder {
        let sequence = self
            .instance
            .borrow()
            .contract()
            .get_clause(clause_name)
            .and_then(|clause| clause.csv_blocks())
            .map(Sequence);
        SpendBuilder {
            instance: self.instance.clone(),
            clause_name,
            witness_args,
            signers: HashMap::new(),
            explicit_outputs: None,
            output_amounts: BTreeMap::new(),
            sequence,
        }
    }
}

/// The child instances a spend produced (or an observation materialized), in
/// merged-output order. Derefs to a slice of [`InstanceHandle`]s for
/// positional access; [`at`](Children::at) / [`one`](Children::one) convert
/// children into their `contract!`-generated typed handles (or hand back the
/// untyped [`InstanceHandle`], when that is the type asked for).
#[derive(Debug, Clone)]
pub struct Children(Vec<InstanceHandle>);

impl Children {
    pub(crate) fn new(handles: Vec<InstanceHandle>) -> Self {
        Children(handles)
    }

    /// The child created at transaction output `vout`, as the typed handle
    /// `H`. Children are looked up by the output they live at, never by their
    /// position in this list: outputs that are plain payments are not
    /// tracked, so positions and output indices differ.
    pub fn at<H>(&self, vout: u32) -> Result<H, ManagerError>
    where
        H: TryFrom<InstanceHandle>,
        ManagerError: From<H::Error>,
    {
        let handle = self
            .0
            .iter()
            .find(|child| child.outpoint().vout == vout)
            .cloned()
            .ok_or(ManagerError::NoChildAtOutput { index: vout })?;
        Ok(H::try_from(handle)?)
    }

    /// The single child, typed; errors unless exactly one child was produced.
    pub fn one<H>(self) -> Result<H, ManagerError>
    where
        H: TryFrom<InstanceHandle>,
        ManagerError: From<H::Error>,
    {
        match <[InstanceHandle; 1]>::try_from(self.0) {
            Ok([handle]) => Ok(H::try_from(handle)?),
            Err(all) => Err(ManagerError::UnexpectedOutputCount {
                expected: 1,
                got: all.len(),
            }),
        }
    }

    /// The untyped handles.
    pub fn into_vec(self) -> Vec<InstanceHandle> {
        self.0
    }
}

impl std::ops::Deref for Children {
    type Target = [InstanceHandle];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for Children {
    type Item = InstanceHandle;
    type IntoIter = std::vec::IntoIter<InstanceHandle>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Children {
    type Item = &'a InstanceHandle;
    type IntoIter = std::slice::Iter<'a, InstanceHandle>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
