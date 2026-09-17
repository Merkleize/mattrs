//! Stable public handles and typed child access; no RPC or transaction planning.
use super::{ManagerError, SpendBuilder, WrongContractType};
use crate::contracts::{ContractInstance, ContractState, InstanceStatus};
use bitcoin::{OutPoint, Sequence, Transaction, TxOut, Txid};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
};

/// A handle to a contract instance.
///
/// Cheap to clone (it is an `Rc` inside). Unlike the old design it does not borrow
/// the manager, so callers can hold handles across spends and chain naturally. The
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
    /// Wrap a raw instance pointer.
    pub(crate) fn new(instance: Rc<RefCell<ContractInstance>>) -> Self {
        Self { instance }
    }

    /// Get the instance status.
    pub fn status(&self) -> InstanceStatus {
        self.instance.borrow().status()
    }

    /// Get the outpoint (if funded).
    pub fn outpoint(&self) -> Option<OutPoint> {
        self.instance.borrow().outpoint()
    }

    /// The UTXO this instance controls (its funding output), once funded.
    pub fn prevout(&self) -> Option<TxOut> {
        self.instance.borrow().prevout()
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

    /// The contract's encoded parameters (contracts are self-describing).
    /// Decode them with the contract's typed params struct
    /// ([`ContractParams::decode`](crate::contracts::ContractParams::decode));
    /// the `contract!`-generated handles expose this as a typed `params()`.
    pub fn params_bytes(&self) -> Vec<u8> {
        self.instance.borrow().contract().params_bytes().to_vec()
    }

    /// The instance's typed params `P`: read back by downcast when the contract
    /// carries them (every contract built from a typed `P` does — see
    /// [`ErasedContract::params_any`](crate::contracts::ErasedContract::params_any)),
    /// else decoded from the encoded bytes. `None` only if `P` is the wrong
    /// type *and* the bytes don't decode as a `P`.
    pub fn params<P: crate::contracts::ContractParams + 'static>(&self) -> Option<P> {
        let inst = self.instance.borrow();
        if let Some(typed) = inst
            .contract()
            .params_any()
            .and_then(|any| any.downcast_ref::<P>())
        {
            return Some(typed.clone());
        }
        P::decode(inst.contract().params_bytes()).ok()
    }

    /// The name of the clause that spent this instance (None until spent).
    pub fn clause_name(&self) -> Option<String> {
        self.instance.borrow().clause_name().map(str::to_string)
    }

    /// The transaction that funded this instance (None until funded).
    pub fn funding_tx(&self) -> Option<Transaction> {
        self.instance.borrow().funding_tx().cloned()
    }

    /// The transaction that spent this instance (None until spent).
    pub fn spending_tx(&self) -> Option<Transaction> {
        self.instance.borrow().spending_tx().cloned()
    }

    /// Transaction ID that spent this instance (None until spent).
    pub fn spent_in_tx(&self) -> Option<Txid> {
        self.instance.borrow().spent_in_tx()
    }

    /// The input index of the spending transaction that consumed this instance
    /// (None until spent).
    pub fn spending_vin(&self) -> Option<usize> {
        self.instance.borrow().spending_vin()
    }

    /// The witness arguments of the spend, in witness order (None until spent).
    /// Decode them with the clause's typed `*Args` struct
    /// ([`ClauseArgs::decode_from_witness`](crate::contracts::ClauseArgs::decode_from_witness)).
    pub fn spending_args(&self) -> Option<Vec<Vec<u8>>> {
        self.instance
            .borrow()
            .spending_args()
            .map(|args| args.to_vec())
    }

    /// This instance's expanded logical state as `S`, if its type matches.
    /// Commitments are never decoded or reinterpreted as another state type.
    pub fn state<S: ContractState + 'static>(&self) -> Option<S> {
        let inst = self.instance.borrow();
        let erased = inst.state()?;
        erased.as_any().downcast_ref::<S>().cloned()
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
/// positional access; [`typed`](Children::typed) / [`one`](Children::one)
/// convert children into their `contract!`-generated typed handles.
#[derive(Debug, Clone)]
pub struct Children(Vec<InstanceHandle>);

impl Children {
    pub(crate) fn new(handles: Vec<InstanceHandle>) -> Self {
        Children(handles)
    }

    /// The child at `index`, as the typed handle `H`.
    pub fn typed<H>(&self, index: usize) -> Result<H, ManagerError>
    where
        H: TryFrom<InstanceHandle, Error = WrongContractType>,
    {
        let handle = self
            .0
            .get(index)
            .cloned()
            .ok_or(ManagerError::UnexpectedOutputCount {
                expected: index + 1,
                got: self.0.len(),
            })?;
        Ok(H::try_from(handle)?)
    }

    /// The single child, typed; errors unless exactly one child was produced.
    pub fn one<H>(self) -> Result<H, ManagerError>
    where
        H: TryFrom<InstanceHandle, Error = WrongContractType>,
    {
        if self.0.len() != 1 {
            return Err(ManagerError::UnexpectedOutputCount {
                expected: 1,
                got: self.0.len(),
            });
        }
        self.typed(0)
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
