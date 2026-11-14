//! Instance registration and child linking. No RPC and no signer calls.
use super::observation::ObservedInput;
use super::validation::ContractOutputIdentity;
use super::{Children, ContractManager, InstanceHandle, ManagerError};
use crate::contracts::{ContractInstance, NextOutputs, SpendRecord, check_state_type};
use bitcoin::{OutPoint, Transaction};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc, sync::Arc};

impl ContractManager {
    /// Register a freshly funded instance with the manager (and the inspector,
    /// if enabled), handing out its handle.
    pub(super) fn register_instance(
        &mut self,
        instance: Rc<RefCell<ContractInstance>>,
    ) -> InstanceHandle {
        self.instances.push(instance.clone());

        #[cfg(feature = "inspector")]
        self.notify_inspector();

        InstanceHandle { instance }
    }
    /// A managed instance funded at `outpoint`, if any. Used to deduplicate
    /// children when several parents' clause outputs merge into one transaction
    /// output (each parent then links to the same child instance).
    pub(super) fn find_instance_by_outpoint(
        &self,
        outpoint: OutPoint,
    ) -> Option<Rc<RefCell<ContractInstance>>> {
        self.instances
            .iter()
            .find(|inst| inst.borrow().outpoint() == outpoint)
            .cloned()
    }
}

/// Validated lifecycle changes, held privately until broadcast succeeds.
/// Dropping a staged batch has no effect; committing consumes it and cannot fail.
pub(super) struct StagedBatch {
    spending_tx: Arc<Transaction>,
    observed: Vec<ObservedInput>,
    children: BTreeMap<u32, Rc<RefCell<ContractInstance>>>,
    new_children: Vec<Rc<RefCell<ContractInstance>>>,
}

impl ContractManager {
    pub(super) fn stage_batch_update(
        &self,
        observed: Vec<ObservedInput>,
        spending_tx: &Transaction,
    ) -> Result<StagedBatch, ManagerError> {
        // Stage every child before mutating the registry or linking any parent.
        let txid = spending_tx.compute_txid();
        // One shared copy for every parent's spend record and every child.
        let spending_tx = Arc::new(spending_tx.clone());
        let mut children: BTreeMap<u32, Rc<RefCell<ContractInstance>>> = BTreeMap::new();
        let mut new_children = Vec::new();
        for input in &observed {
            // A join adds to a child another input defines. Within a complete
            // batch that input stages it here; a join observed on its own links
            // to the child only if it is already registered.
            if let NextOutputs::Join { index } = &input.next
                && !children.contains_key(index)
                && let Some(child) = self.find_instance_by_outpoint(OutPoint { txid, vout: *index })
            {
                children.insert(*index, child);
            }
            if let NextOutputs::Outputs(outputs) = &input.next {
                for output in outputs {
                    // Plain payments are constrained, but never tracked.
                    let Some((contract, state)) = output.contract() else {
                        continue;
                    };
                    let vout = output.index.resolve(input.vin);
                    let outpoint = OutPoint { txid, vout };
                    // Check expanded state type even if this output already exists.
                    check_state_type(contract.as_ref(), state)?;
                    let cached = input
                        .handle
                        .outputs()
                        .into_iter()
                        .find(|child| child.outpoint() == outpoint);
                    let existing = children
                        .get(&vout)
                        .cloned()
                        .or_else(|| self.find_instance_by_outpoint(outpoint))
                        .or_else(|| cached.map(|child| child.instance));
                    let child = if let Some(existing) = existing {
                        let actual = spending_tx
                            .output
                            .get(vout as usize)
                            .ok_or(ManagerError::MissingContractOutput(outpoint))?;
                        let identity =
                            ContractOutputIdentity::from_clause_output(contract, output)?;
                        if ContractOutputIdentity::from_instance(&existing.borrow())? != identity
                            || identity.script_pubkey != actual.script_pubkey
                        {
                            return Err(ManagerError::ConflictingOutputContract { index: vout });
                        }
                        existing
                    } else {
                        let child = Rc::new(RefCell::new(ContractInstance::funded(
                            contract.clone(),
                            state.clone_boxed(),
                            outpoint,
                            spending_tx.clone(),
                        )?));
                        new_children.push(child.clone());
                        child
                    };
                    children.insert(vout, child);
                }
            }
        }

        Ok(StagedBatch {
            spending_tx,
            observed,
            children,
            new_children,
        })
    }
}

impl StagedBatch {
    /// Handles to the staged children, in output-index order: the same
    /// instances [`commit`](Self::commit) registers and returns.
    pub(super) fn children(&self) -> Vec<InstanceHandle> {
        self.children
            .values()
            .map(|instance| InstanceHandle {
                instance: instance.clone(),
            })
            .collect()
    }

    pub(super) fn commit(self, manager: &mut ContractManager) -> Children {
        let Self {
            spending_tx,
            observed,
            children,
            new_children,
        } = self;
        // Nothing below is fallible: all input metadata and children are staged.
        manager.instances.extend(new_children);
        for input in &observed {
            // Output-index order, so a parent lists its children the way the
            // spend's `Children` does.
            let indices: std::collections::BTreeSet<u32> = match &input.next {
                NextOutputs::Outputs(outputs) => outputs
                    .iter()
                    .filter(|o| o.contract().is_some())
                    .map(|o| o.index.resolve(input.vin))
                    .collect(),
                NextOutputs::Join { index } => [*index].into(),
                _ => Default::default(),
            };
            let mut parent = input.handle.instance.borrow_mut();
            for index in indices {
                // Absent only for a lone join whose target is not observed yet.
                if let Some(child) = children.get(&index) {
                    parent.add_output(child.clone());
                }
            }
            if !input.already_spent {
                parent.mark_spent(SpendRecord::new(
                    spending_tx.clone(),
                    input.vin,
                    input.clause_name.clone(),
                    input.witness_args.clone(),
                ));
            }
        }
        #[cfg(feature = "inspector")]
        manager.notify_inspector();
        Children::new(
            children
                .into_values()
                .map(|instance| InstanceHandle { instance })
                .collect(),
        )
    }
}
