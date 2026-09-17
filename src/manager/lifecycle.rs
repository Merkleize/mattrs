//! Instance registration and child linking. No RPC and no signer calls.
use super::observation::ObservedInput;
use super::validation::ContractOutputIdentity;
use super::{Children, ContractManager, InstanceHandle, ManagerError};
use crate::contracts::{ClauseOutput, ContractInstance, NextOutputs};
use bitcoin::{OutPoint, Transaction};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

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
            .find(|inst| inst.borrow().outpoint() == Some(outpoint))
            .cloned()
    }

    /// Materialize (and register) the child instances a spent parent's clause
    /// outputs define, linking them to the parent. `vin` is the parent's input
    /// index within `spending_tx` (which resolves [`OutputIndex::Same`](crate::contracts::OutputIndex::Same)). A child
    /// already materialized at the same outpoint — e.g. a batch output merged
    /// across inputs — is reused, not duplicated.
    pub(super) fn materialize_outputs(
        &mut self,
        parent: &Rc<RefCell<ContractInstance>>,
        outputs: &[ClauseOutput],
        spending_tx: &Transaction,
        vin: usize,
    ) -> Result<Vec<Rc<RefCell<ContractInstance>>>, ManagerError> {
        let txid = spending_tx.compute_txid();
        let mut resolved = Vec::with_capacity(outputs.len());
        let mut identities = BTreeMap::new();

        for clause_out in outputs {
            let vout = clause_out.index.resolve(vin);
            let outpoint = OutPoint { txid, vout };
            let identity = ContractOutputIdentity::from_clause_output(clause_out);
            if identities
                .get(&vout)
                .is_some_and(|previous| previous != &identity)
            {
                return Err(ManagerError::ConflictingOutputContract { index: vout });
            }
            identities.entry(vout).or_insert(identity);
            let actual = spending_tx
                .output
                .get(vout as usize)
                .ok_or(ManagerError::MissingContractOutput(outpoint))?;
            let expected_script = clause_out
                .next_contract
                .script_pubkey(clause_out.state_commitment().as_ref())?;
            if actual.script_pubkey != expected_script {
                return Err(ManagerError::WrongContractOutput(outpoint));
            }

            if let Some(existing) = self.find_instance_by_outpoint(outpoint) {
                let existing = existing.borrow();
                if ContractOutputIdentity::from_instance(&existing)
                    != ContractOutputIdentity::from_clause_output(clause_out)
                    || existing.script_pubkey()? != actual.script_pubkey
                {
                    return Err(ManagerError::ConflictingOutputContract { index: vout });
                }
            }
            resolved.push((clause_out, outpoint));
        }

        let mut children = Vec::with_capacity(resolved.len());
        for (clause_out, outpoint) in resolved {
            let child = match self.find_instance_by_outpoint(outpoint) {
                Some(existing) => existing,
                None => {
                    // The child contract is self-describing, so its params come
                    // from it; it also carries the logical state for its own
                    // future spends.
                    let instance = Rc::new(RefCell::new(ContractInstance::new(
                        clause_out.next_contract.clone(),
                        clause_out.next_state.clone(),
                    )?));
                    instance
                        .borrow_mut()
                        .mark_funded(outpoint, spending_tx.clone());
                    self.instances.push(instance.clone());
                    instance
                }
            };

            parent.borrow_mut().add_output(child.clone());
            children.push(child);
        }

        Ok(children)
    }
}

/// Validated lifecycle changes, held privately until broadcast succeeds.
/// Dropping a staged batch has no effect; committing consumes it and cannot fail.
pub(super) struct StagedBatch {
    spending_tx: Transaction,
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
        let mut children: BTreeMap<u32, Rc<RefCell<ContractInstance>>> = BTreeMap::new();
        let mut new_children = Vec::new();
        for input in &observed {
            if let NextOutputs::Contracts(outputs) = &input.next {
                for output in outputs {
                    let vout = output.index.resolve(input.vin);
                    let outpoint = OutPoint { txid, vout };
                    // Check expanded state type even if this output already exists.
                    let mut candidate = ContractInstance::new(
                        output.next_contract.clone(),
                        output.next_state.clone(),
                    )?;
                    let cached = input
                        .handle
                        .outputs()
                        .into_iter()
                        .find(|child| child.outpoint() == Some(outpoint));
                    let existing = children
                        .get(&vout)
                        .cloned()
                        .or_else(|| self.find_instance_by_outpoint(outpoint))
                        .or_else(|| cached.map(|child| child.instance));
                    let child = if let Some(existing) = existing {
                        if ContractOutputIdentity::from_instance(&existing.borrow())
                            != ContractOutputIdentity::from_clause_output(output)
                            || existing.borrow().script_pubkey()?
                                != spending_tx.output[vout as usize].script_pubkey
                        {
                            return Err(ManagerError::ConflictingOutputContract { index: vout });
                        }
                        existing
                    } else {
                        candidate.mark_funded(outpoint, spending_tx.clone());
                        let child = Rc::new(RefCell::new(candidate));
                        new_children.push(child.clone());
                        child
                    };
                    children.insert(vout, child);
                }
            }
        }

        Ok(StagedBatch {
            spending_tx: spending_tx.clone(),
            observed,
            children,
            new_children,
        })
    }
}

impl StagedBatch {
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
            let indices: Vec<_> = match &input.next {
                NextOutputs::Contracts(outputs) => {
                    outputs.iter().map(|o| o.index.resolve(input.vin)).collect()
                }
                NextOutputs::Join { index } => vec![*index],
                _ => Vec::new(),
            };
            let mut parent = input.handle.instance.borrow_mut();
            for index in indices {
                parent.add_output(
                    children
                        .get(&index)
                        .expect("validated child target")
                        .clone(),
                );
            }
            if !input.already_spent {
                parent.mark_spent(
                    spending_tx.clone(),
                    input.vin,
                    input.clause_name.clone(),
                    input.witness_args.clone(),
                );
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
