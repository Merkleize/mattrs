//! Funding, mining, and spend discovery through the manager's chain backend.
use super::{Children, ContractManager, InstanceHandle, ManagerError};
use crate::chain::poll_until;
use crate::contracts::{ContractInstance, ContractState, ErasedContract, InstanceStatus};
use bitcoin::{Amount, OutPoint, Transaction};
use std::{cell::RefCell, rc::Rc, sync::Arc, time::Duration};

/// The default polling window of [`ContractManager::wait_for_spend`]; see
/// [`ContractManager::wait_for_spend_within`] to override it.
pub(super) const DEFAULT_POLL_WINDOW: Duration = Duration::from_secs(30);

impl ContractManager {
    /// Create and fund a new contract instance holding `state` (pass `()` for
    /// a stateless contract). Params are taken from the (self-describing)
    /// contract.
    pub fn fund_instance(
        &mut self,
        contract: std::sync::Arc<dyn ErasedContract>,
        state: impl ContractState + 'static,
        amount: Amount,
    ) -> Result<InstanceHandle, ManagerError> {
        // Reject a state of the wrong type before any money moves.
        crate::contracts::check_state_type(contract.as_ref(), &state)?;
        let script_pubkey = contract.script_pubkey(&state.commitment())?;

        let tx = self.chain()?.fund_output(&script_pubkey, amount)?;
        let txid = tx.compute_txid();

        // Find the output index
        let vout = tx
            .output
            .iter()
            .position(|output| output.script_pubkey == script_pubkey)
            .ok_or(ManagerError::OutputNotFound)?;

        let outpoint = OutPoint {
            txid,
            vout: vout as u32,
        };

        let instance = ContractInstance::funded(contract, Box::new(state), outpoint, Arc::new(tx))?;
        Ok(self.register_instance(Rc::new(RefCell::new(instance))))
    }

    /// Mine blocks (regtest and test chains).
    pub fn mine_blocks(&self, n: u64) -> Result<(), ManagerError> {
        let n = u32::try_from(n)
            .map_err(|_| ManagerError::Other(format!("cannot mine {n} blocks at once")))?;
        Ok(self.chain()?.mine_blocks(n)?)
    }

    /// Start tracking a contract instance funded externally (e.g. by a
    /// counterparty): fetch its funding transaction, verify that `outpoint` pays
    /// the contract's address for `state` (`()` for a stateless contract), and
    /// register the funded instance.
    ///
    /// This is the observer-side entry point of a multi-party protocol: the
    /// funder shares the outpoint, both sides construct the same contract, and
    /// the observer then follows it with [`wait_for_spend`](Self::wait_for_spend).
    pub fn track_instance(
        &mut self,
        contract: std::sync::Arc<dyn ErasedContract>,
        state: impl ContractState + 'static,
        outpoint: OutPoint,
    ) -> Result<InstanceHandle, ManagerError> {
        crate::contracts::check_state_type(contract.as_ref(), &state)?;
        let expected_spk = contract.script_pubkey(&state.commitment())?;
        let funding_tx = self
            .chain()?
            .transaction(outpoint.txid)?
            .ok_or(ManagerError::TransactionNotFound(outpoint.txid))?;
        let paid = funding_tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(ManagerError::OutputNotFound)?;
        if paid.script_pubkey != expected_spk {
            return Err(ManagerError::WrongFundingScript(outpoint));
        }

        let instance =
            ContractInstance::funded(contract, Box::new(state), outpoint, Arc::new(funding_tx))?;
        Ok(self.register_instance(Rc::new(RefCell::new(instance))))
    }
    /// Wait until `handle`'s instance is spent on-chain (watching the mempool and
    /// new blocks), then decode the spend and materialize the child instances via
    /// [`observe_spend`](Self::observe_spend).
    ///
    /// This is how a party follows a covenant driven by someone else: the
    /// returned children carry their contracts and logical state, ready for
    /// further spends or waits. The clause and its witness arguments are recorded
    /// on the instance ([`InstanceHandle::clause_name`] /
    /// [`InstanceHandle::spending_args`]).
    pub fn wait_for_spend(&mut self, handle: &InstanceHandle) -> Result<Children, ManagerError> {
        self.wait_for_spend_within(handle, Some(DEFAULT_POLL_WINDOW))
    }

    /// Wait for a transaction spending the first handle, then strictly observe
    /// it as one batch. All input contexts must be supplied; if the transaction
    /// spends only a subset of `handles` or has unknown co-inputs, return an
    /// error without observing any parent. Performs node reads but no broadcast.
    ///
    /// For inputs that may be spent in separate transactions, call
    /// [`wait_for_spend`](Self::wait_for_spend) on each.
    pub fn wait_for_batch(
        &mut self,
        handles: &[&InstanceHandle],
    ) -> Result<Children, ManagerError> {
        let tx = self.wait_for_batch_tx(handles)?;
        self.observe_batch(handles, &tx)
    }

    pub(super) fn wait_for_batch_tx(
        &self,
        handles: &[&InstanceHandle],
    ) -> Result<Transaction, ManagerError> {
        let first = handles.first().ok_or_else(|| {
            ManagerError::InvalidInstance("cannot wait for an empty batch".into())
        })?;
        match first.spending_tx() {
            Some(tx) => Ok(Transaction::clone(&tx)),
            None => self.wait_for_spending_tx(first.outpoint(), Some(DEFAULT_POLL_WINDOW)),
        }
    }

    /// [`wait_for_spend`](Self::wait_for_spend) with an explicit polling window:
    /// give up with [`ManagerError::SpendNotFound`] after `window`, or poll
    /// forever when `window` is `None` (e.g. waiting on a human counterparty).
    pub fn wait_for_spend_within(
        &mut self,
        handle: &InstanceHandle,
        window: Option<Duration>,
    ) -> Result<Children, ManagerError> {
        if handle.status() == InstanceStatus::Spent {
            return Ok(handle.outputs());
        }
        let spending_tx = self.wait_for_spending_tx(handle.outpoint(), window)?;
        self.observe_spend(handle, &spending_tx)
    }

    /// Poll (within `window`; `None` = forever) until the chain reports a
    /// transaction spending `outpoint` (mempool or block).
    pub(super) fn wait_for_spending_tx(
        &self,
        outpoint: OutPoint,
        window: Option<Duration>,
    ) -> Result<Transaction, ManagerError> {
        let chain = self.chain()?;
        poll_until(window, || chain.find_spending_tx(outpoint))?
            .ok_or(ManagerError::SpendNotFound(outpoint))
    }
}
