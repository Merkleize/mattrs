//! Helpers for exercising contracts without a Bitcoin node — used by the
//! `tests/support` fixtures.
//!
//! [`local_manager`] is a manager on an in-memory chain: instances are funded,
//! spent and tracked through the same calls as against a node, only no script
//! is executed. [`apply_batch`] records a batch spend without broadcasting it.

use std::rc::Rc;

use bitcoin::Transaction;

use crate::manager::{Children, ContractManager, InstanceHandle, ManagerError, SpendBuilder};

#[cfg(test)]
pub(crate) use fake::fund_fake;

/// A manager on its own fresh in-memory [`LocalChain`](crate::chain::LocalChain)
/// (regtest addresses): `contract.fund(&mut manager, ..)`, `exec`, `track`
/// and `mine_blocks` all work on it with no node. It mines a block after
/// each transaction it sends ([`ContractManager::with_auto_mining`]), since
/// a funding or a spend is recorded only once confirmed and nobody else
/// mines here. To put several parties on one chain, share a `LocalChain`
/// between managers with [`ContractManager::on`] instead.
pub fn local_manager() -> ContractManager {
    ContractManager::on(
        Rc::new(crate::chain::LocalChain::new()),
        bitcoin::Network::Regtest,
    )
    .with_auto_mining()
}

/// Build the batch transaction for `builders` and decode it against each of
/// `parents` with [`ContractManager::observe_batch`], materializing the
/// (deduplicated) children — the offline counterpart of
/// [`ContractManager::spend_batch`]: no broadcast, no RPC. Children merged
/// across inputs (a shared preserve index) are returned once, and the
/// order of `parents` does not matter. Every input must have a parent context;
/// constraints are checked together before any parent is changed, and joins
/// are linked in the same call.
pub fn apply_batch(
    manager: &mut ContractManager,
    parents: &[&InstanceHandle],
    builders: &[SpendBuilder],
) -> Result<(Transaction, Children), ManagerError> {
    let tx = crate::manager::build_batch_tx(builders)?;
    let children = manager.observe_batch(parents, &tx)?;
    Ok((tx, children))
}

/// Funding without any chain, for the crate's own unit tests.
#[cfg(test)]
mod fake {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    use bitcoin::{Amount, OutPoint, Transaction, TxOut};

    use crate::contracts::{ContractInstance, ContractState, ErasedContract};
    use crate::manager::InstanceHandle;

    /// Fake a funded instance of `contract` carrying `state` (`()` for a stateless
    /// contract) and holding `amount`, at a distinct outpoint keyed by `seed`.
    ///
    /// The in-memory "funding transaction" pays the contract's own address (derived
    /// from its committed state), so a spend built against the returned handle is
    /// valid to inspect — it simply is never broadcast. `seed` distinguishes the
    /// outpoints when a caller fake-funds several instances.
    pub(crate) fn fund_fake(
        contract: Arc<dyn ErasedContract>,
        state: impl ContractState + 'static,
        amount: Amount,
        seed: u8,
    ) -> InstanceHandle {
        let script_pubkey = contract
            .script_pubkey(&state.commitment())
            .expect("contract script_pubkey");
        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(seed.into()),
            input: vec![],
            output: vec![TxOut {
                script_pubkey,
                value: amount,
            }],
        };
        let outpoint = OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let instance =
            ContractInstance::funded(contract, Box::new(state), outpoint, Arc::new(funding_tx))
                .expect("state matches contract");
        InstanceHandle::new(Rc::new(RefCell::new(instance)))
    }
}
