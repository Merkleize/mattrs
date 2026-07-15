//! Chain access for protocol runners.
//!
//! Everything a runner does against the chain goes through [`ChainView`], so
//! the same role logic runs identically against a real node ([`RpcChain`]) and
//! against the in-memory chain used by deterministic offline tests
//! ([`LocalChain`]).

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use bitcoin::{OutPoint, Transaction, Txid};
use bitcoincore_rpc::{Client, RpcApi};

use super::ProtocolError;
use crate::manager::{
    BlockCache, ManagerError, find_spending_tx_once, is_tx_not_found, spend_scan_start,
    tx_confirmation_height,
};

/// The chain operations a protocol runner performs. Methods take `&self`
/// (implementations use interior mutability) so one chain can be shared —
/// e.g. by two parties' runners interleaved in a test.
pub trait ChainView {
    /// Broadcast a transaction.
    fn broadcast(&self, tx: &Transaction) -> Result<(), ProtocolError>;

    /// A single, non-blocking look for a transaction spending `outpoint`
    /// (mempool or block), if one exists.
    fn find_spending_tx(&self, outpoint: OutPoint) -> Result<Option<Transaction>, ProtocolError>;

    /// The current tip height.
    fn height(&self) -> Result<u32, ProtocolError>;

    /// The height `txid` confirmed at (`None` while unconfirmed or unknown).
    fn confirmation_height(&self, txid: Txid) -> Result<Option<u32>, ProtocolError>;
}

/// A [`ChainView`] over a real Bitcoin node's RPC interface (the same watching
/// strategy as [`ContractManager::wait_for_spend`]: the mempool via
/// `gettxspendingprevout`, plus a per-outpoint block scan from the funding
/// transaction's height onward).
///
/// [`ContractManager::wait_for_spend`]: crate::manager::ContractManager::wait_for_spend
pub struct RpcChain {
    client: Client,
    scan: RefCell<ScanState>,
}

#[derive(Default)]
struct ScanState {
    /// Per-outpoint cursor of the next block height to scan for a spend.
    cursors: HashMap<OutPoint, u64>,
    /// Blocks fetched by one outpoint's scan and not yet passed by all the
    /// others, so concurrent tokens download each new block once.
    blocks: BlockCache,
}

impl RpcChain {
    /// Wrap an RPC client (e.g. from
    /// [`regtest_rpc_client`](crate::manager::regtest_rpc_client)).
    pub fn new(client: Client) -> Self {
        RpcChain {
            client,
            scan: RefCell::new(ScanState::default()),
        }
    }
}

impl ChainView for RpcChain {
    fn broadcast(&self, tx: &Transaction) -> Result<(), ProtocolError> {
        self.client
            .send_raw_transaction(tx)
            .map_err(ManagerError::from)?;
        Ok(())
    }

    fn find_spending_tx(&self, outpoint: OutPoint) -> Result<Option<Transaction>, ProtocolError> {
        let mut scan = self.scan.borrow_mut();
        let ScanState { cursors, blocks } = &mut *scan;
        let cursor = match cursors.entry(outpoint) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(spend_scan_start(&self.client, outpoint)?),
        };
        let found = find_spending_tx_once(&self.client, outpoint, cursor, blocks)?;
        // Once every cursor is past a height, nobody will read it again.
        if let Some(min) = cursors.values().copied().min() {
            blocks.retain_from(min);
        }
        Ok(found)
    }

    fn height(&self) -> Result<u32, ProtocolError> {
        let height = self.client.get_block_count().map_err(ManagerError::from)?;
        u32::try_from(height)
            .map_err(|_| ProtocolError::Other(format!("block height {height} exceeds u32::MAX")))
    }

    fn confirmation_height(&self, txid: Txid) -> Result<Option<u32>, ProtocolError> {
        match tx_confirmation_height(&self.client, &txid) {
            Ok(height) => height
                .map(|h| {
                    u32::try_from(h).map_err(|_| {
                        ProtocolError::Other(format!("confirmation height {h} exceeds u32::MAX"))
                    })
                })
                .transpose(),
            // A transaction the node does not know (yet) is *unknown*, not a
            // failure — the same answer `LocalChain` gives, so a role behaves
            // identically on both chain views.
            Err(ManagerError::RpcError(e)) if is_tx_not_found(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// A deterministic in-memory [`ChainView`] for offline tests: transactions are
/// indexed but no scripts are executed, so it validates *protocol* logic (turn
/// order, routing, timeouts) — consensus validity stays with the regtest
/// end-to-end tests.
///
/// Share one instance between the parties' runners (`Rc<LocalChain>`) and
/// advance time explicitly with [`mine`](LocalChain::mine) to exercise
/// timeout paths.
#[derive(Default)]
pub struct LocalChain {
    inner: RefCell<LocalChainInner>,
}

#[derive(Default)]
struct LocalChainInner {
    height: u32,
    /// Broadcast, not yet mined.
    mempool: Vec<Txid>,
    /// Confirmation height by txid.
    confirmed: HashMap<Txid, u32>,
    /// Every transaction ever broadcast.
    txs: HashMap<Txid, Transaction>,
    /// Which transaction spends each outpoint (mempool and blocks alike).
    spends: HashMap<OutPoint, Txid>,
}

impl LocalChain {
    /// An empty chain at height 0.
    pub fn new() -> Self {
        LocalChain::default()
    }

    /// Confirm the whole mempool in the next block, then advance the tip to
    /// `height + n`.
    pub fn mine(&self, n: u32) {
        assert!(n > 0, "mining zero blocks is a no-op");
        let mut inner = self.inner.borrow_mut();
        let confirm_at = inner.height + 1;
        for txid in std::mem::take(&mut inner.mempool) {
            inner.confirmed.insert(txid, confirm_at);
        }
        inner.height += n;
    }

    /// Declare an externally-created transaction (e.g. a fake funding) as
    /// confirmed at `height`, so timeouts counted from it can fire.
    pub fn assume_confirmed(&self, txid: Txid, height: u32) {
        let mut inner = self.inner.borrow_mut();
        inner.confirmed.insert(txid, height);
        inner.height = inner.height.max(height);
    }
}

impl ChainView for LocalChain {
    fn broadcast(&self, tx: &Transaction) -> Result<(), ProtocolError> {
        let mut inner = self.inner.borrow_mut();
        let txid = tx.compute_txid();
        if inner.txs.contains_key(&txid) {
            return Ok(()); // idempotent re-broadcast
        }
        for input in &tx.input {
            if let Some(other) = inner.spends.get(&input.previous_output) {
                return Err(ProtocolError::Other(format!(
                    "double spend of {} (already spent by {})",
                    input.previous_output, other
                )));
            }
        }
        for input in &tx.input {
            inner.spends.insert(input.previous_output, txid);
        }
        inner.txs.insert(txid, tx.clone());
        inner.mempool.push(txid);
        Ok(())
    }

    fn find_spending_tx(&self, outpoint: OutPoint) -> Result<Option<Transaction>, ProtocolError> {
        let inner = self.inner.borrow();
        Ok(inner
            .spends
            .get(&outpoint)
            .map(|txid| inner.txs[txid].clone()))
    }

    fn height(&self) -> Result<u32, ProtocolError> {
        Ok(self.inner.borrow().height)
    }

    fn confirmation_height(&self, txid: Txid) -> Result<Option<u32>, ProtocolError> {
        Ok(self.inner.borrow().confirmed.get(&txid).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Sequence, TxIn, Witness};

    fn tx_spending(outpoint: OutPoint, lock_time: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            // Distinct lock times give distinct txids for conflicting spends.
            lock_time: LockTime::from_consensus(lock_time),
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Default::default(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![],
        }
    }

    fn outpoint(seed: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([seed; 32])),
            vout: 0,
        }
    }

    #[test]
    fn broadcast_and_find_spend() {
        let chain = LocalChain::new();
        let op = outpoint(1);
        assert!(chain.find_spending_tx(op).unwrap().is_none());

        let tx = tx_spending(op, 0);
        chain.broadcast(&tx).unwrap();
        // Visible from the mempool, before any block.
        assert_eq!(chain.find_spending_tx(op).unwrap(), Some(tx.clone()));
        // Re-broadcasting the same tx is fine; a conflicting spend is not.
        chain.broadcast(&tx).unwrap();
        let conflict = tx_spending(op, 7);
        assert!(chain.broadcast(&conflict).is_err());
    }

    #[test]
    fn mining_confirms_and_advances() {
        let chain = LocalChain::new();
        let tx = tx_spending(outpoint(2), 0);
        chain.broadcast(&tx).unwrap();
        let txid = tx.compute_txid();
        assert_eq!(chain.confirmation_height(txid).unwrap(), None);

        chain.mine(3);
        assert_eq!(chain.height().unwrap(), 3);
        assert_eq!(chain.confirmation_height(txid).unwrap(), Some(1));
        // Spends stay visible after confirmation.
        assert!(chain.find_spending_tx(outpoint(2)).unwrap().is_some());
    }

    #[test]
    fn assume_confirmed_seeds_external_funding() {
        let chain = LocalChain::new();
        let txid = Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([9u8; 32]));
        chain.assume_confirmed(txid, 5);
        assert_eq!(chain.confirmation_height(txid).unwrap(), Some(5));
        assert_eq!(chain.height().unwrap(), 5);
    }
}
