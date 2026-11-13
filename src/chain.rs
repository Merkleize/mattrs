//! Chain access: the one seam between mattrs and a Bitcoin node.
//!
//! Everything the [`ContractManager`](crate::manager::ContractManager) and the
//! protocol [`Runner`](crate::protocol::Runner) do against the chain goes
//! through [`ChainView`], so the same contract and role logic runs identically
//! against a real node (`RpcChain`, with the `rpc` feature) and against the
//! in-memory chain used by deterministic offline tests ([`LocalChain`]).

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

use bitcoin::{Amount, OutPoint, Script, Transaction, TxOut, Txid};

#[cfg(feature = "rpc")]
mod rpc;
#[cfg(feature = "rpc")]
pub use rpc::{RpcChain, regtest_rpc_client};

/// The interval between chain polls.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Poll `check` every [`POLL_INTERVAL`] until it yields a value or `window`
/// elapses (`None` = poll forever). Returns `Ok(None)` on timeout.
pub(crate) fn poll_until<T, E>(
    window: Option<Duration>,
    mut check: impl FnMut() -> Result<Option<T>, E>,
) -> Result<Option<T>, E> {
    let deadline = window.map(|w| std::time::Instant::now() + w);
    loop {
        if let Some(value) = check()? {
            return Ok(Some(value));
        }
        if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            return Ok(None);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Why a [`ChainView`] operation failed. Deliberately independent of the
/// protocol and manager layers, so a chain backend can be implemented (and
/// used) without either.
#[derive(Debug)]
pub enum ChainError {
    /// The node could not be reached, or answered with an error.
    #[cfg(feature = "rpc")]
    Rpc(bitcoincore_rpc::Error),
    /// The chain refused a broadcast transaction (e.g. a double spend).
    Rejected(String),
    /// This backend does not provide the operation (e.g. a read-only view
    /// asked to fund an output).
    Unsupported(&'static str),
    /// Any other backend failure.
    Other(String),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "rpc")]
            ChainError::Rpc(e) => write!(f, "RPC error: {e}"),
            ChainError::Rejected(msg) => write!(f, "transaction rejected: {msg}"),
            ChainError::Unsupported(op) => write!(f, "this chain backend cannot {op}"),
            ChainError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "rpc")]
            ChainError::Rpc(e) => Some(e),
            _ => None,
        }
    }
}

/// The chain operations mattrs performs. Methods take `&self`
/// (implementations use interior mutability) so one chain can be shared —
/// e.g. by two parties' managers interleaved in a test.
pub trait ChainView {
    /// Broadcast a transaction.
    fn broadcast(&self, tx: &Transaction) -> Result<(), ChainError>;

    /// A single, non-blocking look for a transaction spending `outpoint`
    /// (mempool or block), if one exists.
    fn find_spending_tx(&self, outpoint: OutPoint) -> Result<Option<Transaction>, ChainError>;

    /// The transaction `txid`, if this chain knows it (mempool or block).
    fn transaction(&self, txid: Txid) -> Result<Option<Transaction>, ChainError>;

    /// The current tip height.
    fn height(&self) -> Result<u32, ChainError>;

    /// The height `txid` confirmed at (`None` while unconfirmed or unknown).
    fn confirmation_height(&self, txid: Txid) -> Result<Option<u32>, ChainError>;

    /// Pay `amount` to `script_pubkey` from the backend's own funds (a node
    /// wallet, or thin air on a test chain) and return the funding
    /// transaction. Backends without funds keep the default, which refuses.
    fn fund_output(
        &self,
        script_pubkey: &Script,
        amount: Amount,
    ) -> Result<Transaction, ChainError> {
        let _ = (script_pubkey, amount);
        Err(ChainError::Unsupported("fund outputs"))
    }

    /// Mine `n` blocks (regtest and test chains). The default refuses.
    fn mine_blocks(&self, n: u32) -> Result<(), ChainError> {
        let _ = n;
        Err(ChainError::Unsupported("mine blocks"))
    }
}

/// A deterministic in-memory [`ChainView`] for offline tests: transactions are
/// indexed but no scripts are executed, so it validates *protocol* logic (turn
/// order, routing, timeouts) — consensus validity stays with the regtest
/// end-to-end tests.
///
/// Share one instance between the parties' managers (`Rc<LocalChain>`) and
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
    /// How many outputs [`fund_output`](ChainView::fund_output) created, so
    /// each funding transaction is distinct.
    funded: u32,
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
    fn broadcast(&self, tx: &Transaction) -> Result<(), ChainError> {
        let mut inner = self.inner.borrow_mut();
        let txid = tx.compute_txid();
        if inner.txs.contains_key(&txid) {
            return Ok(()); // idempotent re-broadcast
        }
        for input in &tx.input {
            if let Some(other) = inner.spends.get(&input.previous_output) {
                return Err(ChainError::Rejected(format!(
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

    fn find_spending_tx(&self, outpoint: OutPoint) -> Result<Option<Transaction>, ChainError> {
        let inner = self.inner.borrow();
        Ok(inner
            .spends
            .get(&outpoint)
            .map(|txid| inner.txs[txid].clone()))
    }

    fn transaction(&self, txid: Txid) -> Result<Option<Transaction>, ChainError> {
        Ok(self.inner.borrow().txs.get(&txid).cloned())
    }

    fn height(&self) -> Result<u32, ChainError> {
        Ok(self.inner.borrow().height)
    }

    fn confirmation_height(&self, txid: Txid) -> Result<Option<u32>, ChainError> {
        Ok(self.inner.borrow().confirmed.get(&txid).copied())
    }

    /// Mint the output out of thin air: an input-less transaction, placed in
    /// the mempool like any other.
    fn fund_output(
        &self,
        script_pubkey: &Script,
        amount: Amount,
    ) -> Result<Transaction, ChainError> {
        let mut inner = self.inner.borrow_mut();
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            // Distinct lock times give distinct txids for equal outputs.
            lock_time: bitcoin::absolute::LockTime::from_consensus(inner.funded),
            input: vec![],
            output: vec![TxOut {
                script_pubkey: script_pubkey.to_owned(),
                value: amount,
            }],
        };
        inner.funded += 1;
        let txid = tx.compute_txid();
        inner.txs.insert(txid, tx.clone());
        inner.mempool.push(txid);
        Ok(tx)
    }

    fn mine_blocks(&self, n: u32) -> Result<(), ChainError> {
        if n > 0 {
            self.mine(n);
        }
        Ok(())
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

    #[test]
    fn funding_mints_distinct_known_outputs() {
        let chain = LocalChain::new();
        let spk = bitcoin::ScriptBuf::new();
        let a = chain.fund_output(&spk, Amount::from_sat(5)).unwrap();
        let b = chain.fund_output(&spk, Amount::from_sat(5)).unwrap();
        assert_ne!(a.compute_txid(), b.compute_txid());
        assert_eq!(
            chain.transaction(a.compute_txid()).unwrap(),
            Some(a.clone())
        );
        assert_eq!(chain.confirmation_height(a.compute_txid()).unwrap(), None);
        chain.mine_blocks(1).unwrap();
        assert_eq!(
            chain.confirmation_height(a.compute_txid()).unwrap(),
            Some(1)
        );
    }
}
