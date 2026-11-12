//! Node I/O, funding, mining, and spend discovery.
//! Shared scan helpers also serve the protocol runner.
use super::{Children, ContractManager, InstanceHandle, ManagerError};
use crate::contracts::{ContractInstance, ContractState, ErasedContract, InstanceStatus};
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitcoincore_rpc::{Client, RpcApi};
use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::Arc, thread::sleep, time::Duration};

/// The interval between chain polls.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The default polling window of [`ContractManager::wait_for_spend`] and
/// [`ContractManager::wait_for_transaction`]; see
/// [`ContractManager::wait_for_spend_within`] to override it.
pub(super) const DEFAULT_POLL_WINDOW: Duration = Duration::from_secs(30);

/// Poll `check` every [`POLL_INTERVAL`] until it yields a value or `window`
/// elapses (`None` = poll forever). Returns `Ok(None)` on timeout.
pub(super) fn poll_until<T>(
    window: Option<Duration>,
    mut check: impl FnMut() -> Result<Option<T>, ManagerError>,
) -> Result<Option<T>, ManagerError> {
    let deadline = window.map(|w| std::time::Instant::now() + w);
    loop {
        if let Some(value) = check()? {
            return Ok(Some(value));
        }
        if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            return Ok(None);
        }
        sleep(POLL_INTERVAL);
    }
}

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

        // Fund it using RPC
        let address = bitcoin::Address::from_script(&script_pubkey, self.network.params())
            .map_err(|e| ManagerError::Other(format!("Failed to create address: {}", e)))?;

        let txid = self
            .rpc
            .send_to_address(&address, amount, None, None, None, None, None, None)?;

        // Wait for the transaction to appear
        let tx = self.wait_for_transaction(txid)?;

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

    /// Mine blocks (for regtest).
    pub fn mine_blocks(&self, n: u64) -> Result<(), ManagerError> {
        let address = self.rpc.get_new_address(None, None)?.assume_checked();
        self.rpc.generate_to_address(n, &address)?;
        Ok(())
    }

    pub(super) fn wait_for_transaction(&self, txid: Txid) -> Result<Transaction, ManagerError> {
        poll_until(Some(DEFAULT_POLL_WINDOW), || {
            match self.rpc.get_raw_transaction(&txid, None) {
                Ok(tx) => Ok(Some(tx)),
                Err(e) if is_tx_not_found(&e) => Ok(None), // not (yet) known to the node
                Err(e) => Err(e.into()),
            }
        })?
        .ok_or(ManagerError::TransactionNotFound(txid))
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
        let funding_tx = self.rpc.get_raw_transaction(&outpoint.txid, None)?;
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
    /// For inputs that may be spent in separate transactions, use
    /// [`wait_for_spends`](Self::wait_for_spends), which provides per-input checks.
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

    /// [`wait_for_spend`](Self::wait_for_spend) for several instances (possibly
    /// spent by one batch transaction). Children merged across inputs are
    /// materialized once and returned once.
    /// This uses per-input checks, not aggregate accounting. If all handles are
    /// intended to spend together, use [`wait_for_batch`](Self::wait_for_batch).
    pub fn wait_for_spends(
        &mut self,
        handles: &[InstanceHandle],
    ) -> Result<Children, ManagerError> {
        let mut result: Vec<InstanceHandle> = Vec::new();
        // First discover/observe every spend, then revisit every handle so a
        // Join seen before its defining input can link to the shared child.
        for _ in 0..2 {
            for handle in handles {
                let children = if let Some(tx) = handle.spending_tx() {
                    self.observe_spend(handle, &tx)?
                } else {
                    self.wait_for_spend(handle)?
                };
                for child in children {
                    if !result.contains(&child) {
                        result.push(child);
                    }
                }
            }
        }
        Ok(Children::new(result))
    }

    /// Poll (within `window`; `None` = forever) until a transaction spending
    /// `outpoint` appears, in the mempool (`gettxspendingprevout`) or in a
    /// block (scanned from the funding transaction's height onward).
    pub(super) fn wait_for_spending_tx(
        &self,
        outpoint: OutPoint,
        window: Option<Duration>,
    ) -> Result<Transaction, ManagerError> {
        let mut next_height = spend_scan_start(&self.rpc, outpoint)?;
        let mut blocks = BlockCache::default();
        poll_until(window, || {
            let found = find_spending_tx_once(&self.rpc, outpoint, &mut next_height, &mut blocks);
            // A single cursor never re-reads a scanned block.
            blocks.retain_from(next_height);
            found
        })?
        .ok_or(ManagerError::SpendNotFound(outpoint))
    }
}

/// The height `txid` confirmed at (`None` while it sits in the mempool).
/// Requires the node to know the transaction (wallet, mempool, or `txindex`);
/// an unknown `txid` is an error ([`is_tx_not_found`] tells it apart).
pub(crate) fn tx_confirmation_height(
    rpc: &Client,
    txid: &Txid,
) -> Result<Option<u64>, ManagerError> {
    let info = rpc.get_raw_transaction_info(txid, None)?;
    Ok(match info.blockhash {
        Some(hash) => Some(rpc.get_block_header_info(&hash)?.height as u64),
        None => None,
    })
}

/// The block height where a scan for spends of `outpoint` should start: where
/// the funding transaction confirmed (or the next block, if it is still
/// unconfirmed).
pub(crate) fn spend_scan_start(rpc: &Client, outpoint: OutPoint) -> Result<u64, ManagerError> {
    Ok(match tx_confirmation_height(rpc, &outpoint.txid)? {
        Some(height) => height,
        None => rpc.get_block_count()? + 1,
    })
}

/// A cache of fetched blocks, shared between the spend scans of several
/// outpoints so each new block is downloaded once even when many cursors walk
/// the same range. Evict with [`retain_from`](BlockCache::retain_from) once
/// every cursor has passed a height.
#[derive(Default)]
pub(crate) struct BlockCache(HashMap<u64, bitcoin::Block>);

impl BlockCache {
    fn get(&mut self, rpc: &Client, height: u64) -> Result<&bitcoin::Block, ManagerError> {
        match self.0.entry(height) {
            std::collections::hash_map::Entry::Occupied(e) => Ok(e.into_mut()),
            std::collections::hash_map::Entry::Vacant(e) => {
                let hash = rpc.get_block_hash(height)?;
                Ok(e.insert(rpc.get_block(&hash)?))
            }
        }
    }

    /// Drop every cached block below `height`.
    pub(crate) fn retain_from(&mut self, height: u64) {
        self.0.retain(|h, _| *h >= height);
    }

    /// Drop every cached block.
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }

    #[cfg(test)]
    pub(crate) fn insert(&mut self, height: u64, block: bitcoin::Block) {
        self.0.insert(height, block);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

/// A single, non-blocking look for a transaction spending `outpoint`: the
/// mempool first (`gettxspendingprevout`), then the blocks from `*next_height`
/// to the tip (the cursor advances past the blocks already scanned; seed it
/// with [`spend_scan_start`], and share one `blocks` cache between the scans
/// of concurrent outpoints).
pub(crate) fn find_spending_tx_once(
    rpc: &Client,
    outpoint: OutPoint,
    next_height: &mut u64,
    blocks: &mut BlockCache,
) -> Result<Option<Transaction>, ManagerError> {
    // 1. The mempool.
    let query = serde_json::json!([{
        "txid": outpoint.txid.to_string(),
        "vout": outpoint.vout,
    }]);
    let res: serde_json::Value = rpc.call("gettxspendingprevout", &[query])?;
    if let Some(txid_str) = res
        .get(0)
        .and_then(|entry| entry.get("spendingtxid"))
        .and_then(|v| v.as_str())
    {
        let txid: Txid = txid_str
            .parse()
            .map_err(|e| ManagerError::Other(format!("bad spendingtxid: {}", e)))?;
        return Ok(Some(rpc.get_raw_transaction(&txid, None)?));
    }

    // 2. Blocks mined since the last look.
    let tip = rpc.get_block_count()?;
    while *next_height <= tip {
        let block = blocks.get(rpc, *next_height)?;
        if let Some(tx) = block
            .txdata
            .iter()
            .find(|tx| tx.input.iter().any(|i| i.previous_output == outpoint))
        {
            return Ok(Some(tx.clone()));
        }
        *next_height += 1;
    }

    Ok(None)
}

/// An RPC client for a local regtest node, for tests, examples and demos. The
/// `wallet_name` wallet must be already loaded and funded.
///
/// # Environment variables
///
/// - `BITCOIN_RPC_URL`: the node's URL (default `http://localhost:18443`).
/// - `BITCOIN_RPC_USER` / `BITCOIN_RPC_PASSWORD`: RPC credentials. When unset,
///   falls back to cookie authentication with `BITCOIN_RPC_COOKIE` (default
///   `~/.bitcoin/regtest/.cookie`) — a stock regtest `bitcoind` works with no
///   configuration at all.
pub fn regtest_rpc_client(wallet_name: &str) -> Client {
    let rpc_url =
        std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_url_full = format!("{}/wallet/{}", rpc_url, wallet_name);

    let auth = match (
        std::env::var("BITCOIN_RPC_USER"),
        std::env::var("BITCOIN_RPC_PASSWORD"),
    ) {
        (Ok(user), Ok(password)) => bitcoincore_rpc::Auth::UserPass(user, password),
        _ => {
            let cookie = std::env::var("BITCOIN_RPC_COOKIE")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    let home = std::env::var("HOME").expect("HOME not set");
                    std::path::PathBuf::from(home).join(".bitcoin/regtest/.cookie")
                });
            bitcoincore_rpc::Auth::CookieFile(cookie)
        }
    };

    Client::new(&rpc_url_full, auth).expect("Failed to create RPC client")
}

/// Whether an RPC error is Core's "No such mempool or blockchain transaction"
/// (code -5), i.e. the transaction is not (yet) known to the node — as opposed
/// to a real failure (node unreachable, bad credentials, ...).
pub(crate) fn is_tx_not_found(e: &bitcoincore_rpc::Error) -> bool {
    matches!(
        e,
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(rpc_err))
            if rpc_err.code == -5
    )
}
