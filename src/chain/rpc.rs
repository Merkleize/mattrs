//! [`ChainView`] over a Bitcoin node's RPC interface.

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::time::Duration;

use bitcoin::{Amount, OutPoint, Script, Transaction, Txid};
use bitcoincore_rpc::{Client, RpcApi};

use super::{ChainError, ChainView, poll_until};

/// How long [`RpcChain::fund_output`](ChainView::fund_output) waits for the
/// node to report the funding transaction it just created.
const FUNDING_WINDOW: Duration = Duration::from_secs(30);

impl From<bitcoincore_rpc::Error> for ChainError {
    fn from(e: bitcoincore_rpc::Error) -> Self {
        ChainError::Rpc(e)
    }
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

impl ScanState {
    /// Bookkeeping after one look for a spend of `outpoint`. A scan that is
    /// `done` (its spend was found, or its caller stopped looking) drops its
    /// cursor: a cursor left behind would pin the eviction floor at its
    /// height and retain every block fetched afterwards. Blocks below every
    /// remaining cursor are evicted.
    fn settle(&mut self, outpoint: OutPoint, done: bool) {
        if done {
            self.cursors.remove(&outpoint);
        }
        match self.cursors.values().copied().min() {
            Some(min) => self.blocks.retain_from(min),
            None => self.blocks.clear(),
        }
    }
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
    fn broadcast(&self, tx: &Transaction) -> Result<(), ChainError> {
        self.client.send_raw_transaction(tx)?;
        Ok(())
    }

    fn find_spending_tx(&self, outpoint: OutPoint) -> Result<Option<Transaction>, ChainError> {
        let mut scan = self.scan.borrow_mut();
        let ScanState { cursors, blocks } = &mut *scan;
        let cursor = match cursors.entry(outpoint) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(spend_scan_start(&self.client, outpoint)?),
        };
        let found = find_spending_tx_once(&self.client, outpoint, cursor, blocks)?;
        scan.settle(outpoint, found.is_some());
        Ok(found)
    }

    fn stop_watching(&self, outpoint: OutPoint) {
        self.scan.borrow_mut().settle(outpoint, true);
    }

    fn transaction(&self, txid: Txid) -> Result<Option<Transaction>, ChainError> {
        match self.client.get_raw_transaction(&txid, None) {
            Ok(tx) => Ok(Some(tx)),
            Err(e) if is_tx_not_found(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn height(&self) -> Result<u32, ChainError> {
        let height = self.client.get_block_count()?;
        u32::try_from(height)
            .map_err(|_| ChainError::Other(format!("block height {height} exceeds u32::MAX")))
    }

    fn confirmation_height(&self, txid: Txid) -> Result<Option<u32>, ChainError> {
        match tx_confirmation_height(&self.client, &txid) {
            Ok(height) => height
                .map(|h| {
                    u32::try_from(h).map_err(|_| {
                        ChainError::Other(format!("confirmation height {h} exceeds u32::MAX"))
                    })
                })
                .transpose(),
            // A transaction the node does not know (yet) is *unknown*, not a
            // failure — the same answer `LocalChain` gives, so a role behaves
            // identically on both chain views.
            Err(ChainError::Rpc(e)) if is_tx_not_found(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Pay from the node's loaded wallet, then wait for the node to report
    /// the transaction.
    fn fund_output(
        &self,
        script_pubkey: &Script,
        amount: Amount,
    ) -> Result<Transaction, ChainError> {
        let network = self.client.get_blockchain_info()?.chain;
        let address = bitcoin::Address::from_script(script_pubkey, network.params())
            .map_err(|e| ChainError::Other(format!("no address for the output script: {e}")))?;
        let txid = self
            .client
            .send_to_address(&address, amount, None, None, None, None, None, None)?;
        poll_until(Some(FUNDING_WINDOW), || self.transaction(txid))?
            .ok_or_else(|| ChainError::Other(format!("funding transaction {txid} never appeared")))
    }

    fn mine_blocks(&self, n: u32) -> Result<(), ChainError> {
        let address = self.client.get_new_address(None, None)?.assume_checked();
        self.client.generate_to_address(n.into(), &address)?;
        Ok(())
    }
}

/// The height `txid` confirmed at (`None` while it sits in the mempool).
/// Requires the node to know the transaction (wallet, mempool, or `txindex`);
/// an unknown `txid` is an error ([`is_tx_not_found`] tells it apart).
fn tx_confirmation_height(rpc: &Client, txid: &Txid) -> Result<Option<u64>, ChainError> {
    let info = rpc.get_raw_transaction_info(txid, None)?;
    Ok(match info.blockhash {
        Some(hash) => Some(rpc.get_block_header_info(&hash)?.height as u64),
        None => None,
    })
}

/// The block height where a scan for spends of `outpoint` should start: where
/// the funding transaction confirmed (or the next block, if it is still
/// unconfirmed).
fn spend_scan_start(rpc: &Client, outpoint: OutPoint) -> Result<u64, ChainError> {
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
struct BlockCache(HashMap<u64, bitcoin::Block>);

impl BlockCache {
    fn get(&mut self, rpc: &Client, height: u64) -> Result<&bitcoin::Block, ChainError> {
        match self.0.entry(height) {
            std::collections::hash_map::Entry::Occupied(e) => Ok(e.into_mut()),
            std::collections::hash_map::Entry::Vacant(e) => {
                let hash = rpc.get_block_hash(height)?;
                Ok(e.insert(rpc.get_block(&hash)?))
            }
        }
    }

    /// Drop every cached block below `height`.
    fn retain_from(&mut self, height: u64) {
        self.0.retain(|h, _| *h >= height);
    }

    /// Drop every cached block.
    fn clear(&mut self) {
        self.0.clear();
    }

    #[cfg(test)]
    fn insert(&mut self, height: u64, block: bitcoin::Block) {
        self.0.insert(height, block);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// A single, non-blocking look for a transaction spending `outpoint`: the
/// mempool first (`gettxspendingprevout`), then the blocks from `*next_height`
/// to the tip (the cursor advances past the blocks already scanned; seed it
/// with [`spend_scan_start`], and share one `blocks` cache between the scans
/// of concurrent outpoints).
fn find_spending_tx_once(
    rpc: &Client,
    outpoint: OutPoint,
    next_height: &mut u64,
    blocks: &mut BlockCache,
) -> Result<Option<Transaction>, ChainError> {
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
            .map_err(|e| ChainError::Other(format!("bad spendingtxid: {}", e)))?;
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
///
/// # Panics
///
/// Panics if the client cannot be created — in practice, when the cookie file
/// is missing because no node is running (or it keeps its data elsewhere).
pub fn regtest_rpc_client(wallet_name: &str) -> Client {
    let rpc_url =
        std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_url_full = format!("{}/wallet/{}", rpc_url, wallet_name);

    let (auth, auth_hint) = match (
        std::env::var("BITCOIN_RPC_USER"),
        std::env::var("BITCOIN_RPC_PASSWORD"),
    ) {
        (Ok(user), Ok(password)) => (
            bitcoincore_rpc::Auth::UserPass(user, password),
            "BITCOIN_RPC_USER / BITCOIN_RPC_PASSWORD".to_string(),
        ),
        _ => {
            let cookie = std::env::var("BITCOIN_RPC_COOKIE")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    let home = std::env::var("HOME").expect("HOME not set");
                    std::path::PathBuf::from(home).join(".bitcoin/regtest/.cookie")
                });
            let hint = format!(
                "the cookie file {}; is the regtest node running? Otherwise set \
                 BITCOIN_RPC_COOKIE, or BITCOIN_RPC_USER and BITCOIN_RPC_PASSWORD",
                cookie.display()
            );
            (bitcoincore_rpc::Auth::CookieFile(cookie), hint)
        }
    };

    Client::new(&rpc_url_full, auth).unwrap_or_else(|e| {
        panic!("cannot create an RPC client for {rpc_url_full} with {auth_hint}: {e}")
    })
}

/// Whether an RPC error is Core's "No such mempool or blockchain transaction"
/// (code -5), i.e. the transaction is not (yet) known to the node — as opposed
/// to a real failure (node unreachable, bad credentials, ...).
fn is_tx_not_found(e: &bitcoincore_rpc::Error) -> bool {
    matches!(
        e,
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(rpc_err))
            if rpc_err.code == -5
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outpoint(seed: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([seed; 32])),
            vout: 0,
        }
    }

    #[test]
    fn an_abandoned_wait_releases_its_cursor_and_blocks() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let chain = RpcChain::new(
            Client::new("http://127.0.0.1:1", bitcoincore_rpc::Auth::None).expect("no I/O yet"),
        );
        {
            let mut scan = chain.scan.borrow_mut();
            scan.cursors.insert(outpoint(1), 10);
            scan.cursors.insert(outpoint(2), 12);
            for height in 10..=14 {
                scan.blocks.insert(height, block.clone());
            }
        }

        // The caller waiting on the lagging outpoint gives up.
        chain.stop_watching(outpoint(1));
        let scan = chain.scan.borrow();
        assert!(!scan.cursors.contains_key(&outpoint(1)));
        assert_eq!(scan.blocks.len(), 3);
    }

    #[test]
    fn a_found_spend_releases_its_cursor_and_blocks() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut scan = ScanState::default();
        scan.cursors.insert(outpoint(1), 10);
        scan.cursors.insert(outpoint(2), 12);
        for height in 10..=14 {
            scan.blocks.insert(height, block.clone());
        }

        // Still waiting on both: everything from the lowest cursor is kept.
        scan.settle(outpoint(2), false);
        assert_eq!(scan.blocks.len(), 5);

        // The lagging outpoint's spend is found: its cursor must not keep
        // pinning the blocks only it still needed.
        scan.settle(outpoint(1), true);
        assert!(!scan.cursors.contains_key(&outpoint(1)));
        assert_eq!(scan.blocks.len(), 3);

        // Nothing left to watch: nothing left to cache.
        scan.settle(outpoint(2), true);
        assert!(scan.cursors.is_empty());
        assert_eq!(scan.blocks.len(), 0);
    }
}
