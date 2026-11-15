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

/// A [`ChainView`] over a real Bitcoin node's RPC interface. A spend is found
/// by a per-outpoint block scan, from the funding transaction's height up to
/// the last block with the confirmations asked for. Only
/// [`find_unsettled_spend`](ChainView::find_unsettled_spend) also looks at
/// shallower blocks and at the mempool (`gettxspendingprevout`).
///
/// The scan never passes a block shallower than the confirmations asked for,
/// so a reorganization no deeper than that is followed; a deeper one is not.
pub struct RpcChain {
    client: Client,
    scan: RefCell<ScanState>,
}

#[derive(Default)]
struct ScanState {
    /// The next block height to scan for a spend, per outpoint and per
    /// confirmation depth asked for. Every block below a cursor had that many
    /// confirmations when it was scanned; a cursor is therefore only good for
    /// its own depth, and a lookup at another depth keeps its own.
    cursors: HashMap<(OutPoint, u32), u64>,
    /// Blocks fetched by one outpoint's scan and not yet passed by all the
    /// others, so concurrent tokens download each new block once.
    blocks: BlockCache,
}

impl ScanState {
    /// Evict the blocks below every cursor (all of them, with no cursor
    /// left): no scan will read them again. Run after every look.
    fn evict(&mut self) {
        match self.cursors.values().copied().min() {
            Some(min) => self.blocks.retain_from(min),
            None => self.blocks.clear(),
        }
    }

    /// The scan for a spend of `outpoint` at this depth is over (the spend
    /// was found, or its caller stopped looking): drop its cursor. A cursor
    /// left behind would pin the eviction floor at its height and retain
    /// every block fetched afterwards.
    fn release(&mut self, outpoint: OutPoint, min_confirmations: u32) {
        self.cursors.remove(&(outpoint, min_confirmations));
        self.evict();
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

    fn find_spending_tx(
        &self,
        outpoint: OutPoint,
        min_confirmations: u32,
    ) -> Result<Option<Transaction>, ChainError> {
        let mut scan = self.scan.borrow_mut();
        let ScanState { cursors, blocks } = &mut *scan;
        let cursor = match cursors.entry((outpoint, min_confirmations)) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                e.insert(spend_scan_start(&self.client, outpoint, min_confirmations)?)
            }
        };
        let found =
            find_spending_tx_once(&self.client, outpoint, min_confirmations, cursor, blocks)?;
        match found {
            Some(_) => scan.release(outpoint, min_confirmations),
            None => scan.evict(),
        }
        Ok(found)
    }

    /// The mempool, then every block the confirmed scans have not passed
    /// yet, up to the tip. The scans' cursors are read, not moved: blocks
    /// still too shallow to count stay ahead of them.
    fn find_unsettled_spend(&self, outpoint: OutPoint) -> Result<Option<Transaction>, ChainError> {
        let mut scan = self.scan.borrow_mut();
        let watched = scan
            .cursors
            .iter()
            .filter(|((watched, _), _)| *watched == outpoint)
            .map(|(_, cursor)| *cursor)
            .min();
        let mut cursor = match watched {
            Some(cursor) => cursor,
            // A one-off look at the chain as it is now.
            None => spend_scan_start(&self.client, outpoint, 1)?,
        };
        let found = match find_mempool_spend(&self.client, outpoint) {
            Ok(None) => {
                find_spending_tx_once(&self.client, outpoint, 1, &mut cursor, &mut scan.blocks)
            }
            in_mempool => in_mempool,
        };
        // This look keeps no cursor, so nothing else would release the
        // blocks it fetched.
        scan.evict();
        found
    }

    fn stop_watching(&self, outpoint: OutPoint, min_confirmations: u32) {
        self.scan.borrow_mut().release(outpoint, min_confirmations);
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

/// The block height where a scan for spends of `outpoint`, with
/// `min_confirmations`, should start (see [`scan_start`]).
fn spend_scan_start(
    rpc: &Client,
    outpoint: OutPoint,
    min_confirmations: u32,
) -> Result<u64, ChainError> {
    let funded_at = tx_confirmation_height(rpc, &outpoint.txid)?;
    Ok(scan_start(
        funded_at,
        rpc.get_block_count()?,
        min_confirmations,
    ))
}

/// Where a scan for the spend of an output starts, given the height its
/// funding transaction confirmed at (if it has), the tip, and the depth at
/// which a block is taken as final.
///
/// A spend cannot sit below its funding, but the funding's height is only a
/// lower bound once that block is final. Until then, a reorganization can
/// move the funding (and a spend with it) down to any block that is not
/// final yet, so the scan starts at the first of those.
fn scan_start(funded_at: Option<u64>, tip: u64, min_confirmations: u32) -> u64 {
    // Blocks up to `tip - (depth - 1)` are final.
    let first_unsettled = (tip + 2).saturating_sub(u64::from(min_confirmations.max(1)));
    match funded_at {
        Some(height) => height.min(first_unsettled),
        None => first_unsettled,
    }
}

/// A cache of fetched blocks, shared between the spend scans of several
/// outpoints so each new block is downloaded once even when many cursors walk
/// the same range. Evict with [`retain_from`](BlockCache::retain_from) once
/// every cursor has passed a height.
///
/// A block is cached under its height together with its hash, and reused only
/// while the active chain still has that hash there: scans waiting for
/// different depths share the cache, so a block one of them fetched at the
/// tip can be reorganized away before a deeper one reads it.
#[derive(Default)]
struct BlockCache(HashMap<u64, (bitcoin::BlockHash, bitcoin::Block)>);

impl BlockCache {
    /// The block at `height` on the node's active chain. Its hash is asked
    /// for every time; the block itself is downloaded only when the cached
    /// one is not that block.
    fn get(&mut self, rpc: &Client, height: u64) -> Result<&bitcoin::Block, ChainError> {
        let hash = rpc.get_block_hash(height)?;
        if !self.holds(height, &hash) {
            self.0.insert(height, (hash, rpc.get_block(&hash)?));
        }
        Ok(&self.0[&height].1)
    }

    /// Whether the block cached at `height` is the one with `hash`.
    fn holds(&self, height: u64, hash: &bitcoin::BlockHash) -> bool {
        self.0
            .get(&height)
            .is_some_and(|(cached, _)| cached == hash)
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
        self.0.insert(height, (block.block_hash(), block));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// The last block height a spend may sit at to have `min_confirmations`
/// confirmations under a tip at height `tip` (`None` when no block is deep
/// enough yet). Zero confirmations scan up to the tip, like one.
fn deepest_scan_height(tip: u64, min_confirmations: u32) -> Option<u64> {
    tip.checked_sub(u64::from(min_confirmations.saturating_sub(1)))
}

/// The transaction spending `outpoint` in the node's mempool, if any
/// (`gettxspendingprevout`).
fn find_mempool_spend(rpc: &Client, outpoint: OutPoint) -> Result<Option<Transaction>, ChainError> {
    let query = serde_json::json!([{
        "txid": outpoint.txid.to_string(),
        "vout": outpoint.vout,
    }]);
    let res: serde_json::Value = rpc.call("gettxspendingprevout", &[query])?;
    let Some(txid_str) = res
        .get(0)
        .and_then(|entry| entry.get("spendingtxid"))
        .and_then(|v| v.as_str())
    else {
        return Ok(None);
    };
    let txid: Txid = txid_str
        .parse()
        .map_err(|e| ChainError::Other(format!("bad spendingtxid: {}", e)))?;
    Ok(Some(rpc.get_raw_transaction(&txid, None)?))
}

/// A single, non-blocking look for a transaction spending `outpoint` with at
/// least `min_confirmations` confirmations: the blocks from `*next_height` to
/// the last one that deep (the cursor advances past the blocks already
/// scanned; seed it with [`spend_scan_start`] for the same depth, and share
/// one `blocks` cache between the scans of concurrent outpoints).
fn find_spending_tx_once(
    rpc: &Client,
    outpoint: OutPoint,
    min_confirmations: u32,
    next_height: &mut u64,
    blocks: &mut BlockCache,
) -> Result<Option<Transaction>, ChainError> {
    let Some(last) = deepest_scan_height(rpc.get_block_count()?, min_confirmations) else {
        return Ok(None);
    };
    while *next_height <= last {
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
/// # Errors
///
/// Fails if the client cannot be created — in practice, when the cookie file
/// is missing because no node is running (or it keeps its data elsewhere).
/// The error names the URL and the credentials that were tried.
pub fn regtest_rpc_client(wallet_name: &str) -> Result<Client, ChainError> {
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
                .or_else(|_| {
                    std::env::var("HOME")
                        .map(|home| std::path::PathBuf::from(home).join(".bitcoin/regtest/.cookie"))
                        .map_err(|_| {
                            ChainError::Other(
                                "cannot locate the node's cookie file: HOME is not set; set \
                                 BITCOIN_RPC_COOKIE, or BITCOIN_RPC_USER and BITCOIN_RPC_PASSWORD"
                                    .into(),
                            )
                        })
                })?;
            let hint = format!(
                "the cookie file {}; is the regtest node running? Otherwise set \
                 BITCOIN_RPC_COOKIE, or BITCOIN_RPC_USER and BITCOIN_RPC_PASSWORD",
                cookie.display()
            );
            (bitcoincore_rpc::Auth::CookieFile(cookie), hint)
        }
    };

    Client::new(&rpc_url_full, auth).map_err(|e| {
        ChainError::Other(format!(
            "cannot create an RPC client for {rpc_url_full} with {auth_hint}: {e}"
        ))
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
    fn the_scan_stops_at_the_last_block_with_enough_confirmations() {
        // The tip block has one confirmation.
        assert_eq!(deepest_scan_height(100, 0), Some(100));
        assert_eq!(deepest_scan_height(100, 1), Some(100));
        assert_eq!(deepest_scan_height(100, 6), Some(95));
        assert_eq!(deepest_scan_height(5, 6), Some(0));
        assert_eq!(deepest_scan_height(4, 6), None);
    }

    #[test]
    fn a_cached_block_is_not_reused_for_another_block_at_its_height() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let replaced = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Testnet);
        let mut blocks = BlockCache::default();
        blocks.insert(100, block.clone());

        assert!(blocks.holds(100, &block.block_hash()));
        // After a reorganization, the active chain has another block there.
        assert!(!blocks.holds(100, &replaced.block_hash()));
        assert!(!blocks.holds(101, &block.block_hash()));
    }

    #[test]
    fn a_scan_starts_below_a_funding_that_is_not_final_yet() {
        // Funded in a final block: nothing below it can hold the spend.
        assert_eq!(scan_start(Some(90), 100, 1), 90);
        assert_eq!(scan_start(Some(90), 100, 6), 90);
        // One confirmation: the tip is final, an unconfirmed funding is next.
        assert_eq!(scan_start(Some(100), 100, 1), 100);
        assert_eq!(scan_start(None, 100, 1), 101);
        // Six confirmations: blocks 96..=100 can still be replaced, and the
        // funding (with its spend) can land in any of them.
        assert_eq!(scan_start(Some(100), 100, 6), 96);
        assert_eq!(scan_start(None, 100, 6), 96);
        assert_eq!(scan_start(Some(95), 100, 6), 95);
        // Zero confirmations scan like one; a short chain starts at genesis.
        assert_eq!(scan_start(None, 100, 0), 101);
        assert_eq!(scan_start(None, 3, 6), 0);
    }

    #[test]
    fn an_abandoned_wait_releases_its_cursor_and_blocks() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let chain = RpcChain::new(
            Client::new("http://127.0.0.1:1", bitcoincore_rpc::Auth::None).expect("no I/O yet"),
        );
        {
            let mut scan = chain.scan.borrow_mut();
            // The lagging outpoint is watched at two depths.
            scan.cursors.insert((outpoint(1), 6), 10);
            scan.cursors.insert((outpoint(1), 1), 11);
            scan.cursors.insert((outpoint(2), 1), 12);
            for height in 10..=14 {
                scan.blocks.insert(height, block.clone());
            }
        }

        // The caller waiting for six confirmations gives up (or now waits
        // for another depth): only that watch goes.
        chain.stop_watching(outpoint(1), 6);
        {
            let scan = chain.scan.borrow();
            assert_eq!(scan.cursors.len(), 2);
            assert!(scan.cursors.contains_key(&(outpoint(1), 1)));
            assert_eq!(scan.blocks.len(), 4);
        }
        chain.stop_watching(outpoint(1), 1);
        assert_eq!(chain.scan.borrow().blocks.len(), 3);
    }

    #[test]
    fn a_found_spend_releases_its_cursor_and_blocks() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut scan = ScanState::default();
        scan.cursors.insert((outpoint(1), 1), 10);
        scan.cursors.insert((outpoint(2), 1), 12);
        for height in 10..=14 {
            scan.blocks.insert(height, block.clone());
        }

        // Still waiting on both: everything from the lowest cursor is kept.
        scan.evict();
        assert_eq!(scan.blocks.len(), 5);

        // The lagging outpoint's spend is found: its cursor must not keep
        // pinning the blocks only it still needed.
        scan.release(outpoint(1), 1);
        assert!(!scan.cursors.contains_key(&(outpoint(1), 1)));
        assert_eq!(scan.blocks.len(), 3);

        // Nothing left to watch: nothing left to cache.
        scan.release(outpoint(2), 1);
        assert!(scan.cursors.is_empty());
        assert_eq!(scan.blocks.len(), 0);
    }

    #[test]
    fn a_scan_at_one_depth_does_not_move_the_scan_at_another() {
        let mut scan = ScanState::default();
        scan.cursors.insert((outpoint(1), 1), 101);
        scan.cursors.insert((outpoint(1), 6), 96);

        // The shallow scan finding the spend leaves the deep one in place,
        // still short of the blocks that are not final for it.
        scan.release(outpoint(1), 1);
        assert_eq!(scan.cursors.get(&(outpoint(1), 6)), Some(&96));
    }
}
