//! Chain access for protocol runners.
//!
//! Everything a runner does against the chain goes through [`ChainView`], so
//! the same role logic runs identically against a real node and against the
//! in-memory chain used by deterministic offline tests.

use bitcoin::{OutPoint, Transaction, Txid};

use super::ProtocolError;

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
