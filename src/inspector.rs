//! Live inspection of a [`ContractManager`](crate::manager::ContractManager)'s
//! state (behind the `inspector` feature).
//!
//! [`ContractManager::enable_inspector`](crate::manager::ContractManager::enable_inspector)
//! starts a TCP server that pushes a JSON [`ManagerSnapshot`] — one line per
//! update — to every connected client whenever an instance is created, funded,
//! or spent. The `mattrs-inspector` workspace crate is a ratatui client for it;
//! `nc localhost 34443` works too.

use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::contracts::ContractInstance;

/// One push of the manager's whole state: every instance it tracks.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ManagerSnapshot {
    pub timestamp_ms: u64,
    pub instances: Vec<InstanceSnapshot>,
}

/// One contract instance, flattened to displayable fields.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InstanceSnapshot {
    /// Position in the manager's instance list.
    pub index: usize,
    pub contract_name: String,
    /// `Unfunded` / `Funded` / `Spent`.
    pub status: String,
    /// The committed state bytes (hex), empty for stateless contracts.
    pub data_hex: String,
    /// The instance's address, when its script pubkey is well-formed.
    pub address: Option<String>,
    /// The funded outpoint as `txid:vout`.
    pub outpoint: Option<String>,
    pub funding_txid: Option<String>,
    pub funding_amount_sat: Option<u64>,
    pub spending_txid: Option<String>,
    pub spending_clause: Option<String>,
    /// The spending witness arguments (hex), in witness order.
    pub spending_args: Option<Vec<String>>,
}

/// Flatten one instance for the snapshot.
pub fn snapshot_instance(
    index: usize,
    inst: &ContractInstance,
    network: bitcoin::Network,
) -> InstanceSnapshot {
    let data = inst.committed_state_bytes().unwrap_or_default();

    let address = inst
        .script_pubkey()
        .ok()
        .and_then(|spk| bitcoin::Address::from_script(&spk, network.params()).ok())
        .map(|a| a.to_string());

    let outpoint = inst.outpoint().map(|op| format!("{}:{}", op.txid, op.vout));
    let funding_txid = inst.funding_tx().map(|tx| tx.compute_txid().to_string());
    let funding_amount_sat = inst.prevout().map(|out| out.value.to_sat());
    let spending_txid = inst.spent_in_tx().map(|txid| txid.to_string());
    let spending_clause = inst.clause_name().map(|s| s.to_string());
    let spending_args = inst
        .spending_args()
        .map(|args| args.iter().map(hex::encode).collect());

    InstanceSnapshot {
        index,
        contract_name: inst.contract().contract_name().to_string(),
        status: format!("{:?}", inst.status()),
        data_hex: hex::encode(data),
        address,
        outpoint,
        funding_txid,
        funding_amount_sat,
        spending_txid,
        spending_clause,
        spending_args,
    }
}

/// Milliseconds since the Unix epoch, for [`ManagerSnapshot::timestamp_ms`].
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Serve `state` on `127.0.0.1:port`: each client gets the current snapshot on
/// connect, then a fresh one (a single JSON line) whenever `notify` fires.
pub fn start_inspector_server(
    state: Arc<Mutex<ManagerSnapshot>>,
    notify: Arc<Condvar>,
    port: u16,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .expect("Failed to bind inspector server");

        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };

            let state = Arc::clone(&state);
            let notify = Arc::clone(&notify);

            thread::spawn(move || {
                let mut stream = stream;

                // Send initial snapshot
                {
                    let snap = state.lock().unwrap();
                    let mut data = serde_json::to_string(&*snap).unwrap();
                    data.push('\n');
                    if stream.write_all(data.as_bytes()).is_err() {
                        return;
                    }
                }

                loop {
                    // Wait for notification
                    {
                        let lock = state.lock().unwrap();
                        let _lock = notify.wait(lock).unwrap();
                    }

                    let snap = state.lock().unwrap();
                    let mut data = serde_json::to_string(&*snap).unwrap();
                    data.push('\n');
                    if stream.write_all(data.as_bytes()).is_err() {
                        return; // client disconnected
                    }
                }
            });
        }
    })
}
