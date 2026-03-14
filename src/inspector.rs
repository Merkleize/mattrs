use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::contracts::ContractInstance;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ManagerSnapshot {
    pub timestamp_ms: u64,
    pub instances: Vec<InstanceSnapshot>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InstanceSnapshot {
    pub index: usize,
    pub contract_name: String,
    pub status: String,
    pub data_hex: String,
    pub address: String,
    pub outpoint: Option<String>,
    pub funding_txid: Option<String>,
    pub funding_amount_sat: Option<u64>,
    pub spending_txid: Option<String>,
    pub spending_clause: Option<String>,
    pub spending_args: Option<HashMap<String, String>>,
    pub last_height: Option<u64>,
}

pub fn snapshot_instance(idx: usize, inst: &ContractInstance) -> InstanceSnapshot {
    let outpoint = inst.outpoint().map(|op| format!("{}:{}", op.txid, op.vout));

    let funding_txid = inst.funding_tx().map(|tx| tx.compute_txid().to_string());

    let funding_amount_sat = inst.outpoint().and_then(|op| {
        inst.funding_tx()
            .and_then(|tx| tx.output.get(op.vout as usize))
            .map(|out| out.value.to_sat())
    });

    let spending_txid = inst.spending_tx().map(|tx| tx.compute_txid().to_string());

    let spending_clause = inst.spending_clause().map(|s| s.to_string());

    let spending_args = inst.spending_args().map(|args| {
        args.iter()
            .map(|(k, v)| (k.clone(), hex::encode(v)))
            .collect()
    });

    InstanceSnapshot {
        index: idx,
        contract_name: inst.contract().name().to_string(),
        status: format!("{:?}", inst.status()),
        data_hex: hex::encode(inst.data()),
        address: inst.get_address().to_string(),
        outpoint,
        funding_txid,
        funding_amount_sat,
        spending_txid,
        spending_clause,
        spending_args,
        last_height: inst.last_height(),
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

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
