//! Live inspection of a [`ContractManager`](crate::manager::ContractManager)'s
//! state (behind the `inspector` feature).
//!
//! [`ContractManager::enable_inspector`](crate::manager::ContractManager::enable_inspector)
//! starts a loopback TCP server that pushes one JSON [`ManagerSnapshot`] line on
//! every state change. Snapshots contain the contract graph, terminal outputs,
//! and normalized transaction details. The `mattrs-inspector` workspace crate
//! bridges this stream to its browser UI; `nc localhost 34443` also works.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::net::TcpListener;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::{Address, Network, Transaction};
use serde::{Deserialize, Serialize};

use crate::contracts::ContractInstance;

/// One push of the manager's complete, current inspection state.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagerSnapshot {
    pub timestamp_ms: u64,
    pub instances: Vec<InstanceSnapshot>,
    /// Non-contract transaction outputs created by managed spends.
    #[serde(default)]
    pub terminal_utxos: Vec<TerminalUtxoSnapshot>,
    /// Funding and spending transactions, deduplicated by txid.
    #[serde(default)]
    pub transactions: Vec<TransactionSnapshot>,
}

/// One contract instance and its links to graph descendants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct InstanceSnapshot {
    /// Stable position in the manager's append-only instance list.
    pub index: usize,
    pub contract_name: String,
    /// `Unfunded` / `Funded` / `Spent`.
    pub status: String,
    /// The committed state bytes (hex), empty for stateless contracts.
    pub data_hex: String,
    /// Exact contract parameter encoding.
    #[serde(default)]
    pub params_hex: String,
    /// Pretty `Debug` output from the typed contract parameters.
    #[serde(default)]
    pub params_debug: Option<String>,
    /// Pretty `Debug` output from the full logical state, when stateful.
    #[serde(default)]
    pub state_debug: Option<String>,
    /// The instance's address, when its script pubkey is well-formed.
    pub address: Option<String>,
    /// The funded outpoint as `txid:vout`.
    pub outpoint: Option<String>,
    pub funding_txid: Option<String>,
    pub funding_amount_sat: Option<u64>,
    pub spending_txid: Option<String>,
    #[serde(default)]
    pub spending_vin: Option<usize>,
    pub spending_clause: Option<String>,
    /// The spending witness arguments (hex), in witness order.
    pub spending_args: Option<Vec<String>>,
    /// Witness elements grouped under their clause argument names.
    #[serde(default)]
    pub named_spending_args: Option<Vec<NamedArgSnapshot>>,
    /// Actual contract children linked by the manager.
    #[serde(default)]
    pub child_indices: Vec<usize>,
    /// Non-contract outputs of this instance's spending transaction.
    #[serde(default)]
    pub terminal_outpoints: Vec<String>,
}

/// One named clause argument, which may occupy several witness elements.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NamedArgSnapshot {
    pub name: String,
    pub kind: String,
    pub values_hex: Vec<String>,
    pub signer_pubkey: Option<String>,
}

/// A graph-leaf output that was not materialized as a contract instance.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TerminalUtxoSnapshot {
    pub outpoint: String,
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub script_pubkey_hex: String,
    pub address: Option<String>,
}

/// A normalized Bitcoin transaction, suitable for both readable and raw views.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactionSnapshot {
    pub txid: String,
    pub wtxid: String,
    pub version: i32,
    pub lock_time: u32,
    pub size: usize,
    pub vsize: usize,
    pub weight: u64,
    pub inputs: Vec<TransactionInputSnapshot>,
    pub outputs: Vec<TransactionOutputSnapshot>,
    pub raw_hex: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactionInputSnapshot {
    pub previous_output: String,
    pub sequence: u32,
    pub script_sig_hex: String,
    pub witness: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactionOutputSnapshot {
    pub vout: u32,
    pub amount_sat: u64,
    pub script_pubkey_hex: String,
    pub address: Option<String>,
}

/// Flatten one instance without graph relationships.
///
/// Manager snapshots use [`snapshot_instances`] so child and terminal links can
/// be resolved across the complete instance collection.
pub fn snapshot_instance(
    index: usize,
    inst: &ContractInstance,
    network: Network,
) -> InstanceSnapshot {
    snapshot_instance_with_links(index, inst, network, Vec::new(), Vec::new())
}

fn snapshot_instance_with_links(
    index: usize,
    inst: &ContractInstance,
    network: Network,
    child_indices: Vec<usize>,
    terminal_outpoints: Vec<String>,
) -> InstanceSnapshot {
    let data = inst.committed_state_bytes().unwrap_or_default();
    let address = inst
        .script_pubkey()
        .ok()
        .and_then(|spk| Address::from_script(&spk, network.params()).ok())
        .map(|a| a.to_string());
    let outpoint = inst.outpoint().map(|op| op.to_string());
    let funding_txid = inst.funding_tx().map(|tx| tx.compute_txid().to_string());
    let funding_amount_sat = inst.prevout().map(|out| out.value.to_sat());
    let spending_txid = inst.spent_in_tx().map(|txid| txid.to_string());
    let spending_clause = inst.clause_name().map(str::to_string);
    let spending_args = inst
        .spending_args()
        .map(|args| args.iter().map(hex::encode).collect());

    InstanceSnapshot {
        index,
        contract_name: inst.contract().contract_name().to_string(),
        status: format!("{:?}", inst.status()),
        data_hex: hex::encode(data),
        params_hex: hex::encode(inst.contract().params_bytes()),
        params_debug: inst.contract().params_debug(),
        state_debug: inst.state().map(|state| format!("{state:#?}")),
        address,
        outpoint,
        funding_txid,
        funding_amount_sat,
        spending_txid,
        spending_vin: inst.spending_vin(),
        spending_clause,
        spending_args,
        named_spending_args: named_spending_args(inst),
        child_indices,
        terminal_outpoints,
    }
}

fn named_spending_args(inst: &ContractInstance) -> Option<Vec<NamedArgSnapshot>> {
    let args = inst.spending_args()?;
    let clause = inst.contract().get_clause(inst.clause_name()?)?;
    let mut offset = 0usize;
    let mut named = Vec::with_capacity(clause.arg_specs().len());

    for spec in clause.arg_specs() {
        let consumed = spec.arg_type.consume(&args[offset..]).ok()?;
        let end = offset.checked_add(consumed)?;
        let values = args.get(offset..end)?;
        named.push(NamedArgSnapshot {
            name: spec.name.clone(),
            kind: format!("{:?}", spec.arg_type),
            values_hex: values.iter().map(hex::encode).collect(),
            signer_pubkey: spec.arg_type.signer_pubkey().map(hex::encode),
        });
        offset = end;
    }
    (offset == args.len()).then_some(named)
}

/// Build the normalized graph snapshot for all manager-owned instances.
pub(crate) fn snapshot_instances(
    instances: &[Rc<RefCell<ContractInstance>>],
    network: Network,
) -> ManagerSnapshot {
    let mut transaction_map: BTreeMap<String, Transaction> = BTreeMap::new();
    let mut managed_outpoints = BTreeSet::new();

    for instance in instances {
        let instance = instance.borrow();
        if let Some(outpoint) = instance.outpoint() {
            managed_outpoints.insert(outpoint.to_string());
        }
        for tx in [instance.funding_tx(), instance.spending_tx()]
            .into_iter()
            .flatten()
        {
            transaction_map
                .entry(tx.compute_txid().to_string())
                .or_insert_with(|| tx.clone());
        }
    }

    let mut terminal_map: BTreeMap<String, TerminalUtxoSnapshot> = BTreeMap::new();
    let mut terminals_by_txid: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for instance in instances {
        let instance = instance.borrow();
        let Some(tx) = instance.spending_tx() else {
            continue;
        };
        let txid = tx.compute_txid().to_string();
        let mut outpoints = Vec::new();
        for (vout, output) in tx.output.iter().enumerate() {
            let Ok(vout) = u32::try_from(vout) else {
                continue;
            };
            let outpoint = format!("{txid}:{vout}");
            if managed_outpoints.contains(&outpoint) {
                continue;
            }
            outpoints.push(outpoint.clone());
            terminal_map
                .entry(outpoint.clone())
                .or_insert_with(|| TerminalUtxoSnapshot {
                    outpoint,
                    txid: txid.clone(),
                    vout,
                    amount_sat: output.value.to_sat(),
                    script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
                    address: Address::from_script(&output.script_pubkey, network.params())
                        .ok()
                        .map(|address| address.to_string()),
                });
        }
        terminals_by_txid.entry(txid).or_insert(outpoints);
    }

    let snapshots = instances
        .iter()
        .enumerate()
        .map(|(index, instance)| {
            let instance = instance.borrow();
            let child_indices = instance
                .outputs()
                .iter()
                .filter_map(|child| {
                    instances
                        .iter()
                        .position(|candidate| Rc::ptr_eq(candidate, child))
                })
                .collect();
            let terminal_outpoints = instance
                .spent_in_tx()
                .and_then(|txid| terminals_by_txid.get(&txid.to_string()).cloned())
                .unwrap_or_default();
            snapshot_instance_with_links(
                index,
                &instance,
                network,
                child_indices,
                terminal_outpoints,
            )
        })
        .collect();

    ManagerSnapshot {
        timestamp_ms: now_ms(),
        instances: snapshots,
        terminal_utxos: terminal_map.into_values().collect(),
        transactions: transaction_map
            .values()
            .map(|tx| snapshot_transaction(tx, network))
            .collect(),
    }
}

fn snapshot_transaction(tx: &Transaction, network: Network) -> TransactionSnapshot {
    TransactionSnapshot {
        txid: tx.compute_txid().to_string(),
        wtxid: tx.compute_wtxid().to_string(),
        version: tx.version.0,
        lock_time: tx.lock_time.to_consensus_u32(),
        size: tx.total_size(),
        vsize: tx.vsize(),
        weight: tx.weight().to_wu(),
        inputs: tx
            .input
            .iter()
            .map(|input| TransactionInputSnapshot {
                previous_output: input.previous_output.to_string(),
                sequence: input.sequence.to_consensus_u32(),
                script_sig_hex: hex::encode(input.script_sig.as_bytes()),
                witness: input.witness.iter().map(hex::encode).collect(),
            })
            .collect(),
        outputs: tx
            .output
            .iter()
            .enumerate()
            .filter_map(|(vout, output)| {
                Some(TransactionOutputSnapshot {
                    vout: u32::try_from(vout).ok()?,
                    amount_sat: output.value.to_sat(),
                    script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
                    address: Address::from_script(&output.script_pubkey, network.params())
                        .ok()
                        .map(|address| address.to_string()),
                })
            })
            .collect(),
        raw_hex: bitcoin::consensus::encode::serialize_hex(tx),
    }
}

/// Milliseconds since the Unix epoch, for [`ManagerSnapshot::timestamp_ms`].
pub fn now_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// Serve `state` on `127.0.0.1:port`: each client gets the current snapshot on
/// connect, then a fresh JSON line whenever `notify` fires.
pub fn start_inspector_server(
    state: Arc<Mutex<ManagerSnapshot>>,
    notify: Arc<Condvar>,
    port: u16,
) -> io::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;

    Ok(thread::spawn(move || {
        fn lock_snapshot(
            state: &Mutex<ManagerSnapshot>,
        ) -> std::sync::MutexGuard<'_, ManagerSnapshot> {
            state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        fn write_snapshot(stream: &mut impl Write, snapshot: &ManagerSnapshot) -> io::Result<()> {
            serde_json::to_writer(&mut *stream, snapshot).map_err(io::Error::other)?;
            stream.write_all(b"\n")
        }

        for stream in listener.incoming() {
            let stream = match stream {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let state = Arc::clone(&state);
            let notify = Arc::clone(&notify);

            thread::spawn(move || {
                let mut stream = stream;
                let mut last_sent = lock_snapshot(&state).clone();
                if write_snapshot(&mut stream, &last_sent).is_err() {
                    return;
                }
                loop {
                    let current = notify
                        .wait_while(lock_snapshot(&state), |snapshot| snapshot == &last_sent)
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    if write_snapshot(&mut stream, &current).is_err() {
                        return;
                    }
                    last_sent = current;
                }
            });
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    use crate::contracts::{ClauseTree, RawArgs, StandardClause, StandardP2TR};

    fn contract(name: &'static str, tag: i64) -> Arc<dyn crate::contracts::ErasedContract> {
        let script = bitcoin::script::Builder::new()
            .push_int(tag)
            .push_opcode(bitcoin::opcodes::all::OP_DROP)
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script();
        let clause =
            StandardClause::<(), (), RawArgs>::new("advance".to_string(), script, vec![], None);
        Arc::new(
            StandardP2TR::new(
                name,
                crate::nums_key(),
                &(),
                ClauseTree::leaf(Arc::new(clause)),
            )
            .unwrap(),
        )
    }

    fn transaction(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        }
    }

    #[test]
    fn graph_snapshot_links_children_and_deduplicates_terminal_outputs_and_transactions() {
        let parent_contract = contract("Parent", 1);
        let child_contract = contract("Child", 2);
        let parent_spk = parent_contract.script_pubkey(None).unwrap();
        let child_spk = child_contract.script_pubkey(None).unwrap();

        let funding = transaction(
            vec![],
            vec![
                TxOut {
                    value: Amount::from_sat(30_000),
                    script_pubkey: parent_spk.clone(),
                },
                TxOut {
                    value: Amount::from_sat(20_000),
                    script_pubkey: parent_spk,
                },
            ],
        );
        let parent_outpoint = OutPoint {
            txid: funding.compute_txid(),
            vout: 0,
        };
        let second_parent_outpoint = OutPoint {
            txid: funding.compute_txid(),
            vout: 1,
        };
        let spend = transaction(
            vec![
                TxIn {
                    previous_output: parent_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[vec![0xaa]]),
                },
                TxIn {
                    previous_output: second_parent_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[vec![0xbb]]),
                },
            ],
            vec![
                TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: child_spk,
                },
                TxOut {
                    value: Amount::from_sat(9_000),
                    script_pubkey: ScriptBuf::new_op_return([0x42]),
                },
            ],
        );
        let child_outpoint = OutPoint {
            txid: spend.compute_txid(),
            vout: 0,
        };

        let parent = Rc::new(RefCell::new(
            ContractInstance::new(parent_contract.clone(), None).unwrap(),
        ));
        parent
            .borrow_mut()
            .mark_funded(parent_outpoint, funding.clone());
        let second_parent = Rc::new(RefCell::new(
            ContractInstance::new(parent_contract, None).unwrap(),
        ));
        second_parent
            .borrow_mut()
            .mark_funded(second_parent_outpoint, funding.clone());
        let child = Rc::new(RefCell::new(
            ContractInstance::new(child_contract, None).unwrap(),
        ));
        child
            .borrow_mut()
            .mark_funded(child_outpoint, spend.clone());
        parent
            .borrow_mut()
            .mark_spent(spend.clone(), 0, "advance".to_string(), Vec::new());
        parent.borrow_mut().add_output(Rc::clone(&child));
        second_parent
            .borrow_mut()
            .mark_spent(spend.clone(), 1, "advance".to_string(), Vec::new());
        second_parent.borrow_mut().add_output(Rc::clone(&child));

        let snapshot = snapshot_instances(&[parent, second_parent, child], Network::Regtest);
        assert_eq!(snapshot.instances.len(), 3);
        assert_eq!(snapshot.instances[0].child_indices, vec![2]);
        assert_eq!(snapshot.instances[1].child_indices, vec![2]);
        assert_eq!(snapshot.instances[0].terminal_outpoints.len(), 1);
        assert_eq!(
            snapshot.instances[0].terminal_outpoints,
            snapshot.instances[1].terminal_outpoints
        );
        assert_eq!(snapshot.terminal_utxos.len(), 1);
        assert_eq!(snapshot.terminal_utxos[0].vout, 1);
        assert_eq!(snapshot.terminal_utxos[0].amount_sat, 9_000);
        assert_eq!(snapshot.transactions.len(), 2);
        assert_eq!(snapshot.instances[0].params_debug.as_deref(), Some("()"));
        assert!(
            snapshot
                .transactions
                .iter()
                .all(|tx| !tx.raw_hex.is_empty())
        );

        let json = serde_json::to_string(&snapshot).unwrap();
        assert_eq!(
            serde_json::from_str::<ManagerSnapshot>(&json).unwrap(),
            snapshot
        );
    }
}
