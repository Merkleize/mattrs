use std::collections::{HashMap, HashSet};
use std::thread::sleep;
use std::time::Duration;

use bitcoin::{Amount, OutPoint, Script, Sequence, Transaction, TxOut, Txid};
use bitcoincore_rpc::{Client, RpcApi};
use thiserror::Error;

use crate::{
    contracts::{ClauseArgs, Contract, ContractInstance, ContractInstanceStatus, StateData},
    signer::SignerMap,
    tx::{self, SpendTxError},
};

#[derive(Error, Debug)]
pub enum ManagerError {
    #[error(transparent)]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error(transparent)]
    SpendTx(#[from] SpendTxError),
    #[error("Instance {0} is not in FUNDED state")]
    NotFunded(usize),
    #[error("Instance {0} has no outpoint")]
    NoOutpoint(usize),
    #[error("{0}")]
    Other(String),
}

/// Polls the blockchain for an output matching the given scriptPubKey.
fn poll_for_output(
    rpc: &Client,
    script_pub_key: &Script,
    poll_interval: Duration,
    starting_height: Option<u64>,
    txid: Option<Txid>,
) -> Result<(OutPoint, u64), ManagerError> {
    let mut last_block_height = match starting_height {
        Some(h) => h.saturating_sub(1),
        None => rpc.get_block_count()?,
    };

    loop {
        let current_block_height = rpc.get_block_count()?;
        if last_block_height > current_block_height {
            sleep(poll_interval);
            continue;
        }

        let block_hash = rpc.get_block_hash(last_block_height)?;
        let block = rpc.get_block(&block_hash)?;

        for tx in &block.txdata {
            if let Some(target_txid) = txid {
                if tx.compute_txid() != target_txid {
                    continue;
                }
            }
            for (vout, output) in tx.output.iter().enumerate() {
                if output.script_pubkey.as_script() == script_pub_key {
                    let outpoint = OutPoint {
                        txid: tx.compute_txid(),
                        vout: vout as u32,
                    };
                    return Ok((outpoint, last_block_height));
                }
            }
        }

        last_block_height += 1;
        sleep(poll_interval);
    }
}

/// Polls the blockchain for a transaction spending the given outpoint.
pub fn wait_for_spending_tx(
    rpc: &Client,
    outpoint: OutPoint,
    starting_height: u64,
    poll_interval: Duration,
) -> Result<(Transaction, usize, u64), ManagerError> {
    let mut last_block_height = starting_height;

    loop {
        let current_block_height = rpc.get_block_count()?;
        if last_block_height > current_block_height {
            sleep(poll_interval);
            continue;
        }

        for height in last_block_height..=current_block_height {
            let block_hash = rpc.get_block_hash(height)?;
            let block = rpc.get_block(&block_hash)?;

            for tx in block.txdata {
                for (vin_index, vin) in tx.input.iter().enumerate() {
                    if vin.previous_output == outpoint {
                        return Ok((tx, vin_index, height));
                    }
                }
            }
        }

        last_block_height = current_block_height + 1;
        sleep(poll_interval);
    }
}

/// Polls the blockchain for a transaction spending ALL of the given outpoints.
fn wait_for_spending_transaction(
    rpc: &Client,
    outpoints: &HashSet<OutPoint>,
    starting_height: u64,
    poll_interval: Duration,
) -> Result<(Transaction, u64), ManagerError> {
    let mut last_block_height = starting_height;

    loop {
        let current_block_height = rpc.get_block_count()?;
        if last_block_height > current_block_height {
            sleep(poll_interval);
            continue;
        }

        for height in last_block_height..=current_block_height {
            let block_hash = rpc.get_block_hash(height)?;
            let block = rpc.get_block(&block_hash)?;

            for tx in block.txdata {
                let tx_spends: HashSet<OutPoint> = tx
                    .input
                    .iter()
                    .filter(|vin| outpoints.contains(&vin.previous_output))
                    .map(|vin| vin.previous_output)
                    .collect();

                if !tx_spends.is_empty() {
                    if &tx_spends == outpoints {
                        return Ok((tx, height));
                    } else {
                        return Err(ManagerError::Other(format!(
                            "Transaction {} spends some but not all outpoints",
                            tx.compute_txid()
                        )));
                    }
                }
            }
        }

        last_block_height = current_block_height + 1;
        sleep(poll_interval);
    }
}

/// Options for spending: signers, explicit outputs, and sequence.
#[derive(Debug, Clone, Default)]
pub struct SpendOptions<'a> {
    pub signers: Option<&'a SignerMap>,
    pub outputs: Option<&'a [TxOut]>,
    pub sequence: Option<Sequence>,
}

/// Re-export SpendSpec from tx module.
pub use tx::SpendSpec;

/// Manages contract instances. Works entirely with concrete types.
pub struct ContractManager<'a> {
    pub rpc: &'a Client,
    pub(crate) instances: Vec<ContractInstance>,
    pub poll_interval: Duration,
    pub automine: bool,
}

impl<'a> ContractManager<'a> {
    pub fn new(rpc: &'a Client, poll_interval: Duration, automine: bool) -> Self {
        Self {
            rpc,
            instances: vec![],
            poll_interval,
            automine,
        }
    }

    pub fn instance(&self, idx: usize) -> &ContractInstance {
        &self.instances[idx]
    }

    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    pub fn mine_blocks(&self, count: u64) -> Result<(), bitcoincore_rpc::Error> {
        let addr = self.rpc.get_new_address(None, None)?.assume_checked();
        self.rpc.generate_to_address(count, &addr)?;
        Ok(())
    }

    /// Adds a pre-built ContractInstance to the manager. Returns its index.
    pub fn add_instance(&mut self, instance: ContractInstance) -> usize {
        let idx = self.instances.len();
        self.instances.push(instance);
        idx
    }

    /// Polls for a funding output for the given instance, fetches the funding tx,
    /// and updates the instance status to Funded. Returns the instance index.
    pub fn wait_for_output(
        &mut self,
        instance_idx: usize,
        starting_height: Option<u64>,
        txid: Option<Txid>,
    ) -> Result<usize, ManagerError> {
        let spk = self.instances[instance_idx]
            .get_address()
            .script_pubkey();

        let (outpoint, last_height) = poll_for_output(
            self.rpc,
            spk.as_script(),
            self.poll_interval,
            starting_height,
            txid,
        )?;

        let funding_tx = self.rpc.get_raw_transaction(&outpoint.txid, None)?;

        self.instances[instance_idx].outpoint = Some(outpoint);
        self.instances[instance_idx].funding_tx = Some(funding_tx);
        self.instances[instance_idx].status = ContractInstanceStatus::Funded;
        self.instances[instance_idx].last_height = Some(last_height);

        Ok(instance_idx)
    }

    /// Creates a new contract instance, funds it on-chain, and adds it to the manager.
    /// Returns the index of the new instance.
    pub fn fund_instance(
        &mut self,
        contract: Contract,
        data: StateData,
        amount: Amount,
    ) -> Result<usize, ManagerError> {
        let inst = ContractInstance::new(contract, data);
        let idx = self.add_instance(inst);

        let starting_height = self.rpc.get_block_count()?;

        let address = self.instances[idx].get_address();
        let txid = self
            .rpc
            .send_to_address(&address, amount, None, None, None, None, None, None)?;

        if self.automine {
            self.mine_blocks(1)?;
        }

        self.wait_for_output(idx, Some(starting_height), Some(txid))?;

        Ok(idx)
    }

    /// Spends a single instance using the given clause and args.
    /// Signs with provided signers, broadcasts, waits for confirmation,
    /// and returns indices of new instances created from the clause outputs.
    pub fn spend_instance(
        &mut self,
        instance_idx: usize,
        clause_name: &str,
        args: ClauseArgs,
        opts: SpendOptions<'_>,
    ) -> Result<Vec<usize>, ManagerError> {
        let spend_tx = tx::get_spend_tx(
            &self.instances,
            instance_idx,
            clause_name,
            args,
            opts.outputs,
            opts.signers,
            opts.sequence.unwrap_or(Sequence::ZERO),
        )?;

        self.rpc.send_raw_transaction(&spend_tx)?;
        let starting_height = self.rpc.get_block_count()?;

        if self.automine {
            self.mine_blocks(1)?;
        }

        self.wait_for_spend(&[instance_idx], starting_height)
    }

    /// Broadcasts a pre-built transaction that spends the given instances,
    /// waits for confirmation, and returns indices of new instances.
    pub fn spend_and_wait(
        &mut self,
        instance_indices: &[usize],
        tx: &Transaction,
    ) -> Result<Vec<usize>, ManagerError> {
        let cur_height = self.rpc.get_block_count()?;

        for &idx in instance_indices {
            if self.instances[idx].status != ContractInstanceStatus::Funded {
                return Err(ManagerError::NotFunded(idx));
            }
            self.instances[idx].last_height = Some(cur_height);
        }

        self.rpc.send_raw_transaction(tx)?;

        if self.automine {
            self.mine_blocks(1)?;
        }

        self.wait_for_spend(instance_indices, cur_height)
    }

    /// Builds a fully-signed spend transaction without broadcasting.
    /// Use for cheating-attempt tests or when you need the raw tx.
    pub fn build_spend_tx(
        &self,
        instance_idx: usize,
        clause_name: &str,
        args: ClauseArgs,
        opts: SpendOptions<'_>,
    ) -> Result<Transaction, ManagerError> {
        Ok(tx::get_spend_tx(
            &self.instances,
            instance_idx,
            clause_name,
            args,
            opts.outputs,
            opts.signers,
            opts.sequence.unwrap_or(Sequence::ZERO),
        )?)
    }

    /// Builds a multi-input spend transaction, signs, broadcasts, and waits for confirmation.
    /// Returns indices of new instances created from clause outputs.
    pub fn spend_instances(
        &mut self,
        spends: &[SpendSpec],
        opts: SpendOptions<'_>,
        output_amounts: HashMap<usize, Amount>,
    ) -> Result<Vec<usize>, ManagerError> {
        let (mut spend_tx, sighashes) =
            tx::create_spend_tx(&self.instances, spends, &output_amounts, &[])?;

        for (i, spend) in spends.iter().enumerate() {
            let mut args = spend.args.clone();
            spend_tx.input[i].witness = tx::build_witness(
                &self.instances[spend.instance_idx],
                &spend.clause_name,
                &mut args,
                &sighashes[i],
                opts.signers,
            )?;
        }

        let instance_indices: Vec<usize> = spends.iter().map(|s| s.instance_idx).collect();
        self.spend_and_wait(&instance_indices, &spend_tx)
    }

    /// Waits for one or more instances to be spent, processes the spending transaction,
    /// and returns indices of new instances added to the manager.
    pub fn wait_for_spend(
        &mut self,
        instance_indices: &[usize],
        starting_height: u64,
    ) -> Result<Vec<usize>, ManagerError> {
        // Collect outpoints
        let outpoints_set: HashSet<OutPoint> = instance_indices
            .iter()
            .map(|&idx| {
                self.instances[idx]
                    .outpoint
                    .ok_or(ManagerError::NoOutpoint(idx))
            })
            .collect::<Result<HashSet<_>, _>>()?;

        let (tx, last_height) = wait_for_spending_transaction(
            self.rpc,
            &outpoints_set,
            starting_height,
            self.poll_interval,
        )?;

        let new_instances = tx::process_spending_transaction(
            &mut self.instances,
            instance_indices,
            &tx,
            last_height,
        )?;

        let mut new_indices = Vec::new();
        for inst in new_instances {
            new_indices.push(self.add_instance(inst));
        }

        Ok(new_indices)
    }
}
