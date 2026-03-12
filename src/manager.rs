use std::collections::{HashMap, HashSet};
use std::thread::sleep;
use std::time::Duration;

use bitcoin::{Amount, OutPoint, Script, Sequence, Transaction, TxOut, Txid};
use bitcoincore_rpc::{Client, RpcApi};

use crate::{
    contracts::{ClauseArgs, Contract, ContractInstance, ContractInstanceStatus, StateData},
    signer::SignerMap,
    tx,
};

/// Polls the blockchain for an output matching the given scriptPubKey.
pub fn wait_for_output(
    rpc: &Client,
    script_pub_key: &Script,
    poll_interval: f64,
    starting_height: Option<u64>,
    txid: Option<Txid>,
) -> Result<(OutPoint, u64), Box<dyn std::error::Error>> {
    let mut last_block_height = match starting_height {
        Some(h) => h.saturating_sub(1),
        None => rpc.get_block_count()?,
    };

    loop {
        let current_block_height = rpc.get_block_count()?;
        if last_block_height > current_block_height {
            sleep(Duration::from_secs_f64(poll_interval));
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
        sleep(Duration::from_secs_f64(poll_interval));
    }
}

/// Polls the blockchain for a transaction spending the given outpoint.
pub fn wait_for_spending_tx(
    rpc: &Client,
    outpoint: OutPoint,
    starting_height: u64,
    poll_interval: f64,
) -> Result<(Transaction, usize, u64), Box<dyn std::error::Error>> {
    let mut last_block_height = starting_height;

    loop {
        let current_block_height = rpc.get_block_count()?;
        if last_block_height > current_block_height {
            sleep(Duration::from_secs_f64(poll_interval));
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
        sleep(Duration::from_secs_f64(poll_interval));
    }
}

/// Polls the blockchain for a transaction spending ALL of the given outpoints.
fn wait_for_spending_transaction(
    rpc: &Client,
    outpoints: &HashSet<OutPoint>,
    starting_height: u64,
    poll_interval: f64,
) -> Result<(Transaction, u64), Box<dyn std::error::Error>> {
    let mut last_block_height = starting_height;

    loop {
        let current_block_height = rpc.get_block_count()?;
        if last_block_height > current_block_height {
            sleep(Duration::from_secs_f64(poll_interval));
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
                        return Err(format!(
                            "Transaction {} spends some but not all outpoints",
                            tx.compute_txid()
                        )
                        .into());
                    }
                }
            }
        }

        last_block_height = current_block_height + 1;
        sleep(Duration::from_secs_f64(poll_interval));
    }
}

/// Options for terminal clause spends (outputs and sequence).
#[derive(Debug, Clone, Default)]
pub struct SpendOptions<'a> {
    pub outputs: Option<&'a [TxOut]>,
    pub sequence: Option<Sequence>,
}

/// Manages contract instances. Works entirely with concrete types.
pub struct ContractManager<'a> {
    pub rpc: &'a Client,
    pub instances: Vec<ContractInstance>,
    pub poll_interval: f64,
    pub automine: bool,
}

impl<'a> ContractManager<'a> {
    pub fn new(rpc: &'a Client, poll_interval: f64, automine: bool) -> Self {
        Self {
            rpc,
            instances: vec![],
            poll_interval,
            automine,
        }
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

    /// Creates a new contract instance, funds it on-chain, and adds it to the manager.
    /// Returns the index of the new instance.
    pub fn fund_instance(
        &mut self,
        contract: Contract,
        data: StateData,
        amount: u64,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut inst = ContractInstance::new(contract, data);
        let address = inst.get_address();

        let starting_height = self.rpc.get_block_count()?;

        let amount_btc = Amount::from_sat(amount);
        let txid = self
            .rpc
            .send_to_address(&address, amount_btc, None, None, None, None, None, None)?;

        if self.automine {
            self.mine_blocks(1)?;
        }

        let (outpoint, last_height) = wait_for_output(
            self.rpc,
            address.script_pubkey().as_script(),
            self.poll_interval,
            Some(starting_height),
            Some(txid),
        )?;

        let funding_tx = self.rpc.get_raw_transaction(&txid, None)?;

        inst.outpoint = Some(outpoint);
        inst.status = ContractInstanceStatus::Funded;
        inst.funding_tx = Some(funding_tx);
        inst.last_height = Some(last_height);

        Ok(self.add_instance(inst))
    }

    /// Spends a single instance using the given clause and args.
    /// Signs with provided signers, broadcasts, waits for confirmation,
    /// and returns indices of new instances created from the clause outputs.
    pub fn spend_instance(
        &mut self,
        instance_idx: usize,
        clause_name: &str,
        args: ClauseArgs,
        signers: Option<&SignerMap>,
        outputs: Option<&[TxOut]>,
        sequence: Option<Sequence>,
    ) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
        let spend_tx = tx::get_spend_tx(
            &self.instances,
            instance_idx,
            clause_name,
            args,
            outputs,
            signers,
            sequence.unwrap_or(Sequence::ZERO),
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
    ) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
        let cur_height = self.rpc.get_block_count()?;

        for &idx in instance_indices {
            if self.instances[idx].status != ContractInstanceStatus::Funded {
                return Err("All instances should be FUNDED".into());
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
        outputs: Option<&[TxOut]>,
        signers: Option<&SignerMap>,
        sequence: Option<Sequence>,
    ) -> Result<Transaction, Box<dyn std::error::Error>> {
        Ok(tx::get_spend_tx(
            &self.instances,
            instance_idx,
            clause_name,
            args,
            outputs,
            signers,
            sequence.unwrap_or(Sequence::ZERO),
        )?)
    }

    /// Builds a multi-input spend transaction, signs, broadcasts, and waits for confirmation.
    /// Each element of `spends` is (instance_idx, clause_name, args).
    /// Returns indices of new instances created from clause outputs.
    pub fn spend_instances(
        &mut self,
        spends: Vec<(usize, &str, ClauseArgs)>,
        signers: Option<&SignerMap>,
        output_amounts: HashMap<usize, u64>,
        sequence: Sequence,
    ) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
        let spend_specs: Vec<tx::SpendSpec> = spends
            .iter()
            .map(|(idx, clause_name, args)| tx::SpendSpec {
                instance_idx: *idx,
                clause_name: clause_name.to_string(),
                args: args.clone(),
                sequence,
            })
            .collect();

        let (mut spend_tx, sighashes) =
            tx::create_spend_tx(&self.instances, &spend_specs, &output_amounts, &[])?;

        for (i, (idx, clause_name, args)) in spends.into_iter().enumerate() {
            let mut args = args;
            spend_tx.input[i].witness = tx::build_witness(
                &self.instances[idx],
                clause_name,
                &mut args,
                &sighashes[i],
                signers,
            )?;
        }

        let instance_indices: Vec<usize> = spend_specs.iter().map(|s| s.instance_idx).collect();
        self.spend_and_wait(&instance_indices, &spend_tx)
    }

    /// Waits for one or more instances to be spent, processes the spending transaction,
    /// and returns indices of new instances added to the manager.
    pub fn wait_for_spend(
        &mut self,
        instance_indices: &[usize],
        starting_height: u64,
    ) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
        // Collect outpoints
        let outpoints_set: HashSet<OutPoint> = instance_indices
            .iter()
            .map(|&idx| {
                self.instances[idx]
                    .outpoint
                    .ok_or("Instance has no outpoint")
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
