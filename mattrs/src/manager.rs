use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
    thread::sleep,
    time::Duration,
};

use bitcoin::{Amount, OutPoint, Script, Transaction, TxOut, Txid, XOnlyPublicKey};
use bitcoincore_rpc::{Client, RpcApi};

use crate::{
    contract_instance::{ContractInstance, ContractInstanceStatus},
    contracts::{ClauseArguments, Contract, ContractState},
    signer::SchnorrSigner,
    tx::{get_spend_tx, process_spending_transaction},
};

/// Waits for a specific output on the Bitcoin blockchain.
///
/// # Arguments
///
/// * `rpc_connection` - An authenticated RPC client to interact with Bitcoin Core.
/// * `script_pub_key` - The scriptPubKey to search for in transaction outputs.
/// * `poll_interval` - Time in seconds between each poll of the blockchain.
/// * `starting_height` - Optional starting block height. If `None`, starts from the current block height.
/// * `txid` - Optional transaction ID to filter transactions. If `None`, all transactions are considered.
/// * `min_amount` - Optional minimum amount in satoshis that the output must have.
///
/// # Returns
///
/// A tuple containing the found `OutPoint` and the block height where it was found.
///
/// # Errors
///
/// Returns an error if there are issues communicating with the RPC or processing the data.
pub async fn wait_for_output(
    rpc_connection: &Client,
    script_pub_key: &Script,
    poll_interval: f64,
    starting_height: Option<u64>,
    txid: Option<Txid>,
    min_amount: Option<u64>,
) -> Result<(OutPoint, u64), Box<dyn std::error::Error>> {
    // Initialize the last block height
    let mut last_block_height = if let Some(height) = starting_height {
        height.saturating_sub(1)
    } else {
        rpc_connection
            .get_block_count()
            .expect("Failed to retrieve current block count")
    };

    loop {
        // Retrieve the current block height
        let current_block_height = match rpc_connection.get_block_count() {
            Ok(height) => height,
            Err(e) => {
                eprintln!("Error fetching block count: {}", e);
                sleep(Duration::from_secs_f64(poll_interval));
                continue;
            }
        };

        // If the last checked block is ahead of the current, wait and retry
        if last_block_height > current_block_height {
            sleep(Duration::from_secs_f64(poll_interval));
            continue;
        }

        // Fetch the block hash for the current height
        let block_hash = match rpc_connection.get_block_hash(last_block_height) {
            Ok(hash) => hash,
            Err(e) => {
                eprintln!(
                    "Error fetching block hash at height {}: {}",
                    last_block_height, e
                );
                sleep(Duration::from_secs_f64(poll_interval));
                continue;
            }
        };

        // Retrieve verbose block information
        let block = match rpc_connection.get_block(&block_hash) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Error fetching block data for hash {}: {}", block_hash, e);
                sleep(Duration::from_secs_f64(poll_interval));
                continue;
            }
        };

        // Iterate through each transaction in the block
        for tx in block.txdata {
            // If a specific txid is provided, skip transactions that don't match
            if let Some(ref target_txid) = txid {
                if tx.compute_txid() != *target_txid {
                    continue;
                }
            }

            // Iterate through each output in the transaction
            for (vout_index, vout) in tx.output.iter().enumerate() {
                // If a minimum amount is specified, skip outputs below this threshold
                if let Some(min_amt) = min_amount {
                    // Convert BTC to satoshis
                    let value_sats = vout.value.to_sat();
                    if value_sats < min_amt {
                        continue;
                    }
                }

                let spk = &vout.script_pubkey;

                // Check if the scriptPubKey matches
                if *spk == *script_pub_key {
                    // Create the OutPoint
                    let outpoint = OutPoint {
                        txid: tx.compute_txid(),
                        vout: vout_index as u32,
                    };
                    return Ok((outpoint, last_block_height));
                }
            }
        }

        // Move to the next block
        last_block_height += 1;

        // Sleep before the next poll
        sleep(Duration::from_secs_f64(poll_interval));
    }
}

/// Waits for a transaction that spends the specified outpoint.
///
/// # Arguments
/// - `rpc_connection`: The RPC client to interact with Bitcoin Core.
/// - `outpoint`: The outpoint to monitor for spending.
/// - `starting_height`: Optional starting block height. If `None`, starts from the current block height.
/// - `poll_interval`: Time in seconds between each poll of the blockchain. It must be positive.
///
/// # Returns
/// A tuple containing the found `Transaction`, the input index (`usize`) where the outpoint was spent,
/// and the block height where it was found.
///
/// # Errors
/// Returns an error if there are issues communicating with the RPC or processing the data.
pub async fn wait_for_spending_tx(
    rpc_connection: &Client,
    outpoint: OutPoint,
    starting_height: Option<u64>,
    poll_interval: f64,
) -> Result<(Transaction, usize, u64), Box<dyn std::error::Error>> {
    if poll_interval <= 0.0 {
        return Err("Poll interval must be greater than zero".into());
    }

    // Initialize the last block height
    let mut last_block_height = if let Some(height) = starting_height {
        height.saturating_sub(1)
    } else {
        rpc_connection
            .get_block_count()
            .expect("Failed to retrieve current block count")
    };

    loop {
        // Retrieve the current block height
        let current_block_height = match rpc_connection.get_block_count() {
            Ok(height) => height,
            Err(e) => {
                eprintln!("Error fetching block count: {}", e);
                sleep(Duration::from_secs_f64(poll_interval));
                continue;
            }
        };

        // If the last checked block is ahead of the current, wait and retry
        if last_block_height > current_block_height {
            sleep(Duration::from_secs_f64(poll_interval));
            continue;
        }

        // Fetch blocks from last_block_height up to current_block_height
        for height in last_block_height..=current_block_height {
            let block_hash = match rpc_connection.get_block_hash(height) {
                Ok(hash) => hash,
                Err(e) => {
                    eprintln!("Error fetching block hash at height {}: {}", height, e);
                    sleep(Duration::from_secs_f64(poll_interval));
                    continue;
                }
            };

            // Retrieve the block
            let block = match rpc_connection.get_block(&block_hash) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error fetching block data for hash {}: {}", block_hash, e);
                    sleep(Duration::from_secs_f64(poll_interval));
                    continue;
                }
            };

            // Iterate over each transaction in the block
            for tx in block.txdata {
                // Iterate over each input in the transaction
                for (vin_index, vin) in tx.input.iter().enumerate() {
                    if vin.previous_output == outpoint {
                        return Ok((tx, vin_index, height));
                    }
                }
            }
        }

        // Update the last checked block height
        last_block_height = current_block_height + 1;

        // Sleep before the next poll
        sleep(Duration::from_secs_f64(poll_interval));
    }
}

/// Waits for a transaction that spends all the specified outpoints.
///
/// # Arguments
/// - `rpc_connection`: The RPC client to interact with Bitcoin Core.
/// - `outpoints`: A set of outpoints to monitor for spending.
/// - `starting_height`: The block height to start monitoring from.
/// - `poll_interval`: Time in seconds between each poll of the blockchain.
///
/// # Returns
/// A tuple containing the found `Transaction` and the block height where it was found.
///
/// # Errors
/// Returns an error if a transaction is found that spends some but not all of the outpoints.
pub async fn wait_for_spending_transaction(
    rpc_connection: &Client,
    outpoints: HashSet<OutPoint>,
    starting_height: u64,
    poll_interval: f64,
) -> Result<(Transaction, u64), Box<dyn std::error::Error>> {
    let mut last_block_height = starting_height;

    loop {
        // Retrieve the current block height
        let current_block_height = match rpc_connection.get_block_count() {
            Ok(height) => height,
            Err(e) => {
                eprintln!("Error fetching block count: {}", e);
                sleep(Duration::from_secs_f64(poll_interval));
                continue;
            }
        };

        if last_block_height > current_block_height {
            sleep(Duration::from_secs_f64(poll_interval));
            continue;
        }

        for height in last_block_height..=current_block_height {
            let block_hash = match rpc_connection.get_block_hash(height) {
                Ok(hash) => hash,
                Err(e) => {
                    eprintln!("Error fetching block hash at height {}: {}", height, e);
                    sleep(Duration::from_secs_f64(poll_interval));
                    continue;
                }
            };

            let block = match rpc_connection.get_block(&block_hash) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error fetching block data for hash {}: {}", block_hash, e);
                    sleep(Duration::from_secs_f64(poll_interval));
                    continue;
                }
            };

            for tx in block.txdata {
                let mut tx_spends: HashSet<OutPoint> = HashSet::new();

                for vin in tx.input.iter() {
                    if outpoints.contains(&vin.previous_output) {
                        tx_spends.insert(vin.previous_output.clone());
                    }
                }

                if !tx_spends.is_empty() {
                    if tx_spends == outpoints {
                        // Transaction spends all outpoints
                        return Ok((tx, height));
                    } else {
                        // Transaction spends some, but not all, outpoints
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

pub struct ContractManager<'a> {
    rpc: &'a Client,
    instances: Vec<Rc<RefCell<ContractInstance>>>,
    poll_interval: f64,
    automine: bool,
}

impl<'a> ContractManager<'a> {
    pub fn new(rpc: &'a Client, poll_interval: f64, automine: bool) -> Self {
        if poll_interval <= 0.0 {
            panic!("Poll interval must be greater than zero");
        }

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

    pub fn get_instances(&self) -> Vec<Rc<RefCell<ContractInstance>>> {
        self.instances.clone()
    }

    pub fn add_instance(&mut self, ci: Rc<RefCell<ContractInstance>>) {
        self.instances.push(ci);
    }

    pub async fn fund_instance(
        &mut self,
        contract: Box<dyn Contract>,
        state: Option<Box<dyn ContractState>>,
        amount: u64,
    ) -> Result<Rc<RefCell<ContractInstance>>, Box<dyn std::error::Error>> {
        // Create a new contract instance
        let mut inst = ContractInstance::new(contract);
        if let Some(st) = state {
            inst.set_state(st);
        }
        let rc_inst = Rc::new(RefCell::new(inst));

        // Add the new contract instance to the manager
        self.add_instance(Rc::clone(&rc_inst));

        // 1) send transaction funding the instance
        let address = rc_inst.borrow().get_address();

        // height before the transaction is sent
        let starting_height = self.rpc.get_block_count()?;

        // Send the specified amount to the address
        let amount_btc = Amount::from_sat(amount);
        let txid = self
            .rpc
            .send_to_address(&address, amount_btc, None, None, None, None, None, None)?;

        if self.automine {
            // mine a block
            let addr = self.rpc.get_new_address(None, None)?.assume_checked();
            self.rpc.generate_to_address(1, &addr)?;
        }

        let (outpoint, last_height) = wait_for_output(
            self.rpc,
            &rc_inst.borrow().get_script().as_script(),
            0.1,
            Some(starting_height),
            Some(txid),
            Some(amount_btc.to_sat()),
        )
        .await?;

        let tx = self.rpc.get_raw_transaction(&txid, None)?;

        // Update the contract instance
        {
            let mut inst_mut = rc_inst.borrow_mut();
            inst_mut.outpoint = Some(outpoint);
            inst_mut.status = ContractInstanceStatus::Funded;
            inst_mut.funding_tx = Some(tx);
            inst_mut.last_height = Some(last_height);
        }

        // Return the Rc pointer to the newly created ContractInstance
        Ok(rc_inst)
    }

    pub async fn spend_instance(
        &mut self,
        instance: Rc<RefCell<ContractInstance>>,
        clause_name: &str,
        clause_args: Box<dyn ClauseArguments>,
        outputs: Option<Vec<TxOut>>,
        signers: Option<&HashMap<XOnlyPublicKey, Box<dyn SchnorrSigner>>>,
    ) -> Result<Vec<Rc<RefCell<ContractInstance>>>, Box<dyn std::error::Error>> {
        let spend_tx = get_spend_tx(&instance, clause_name, clause_args, outputs, signers)?;

        // send transaction
        self.rpc.send_raw_transaction(&spend_tx)?;

        // height before the transaction is sent
        let starting_height = self.rpc.get_block_count()?;

        if self.automine {
            // mine a block
            let addr = self.rpc.get_new_address(None, None)?.assume_checked();
            self.rpc.generate_to_address(1, &addr)?;
        }

        // wait for transaction to confirm and compute the next outputs and compute the next instances
        self.wait_for_spend(&[&instance], starting_height).await
    }

    pub async fn spend_and_wait(
        &mut self,
        instances: &[&Rc<RefCell<ContractInstance>>],
        tx: &Transaction,
    ) -> Result<Vec<Rc<RefCell<ContractInstance>>>, Box<dyn std::error::Error>> {
        let cur_height = self.rpc.get_block_count()?;

        for instance in instances.iter() {
            if instance.borrow().status != ContractInstanceStatus::Funded {
                return Err("Unexpected status: all instances should be FUNDED".into());
            }
        }
        for instance in instances {
            instance.borrow_mut().last_height = Some(cur_height);
        }

        self.rpc.send_raw_transaction(tx)?;

        if self.automine {
            self.mine_blocks(1)?;
        }
        self.wait_for_spend(instances, cur_height).await
    }

    /// Waits for one or more contract instances to be spent and processes the resulting transactions
    /// to update the contract states and possibly create new contract instances.
    ///
    /// This method polls the node until it finds a transaction that spends all the specified contract
    /// instances. When such a transaction is found, it updates the contract instances' states to
    /// `SPENT`, decodes the spending transactions to extract relevant data (such as the executed
    /// clause and its arguments), and creates new contract instances as dictated by the contract logic.
    ///
    /// # Parameters
    /// - `instances`: A slice of contract instances to monitor for spending transactions.
    /// - `starting_height`: The block height to start polling from.
    ///
    /// # Returns
    /// A vector of new contract instances created as a result of the spending transactions.
    ///
    /// # Errors
    /// Returns an error if any of the specified contract instances is not in the `FUNDED` state,
    /// if the spending transaction references a clause that is not found in the contract, or if
    /// the spending transaction spends some, but not all the given instances.
    pub async fn wait_for_spend(
        &mut self,
        instances: &[&Rc<RefCell<ContractInstance>>],
        starting_height: u64,
    ) -> Result<Vec<Rc<RefCell<ContractInstance>>>, Box<dyn std::error::Error>> {
        let outpoints_set: HashSet<OutPoint> = instances
            .iter()
            .map(|instance_rc| {
                let instance = instance_rc.borrow();
                instance
                    .outpoint
                    .as_ref()
                    .ok_or("Instance has no outpoint")
                    .map(|op| op.clone())
            })
            .collect::<Result<HashSet<_>, _>>()?;

        let (tx, last_height) = wait_for_spending_transaction(
            self.rpc,
            outpoints_set,
            starting_height,
            self.poll_interval,
        )
        .await?;

        let result = process_spending_transaction(instances, &tx, last_height)?;

        // Add the new instances to the manager
        for instance in &result {
            self.add_instance(instance.clone());
        }

        Ok(result)
    }
}
