use std::collections::HashMap;

use bitcoin::{Amount, Sequence, TxOut};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use mattrs::{
    contracts::{ClauseArgs, ContractInstanceStatus},
    hub::ram::{make_ram, proof_to_arg},
    manager::ContractManager,
    merkle::MerkleTree,
    report::{format_tx_markdown, Report},
    sha256, tx,
};

const AMOUNT: u64 = 20_000;

fn get_rpc_client(wallet_name: &str) -> Client {
    let rpc_url =
        std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_user =
        std::env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "rpcuser".to_string());
    let rpc_pass =
        std::env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "rpcpass".to_string());

    let url = format!("{}/wallet/{}", rpc_url, wallet_name);
    Client::new(&url, Auth::UserPass(rpc_user, rpc_pass)).expect("Failed to create RPC client")
}

fn ensure_funds(client: &Client) {
    let balance = client.get_balance(None, None).unwrap();
    if balance < Amount::from_sat(100_000_000) {
        let addr = client
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();
        client.generate_to_address(101, &addr).unwrap();
    }
}

/// Build a terminal spend tx for the "withdraw" clause (no CCV outputs).
fn build_withdraw_tx(
    manager: &ContractManager,
    instance_idx: usize,
    args: ClauseArgs,
) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
    // Spend to a dummy P2WSH output
    let dummy_script = bitcoin::ScriptBuf::new_witness_program(
        &bitcoin::WitnessProgram::new(
            bitcoin::WitnessVersion::V0,
            &[0x42u8; 32],
        )
        .unwrap(),
    );
    let outputs = vec![TxOut {
        script_pubkey: dummy_script,
        value: Amount::from_sat(AMOUNT),
    }];

    let spend_spec = tx::SpendSpec {
        instance_idx,
        clause_name: "withdraw".to_string(),
        args: args.clone(),
    };

    let (mut spend_tx, _) =
        tx::create_spend_tx(&manager.instances, &[spend_spec], &HashMap::new(), &outputs)?;

    spend_tx.lock_time = bitcoin::absolute::LockTime::ZERO;
    spend_tx.input[0].sequence = Sequence::ZERO;
    spend_tx.version = bitcoin::transaction::Version::TWO;

    // Build witness (no signers needed)
    let inst = &manager.instances[instance_idx];
    let mut args_mut = args;
    let funding_tx = inst.funding_tx.as_ref().unwrap();
    let outpoint = inst.outpoint.unwrap();
    let spent_utxos = vec![funding_tx.output[outpoint.vout as usize].clone()];

    let leaf_script = inst.contract.get_clause("withdraw").unwrap().script.clone();

    let mut sighash_cache = bitcoin::sighash::SighashCache::new(spend_tx.clone());
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&spent_utxos),
            bitcoin::TapLeafHash::from_script(&leaf_script, bitcoin::taproot::LeafVersion::TapScript),
            bitcoin::TapSighashType::Default,
        )
        .map(|h| bitcoin::hashes::Hash::to_byte_array(h))
        .map_err(|e| format!("Sighash failed: {}", e))?;

    spend_tx.input[0].witness =
        tx::build_witness(inst, "withdraw", &mut args_mut, &sighash, None)?;

    Ok(spend_tx)
}

#[test]
fn test_withdraw() -> Result<(), Box<dyn std::error::Error>> {
    let client = get_rpc_client("testwallet");
    ensure_funds(&client);

    for size in [8, 16] {
        for &leaf_index in &[0usize, 1, 4, size - 2, size - 1] {
            let leaves: Vec<[u8; 32]> = (0..size).map(|i| sha256(&[i as u8])).collect();
            let mt = MerkleTree::new(leaves.clone());

            let ram = make_ram(size);
            let state = mt.root().to_vec();
            let mut manager = ContractManager::new(&client, 0.1, true);
            let ram_idx = manager.fund_instance(ram, state, AMOUNT)?;

            let proof = mt.prove_leaf(leaf_index);
            let mut args: ClauseArgs = HashMap::new();
            args.insert("merkle_proof".to_string(), proof_to_arg(&proof));
            args.insert("merkle_root".to_string(), mt.root().to_vec());

            let spend_tx = build_withdraw_tx(&manager, ram_idx, args)?;
            let result = manager.spend_and_wait(&[ram_idx], &spend_tx)?;

            assert_eq!(result.len(), 0, "withdraw should be terminal");
            assert_eq!(
                manager.instances[ram_idx].status,
                ContractInstanceStatus::Spent
            );
            println!(
                "test_withdraw passed: size={}, leaf_index={}",
                size, leaf_index
            );
        }
    }

    Ok(())
}

#[test]
fn test_write() -> Result<(), Box<dyn std::error::Error>> {
    let client = get_rpc_client("testwallet");
    ensure_funds(&client);

    let size = 8;
    let leaf_index = 5;
    let new_value = sha256(b"now this is different");

    let leaves: Vec<[u8; 32]> = (0..size).map(|i| sha256(&[i as u8])).collect();
    let mt = MerkleTree::new(leaves.clone());

    let ram = make_ram(size);
    let state = mt.root().to_vec();
    let mut manager = ContractManager::new(&client, 0.1, true);
    let ram_idx = manager.fund_instance(ram, state, AMOUNT)?;

    let proof = mt.prove_leaf(leaf_index);
    let mut args: ClauseArgs = HashMap::new();
    args.insert("merkle_proof".to_string(), proof_to_arg(&proof));
    args.insert("new_value".to_string(), new_value.to_vec());
    args.insert("merkle_root".to_string(), mt.root().to_vec());

    let new_indices = manager.spend_instance(ram_idx, "write", args, None)?;

    assert_eq!(new_indices.len(), 1);
    let new_idx = new_indices[0];
    assert_eq!(
        manager.instances[new_idx].contract.name(),
        format!("RAM_{}", size)
    );

    // Verify the new state matches the modified leaves
    let mut modified_leaves = leaves;
    modified_leaves[leaf_index] = new_value;
    let expected_root = MerkleTree::new(modified_leaves).root();
    assert_eq!(
        manager.instances[new_idx].data,
        expected_root.to_vec()
    );

    println!("test_write passed!");
    Ok(())
}

#[test]
fn test_write_loop() -> Result<(), Box<dyn std::error::Error>> {
    let client = get_rpc_client("testwallet");
    ensure_funds(&client);

    let size = 8usize;
    let mut leaves: Vec<[u8; 32]> = (0..size).map(|i| sha256(&[i as u8])).collect();

    let ram = make_ram(size);
    let state = MerkleTree::new(leaves.clone()).root().to_vec();
    let mut manager = ContractManager::new(&client, 0.1, true);
    let mut cur_idx = manager.fund_instance(ram, state, AMOUNT)?;

    let mut report = Report::new();

    for i in 0..16usize {
        let leaf_index = i % size;
        let new_value = sha256(&[(100 + i) as u8]);

        let mt = MerkleTree::new(leaves.clone());
        let proof = mt.prove_leaf(leaf_index);

        let mut args: ClauseArgs = HashMap::new();
        args.insert("merkle_proof".to_string(), proof_to_arg(&proof));
        args.insert("new_value".to_string(), new_value.to_vec());
        args.insert("merkle_root".to_string(), mt.root().to_vec());

        let new_indices = manager.spend_instance(cur_idx, "write", args, None)?;

        assert_eq!(new_indices.len(), 1);
        let new_idx = new_indices[0];
        assert_eq!(
            manager.instances[new_idx].contract.name(),
            format!("RAM_{}", size)
        );

        // Update local leaves
        leaves[leaf_index] = new_value;
        let expected_root = MerkleTree::new(leaves.clone()).root();
        assert_eq!(
            manager.instances[new_idx].data,
            expected_root.to_vec(),
            "Root mismatch at iteration {}",
            i
        );

        report.write(
            "RAM write loop",
            format_tx_markdown(
                manager.instances[cur_idx].spending_tx.as_ref().unwrap(),
                &format!("Write iteration {} (leaf {})", i, leaf_index),
            ),
        );

        cur_idx = new_idx;
        println!("write_loop iteration {} passed (leaf {})", i, leaf_index);
    }

    report.finalize("reports/report_ram.md");
    println!("test_write_loop passed!");
    Ok(())
}
