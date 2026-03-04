mod common;

use std::collections::HashMap;

use bitcoin::{Amount, Sequence, TxOut};

use mattrs::{
    contracts::{ClauseArgs, ContractInstanceStatus},
    hub::ram::{make_ram, proof_to_arg},
    manager::ContractManager,
    merkle::MerkleTree,
    report::{format_tx_markdown, Report},
    sha256,
};

const AMOUNT: u64 = 20_000;

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

    common::build_terminal_spend_tx(
        manager,
        instance_idx,
        "withdraw",
        args,
        &outputs,
        None,
        Sequence::ZERO,
    )
}

#[test]
fn test_withdraw() -> Result<(), Box<dyn std::error::Error>> {
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);

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
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);

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
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);

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
