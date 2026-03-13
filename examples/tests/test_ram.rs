mod common;

use std::time::Duration;

use bitcoin::{Amount, TxOut};

use mattrs::{
    contracts::ContractInstanceStatus,
    manager::{ContractManager, SpendOptions},
    merkle::MerkleTree,
    report::{format_tx_markdown, Report},
    sha256,
};
use mattrs_examples::ram::{make_ram, proof_to_arg, RamInstance};

const AMOUNT: Amount = Amount::from_sat(20_000);

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
            let mut manager = ContractManager::new(&client, Duration::from_secs_f64(0.1), true);
            let ram = RamInstance::fund(&mut manager, ram, state, AMOUNT)?;
            let ram_idx = ram.idx();

            let proof = mt.prove_leaf(leaf_index);

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
                value: AMOUNT,
            }];

            ram.withdraw(&mut manager, proof_to_arg(&proof), mt.root(), SpendOptions {
                outputs: Some(&outputs),
                ..Default::default()
            })?;

            assert_eq!(
                manager.instance(ram_idx).status(),
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
    let mut manager = ContractManager::new(&client, Duration::from_secs_f64(0.1), true);
    let ram = RamInstance::fund(&mut manager, ram, state, AMOUNT)?;

    let proof = mt.prove_leaf(leaf_index);
    let (new_ram,) = ram.write(&mut manager, proof_to_arg(&proof), new_value, mt.root())?;

    assert_eq!(
        manager.instance(new_ram.idx()).contract().name(),
        format!("RAM_{}", size)
    );

    // Verify the new state matches the modified leaves
    let mut modified_leaves = leaves;
    modified_leaves[leaf_index] = new_value;
    let expected_root = MerkleTree::new(modified_leaves).root();
    assert_eq!(
        manager.instance(new_ram.idx()).data(),
        &expected_root.to_vec()
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
    let mut manager = ContractManager::new(&client, Duration::from_secs_f64(0.1), true);
    let initial_ram = RamInstance::fund(&mut manager, ram, state, AMOUNT)?;
    let mut cur_idx = initial_ram.idx();

    let mut report = Report::new();

    for i in 0..16usize {
        let leaf_index = i % size;
        let new_value = sha256(&[(100 + i) as u8]);

        let mt = MerkleTree::new(leaves.clone());
        let proof = mt.prove_leaf(leaf_index);

        let ram = RamInstance(cur_idx);
        let (new_ram,) = ram.write(&mut manager, proof_to_arg(&proof), new_value, mt.root())?;

        assert_eq!(
            manager.instance(new_ram.idx()).contract().name(),
            format!("RAM_{}", size)
        );

        // Update local leaves
        leaves[leaf_index] = new_value;
        let expected_root = MerkleTree::new(leaves.clone()).root();
        assert_eq!(
            manager.instance(new_ram.idx()).data(),
            &expected_root.to_vec(),
            "Root mismatch at iteration {}",
            i
        );

        report.write(
            "RAM write loop",
            format_tx_markdown(
                manager.instance(cur_idx).spending_tx().unwrap(),
                &format!("Write iteration {} (leaf {})", i, leaf_index),
            ),
        );

        cur_idx = new_ram.idx();
        println!("write_loop iteration {} passed (leaf {})", i, leaf_index);
    }

    report.finalize("reports/report_ram.md");
    println!("test_write_loop passed!");
    Ok(())
}
