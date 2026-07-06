//! RAM / Merkle-tree port tests.
//!
//! Verifies the ported data Merkle tree against the pymatt reference
//! (`matt/merkle.py`): the root, a membership proof, and the root recomputed after
//! a leaf update all match byte-for-byte.

mod support;

use mattrs::merkle::{ceil_lg, floor_lg, get_directions, MerkleProofType, MerkleTree, WitProof};
use support::ram::{Ram, RamHandle, RamParams, RamState};

fn ref_leaves() -> Vec<[u8; 32]> {
    (0..4u8).map(|i| [i; 32]).collect()
}

#[test]
fn test_merkle_root_matches_reference() {
    let tree = MerkleTree::new(ref_leaves());
    assert_eq!(
        hex::encode(tree.root()),
        "d35f51699389da7eec7ce5eb02640c6d318cf51ae39eca890bbc7b84ecb5da68"
    );
}

#[test]
fn test_merkle_proof_matches_reference() {
    let tree = MerkleTree::new(ref_leaves());
    let proof = tree.prove_leaf(2);

    let hashes: Vec<String> = proof.hashes.iter().map(hex::encode).collect();
    assert_eq!(
        hashes,
        vec![
            "5c85955f709283ecce2b74f1b1552918819f390911816e7bb466805a38ab87f3".to_string(),
            "0303030303030303030303030303030303030303030303030303030303030303".to_string(),
        ]
    );
    assert_eq!(proof.directions, vec![1, 0]);
    assert_eq!(
        hex::encode(proof.x),
        "0202020202020202020202020202020202020202020202020202020202020202"
    );
    assert_eq!(proof.get_leaf_index(), 2);

    // Updating leaf 2 to 0xaa..aa yields the pymatt reference root.
    assert_eq!(
        hex::encode(proof.get_new_root_after_update([0xaa; 32])),
        "3aa8204b0ee00574bb39bf04a6e3853f42685588aa06f4aadf423e6035f94b29"
    );

    // Re-applying the current leaf value reconstructs the tree's own root, and the
    // witness stack has the expected 2n+1 shape.
    assert_eq!(proof.get_new_root_after_update(proof.x), tree.root());
    assert_eq!(proof.to_wit_stack().len(), 2 * proof.hashes.len() + 1);
}

// Regenerate the pinned root with pymatt (from the repo root):
//   pymatt/venv/bin/python -c "
//   import sys; sys.path[:0] = ['pymatt/src', 'pymatt/examples/ram']
//   from ram_contracts import RAM
//   print(RAM(4).get_tr_info(b'\x00'*32).merkle_root.hex())"
#[test]
fn test_ram_taptree_matches_reference() {
    // Byte-compatibility proof for the withdraw/write tapscripts: the taptree root
    // matches the pymatt reference RAM(4).get_taptree_merkle_root().
    let ram = Ram::new(RamParams { size: 4 });
    assert_eq!(
        hex::encode(ram.taptree_root()),
        "c86ddcabdddb39b345fbb7bc3cc4471c4a57672dddb27615a3b7e69027cf7bad"
    );
}

#[test]
fn test_wit_proof_witness_roundtrip() {
    use mattrs::contracts::WitnessEncodable;

    let tree = MerkleTree::new((0..4u8).map(|i| [i; 32]).collect());
    let proof = tree.prove_leaf(2);
    let wp: WitProof<2> = proof.to_wit_proof();

    // The typed encoding is exactly the raw 2n+1 witness-stack layout.
    let stack = wp.encode_to_witness();
    assert_eq!(stack.len(), 5);
    assert_eq!(stack, proof.to_wit_stack());

    // Decode consumes exactly 2n+1 and round-trips, even with trailing witness args
    // (so a following argument like `merkle_root` decodes correctly after it).
    let (decoded, consumed) = WitProof::<2>::decode_from_witness(&stack).unwrap();
    assert_eq!(consumed, 5);
    assert_eq!(decoded, wp);

    let mut with_tail = stack.clone();
    with_tail.push([9u8; 32].to_vec());
    let (_d2, consumed2) = WitProof::<2>::decode_from_witness(&with_tail).unwrap();
    assert_eq!(consumed2, 5);
}

#[test]
fn test_merkle_proof_type_arg_consumes_2n_plus_1() {
    use mattrs::contracts::ArgType;

    let mpt = MerkleProofType::new(2);
    let tree = MerkleTree::new((0..4u8).map(|i| [i; 32]).collect());
    let mut stack = tree.prove_leaf(2).to_wit_stack();
    stack.push([9u8; 32].to_vec()); // a trailing argument

    assert_eq!(mpt.consume(&stack).unwrap(), 5);
}

#[test]
fn test_ram_write_commits_updated_root() {
    // Spend the `write` clause: it decodes the Merkle proof from the witness
    // (MerkleProofType), reads the cells from the instance's expanded state, updates
    // cell 2, and commits the new Merkle root to the output. Builds locally, no RPC.
    use bitcoin::Amount;
    use mattrs::manager::ContractManager;
    use support::testkit::{fund_fake, offline_client, try_handle};

    let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
    let ram = Ram::new(RamParams { size: 4 });

    // The instance commits the initial leaves' Merkle root, and carries the leaves
    // themselves as expanded state.
    let committed = MerkleTree::new(leaves.clone()).root();
    let handle = try_handle::<RamHandle>(fund_fake(
        ram.as_erased(),
        Some(Box::new(RamState {
            leaves: leaves.clone(),
        })),
        100_000,
        0,
    ));

    let client = offline_client();
    let manager = ContractManager::new(client);

    // Prove cell 2 and write a new value into it.
    let tree = MerkleTree::new(leaves.clone());
    let proof: WitProof<2> = tree.prove_leaf(2).to_wit_proof();
    let new_value = [0xaa; 32];

    let tx = handle
        .write(proof, new_value, committed)
        .build_tx(&manager)
        .unwrap();

    // The single output commits the updated Merkle root, preserving the amount.
    let mut updated = leaves.clone();
    updated[2] = new_value;
    let new_root = MerkleTree::new(updated).root();
    let expected = ram.as_erased().script_pubkey(Some(new_root.as_slice())).unwrap();

    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].script_pubkey, expected);
    assert_eq!(tx.output[0].value, Amount::from_sat(100_000));
    // and it is not the pre-update commitment
    assert_ne!(new_root, committed);
}

#[test]
fn test_merkle_helpers_match_reference() {
    assert_eq!(get_directions(4, 2), vec![1, 0]);
    assert_eq!(floor_lg(8), 3);
    assert_eq!(ceil_lg(5), 3);
}

// ----------------------------------------------------------------------------
// End-to-end (regtest): write then withdraw, validated by a real node.
// ----------------------------------------------------------------------------

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_ram_write_and_withdraw_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::Amount;
    use mattrs::manager::ContractManager;
    use mattrs::report::Report;
    use support::testkit::{regtest_client, report_spend};

    let client = regtest_client("testwallet");
    let mut manager = ContractManager::new(client);
    let mut report = Report::new();

    let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
    let ram = Ram::new(RamParams { size: 4 }).fund(
        &mut manager,
        Amount::from_sat(100_000),
        RamState {
            leaves: leaves.clone(),
        },
    )?;

    // Write cell 2, proving its current value; the node validates the tapscript's
    // in-script Merkle-root recomputation of both the old and the new root.
    let tree = MerkleTree::new(leaves.clone());
    let proof: WitProof<2> = tree.prove_leaf(2).to_wit_proof();
    let new_value = [0xaa; 32];
    let child: RamHandle = ram
        .write(proof, new_value, tree.root())
        .exec_one(&mut manager)?
        .try_into()?;
    report_spend(
        &mut report,
        "RAM",
        "write (update cell 2)",
        &manager,
        ram.handle(),
    );

    // Withdraw from the updated RAM, proving the freshly written value.
    let mut updated = leaves.clone();
    updated[2] = new_value;
    let new_tree = MerkleTree::new(updated);
    let proof: WitProof<2> = new_tree.prove_leaf(2).to_wit_proof();

    use bitcoincore_rpc::RpcApi;
    let dest = manager.rpc().get_new_address(None, None)?.assume_checked();
    child
        .withdraw(proof, new_tree.root())
        .outputs(vec![bitcoin::TxOut {
            script_pubkey: dest.script_pubkey(),
            value: Amount::from_sat(100_000),
        }])
        .exec_none(&mut manager)?;
    report_spend(
        &mut report,
        "RAM",
        "withdraw (prove cell 2)",
        &manager,
        child.handle(),
    );

    report.finalize("reports/report_ram.md");
    Ok(())
}
