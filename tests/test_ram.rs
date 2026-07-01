//! RAM / Merkle-tree port tests.
//!
//! Verifies the ported data Merkle tree against the pymatt reference
//! (`matt/merkle.py`): the root, a membership proof, and the root recomputed after
//! a leaf update all match byte-for-byte.

mod support;

use support::merkle::{ceil_lg, floor_lg, get_directions, MerkleTree};
use support::ram::{Ram, RamParams};

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

#[test]
fn test_ram_taptree_matches_reference() {
    // Byte-compatibility proof for the withdraw/write tapscripts: the taptree root
    // matches the pymatt reference RAM(4).get_taptree_merkle_root().
    let ram = Ram::new(RamParams { size: 4 });
    assert_eq!(
        hex::encode(ram.contract.taptree.root_hash()),
        "c86ddcabdddb39b345fbb7bc3cc4471c4a57672dddb27615a3b7e69027cf7bad"
    );
}

#[test]
fn test_merkle_helpers_match_reference() {
    assert_eq!(get_directions(4, 2), vec![1, 0]);
    assert_eq!(floor_lg(8), 3);
    assert_eq!(ceil_lg(5), 3);
}
