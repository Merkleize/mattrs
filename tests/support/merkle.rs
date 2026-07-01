//! Data Merkle tree, ported from pymatt's `matt/merkle.py`.
//!
//! A left-complete binary Merkle tree over a fixed vector of 32-byte leaves (the
//! leaves are *not* re-hashed). Internal nodes are `sha256(left || right)`. This is
//! the off-chain half of the RAM / fraud-proof contracts: it produces the root that
//! a contract commits to, and the membership proofs a spend reveals.
#![allow(dead_code)]

use bitcoin::hashes::{sha256, Hash};
use mattrs::script_utils::bn2vch;

/// The empty-tree root.
pub const NIL: [u8; 32] = [0u8; 32];

/// `floor(log2(n))` for `n >= 1`.
pub fn floor_lg(n: usize) -> u32 {
    assert!(n > 0);
    let mut r = 0;
    let mut t = 1usize;
    while 2 * t <= n {
        t *= 2;
        r += 1;
    }
    r
}

/// `ceil(log2(n))` for `n >= 1`.
pub fn ceil_lg(n: usize) -> u32 {
    assert!(n > 0);
    let mut r = 0;
    let mut t = 1usize;
    while t < n {
        t *= 2;
        r += 1;
    }
    r
}

/// Whether `n` (>= 1) is a power of two.
pub fn is_power_of_2(n: usize) -> bool {
    assert!(n >= 1);
    n & (n - 1) == 0
}

/// The largest power of two strictly less than `n` (for `n >= 2`).
pub fn largest_power_of_2_less_than(n: usize) -> usize {
    assert!(n > 1);
    if is_power_of_2(n) {
        n / 2
    } else {
        1usize << floor_lg(n)
    }
}

/// `sha256(left || right)`.
pub fn combine_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256::Hash::hash(&buf).to_byte_array()
}

/// The left/right directions (0 = left, 1 = right) from the root to `index` in a
/// tree of `size` leaves.
pub fn get_directions(size: usize, index: usize) -> Vec<u8> {
    assert!(size > 0 && index < size);
    let mut directions = Vec::new();
    let mut size = size;
    let mut index = index;
    while size > 1 {
        let depth = ceil_lg(size);
        let mask = 1usize << (depth - 1);
        let right = index & mask != 0;
        directions.push(right as u8);
        if right {
            size -= mask;
            index -= mask;
        } else {
            size = mask;
        }
    }
    directions
}

fn subtree_root(leaves: &[[u8; 32]], begin: usize, size: usize) -> [u8; 32] {
    if size == 1 {
        return leaves[begin];
    }
    let lsize = largest_power_of_2_less_than(size);
    combine_hashes(
        &subtree_root(leaves, begin, lsize),
        &subtree_root(leaves, begin + lsize, size - lsize),
    )
}

fn collect_siblings(
    leaves: &[[u8; 32]],
    begin: usize,
    size: usize,
    index: usize,
    out: &mut Vec<[u8; 32]>,
) {
    if size == 1 {
        return;
    }
    let lsize = largest_power_of_2_less_than(size);
    if index - begin < lsize {
        out.push(subtree_root(leaves, begin + lsize, size - lsize));
        collect_siblings(leaves, begin, lsize, index, out);
    } else {
        out.push(subtree_root(leaves, begin, lsize));
        collect_siblings(leaves, begin + lsize, size - lsize, index, out);
    }
}

/// A Merkle proof: the sibling `hashes` (root → leaf), the `directions` at each
/// step, and the leaf value `x`.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub hashes: Vec<[u8; 32]>,
    pub directions: Vec<u8>,
    pub x: [u8; 32],
}

impl MerkleProof {
    /// The index of the proven leaf, reconstructed from the directions.
    pub fn get_leaf_index(&self) -> usize {
        let mut i = 0usize;
        for d in &self.directions {
            i = 2 * i + (*d as usize);
        }
        i
    }

    /// The root the tree would have if this leaf were set to `new_value`.
    pub fn get_new_root_after_update(&self, new_value: [u8; 32]) -> [u8; 32] {
        let mut r = new_value;
        for (d, h) in self.directions.iter().zip(&self.hashes).rev() {
            r = if *d == 0 {
                combine_hashes(&r, h)
            } else {
                combine_hashes(h, &r)
            };
        }
        r
    }

    /// The witness-stack layout: `<h_1> <d_1> ... <h_n> <d_n> <x>` (2n + 1 elements).
    pub fn to_wit_stack(&self) -> Vec<Vec<u8>> {
        let mut stack = Vec::with_capacity(2 * self.hashes.len() + 1);
        for (h, d) in self.hashes.iter().zip(&self.directions) {
            stack.push(h.to_vec());
            stack.push(bn2vch(*d as i64));
        }
        stack.push(self.x.to_vec());
        stack
    }
}

/// A fixed-size left-complete Merkle tree over 32-byte leaves.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Build a tree over the given leaves.
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        Self { leaves }
    }

    /// The number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The Merkle root (or [`NIL`] for an empty tree).
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            NIL
        } else {
            subtree_root(&self.leaves, 0, self.leaves.len())
        }
    }

    /// The value of leaf `i`.
    pub fn get(&self, i: usize) -> [u8; 32] {
        self.leaves[i]
    }

    /// Set leaf `index` to `x`, recomputing the tree.
    pub fn set(&mut self, index: usize, x: [u8; 32]) {
        self.leaves[index] = x;
    }

    /// A membership proof for leaf `index`.
    pub fn prove_leaf(&self, index: usize) -> MerkleProof {
        let mut hashes = Vec::new();
        collect_siblings(&self.leaves, 0, self.leaves.len(), index, &mut hashes);
        MerkleProof {
            hashes,
            directions: get_directions(self.leaves.len(), index),
            x: self.leaves[index],
        }
    }
}
