use bitcoin::ScriptBuf;
use bitcoin::opcodes::all::*;

use crate::sha256;

/// Combine two 32-byte hashes: sha256(left || right).
pub fn combine_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left);
    data[32..].copy_from_slice(right);
    sha256(&data)
}

/// Check if n is a power of 2.
pub fn is_power_of_2(n: usize) -> bool {
    n >= 1 && (n & (n - 1)) == 0
}

/// Largest power of 2 strictly less than n (n must be > 1).
fn largest_power_of_2_less_than(n: usize) -> usize {
    assert!(n > 1);
    if is_power_of_2(n) {
        n / 2
    } else {
        1 << floor_lg(n)
    }
}

pub fn floor_lg(n: usize) -> u32 {
    assert!(n > 0);
    let mut r = 0;
    let mut t = 1;
    while 2 * t <= n {
        t *= 2;
        r += 1;
    }
    r
}

/// Compute the merkle root of a list of 32-byte leaves using a left-complete binary tree.
///
/// Matches pymatt's `MerkleTree([...]).root` / `make_tree` which splits
/// n leaves into left = largest_power_of_2_less_than(n) and right = remainder.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(!leaves.is_empty(), "merkle_root requires at least 1 leaf");
    merkle_root_slice(leaves)
}

fn merkle_root_slice(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => panic!("empty"),
        1 => leaves[0],
        _ => {
            let split = largest_power_of_2_less_than(leaves.len());
            let left = merkle_root_slice(&leaves[..split]);
            let right = merkle_root_slice(&leaves[split..]);
            combine_hashes(&left, &right)
        }
    }
}

pub fn ceil_lg(n: usize) -> u32 {
    assert!(n > 0);
    let mut r = 0;
    let mut t = 1;
    while t < n {
        t *= 2;
        r += 1;
    }
    r
}

/// Returns root-to-leaf path directions in a left-complete binary tree.
/// `true` = right child, `false` = left child.
pub fn get_directions(size: usize, index: usize) -> Vec<bool> {
    assert!(size > 0);
    assert!(index < size);

    let mut directions = Vec::new();
    if size == 1 {
        return directions;
    }

    let mut size = size;
    let mut index = index;

    while size > 1 {
        let depth = ceil_lg(size);
        let mask = 1usize << (depth - 1);
        let right_child = index & mask != 0;
        directions.push(right_child);
        if right_child {
            size -= mask;
            index -= mask;
        } else {
            size = mask;
        }
    }

    directions
}

/// A Merkle proof: sibling hashes along the path from root to leaf,
/// directions at each level, and the leaf value.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub hashes: Vec<[u8; 32]>,
    pub directions: Vec<bool>,
    pub x: [u8; 32],
}

impl MerkleProof {
    pub fn new(hashes: Vec<[u8; 32]>, directions: Vec<bool>, x: [u8; 32]) -> Self {
        assert_eq!(hashes.len(), directions.len());
        Self { hashes, directions, x }
    }

    /// Reconstruct the leaf index from the directions.
    pub fn get_leaf_index(&self) -> usize {
        let mut i = 0;
        for &d in &self.directions {
            i = 2 * i + d as usize;
        }
        i
    }

    /// Compute the new merkle root if the leaf is replaced with `new_value`.
    pub fn get_new_root_after_update(&self, new_value: &[u8; 32]) -> [u8; 32] {
        let mut r = *new_value;
        for (d, h) in self.directions.iter().rev().zip(self.hashes.iter().rev()) {
            if !d {
                // left child: r || h
                r = combine_hashes(&r, h);
            } else {
                // right child: h || r
                r = combine_hashes(h, &r);
            }
        }
        r
    }

    /// Encode the proof as witness stack elements:
    /// `[h_1, d_1, h_2, d_2, ..., h_n, d_n, x]`
    /// Directions: 0 = `[]` (empty), 1 = `[0x01]`.
    pub fn to_witness_stack(&self) -> Vec<Vec<u8>> {
        let mut stack = Vec::with_capacity(2 * self.hashes.len() + 1);
        for (h, &d) in self.hashes.iter().zip(&self.directions) {
            stack.push(h.to_vec());
            if d {
                stack.push(vec![0x01]);
            } else {
                stack.push(vec![]);
            }
        }
        stack.push(self.x.to_vec());
        stack
    }

    /// Decode a proof from witness stack elements.
    pub fn from_witness_stack(stack: &[Vec<u8>]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if stack.len() < 3 || stack.len() % 2 == 0 {
            return Err("Witness stack must contain an odd number of elements (>= 3)".into());
        }
        let x: [u8; 32] = stack.last().unwrap().as_slice().try_into()
            .map_err(|_| "Leaf value must be 32 bytes")?;
        let pairs = &stack[..stack.len() - 1];
        let n = pairs.len() / 2;
        let mut hashes = Vec::with_capacity(n);
        let mut directions = Vec::with_capacity(n);
        for i in 0..n {
            let h: [u8; 32] = pairs[2 * i].as_slice().try_into()
                .map_err(|_| format!("Hash {} must be 32 bytes", i))?;
            hashes.push(h);
            let d_bytes = &pairs[2 * i + 1];
            let d = if d_bytes.is_empty() {
                false
            } else {
                bitcoin::script::read_scriptint(d_bytes)
                    .map_err(|e| format!("Direction {}: {}", i, e))? != 0
            };
            directions.push(d);
        }
        Ok(Self { hashes, directions, x })
    }
}

/// A simple Merkle tree over `[u8; 32]` leaves. Recomputes root/proofs on demand.
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        assert!(!leaves.is_empty());
        Self { leaves }
    }

    pub fn root(&self) -> [u8; 32] {
        merkle_root(&self.leaves)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn get(&self, i: usize) -> &[u8; 32] {
        &self.leaves[i]
    }

    pub fn set(&mut self, i: usize, val: [u8; 32]) {
        self.leaves[i] = val;
    }

    /// Produce a Merkle proof for the leaf at `index`.
    pub fn prove_leaf(&self, index: usize) -> MerkleProof {
        assert!(index < self.leaves.len());
        let siblings = collect_siblings(&self.leaves, index);
        // siblings are collected leaf-to-root; reverse for root-to-leaf
        let siblings_rev: Vec<[u8; 32]> = siblings.into_iter().rev().collect();
        let directions = get_directions(self.leaves.len(), index);
        MerkleProof::new(siblings_rev, directions, self.leaves[index])
    }
}

/// Recursively collect sibling hashes from leaf to root for the given index.
fn collect_siblings(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return vec![];
    }
    let split = largest_power_of_2_less_than(leaves.len());
    if index < split {
        let mut sibs = collect_siblings(&leaves[..split], index);
        sibs.push(merkle_root_slice(&leaves[split..]));
        sibs
    } else {
        let mut sibs = collect_siblings(&leaves[split..], index - split);
        sibs.push(merkle_root_slice(&leaves[..split]));
        sibs
    }
}

// ---------------------------------------------------------------------------
// Script helpers for on-chain merkle root computation
// ---------------------------------------------------------------------------

/// Reduces n stack elements to a single merkle root via repeated CAT SHA256.
///
/// Stack: x_0 x_1 ... x_{n-1} → ... root
///
/// This does NOT preserve the original elements (they are consumed).
/// The calling code should dup them first if needed.
pub fn merkle_root_script(n: usize) -> ScriptBuf {
    assert!(n >= 1);
    let mut bytes = Vec::new();
    let mut sz = n;
    while sz > 1 {
        let layer = reduce_merkle_layer_script(sz);
        bytes.extend_from_slice(layer.as_bytes());
        sz = (sz + 1) / 2;
    }
    ScriptBuf::from(bytes)
}

/// Reduces one layer: pairs adjacent elements with CAT SHA256.
/// If n is odd, the last element is kept (moved to altstack then back).
///
/// n=1: no-op
/// n=2: CAT SHA256
/// n odd: TOALTSTACK <reduce(n-1)> FROMALTSTACK
/// n even: CAT SHA256 TOALTSTACK <reduce(n-2)> FROMALTSTACK
fn reduce_merkle_layer_script(n: usize) -> ScriptBuf {
    assert!(n >= 1);
    let mut bytes = Vec::new();
    reduce_merkle_layer_inner(n, &mut bytes);
    ScriptBuf::from(bytes)
}

fn reduce_merkle_layer_inner(n: usize, out: &mut Vec<u8>) {
    if n <= 1 {
        return;
    }
    if n == 2 {
        out.push(OP_CAT.to_u8());
        out.push(OP_SHA256.to_u8());
        return;
    }
    if n % 2 == 1 {
        // odd: save last, reduce n-1, restore
        out.push(OP_TOALTSTACK.to_u8());
        reduce_merkle_layer_inner(n - 1, out);
        out.push(OP_FROMALTSTACK.to_u8());
    } else {
        // even: reduce last pair first, save result, reduce rest, restore
        out.push(OP_CAT.to_u8());
        out.push(OP_SHA256.to_u8());
        out.push(OP_TOALTSTACK.to_u8());
        reduce_merkle_layer_inner(n - 2, out);
        out.push(OP_FROMALTSTACK.to_u8());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    #[test]
    fn test_merkle_root_single() {
        let leaf = sha256(b"hello");
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn test_merkle_root_two() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        let expected = combine_hashes(&a, &b);
        assert_eq!(merkle_root(&[a, b]), expected);
    }

    #[test]
    fn test_merkle_root_three() {
        // 3 leaves: left child gets 2 (largest power of 2 < 3), right child gets 1
        let a = sha256(b"a");
        let b = sha256(b"b");
        let c = sha256(b"c");
        let left = combine_hashes(&a, &b);
        let expected = combine_hashes(&left, &c);
        assert_eq!(merkle_root(&[a, b, c]), expected);
    }

    #[test]
    fn test_merkle_root_five() {
        // 5 leaves: left child gets 4, right child gets 1
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| sha256(&[i])).collect();
        let l01 = combine_hashes(&leaves[0], &leaves[1]);
        let l23 = combine_hashes(&leaves[2], &leaves[3]);
        let left = combine_hashes(&l01, &l23);
        let expected = combine_hashes(&left, &leaves[4]);
        assert_eq!(merkle_root(&leaves), expected);
    }

    #[test]
    fn test_merkle_root_eight() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| sha256(&[i])).collect();
        let l01 = combine_hashes(&leaves[0], &leaves[1]);
        let l23 = combine_hashes(&leaves[2], &leaves[3]);
        let l45 = combine_hashes(&leaves[4], &leaves[5]);
        let l67 = combine_hashes(&leaves[6], &leaves[7]);
        let l0123 = combine_hashes(&l01, &l23);
        let l4567 = combine_hashes(&l45, &l67);
        let expected = combine_hashes(&l0123, &l4567);
        assert_eq!(merkle_root(&leaves), expected);
    }

    #[test]
    fn test_is_power_of_2() {
        assert!(is_power_of_2(1));
        assert!(is_power_of_2(2));
        assert!(is_power_of_2(4));
        assert!(is_power_of_2(8));
        assert!(!is_power_of_2(3));
        assert!(!is_power_of_2(5));
        assert!(!is_power_of_2(6));
    }

    #[test]
    fn test_get_directions() {
        // Size 8 (power of 2): binary tree is complete
        assert_eq!(get_directions(8, 0), vec![false, false, false]);
        assert_eq!(get_directions(8, 7), vec![true, true, true]);
        assert_eq!(get_directions(8, 4), vec![true, false, false]);
        // Size 1: no directions
        assert_eq!(get_directions(1, 0), Vec::<bool>::new());
        // Size 5: left subtree has 4, right has 1
        assert_eq!(get_directions(5, 4), vec![true]);
        assert_eq!(get_directions(5, 0), vec![false, false, false]);
        assert_eq!(get_directions(5, 3), vec![false, true, true]);
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        for size in [2, 3, 5, 8, 16] {
            let leaves: Vec<[u8; 32]> = (0..size).map(|i| sha256(&[i as u8])).collect();
            let tree = MerkleTree::new(leaves.clone());
            for idx in 0..size {
                let proof = tree.prove_leaf(idx);
                // Witness roundtrip
                let stack = proof.to_witness_stack();
                let decoded = MerkleProof::from_witness_stack(&stack).unwrap();
                assert_eq!(decoded.hashes, proof.hashes);
                assert_eq!(decoded.directions, proof.directions);
                assert_eq!(decoded.x, proof.x);
                // Leaf index (only valid for power-of-2 sizes)
                if is_power_of_2(size) {
                    assert_eq!(proof.get_leaf_index(), idx);
                }
            }
        }
    }

    #[test]
    fn test_merkle_proof_root_verification() {
        for size in [2, 4, 8, 16] {
            let leaves: Vec<[u8; 32]> = (0..size).map(|i| sha256(&[i as u8])).collect();
            let tree = MerkleTree::new(leaves);
            let root = tree.root();
            for idx in 0..size {
                let proof = tree.prove_leaf(idx);
                // Verify: updating with same value gives same root
                let recomputed = proof.get_new_root_after_update(&proof.x);
                assert_eq!(recomputed, root, "Root mismatch for size={}, idx={}", size, idx);
            }
        }
    }

    #[test]
    fn test_merkle_proof_update() {
        let size = 8;
        let leaves: Vec<[u8; 32]> = (0..size).map(|i| sha256(&[i as u8])).collect();
        let tree = MerkleTree::new(leaves.clone());
        let new_val = sha256(b"new");

        for idx in 0..size {
            let proof = tree.prove_leaf(idx);
            let new_root = proof.get_new_root_after_update(&new_val);
            // Build expected by modifying the leaves directly
            let mut modified = leaves.clone();
            modified[idx] = new_val;
            assert_eq!(new_root, merkle_root(&modified), "Update mismatch at idx={}", idx);
        }
    }

    #[test]
    fn test_merkle_tree_prove_various_sizes() {
        for size in [1, 2, 3, 5, 7, 8, 9, 15, 16] {
            let leaves: Vec<[u8; 32]> = (0..size).map(|i| sha256(&[i as u8])).collect();
            let tree = MerkleTree::new(leaves.clone());
            let root = tree.root();
            assert_eq!(root, merkle_root(&leaves));
            for idx in 0..size {
                let proof = tree.prove_leaf(idx);
                let recomputed = proof.get_new_root_after_update(&proof.x);
                assert_eq!(recomputed, root, "size={}, idx={}", size, idx);
            }
        }
    }
}
