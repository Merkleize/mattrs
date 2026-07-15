//! Data Merkle tree, ported from pymatt's `matt/merkle.py`.
//!
//! A left-complete binary Merkle tree over a fixed vector of 32-byte leaves (the
//! leaves are *not* re-hashed). Internal nodes are `sha256(left || right)`. This is
//! the off-chain half of the RAM / fraud-proof contracts: it produces the root that
//! a contract commits to, and the membership proofs a spend reveals.

use crate::contracts::{ArgType, WitnessEncodable, WitnessError};
use crate::script_utils::{bn2vch, vch2bn};
use bitcoin::hashes::{Hash, sha256};

/// Errors produced while constructing or converting Merkle proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    /// The requested leaf is outside the tree.
    LeafIndexOutOfBounds { index: usize, len: usize },
    /// A proof must contain one direction for every sibling hash.
    MismatchedProofLengths { hashes: usize, directions: usize },
    /// A proof direction must be exactly zero (left) or one (right).
    InvalidDirection(i64),
    /// A dynamically sized proof cannot be converted to the requested depth.
    InvalidProofDepth { expected: usize, actual: usize },
    /// Reconstructing an index from an excessively deep proof overflowed.
    LeafIndexOverflow,
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeafIndexOutOfBounds { index, len } => {
                write!(f, "leaf index {index} is out of bounds for {len} leaves")
            }
            Self::MismatchedProofLengths { hashes, directions } => write!(
                f,
                "Merkle proof has {hashes} hashes but {directions} directions"
            ),
            Self::InvalidDirection(direction) => {
                write!(f, "Merkle proof direction must be 0 or 1, got {direction}")
            }
            Self::InvalidProofDepth { expected, actual } => {
                write!(f, "Merkle proof has depth {actual}, expected {expected}")
            }
            Self::LeafIndexOverflow => write!(f, "Merkle proof leaf index overflows usize"),
        }
    }
}

impl std::error::Error for MerkleError {}

/// The empty-tree root.
pub const NIL: [u8; 32] = [0u8; 32];

/// `floor(log2(n))` for `n >= 1`.
pub fn floor_lg(n: usize) -> u32 {
    assert!(n > 0);
    usize::BITS - 1 - n.leading_zeros()
}

/// `ceil(log2(n))` for `n >= 1`.
pub fn ceil_lg(n: usize) -> u32 {
    assert!(n > 0);
    usize::BITS - (n - 1).leading_zeros()
}

/// Whether `n` is a non-zero power of two.
pub fn is_power_of_2(n: usize) -> bool {
    n.is_power_of_two()
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
///
/// Returns [`MerkleError::LeafIndexOutOfBounds`] when `index >= size`, including
/// every index into an empty tree.
pub fn get_directions(size: usize, index: usize) -> Result<Vec<u8>, MerkleError> {
    if index >= size {
        return Err(MerkleError::LeafIndexOutOfBounds { index, len: size });
    }
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
    Ok(directions)
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
    hashes: Vec<[u8; 32]>,
    directions: Vec<u8>,
    x: [u8; 32],
    leaf_index: usize,
}

impl MerkleProof {
    /// Construct a proof from its path, validating its shape and directions.
    /// This constructor is intended for perfect trees, where the direction bits
    /// directly encode the leaf index. Proofs returned by [`MerkleTree`] retain
    /// the exact index for left-complete trees as well.
    pub fn new(
        hashes: Vec<[u8; 32]>,
        directions: Vec<u8>,
        x: [u8; 32],
    ) -> Result<Self, MerkleError> {
        if hashes.len() != directions.len() {
            return Err(MerkleError::MismatchedProofLengths {
                hashes: hashes.len(),
                directions: directions.len(),
            });
        }
        let leaf_index = directions.iter().try_fold(0usize, |index, direction| {
            if *direction > 1 {
                return Err(MerkleError::InvalidDirection(*direction as i64));
            }
            index
                .checked_mul(2)
                .and_then(|index| index.checked_add(*direction as usize))
                .ok_or(MerkleError::LeafIndexOverflow)
        })?;
        Ok(Self {
            hashes,
            directions,
            x,
            leaf_index,
        })
    }

    /// The sibling hashes, ordered from root to leaf.
    pub fn hashes(&self) -> &[[u8; 32]] {
        &self.hashes
    }

    /// The path directions, ordered from root to leaf.
    pub fn directions(&self) -> &[u8] {
        &self.directions
    }

    /// The proven leaf value.
    pub fn leaf(&self) -> [u8; 32] {
        self.x
    }

    /// The exact index of the proven leaf.
    pub fn leaf_index(&self) -> usize {
        self.leaf_index
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

    /// A membership proof for leaf `index`.
    ///
    /// Returns [`MerkleError::LeafIndexOutOfBounds`] for an empty tree or an
    /// index beyond the final leaf.
    pub fn prove_leaf(&self, index: usize) -> Result<MerkleProof, MerkleError> {
        if index >= self.leaves.len() {
            return Err(MerkleError::LeafIndexOutOfBounds {
                index,
                len: self.leaves.len(),
            });
        }
        let mut hashes = Vec::new();
        collect_siblings(&self.leaves, 0, self.leaves.len(), index, &mut hashes);
        Ok(MerkleProof {
            hashes,
            directions: get_directions(self.leaves.len(), index)?,
            x: self.leaves[index],
            leaf_index: index,
        })
    }
}

// ============================================================================
// Witness serialization: MerkleProofType (a multi-element witness argument)
// ============================================================================

impl MerkleProof {
    /// Convert to a fixed-depth witness proof.
    pub fn to_wit_proof<const N: usize>(&self) -> Result<WitProof<N>, MerkleError> {
        if self.hashes.len() != N {
            return Err(MerkleError::InvalidProofDepth {
                expected: N,
                actual: self.hashes.len(),
            });
        }
        let mut hashes = [[0u8; 32]; N];
        let mut directions = [0u8; N];
        hashes.copy_from_slice(&self.hashes);
        directions.copy_from_slice(&self.directions);
        Ok(WitProof {
            hashes,
            directions,
            x: self.x,
        })
    }
}

/// A depth-`N` Merkle proof in witness form: `<h_1> <d_1> ... <h_N> <d_N> <x>`
/// (exactly `2N + 1` witness elements). The const depth lets it round-trip through
/// the typed args-struct decode, which needs a fixed element count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitProof<const N: usize> {
    hashes: [[u8; 32]; N],
    directions: [u8; N],
    x: [u8; 32],
}

impl<const N: usize> WitProof<N> {
    /// Construct a fixed-depth proof, rejecting non-binary directions.
    pub fn new(
        hashes: [[u8; 32]; N],
        directions: [u8; N],
        x: [u8; 32],
    ) -> Result<Self, MerkleError> {
        if let Some(direction) = directions.iter().find(|direction| **direction > 1) {
            return Err(MerkleError::InvalidDirection(*direction as i64));
        }
        Ok(Self {
            hashes,
            directions,
            x,
        })
    }

    /// The sibling hashes, ordered from root to leaf.
    pub fn hashes(&self) -> &[[u8; 32]; N] {
        &self.hashes
    }

    /// The path directions, ordered from root to leaf.
    pub fn directions(&self) -> &[u8; N] {
        &self.directions
    }

    /// The proven leaf value.
    pub fn leaf(&self) -> [u8; 32] {
        self.x
    }

    /// The index of the proven leaf, reconstructed from the directions.
    ///
    /// Returns [`MerkleError::LeafIndexOverflow`] if `N` exceeds the number of
    /// direction bits representable by `usize`.
    pub fn leaf_index(&self) -> Result<usize, MerkleError> {
        self.directions.iter().try_fold(0usize, |index, direction| {
            index
                .checked_mul(2)
                .and_then(|index| index.checked_add(*direction as usize))
                .ok_or(MerkleError::LeafIndexOverflow)
        })
    }
}

impl<const N: usize> WitnessEncodable for WitProof<N> {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        let mut stack = Vec::with_capacity(2 * N + 1);
        for i in 0..N {
            stack.push(self.hashes[i].to_vec());
            stack.push(bn2vch(self.directions[i] as i64));
        }
        stack.push(self.x.to_vec());
        stack
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        let needed = 2 * N + 1;
        if witness.len() < needed {
            return Err(WitnessError::InsufficientData);
        }
        let as_hash = |bytes: &[u8]| -> Result<[u8; 32], WitnessError> {
            bytes
                .try_into()
                .map_err(|_| WitnessError::InvalidValue("proof element must be 32 bytes".into()))
        };
        let mut hashes = [[0u8; 32]; N];
        let mut directions = [0u8; N];
        for i in 0..N {
            hashes[i] = as_hash(&witness[2 * i])?;
            let direction = vch2bn(&witness[2 * i + 1])?;
            directions[i] = match direction {
                0 | 1 => direction as u8,
                other => {
                    return Err(WitnessError::InvalidValue(format!(
                        "proof direction must be 0 or 1, got {other}"
                    )));
                }
            };
        }
        let x = as_hash(&witness[2 * N])?;
        Ok((
            WitProof {
                hashes,
                directions,
                x,
            },
            needed,
        ))
    }
}

/// The [`ArgType`] for a depth-`depth` Merkle proof: it consumes `2*depth + 1`
/// witness elements. Proof values themselves flow through the typed args struct
/// (via [`WitProof`]'s [`WitnessEncodable`]); this exists so a clause's `arg_specs`
/// account for the right number of witness elements.
#[derive(Debug, Clone)]
pub struct MerkleProofType {
    depth: usize,
}

impl MerkleProofType {
    pub fn new(depth: usize) -> Self {
        Self { depth }
    }
}

impl ArgType for MerkleProofType {
    fn consume(&self, witness: &[Vec<u8>]) -> Result<usize, WitnessError> {
        let needed = self
            .depth
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| WitnessError::InvalidValue("proof depth is too large".into()))?;
        if witness.len() < needed {
            return Err(WitnessError::InsufficientData);
        }
        for level in 0..self.depth {
            if witness[2 * level].len() != 32 {
                return Err(WitnessError::InvalidValue(format!(
                    "proof hash at level {level} must be 32 bytes"
                )));
            }
            match vch2bn(&witness[2 * level + 1])? {
                0 | 1 => {}
                direction => {
                    return Err(WitnessError::InvalidValue(format!(
                        "proof direction at level {level} must be 0 or 1, got {direction}"
                    )));
                }
            }
        }
        if witness[needed - 1].len() != 32 {
            return Err(WitnessError::InvalidValue(
                "proof leaf must be 32 bytes".into(),
            ));
        }
        Ok(needed)
    }

    fn witness_elements(&self) -> usize {
        self.depth
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .expect("Merkle proof depth is too large")
    }

    fn clone_boxed(&self) -> Box<dyn ArgType> {
        Box::new(self.clone())
    }
}
