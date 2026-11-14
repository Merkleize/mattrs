//! Taproot trees: the script tree behind an address, the clause tree it is derived from, and key tweaking.

use std::{fmt, fmt::Debug, sync::Arc};

use super::{ContractError, ErasedClause};
use bitcoin::{
    ScriptBuf, TapTweakHash, XOnlyPublicKey, hashes::Hash, hashes::sha256, key::Secp256k1,
    taproot::LeafVersion, taproot::TapLeafHash, taproot::TapNodeHash,
};

/// A single leaf in a taproot tree.
#[derive(Debug, Clone, PartialEq)]
pub struct TapLeaf {
    /// The clause name this leaf belongs to (not consensus-visible).
    pub name: String,
    /// The leaf's tapscript.
    pub script: ScriptBuf,
}

/// Recursive taproot tree structure.
#[derive(Debug, Clone)]
pub enum TapTree {
    Leaf(TapLeaf),
    Branch {
        left: Arc<TapTree>,
        right: Arc<TapTree>,
    },
}

impl TapTree {
    /// Create a new leaf node.
    pub fn leaf(name: impl Into<String>, script: ScriptBuf) -> Self {
        TapTree::Leaf(TapLeaf {
            name: name.into(),
            script,
        })
    }

    /// Create a new branch node.
    pub fn branch(left: TapTree, right: TapTree) -> Self {
        TapTree::Branch {
            left: Arc::new(left),
            right: Arc::new(right),
        }
    }

    /// Compute the merkle root hash of this tree.
    pub fn root_hash(&self) -> [u8; 32] {
        match self {
            TapTree::Leaf(TapLeaf { name: _, script }) => {
                let leaf_hash =
                    TapLeafHash::from_script(script.as_script(), LeafVersion::TapScript);
                *leaf_hash.as_byte_array()
            }
            TapTree::Branch { left, right } => {
                let left_hash = TapNodeHash::from_byte_array(left.root_hash());
                let right_hash = TapNodeHash::from_byte_array(right.root_hash());
                let node_hash = TapNodeHash::from_node_hashes(left_hash, right_hash);
                *node_hash.as_byte_array()
            }
        }
    }

    /// Get the merkle proof for a specific leaf: the sibling hashes ordered
    /// leaf-to-root (deepest sibling first), as a BIP341 control block expects.
    pub fn merkle_proof(&self, target_leaf: &TapLeaf) -> Option<Vec<[u8; 32]>> {
        match self {
            TapTree::Leaf(leaf) => {
                if leaf == target_leaf {
                    Some(Vec::new())
                } else {
                    None
                }
            }
            TapTree::Branch { left, right } => {
                if let Some(mut proof) = left.merkle_proof(target_leaf) {
                    proof.push(right.root_hash());
                    Some(proof)
                } else if let Some(mut proof) = right.merkle_proof(target_leaf) {
                    proof.push(left.root_hash());
                    Some(proof)
                } else {
                    None
                }
            }
        }
    }

    /// Find a specific leaf by name.
    pub fn find_leaf(&self, name: &str) -> Option<&TapLeaf> {
        match self {
            TapTree::Leaf(leaf) => {
                if leaf.name == name {
                    Some(leaf)
                } else {
                    None
                }
            }
            TapTree::Branch { left, right } => {
                left.find_leaf(name).or_else(|| right.find_leaf(name))
            }
        }
    }

    /// Get all leaves in the tree (in order).
    pub fn leaves(&self) -> Vec<&TapLeaf> {
        match self {
            TapTree::Leaf(leaf) => vec![leaf],
            TapTree::Branch { left, right } => {
                let mut result = left.leaves();
                result.extend(right.leaves());
                result
            }
        }
    }

    /// Generate a control block for spending a specific clause.
    pub fn control_block(
        &self,
        internal_pubkey: &XOnlyPublicKey,
        clause_name: &str,
    ) -> Option<Vec<u8>> {
        let tapleaf = self.find_leaf(clause_name)?;
        let merkle_root = TapNodeHash::from_byte_array(self.root_hash());
        let tweak =
            TapTweakHash::from_key_and_tweak(*internal_pubkey, Some(merkle_root)).to_scalar();

        let secp = Secp256k1::new();
        let (_, parity) = internal_pubkey
            .add_tweak(&secp, &tweak)
            .expect("Taproot tweak should never fail");

        let c0 = 0xC0u8 | parity.to_u8();
        let xonly_bytes = internal_pubkey.serialize();

        let mut control_block = Vec::new();
        control_block.push(c0);
        control_block.extend_from_slice(&xonly_bytes);

        let merkle_proof = self.merkle_proof(tapleaf)?;
        for hash in merkle_proof {
            control_block.extend_from_slice(&hash);
        }

        Some(control_block)
    }
}

/// A taproot tree whose leaves are clauses.
///
/// This is the single source of truth for a contract's tapscript layout: both
/// the script [`TapTree`] (and therefore the address) and the `name -> clause`
/// lookup used when spending are *derived* from the same `ClauseTree`, so they
/// can never drift apart. Build one with the `clause_tree!` macro and hand it to
/// `StandardP2TR::new`.
pub enum ClauseTree {
    Leaf(Arc<dyn ErasedClause>),
    Branch(Arc<ClauseTree>, Arc<ClauseTree>),
}

impl ClauseTree {
    /// Create a leaf from a clause.
    pub fn leaf(clause: Arc<dyn ErasedClause>) -> Self {
        ClauseTree::Leaf(clause)
    }

    /// Create a branch from two subtrees.
    pub fn branch(left: ClauseTree, right: ClauseTree) -> Self {
        ClauseTree::Branch(Arc::new(left), Arc::new(right))
    }

    /// Derive the script taptree (each leaf carries the clause name + script).
    pub fn to_script_tree(&self) -> TapTree {
        match self {
            ClauseTree::Leaf(clause) => TapTree::Leaf(TapLeaf {
                name: clause.name().to_string(),
                script: clause.script().clone(),
            }),
            ClauseTree::Branch(left, right) => {
                TapTree::branch(left.to_script_tree(), right.to_script_tree())
            }
        }
    }

    /// Collect all clauses, left-to-right (witness/spec order).
    pub fn clauses(&self) -> Vec<Arc<dyn ErasedClause>> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }

    fn collect(&self, out: &mut Vec<Arc<dyn ErasedClause>>) {
        match self {
            ClauseTree::Leaf(clause) => out.push(clause.clone()),
            ClauseTree::Branch(left, right) => {
                left.collect(out);
                right.collect(out);
            }
        }
    }
}

impl Debug for ClauseTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClauseTree::Leaf(clause) => f.debug_tuple("Leaf").field(&clause.name()).finish(),
            ClauseTree::Branch(left, right) => {
                f.debug_tuple("Branch").field(left).field(right).finish()
            }
        }
    }
}

/// Compute a tweaked key for augmented contracts with state commitment.
/// Uses SHA256(naked_key || data) for a nonempty CCV data operand. There is no
/// length-dependent prehash. [`apply_state_tweak`] skips the tweak for empty data.
pub fn compute_state_tweak(naked_key: &[u8; 32], commitment: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + commitment.len());
    data.extend_from_slice(naked_key);
    data.extend_from_slice(commitment);
    let hash = sha256::Hash::hash(&data);
    *hash.as_byte_array()
}

/// Apply the CCV data tweak using the exact commitment bytes. Empty data leaves
/// the naked key unchanged; all nonempty lengths use the same algorithm.
pub fn apply_state_tweak(
    naked_key: &XOnlyPublicKey,
    commitment: &[u8],
) -> Result<XOnlyPublicKey, ContractError> {
    if commitment.is_empty() {
        return Ok(*naked_key);
    }
    let tweak_bytes = compute_state_tweak(&naked_key.serialize(), commitment);

    let secp = Secp256k1::new();
    let scalar = bitcoin::secp256k1::Scalar::from_be_bytes(tweak_bytes)
        .map_err(|e| ContractError::Key(format!("invalid scalar: {}", e)))?;

    naked_key
        .add_tweak(&secp, &scalar)
        .map(|(tweaked, _parity)| tweaked)
        .map_err(|e| ContractError::Key(format!("failed to apply tweak: {}", e)))
}

/// Compute the final taproot output key from internal key and taptree.
pub fn compute_taproot_output_key(
    internal_key: &XOnlyPublicKey,
    taptree: Option<&TapTree>,
) -> XOnlyPublicKey {
    let merkle_root = taptree.map(|tree| TapNodeHash::from_byte_array(tree.root_hash()));
    let tweak = TapTweakHash::from_key_and_tweak(*internal_key, merkle_root).to_scalar();

    let secp = Secp256k1::new();
    internal_key
        .add_tweak(&secp, &tweak)
        .expect("Taproot tweak should never fail")
        .0
}
