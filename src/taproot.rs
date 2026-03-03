use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::Scalar;
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::{hashes::sha256, Address, KnownHrp, TapTweakHash, XOnlyPublicKey};

use crate::contracts::Clause;

#[derive(Debug)]
pub enum TapTree {
    Leaf(Clause),
    Branch {
        left: Box<TapTree>,
        right: Box<TapTree>,
    },
}

impl TapTree {
    pub fn get_root_hash(&self) -> [u8; 32] {
        match self {
            TapTree::Leaf(clause) => {
                let leaf_hash =
                    TapLeafHash::from_script(clause.script.as_script(), LeafVersion::TapScript);
                *leaf_hash.as_byte_array()
            }
            TapTree::Branch { left, right } => {
                let left_hash = TapNodeHash::from_byte_array(left.get_root_hash());
                let right_hash = TapNodeHash::from_byte_array(right.get_root_hash());
                let node_hash = TapNodeHash::from_node_hashes(left_hash, right_hash);
                *node_hash.as_byte_array()
            }
        }
    }

    pub fn get_merkle_proof_by_name(&self, target_name: &str) -> Option<Vec<[u8; 32]>> {
        match self {
            TapTree::Leaf(clause) => {
                if clause.name == target_name {
                    Some(Vec::new())
                } else {
                    None
                }
            }
            TapTree::Branch { left, right } => {
                if let Some(mut proof) = left.get_merkle_proof_by_name(target_name) {
                    proof.push(right.get_root_hash());
                    Some(proof)
                } else if let Some(mut proof) = right.get_merkle_proof_by_name(target_name) {
                    proof.push(left.get_root_hash());
                    Some(proof)
                } else {
                    None
                }
            }
        }
    }

    pub fn get_clause(&self, name: &str) -> Option<&Clause> {
        match self {
            TapTree::Leaf(clause) => {
                if clause.name == name {
                    Some(clause)
                } else {
                    None
                }
            }
            TapTree::Branch { left, right } => {
                left.get_clause(name).or_else(|| right.get_clause(name))
            }
        }
    }

    pub fn get_control_block(
        &self,
        internal_pubkey: &XOnlyPublicKey,
        clause_name: &str,
    ) -> Vec<u8> {
        let _clause = self
            .get_clause(clause_name)
            .expect("Clause not found in taptree");

        let merkle_root = TapNodeHash::from_byte_array(self.get_root_hash());
        let tweak =
            TapTweakHash::from_key_and_tweak(*internal_pubkey, Some(merkle_root)).to_scalar();

        let secp = Secp256k1::new();
        let (_, parity) = internal_pubkey
            .add_tweak(&secp, &tweak)
            .expect("Should never fail");

        let c0 = 0xC0u8 | parity.to_u8();
        let xonly_bytes = internal_pubkey.serialize();

        let mut control_block = Vec::new();
        control_block.push(c0);
        control_block.extend_from_slice(&xonly_bytes);

        let merkle_proof = self
            .get_merkle_proof_by_name(clause_name)
            .expect("Merkle proof generation for controlblock failed");

        for hash in merkle_proof {
            control_block.extend_from_slice(&hash);
        }

        control_block
    }

    pub fn get_leaves(&self) -> Vec<&Clause> {
        match self {
            TapTree::Leaf(clause) => vec![clause],
            TapTree::Branch { left, right } => {
                let mut leaves = left.get_leaves();
                leaves.extend(right.get_leaves());
                leaves
            }
        }
    }

    /// Finds a clause by its script bytes (used for decoding witness stacks).
    pub fn get_clause_by_script(&self, script: &bitcoin::ScriptBuf) -> Option<&Clause> {
        match self {
            TapTree::Leaf(clause) => {
                if &clause.script == script {
                    Some(clause)
                } else {
                    None
                }
            }
            TapTree::Branch { left, right } => left
                .get_clause_by_script(script)
                .or_else(|| right.get_clause_by_script(script)),
        }
    }

    pub fn get_clause_names(&self) -> Vec<&str> {
        self.get_leaves()
            .iter()
            .map(|c| c.name.as_str())
            .collect()
    }
}

/// Tweaks a naked internal pubkey with embedded data (state commitment).
/// Returns the tweaked pubkey: P' = P + SHA256(P || data) * G
pub fn tweak_embed_data(naked_key: &XOnlyPublicKey, data: &[u8]) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let mut engine = sha256::Hash::engine();
    engine.input(&naked_key.serialize());
    engine.input(data);
    let tweak_data = sha256::Hash::from_engine(engine).to_byte_array();
    let (pk, _) = naked_key
        .add_tweak(&secp, &Scalar::from_be_bytes(tweak_data).unwrap())
        .unwrap();
    pk
}

/// Computes a taproot address from an internal pubkey and taptree.
pub fn get_taproot_address(internal_pubkey: &XOnlyPublicKey, taptree: &TapTree) -> Address {
    let secp = Secp256k1::new();
    let taptree_hash = TapNodeHash::from_byte_array(taptree.get_root_hash());
    Address::p2tr(
        &secp,
        *internal_pubkey,
        Some(taptree_hash),
        KnownHrp::Regtest,
    )
}
