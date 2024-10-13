use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;

use bitcoin::hashes::Hash;
use bitcoin::script::write_scriptint;
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::{ScriptBuf, XOnlyPublicKey};

pub const OP_CHECKCONTRACTVERIFY: u8 = 0xbb;
pub const OP_CHECKTEMPLATEVERIFY: u8 = 0xb3;

pub const CCV_FLAG_CHECK_INPUT: i32 = -1;
pub const CCV_FLAG_IGNORE_OUTPUT_AMOUNT: i32 = 1;
pub const CCV_FLAG_DEDUCT_OUTPUT_AMOUNT: i32 = 2;

pub const NUMS_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Debug, Clone, PartialEq)]
pub struct TapLeaf {
    pub name: String,
    pub script: ScriptBuf,
    // we assume the leaf version is 0xC0
}

#[derive(Debug, Clone)]
pub enum TapTree {
    Leaf(TapLeaf),
    Branch {
        left: Box<TapTree>,
        right: Box<TapTree>,
    },
}

impl TapTree {
    pub fn get_root_hash(&self) -> [u8; 32] {
        match self {
            TapTree::Leaf(TapLeaf { name: _, script }) => {
                // Compute TapLeafHash
                let leaf_hash =
                    TapLeafHash::from_script(script.as_script(), LeafVersion::TapScript);
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

    pub fn get_merkle_proof(&self, target_leaf: &TapLeaf) -> Option<Vec<[u8; 32]>> {
        match self {
            TapTree::Leaf(leaf) => {
                if leaf == target_leaf {
                    Some(Vec::new())
                } else {
                    None
                }
            }
            TapTree::Branch { left, right } => {
                if let Some(mut proof) = left.get_merkle_proof(target_leaf) {
                    // Target leaf is in the left subtree
                    proof.insert(0, right.get_root_hash());
                    Some(proof)
                } else if let Some(mut proof) = right.get_merkle_proof(target_leaf) {
                    // Target leaf is in the right subtree
                    proof.insert(0, left.get_root_hash());
                    Some(proof)
                } else {
                    None
                }
            }
        }
    }

    // finds the tapleaf for a clause (if any)
    pub fn get_tapleaf(&self, name: &str) -> Option<&TapLeaf> {
        match self {
            TapTree::Leaf(leaf) => {
                if leaf.name == name {
                    Some(leaf)
                } else {
                    None
                }
            }
            TapTree::Branch { left, right } => {
                if let Some(leaf) = left.get_tapleaf(name) {
                    Some(leaf)
                } else if let Some(leaf) = right.get_tapleaf(name) {
                    Some(leaf)
                } else {
                    None
                }
            }
        }
    }

    pub fn get_control_block(
        &self,
        internal_pubkey: &XOnlyPublicKey,
        clause_name: &str,
    ) -> Vec<u8> {
        let tapleaf = self.get_tapleaf(clause_name).expect("Tapleaf not found");

        // Get the Merkle proof
        let merkle_proof = self
            .get_merkle_proof(tapleaf)
            .expect("Merkle proof generation for controlblock failed");

        // TODO: get the right parity
        let parity = bitcoin::key::Parity::Even; // TODO: get the right parity

        // Compute c[0]
        let c0 = 0xC0u8 | parity.to_u8();

        // c[1..33] is the x coordinate of the internal pubkey
        let xonly_bytes = internal_pubkey.serialize();

        // Assemble the control block
        let mut control_block = Vec::new();
        control_block.push(c0);
        control_block.extend_from_slice(&xonly_bytes);

        // Append the Merkle proof
        for hash in merkle_proof {
            control_block.extend_from_slice(&hash);
        }

        control_block
    }

    pub fn get_leaves(&self) -> Vec<TapLeaf> {
        match self {
            TapTree::Leaf(t) => vec![t.clone()],
            TapTree::Branch { left, right } => {
                let mut leaves = left.get_leaves();
                leaves.extend(right.get_leaves());
                leaves
            }
        }
    }

    pub fn get_clauses(&self) -> Vec<String> {
        self.get_leaves().iter().map(|l| l.name.clone()).collect()
    }
}

pub trait ContractParams: Debug + Any {
    fn as_any(&self) -> &dyn Any;
}

pub trait ContractState: Debug + Any {
    fn as_any(&self) -> &dyn Any;

    /// Encodes the state of an instance into the 32-byte data format that can be encoded in the UTXO.
    fn encode(&self) -> [u8; 32] {
        panic!("Not implemented for this State")
    }

    /// Returns a CScript that computes the commitment to the state, assuming that the top of the stack contains the
    /// values of the individual stack items that allow to compute the state commitment, as output by the encode() function.
    /// Contracts might decide not to implement this (and raise an error if this is called), but they must document how the
    /// state commitment should be computed if not. Contracts implementing it should document what the expected stack
    /// elements are when the encoder_script is used.
    fn encoder_script(&self) -> ScriptBuf {
        panic!("Not implemented for this State")
    }
}

impl ContractState for () {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait ClauseArguments: Any + Debug {
    fn as_any(&self) -> &dyn Any;

    fn arg_names(&self) -> Vec<String>;
    fn as_hashmap(&self, params: &dyn ContractParams) -> HashMap<String, WitnessStackElement>;
}

pub trait Contract: Any + Debug {
    fn is_augmented(&self) -> bool;
    fn get_taptree(&self) -> TapTree;
    fn get_naked_internal_key(&self) -> XOnlyPublicKey;

    fn get_clauses(&self) -> Vec<String> {
        self.get_taptree().get_clauses()
    }

    fn get_params(&self) -> Box<&dyn ContractParams>;

    fn next_outputs(
        &self,
        clause_name: &str,
        params: &dyn ContractParams,
        args: &dyn ClauseArguments,
        state: &dyn ContractState,
    ) -> ClauseOutputs;

    fn stack_elements_from_args(
        &self,
        clause_name: &str,
        args: &dyn ClauseArguments,
    ) -> Result<Vec<WitnessStackElement>, Box<dyn std::error::Error>>;
}

#[derive(Debug, Clone)]
pub enum WitnessStackElement {
    Bytes(Vec<u8>),
    Signature { pk: XOnlyPublicKey },
}

// encoders
pub fn encode_bytes<A: AsRef<[u8]>, P: ?Sized>(arg: &A, _params: &P) -> WitnessStackElement {
    WitnessStackElement::Bytes(arg.as_ref().to_vec())
}

pub fn encode_i32<P: ?Sized>(arg: &i32, _params: &P) -> WitnessStackElement {
    let mut buf = [0u8; 8];
    let len = write_scriptint(&mut buf, *arg as i64);
    WitnessStackElement::Bytes(buf[..len].to_vec())
}

pub fn encode_sig(pk: XOnlyPublicKey) -> WitnessStackElement {
    WitnessStackElement::Signature { pk }
}

// Define the ClauseOutputAmountBehaviour enum
#[derive(Debug, PartialEq)]
pub enum CcvClauseOutputAmountBehaviour {
    PreserveOutput, // The output should be at least as large as the input
    IgnoreOutput,   // The output amount is not checked
    DeductOutput,   // The output amount is subtracted from the input
}

// TODO

#[derive(Debug)]
pub struct CcvOutputDescription {
    pub n: i32,
    pub next_contract: Box<dyn Contract>,
    pub next_state: Option<Box<dyn ContractState>>,
    pub behaviour: CcvClauseOutputAmountBehaviour,
}

pub enum ClauseOutputs {
    CtvTemplate, // TODO
    CcvList(Vec<CcvOutputDescription>),
}

// Define the Clause trait
pub trait Clause: Debug + Clone {
    type Params: ContractParams;
    type Args: ClauseArguments;
    type State: ContractState;

    fn name() -> String;
    fn script(params: &Self::Params) -> ScriptBuf;
    fn next_outputs(params: &Self::Params, args: &Self::Args, state: &Self::State)
        -> ClauseOutputs;
    fn stack_elements_from_args(
        params: &Self::Params,
        args: &Self::Args,
    ) -> Result<Vec<WitnessStackElement>, Box<dyn std::error::Error>> {
        let args_map = args.as_hashmap(params);
        let arg_names = args.arg_names();

        let mut stack_elements = Vec::new();
        for arg_name in arg_names {
            match args_map.get(&arg_name) {
                Some(arg) => stack_elements.push(arg.clone()),
                None => {
                    return Err(format!("Argument {} not found in args_map", arg_name).into());
                }
            }
        }
        Ok(stack_elements)
    }
}
