use std::any::Any;
use std::fmt::Debug;

use bitcoin::hashes::Hash;
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

#[derive(Debug, Clone)]
pub struct TapLeaf {
    pub name: String,
    pub script: ScriptBuf,
    pub leaf_version: LeafVersion,
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
            TapTree::Leaf(TapLeaf {
                name: _,
                script,
                leaf_version,
            }) => *TapLeafHash::from_script(script, *leaf_version).as_byte_array(),
            TapTree::Branch { left, right } => {
                let left_hash = TapNodeHash::from_byte_array(left.get_root_hash());
                let right_hash = TapNodeHash::from_byte_array(right.get_root_hash());
                *TapNodeHash::from_node_hashes(left_hash, right_hash).as_byte_array()
            }
        }
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
impl<T: Any + Debug> ContractParams for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
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

    fn as_arg_specs() -> ArgSpecs
    where
        Self: Sized;
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
}

// The possible types to specify one of the arguments of a clause
pub enum ArgSpec {
    Int,
    Bytes,
    Signature { pk: XOnlyPublicKey },
}

// Each argument has a name and a type, and they are ordered
pub type ArgSpecs = Vec<(String, ArgSpec)>;

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
    fn arg_specs() -> ArgSpecs;
    fn next_outputs(params: &Self::Params, args: &Self::Args, state: &Self::State)
        -> ClauseOutputs;
}
