use std::any::Any;
use std::fmt::Debug;

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
}

pub trait ContractParams: Debug + Any + Clone {}
impl<T: Any + Debug + Clone> ContractParams for T {}
pub trait ContractState: Debug + Any {
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

impl<T: Any + Debug + Clone> ContractState for T {}

pub trait ClauseArguments: Any + Debug + Clone {
    fn as_arg_specs() -> ArgSpecs;
}

pub trait Contract<P: ContractParams, S: ContractState = ()> {
    fn get_taptree(&self) -> TapTree;
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
    pub next_contract: Box<dyn Any>,
    pub next_state: Option<Box<dyn Any>>,
    pub behaviour: CcvClauseOutputAmountBehaviour,
}

pub enum ClauseOutputs {
    CtvTemplate, // TODO
    CcvList(Vec<CcvOutputDescription>),
}

// Define the Clause trait
pub trait Clause<P: ContractParams, A: ClauseArguments, S: ContractState = ()>:
    Debug + Clone
{
    fn name() -> String;
    fn script(params: &P) -> ScriptBuf;
    fn arg_specs() -> ArgSpecs;
    fn next_outputs(params: &P, args: &A, state: &S) -> ClauseOutputs;
}

// MACROS

#[macro_export]
macro_rules! ccv_list {
    (
        $(
            $behaviour:ident ( $n:expr ) => $contract:expr $( ; $state:expr )? $(,)?
        )*
    ) => {
        ClauseOutputs::CcvList(vec![
            $(
                CcvOutputDescription {
                    n: $n,
                    next_contract: Box::new($contract.clone()),
                    next_state: ccv_list!(@optional_state $( $state )? ),
                    behaviour: ccv_list!(@parse_behaviour $behaviour),
                }
            ),*
        ])
    };
    (@optional_state $state:expr) => {
        Some(Box::new($state))
    };
    (@optional_state) => {
        None
    };
    (@parse_behaviour deduct) => { CcvClauseOutputAmountBehaviour::DeductOutput };
    (@parse_behaviour preserve) => { CcvClauseOutputAmountBehaviour::PreserveOutput };
}

#[macro_export]
macro_rules! define_clause {
    (
        $clause_struct_name:ident,
        $clause_args_struct_name:ident,
        $clause_string_name:expr,
        $contract_params:ty,
        $contract_state:ty,
        args { $( $arg_name:ident : $arg_type:ty => $arg_spec:expr ),* $(,)? },
        script($script_params:tt) $script_body:block,
        next_outputs($no_params:tt,$no_args:tt,$no_state:tt) $next_outputs_body:block
    ) => {
        #[derive(Debug, Clone)]
        pub struct $clause_struct_name {}

        #[derive(Debug, Clone)]
        pub struct $clause_args_struct_name {
            $(pub $arg_name: $arg_type),*
        }

        impl ClauseArguments for $clause_args_struct_name {
            fn as_arg_specs() -> ArgSpecs {
                vec![
                    $(
                        (stringify!($arg_name).to_string(), $arg_spec),
                    )*
                ]
            }
        }

        impl Clause<$contract_params, $clause_args_struct_name, $contract_state> for $clause_struct_name {
            fn name() -> String {
                $clause_string_name.into()
            }

            fn script($script_params: &$contract_params) -> ScriptBuf {
                $script_body
            }

            fn arg_specs() -> ArgSpecs {
                <$clause_args_struct_name>::as_arg_specs()
            }

            fn next_outputs(
                $no_params: &$contract_params,
                $no_args: &$clause_args_struct_name,
                $no_state: &$contract_state,
            ) -> ClauseOutputs {
                $next_outputs_body
            }
        }
    };
}

#[macro_export]
macro_rules! define_contract {
    (
        $contract_struct_name:ident,
        $contract_params:ty,
        $contract_state:ty,
        taptree: $taptree:tt
    ) => {
        #[derive(Debug, Clone)]
        pub struct $contract_struct_name {
            pub params: $contract_params,
        }

        impl $contract_struct_name {
            pub fn new(params: $contract_params) -> Self {
                Self { params }
            }
        }

        impl Contract<$contract_params, $contract_state> for $contract_struct_name {
            fn get_taptree(&self) -> TapTree {
                define_contract!(@process_taptree self, $taptree)
            }
        }
    };

    // Process a single clause (leaf node)
    (@process_taptree $self:ident, $clause:ident) => {{
        let script = $clause::script(&$self.params);
        let name = $clause::name().to_string();
        TapTree::Leaf(TapLeaf {
            name,
            script,
            leaf_version: LeafVersion::TapScript,
        })
    }};

    // Process a tuple representing a TapTree branch
    (@process_taptree $self:ident, ( $left:tt , $right:tt ) ) => {{
        let left = define_contract!(@process_taptree $self, $left);
        let right = define_contract!(@process_taptree $self, $right);
        TapTree::Branch {
            left: Box::new(left),
            right: Box::new(right),
        }
    }};
}

/// CONTRACT IMPLEMENTATIONS
use bitcoin::{hashes::Hash, opcodes, script::Builder};

#[derive(Debug, Clone)]
struct VaultParams {
    alternate_pk: Option<XOnlyPublicKey>,
    spend_delay: u32,
    recover_pk: XOnlyPublicKey,
    unvault_pk: XOnlyPublicKey,
}

// clause: trigger

define_clause!(
    VaultTriggerClause,
    VaultTriggerClauseArgs,
    "trigger",
    VaultParams,
    (),
    args {
        sig: [u8; 64] => ArgSpec::Bytes,
        ctv_hash: [u8; 32] => ArgSpec::Bytes,
        out_i: i32 => ArgSpec::Int,
    },
    script(params) {
        let unvaulting = Unvaulting::new(UnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        });

        let builder = Builder::new();
        let builder = if let Some(pk) = params.alternate_pk {
            builder.push_x_only_key(&pk)
        } else {
            builder.push_opcode(opcodes::OP_0)
        };
        let builder = builder
            .push_slice(unvaulting.get_taptree().get_root_hash())
            .push_int(0)
            .push_opcode(OP_CHECKCONTRACTVERIFY.into())
            .push_x_only_key(&params.unvault_pk)
            .push_opcode(opcodes::all::OP_CHECKSIG);
        builder.into_script()
    },
    next_outputs(params, args, _state) {
        // next_outputs body
        let unvaulting = Unvaulting::new(UnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        });

        ccv_list![
            preserve(args.out_i) => unvaulting; UnvaultingState::new(args.ctv_hash),
        ]
    }
);

// clause: trigger_and_revault

define_clause!(
    VaultTriggerAndRevaultClause,
    VaultTriggerAndRevaultClauseArgs,
    "trigger_and_revault",
    VaultParams,
    (),
    args {
        sig: [u8; 64] => ArgSpec::Bytes,
        ctv_hash: [u8; 32] => ArgSpec::Bytes,
        out_i: i32 => ArgSpec::Int,
        revault_out_i: i32 => ArgSpec::Int,
    },
    script(params) {
        let unvaulting = Unvaulting::new(UnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        });

        let builder = Builder::new()
            .push_int(0)
            .push_opcode(opcodes::all::OP_SWAP)
            .push_int(-1)
            .push_int(-1)
            .push_int(CCV_FLAG_DEDUCT_OUTPUT_AMOUNT.into())
            .push_opcode(OP_CHECKCONTRACTVERIFY.into());

        let builder = if let Some(pk) = params.alternate_pk {
            builder.push_x_only_key(&pk)
        } else {
            builder.push_opcode(opcodes::OP_0)
        };
        let builder = builder
            .push_slice(unvaulting.get_taptree().get_root_hash())
            .push_int(0)
            .push_opcode(OP_CHECKCONTRACTVERIFY.into())
            .push_x_only_key(&params.unvault_pk)
            .push_opcode(opcodes::all::OP_CHECKSIG);
        builder.into_script()
    },
    next_outputs(params, args, _state) {
        let unvaulting = Unvaulting::new(UnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        });

        ccv_list![
            deduct(args.revault_out_i) => Vault::new(params.clone()),
            preserve(args.out_i) => unvaulting; UnvaultingState::new(args.ctv_hash)
        ]
    }
);

// clause: recover

define_clause!(
    VaultRecoverClause,
    VaultRecoverClauseArgs,
    "recover",
    VaultParams,
    (),
    args { },
    script(params) {
        Builder::new()
            .push_int(0)
            .push_opcode(opcodes::all::OP_SWAP)
            .push_x_only_key(&params.recover_pk)
            .push_int(0)
            .push_int(0)
            .push_opcode(OP_CHECKCONTRACTVERIFY.into())
            .push_opcode(opcodes::OP_TRUE)
            .into_script()
    },
    next_outputs(_params, _args, _state) {
        ccv_list![]
    }
);

define_contract!(
    Vault,
    VaultParams,
    (),
    taptree: (VaultTriggerAndRevaultClause, (VaultTriggerClause, VaultRecoverClause))
);

#[derive(Debug, Clone)]
struct UnvaultingParams {
    alternate_pk: Option<XOnlyPublicKey>,
    spend_delay: u32,
    recover_pk: XOnlyPublicKey,
}

// Define the UnvaultingState
#[derive(Debug)]
struct UnvaultingState {
    ctv_hash: [u8; 32],
}

impl UnvaultingState {
    fn new(ctv_hash: [u8; 32]) -> Self {
        Self { ctv_hash }
    }
}

impl ContractState for UnvaultingState {
    fn encode(&self) -> [u8; 32] {
        self.ctv_hash
    }
}

// clause: withdraw

define_clause!(
    UnvaultingWithdrawClause,
    UnvaultingWithdrawClauseArgs,
    "withdraw",
    UnvaultingParams,
    UnvaultingState,
    args {
        ctv_hash: [u8; 32] => ArgSpec::Bytes,
    },
    script(params) {
        let builder = Builder::new().push_int(-1);
        let builder = if let Some(pk) = params.alternate_pk {
            builder.push_x_only_key(&pk)
        } else {
            builder.push_opcode(opcodes::OP_0)
        };
        let builder = builder
            .push_int(-1)
            .push_int(CCV_FLAG_CHECK_INPUT.into())
            .push_opcode(OP_CHECKCONTRACTVERIFY.into())
            .push_int(params.spend_delay.into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(OP_CHECKTEMPLATEVERIFY.into());
        builder.into_script()
    },
    next_outputs(_params, _args, _state) {
        ccv_list![]
    }
);

// clause: recover

define_clause!(
    UnvaultingRecoverClause,
    UnvaultingRecoverClauseArgs,
    "Recover",
    UnvaultingParams,
    UnvaultingState,
    args {
        out_i: i32 => ArgSpec::Int,
    },
    script(params) {
        Builder::new()
            .push_int(0)
            .push_opcode(opcodes::all::OP_SWAP)
            .push_x_only_key(&params.recover_pk)
            .push_int(0)
            .push_int(0)
            .push_opcode(OP_CHECKCONTRACTVERIFY.into())
            .push_opcode(opcodes::OP_TRUE)
            .into_script()
    },
    next_outputs(_params, _args, _state) {
        ccv_list![]
    }
);

define_contract!(
    Unvaulting,
    UnvaultingParams,
    UnvaultingState,
    taptree: (UnvaultingWithdrawClause, UnvaultingRecoverClause)
);

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
