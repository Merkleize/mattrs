use std::any::Any;
use std::fmt::Debug;

use bitcoin::{ScriptBuf, XOnlyPublicKey};

pub const OP_CHECKCONTRACTVERIFY: u8 = 0xbb;
pub const OP_CHECKTEMPLATEVERIFY: u8 = 0xb3;

pub const CCV_FLAG_CHECK_INPUT: i32 = -1;
pub const CCV_FLAG_IGNORE_OUTPUT_AMOUNT: i32 = 1;
pub const CCV_FLAG_DEDUCT_OUTPUT_AMOUNT: i32 = 2;

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
    fn get_taptree_merkle_root(&self) -> [u8; 32];
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

macro_rules! define_clause_args {
    (
        $args_name:ident,
        {
            $(
                $field:ident : $type:ty => $arg_spec:expr
            ),* $(,)?
        }
    ) => {
        #[derive(Debug, Clone)]
        pub struct $args_name {
            $(pub $field : $type),*
        }

        impl ClauseArguments for $args_name {
            fn as_arg_specs() -> ArgSpecs {
                vec![
                    $(
                        (stringify!($field).to_string(), $arg_spec),
                    )*
                ]
            }
        }
    };
}

#[macro_export]
macro_rules! define_clause {
    (
        $clause_struct_name:ident,
        $clause_string_name:expr,
        $contract_params:ty,
        $clause_args:ty,
        $contract_state:ty,
        script($script_params:tt) $script_body:block,
        next_outputs($no_params:tt,$no_args:tt,$no_state:tt) $next_outputs_body:block
    ) => {
        #[derive(Debug, Clone)]
        pub struct $clause_struct_name {}

        impl Clause<$contract_params, $clause_args, $contract_state> for $clause_struct_name {
            fn name() -> String {
                $clause_string_name.into()
            }

            fn script($script_params: &$contract_params) -> ScriptBuf {
                $script_body
            }

            fn arg_specs() -> ArgSpecs {
                <$clause_args>::as_arg_specs()
            }

            fn next_outputs(
                $no_params: &$contract_params,
                $no_args: &$clause_args,
                $no_state: &$contract_state,
            ) -> ClauseOutputs {
                $next_outputs_body
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        hashes::Hash,
        opcodes,
        script::Builder,
        taproot::{self, LeafVersion},
        TapLeafHash, XOnlyPublicKey,
    };

    #[derive(Debug, Clone)]
    struct VaultParams {
        alternate_pk: Option<XOnlyPublicKey>,
        spend_delay: u32,
        recover_pk: XOnlyPublicKey,
        unvault_pk: XOnlyPublicKey,
    }
    #[derive(Debug, Clone)]
    struct Vault {
        pub params: VaultParams,
    }
    impl Vault {
        pub fn new(params: VaultParams) -> Self {
            Self { params }
        }
    }

    // clause: trigger

    define_clause_args!(
        VaultTriggerClauseArgs,
        {
            sig: [u8; 64] => ArgSpec::Bytes,
            ctv_hash: [u8; 32] => ArgSpec::Bytes,
            out_i: i32 => ArgSpec::Int,
        }
    );

    define_clause!(
        VaultTriggerClause,
        "trigger",
        VaultParams,
        VaultTriggerClauseArgs,
        (),
        script(params) {
            // script body
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
                .push_slice(unvaulting.get_taptree_merkle_root())
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

    define_clause_args!(
        VaultTriggerAndRevaultClauseArgs,
        {
            sig: [u8; 64] => ArgSpec::Bytes,
            ctv_hash: [u8; 32] => ArgSpec::Bytes,
            out_i: i32 => ArgSpec::Int,
            revault_out_i: i32 => ArgSpec::Int,
        }
    );

    define_clause!(
        VaultTriggerAndRevaultClause,
        "trigger_and_revault",
        VaultParams,
        VaultTriggerAndRevaultClauseArgs,
        (),
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
                .push_slice(unvaulting.get_taptree_merkle_root())
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

    define_clause_args!(
        VaultRecoverClauseArgs,
        {
            out_i: i32 => ArgSpec::Int,
        }
    );

    define_clause!(
        VaultRecoverClause,
        "recover",
        VaultParams,
        VaultRecoverClauseArgs,
        (),
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

    impl Contract<VaultParams> for Vault {
        fn get_taptree_merkle_root(&self) -> [u8; 32] {
            let trigger_script = VaultTriggerClause::script(&self.params);
            let trigger_and_revault_script = VaultTriggerAndRevaultClause::script(&self.params);
            let recover_script = VaultRecoverClause::script(&self.params);

            // Compute TapLeafHashes
            let t = TapLeafHash::from_script(&trigger_script, LeafVersion::TapScript);
            let tr = TapLeafHash::from_script(&trigger_and_revault_script, LeafVersion::TapScript);
            let r = TapLeafHash::from_script(&recover_script, LeafVersion::TapScript);

            taproot::TapNodeHash::from_node_hashes(
                tr.into(),
                taproot::TapNodeHash::from_node_hashes(t.into(), r.into()),
            )
            .to_raw_hash()
            .to_byte_array()
        }
    }

    #[derive(Debug, Clone)]
    struct Unvaulting {
        params: UnvaultingParams,
    }
    impl Unvaulting {
        pub fn new(params: UnvaultingParams) -> Self {
            Self { params }
        }
    }

    #[derive(Debug, Clone)]
    struct UnvaultingParams {
        alternate_pk: Option<XOnlyPublicKey>,
        spend_delay: u32,
        recover_pk: XOnlyPublicKey,
    }

    impl Contract<UnvaultingParams, UnvaultingState> for Unvaulting {
        fn get_taptree_merkle_root(&self) -> [u8; 32] {
            let withdraw_script = UnvaultingWithdrawClause::script(&self.params);
            let recover_script = UnvaultingRecoverClause::script(&self.params);

            // Compute TapLeafHashes
            let w = TapLeafHash::from_script(&withdraw_script, LeafVersion::TapScript);
            let r = TapLeafHash::from_script(&recover_script, LeafVersion::TapScript);

            taproot::TapNodeHash::from_node_hashes(w.into(), r.into())
                .to_raw_hash()
                .to_byte_array()
        }
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

    define_clause_args!(
        UnvaultingWithdrawClauseArgs,
        {
            ctv_hash: [u8; 32] => ArgSpec::Bytes,
        }
    );

    define_clause!(
        UnvaultingWithdrawClause,
        "withdraw",
        UnvaultingParams,
        UnvaultingWithdrawClauseArgs,
        (),
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

    define_clause_args!(
        UnvaultingRecoverClauseArgs,
        {
            out_i: i32 => ArgSpec::Int,
        }
    );

    define_clause!(
        UnvaultingRecoverClause,
        "recover",
        UnvaultingParams,
        UnvaultingRecoverClauseArgs,
        (),
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
}
