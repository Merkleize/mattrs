use std::fmt::Debug;

use bitcoin::{ScriptBuf, XOnlyPublicKey};

pub const OP_CHECKCONTRACTVERIFY: u8 = 0xbb;
pub const OP_CHECKTEMPLATEVERIFY: u8 = 0xb3;

pub const CCV_FLAG_CHECK_INPUT: i32 = -1;
pub const CCV_FLAG_IGNORE_OUTPUT_AMOUNT: i32 = 1;
pub const CCV_FLAG_DEDUCT_OUTPUT_AMOUNT: i32 = 2;

pub trait CloneBox {
    fn clone_box(&self) -> Box<dyn Contract>;
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
pub trait ClauseArguments {}

pub struct Clause<A: ClauseArguments, S: ContractState> {
    name: String,
    script: ScriptBuf,
    arg_specs: ArgSpecs,
    next_outputs_fn: Box<dyn Fn(A, S) -> ClauseOutputs>,
}

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

/// Describes the State of a ContractInstance.
pub trait ContractState: Debug {
    /// Encodes the state of an instance into the 32-byte data format that can be encoded in the UTXO.
    fn encode(&self) -> [u8; 32];

    /// Returns a CScript that computes the commitment to the state, assuming that the top of the stack contains the
    /// values of the individual stack items that allow to compute the state commitment, as output by the encode() function.
    /// Contracts might decide not to implement this (and raise an error if this is called), but they must document how the
    /// state commitment should be computed if not. Contracts implementing it should document what the expected stack
    /// elements are when the encoder_script is used.
    fn encoder_script(&self) -> ScriptBuf {
        panic!("Not implemented for this State")
    }
}

// TODO: do we want this? Or do we distinguish between stateful and stateless contracts/clauses etc?
impl ContractState for () {
    fn encode(&self) -> [u8; 32] {
        panic!("Empty state cannot be encoded")
    }
}

pub trait Contract: Debug + CloneBox {
    // Returns the list of clauses of this contract
    fn get_taptree_merkle_root(&self) -> [u8; 32];
}

pub trait ContractInstance {}

// MACROS

macro_rules! clause {
    // Pattern when next_outputs_fn is provided
    (
        name: $name:expr,
        script: $script:expr,
        args {
            $($arg_name:ident : $arg_spec:expr => $arg_type:ty),* $(,)?
        },
        next_outputs_fn($args_ident:ident, $state_ident:ident) $fn_body:block
    ) => {
        {
            // Define the argument struct
            #[derive(Debug)]
            struct Args {
                $(pub $arg_name: $arg_type),*
            }

            // Implement ClauseArguments for the argument struct
            impl ClauseArguments for Args {}

            // Create the argument specifications
            let arg_specs: ArgSpecs = vec![
                $( (stringify!($arg_name).to_string(), $arg_spec) ),*
            ];

            // Create the next_outputs_fn closure
            let next_outputs_fn = {
                move |$args_ident: Args, $state_ident| $fn_body
            };

            // Construct the Clause instance
            Clause {
                name: $name.into(),
                script: $script,
                arg_specs,
                next_outputs_fn: Box::new(next_outputs_fn),
            }
        }
    };
    // Pattern when next_outputs_fn is omitted
    (
        name: $name:expr,
        script: $script:expr,
        args {
            $($arg_name:ident : $arg_spec:expr => $arg_type:ty),* $(,)?
        }
    ) => {
        {
            // Define the argument struct
            #[derive(Debug)]
            struct Args {
                $(pub $arg_name: $arg_type),*
            }

            // Implement ClauseArguments for the argument struct
            impl ClauseArguments for Args {}

            // Create the argument specifications
            let arg_specs: ArgSpecs = vec![
                $( (stringify!($arg_name).to_string(), $arg_spec) ),*
            ];

            // Create the default next_outputs_fn closure
            let next_outputs_fn = {
                move |_args: Args, _state| ClauseOutputs::CcvList(vec![])
            };

            // Construct the Clause instance
            Clause {
                name: $name.into(),
                script: $script,
                arg_specs,
                next_outputs_fn: Box::new(next_outputs_fn),
            }
        }
    };
}

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
                    next_contract: $contract.clone_box(),
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

#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::Hash,
        opcodes,
        script::Builder,
        taproot::{self, LeafVersion},
        TapLeafHash, XOnlyPublicKey,
    };
    use bitcoin_script::bitcoin_script;

    use super::*;

    #[derive(Debug, Clone)]
    struct Vault {
        alternate_pk: Option<XOnlyPublicKey>,
        spend_delay: u32,
        recover_pk: XOnlyPublicKey,
        unvault_pk: XOnlyPublicKey,
    }

    #[derive(Debug, Clone)]
    struct Vault_State {}

    impl CloneBox for Vault {
        fn clone_box(&self) -> Box<dyn Contract> {
            Box::new(self.clone())
        }
    }

    impl Contract for Vault {
        fn get_taptree_merkle_root(&self) -> [u8; 32] {
            let unvaulting = Unvaulting {
                alternate_pk: self.alternate_pk,
                spend_delay: self.spend_delay,
                recover_pk: self.recover_pk,
            };

            // Clause: trigger

            let trigger = clause! {
                name: "trigger",
                script: {
                    let builder = Builder::new();
                    let builder = if let Some(pk) = self.alternate_pk {
                        builder.push_x_only_key(&pk)
                    } else {
                        builder.push_opcode(opcodes::OP_0)
                    };
                    let builder = builder
                        .push_slice(unvaulting.get_taptree_merkle_root())
                        .push_int(0)
                        .push_opcode(OP_CHECKCONTRACTVERIFY.into())
                        .push_x_only_key(&self.unvault_pk)
                        .push_opcode(opcodes::all::OP_CHECKSIG);
                    builder.into_script()
                },
                // script: {
                //     bitcoin_script! {
                //         <if let Some(pk) = self.alternate_pk { pk } else { 0 }>
                //         <unvaulting.get_taptree_merkle_root()>
                //         0
                //         OP_RETURN_187 // wrong, doesn't exist in bitcoin_script crate
                //         <self.unvault_pk>
                //         OP_CHECKSIG
                //     }
                // },
                args {
                    sig: ArgSpec::Bytes => [u8; 64],
                    ctv_hash: ArgSpec::Bytes => [u8; 32],
                    out_i: ArgSpec::Int => i32,
                },
                next_outputs_fn(args, _state) {
                    ccv_list![
                        preserve(args.out_i) => unvaulting; UnvaultingState::new(args.ctv_hash),
                    ]
                }
            };

            // Clause: trigger_and_revault

            let trigger_and_revault = clause! {
                name: "trigger_and_revault",
                script: {
                    let builder = Builder::new()
                        .push_int(0)
                        .push_opcode(opcodes::all::OP_SWAP)
                        .push_int(-1)
                        .push_int(-1)
                        .push_int(CCV_FLAG_DEDUCT_OUTPUT_AMOUNT.into())
                        .push_opcode(OP_CHECKCONTRACTVERIFY.into());

                    let builder = if let Some(pk) = self.alternate_pk {
                        builder.push_x_only_key(&pk)
                    } else {
                        builder.push_opcode(opcodes::OP_0)
                    };
                    let builder = builder
                        .push_slice(unvaulting.get_taptree_merkle_root())
                        .push_int(0)
                        .push_opcode(OP_CHECKCONTRACTVERIFY.into())
                        .push_x_only_key(&self.unvault_pk)
                        .push_opcode(opcodes::all::OP_CHECKSIG);
                    builder.into_script()
                },
                args {
                    sig: ArgSpec::Bytes => [u8; 64],
                    ctv_hash: ArgSpec::Bytes => [u8; 32],
                    out_i: ArgSpec::Int => i32,
                    revault_out_i: ArgSpec::Int => i32,
                },
                next_outputs_fn(args, _state) {
                    ccv_list![
                        deduct(args.revault_out_i) => self,
                        preserve(args.out_i) => unvaulting; UnvaultingState::new(args.ctv_hash)
                    ]
                }
            };

            // Clause: recover

            let recover = clause! {
                name: "recover",
                script: {
                    Builder::new()
                        .push_int(0)
                        .push_opcode(opcodes::all::OP_SWAP)
                        .push_x_only_key(&self.recover_pk)
                        .push_int(0)
                        .push_int(0)
                        .push_opcode(OP_CHECKCONTRACTVERIFY.into())
                        .push_opcode(opcodes::OP_TRUE)
                        .into_script()
                },
                args {
                    out_i: ArgSpec::Int => i32,
                },
                next_outputs_fn(args, _state) {
                    ccv_list![]
                }
            };
            let t = TapLeafHash::from_script(trigger.script.as_script(), LeafVersion::TapScript);
            let tr = TapLeafHash::from_script(
                trigger_and_revault.script.as_script(),
                LeafVersion::TapScript,
            );
            let r = TapLeafHash::from_script(recover.script.as_script(), LeafVersion::TapScript);

            taproot::TapNodeHash::from_node_hashes(
                tr.into(),
                taproot::TapNodeHash::from_node_hashes(t.into(), r.into()),
            )
            .to_raw_hash()
            .to_byte_array()
        }
    }

    #[derive(Debug)]
    struct VaultTriggerArgs {
        sig: [u8; 64],
        ctv_hash: [u8; 32],
        out_i: i32,
    }

    #[derive(Debug)]
    struct UnvaultingState {
        ctv_hash: [u8; 32],
    }

    impl ContractState for UnvaultingState {
        fn encode(&self) -> [u8; 32] {
            self.ctv_hash
        }
    }
    impl UnvaultingState {
        fn new(ctv_hash: [u8; 32]) -> Self {
            Self { ctv_hash }
        }
    }

    #[derive(Debug, Clone)]
    struct Unvaulting {
        alternate_pk: Option<XOnlyPublicKey>,
        spend_delay: u32,
        recover_pk: XOnlyPublicKey,
    }

    impl CloneBox for Unvaulting {
        fn clone_box(&self) -> Box<dyn Contract> {
            Box::new(self.clone())
        }
    }

    impl Contract for Unvaulting {
        fn get_taptree_merkle_root(&self) -> [u8; 32] {
            let withdraw = clause! {
                name: "recover",
                script: {
                    let builder = Builder::new().push_int(-1);
                    let builder = if let Some(pk) = self.alternate_pk {
                        builder.push_x_only_key(&pk)
                    } else {
                        builder.push_opcode(opcodes::OP_0)
                    };
                    let builder = builder
                        .push_int(-1)
                        .push_int(CCV_FLAG_CHECK_INPUT.into())
                        .push_opcode(OP_CHECKCONTRACTVERIFY.into())
                        .push_int(self.spend_delay.into())
                        .push_opcode(opcodes::all::OP_CSV)
                        .push_opcode(opcodes::all::OP_DROP)
                        .push_opcode(OP_CHECKTEMPLATEVERIFY.into());
                    builder.into_script()
                },
                args {
                    ctv_hash: ArgSpec::Bytes => [u8; 32],
                }
            };

            let recover = clause! {
                name: "recover",
                script: {
                    Builder::new()
                        .push_int(0)
                        .push_opcode(opcodes::all::OP_SWAP)
                        .push_x_only_key(&self.recover_pk)
                        .push_int(0)
                        .push_int(0)
                        .push_opcode(OP_CHECKCONTRACTVERIFY.into())
                        .push_opcode(opcodes::OP_TRUE)
                        .into_script()
                },
                args {
                    out_i: ArgSpec::Int => i32,
                }
            };

            let w = TapLeafHash::from_script(withdraw.script.as_script(), LeafVersion::TapScript);
            let r = TapLeafHash::from_script(recover.script.as_script(), LeafVersion::TapScript);

            taproot::TapNodeHash::from_node_hashes(w.into(), r.into())
                .to_raw_hash()
                .to_byte_array()
        }
    }
}
