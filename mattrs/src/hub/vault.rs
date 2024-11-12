/// CONTRACT IMPLEMENTATIONS
use bitcoin::{opcodes, script::Builder, XOnlyPublicKey};

use crate::{
    ccv_list,
    contracts::{
        Clause, Contract, ContractParams, ContractState, Signature, CCV_FLAG_CHECK_INPUT,
        CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, NUMS_KEY, OP_CHECKCONTRACTVERIFY, OP_CHECKTEMPLATEVERIFY,
    },
    define_clause, define_contract, define_params,
};

define_params!(VaultParams {
    alternate_pk: Option<XOnlyPublicKey>,
    spend_delay: u32,
    recover_pk: XOnlyPublicKey,
    unvault_pk: XOnlyPublicKey,
});

// clause: trigger

define_clause!(
    VaultTriggerClause,
    VaultTriggerClauseArgs,
    "trigger",
    VaultParams,
    (),
    args {
        sig: Signature => |p: &VaultParams| p.unvault_pk,
        ctv_hash: [u8; 32],
        out_i: i32,
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
        sig: Signature => |p: &VaultParams| p.unvault_pk,
        ctv_hash: [u8; 32],
        out_i: i32,
        revault_out_i: i32,
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
    params: VaultParams,
    get_pk(params) {
        let nums_pk = XOnlyPublicKey::from_slice(&NUMS_KEY).expect("Valid default key");
        params.alternate_pk.unwrap_or(nums_pk)
    },
    taptree: (VaultTriggerClause, (VaultTriggerAndRevaultClause, VaultRecoverClause))
);

define_params!(UnvaultingParams {
    alternate_pk: Option<XOnlyPublicKey>,
    spend_delay: u32,
    recover_pk: XOnlyPublicKey,
});

// Define the UnvaultingState
#[derive(Debug)]
pub struct UnvaultingState {
    pub ctv_hash: [u8; 32],
}

impl UnvaultingState {
    fn new(ctv_hash: [u8; 32]) -> Self {
        Self { ctv_hash }
    }
}

impl ContractState for UnvaultingState {
    // TODO: implement a define_state macro to hide the boilerplate
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

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
        ctv_hash: [u8; 32],
    },
    script(params) {
        let builder = Builder::new()
            .push_opcode(opcodes::all::OP_DUP);

        let builder = builder.push_int(-1);
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
    "recover",
    UnvaultingParams,
    UnvaultingState,
    args {
        ctv_hash: [u8; 32],
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
    params: UnvaultingParams,
    state: UnvaultingState,
    get_pk(params) {
        let nums_pk = XOnlyPublicKey::from_slice(&NUMS_KEY).expect("Valid default key");
        params.alternate_pk.unwrap_or(nums_pk)
    },
    taptree: (UnvaultingWithdrawClause, UnvaultingRecoverClause)
);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{bip32::Xpriv, hashes::Hash, key::Secp256k1, Address, KnownHrp, TapNodeHash};

    use super::*;

    #[test]
    fn test_vault_address() {
        let secp = Secp256k1::new();

        let unvault_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
        ).unwrap();
        let unvault_pubkey = unvault_privkey.to_priv().public_key(&secp);

        let recover_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
        ).unwrap();
        let recover_pubkey = recover_privkey.to_priv().public_key(&secp);

        let vault = Vault::new(VaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey.into(),
            unvault_pk: unvault_pubkey.into(),
        });

        let internal_key = vault.get_naked_internal_key();
        let taptree_hash = TapNodeHash::from_byte_array(vault.get_taptree().get_root_hash());

        let taproot_address =
            Address::p2tr(&secp, internal_key, Some(taptree_hash), KnownHrp::Regtest);

        assert_eq!(
            taproot_address.to_string(),
            "bcrt1plkh3clum5e2rynql75ufxxqxw898arfumqnua60hwr76q4y0jeksu88u3m"
        );
    }
}
