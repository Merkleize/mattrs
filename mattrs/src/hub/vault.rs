use bitcoin::XOnlyPublicKey;
use bitcoin_script::{define_pushable, script};

define_pushable!();

use crate::{
    ccv_list,
    contracts::{
        Clause, Contract, ContractParams, Signature, CCV_FLAG_CHECK_INPUT,
        CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, NUMS_KEY,
    },
    define_clause, define_contract, define_params, define_state, optional_key,
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

        // witness: <sig> <ctv-hash> <out_i>
        script! {
            <optional_key(params.alternate_pk)>
            <unvaulting.get_taptree().get_root_hash()>
            0
            CHECKCONTRACTVERIFY

            <params.unvault_pk>
            CHECKSIG
        }
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

        // witness: <sig> <ctv-hash> <trigger_out_i> <revault_out_i>
        script! {
            0 OP_SWAP // no data tweak
            -1 // current input's taptweak
            -1 // taptree
            <CCV_FLAG_DEDUCT_OUTPUT_AMOUNT>
            CHECKCONTRACTVERIFY

            // data and index already on the stack
            <optional_key(params.alternate_pk)>
            <unvaulting.get_taptree().get_root_hash()>
            0
            CHECKCONTRACTVERIFY

            <params.unvault_pk>
            CHECKSIG
        }
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
    // witness: <out_i>
    script(params) {
        script! {
            0 // data
            SWAP // <out_i> (from witness)
            <params.recover_pk>
            0 // taptree
            0 // flags
            CHECKCONTRACTVERIFY
            TRUE
        }
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

define_state!(
    UnvaultingState {
        ctv_hash: [u8; 32]
    },
    encode(state){
        state.ctv_hash
    },
    encoder_script() {
        script! {}
    }
);

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
    // witness: <ctv_hash>
    script(params) {
        script! {
            DUP
            -1 <optional_key(params.alternate_pk)> -1 <CCV_FLAG_CHECK_INPUT> CHECKCONTRACTVERIFY

            // check timelock
            <params.spend_delay>
            CSV
            DROP

            // Check that the transaction output is as expected
            CHECKTEMPLATEVERIFY
        }
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
        script! {
            0 // data
            SWAP // <out_i> (from witness)
            <params.recover_pk>
            0 // taptree
            0 // flags
            CHECKCONTRACTVERIFY
            TRUE        }
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
