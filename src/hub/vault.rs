use bitcoin::XOnlyPublicKey;
use bitcoin_script::{define_pushable, script};

use crate::ccv::{
    CCV_FLAG_CHECK_INPUT, CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, NUMS_KEY,
};
use crate::contracts::{
    arg_as_bytes, arg_as_int, standard_clause, ArgType, CcvAmountBehaviour, ClauseOutput, Contract,
};
use crate::taproot::TapTree;
use crate::{define_state, optional_key, typed_instance};

define_pushable!();

// --- Vault ---

#[derive(Debug, Clone)]
pub struct VaultParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
    pub unvault_pk: XOnlyPublicKey,
}

pub fn make_vault(params: &VaultParams) -> Contract {
    let unvaulting = make_unvaulting(&UnvaultingParams {
        alternate_pk: params.alternate_pk,
        spend_delay: params.spend_delay,
        recover_pk: params.recover_pk,
    });

    let unvaulting_taptree_root = unvaulting.get_taptree_merkle_root();
    let pk = params
        .alternate_pk
        .unwrap_or_else(|| XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap());

    // --- trigger clause ---
    let trigger = {
        let trigger_script = {
            let opt_key = optional_key(params.alternate_pk);
            script! {
                <opt_key>
                <unvaulting_taptree_root>
                0
                CHECKCONTRACTVERIFY

                <params.unvault_pk>
                CHECKSIG
            }
        };

        let unvaulting_for_next = unvaulting.clone();
        standard_clause(
            "trigger",
            trigger_script,
            vec![
                ("sig", ArgType::Signer(params.unvault_pk)),
                ("ctv_hash", ArgType::Bytes(32)),
                ("out_i", ArgType::Int),
            ],
            move |args, _state| {
                Ok(vec![ClauseOutput {
                    n: arg_as_int(args, "out_i")?,
                    next_contract: unvaulting_for_next.clone(),
                    next_state: arg_as_bytes(args, "ctv_hash")?.clone(),
                    amount_behaviour: CcvAmountBehaviour::Preserve,
                }])
            },
        )
    };

    // --- trigger_and_revault clause ---
    let trigger_and_revault = {
        let vault_params = params.clone();
        let unvaulting_for_next = unvaulting.clone();
        let tar_script = {
            let opt_key = optional_key(params.alternate_pk);
            script! {
                0 OP_SWAP  // no data tweak
                -1         // current input's taptweak
                -1         // taptree
                <CCV_FLAG_DEDUCT_OUTPUT_AMOUNT>
                CHECKCONTRACTVERIFY

                // data and index already on the stack
                <opt_key>
                <unvaulting_taptree_root>
                0
                CHECKCONTRACTVERIFY

                <params.unvault_pk>
                CHECKSIG
            }
        };

        standard_clause(
            "trigger_and_revault",
            tar_script,
            vec![
                ("sig", ArgType::Signer(params.unvault_pk)),
                ("ctv_hash", ArgType::Bytes(32)),
                ("out_i", ArgType::Int),
                ("revault_out_i", ArgType::Int),
            ],
            move |args, _state| {
                let revault_contract = make_vault(&vault_params);
                Ok(vec![
                    ClauseOutput {
                        n: arg_as_int(args, "revault_out_i")?,
                        next_contract: revault_contract,
                        next_state: vec![],
                        amount_behaviour: CcvAmountBehaviour::Deduct,
                    },
                    ClauseOutput {
                        n: arg_as_int(args, "out_i")?,
                        next_contract: unvaulting_for_next.clone(),
                        next_state: arg_as_bytes(args, "ctv_hash")?.clone(),
                        amount_behaviour: CcvAmountBehaviour::Preserve,
                    },
                ])
            },
        )
    };

    // --- recover clause ---
    let recover = {
        let recover_script = {
            script! {
                0    // data
                SWAP // <out_i> (from witness)
                <params.recover_pk>
                0    // taptree
                0    // flags
                CHECKCONTRACTVERIFY
                TRUE
            }
        };

        let recover_pk = params.recover_pk;
        standard_clause(
            "recover",
            recover_script,
            vec![("out_i", ArgType::Int)],
            move |args, _state| {
                Ok(vec![ClauseOutput {
                    n: arg_as_int(args, "out_i")?,
                    next_contract: Contract::new_opaque_p2tr(recover_pk),
                    next_state: vec![],
                    amount_behaviour: CcvAmountBehaviour::Preserve,
                }])
            },
        )
    };

    Contract::new(
        "Vault",
        pk,
        TapTree::Branch {
            left: Box::new(TapTree::Leaf(trigger)),
            right: Box::new(TapTree::Branch {
                left: Box::new(TapTree::Leaf(trigger_and_revault)),
                right: Box::new(TapTree::Leaf(recover)),
            }),
        },
    )
}

// --- Unvaulting ---

#[derive(Debug, Clone)]
pub struct UnvaultingParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
}

define_state! {
    UnvaultingState {
        ctv_hash: [u8; 32],
    }
}

pub fn make_unvaulting(params: &UnvaultingParams) -> Contract {
    let pk = params
        .alternate_pk
        .unwrap_or_else(|| XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap());

    // --- withdraw clause ---
    let withdraw = {
        let withdraw_script = {
            let opt_key = optional_key(params.alternate_pk);
            script! {
                DUP
                -1 <opt_key> -1 <CCV_FLAG_CHECK_INPUT> CHECKCONTRACTVERIFY

                // check timelock
                <params.spend_delay>
                CSV
                DROP

                // Check that the transaction output is as expected
                CHECKTEMPLATEVERIFY
            }
        };

        standard_clause(
            "withdraw",
            withdraw_script,
            vec![("ctv_hash", ArgType::Bytes(32))],
            |_args, _state| Ok(vec![]),
        )
    };

    // --- recover clause ---
    let recover = {
        let recover_script = {
            script! {
                0    // data
                SWAP // <out_i> (from witness)
                <params.recover_pk>
                0    // taptree
                0    // flags
                CHECKCONTRACTVERIFY
                TRUE
            }
        };

        let recover_pk = params.recover_pk;
        standard_clause(
            "recover",
            recover_script,
            vec![("out_i", ArgType::Int)],
            move |args, _state| {
                Ok(vec![ClauseOutput {
                    n: arg_as_int(args, "out_i")?,
                    next_contract: Contract::new_opaque_p2tr(recover_pk),
                    next_state: vec![],
                    amount_behaviour: CcvAmountBehaviour::Preserve,
                }])
            },
        )
    };

    Contract::new(
        "Unvaulting",
        pk,
        TapTree::Branch {
            left: Box::new(TapTree::Leaf(withdraw)),
            right: Box::new(TapTree::Leaf(recover)),
        },
    )
}

// --- Typed instance wrappers ---

typed_instance! {
    VaultInstance {
        fn trigger(ctv_hash: bytes[32], out_i: i32) [signed] -> (UnvaultingInstance);
        fn trigger_and_revault(ctv_hash: bytes[32], out_i: i32, revault_out_i: i32) [signed] -> (VaultInstance, UnvaultingInstance);
        fn recover(out_i: i32) -> ();
    }
}

typed_instance! {
    UnvaultingInstance {
        fn recover(out_i: i32) -> ();
    }
}

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

        let vault = make_vault(&VaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey.into(),
            unvault_pk: unvault_pubkey.into(),
        });

        let internal_key = vault.naked_internal_pubkey();
        let taptree_hash = TapNodeHash::from_byte_array(vault.get_taptree_merkle_root());

        let taproot_address =
            Address::p2tr(&secp, *internal_key, Some(taptree_hash), KnownHrp::Regtest);

        assert_eq!(
            taproot_address.to_string(),
            "bcrt1plkh3clum5e2rynql75ufxxqxw898arfumqnua60hwr76q4y0jeksu88u3m"
        );
    }

    #[test]
    fn test_vault_clause_names() {
        let secp = Secp256k1::new();

        let unvault_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
        ).unwrap();
        let unvault_pubkey = unvault_privkey.to_priv().public_key(&secp);

        let recover_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
        ).unwrap();
        let recover_pubkey = recover_privkey.to_priv().public_key(&secp);

        let vault = make_vault(&VaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey.into(),
            unvault_pk: unvault_pubkey.into(),
        });

        let names = vault.clause_names();
        assert_eq!(names, vec!["trigger", "trigger_and_revault", "recover"]);
    }

    #[test]
    fn test_trigger_next_outputs() {
        let secp = Secp256k1::new();

        let unvault_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
        ).unwrap();
        let unvault_pubkey = unvault_privkey.to_priv().public_key(&secp);

        let recover_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
        ).unwrap();
        let recover_pubkey = recover_privkey.to_priv().public_key(&secp);

        let vault = make_vault(&VaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey.into(),
            unvault_pk: unvault_pubkey.into(),
        });

        // Build clause args manually (matching what standard_clause expects)
        let mut clause_args = std::collections::HashMap::new();
        clause_args.insert("sig".to_string(), [0u8; 64].to_vec());
        clause_args.insert("ctv_hash".to_string(), [0xAA; 32].to_vec());
        clause_args.insert("out_i".to_string(), vec![]); // scriptint 0 = empty

        if let TapTree::Branch { left, .. } = vault.taptree() {
            if let TapTree::Leaf(ref clause) = **left {
                assert_eq!(clause.name, "trigger");
                let outputs = (clause.next_outputs)(&clause_args, &vec![]).unwrap();
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].n, 0);
                assert_eq!(outputs[0].next_state, vec![0xAA; 32]);
                assert_eq!(outputs[0].amount_behaviour, CcvAmountBehaviour::Preserve);
                assert_eq!(outputs[0].next_contract.name(), "Unvaulting");
            } else {
                panic!("Expected Leaf");
            }
        } else {
            panic!("Expected Branch");
        }
    }
}
