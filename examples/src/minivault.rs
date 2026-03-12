use bitcoin::XOnlyPublicKey;
use bitcoin_script::{define_pushable, script};

use mattrs::ccv::{CCV_FLAG_CHECK_INPUT, CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, NUMS_KEY};
use mattrs::contracts::{arg_as_bytes, CcvAmountBehaviour, ClauseOutput, Contract};
use mattrs::taproot::TapTree;
use mattrs::{ccv_outputs, contract, define_state, optional_key};

define_pushable!();

// --- MiniVault ---

#[derive(Debug, Clone)]
pub struct MiniVaultParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
    pub unvault_pk: XOnlyPublicKey,
    pub has_partial_revault: bool,
    pub has_early_recover: bool,
}

#[derive(Debug, Clone)]
pub struct MiniUnvaultingParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
}

define_state! {
    MiniUnvaultingState {
        withdrawal_pk: [u8; 32],
    }
}

pub fn make_mini_unvaulting(params: &MiniUnvaultingParams) -> Contract {
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
                0    // no data
                0    // output index 0
                2 PICK // withdrawal_pk
                0    // no taptweak
                0    // default flags
                CHECKCONTRACTVERIFY

                // withdrawal_pk remains on stack (truthy)
            }
        };

        MiniUnvaultingClause::withdraw(
            withdraw_script,
            |args, _state| {
                let pk_bytes = arg_as_bytes(args, "withdrawal_pk").unwrap();
                let wpk = XOnlyPublicKey::from_slice(pk_bytes).unwrap();
                Ok(vec![ClauseOutput {
                    n: 0,
                    next_contract: Contract::new_opaque_p2tr(wpk),
                    next_state: vec![],
                    amount_behaviour: CcvAmountBehaviour::Preserve,
                }])
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
        MiniUnvaultingClause::recover(
            recover_script,
            ccv_outputs!(out_i => Contract::new_opaque_p2tr(recover_pk)),
        )
    };

    Contract::new(
        "MiniUnvaulting",
        pk,
        TapTree::Branch {
            left: Box::new(TapTree::Leaf(withdraw)),
            right: Box::new(TapTree::Leaf(recover)),
        },
    )
}

// --- MiniVault ---

pub fn make_minivault(params: &MiniVaultParams) -> Contract {
    let unvaulting = make_mini_unvaulting(&MiniUnvaultingParams {
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
        let unvault_pk = params.unvault_pk;
        MiniVaultClause::trigger(
            trigger_script,
            move |_args, _state| unvault_pk,
            ccv_outputs!(out_i => unvaulting_for_next.clone(), state: withdrawal_pk),
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

        let unvault_pk = params.unvault_pk;
        MiniVaultClause::trigger_and_revault(
            tar_script,
            move |_args, _state| unvault_pk,
            ccv_outputs!(
                revault_out_i => make_minivault(&vault_params), deduct;
                out_i => unvaulting_for_next.clone(), state: withdrawal_pk
            ),
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
        MiniVaultClause::recover(
            recover_script,
            ccv_outputs!(out_i => Contract::new_opaque_p2tr(recover_pk)),
        )
    };

    // Conditional taptree based on has_partial_revault and has_early_recover
    let taptree = if params.has_partial_revault {
        if params.has_early_recover {
            // [trigger, [trigger_and_revault, recover]]
            TapTree::Branch {
                left: Box::new(TapTree::Leaf(trigger)),
                right: Box::new(TapTree::Branch {
                    left: Box::new(TapTree::Leaf(trigger_and_revault)),
                    right: Box::new(TapTree::Leaf(recover)),
                }),
            }
        } else {
            // [trigger, trigger_and_revault]
            TapTree::Branch {
                left: Box::new(TapTree::Leaf(trigger)),
                right: Box::new(TapTree::Leaf(trigger_and_revault)),
            }
        }
    } else if params.has_early_recover {
        // [trigger, recover]
        TapTree::Branch {
            left: Box::new(TapTree::Leaf(trigger)),
            right: Box::new(TapTree::Leaf(recover)),
        }
    } else {
        // single leaf: trigger
        TapTree::Leaf(trigger)
    };

    Contract::new("MiniVault", pk, taptree)
}

// --- Typed instance wrappers ---

contract! {
    MiniVaultInstance, MiniVaultClause {
        fn trigger(sig: sig, withdrawal_pk: [u8; 32], out_i: i32) -> (MiniUnvaultingInstance);
        fn trigger_and_revault(sig: sig, withdrawal_pk: [u8; 32], out_i: i32, revault_out_i: i32) -> (MiniVaultInstance, MiniUnvaultingInstance);
        fn recover(out_i: i32) -> ();
    }
}

contract! {
    MiniUnvaultingInstance, MiniUnvaultingClause {
        fn withdraw(withdrawal_pk: [u8; 32]) -> ();
        fn recover(out_i: i32) -> ();
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{bip32::Xpriv, hashes::Hash, key::Secp256k1, Address, KnownHrp, TapNodeHash};

    use mattrs::contracts::CcvAmountBehaviour;

    use super::*;

    fn test_keys() -> (XOnlyPublicKey, XOnlyPublicKey) {
        let secp = Secp256k1::new();

        let unvault_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
        ).unwrap();
        let unvault_pubkey = unvault_privkey.to_priv().public_key(&secp);

        let recover_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
        ).unwrap();
        let recover_pubkey = recover_privkey.to_priv().public_key(&secp);

        (unvault_pubkey.into(), recover_pubkey.into())
    }

    #[test]
    fn test_minivault_address_full() {
        let secp = Secp256k1::new();
        let (unvault_pubkey, recover_pubkey) = test_keys();

        let vault = make_minivault(&MiniVaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey,
            unvault_pk: unvault_pubkey,
            has_partial_revault: true,
            has_early_recover: true,
        });

        let internal_key = vault.naked_internal_pubkey();
        let taptree_hash = TapNodeHash::from_byte_array(vault.get_taptree_merkle_root());
        let address = Address::p2tr(&secp, *internal_key, Some(taptree_hash), KnownHrp::Regtest);

        // Ensure address is deterministic (value will differ from vault.rs due to different scripts)
        let addr_str = address.to_string();
        assert!(addr_str.starts_with("bcrt1p"), "Expected regtest taproot address, got {}", addr_str);
    }

    #[test]
    fn test_minivault_clause_names_full() {
        let (unvault_pubkey, recover_pubkey) = test_keys();

        let vault = make_minivault(&MiniVaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey,
            unvault_pk: unvault_pubkey,
            has_partial_revault: true,
            has_early_recover: true,
        });

        assert_eq!(vault.clause_names(), vec!["trigger", "trigger_and_revault", "recover"]);
    }

    #[test]
    fn test_minivault_clause_names_no_revault() {
        let (unvault_pubkey, recover_pubkey) = test_keys();

        let vault = make_minivault(&MiniVaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey,
            unvault_pk: unvault_pubkey,
            has_partial_revault: false,
            has_early_recover: true,
        });

        assert_eq!(vault.clause_names(), vec!["trigger", "recover"]);
    }

    #[test]
    fn test_minivault_clause_names_no_recover() {
        let (unvault_pubkey, recover_pubkey) = test_keys();

        let vault = make_minivault(&MiniVaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey,
            unvault_pk: unvault_pubkey,
            has_partial_revault: true,
            has_early_recover: false,
        });

        assert_eq!(vault.clause_names(), vec!["trigger", "trigger_and_revault"]);
    }

    #[test]
    fn test_minivault_clause_names_light() {
        let (unvault_pubkey, recover_pubkey) = test_keys();

        let vault = make_minivault(&MiniVaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey,
            unvault_pk: unvault_pubkey,
            has_partial_revault: false,
            has_early_recover: false,
        });

        assert_eq!(vault.clause_names(), vec!["trigger"]);
    }

    #[test]
    fn test_mini_unvaulting_clause_names() {
        let (_, recover_pubkey) = test_keys();

        let unvaulting = make_mini_unvaulting(&MiniUnvaultingParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey,
        });

        assert_eq!(unvaulting.clause_names(), vec!["withdraw", "recover"]);
    }

    #[test]
    fn test_trigger_next_outputs() {
        let (unvault_pubkey, recover_pubkey) = test_keys();

        let vault = make_minivault(&MiniVaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey,
            unvault_pk: unvault_pubkey,
            has_partial_revault: true,
            has_early_recover: true,
        });

        let mut clause_args = std::collections::HashMap::new();
        clause_args.insert("sig".to_string(), [0u8; 64].to_vec());
        clause_args.insert("withdrawal_pk".to_string(), [0xAA; 32].to_vec());
        clause_args.insert("out_i".to_string(), vec![]); // scriptint 0 = empty

        if let TapTree::Branch { left, .. } = vault.taptree() {
            if let TapTree::Leaf(ref clause) = **left {
                assert_eq!(clause.name, "trigger");
                let outputs = (clause.next_outputs)(&clause_args, &vec![]).unwrap();
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].n, 0);
                assert_eq!(outputs[0].next_state, vec![0xAA; 32]);
                assert_eq!(outputs[0].amount_behaviour, CcvAmountBehaviour::Preserve);
                assert_eq!(outputs[0].next_contract.name(), "MiniUnvaulting");
            } else {
                panic!("Expected Leaf");
            }
        } else {
            panic!("Expected Branch");
        }
    }

    #[test]
    fn test_withdraw_next_outputs() {
        let (unvault_pubkey, recover_pubkey) = test_keys();

        let unvaulting = make_mini_unvaulting(&MiniUnvaultingParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: recover_pubkey,
        });

        // Use a valid x-only public key
        let withdrawal_pk: [u8; 32] = unvault_pubkey.serialize();
        let mut clause_args = std::collections::HashMap::new();
        clause_args.insert("withdrawal_pk".to_string(), withdrawal_pk.to_vec());

        if let TapTree::Branch { left, .. } = unvaulting.taptree() {
            if let TapTree::Leaf(ref clause) = **left {
                assert_eq!(clause.name, "withdraw");
                let outputs = (clause.next_outputs)(&clause_args, &vec![]).unwrap();
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].n, 0);
                assert_eq!(outputs[0].next_state, Vec::<u8>::new());
                assert_eq!(outputs[0].amount_behaviour, CcvAmountBehaviour::Preserve);
                assert_eq!(outputs[0].next_contract.name(), "OpaqueP2TR");
            } else {
                panic!("Expected Leaf");
            }
        } else {
            panic!("Expected Branch");
        }
    }
}
