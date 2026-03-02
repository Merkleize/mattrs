use std::collections::HashMap;

use bitcoin::XOnlyPublicKey;
use bitcoin_script::{define_pushable, script};

use crate::ccv::{
    CCV_FLAG_CHECK_INPUT, CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, NUMS_KEY,
};
use crate::contracts::{CcvAmountBehaviour, Clause, ClauseOutput, Contract};
use crate::taproot::TapTree;
use crate::{define_clause_args, define_state, optional_key};

define_pushable!();

// --- Vault ---

#[derive(Debug, Clone)]
pub struct VaultParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
    pub unvault_pk: XOnlyPublicKey,
}

define_clause_args! {
    TriggerArgs {
        sig: bytes[64],
        ctv_hash: bytes[32],
        out_i: i32,
    }
}

define_clause_args! {
    TriggerAndRevaultArgs {
        sig: bytes[64],
        ctv_hash: bytes[32],
        out_i: i32,
        revault_out_i: i32,
    }
}

// Recover clause has no args (empty witness besides script+control block)

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
        let script = {
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
        Clause {
            name: "trigger".into(),
            script,
            signer_args: HashMap::from([("sig".into(), params.unvault_pk)]),
            args_to_witness: Box::new(|args| {
                let a = TriggerArgs::from_clause_args(args)?;
                Ok(vec![a.sig.to_vec(), a.ctv_hash.to_vec(), {
                    let mut buf = [0u8; 8];
                    let len = bitcoin::script::write_scriptint(&mut buf, a.out_i as i64);
                    buf[..len].to_vec()
                }])
            }),
            witness_to_args: Box::new(|stack| {
                if stack.len() != 3 {
                    return Err(format!("trigger: expected 3 witness elements, got {}", stack.len()).into());
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&stack[0]);
                let mut ctv_hash = [0u8; 32];
                ctv_hash.copy_from_slice(&stack[1]);
                let out_i = bitcoin::script::read_scriptint(&stack[2])
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?
                    as i32;
                Ok(TriggerArgs { sig, ctv_hash, out_i }.to_clause_args())
            }),
            next_outputs: Box::new(move |args, _state| {
                let ctv_hash = args.get("ctv_hash")
                    .ok_or("Missing ctv_hash")?
                    .clone();
                let out_i_bytes = args.get("out_i")
                    .ok_or("Missing out_i")?;
                let out_i = bitcoin::script::read_scriptint(out_i_bytes)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?
                    as i32;
                Ok(vec![ClauseOutput {
                    n: out_i,
                    next_contract: unvaulting_for_next.clone(),
                    next_state: ctv_hash,
                    amount_behaviour: CcvAmountBehaviour::Preserve,
                }])
            }),
        }
    };

    // --- trigger_and_revault clause ---
    let trigger_and_revault = {
        let vault_params = params.clone();
        let unvaulting_for_next = unvaulting.clone();
        let script = {
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

        Clause {
            name: "trigger_and_revault".into(),
            script,
            signer_args: HashMap::from([("sig".into(), params.unvault_pk)]),
            args_to_witness: Box::new(|args| {
                let a = TriggerAndRevaultArgs::from_clause_args(args)?;
                Ok(vec![a.sig.to_vec(), a.ctv_hash.to_vec(), {
                    let mut buf = [0u8; 8];
                    let len = bitcoin::script::write_scriptint(&mut buf, a.out_i as i64);
                    buf[..len].to_vec()
                }, {
                    let mut buf = [0u8; 8];
                    let len = bitcoin::script::write_scriptint(&mut buf, a.revault_out_i as i64);
                    buf[..len].to_vec()
                }])
            }),
            witness_to_args: Box::new(|stack| {
                if stack.len() != 4 {
                    return Err(format!("trigger_and_revault: expected 4 witness elements, got {}", stack.len()).into());
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&stack[0]);
                let mut ctv_hash = [0u8; 32];
                ctv_hash.copy_from_slice(&stack[1]);
                let out_i = bitcoin::script::read_scriptint(&stack[2])
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?
                    as i32;
                let revault_out_i = bitcoin::script::read_scriptint(&stack[3])
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?
                    as i32;
                Ok(TriggerAndRevaultArgs { sig, ctv_hash, out_i, revault_out_i }.to_clause_args())
            }),
            next_outputs: Box::new(move |args, _state| {
                let ctv_hash = args.get("ctv_hash")
                    .ok_or("Missing ctv_hash")?
                    .clone();
                let out_i_bytes = args.get("out_i")
                    .ok_or("Missing out_i")?;
                let out_i = bitcoin::script::read_scriptint(out_i_bytes)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?
                    as i32;
                let revault_out_i_bytes = args.get("revault_out_i")
                    .ok_or("Missing revault_out_i")?;
                let revault_out_i = bitcoin::script::read_scriptint(revault_out_i_bytes)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?
                    as i32;

                let revault_contract = make_vault(&vault_params);
                Ok(vec![
                    ClauseOutput {
                        n: revault_out_i,
                        next_contract: revault_contract,
                        next_state: vec![],
                        amount_behaviour: CcvAmountBehaviour::Deduct,
                    },
                    ClauseOutput {
                        n: out_i,
                        next_contract: unvaulting_for_next.clone(),
                        next_state: ctv_hash,
                        amount_behaviour: CcvAmountBehaviour::Preserve,
                    },
                ])
            }),
        }
    };

    // --- recover clause ---
    let recover = {
        let script = {
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

        Clause {
            name: "recover".into(),
            script,
            signer_args: HashMap::new(),
            args_to_witness: Box::new(|_args| Ok(vec![])),
            witness_to_args: Box::new(|_stack| Ok(HashMap::new())),
            next_outputs: Box::new(|_args, _state| Ok(vec![])),
        }
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

define_clause_args! {
    WithdrawArgs {
        ctv_hash: bytes[32],
    }
}

define_clause_args! {
    UnvaultingRecoverArgs {
        ctv_hash: bytes[32],
    }
}

pub fn make_unvaulting(params: &UnvaultingParams) -> Contract {
    let pk = params
        .alternate_pk
        .unwrap_or_else(|| XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap());

    // --- withdraw clause ---
    let withdraw = {
        let script = {
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

        Clause {
            name: "withdraw".into(),
            script,
            signer_args: HashMap::new(),
            args_to_witness: Box::new(|args| {
                let a = WithdrawArgs::from_clause_args(args)?;
                Ok(vec![a.ctv_hash.to_vec()])
            }),
            witness_to_args: Box::new(|stack| {
                if stack.len() != 1 {
                    return Err(format!("withdraw: expected 1 witness element, got {}", stack.len()).into());
                }
                let mut ctv_hash = [0u8; 32];
                ctv_hash.copy_from_slice(&stack[0]);
                Ok(WithdrawArgs { ctv_hash }.to_clause_args())
            }),
            next_outputs: Box::new(|_args, _state| Ok(vec![])),
        }
    };

    // --- recover clause ---
    let recover = {
        let script = {
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

        Clause {
            name: "recover".into(),
            script,
            signer_args: HashMap::new(),
            args_to_witness: Box::new(|args| {
                let a = UnvaultingRecoverArgs::from_clause_args(args)?;
                Ok(vec![a.ctv_hash.to_vec()])
            }),
            witness_to_args: Box::new(|stack| {
                if stack.len() != 1 {
                    return Err(format!("recover: expected 1 witness element, got {}", stack.len()).into());
                }
                let mut ctv_hash = [0u8; 32];
                ctv_hash.copy_from_slice(&stack[0]);
                Ok(UnvaultingRecoverArgs { ctv_hash }.to_clause_args())
            }),
            next_outputs: Box::new(|_args, _state| Ok(vec![])),
        }
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
    fn test_trigger_args_roundtrip() {
        let original = TriggerArgs {
            sig: [0xAB; 64],
            ctv_hash: [0xCD; 32],
            out_i: 42,
        };

        let clause_args = original.to_clause_args();
        let decoded = TriggerArgs::from_clause_args(&clause_args).unwrap();

        assert_eq!(original.sig, decoded.sig);
        assert_eq!(original.ctv_hash, decoded.ctv_hash);
        assert_eq!(original.out_i, decoded.out_i);
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

        let args = TriggerArgs {
            sig: [0u8; 64],
            ctv_hash: [0xAA; 32],
            out_i: 0,
        };
        let clause_args = args.to_clause_args();
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
