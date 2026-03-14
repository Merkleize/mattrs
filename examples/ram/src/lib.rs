use std::collections::HashMap;

use bitcoin::opcodes::all::*;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;

use mattrs::ccv::{CCV_FLAG_CHECK_INPUT, NUMS_KEY, OP_CHECKCONTRACTVERIFY};
use mattrs::contract;
use mattrs::contracts::{Bytes, CcvAmountBehaviour, Clause, ClauseOutput, Contract};
use mattrs::merkle::{floor_lg, is_power_of_2, MerkleProof};
use mattrs::script_helpers::{check_input_contract, push_number};
use mattrs::taproot::TapTree;

contract! {
    RamInstance, RamClause {
        fn write(merkle_proof: Bytes, new_value: [u8; 32], merkle_root: [u8; 32]) -> (RamInstance);
        fn withdraw(merkle_proof: Bytes, merkle_root: [u8; 32]) -> ();
    }
}

// ---------------------------------------------------------------------------
// Compact binary encoding for MerkleProof in ClauseArgs
// ---------------------------------------------------------------------------

/// Encode a MerkleProof into a single compact binary blob.
/// Format: `[n:u8] [h1:32 d1:1 ... hn:32 dn:1] [x:32]`
pub fn proof_to_arg(proof: &MerkleProof) -> Vec<u8> {
    let n = proof.hashes.len();
    let mut buf = Vec::with_capacity(1 + n * 33 + 32);
    buf.push(n as u8);
    for (h, &d) in proof.hashes.iter().zip(&proof.directions) {
        buf.extend_from_slice(h);
        buf.push(d as u8);
    }
    buf.extend_from_slice(&proof.x);
    buf
}

/// Decode a MerkleProof from the compact binary format.
pub fn proof_from_arg(data: &[u8]) -> Result<MerkleProof, Box<dyn std::error::Error + Send + Sync>> {
    if data.is_empty() {
        return Err("Empty proof arg".into());
    }
    let n = data[0] as usize;
    let expected_len = 1 + n * 33 + 32;
    if data.len() != expected_len {
        return Err(format!("Expected {} bytes, got {}", expected_len, data.len()).into());
    }
    let mut hashes = Vec::with_capacity(n);
    let mut directions = Vec::with_capacity(n);
    let mut pos = 1;
    for _ in 0..n {
        let h: [u8; 32] = data[pos..pos + 32].try_into().unwrap();
        hashes.push(h);
        directions.push(data[pos + 32] != 0);
        pos += 33;
    }
    let x: [u8; 32] = data[pos..pos + 32].try_into().unwrap();
    Ok(MerkleProof::new(hashes, directions, x))
}

// ---------------------------------------------------------------------------
// RAM contract
// ---------------------------------------------------------------------------

/// Build a RAM contract with `size` leaves.
///
/// Two clauses:
/// - **withdraw**: terminal spend proving leaf membership via Merkle proof
/// - **write**: atomic leaf update, self-referencing via CCV (taptree=-1)
pub fn make_ram(size: usize) -> Contract {
    assert!(is_power_of_2(size));
    let n = floor_lg(size) as usize;
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap();

    // -----------------------------------------------------------------------
    // Withdraw clause
    // -----------------------------------------------------------------------
    // Witness: <h_1> <d_1> ... <h_n> <d_n> <x> <root>
    // Script:
    //   DUP TOALTSTACK
    //   check_input_contract()
    //   [SWAP NOTIF SWAP ENDIF CAT SHA256] * n
    //   FROMALTSTACK EQUAL
    let withdraw_script = {
        let mut bytes = Vec::new();
        bytes.push(OP_DUP.to_u8());
        bytes.push(OP_TOALTSTACK.to_u8());
        bytes.extend_from_slice(check_input_contract().as_bytes());
        for _ in 0..n {
            bytes.push(OP_SWAP.to_u8());
            bytes.push(OP_NOTIF.to_u8());
            bytes.push(OP_SWAP.to_u8());
            bytes.push(OP_ENDIF.to_u8());
            bytes.push(OP_CAT.to_u8());
            bytes.push(OP_SHA256.to_u8());
        }
        bytes.push(OP_FROMALTSTACK.to_u8());
        bytes.push(OP_EQUAL.to_u8());
        ScriptBuf::from(bytes)
    };

    let withdraw_n = n;
    let withdraw = Clause {
        name: "withdraw".into(),
        script: withdraw_script,
        signer_args: HashMap::new(),
        args_to_witness: Box::new(move |args| {
            let proof = proof_from_arg(
                args.get("merkle_proof").ok_or("Missing arg 'merkle_proof'")?,
            )?;
            let root = args.get("merkle_root").ok_or("Missing arg 'merkle_root'")?;
            if proof.hashes.len() != withdraw_n {
                return Err(format!(
                    "Proof depth mismatch: expected {}, got {}",
                    withdraw_n,
                    proof.hashes.len()
                )
                .into());
            }
            let mut wit = proof.to_witness_stack();
            wit.push(root.clone());
            Ok(wit)
        }),
        witness_to_args: Box::new(move |stack| {
            let expected = 2 * withdraw_n + 2;
            if stack.len() != expected {
                return Err(format!(
                    "withdraw: expected {} witness elements, got {}",
                    expected,
                    stack.len()
                )
                .into());
            }
            let proof = MerkleProof::from_witness_stack(&stack[..stack.len() - 1])?;
            let root = stack.last().unwrap().clone();
            let mut args = HashMap::new();
            args.insert("merkle_proof".to_string(), proof_to_arg(&proof));
            args.insert("merkle_root".to_string(), root);
            Ok(args)
        }),
        next_outputs: Box::new(|_, _| Ok(vec![])),
    };

    // -----------------------------------------------------------------------
    // Write clause
    // -----------------------------------------------------------------------
    // Witness: <h_1> <d_1> ... <h_n> <d_n> <x_old> <x_new> <root>
    // Script:
    //   DUP TOALTSTACK
    //   check_input_contract()
    //   [2 ROLL IF <right> ELSE <left> ENDIF CAT SHA256 SWAP] * n
    //   SWAP FROMALTSTACK EQUALVERIFY
    //   -1 0 -1 0 CCV
    //   TRUE
    let write_script = {
        let mut bytes = Vec::new();
        bytes.push(OP_DUP.to_u8());
        bytes.push(OP_TOALTSTACK.to_u8());

        // check_input_contract
        push_number(&mut bytes, -1);
        bytes.push(OP_PUSHBYTES_0.to_u8());
        push_number(&mut bytes, -1);
        push_number(&mut bytes, CCV_FLAG_CHECK_INPUT as i64);
        bytes.push(OP_CHECKCONTRACTVERIFY);

        for _ in 0..n {
            // 2 ROLL
            push_number(&mut bytes, 2);
            bytes.push(OP_ROLL.to_u8());

            bytes.push(OP_IF.to_u8());
            // right child: h || x
            // stack: <h> <x_old> <x_new>
            push_number(&mut bytes, 2);
            bytes.push(OP_PICK.to_u8());
            // stack: <h> <x_old> <x_new> <h>
            bytes.push(OP_SWAP.to_u8());
            bytes.push(OP_CAT.to_u8());
            bytes.push(OP_SHA256.to_u8());
            // stack: <h> <x_old> <SHA(h || x_new)>
            bytes.push(OP_SWAP.to_u8());
            // stack: <h> <SHA(h || x_new)> <x_old>
            bytes.push(OP_ROT.to_u8());
            // stack: <SHA(h || x_new)> <x_old> <h>
            bytes.push(OP_SWAP.to_u8());

            bytes.push(OP_ELSE.to_u8());
            // left child: x || h
            // stack: <h> <x_old> <x_new>
            push_number(&mut bytes, 2);
            bytes.push(OP_PICK.to_u8());
            // stack: <h> <x_old> <x_new> <h>
            bytes.push(OP_CAT.to_u8());
            bytes.push(OP_SHA256.to_u8());
            // stack: <h> <x_old> <SHA(x_new || h)>
            bytes.push(OP_SWAP.to_u8());
            bytes.push(OP_ROT.to_u8());
            // stack: <SHA(x_new || h)> <x_old> <h>

            bytes.push(OP_ENDIF.to_u8());

            // common: CAT SHA256 SWAP
            bytes.push(OP_CAT.to_u8());
            bytes.push(OP_SHA256.to_u8());
            bytes.push(OP_SWAP.to_u8());
        }

        // stack: <old_root> <new_root>
        // alt  : <root>
        bytes.push(OP_SWAP.to_u8());
        bytes.push(OP_FROMALTSTACK.to_u8());
        bytes.push(OP_EQUALVERIFY.to_u8());

        // CCV to enforce output: -1 0 -1 0 CCV
        push_number(&mut bytes, -1);
        bytes.push(OP_PUSHBYTES_0.to_u8());
        push_number(&mut bytes, -1);
        push_number(&mut bytes, 0);
        bytes.push(OP_CHECKCONTRACTVERIFY);

        bytes.push(OP_PUSHNUM_1.to_u8()); // OP_TRUE
        ScriptBuf::from(bytes)
    };

    let write_n = n;
    let write_size = size;
    let write = Clause {
        name: "write".into(),
        script: write_script,
        signer_args: HashMap::new(),
        args_to_witness: Box::new(move |args| {
            let proof = proof_from_arg(
                args.get("merkle_proof").ok_or("Missing arg 'merkle_proof'")?,
            )?;
            let new_value = args.get("new_value").ok_or("Missing arg 'new_value'")?;
            let root = args.get("merkle_root").ok_or("Missing arg 'merkle_root'")?;
            if proof.hashes.len() != write_n {
                return Err(format!(
                    "Proof depth mismatch: expected {}, got {}",
                    write_n,
                    proof.hashes.len()
                )
                .into());
            }
            // Witness: <h_1> <d_1> ... <h_n> <d_n> <x_old> <x_new> <root>
            let mut wit = proof.to_witness_stack();
            wit.push(new_value.clone());
            wit.push(root.clone());
            Ok(wit)
        }),
        witness_to_args: Box::new(move |stack| {
            let expected = 2 * write_n + 3;
            if stack.len() != expected {
                return Err(format!(
                    "write: expected {} witness elements, got {}",
                    expected,
                    stack.len()
                )
                .into());
            }
            // Last 2 elements are new_value and root; everything before is proof
            let proof = MerkleProof::from_witness_stack(&stack[..stack.len() - 2])?;
            let new_value = stack[stack.len() - 2].clone();
            let root = stack[stack.len() - 1].clone();
            let mut args = HashMap::new();
            args.insert("merkle_proof".to_string(), proof_to_arg(&proof));
            args.insert("new_value".to_string(), new_value);
            args.insert("merkle_root".to_string(), root);
            Ok(args)
        }),
        next_outputs: Box::new(move |args, _state| {
            let proof = proof_from_arg(
                args.get("merkle_proof").ok_or("Missing arg 'merkle_proof'")?,
            )?;
            let new_value: [u8; 32] = args
                .get("new_value")
                .ok_or("Missing arg 'new_value'")?
                .as_slice()
                .try_into()
                .map_err(|_| "new_value must be 32 bytes")?;

            let new_root = proof.get_new_root_after_update(&new_value);
            Ok(vec![ClauseOutput {
                n: -1,
                next_contract: make_ram(write_size),
                next_state: new_root.to_vec(),
                amount_behaviour: CcvAmountBehaviour::Preserve,
            }])
        }),
    };

    Contract::new(
        format!("RAM_{}", size),
        nums,
        TapTree::Branch {
            left: Box::new(TapTree::Leaf(withdraw)),
            right: Box::new(TapTree::Leaf(write)),
        },
    )
}
