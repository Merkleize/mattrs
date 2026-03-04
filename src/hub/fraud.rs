use std::sync::Arc;

use bitcoin::opcodes::all::*;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;

use crate::ccv::NUMS_KEY;
use crate::contracts::{
    ArgType, CcvAmountBehaviour, ClauseOutput, Contract, StateData, standard_clause,
};
use crate::merkle::{self, is_power_of_2};
use crate::script_helpers::{
    cat_scripts, check_input_contract, check_output_contract, drop_script, dup_script,
    encoder_script, older_script,
};
use crate::taproot::TapTree;

// ---------------------------------------------------------------------------
// Computer
// ---------------------------------------------------------------------------

/// Describes how to compute and encode a single step: y = func(x), h = encoder(x).
pub struct Computer {
    /// Script to hash the top-of-stack value (e.g. SHA256).
    pub encoder: ScriptBuf,
    /// Script to compute f(x) from x on the stack (e.g. DUP ADD).
    pub func: ScriptBuf,
    /// Argument specs for the input value x.
    pub specs: Vec<(&'static str, ArgType)>,
}

/// The `2x` computer: f(x) = 2*x, encoder = SHA256.
pub fn compute_2x() -> Computer {
    Computer {
        encoder: ScriptBuf::from(vec![OP_SHA256.to_u8()]),
        func: ScriptBuf::from(vec![OP_DUP.to_u8(), OP_ADD.to_u8()]),
        specs: vec![("x", ArgType::Int)],
    }
}

// ---------------------------------------------------------------------------
// State encoding helpers
// ---------------------------------------------------------------------------

/// Leaf state: merkle_root([h_start, h_end_alice, h_end_bob]) — 3 leaves
pub fn leaf_state(h_start: [u8; 32], h_end_alice: [u8; 32], h_end_bob: [u8; 32]) -> StateData {
    merkle::merkle_root(&[h_start, h_end_alice, h_end_bob]).to_vec()
}

/// Bisect_1 state: merkle_root([h_start, h_end_a, h_end_b, trace_a, trace_b]) — 5 leaves
pub fn bisect1_state(
    h_start: [u8; 32],
    h_end_a: [u8; 32],
    h_end_b: [u8; 32],
    trace_a: [u8; 32],
    trace_b: [u8; 32],
) -> StateData {
    merkle::merkle_root(&[h_start, h_end_a, h_end_b, trace_a, trace_b]).to_vec()
}

/// Bisect_2 state: merkle_root([h_start, h_end_a, h_end_b, trace_a, trace_b, h_mid_a, trace_left_a, trace_right_a]) — 8 leaves
pub fn bisect2_state(
    h_start: [u8; 32],
    h_end_a: [u8; 32],
    h_end_b: [u8; 32],
    trace_a: [u8; 32],
    trace_b: [u8; 32],
    h_mid_a: [u8; 32],
    trace_left_a: [u8; 32],
    trace_right_a: [u8; 32],
) -> StateData {
    merkle::merkle_root(&[
        h_start,
        h_end_a,
        h_end_b,
        trace_a,
        trace_b,
        h_mid_a,
        trace_left_a,
        trace_right_a,
    ])
    .to_vec()
}

// ---------------------------------------------------------------------------
// Leaf contract
// ---------------------------------------------------------------------------

/// Build a Leaf contract.
///
/// Two terminal clauses:
/// - alice_reveal: Alice proves she computed the step correctly
/// - bob_reveal: Bob proves he computed the step correctly
pub fn make_leaf(
    alice_pk: XOnlyPublicKey,
    bob_pk: XOnlyPublicKey,
    computer: &Computer,
) -> Contract {
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap();
    let n_specs = computer.specs.len();

    // alice_reveal: <alice_sig> <x...> <h_y_b>
    // Script: TOALTSTACK, dup(specs), encoder, TOALTSTACK, func, encoder,
    //         FROMALTSTACK SWAP FROMALTSTACK, merkle_root(3), check_input, alice_pk CHECKSIG
    let alice_reveal = {
        let script = cat_scripts(&[
            op(OP_TOALTSTACK),
            dup_script(n_specs),
            computer.encoder.clone(),
            op(OP_TOALTSTACK),
            computer.func.clone(),
            computer.encoder.clone(),
            // stack: <alice_sig> <h_y>  altstack: [h_y_b, h_x]
            // → <alice_sig> <h_x> <h_y> <h_y_b>
            ScriptBuf::from(vec![
                OP_FROMALTSTACK.to_u8(),
                OP_SWAP.to_u8(),
                OP_FROMALTSTACK.to_u8(),
            ]),
            encoder_script(3),
            check_input_contract(),
            push_pk(alice_pk),
            op(OP_CHECKSIG),
        ]);

        let mut arg_specs: Vec<(&'static str, ArgType)> =
            vec![("alice_sig", signer_type(alice_pk))];
        arg_specs.extend(computer.specs.iter().cloned());
        arg_specs.push(("h_y_b", ArgType::Bytes(32)));

        standard_clause("alice_reveal", script, arg_specs, |_, _| Ok(vec![]))
    };

    // bob_reveal: <bob_sig> <x...> <h_y_a>
    // Script: TOALTSTACK, dup(specs), encoder, TOALTSTACK, func, encoder,
    //         FROMALTSTACK SWAP FROMALTSTACK SWAP, merkle_root(3), check_input, bob_pk CHECKSIG
    let bob_reveal = {
        let script = cat_scripts(&[
            op(OP_TOALTSTACK),
            dup_script(n_specs),
            computer.encoder.clone(),
            op(OP_TOALTSTACK),
            computer.func.clone(),
            computer.encoder.clone(),
            // stack: <bob_sig> <h_y>  altstack: [h_y_a, h_start]
            // → <bob_sig> <h_start> <h_y_a> <h_y>
            ScriptBuf::from(vec![
                OP_FROMALTSTACK.to_u8(),
                OP_SWAP.to_u8(),
                OP_FROMALTSTACK.to_u8(),
                OP_SWAP.to_u8(),
            ]),
            encoder_script(3),
            check_input_contract(),
            push_pk(bob_pk),
            op(OP_CHECKSIG),
        ]);

        let mut arg_specs: Vec<(&'static str, ArgType)> =
            vec![("bob_sig", signer_type(bob_pk))];
        arg_specs.extend(computer.specs.iter().cloned());
        arg_specs.push(("h_y_a", ArgType::Bytes(32)));

        standard_clause("bob_reveal", script, arg_specs, |_, _| Ok(vec![]))
    };

    Contract::new(
        "Leaf",
        nums,
        TapTree::Branch {
            left: Box::new(TapTree::Leaf(alice_reveal)),
            right: Box::new(TapTree::Leaf(bob_reveal)),
        },
    )
}

// ---------------------------------------------------------------------------
// Bisect_1 contract
// ---------------------------------------------------------------------------

/// Build a Bisect_1 contract for interval [i, j].
///
/// State: merkle_root([h_start, h_end_a, h_end_b, trace_a, trace_b])
///
/// Clauses:
/// - alice_reveal → Bisect_2
/// - forfait → Bob wins (timeout)
pub fn make_bisect_1(
    alice_pk: XOnlyPublicKey,
    bob_pk: XOnlyPublicKey,
    i: usize,
    j: usize,
    leaf_factory: &dyn Fn(usize) -> Contract,
    forfait_timeout: u32,
) -> Contract {
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap();
    assert!(j > i);
    let n = j - i + 1;
    assert!(n >= 2 && is_power_of_2(n));

    let bisect_2 = make_bisect_2(alice_pk, bob_pk, i, j, leaf_factory, forfait_timeout);

    // alice_reveal: <alice_sig> <h_start> <h_end_a> <h_end_b> <trace_a> <trace_b> <h_mid_a> <trace_left_a> <trace_right_a>
    //
    // After TOALTSTACK*3 + dup(5) + encoder_script(5) + check_input + FROMALTSTACK*3:
    // Stack positions (0=top):
    //   0=trace_right_a, 1=trace_left_a, 2=h_mid_a,
    //   3=trace_b, 4=trace_a, 5=h_end_b, 6=h_end_a, 7=h_start, 8=alice_sig
    //
    // Trace equation check (matching pymatt exactly):
    //   7 PICK (h_start), 7 PICK (h_end_a), CAT,
    //   2 PICK (trace_left_a), CAT, 1 PICK (trace_right_a), CAT, SHA256,
    //   5 PICK (trace_a), EQUALVERIFY
    let alice_reveal = {
        let b2_encoder = encoder_script(8);
        let b2_ccv = check_output_contract(&bisect_2);

        let script = cat_scripts(&[
            ops(&[OP_TOALTSTACK, OP_TOALTSTACK, OP_TOALTSTACK]),
            dup_script(5),
            encoder_script(5),
            check_input_contract(),
            ops(&[OP_FROMALTSTACK, OP_FROMALTSTACK, OP_FROMALTSTACK]),
            // trace equation
            pick(7),
            pick(7),
            op(OP_CAT),
            pick(2),
            op(OP_CAT),
            pick(1),
            op(OP_CAT),
            op(OP_SHA256),
            pick(5),
            op(OP_EQUALVERIFY),
            // check output
            b2_encoder,
            b2_ccv,
            push_pk(alice_pk),
            op(OP_CHECKSIG),
        ]);

        let bisect_2_for_next = bisect_2.clone();
        standard_clause(
            "alice_reveal",
            script,
            vec![
                ("alice_sig", signer_type(alice_pk)),
                ("h_start", ArgType::Bytes(32)),
                ("h_end_a", ArgType::Bytes(32)),
                ("h_end_b", ArgType::Bytes(32)),
                ("trace_a", ArgType::Bytes(32)),
                ("trace_b", ArgType::Bytes(32)),
                ("h_mid_a", ArgType::Bytes(32)),
                ("trace_left_a", ArgType::Bytes(32)),
                ("trace_right_a", ArgType::Bytes(32)),
            ],
            move |args, _| {
                Ok(vec![ClauseOutput {
                    n: -1,
                    next_contract: bisect_2_for_next.clone(),
                    next_state: bisect2_state(
                        to32(&args["h_start"]),
                        to32(&args["h_end_a"]),
                        to32(&args["h_end_b"]),
                        to32(&args["trace_a"]),
                        to32(&args["trace_b"]),
                        to32(&args["h_mid_a"]),
                        to32(&args["trace_left_a"]),
                        to32(&args["trace_right_a"]),
                    ),
                    amount_behaviour: CcvAmountBehaviour::Preserve,
                }])
            },
        )
    };

    // forfait: Bob wins after timeout
    let forfait = standard_clause(
        "forfait",
        cat_scripts(&[older_script(forfait_timeout), push_pk(bob_pk), op(OP_CHECKSIG)]),
        vec![("bob_sig", signer_type(bob_pk))],
        |_, _| Ok(vec![]),
    );

    Contract::new(
        "Bisect_1",
        nums,
        TapTree::Branch {
            left: Box::new(TapTree::Leaf(alice_reveal)),
            right: Box::new(TapTree::Leaf(forfait)),
        },
    )
}

// ---------------------------------------------------------------------------
// Bisect_2 contract
// ---------------------------------------------------------------------------

/// Build a Bisect_2 contract for interval [i, j].
///
/// State: merkle_root([h_start, h_end_a, h_end_b, trace_a, trace_b, h_mid_a, trace_left_a, trace_right_a])
///
/// Clauses:
/// - bob_reveal_left → left child (Bisect_1 or Leaf)
/// - bob_reveal_right → right child (Bisect_1 or Leaf)
/// - forfait → Alice wins (timeout)
pub fn make_bisect_2(
    alice_pk: XOnlyPublicKey,
    bob_pk: XOnlyPublicKey,
    i: usize,
    j: usize,
    leaf_factory: &dyn Fn(usize) -> Contract,
    forfait_timeout: u32,
) -> Contract {
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap();
    assert!(j > i);
    let n = j - i + 1;
    assert!(n >= 2 && is_power_of_2(n));
    let m = n / 2;
    let are_children_leaves = m == 1;

    let (child_left, child_right) = if are_children_leaves {
        (leaf_factory(i), leaf_factory(i + 1))
    } else {
        (
            make_bisect_1(alice_pk, bob_pk, i, i + m - 1, leaf_factory, forfait_timeout),
            make_bisect_1(alice_pk, bob_pk, i + m, j, leaf_factory, forfait_timeout),
        )
    };

    let bob_arg_specs = || {
        vec![
            ("bob_sig", signer_type(bob_pk)),
            ("h_start", ArgType::Bytes(32)),
            ("h_end_a", ArgType::Bytes(32)),
            ("h_end_b", ArgType::Bytes(32)),
            ("trace_a", ArgType::Bytes(32)),
            ("trace_b", ArgType::Bytes(32)),
            ("h_mid_a", ArgType::Bytes(32)),
            ("trace_left_a", ArgType::Bytes(32)),
            ("trace_right_a", ArgType::Bytes(32)),
            ("h_mid_b", ArgType::Bytes(32)),
            ("trace_left_b", ArgType::Bytes(32)),
            ("trace_right_b", ArgType::Bytes(32)),
        ]
    };

    // Common preamble for bob_reveal_left and bob_reveal_right:
    // After TOALTSTACK*3 + dup(8) + encoder_script(8) + check_input + FROMALTSTACK*3:
    //
    // Stack positions (0=top):
    //   0=trace_right_b, 1=trace_left_b, 2=h_mid_b,
    //   3=trace_right_a, 4=trace_left_a, 5=h_mid_a,
    //   6=trace_b, 7=trace_a, 8=h_end_b, 9=h_end_a, 10=h_start, 11=bob_sig
    //
    // Trace equation (Bob's trace, matching pymatt exactly):
    //   10 PICK (h_start), 9 PICK (h_end_b), CAT,
    //   2 PICK (trace_left_b), CAT, 1 PICK (trace_right_b), CAT, SHA256,
    //   7 PICK (trace_b), EQUALVERIFY

    let trace_check = cat_scripts(&[
        ops(&[OP_TOALTSTACK, OP_TOALTSTACK, OP_TOALTSTACK]),
        dup_script(8),
        encoder_script(8),
        check_input_contract(),
        ops(&[OP_FROMALTSTACK, OP_FROMALTSTACK, OP_FROMALTSTACK]),
        pick(10),
        pick(9),
        op(OP_CAT),
        pick(2),
        op(OP_CAT),
        pick(1),
        op(OP_CAT),
        op(OP_SHA256),
        pick(7),
        op(OP_EQUALVERIFY),
    ]);

    // bob_reveal_left: h_mid_a != h_mid_b → iterate on left child
    let bob_reveal_left = {
        let child_ccv = check_output_contract(&child_left);
        let output_check = if are_children_leaves {
            // Leaf state: [h_start, h_mid_a, h_mid_b]
            // After h_mid check, stack is back to 12 original items
            cat_scripts(&[
                pick(10),        // h_start
                pick(1 + 5),     // h_mid_a
                pick(2 + 2),     // h_mid_b
                encoder_script(3),
                child_ccv,
            ])
        } else {
            // Bisect_1 state: [h_start, h_mid_a, h_mid_b, trace_left_a, trace_left_b]
            cat_scripts(&[
                pick(10),        // h_start
                pick(1 + 5),     // h_mid_a
                pick(2 + 2),     // h_mid_b
                pick(3 + 4),     // trace_left_a
                pick(4 + 1),     // trace_left_b
                encoder_script(5),
                child_ccv,
            ])
        };

        let script = cat_scripts(&[
            trace_check.clone(),
            // check h_mid_a != h_mid_b
            pick(5),
            pick(3),
            ops(&[OP_EQUAL, OP_NOT, OP_VERIFY]),
            output_check,
            drop_script(11),
            push_pk(bob_pk),
            op(OP_CHECKSIG),
        ]);

        let child = child_left.clone();
        standard_clause(
            "bob_reveal_left",
            script,
            bob_arg_specs(),
            move |args, _| {
                let next_state = if are_children_leaves {
                    leaf_state(to32(&args["h_start"]), to32(&args["h_mid_a"]), to32(&args["h_mid_b"]))
                } else {
                    bisect1_state(
                        to32(&args["h_start"]),
                        to32(&args["h_mid_a"]),
                        to32(&args["h_mid_b"]),
                        to32(&args["trace_left_a"]),
                        to32(&args["trace_left_b"]),
                    )
                };
                Ok(vec![ClauseOutput {
                    n: -1,
                    next_contract: child.clone(),
                    next_state,
                    amount_behaviour: CcvAmountBehaviour::Preserve,
                }])
            },
        )
    };

    // bob_reveal_right: h_mid_a == h_mid_b → iterate on right child
    let bob_reveal_right = {
        let child_ccv = check_output_contract(&child_right);
        let output_check = if are_children_leaves {
            // Leaf state: [h_mid_a, h_end_a, h_end_b]
            cat_scripts(&[
                pick(5),         // h_mid_a
                pick(1 + 9),     // h_end_a
                pick(2 + 8),     // h_end_b
                encoder_script(3),
                child_ccv,
            ])
        } else {
            // Bisect_1 state: [h_mid_a, h_end_a, h_end_b, trace_right_a, trace_right_b]
            cat_scripts(&[
                pick(5),         // h_mid_a
                pick(1 + 9),     // h_end_a
                pick(2 + 8),     // h_end_b
                pick(3 + 3),     // trace_right_a
                pick(4 + 0),     // trace_right_b
                encoder_script(5),
                child_ccv,
            ])
        };

        let script = cat_scripts(&[
            trace_check,
            // check h_mid_a == h_mid_b
            pick(5),
            pick(3),
            op(OP_EQUALVERIFY),
            output_check,
            drop_script(11),
            push_pk(bob_pk),
            op(OP_CHECKSIG),
        ]);

        let child = child_right.clone();
        standard_clause(
            "bob_reveal_right",
            script,
            bob_arg_specs(),
            move |args, _| {
                let next_state = if are_children_leaves {
                    leaf_state(
                        to32(&args["h_mid_a"]),
                        to32(&args["h_end_a"]),
                        to32(&args["h_end_b"]),
                    )
                } else {
                    bisect1_state(
                        to32(&args["h_mid_a"]),
                        to32(&args["h_end_a"]),
                        to32(&args["h_end_b"]),
                        to32(&args["trace_right_a"]),
                        to32(&args["trace_right_b"]),
                    )
                };
                Ok(vec![ClauseOutput {
                    n: -1,
                    next_contract: child.clone(),
                    next_state,
                    amount_behaviour: CcvAmountBehaviour::Preserve,
                }])
            },
        )
    };

    // forfait: Alice wins after timeout
    let forfait = standard_clause(
        "forfait",
        cat_scripts(&[older_script(forfait_timeout), push_pk(alice_pk), op(OP_CHECKSIG)]),
        vec![("alice_sig", signer_type(alice_pk))],
        |_, _| Ok(vec![]),
    );

    // Taptree layout: [[bob_reveal_left, bob_reveal_right], forfait]
    Contract::new(
        "Bisect_2",
        nums,
        TapTree::Branch {
            left: Box::new(TapTree::Branch {
                left: Box::new(TapTree::Leaf(bob_reveal_left)),
                right: Box::new(TapTree::Leaf(bob_reveal_right)),
            }),
            right: Box::new(TapTree::Leaf(forfait)),
        },
    )
}

// ---------------------------------------------------------------------------
// Script building helpers
// ---------------------------------------------------------------------------

/// Single opcode as ScriptBuf.
fn op(opcode: bitcoin::opcodes::Opcode) -> ScriptBuf {
    ScriptBuf::from(vec![opcode.to_u8()])
}

/// Multiple opcodes as ScriptBuf.
fn ops(opcodes: &[bitcoin::opcodes::Opcode]) -> ScriptBuf {
    ScriptBuf::from(opcodes.iter().map(|o| o.to_u8()).collect::<Vec<_>>())
}

/// N PICK instruction.
fn pick(n: usize) -> ScriptBuf {
    let mut bytes = Vec::new();
    push_number_to(&mut bytes, n as i64);
    bytes.push(OP_PICK.to_u8());
    ScriptBuf::from(bytes)
}

/// Push an x-only pubkey (32 bytes) onto the script.
fn push_pk(pk: XOnlyPublicKey) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(33);
    bytes.push(OP_PUSHBYTES_32.to_u8());
    bytes.extend_from_slice(&pk.serialize());
    ScriptBuf::from(bytes)
}

/// Push a script number.
fn push_number_to(bytes: &mut Vec<u8>, n: i64) {
    match n {
        -1 => bytes.push(OP_PUSHNUM_NEG1.to_u8()),
        0 => bytes.push(OP_PUSHBYTES_0.to_u8()),
        1..=16 => bytes.push((OP_PUSHNUM_1.to_u8() as i64 + n - 1) as u8),
        _ => {
            let mut buf = [0u8; 8];
            let len = bitcoin::script::write_scriptint(&mut buf, n);
            bytes.push(len as u8);
            bytes.extend_from_slice(&buf[..len]);
        }
    }
}

/// Create a Signer ArgType for the given pubkey.
fn signer_type(pk: XOnlyPublicKey) -> ArgType {
    ArgType::Signer(Arc::new(move |_, _| pk))
}

/// Convert a &[u8] to [u8; 32].
fn to32(data: &[u8]) -> [u8; 32] {
    data.try_into().expect("expected 32 bytes")
}
