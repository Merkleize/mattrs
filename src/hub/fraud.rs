use std::sync::Arc;

use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;

use bitcoin_script::{define_pushable, script};

use crate::ccv::NUMS_KEY;
use crate::contract;
use crate::contracts::{
    ArgType, CcvAmountBehaviour, ClauseOutput, Contract, StateData, standard_clause,
};
use crate::merkle::merkle_root_script;
use crate::merkle::{self, is_power_of_2};
use crate::script_helpers::{
    check_input_contract, check_output_contract, drop_script, dup, older_script,
};
use crate::taproot::TapTree;

define_pushable!();

contract! {
    LeafInstance, LeafClause {
        fn alice_reveal(alice_sig: sig, x: i32, h_y_b: [u8; 32]) -> ();
        fn bob_reveal(bob_sig: sig, x: i32, h_y_a: [u8; 32]) -> ();
    }
}

contract! {
    Bisect1Instance, Bisect1Clause {
        fn alice_reveal(alice_sig: sig, h_start: [u8; 32], h_end_a: [u8; 32], h_end_b: [u8; 32], trace_a: [u8; 32], trace_b: [u8; 32], h_mid_a: [u8; 32], trace_left_a: [u8; 32], trace_right_a: [u8; 32]) -> (Bisect2Instance);
        fn forfait(bob_sig: sig) -> ();
    }
}

/// Wraps either a Bisect1Instance or LeafInstance index.
/// Use `.as_bisect1()` / `.as_leaf()` to convert based on protocol step.
pub struct BisectChildInstance(pub usize);
impl BisectChildInstance {
    pub fn idx(&self) -> usize { self.0 }
    pub fn as_bisect1(self) -> Bisect1Instance { Bisect1Instance(self.0) }
    pub fn as_leaf(self) -> LeafInstance { LeafInstance(self.0) }
}

contract! {
    Bisect2Instance, Bisect2Clause {
        fn bob_reveal_left(bob_sig: sig, h_start: [u8; 32], h_end_a: [u8; 32], h_end_b: [u8; 32], trace_a: [u8; 32], trace_b: [u8; 32], h_mid_a: [u8; 32], trace_left_a: [u8; 32], trace_right_a: [u8; 32], h_mid_b: [u8; 32], trace_left_b: [u8; 32], trace_right_b: [u8; 32]) -> (BisectChildInstance);
        fn bob_reveal_right(bob_sig: sig, h_start: [u8; 32], h_end_a: [u8; 32], h_end_b: [u8; 32], trace_a: [u8; 32], trace_b: [u8; 32], h_mid_a: [u8; 32], trace_left_a: [u8; 32], trace_right_a: [u8; 32], h_mid_b: [u8; 32], trace_left_b: [u8; 32], trace_right_b: [u8; 32]) -> (BisectChildInstance);
        fn forfait(alice_sig: sig) -> ();
    }
}

// ---------------------------------------------------------------------------
// Computer
// ---------------------------------------------------------------------------

/// Describes how to compute and encode a single step: y = func(x), h = encoder(x).
#[derive(Clone)]
pub struct Computer {
    /// Script to hash the top-of-stack value (e.g. SHA256).
    pub encoder: ScriptBuf,
    /// Script to compute f(x) from x on the stack (e.g. DUP ADD).
    pub func: ScriptBuf,
    /// Argument specs for the input value x.
    pub specs: Vec<(&'static str, ArgType)>,
}

/// Build a complete fraud-proof contract for a uniform computation.
///
/// This is the high-level entry point: callers only provide the `Computer`
/// describing a single step; the framework wires up the full bisection tree
/// and leaf contracts.
pub fn make_fraud_proof(
    alice_pk: XOnlyPublicKey,
    bob_pk: XOnlyPublicKey,
    i: usize,
    j: usize,
    computer: &Computer,
    forfait_timeout: u32,
) -> Contract {
    let computer = computer.clone();
    let leaf_factory = move |_step: usize| make_leaf(alice_pk, bob_pk, &computer);
    make_bisect_1(alice_pk, bob_pk, i, j, &leaf_factory, forfait_timeout)
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
    let alice_reveal = {
        let dup_n = dup(n_specs);
        let encoder = computer.encoder.clone();
        let func = computer.func.clone();
        let encoder2 = computer.encoder.clone();
        let mr3 = merkle_root_script(3);
        let chk_in = check_input_contract();
        let script = script! {
            TOALTSTACK
            <dup_n>
            <encoder>
            TOALTSTACK
            <func>
            <encoder2>
            // <alice_sig> <h_y>  --  <h_y_b> <h_x>
            FROMALTSTACK
            SWAP
            FROMALTSTACK
            <mr3>
            <chk_in>
            <alice_pk>
            CHECKSIG
        };

        let mut arg_specs: Vec<(&'static str, ArgType)> =
            vec![("alice_sig", signer_type(alice_pk))];
        arg_specs.extend(computer.specs.iter().cloned());
        arg_specs.push(("h_y_b", ArgType::Bytes(32)));

        standard_clause("alice_reveal", script, arg_specs, |_, _| Ok(vec![]))
    };

    // bob_reveal: <bob_sig> <x...> <h_y_a>
    let bob_reveal = {
        let dup_n = dup(n_specs);
        let encoder = computer.encoder.clone();
        let func = computer.func.clone();
        let encoder2 = computer.encoder.clone();
        let mr3 = merkle_root_script(3);
        let chk_in = check_input_contract();
        let script = script! {
            TOALTSTACK
            <dup_n>
            <encoder>
            TOALTSTACK
            <func>
            <encoder2>
            // <bob_sig> <h_y>  --  <h_y_a> <h_start>
            FROMALTSTACK
            SWAP
            FROMALTSTACK
            SWAP
            <mr3>
            <chk_in>
            <bob_pk>
            CHECKSIG
        };

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

    // alice_reveal: <alice_sig> <h_i> <h_{j+1;a}> <h_{j+1;b}> <t_{i,j;a}> <t_{i,j;b}> <h_{i+m;a}> <t_{i,i+m-1;a}> <t_{i+m,j;a}>
    let alice_reveal = {
        let b2_encoder = merkle_root_script(8);
        let b2_ccv = check_output_contract(&bisect_2);
        let dup5 = dup(5);
        let mr5 = merkle_root_script(5);
        let chk_in = check_input_contract();

        let script = script! {
            TOALTSTACK TOALTSTACK TOALTSTACK
            <dup5>
            <mr5>
            <chk_in>
            FROMALTSTACK FROMALTSTACK FROMALTSTACK
            // check equation for t_{i,j;a}:
            //   t_{i,j;a} = H(h_i || h_{j+1;a} || t_{i,i+m-1;a} || t_{i+m,j;a})
            7 PICK  // h_i
            7 PICK  // h_{j+1;a}
            CAT
            2 PICK  // t_{i,i+m-1;a}
            CAT
            1 PICK  // t_{i+m,j;a}
            CAT
            SHA256
            5 PICK  // t_{i,j;a}
            EQUALVERIFY
            // check output
            <b2_encoder>
            <b2_ccv>
            <alice_pk>
            CHECKSIG
        };

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
    let older = older_script(forfait_timeout);
    let forfait = standard_clause(
        "forfait",
        script! { <older> <bob_pk> CHECKSIG },
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
    // verify embedded data, then check equation for t_{i,j;b}
    let trace_check = {
        let dup8 = dup(8);
        let mr8 = merkle_root_script(8);
        let chk_in = check_input_contract();
        script! {
            TOALTSTACK TOALTSTACK TOALTSTACK
            <dup8>
            <mr8>
            <chk_in>
            FROMALTSTACK FROMALTSTACK FROMALTSTACK
            // check equation for t_{i,j;b}:
            //   t_{i,j;b} = H(h_i || h_{j+1;b} || t_{i,i+m-1;b} || t_{i+m,j;b})
            10 PICK  // h_i
            9 PICK   // h_{j+1;b}
            CAT
            2 PICK   // t_{i,i+m-1;b}
            CAT
            1 PICK   // t_{i+m,j;b}
            CAT
            SHA256
            7 PICK   // t_{i,j;b}
            EQUALVERIFY
        }
    };

    // bob_reveal_left: h_{i+m;a} != h_{i+m;b} → iterate on left child
    let bob_reveal_left = {
        let child_ccv = check_output_contract(&child_left);
        let output_check = if are_children_leaves {
            // [h_i, h_{i+m;a}, h_{i+m;b}]
            let mr3 = merkle_root_script(3);
            script! {
                10 PICK        // h_i
                6 PICK         // h_{i+m;a}
                4 PICK         // h_{i+m;b}
                <mr3>
                <child_ccv>
            }
        } else {
            // [h_i, h_{i+m;a}, h_{i+m;b}, t_{i,i+m-1;a}, t_{i,i+m-1;b}]
            let mr5 = merkle_root_script(5);
            script! {
                10 PICK        // h_i
                6 PICK         // h_{i+m;a}
                4 PICK         // h_{i+m;b}
                7 PICK         // t_{i,i+m-1;a}
                5 PICK         // t_{i,i+m-1;b}
                <mr5>
                <child_ccv>
            }
        };

        let tc = trace_check.clone();
        let drop11 = drop_script(11);
        let script = script! {
            <tc>
            // check h_{i+m;a} != h_{i+m;b}
            5 PICK
            3 PICK
            EQUAL NOT VERIFY
            <output_check>
            <drop11>
            <bob_pk>
            CHECKSIG
        };

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

    // bob_reveal_right: h_{i+m;a} == h_{i+m;b} → iterate on right child
    let bob_reveal_right = {
        let child_ccv = check_output_contract(&child_right);
        let output_check = if are_children_leaves {
            // [h_{i+m}, h_{j+1;a}, h_{j+1;b}]
            let mr3 = merkle_root_script(3);
            script! {
                5 PICK          // h_{i+m}
                10 PICK         // h_{j+1;a}
                10 PICK         // h_{j+1;b}
                <mr3>
                <child_ccv>
            }
        } else {
            // [h_{i+m}, h_{j+1;a}, h_{j+1;b}, t_{i+m,j;a}, t_{i+m,j;b}]
            let mr5 = merkle_root_script(5);
            script! {
                5 PICK          // h_{i+m}
                10 PICK         // h_{j+1;a}
                10 PICK         // h_{j+1;b}
                6 PICK          // t_{i+m,j;a}
                4 PICK          // t_{i+m,j;b}
                <mr5>
                <child_ccv>
            }
        };

        let drop11 = drop_script(11);
        let script = script! {
            <trace_check>
            // check h_{i+m;a} == h_{i+m;b}
            5 PICK
            3 PICK
            EQUALVERIFY
            <output_check>
            <drop11>
            <bob_pk>
            CHECKSIG
        };

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
    let older = older_script(forfait_timeout);
    let forfait = standard_clause(
        "forfait",
        script! { <older> <alice_pk> CHECKSIG },
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
// Helpers
// ---------------------------------------------------------------------------

/// Create a Signer ArgType for the given pubkey.
fn signer_type(pk: XOnlyPublicKey) -> ArgType {
    ArgType::Signer(Arc::new(move |_, _| pk))
}

/// Convert a &[u8] to [u8; 32].
fn to32(data: &[u8]) -> [u8; 32] {
    data.try_into().expect("expected 32 bytes")
}
