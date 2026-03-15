use std::sync::Arc;

use bitcoin::XOnlyPublicKey;

use mattrs::ccv::NUMS_KEY;
use mattrs::contracts::{
    arg_as_bytes, arg_as_int, ArgType, Bytes, CcvAmountBehaviour, ClauseArg, ClauseOutput,
    Contract, standard_clause,
};
use bitcoin::opcodes::all::*;
use bitcoin::ScriptBuf;
use mattrs::hub::fraud::{Bisect1Instance, Computer, bisect1_state, make_fraud_proof};
use mattrs::merkle;
use mattrs::script_helpers::{
    check_input_contract, check_output_contract, dup, merkle_root_script, older_script,
};
use mattrs::taproot::TapTree;
use mattrs::{contract, sha256};

use bitcoin_script::{define_pushable, script};
define_pushable!();

// ---------------------------------------------------------------------------
// Computer
// ---------------------------------------------------------------------------

/// The `2x` computer: f(x) = 2*x, encoder = SHA256.
pub fn compute_2x() -> Computer {
    Computer {
        encoder: ScriptBuf::from(vec![OP_SHA256.to_u8()]),
        func: ScriptBuf::from(vec![OP_DUP.to_u8(), OP_ADD.to_u8()]),
        specs: vec![("x", ArgType::Int)],
    }
}

// ---------------------------------------------------------------------------
// Params
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct G256Params {
    pub alice_pk: XOnlyPublicKey,
    pub bob_pk: XOnlyPublicKey,
    pub forfait_timeout: u32,
}

// ---------------------------------------------------------------------------
// G256_S0 — Bob chooses x
// ---------------------------------------------------------------------------

/// Stateless contract. Bob picks x.
///
/// choose: <bob_sig> <x> → S1 with state SHA256(scriptint(x))
pub fn make_g256_s0(params: &G256Params) -> Contract {
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap();

    let s1 = make_g256_s1(params);
    let s1_taptree_root = s1.get_taptree_merkle_root();

    // choose: witness [bob_sig, x]
    // Script: x is on stack, compute SHA256 for state, check output, verify bob_sig
    let choose_script = script! {
        // stack: bob_sig x
        // S1 encoder is SHA256 — applied to x (as scriptint)
        SHA256
        // check output: S1 contract with that state
        0 0 <s1_taptree_root> 0 CHECKCONTRACTVERIFY
        // check bob signature
        <params.bob_pk> CHECKSIG
    };

    let s1_for_next = s1.clone();
    let bob_pk = params.bob_pk;
    let choose = G256S0Clause::choose(
        choose_script,
        move |_, _| bob_pk,
        move |args, _| {
            let x = arg_as_int(args, "x")?;
            let x_bytes = <i32 as ClauseArg>::to_bytes(&x);
            let state = sha256(&x_bytes);
            Ok(vec![ClauseOutput {
                n: -1,
                next_contract: s1_for_next.clone(),
                next_state: state.to_vec(),
                amount_behaviour: CcvAmountBehaviour::Preserve,
            }])
        },
    );

    Contract::new("G256_S0", nums, TapTree::Leaf(choose))
}

// ---------------------------------------------------------------------------
// G256_S1 — Alice reveals her answer
// ---------------------------------------------------------------------------

/// State: SHA256(scriptint(x)).
///
/// reveal: <alice_sig> <t_a> <y> <x> → S2 with state merkle_root([t_a, sha256(y), sha256(x)])
pub fn make_g256_s1(params: &G256Params) -> Contract {
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap();

    let s2 = make_g256_s2(params);

    // reveal: witness [alice_sig, t_a, y, x]
    // Script: DUP SHA256 check_input, then S2 encoder + check_output, alice_pk CHECKSIG
    //
    // S1 state encoder: SHA256 (applied to x on stack)
    // S2 state encoder: TOALTSTACK SHA256 FROMALTSTACK SHA256 merkle_root(3)
    //   Applied to stack [t_a, y, x] → merkle_root([t_a, sha256(y), sha256(x)])
    //   Note: top of stack is x, so: x → SHA256(x), then TOALTSTACK pushes sha256(x),
    //   y → SHA256(y), FROMALTSTACK → sha256(x) back. Then: t_a sha256(y) sha256(x)
    //   Wait, let's trace pymatt:
    //   Stack (bottom to top): alice_sig t_a y x
    //   DUP → alice_sig t_a y x x
    //   SHA256 → alice_sig t_a y x sha256(x)
    //   check_input → alice_sig t_a y x  (check_input consumes sha256(x))
    //   Now S2 encoder on [t_a, y, x]:
    //     TOALTSTACK → alice_sig t_a y | altstack: [x]
    //     SHA256 → alice_sig t_a sha256(y) | altstack: [x]
    //     FROMALTSTACK → alice_sig t_a sha256(y) x
    //     SHA256 → alice_sig t_a sha256(y) sha256(x)
    //     merkle_root(3) → alice_sig merkle_root([t_a, sha256(y), sha256(x)])
    //   Wait, the stack order matters: top element = sha256(x), next = sha256(y), next = t_a
    //   merkle_root(3) reduces 3 top elements.
    //   So the leaves for merkle_root are: bottom=t_a, mid=sha256(y), top=sha256(x)
    //   Hmm, but merkle_root processes from the bottom. Let me think about this:
    //   In pymatt, merkle_root(3) reduces the 3 top stack elements.
    //   The reduce_merkle_layer(3) for 3 leaves:
    //     n=3, odd: TOALTSTACK, reduce(2), FROMALTSTACK
    //     reduce(2) = CAT SHA256
    //   So: stack top is sha256(x), then sha256(y), then t_a
    //   TOALTSTACK → saves sha256(x) to altstack
    //   stack: ... t_a sha256(y)
    //   CAT SHA256 → sha256(t_a || sha256(y))
    //   FROMALTSTACK → sha256(x)
    //   Next layer: n=2: CAT SHA256
    //   → sha256(sha256(t_a||sha256(y)) || sha256(x))
    //   Which matches: combine(combine(t_a, sha256(y)), sha256(x))
    //   = merkle_root([t_a, sha256(y), sha256(x)]) ✓

    let reveal_script = script! {
        // DUP SHA256 check_input_contract (S1 encoder is just SHA256)
        DUP SHA256
        <check_input_contract()>
        // S2 encoder: TOALTSTACK SHA256 FROMALTSTACK SHA256 merkle_root(3)
        TOALTSTACK SHA256 FROMALTSTACK SHA256
        <merkle_root_script(3)>
        // check_output
        <check_output_contract(&s2)>
        <params.alice_pk>
        CHECKSIG
    };

    let s2_for_next = s2.clone();
    let alice_pk = params.alice_pk;
    let reveal = G256S1Clause::reveal(
        reveal_script,
        move |_, _| alice_pk,
        move |args, _| {
            let t_a = arg_as_bytes(args, "t_a")?.clone();
            let y = arg_as_int(args, "y")?;
            let x = arg_as_int(args, "x")?;
            let state = g256_s2_state(&t_a, y, x);
            Ok(vec![ClauseOutput {
                n: -1,
                next_contract: s2_for_next.clone(),
                next_state: state,
                amount_behaviour: CcvAmountBehaviour::Preserve,
            }])
        },
    );

    Contract::new("G256_S1", nums, TapTree::Leaf(reveal))
}

/// Compute S2 state: merkle_root([t_a, sha256(scriptint(y)), sha256(scriptint(x))])
pub fn g256_s2_state(t_a: &[u8], y: i32, x: i32) -> Vec<u8> {
    let h_y = sha256(&<i32 as ClauseArg>::to_bytes(&y));
    let h_x = sha256(&<i32 as ClauseArg>::to_bytes(&x));
    let mut t_a_arr = [0u8; 32];
    t_a_arr.copy_from_slice(t_a);
    merkle::merkle_root(&[t_a_arr, h_y, h_x]).to_vec()
}

// ---------------------------------------------------------------------------
// G256_S2 — Challenge or withdraw
// ---------------------------------------------------------------------------

/// State: merkle_root([t_a, sha256(scriptint(y)), sha256(scriptint(x))]) — 3 leaves
///
/// Clauses:
/// - withdraw: Alice takes funds after timeout
/// - start_challenge: Bob challenges, transitioning to Bisect_1[0,n-1]
pub fn make_g256_s2(params: &G256Params) -> Contract {
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap();
    let alice_pk = params.alice_pk;
    let bob_pk = params.bob_pk;
    let forfait_timeout = params.forfait_timeout;

    // withdraw: <alice_sig> + older
    let older = older_script(forfait_timeout);
    let withdraw = standard_clause(
        "withdraw",
        script! { <older> <alice_pk> CHECKSIG },
        vec![("alice_sig", ArgType::Signer(Arc::new(move |_, _| alice_pk)))],
        |_, _| Ok(vec![]),
    );

    // Build the initial bisect contract
    let bisect_0 = make_fraud_proof(alice_pk, bob_pk, 0, 7, &compute_2x(), forfait_timeout);

    // start_challenge: <bob_sig> <t_a> <y> <x> <z> <t_b>
    //
    // After witness decoding, stack (bottom to top): bob_sig t_a y x z t_b
    //
    // Trace through the script:
    //   TOALTSTACK → save t_b;  stack: bob_sig t_a y x z
    //   DUP 3 PICK EQUAL NOT VERIFY → check y != z
    //   TOALTSTACK → save z;  stack: bob_sig t_a y x  altstack: [t_b, z]
    //   dup(3) → bob_sig t_a y x t_a y x
    //   S2 encoder (TOALTSTACK SHA256 FROMALTSTACK SHA256 merkle_root(3)) + check_input
    //     → verifies merkle_root([t_a, sha256(y), sha256(x)]) matches input state
    //   stack: bob_sig t_a y x
    //   SHA256 SWAP SHA256 ROT → bob_sig sha256(x) sha256(y) t_a
    //   FROMALTSTACK SHA256 SWAP → bob_sig sha256(x) sha256(y) sha256(z) t_a
    //   FROMALTSTACK → bob_sig sha256(x) sha256(y) sha256(z) t_a t_b
    //   Bisect_1 encoder: merkle_root(5) + check_output_contract

    let start_challenge_script = script! {
        // save t_b to altstack
        TOALTSTACK
        // check y != z
        DUP 3 PICK EQUAL NOT VERIFY
        // save z to altstack
        TOALTSTACK
        // dup top 3 for state verification
        <dup(3)>
        // S2 encoder + check_input
        TOALTSTACK SHA256 FROMALTSTACK SHA256
        <merkle_root_script(3)>
        <check_input_contract()>
        // stack: bob_sig t_a y x
        SHA256 SWAP SHA256 ROT
        // FROMALTSTACK SHA256 → sha256(z)
        FROMALTSTACK SHA256
        SWAP
        // FROMALTSTACK → t_b
        FROMALTSTACK
        // stack: bob_sig sha256(x) sha256(y) sha256(z) t_a t_b
        <merkle_root_script(5)> // bisect_0_encoder
        <check_output_contract(&bisect_0)>
        <bob_pk>
        CHECKSIG
    };

    let bisect_0_for_next = bisect_0.clone();
    let start_challenge = standard_clause(
        "start_challenge",
        start_challenge_script,
        vec![
            ("bob_sig", ArgType::Signer(Arc::new(move |_, _| bob_pk))),
            ("t_a", ArgType::Bytes(32)),
            ("y", ArgType::Int),
            ("x", ArgType::Int),
            ("z", ArgType::Int),
            ("t_b", ArgType::Bytes(32)),
        ],
        move |args, _| {
            let x = arg_as_int(args, "x")?;
            let y = arg_as_int(args, "y")?;
            let z = arg_as_int(args, "z")?;
            let t_a = arg_as_bytes(args, "t_a")?;
            let t_b = arg_as_bytes(args, "t_b")?;

            let h_x = sha256(&<i32 as ClauseArg>::to_bytes(&x));
            let h_y = sha256(&<i32 as ClauseArg>::to_bytes(&y));
            let h_z = sha256(&<i32 as ClauseArg>::to_bytes(&z));

            let state = bisect1_state(h_x, h_y, h_z, to32(t_a), to32(t_b));
            Ok(vec![ClauseOutput {
                n: -1,
                next_contract: bisect_0_for_next.clone(),
                next_state: state,
                amount_behaviour: CcvAmountBehaviour::Preserve,
            }])
        },
    );

    Contract::new(
        "G256_S2",
        nums,
        TapTree::Branch {
            left: Box::new(TapTree::Leaf(withdraw)),
            right: Box::new(TapTree::Leaf(start_challenge)),
        },
    )
}

// ---------------------------------------------------------------------------
// Typed wrappers
// ---------------------------------------------------------------------------

contract! {
    G256S0Instance, G256S0Clause {
        fn choose(bob_sig: sig, x: i32) -> (G256S1Instance);
    }
}

contract! {
    G256S1Instance, G256S1Clause {
        fn reveal(alice_sig: sig, t_a: Bytes, y: i32, x: i32) -> (G256S2Instance);
    }
}

contract! {
    G256S2Instance, G256S2Clause {
        fn start_challenge(bob_sig: sig, t_a: Bytes, y: i32, x: i32, z: i32, t_b: Bytes) -> (Bisect1Instance);
        fn withdraw(alice_sig: sig) -> ();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to32(data: &[u8]) -> [u8; 32] {
    data.try_into().expect("expected 32 bytes")
}
