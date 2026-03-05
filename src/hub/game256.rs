use std::sync::Arc;

use bitcoin::opcodes::all::*;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;

use crate::ccv::NUMS_KEY;
use crate::contracts::{
    arg_as_bytes, arg_as_int, ArgType, Bytes, CcvAmountBehaviour, ClauseArg, ClauseOutput,
    Contract, standard_clause,
};
use crate::hub::fraud::{Bisect1Instance, bisect1_state, compute_2x, make_bisect_1, make_leaf};
use crate::merkle;
use crate::script_helpers::{
    cat_scripts, check_input_contract, check_output_contract, dup_script, encoder_script,
    older_script,
};
use crate::taproot::TapTree;
use crate::{contract, sha256};

use bitcoin_script::{define_pushable, script};
define_pushable!();

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

    let s2_encoder = cat_scripts(&[
        ScriptBuf::from(vec![
            OP_TOALTSTACK.to_u8(),
            OP_SHA256.to_u8(),
            OP_FROMALTSTACK.to_u8(),
            OP_SHA256.to_u8(),
        ]),
        encoder_script(3),
    ]);

    let reveal_script = cat_scripts(&[
        // DUP SHA256 check_input_contract
        ScriptBuf::from(vec![OP_DUP.to_u8()]),
        // S1 encoder is just SHA256
        ScriptBuf::from(vec![OP_SHA256.to_u8()]),
        check_input_contract(),
        // S2 encoder + check_output
        s2_encoder,
        check_output_contract(&s2),
        push_pk(params.alice_pk),
        ScriptBuf::from(vec![OP_CHECKSIG.to_u8()]),
    ]);

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
    let withdraw = standard_clause(
        "withdraw",
        cat_scripts(&[
            older_script(forfait_timeout),
            push_pk(alice_pk),
            ScriptBuf::from(vec![OP_CHECKSIG.to_u8()]),
        ]),
        vec![("alice_sig", ArgType::Signer(Arc::new(move |_, _| alice_pk)))],
        |_, _| Ok(vec![]),
    );

    // Build the initial bisect contract
    let leaf_factory = move |_i: usize| make_leaf(alice_pk, bob_pk, &compute_2x());
    let bisect_0 = make_bisect_1(alice_pk, bob_pk, 0, 7, &leaf_factory, forfait_timeout);

    // S2 state encoder: TOALTSTACK SHA256 FROMALTSTACK SHA256 merkle_root(3)
    let s2_encoder = cat_scripts(&[
        ScriptBuf::from(vec![
            OP_TOALTSTACK.to_u8(),
            OP_SHA256.to_u8(),
            OP_FROMALTSTACK.to_u8(),
            OP_SHA256.to_u8(),
        ]),
        encoder_script(3),
    ]);

    // start_challenge: <bob_sig> <t_a> <y> <x> <z> <t_b>
    //
    // After witness decoding, stack (bottom to top): bob_sig t_a y x z t_b
    //
    // Matching pymatt:
    //   TOALTSTACK → save t_b
    //   DUP 3 PICK EQUAL NOT VERIFY → check y != z (z is now at top, y at position 3)
    //   Wait: after TOALTSTACK of t_b, stack is: bob_sig t_a y x z
    //   Positions: 0=z, 1=x, 2=y, 3=t_a, 4=bob_sig
    //   DUP → bob_sig t_a y x z z
    //   3 PICK → copies position 3 = y
    //   stack: bob_sig t_a y x z z y
    //   EQUAL NOT VERIFY → z != y
    //   stack: bob_sig t_a y x z
    //   TOALTSTACK → save z
    //   stack: bob_sig t_a y x  altstack: [t_b, z]
    //
    //   dup(3) → bob_sig t_a y x t_a y x
    //   S2 encoder on top 3 → merkle_root([t_a, sha256(y), sha256(x)])
    //   check_input → consumes hash
    //   stack: bob_sig t_a y x
    //
    //   SHA256 → bob_sig t_a y sha256(x)
    //   SWAP → bob_sig t_a sha256(x) y
    //   SHA256 → bob_sig t_a sha256(x) sha256(y)
    //   ROT → bob_sig sha256(x) sha256(y) t_a
    //
    //   FROMALTSTACK SHA256 → bob_sig sha256(x) sha256(y) t_a sha256(z)  altstack: [t_b]
    //   SWAP → bob_sig sha256(x) sha256(y) sha256(z) t_a
    //
    //   FROMALTSTACK → bob_sig sha256(x) sha256(y) sha256(z) t_a t_b
    //
    //   Bisect_1 encoder: merkle_root(5) on [sha256(x), sha256(y), sha256(z), t_a, t_b]
    //   Wait, the stack order matters. From bottom to top:
    //   sha256(x) sha256(y) sha256(z) t_a t_b
    //   That becomes: h_start=sha256(x), h_end_a=sha256(y), h_end_b=sha256(z), trace_a=t_a, trace_b=t_b
    //   encoder_script(5) reduces these 5 to merkle_root
    //   check_output_contract verifies

    let bisect_0_encoder = encoder_script(5);
    let bisect_0_ccv = check_output_contract(&bisect_0);

    let start_challenge_script = cat_scripts(&[
        // save t_b to altstack
        ScriptBuf::from(vec![OP_TOALTSTACK.to_u8()]),
        // check y != z
        ScriptBuf::from(vec![
            OP_DUP.to_u8(),
        ]),
        push_number(3),
        ScriptBuf::from(vec![
            OP_PICK.to_u8(),
            OP_EQUAL.to_u8(),
            OP_NOT.to_u8(),
            OP_VERIFY.to_u8(),
        ]),
        // save z to altstack
        ScriptBuf::from(vec![OP_TOALTSTACK.to_u8()]),
        // dup top 3 for state verification
        dup_script(3),
        // S2 encoder + check_input
        s2_encoder,
        check_input_contract(),
        // stack: bob_sig t_a y x
        // SHA256 SWAP SHA256 ROT
        ScriptBuf::from(vec![
            OP_SHA256.to_u8(),
            OP_SWAP.to_u8(),
            OP_SHA256.to_u8(),
            OP_ROT.to_u8(),
        ]),
        // FROMALTSTACK SHA256 → sha256(z)
        ScriptBuf::from(vec![
            OP_FROMALTSTACK.to_u8(),
            OP_SHA256.to_u8(),
        ]),
        // SWAP
        ScriptBuf::from(vec![OP_SWAP.to_u8()]),
        // FROMALTSTACK → t_b
        ScriptBuf::from(vec![OP_FROMALTSTACK.to_u8()]),
        // stack: bob_sig sha256(x) sha256(y) sha256(z) t_a t_b
        bisect_0_encoder,
        bisect_0_ccv,
        push_pk(bob_pk),
        ScriptBuf::from(vec![OP_CHECKSIG.to_u8()]),
    ]);

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

fn push_pk(pk: XOnlyPublicKey) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(33);
    bytes.push(OP_PUSHBYTES_32.to_u8());
    bytes.extend_from_slice(&pk.serialize());
    ScriptBuf::from(bytes)
}

fn push_number(n: i64) -> ScriptBuf {
    let mut bytes = Vec::new();
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
    ScriptBuf::from(bytes)
}

fn to32(data: &[u8]) -> [u8; 32] {
    data.try_into().expect("expected 32 bytes")
}
