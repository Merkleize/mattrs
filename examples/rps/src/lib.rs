use bitcoin::{Amount, Sequence, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};

use mattrs::ccv::{CCV_FLAG_CHECK_INPUT, NUMS_KEY};
use mattrs::contracts::{
    arg_as_int, Bytes, CcvAmountBehaviour, ClauseArg, ClauseOutput, Contract,
};
use mattrs::ctv::make_ctv_template_hash;
use mattrs::taproot::TapTree;
use mattrs::{ccv_outputs, contract, sha256};

define_pushable!();

// --- RPS helpers ---

/// Compute Alice's move commitment: SHA256(scriptint(m) || r).
pub fn calculate_hash(m: i32, r: &[u8; 32]) -> [u8; 32] {
    let m_bytes = m.to_bytes(); // ClauseArg::to_bytes — scriptint encoding
    let mut data = Vec::with_capacity(m_bytes.len() + 32);
    data.extend_from_slice(&m_bytes);
    data.extend_from_slice(r);
    sha256(&data)
}

/// Adjudicate an RPS game given both moves.
pub fn adjudicate(m_alice: i32, m_bob: i32) -> &'static str {
    let diff = ((m_bob - m_alice) % 3 + 3) % 3;
    match diff {
        0 => "tie",
        1 => "bob_wins",
        2 => "alice_wins",
        _ => unreachable!(),
    }
}

// --- RPS params ---

#[derive(Debug, Clone)]
pub struct RpsParams {
    pub alice_pk: XOnlyPublicKey,
    pub bob_pk: XOnlyPublicKey,
    pub c_a: [u8; 32],
    pub stake: u64,
}

// --- S0: Bob plays his move ---

pub fn make_rps_s0(params: &RpsParams) -> Contract {
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap();

    let s1 = make_rps_s1(params);
    let s1_taptree_root = s1.get_taptree_merkle_root();

    // bob_move clause
    // Witness order (from contract! macro): [m_b, bob_sig]
    // Stack (bottom→top): m_b, bob_sig
    let bob_move = {
        let bob_move_script = script! {
            <params.bob_pk> CHECKSIG        // consume bob_sig (top of stack)
            SWAP                            // swap result with m_b
            DUP 0 3 WITHIN VERIFY          // check m_b ∈ {0,1,2}
            SHA256                          // state = SHA256(scriptint(m_b))
            0 0 <s1_taptree_root> 0 CHECKCONTRACTVERIFY  // check output 0 is S1 with that state
        };

        let s1_for_next = s1.clone();
        let bob_pk = params.bob_pk;
        RpsS0Clause::bob_move(
            bob_move_script,
            move |_args, _state| bob_pk,
            move |args, _state| {
                let m_b = arg_as_int(args, "m_b")?;
                let m_b_scriptint = <i32 as ClauseArg>::to_bytes(&m_b);
                let state = sha256(&m_b_scriptint);
                Ok(vec![ClauseOutput {
                    n: 0,
                    next_contract: s1_for_next.clone(),
                    next_state: state.to_vec(),
                    amount_behaviour: CcvAmountBehaviour::Preserve,
                }])
            },
        )
    };

    Contract::new(
        "RpsS0",
        nums,
        TapTree::Leaf(bob_move),
    )
}

// --- S1: Alice reveals, game is adjudicated ---

pub fn make_rps_s1(params: &RpsParams) -> Contract {
    let nums = XOnlyPublicKey::from_slice(&NUMS_KEY).unwrap();

    // Compute CTV template hashes for each outcome
    let alice_addr = Contract::new_opaque_p2tr(params.alice_pk).get_address(&vec![]);
    let bob_addr = Contract::new_opaque_p2tr(params.bob_pk).get_address(&vec![]);

    let tmpl_alice_wins = vec![
        (alice_addr.clone(), Amount::from_sat(2 * params.stake)),
    ];
    let tmpl_bob_wins = vec![
        (bob_addr.clone(), Amount::from_sat(2 * params.stake)),
    ];
    let tmpl_tie = vec![
        (alice_addr, Amount::from_sat(params.stake)),
        (bob_addr, Amount::from_sat(params.stake)),
    ];

    let ctv_hash_alice_wins = make_ctv_template_hash(&tmpl_alice_wins, Sequence::ZERO)
        .expect("CTV hash computation failed");
    let ctv_hash_bob_wins = make_ctv_template_hash(&tmpl_bob_wins, Sequence::ZERO)
        .expect("CTV hash computation failed");
    let ctv_hash_tie = make_ctv_template_hash(&tmpl_tie, Sequence::ZERO)
        .expect("CTV hash computation failed");

    let c_a = params.c_a;

    // Helper to build a clause script parameterized by diff and ctv_hash
    let make_clause_script = |diff: i32, ctv_hash: [u8; 32]| {
        // Witness order: [m_b, m_a, r_a]
        // Stack (bottom→top): m_b, m_a, r_a
        script! {
            OVER DUP TOALTSTACK         // save m_a to altstack
            0 3 WITHIN VERIFY           // check m_a ∈ {0,1,2}

            // stack: m_b, m_a, r_a     altstack: [m_a]
            CAT SHA256                   // SHA256(m_a || r_a)
            <c_a> EQUALVERIFY           // check equals Alice's commitment

            // stack: m_b               altstack: [m_a]
            DUP SHA256                   // hash m_b for state check
            -1 0 -1 <CCV_FLAG_CHECK_INPUT> CHECKCONTRACTVERIFY  // check input state

            // stack: m_b               altstack: [m_a]
            FROMALTSTACK SUB            // m_b - m_a
            DUP 0 LESSTHAN IF 3 ADD ENDIF  // mod 3 (if negative, add 3)
            <diff> EQUALVERIFY          // check correct outcome
            <ctv_hash> CHECKTEMPLATEVERIFY
        }
    };

    let alice_wins = RpsS1Clause::alice_wins(
        make_clause_script(2, ctv_hash_alice_wins),
        ccv_outputs!(),
    );
    let bob_wins = RpsS1Clause::bob_wins(
        make_clause_script(1, ctv_hash_bob_wins),
        ccv_outputs!(),
    );
    let tie = RpsS1Clause::tie(
        make_clause_script(0, ctv_hash_tie),
        ccv_outputs!(),
    );

    // Taptree layout: [alice_wins, [bob_wins, tie]] (matching pymatt)
    Contract::new(
        "RpsS1",
        nums,
        TapTree::Branch {
            left: Box::new(TapTree::Leaf(alice_wins)),
            right: Box::new(TapTree::Branch {
                left: Box::new(TapTree::Leaf(bob_wins)),
                right: Box::new(TapTree::Leaf(tie)),
            }),
        },
    )
}

// --- Typed instance wrappers ---

contract! {
    RpsS0Instance, RpsS0Clause {
        fn bob_move(m_b: i32, bob_sig: sig) -> (RpsS1Instance);
    }
}

contract! {
    RpsS1Instance, RpsS1Clause {
        fn alice_wins(m_b: i32, m_a: i32, r_a: Bytes) -> ();
        fn bob_wins(m_b: i32, m_a: i32, r_a: Bytes) -> ();
        fn tie(m_b: i32, m_a: i32, r_a: Bytes) -> ();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use bitcoin::{bip32::Xpriv, key::Secp256k1};

    #[test]
    fn test_rps_adjudicate() {
        // rock=0, paper=1, scissors=2
        assert_eq!(adjudicate(0, 0), "tie");
        assert_eq!(adjudicate(0, 1), "bob_wins");   // paper beats rock
        assert_eq!(adjudicate(0, 2), "alice_wins");  // rock beats scissors
        assert_eq!(adjudicate(1, 0), "alice_wins");  // paper beats rock
        assert_eq!(adjudicate(1, 1), "tie");
        assert_eq!(adjudicate(1, 2), "bob_wins");   // scissors beats paper
        assert_eq!(adjudicate(2, 0), "bob_wins");   // rock beats scissors
        assert_eq!(adjudicate(2, 1), "alice_wins");  // scissors beats paper
        assert_eq!(adjudicate(2, 2), "tie");
    }

    #[test]
    fn test_rps_calculate_hash() {
        let r = [0xAA; 32];
        let h0 = calculate_hash(0, &r);
        let h1 = calculate_hash(1, &r);
        let h2 = calculate_hash(2, &r);
        // Different moves should give different hashes
        assert_ne!(h0, h1);
        assert_ne!(h1, h2);
        assert_ne!(h0, h2);
        // Same move + randomness should be deterministic
        assert_eq!(h0, calculate_hash(0, &r));
    }

    #[test]
    fn test_rps_contracts_build() {
        let secp = Secp256k1::new();

        let alice_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
        ).unwrap();
        let alice_pk: XOnlyPublicKey = alice_privkey.to_priv().public_key(&secp).into();

        let bob_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
        ).unwrap();
        let bob_pk: XOnlyPublicKey = bob_privkey.to_priv().public_key(&secp).into();

        let r_a = [0x42; 32];
        let c_a = calculate_hash(0, &r_a);

        let params = RpsParams {
            alice_pk,
            bob_pk,
            c_a,
            stake: 1000,
        };

        let s0 = make_rps_s0(&params);
        assert_eq!(s0.clause_names(), vec!["bob_move"]);

        let s1 = make_rps_s1(&params);
        assert_eq!(s1.clause_names(), vec!["alice_wins", "bob_wins", "tie"]);
    }
}
