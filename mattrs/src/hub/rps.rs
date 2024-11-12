use bitcoin::{
    consensus::Encodable,
    hashes::{sha256, Hash},
    key::Secp256k1,
    opcodes,
    script::Builder,
    Address, Amount, KnownHrp, Sequence, XOnlyPublicKey,
};
use bitcoin_script::{define_pushable, script};
use std::{any::Any, io::Write};

define_pushable!();

use crate::{
    ccv_list,
    contracts::{
        Clause, Contract, ContractParams, ContractState, Signature, CCV_FLAG_CHECK_INPUT, NUMS_KEY,
    },
    ctv::make_ctv_template_hash,
    define_clause, define_contract, define_params,
};

/// Helper functions for the RPS game
pub mod rps {
    use super::*;

    pub const DEFAULT_STAKE: u64 = 1000; // Default stake amount in satoshis

    pub fn move_str(mv: u8) -> &'static str {
        match mv {
            0 => "rock",
            1 => "paper",
            2 => "scissors",
            _ => panic!("Invalid move"),
        }
    }

    pub fn adjudicate(move_alice: u8, move_bob: u8) -> &'static str {
        assert!(move_alice <= 2 && move_bob <= 2);
        if move_bob == move_alice {
            "tie"
        } else if (move_bob + 3 - move_alice) % 3 == 2 {
            "alice_wins"
        } else {
            "bob_wins"
        }
    }

    pub fn calculate_hash(mv: u8, r: &[u8]) -> [u8; 32] {
        assert!(mv <= 2 && r.len() == 32);
        let mut hasher = sha256::HashEngine::default();
        // TODO: does rust-bitcoin have a function for the minimal stack encoding of a number?
        let mv_repr = match mv {
            0 => vec![],
            1 => vec![1u8],
            2 => vec![2u8],
            _ => panic!("Invalid move"),
        };
        hasher.write_all(&mv_repr).unwrap();
        hasher.write_all(r).unwrap();
        sha256::Hash::from_engine(hasher).to_byte_array()
    }
}

// Parameters for the RPSGameS0 contract
define_params!(RPSGameS0Params {
    alice_pk: XOnlyPublicKey,
    bob_pk: XOnlyPublicKey,
    c_a: [u8; 32],
    stake: u64,
});

// Clause for Bob's move in RPSGameS0
define_clause!(
    RPSGameS0BobMove,
    RPSGameS0BobMoveArgs,
    "bob_move",
    RPSGameS0Params,
    (),
    args {
        m_b: i32,
        bob_sig: Signature => |p: &RPSGameS0Params| p.bob_pk,
    },
    // witness: <m_b> <bob_sig>
    script(params) {
        let s1 = RPSGameS1::new(RPSGameS1Params {
            alice_pk: params.alice_pk,
            bob_pk: params.bob_pk,
            c_a: params.c_a,
            stake: params.stake,
        });

        script! {
            <params.bob_pk>
            CHECKSIG
            SWAP

            // stack on successful signature check: <1> <m_b>

            DUP 0 3 WITHIN VERIFY // check that m_b is 0, 1 or 2

            <RPSGameS1State::encoder_script()>
            0 0 <s1.get_taptree().get_root_hash()> 0 CHECKCONTRACTVERIFY
        }
    },
    next_outputs(params, args, _state) {
        let s1 = RPSGameS1::new(RPSGameS1Params {
            alice_pk: params.alice_pk,
            bob_pk: params.bob_pk,
            c_a: params.c_a,
            stake: params.stake,
        });

        ccv_list![
            preserve(0) => s1; RPSGameS1State::new(args.m_b)
        ]
    }
);

// RPSGameS0 contract definition
define_contract!(
    RPSGameS0,
    params: RPSGameS0Params,
    get_pk(_params) {
        XOnlyPublicKey::from_slice(&NUMS_KEY).expect("Valid default key")
    },
    taptree: RPSGameS0BobMove
);

// Parameters for the RPSGameS1 contract
define_params!(RPSGameS1Params {
    alice_pk: XOnlyPublicKey,
    bob_pk: XOnlyPublicKey,
    c_a: [u8; 32],
    stake: u64,
});

/// State for the RPSGameS1 contract
#[derive(Debug)]
pub struct RPSGameS1State {
    m_b_hash: [u8; 32],
}

impl RPSGameS1State {
    pub fn new(m_b: i32) -> Self {
        let mut hasher = sha256::HashEngine::default();
        m_b.consensus_encode(&mut hasher).unwrap();
        let m_b_hash = sha256::Hash::from_engine(hasher).to_byte_array();
        Self { m_b_hash }
    }

    pub fn encoder_script() -> bitcoin::ScriptBuf {
        script! {
            SHA256
        }
    }
}

impl ContractState for RPSGameS1State {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn encode(&self) -> [u8; 32] {
        self.m_b_hash
    }
}

/// Function to generate the script for the clauses in RPSGameS1
fn make_script(diff: i32, ctv_hash: &[u8; 32], c_a: &[u8; 32]) -> bitcoin::ScriptBuf {
    // diff is (m_b - m_a) % 3
    // Witness: [<m_b> <m_a> <r_a>]
    script! {
        OVER DUP TOALTSTACK // save m_a

        // stack: <m_b> <m_a> <r_a>        altstack: <m_a>

        0 3 WITHIN VERIFY // check that m_a is 0, 1 or 2

        // check that SHA256(m_a || r_a) equals c_a
        CAT SHA256
        <c_a>
        EQUALVERIFY

        DUP

        // stack: <m_b> <m_b>              altstack: <m_a>

        <RPSGameS1State::encoder_script()>
        -1 0 -1 <CCV_FLAG_CHECK_INPUT> CHECKCONTRACTVERIFY

        // stack: <m_b>                    altstack: <m_a>

        FROMALTSTACK
        SUB

        // stack: <m_b - m_a>

        // if the result is negative, add 3
        DUP
        0 LESSTHAN
        IF
            3 ADD
        ENDIF

        <diff>  // draw / Bob wins / Alice wins, respectively
        EQUALVERIFY

        <ctv_hash>
        CHECKTEMPLATEVERIFY
    }
}

// Clause for a tie in RPSGameS1
define_clause!(
    RPSGameS1Tie,
    RPSGameS1TieArgs,
    "tie",
    RPSGameS1Params,
    RPSGameS1State,
    args {
        m_b: i32,
        m_a: i32,
        r_a: [u8; 32],
    },
    script(params) {
        let secp = Secp256k1::new();
        let alice_addr = Address::p2tr(&secp, params.alice_pk, None, KnownHrp::Regtest);
        let bob_addr = Address::p2tr(&secp, params.bob_pk, None, KnownHrp::Regtest);

        let tmpl_tie = make_ctv_template_hash(&[
            (alice_addr, Amount::from_sat(params.stake)),
            (bob_addr, Amount::from_sat(params.stake)),
        ], Sequence(0)).unwrap();

        make_script(0, &tmpl_tie, &params.c_a)
    },
    next_outputs(_params, _args, _state) {
        // TODO: we might want to track the P2TR outputs
        ccv_list![]
    }
);

// Clause for Alice winning in RPSGameS1
define_clause!(
    RPSGameS1AliceWins,
    RPSGameS1AliceWinsArgs,
    "alice_wins",
    RPSGameS1Params,
    RPSGameS1State,
    args {
        m_b: i32,
        m_a: i32,
        r_a: [u8; 32],
    },
    script(params) {
        let secp = Secp256k1::new();
        let alice_addr = Address::p2tr(&secp, params.alice_pk, None, KnownHrp::Regtest);

        let tmpl_alice_wins = make_ctv_template_hash(&[
            (alice_addr, Amount::from_sat(params.stake * 2)),
        ], Sequence(0)).unwrap();

        make_script(2, &tmpl_alice_wins, &params.c_a)
    },
    next_outputs(_params, _args, _state) {
        // TODO: we might want to track the P2TR output
        ccv_list![]
    }
);

// Clause for Bob winning in RPSGameS1
define_clause!(
    RPSGameS1BobWins,
    RPSGameS1BobWinsArgs,
    "bob_wins",
    RPSGameS1Params,
    RPSGameS1State,
    args {
        m_b: i32,
        m_a: i32,
        r_a: [u8; 32],
    },
    script(params) {
        let secp = Secp256k1::new();
        let bob_addr = Address::p2tr(&secp, params.bob_pk, None, KnownHrp::Regtest);

        let tmpl_bob_wins = make_ctv_template_hash(&[
            (bob_addr, Amount::from_sat(params.stake * 2)),
        ], Sequence(0)).unwrap();

        make_script(1, &tmpl_bob_wins, &params.c_a)
    },
    next_outputs(_params, _args, _state) {
        // TODO: we might want to track the P2TR output
        ccv_list![]
    }
);

// RPSGameS1 contract definition
define_contract!(
    RPSGameS1,
    params: RPSGameS1Params,
    state: RPSGameS1State,
    get_pk(_params) {
        XOnlyPublicKey::from_slice(&NUMS_KEY).expect("Valid default key")
    },
    taptree: (RPSGameS1AliceWins, (RPSGameS1BobWins, RPSGameS1Tie))
);

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use std::str::FromStr;

    use bitcoin::{bip32::Xpriv, hashes::Hash, key::Secp256k1, Address, KnownHrp, TapNodeHash};

    use super::*;

    #[test]
    fn test_rps_address() {
        let secp = Secp256k1::new();

        let alice_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
        ).unwrap();
        let alice_pubkey = alice_privkey.to_priv().public_key(&secp);

        let bob_privkey = Xpriv::from_str(
            "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
        ).unwrap();
        let bob_pubkey = bob_privkey.to_priv().public_key(&secp);

        // randomness hardcoded for the test
        let r_a = hex!("c5d71484f8cf9bf4b76f47904730804b9e3225a9f133b5dea168f4e2851f072f");
        let c_a = rps::calculate_hash(0, &r_a);

        let s0 = RPSGameS0::new(RPSGameS0Params {
            alice_pk: alice_pubkey.into(),
            bob_pk: bob_pubkey.into(),
            c_a,
            stake: rps::DEFAULT_STAKE,
        });

        let internal_key = s0.get_naked_internal_key();
        let taptree_hash = TapNodeHash::from_byte_array(s0.get_taptree().get_root_hash());

        let taproot_address =
            Address::p2tr(&secp, internal_key, Some(taptree_hash), KnownHrp::Regtest);

        // address computed with pymatt
        assert_eq!(
            taproot_address.to_string(),
            "bcrt1prhmzx9c8g435r54mg88eqan2ewtsea53vg4hhmlzavaa6jeha4vq6lftyp"
        );
    }
}
