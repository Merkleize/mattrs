use bitcoin::{
    consensus::Encodable,
    hashes::{sha256, Hash},
    key::Secp256k1,
    opcodes,
    script::Builder,
    Address, Amount, KnownHrp, ScriptBuf, Sequence, XOnlyPublicKey,
};
use std::{any::Any, io::Write};

use crate::{
    ccv_list,
    contracts::{
        Clause, Contract, ContractParams, ContractState, Signature, CCV_FLAG_CHECK_INPUT, NUMS_KEY,
        OP_CHECKCONTRACTVERIFY, OP_CHECKTEMPLATEVERIFY,
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
    script(params) {
        let s1 = RPSGameS1::new(RPSGameS1Params {
            alice_pk: params.alice_pk,
            bob_pk: params.bob_pk,
            c_a: params.c_a,
            stake: params.stake,
        });

        let builder = Builder::new()
            .push_x_only_key(&params.bob_pk)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_SWAP)
            .push_opcode(opcodes::all::OP_DUP)
            .push_int(0)
            .push_int(3)
            .push_opcode(opcodes::all::OP_WITHIN)
            .push_opcode(opcodes::all::OP_VERIFY)
            .push_opcode(opcodes::all::OP_SHA256) // encoder script
            // .append_script(&check_output_contract(&s1, 0));
            .push_int(0)
            .push_int(0)
            .push_slice(s1.get_taptree().get_root_hash())
            .push_int(0)
            .push_opcode(OP_CHECKCONTRACTVERIFY.into());

        builder.into_script()
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
        Builder::new()
            .push_opcode(opcodes::all::OP_SHA256)
            .into_script()
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
    let s1 = Builder::new()
        .push_opcode(opcodes::all::OP_OVER)
        .push_opcode(opcodes::all::OP_DUP)
        .push_opcode(opcodes::all::OP_TOALTSTACK)
        .push_int(0)
        .push_int(3)
        .push_opcode(opcodes::all::OP_WITHIN)
        .push_opcode(opcodes::all::OP_VERIFY)
        .push_opcode(opcodes::all::OP_CAT)
        .push_opcode(opcodes::all::OP_SHA256)
        .push_slice(c_a)
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_DUP)
        .into_script();
    let s2 = RPSGameS1State::encoder_script();
    let s3 = Builder::new()
        .push_int(-1)
        .push_int(0)
        .push_int(-1)
        .push_int(CCV_FLAG_CHECK_INPUT.into())
        .push_opcode(OP_CHECKCONTRACTVERIFY.into())
        .push_opcode(opcodes::all::OP_FROMALTSTACK)
        .push_opcode(opcodes::all::OP_SUB)
        .push_opcode(opcodes::all::OP_DUP)
        .push_int(0)
        .push_opcode(opcodes::all::OP_LESSTHAN)
        .push_opcode(opcodes::all::OP_IF)
        .push_int(3)
        .push_opcode(opcodes::all::OP_ADD)
        .push_opcode(opcodes::all::OP_ENDIF)
        .push_int(diff.into())
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_slice(ctv_hash)
        .push_opcode(OP_CHECKTEMPLATEVERIFY.into())
        .into_script();

    // concatenate s1, s2 and s3
    let mut script = s1.to_bytes();
    script.extend_from_slice(&s2.to_bytes());
    script.extend_from_slice(&s3.to_bytes());

    ScriptBuf::from(script)
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
