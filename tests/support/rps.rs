//! Rock-Paper-Scissors example (ported from pymatt's `examples/rps`).
//!
//! Two contracts:
//! - `RpsGameS0`: Alice has already committed to her move (`c_a = sha256(m_a || r_a)`)
//!   and funded the game. Bob reveals his move `m_b` (signed), moving to `RpsGameS1`
//!   whose committed state is `sha256(m_b)`.
//! - `RpsGameS1` (augmented): Alice reveals `m_a`/`r_a`; one of three clauses
//!   (`alice_wins` / `bob_wins` / `tie`) checks the outcome and pays out via a CTV
//!   template. This exercises clause-owned CTV templates and CCV `check_in/out`.
#![allow(dead_code)]

use bitcoin::{
    hashes::{sha256, Hash},
    key::Secp256k1,
    Amount, ScriptBuf, Sequence, TxOut, XOnlyPublicKey,
};
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{
    ClauseArgs, ClauseOutput, ContractParams, ContractState, CtvTemplate, WitnessEncodable,
    WitnessError,
};
use mattrs::{contract, script_utils::bn2vch, Signature};
use mattrs_derive::{ContractParams, ContractState};

use mattrs::script_helpers::{check_input_contract, check_output_contract};

define_pushable!();

/// The default stake (in sats) each player bets.
pub const DEFAULT_STAKE: i64 = 1000;

#[derive(Debug, Clone, ContractParams)]
pub struct RpsParams {
    pub alice_pk: XOnlyPublicKey,
    pub bob_pk: XOnlyPublicKey,
    /// Alice's move commitment, `sha256(bn(m_a) || r_a)`.
    pub c_a: [u8; 32],
    pub stake: i64,
}

/// The committed state of `RpsGameS1`: `sha256(bn(m_b))`.
#[derive(Debug, Clone, ContractState)]
pub struct RpsGameS1State {
    pub commitment: [u8; 32],
}

/// `sha256(bn(move))`, the way both players commit to a move on-chain.
pub fn move_commitment(mv: i64) -> [u8; 32] {
    sha256::Hash::hash(&bn2vch(mv)).to_byte_array()
}

fn p2tr_spk(pubkey: XOnlyPublicKey) -> ScriptBuf {
    let secp = Secp256k1::new();
    ScriptBuf::new_p2tr(&secp, pubkey, None)
}

// ============================================================================
// RpsGameS0 — Bob reveals his move
// ============================================================================

contract! {
    contract RpsGameS0 {
        params RpsParams;

        // witness: <m_b> <bob_sig>
        clause bob_move {
            args {
                m_b: i64,
                #[signer(p.bob_pk)]
                sig: Signature,
            }
            script RpsGameS0::bob_move_script;
            next(p, a) {
                let s1 = RpsGameS1::new(p.clone());
                let state = RpsGameS1State { commitment: move_commitment(a.m_b) };
                Ok(vec![ClauseOutput::at(0)
                    .to(s1.as_erased())
                    .with_state(&state)
                    .preserve_amount()
                    .build()])
            }
        }

        tree [bob_move];
    }
}

impl RpsGameS0 {
    fn bob_move_script(p: &RpsParams) -> ScriptBuf {
        let s1_taptree_root = RpsGameS1::new(p.clone()).contract.taptree().root_hash();
        script! {
            // check Bob's signature, leaving <m_b> on top
            { p.bob_pk }
            OP_CHECKSIG
            OP_SWAP

            // check that m_b is 0, 1 or 2
            OP_DUP
            0 3 OP_WITHIN OP_VERIFY

            // commit sha256(m_b) into the next contract's state (output 0)
            OP_SHA256
            { check_output_contract(s1_taptree_root, 0, None) }
        }
    }
}

// ============================================================================
// RpsGameS1 — Alice reveals, outcome is adjudicated
// ============================================================================

contract! {
    contract RpsGameS1 {
        params RpsParams;
        state RpsGameS1State;

        // witness: <m_b> <m_a> <r_a>
        clause alice_wins {
            args { m_b: i64, m_a: i64, r_a: [u8; 32], }
            script RpsGameS1::alice_wins_script;
            next(p, _a) { Ok(RpsGameS1::tmpl_alice_wins(p)) }
        }
        clause bob_wins {
            args { m_b: i64, m_a: i64, r_a: [u8; 32], }
            script RpsGameS1::bob_wins_script;
            next(p, _a) { Ok(RpsGameS1::tmpl_bob_wins(p)) }
        }
        clause tie {
            args { m_b: i64, m_a: i64, r_a: [u8; 32], }
            script RpsGameS1::tie_script;
            next(p, _a) { Ok(RpsGameS1::tmpl_tie(p)) }
        }

        tree [alice_wins, [bob_wins, tie]];
    }
}

impl RpsGameS1 {
    fn tmpl_alice_wins(p: &RpsParams) -> CtvTemplate {
        CtvTemplate::new(
            vec![TxOut {
                script_pubkey: p2tr_spk(p.alice_pk),
                value: Amount::from_sat((2 * p.stake) as u64),
            }],
            Sequence::ZERO,
        )
    }

    fn tmpl_bob_wins(p: &RpsParams) -> CtvTemplate {
        CtvTemplate::new(
            vec![TxOut {
                script_pubkey: p2tr_spk(p.bob_pk),
                value: Amount::from_sat((2 * p.stake) as u64),
            }],
            Sequence::ZERO,
        )
    }

    fn tmpl_tie(p: &RpsParams) -> CtvTemplate {
        CtvTemplate::new(
            vec![
                TxOut {
                    script_pubkey: p2tr_spk(p.alice_pk),
                    value: Amount::from_sat(p.stake as u64),
                },
                TxOut {
                    script_pubkey: p2tr_spk(p.bob_pk),
                    value: Amount::from_sat(p.stake as u64),
                },
            ],
            Sequence::ZERO,
        )
    }

    /// The adjudication script for `diff = (m_b - m_a) mod 3`:
    /// 0 = tie, 1 = Bob wins, 2 = Alice wins.
    fn make_script(p: &RpsParams, diff: i64, ctv_hash: [u8; 32]) -> ScriptBuf {
        // witness: <m_b> <m_a> <r_a>
        script! {
            OP_OVER OP_DUP OP_TOALTSTACK  // save m_a
            0 3 OP_WITHIN OP_VERIFY       // check that m_a is 0, 1 or 2

            // check that sha256(m_a || r_a) == c_a
            OP_CAT OP_SHA256
            { p.c_a }
            OP_EQUALVERIFY

            // commit sha256(m_b) as the current input's state
            OP_DUP
            OP_SHA256
            { check_input_contract(-1, None) }

            // compute (m_b - m_a) mod 3, add 3 if negative
            OP_FROMALTSTACK
            OP_SUB
            OP_DUP
            0 OP_LESSTHAN
            OP_IF
            3 OP_ADD
            OP_ENDIF

            // enforce the outcome and its payout template
            { diff }
            OP_EQUALVERIFY
            { ctv_hash }
            OP_CHECKTEMPLATEVERIFY
        }
    }

    fn tie_script(p: &RpsParams) -> ScriptBuf {
        Self::make_script(p, 0, Self::tmpl_tie(p).ctv_hash())
    }
    fn bob_wins_script(p: &RpsParams) -> ScriptBuf {
        Self::make_script(p, 1, Self::tmpl_bob_wins(p).ctv_hash())
    }
    fn alice_wins_script(p: &RpsParams) -> ScriptBuf {
        Self::make_script(p, 2, Self::tmpl_alice_wins(p).ctv_hash())
    }
}
