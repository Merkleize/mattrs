//! Rock-Paper-Scissors example (ported from pymatt's `examples/rps`).
//!
//! Two contracts:
//! - `RpsGameS0`: Alice has already committed to her move (`c_a = sha256(m_a || r_a)`)
//!   and funded the game. Bob reveals his move `m_b` (signed), moving to `RpsGameS1`
//!   whose committed state is `sha256(m_b)`.
//! - `RpsGameS1` (augmented): Alice reveals `m_a`/`r_a`; one of three clauses
//!   (`alice_wins` / `bob_wins` / `tie`) checks the outcome and pays out via a CTV
//!   template. This exercises clause-owned CTV templates and CCV `check_in/out`.

use bitcoin::{Amount, ScriptBuf, Sequence, TxOut, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{ClauseOutput, CtvTemplate};
use mattrs::{
    contract, script_utils::commit_int, ContractParams, ContractState, Signature,
};

use mattrs::script_helpers::{check_input_contract, check_output_contract, key_path_p2tr};

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
    commit_int(mv)
}

/// Alice's hiding move commitment `c_a = sha256(bn(m_a) || r_a)`: the move
/// blinded with a 32-byte nonce, revealed (and script-verified) only when she
/// adjudicates the game.
pub fn alice_move_commitment(m_a: i64, r_a: &[u8; 32]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    let mut preimage = mattrs::script_utils::bn2vch(m_a);
    preimage.extend_from_slice(r_a);
    sha256::Hash::hash(&preimage).to_byte_array()
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
        let s1_taptree_root = RpsGameS1::new(p.clone()).taptree_root();
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
                script_pubkey: key_path_p2tr(p.alice_pk),
                value: Amount::from_sat((2 * p.stake) as u64),
            }],
            Sequence::ZERO,
        )
    }

    fn tmpl_bob_wins(p: &RpsParams) -> CtvTemplate {
        CtvTemplate::new(
            vec![TxOut {
                script_pubkey: key_path_p2tr(p.bob_pk),
                value: Amount::from_sat((2 * p.stake) as u64),
            }],
            Sequence::ZERO,
        )
    }

    fn tmpl_tie(p: &RpsParams) -> CtvTemplate {
        CtvTemplate::new(
            vec![
                TxOut {
                    script_pubkey: key_path_p2tr(p.alice_pk),
                    value: Amount::from_sat(p.stake as u64),
                },
                TxOut {
                    script_pubkey: key_path_p2tr(p.bob_pk),
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

// ============================================================================
// The parties, as protocol roles
// ============================================================================

/// The two players as declarative [`Role`]s: what each sends (or watches for)
/// at every game state. A [`Runner`](mattrs::protocol::Runner) drives them —
/// the same roles work against a regtest node (see `main.rs`) and the offline
/// `LocalChain` (see `tests/test_protocol.rs`).
pub mod roles {
    use bitcoin::bip32::Xpriv;

    use mattrs::contracts::ClauseArgs;
    use mattrs::protocol::{Action, ProtocolError, Role};
    use mattrs::signer::HotSigner;

    use super::{
        alice_move_commitment, RpsGameS0, RpsGameS0BobMoveArgs, RpsGameS0Handle, RpsGameS1,
        RpsGameS1Clause, RpsGameS1Handle, RpsGameS1TieArgs,
    };

    /// Who takes the pot.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RpsResult {
        AliceWins,
        BobWins,
        Tie,
    }

    /// The adjudicated game, with both revealed moves.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RpsOutcome {
        pub result: RpsResult,
        pub m_a: i64,
        pub m_b: i64,
    }

    /// The game rule, off-chain — the single mirror of the scripts'
    /// `diff = (m_b - m_a) mod 3`: 0 = tie, 1 = Bob wins, 2 = Alice wins.
    pub fn outcome_of(m_a: i64, m_b: i64) -> RpsResult {
        match (m_b - m_a).rem_euclid(3) {
            0 => RpsResult::Tie,
            1 => RpsResult::BobWins,
            _ => RpsResult::AliceWins,
        }
    }

    /// The adjudication clause satisfied by `result`.
    pub fn clause_of(result: RpsResult) -> RpsGameS1Clause {
        match result {
            RpsResult::Tie => RpsGameS1Clause::Tie,
            RpsResult::BobWins => RpsGameS1Clause::BobWins,
            RpsResult::AliceWins => RpsGameS1Clause::AliceWins,
        }
    }

    /// Alice's secrets: her move and the nonce blinding its commitment.
    pub struct AliceData {
        pub m_a: i64,
        pub r_a: [u8; 32],
        /// Demo pacing hook, called with Bob's revealed move and the outcome
        /// just before the adjudication is broadcast.
        pub before_adjudicating: Option<Box<dyn Fn(i64, RpsResult)>>,
    }

    /// Alice funds the game, so her role starts watching: Bob moves first.
    /// Her adjudication reveals `(m_a, r_a)`; the true outcome's clause is the
    /// only one that validates, and its CTV template pays the pot.
    pub fn alice_role() -> Role<AliceData, RpsOutcome> {
        Role::new()
            .on::<RpsGameS0, _>(|_d: &mut AliceData, _h: RpsGameS0Handle, _cx| Ok(Action::Wait))
            .on::<RpsGameS1, _>(|d, h: RpsGameS1Handle, cx| {
                // Bob's move travels in the witness of the spend that got us here.
                let parent = cx.parent.ok_or_else(|| {
                    ProtocolError::Other("S1 arises from S0's bob_move".into())
                })?;
                let witness = parent
                    .spending_args()
                    .ok_or_else(|| ProtocolError::Other("the parent S0 is spent".into()))?;
                let m_b = RpsGameS0BobMoveArgs::decode_from_witness(&witness)?.m_b;

                let result = outcome_of(d.m_a, m_b);
                if let Some(pace) = &d.before_adjudicating {
                    pace(m_b, result);
                }
                let builder = match result {
                    RpsResult::Tie => h.tie(m_b, d.m_a, d.r_a),
                    RpsResult::BobWins => h.bob_wins(m_b, d.m_a, d.r_a),
                    RpsResult::AliceWins => h.alice_wins(m_b, d.m_a, d.r_a),
                };
                let outcome = RpsOutcome {
                    result,
                    m_a: d.m_a,
                    m_b,
                };
                Ok(Action::SendFinal(builder, outcome))
            })
    }

    /// Bob's view: Alice's commitment and his own move.
    pub struct BobData {
        pub m_b: i64,
        pub c_a: [u8; 32],
        pub xpriv: Xpriv,
    }

    /// Bob reveals his move on-chain, then watches the adjudication and checks
    /// Alice's revealed move against her commitment and the game rule.
    pub fn bob_role() -> Role<BobData, RpsOutcome> {
        Role::new()
            .on::<RpsGameS0, _>(|d: &mut BobData, h: RpsGameS0Handle, _cx| {
                Ok(Action::Send(
                    h.bob_move(d.m_b).sign(HotSigner::new(d.xpriv)),
                ))
            })
            .on::<RpsGameS1, _>(|_d, _h: RpsGameS1Handle, _cx| Ok(Action::Wait))
            .on_settled::<RpsGameS1, _>(|d, h: RpsGameS1Handle, _cx| {
                let clause = h
                    .spent_clause()
                    .ok_or_else(|| ProtocolError::Other("the S1 instance is spent".into()))?;
                // The three adjudication clauses share one witness layout.
                let witness = h
                    .handle()
                    .spending_args()
                    .ok_or_else(|| ProtocolError::Other("the S1 instance is spent".into()))?;
                let args = RpsGameS1TieArgs::decode_from_witness(&witness)?;

                if alice_move_commitment(args.m_a, &args.r_a) != d.c_a {
                    return Err(ProtocolError::Other(
                        "Alice's revealed move breaks her commitment".into(),
                    ));
                }
                let result = outcome_of(args.m_a, d.m_b);
                if clause != clause_of(result) {
                    return Err(ProtocolError::Other(format!(
                        "adjudicated clause `{}` does not match the moves",
                        clause.name()
                    )));
                }
                Ok(RpsOutcome {
                    result,
                    m_a: args.m_a,
                    m_b: d.m_b,
                })
            })
    }
}
