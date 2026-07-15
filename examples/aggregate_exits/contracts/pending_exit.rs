//! [`PendingExit`]: Ingrid's aggregate-exit claim under its challenge period.

use bitcoin::ScriptBuf;
use bitcoin_script::define_pushable;
use mattrs::contract;
use mattrs::contracts::{
    ArgSpec, ClauseError, ClauseOutput, WitnessReader, CCV_FLAG_CHECK_INPUT,
    CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
};
use mattrs::manager::SpendBuilder;
use mattrs::script_utils::{bn2vch, commit_int};
use mattrs::ContractState;

use super::delegation::{DelegationChallenge, DelegationChallengeState};
use super::dispute::{BisectRangeParams, ExitBisect1, ExitBisect1State};
use mattrs::stack::{Source, StackScript};
use super::unwind::{Unwind, UnwindState};
use super::{
    dual_proof_layer, spec, spec_num, step_h, ChallengeContext, ExitClaim, PoolParams, PoolTree,
};

define_pushable!();

/// The claim's committed state (Merkle root of the seven leaves, in field
/// order). `unwind_taptree` is carried as data because [`Unwind`]'s scripts
/// reference this contract's taptree — embedding the reverse reference as a
/// script constant would be circular; `start_exit` verified it against its own
/// input instead.
#[derive(Debug, Clone, PartialEq, Eq, ContractState)]
#[commit(merkle)]
pub struct PendingExitState {
    /// [`Unwind`]'s taptree root (revert/continue target).
    pub unwind_taptree: [u8; 32],
    /// The pool root the claim starts from.
    pub r: [u8; 32],
    /// The claimed post-exit root.
    pub r_prime: [u8; 32],
    /// The exit-set bit-tree root.
    pub s_root: [u8; 32],
    /// Ingrid's payout key.
    pub ingrid_pk: [u8; 32],
    /// Ingrid's trace commitment over the N exit steps.
    pub trace_i: [u8; 32],
    /// The claimed aggregate balance.
    #[leaf(sha256)]
    pub x: i64,
}

impl PendingExitState {
    /// The claim state `start_exit` commits for `claim` on behalf of
    /// `ingrid_pk` (also what a bond's `stake_claim` must reproduce).
    pub fn for_claim(
        params: &PoolParams,
        claim: &ExitClaim,
        ingrid_pk: &bitcoin::XOnlyPublicKey,
    ) -> Self {
        PendingExitState {
            unwind_taptree: Unwind::new(params.clone()).taptree_root(),
            r: claim.r,
            r_prime: claim.r_prime,
            s_root: claim.s_root,
            ingrid_pk: ingrid_pk.serialize(),
            trace_i: claim.trace,
            x: claim.x,
        }
    }

    /// The committed state hash (the Merkle root of the seven leaves) — what a
    /// dispute needs to resume this claim.
    pub fn hash(&self) -> [u8; 32] {
        use mattrs::contracts::ContractState;
        self.encode().try_into().expect("merkle commitment is 32 bytes")
    }

    /// The state fields as witness elements, in leaf order (`x` as a script
    /// number: the scripts hash it into its leaf themselves).
    pub fn to_witness(&self) -> Vec<Vec<u8>> {
        vec![
            self.unwind_taptree.to_vec(),
            self.r.to_vec(),
            self.r_prime.to_vec(),
            self.s_root.to_vec(),
            self.ingrid_pk.to_vec(),
            self.trace_i.to_vec(),
            bn2vch(self.x),
        ]
    }
}

contract! {
    /// The claim matures over `challenge_period` blocks. Anyone may then
    /// `finalize` it (the outputs are covenant-fixed); before that, anyone may
    /// challenge the claimed amount/root (`challenge_state`, entering the
    /// bisection game) and anyone may dispute a specific user's delegation
    /// (`challenge_delegation`) — a user who never delegated is their own
    /// natural challenger, but the clause only requires posting the bond.
    ///
    /// Challenges post a bond via a batched [`super::ExitBond`] input; a failed
    /// challenge resumes this contract with the same state (a fresh challenge
    /// period — each retry costs another challenger half their bond).
    contract PendingExit {
        params PoolParams;
        state PendingExitState;

        // witness: <unwind_taptree> <r> <r_prime> <s_root> <ingrid_pk> <trace_i> <x>
        clause finalize {
            args raw |_p| PendingExit::state_specs();
            script PendingExit::finalize_script;
            timelock |p| p.challenge_period;
            next(p, a) {
                PendingExit::finalize_outputs(p, &a.0)
            }
        }

        // witness: <state...> <pe_taptree> <challenger_pk> <h_end_c> <trace_c>
        clause challenge_state {
            args raw |_p| PendingExit::challenge_state_specs();
            script PendingExit::challenge_state_script;
            next(p, a, s) {
                PendingExit::challenge_state_outputs(p, &a.0, s)
            }
        }

        // witness: <state...> <pe_taptree> <challenger_pk> <user_pk> <bal>
        //          (<sib_r_l> <sib_s_l> <d_l>) x depth
        clause challenge_delegation {
            args raw |p| PendingExit::challenge_delegation_specs(p);
            script PendingExit::challenge_delegation_script;
            next(p, a, s) {
                PendingExit::challenge_delegation_outputs(p, &a.0, s)
            }
        }

        tree [finalize, [challenge_state, challenge_delegation]];
    }
}

impl PendingExit {
    fn state_specs() -> Vec<ArgSpec> {
        vec![
            spec("unwind_taptree"),
            spec("r"),
            spec("r_prime"),
            spec("s_root"),
            spec("ingrid_pk"),
            spec("trace_i"),
            spec_num("x"),
        ]
    }

    /// Reveal the state leaves on `s`, commit them as `as_name`, and verify
    /// against the input. `taptree` is `Source::Current` when the clause may
    /// rely on the input's own taptree, or the witness `pe_taptree` when the
    /// clause must bind a copy of it for downstream use. Leaves the seven
    /// witness items (and `as_name`) tracked.
    fn reveal_state(s: &mut StackScript, as_name: &str, taptree: Source) {
        s.pick("x");
        s.sha256_top("x_leaf");
        s.merkle_of(
            &["unwind_taptree", "r", "r_prime", "s_root", "ingrid_pk", "trace_i", "x_leaf"],
            as_name,
        );
        s.ccv(
            Source::Item(as_name),
            -1,
            Source::None,
            taptree,
            CCV_FLAG_CHECK_INPUT,
        );
    }

    fn finalize_script(_p: &PoolParams) -> ScriptBuf {
        let mut s = StackScript::from_specs(&Self::state_specs());
        Self::reveal_state(&mut s, "state", Source::Current);

        // Output 0 pays Ingrid.
        // TODO(OP_AMOUNT): enforce that output 0 carries exactly `x + bond`
        // sats — the claimed aggregate plus Ingrid's returned bond.
        s.ccv(
            Source::None,
            0,
            Source::Item("ingrid_pk"),
            Source::None,
            CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
        );
        // Output 1 continues the pool at the claimed post-exit root.
        s.ccv(
            Source::Item("r_prime"),
            1,
            Source::None,
            Source::Item("unwind_taptree"),
            0,
        );
        s.into_script()
    }

    fn finalize_outputs(
        p: &PoolParams,
        witness: &[Vec<u8>],
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let mut w = WitnessReader::new(witness);
        w.skip(2)?; // unwind_taptree, r
        let r_prime = w.bytes32()?;
        w.skip(1)?; // s_root
        let ingrid_pk = w.xonly()?;
        Ok(vec![
            ClauseOutput::pay_key(0, ingrid_pk),
            ClauseOutput::at(1)
                .to(Unwind::new(p.clone()).as_erased())
                .with_state(&UnwindState { root: r_prime })
                .preserve_amount()
                .build(),
        ])
    }

    fn challenge_state_specs() -> Vec<ArgSpec> {
        let mut specs = Self::state_specs();
        specs.extend([spec("pe_taptree"), spec("challenger_pk"), spec("h_end_c"), spec("trace_c")]);
        specs
    }

    fn challenge_state_script(p: &PoolParams) -> ScriptBuf {
        let mut s = StackScript::from_specs(&Self::challenge_state_specs());

        // Verify the state against the input, binding the witness copy of our
        // own taptree (needed downstream to resume this claim).
        Self::reveal_state(&mut s, "resume", Source::Item("pe_taptree"));

        // The bisection endpoints: h_start = H(r || bn2vch(0)) = H(r), and
        // Ingrid's claimed end H(r_prime || bn2vch(x)); the challenger commits
        // their own end and trace as fresh witness data.
        s.sha_cat(&["r"], "h_start");
        s.sha_cat(&["r_prime", "x"], "h_end_i");
        s.sha_cat(&super::CARRY_ITEMS, "carry");
        s.merkle_of(
            &["h_start", "h_end_i", "h_end_c", "trace_i", "trace_c", "carry"],
            "b1_state",
        );

        // Output 0 is the bisection game over the full step range.
        // TODO(OP_AMOUNT): enforce that output 0 carries the pot plus the
        // challenger's bond (`p.bond` sats on top of the input amount).
        let b1_root = ExitBisect1::new(BisectRangeParams::entry(p)).taptree_root();
        s.ccv(Source::Item("b1_state"), 0, Source::None, Source::Const(b1_root), 0);
        s.into_script()
    }

    fn challenge_state_outputs(
        p: &PoolParams,
        witness: &[Vec<u8>],
        state: Option<&PendingExitState>,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = state.ok_or_else(|| {
            ClauseError::Other("challenge_state needs the claim state".to_string())
        })?;
        let mut w = WitnessReader::new(witness);
        w.skip(7)?; // the state fields; `state` already carries them decoded
        let ctx = ChallengeContext {
            resume_state: state.clone(),
            pe_taptree: w.bytes32()?,
            challenger_pk: w.bytes32()?,
        };
        let b1_state = ExitBisect1State {
            h_start: step_h(&state.r, 0),
            h_end_i: step_h(&state.r_prime, state.x),
            h_end_c: w.bytes32()?,
            trace_i: state.trace_i,
            trace_c: w.bytes32()?,
            ctx,
        };
        w.expect_end()?;
        Ok(vec![ClauseOutput::at(0)
            .to(ExitBisect1::new(BisectRangeParams::entry(p)).as_erased())
            .with_state(&b1_state)
            .preserve_amount()
            .build()])
    }

    fn challenge_delegation_specs(p: &PoolParams) -> Vec<ArgSpec> {
        let mut specs = Self::state_specs();
        specs.extend([spec("pe_taptree"), spec("challenger_pk"), spec("user_pk"), spec_num("bal")]);
        for l in 0..p.depth() {
            specs.push(spec(&format!("sib_r_{l}")));
            specs.push(spec(&format!("sib_s_{l}")));
            specs.push(spec_num(&format!("d_{l}")));
        }
        specs
    }

    fn challenge_delegation_script(p: &PoolParams) -> ScriptBuf {
        let depth = p.depth();
        let mut s = StackScript::from_specs(&Self::challenge_delegation_specs(p));

        Self::reveal_state(&mut s, "resume", Source::Item("pe_taptree"));

        // One shared-direction walk proves that the challenged slot holds
        // `(user_pk, bal)` in the pool root *and* that its exit bit is set.
        s.sha_cat(&["user_pk", "bal"], "a");
        s.push_const("b", commit_int(1));
        for l in (0..depth).rev() {
            s.roll(&format!("sib_r_{l}"));
            s.roll(&format!("sib_s_{l}"));
            s.roll(&format!("d_{l}"));
            s.raw(dual_proof_layer(), 5, &["a", "b"]);
        }
        s.expect_equal("a", "r");
        s.expect_equal("b", "s_root");

        s.merkle_of(
            &["resume", "pe_taptree", "unwind_taptree", "r", "ingrid_pk", "user_pk", "challenger_pk"],
            "dc_state",
        );
        // TODO(OP_AMOUNT): enforce that output 0 carries the pot plus the
        // challenger's bond (`p.bond` sats on top of the input amount).
        let dc_root = DelegationChallenge::new(p.clone()).taptree_root();
        s.ccv(Source::Item("dc_state"), 0, Source::None, Source::Const(dc_root), 0);
        s.into_script()
    }

    fn challenge_delegation_outputs(
        p: &PoolParams,
        witness: &[Vec<u8>],
        state: Option<&PendingExitState>,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = state.ok_or_else(|| {
            ClauseError::Other("challenge_delegation needs the claim state".to_string())
        })?;
        let mut w = WitnessReader::new(witness);
        w.skip(7)?; // the state fields; `state` already carries them decoded
        let pe_taptree = w.bytes32()?;
        let challenger_pk = w.bytes32()?;
        let dc_state = DelegationChallengeState {
            // `bal` and the membership proof follow; the script verified them.
            user_pk: w.bytes32()?,
            ctx: ChallengeContext {
                resume_state: state.clone(),
                pe_taptree,
                challenger_pk,
            },
        };
        Ok(vec![ClauseOutput::at(0)
            .to(DelegationChallenge::new(p.clone()).as_erased())
            .with_state(&dc_state)
            .preserve_amount()
            .build()])
    }
}

impl PendingExitHandle {
    fn claim_state(&self) -> PendingExitState {
        self.state().expect("PendingExit instances carry their claim state")
    }

    /// Settle the matured claim: output 0 pays Ingrid, output 1 continues the
    /// pool at the claimed root. The caller must set the payout amount
    /// (`.output_amount(0, x + bond)`); the clause's `timelock` sets the CSV
    /// sequence.
    pub fn finalize(&self) -> SpendBuilder {
        self.0.spend_clause("finalize", self.claim_state().to_witness())
    }

    /// Open the bisection game on the claimed amount/root. `honest` is the
    /// challenger's own (honest) run of the claimed exit set. Batch with an
    /// [`super::ExitBond`] `stake_state_challenge` spend for the bond.
    pub fn challenge_state(
        &self,
        honest: &ExitClaim,
        challenger_pk: &bitcoin::XOnlyPublicKey,
    ) -> SpendBuilder {
        let state = self.claim_state();
        let pe_taptree = PendingExit::new(self.params()).taptree_root();
        let mut witness = state.to_witness();
        witness.push(pe_taptree.to_vec());
        witness.push(challenger_pk.serialize().to_vec());
        witness.push(honest.hs.last().unwrap().to_vec());
        witness.push(honest.trace.to_vec());
        self.0.spend_clause("challenge_state", witness)
    }

    /// Dispute user `index`'s delegation: prove the slot's account and its set
    /// exit bit, and put Ingrid on the clock to reveal the delegation
    /// signature. Batch with an [`super::ExitBond`] `stake_delegation_challenge`
    /// spend for the bond.
    pub fn challenge_delegation(
        &self,
        pool: &PoolTree,
        bits: &[bool],
        index: usize,
        challenger_pk: &bitcoin::XOnlyPublicKey,
    ) -> SpendBuilder {
        let state = self.claim_state();
        let (user_pk, bal) = pool.accounts[index].expect("challenged slot is empty");
        let account_proof = pool.prove(index);
        let bit_tree =
            mattrs::merkle::MerkleTree::new(bits.iter().map(|b| super::bit_leaf(*b)).collect());
        let bit_proof = bit_tree.prove_leaf(index);
        assert_eq!(account_proof.directions, bit_proof.directions);

        let pe_taptree = PendingExit::new(self.params()).taptree_root();
        let mut witness = state.to_witness();
        witness.push(pe_taptree.to_vec());
        witness.push(challenger_pk.serialize().to_vec());
        witness.push(user_pk.serialize().to_vec());
        witness.push(bn2vch(bal));
        for l in 0..account_proof.hashes.len() {
            witness.push(account_proof.hashes[l].to_vec());
            witness.push(bit_proof.hashes[l].to_vec());
            witness.push(bn2vch(account_proof.directions[l] as i64));
        }
        self.0.spend_clause("challenge_delegation", witness)
    }
}
