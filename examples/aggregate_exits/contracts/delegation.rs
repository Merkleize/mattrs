//! [`DelegationChallenge`]: "user k never delegated to you — prove it."

use bitcoin::ScriptBuf;
use bitcoin_script::{define_pushable, script};
use mattrs::contract;
use mattrs::contracts::{
    ArgSpec, ClauseError, ClauseOutput, CCV_FLAG_CHECK_INPUT, CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
};
use mattrs::manager::SpendBuilder;

use super::bond::{burn_output, key_payout_output};
use super::pending_exit::PendingExit;
use super::stack::{Source, StackScript};
use super::unwind::{Unwind, UnwindState};
use super::{spec, ChallengeContext, PoolParams};

define_pushable!();

/// The challenge's committed state: seven leaves (in [`Self::leaves`] order)
/// carrying everything either outcome needs. The expanded state additionally
/// rides the full claim being disputed, so a defended challenge can resume it.
#[derive(Debug, Clone)]
pub struct DelegationChallengeState {
    /// The challenged user's key (their delegation is what Ingrid must reveal).
    pub user_pk: [u8; 32],
    /// The disputed claim and dispute parties.
    pub ctx: ChallengeContext,
}

impl DelegationChallengeState {
    /// The committed leaves: resume hash, the two carried taptrees, the revert
    /// root, and the three party keys.
    pub fn leaves(&self) -> [[u8; 32]; 7] {
        [
            self.ctx.resume_state.hash(),
            self.ctx.pe_taptree,
            self.ctx.resume_state.unwind_taptree,
            self.ctx.resume_state.r,
            self.ctx.resume_state.ingrid_pk,
            self.user_pk,
            self.ctx.challenger_pk,
        ]
    }

    fn to_witness(&self) -> Vec<Vec<u8>> {
        self.leaves().iter().map(|l| l.to_vec()).collect()
    }
}

super::opaque_merkle_state!(DelegationChallengeState);

/// The tracked-stack names of the seven state leaves, bottom → top.
const STATE_ITEMS: [&str; 7] = [
    "resume",
    "pe_taptree",
    "unwind_taptree",
    "r",
    "ingrid_pk",
    "user_pk",
    "challenger_pk",
];

contract! {
    /// Ingrid defends by revealing the challenged user's delegation signature,
    /// verified against the user's in-pool key with OP_CHECKSIGFROMSTACK: the
    /// claim resumes (with a fresh challenge period) and she pockets half the
    /// challenger's bond, burning the other half. If she cannot within the
    /// response timeout, the withdrawal is reverted and her own bond is
    /// half-slashed to the challenger, half burned.
    contract DelegationChallenge {
        params PoolParams;
        state DelegationChallengeState;

        // witness: the seven state leaves (STATE_ITEMS order), then <sig>
        clause defend {
            args raw |_p| DelegationChallenge::defend_specs();
            script DelegationChallenge::defend_script;
            next(p, a, s) {
                DelegationChallenge::defend_outputs(p, &a.0, s)
            }
        }

        // witness: the seven state leaves (STATE_ITEMS order)
        clause challenger_wins {
            args raw |_p| DelegationChallenge::challenger_wins_specs();
            script DelegationChallenge::challenger_wins_script;
            next(p, a, s) {
                DelegationChallenge::challenger_wins_outputs(p, &a.0, s)
            }
        }

        tree [defend, challenger_wins];
    }
}

impl DelegationChallenge {
    fn state_specs() -> Vec<ArgSpec> {
        STATE_ITEMS.iter().map(|name| spec(name)).collect()
    }

    /// Reveal and verify the seven state leaves against the input commitment.
    fn reveal_state(s: &mut StackScript) {
        s.merkle_of(&STATE_ITEMS, "state");
        s.ccv(
            Source::Item("state"),
            -1,
            Source::None,
            Source::Current,
            CCV_FLAG_CHECK_INPUT,
        );
    }

    fn defend_specs() -> Vec<ArgSpec> {
        let mut specs = Self::state_specs();
        specs.push(spec("sig"));
        specs
    }

    fn defend_script(p: &PoolParams) -> ScriptBuf {
        let mut s = StackScript::from_specs(&Self::defend_specs());
        Self::reveal_state(&mut s);

        // The delegation message is H(pool_id || ingrid_pk); the signature
        // must verify against the user's in-pool key.
        s.push_const("pool_id", p.pool_id);
        s.sha_cat(&["pool_id", "ingrid_pk"], "msg");
        s.roll("sig");
        s.roll("msg");
        s.pick("user_pk");
        s.raw(script! { OP_CHECKSIGFROMSTACK OP_VERIFY }, 3, &[]);

        // Output 0: half the challenger's bond to Ingrid.
        // TODO(OP_AMOUNT): enforce that output 0 carries exactly `bond / 2`.
        s.ccv(
            Source::None,
            0,
            Source::Item("ingrid_pk"),
            Source::None,
            CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
        );
        // Output 1: the other half is burned.
        // TODO(OP_AMOUNT): enforce that output 1 carries `bond - bond / 2`.
        s.ccv(
            Source::None,
            1,
            Source::Const(mattrs::nums_key().serialize()),
            Source::None,
            CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
        );
        // Output 2 resumes the claim (same state, fresh challenge period).
        s.ccv(
            Source::Item("resume"),
            2,
            Source::None,
            Source::Item("pe_taptree"),
            0,
        );
        s.into_script()
    }

    fn defend_outputs(
        p: &PoolParams,
        witness: &[Vec<u8>],
        state: Option<&DelegationChallengeState>,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = state.ok_or_else(|| {
            ClauseError::Other("defend needs the challenge state".to_string())
        })?;
        let ingrid_pk = super::wpk(witness, 4)?;
        Ok(vec![
            key_payout_output(ingrid_pk, 0),
            burn_output(1),
            ClauseOutput::at(2)
                .to(PendingExit::new(p.clone()).as_erased())
                .with_state(&state.ctx.resume_state)
                .preserve_amount()
                .build(),
        ])
    }

    fn challenger_wins_specs() -> Vec<ArgSpec> {
        Self::state_specs()
    }

    fn challenger_wins_script(p: &PoolParams) -> ScriptBuf {
        let mut s = StackScript::from_specs(&Self::challenger_wins_specs());
        s.older(p.response_timeout);
        Self::reveal_state(&mut s);

        // Output 0: the challenger's bond back plus half of Ingrid's.
        // TODO(OP_AMOUNT): enforce that output 0 carries `bond + bond / 2`.
        s.ccv(
            Source::None,
            0,
            Source::Item("challenger_pk"),
            Source::None,
            CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
        );
        // Output 1: the other half of Ingrid's bond is burned.
        // TODO(OP_AMOUNT): enforce that output 1 carries `bond - bond / 2`.
        s.ccv(
            Source::None,
            1,
            Source::Const(mattrs::nums_key().serialize()),
            Source::None,
            CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
        );
        // Output 2 reverts the pool to the pre-claim root.
        s.ccv(
            Source::Item("r"),
            2,
            Source::None,
            Source::Item("unwind_taptree"),
            0,
        );
        s.into_script()
    }

    fn challenger_wins_outputs(
        p: &PoolParams,
        witness: &[Vec<u8>],
        state: Option<&DelegationChallengeState>,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = state.ok_or_else(|| {
            ClauseError::Other("challenger_wins needs the challenge state".to_string())
        })?;
        let challenger_pk = super::wpk(witness, 6)?;
        Ok(vec![
            key_payout_output(challenger_pk, 0),
            burn_output(1),
            ClauseOutput::at(2)
                .to(Unwind::new(p.clone()).as_erased())
                .with_state(&UnwindState {
                    root: state.ctx.resume_state.r,
                })
                .preserve_amount()
                .build(),
        ])
    }
}

impl DelegationChallengeHandle {
    fn challenge_state(&self) -> DelegationChallengeState {
        self.state().expect("DelegationChallenge instances carry their state")
    }

    /// Ingrid reveals the challenged user's delegation signature. The caller
    /// must set the slash amounts (`.output_amount(0, bond / 2)` and
    /// `.output_amount(1, bond - bond / 2)`).
    pub fn defend(&self, delegation_sig: &[u8; 64]) -> SpendBuilder {
        let mut witness = self.challenge_state().to_witness();
        witness.push(delegation_sig.to_vec());
        self.0.spend_clause("defend", witness)
    }

    /// The challenger collects after Ingrid's response timeout. The caller
    /// must set the slash amounts (`.output_amount(0, bond + bond / 2)` and
    /// `.output_amount(1, bond - bond / 2)`); the CSV sequence is set here.
    pub fn challenger_wins(&self) -> SpendBuilder {
        let witness = self.challenge_state().to_witness();
        self.0
            .spend_clause("challenger_wins", witness)
            .sequence(self.params().expect("params decode").response_timeout)
    }
}
