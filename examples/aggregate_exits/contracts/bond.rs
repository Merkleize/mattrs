//! Bonds and bare-key payout outputs.
//!
//! [`ExitBond`] is a plain UTXO its owner pre-funds and then co-spends (via
//! [`mattrs::manager::ContractManager::spend_batch`]) into a claim or challenge
//! transaction: its clause produces the *same* covenant output as the pool-side
//! clause, so the manager merges the two and the bond value joins the pot. The
//! data arguments exist only so `next()` can rebuild that output; the script
//! just checks the owner's signature and drops them.
//!
//! [`KeyPayout`] is the minimal [`ErasedContract`] for an output that pays a
//! bare key as the witness program (`opaque_p2tr`) — what a
//! `CHECKCONTRACTVERIFY` with empty data and empty taptree constrains an output
//! to. [`KeyPayout::burn`] targets the NUMS key: with no known discrete log and
//! no script path, the output is unspendable — the "burned" half of a slashed
//! bond.

use std::sync::Arc;

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs::argtypes::SignerType;
use mattrs::contract;
use mattrs::contracts::{
    ArgSpec, ClauseError, ClauseOutput, ContractError, ErasedClause, ErasedContract, ErasedState,
    NextOutputs, TapTree,
};
use mattrs::manager::SpendBuilder;
use mattrs::script_helpers::opaque_p2tr;
use mattrs_derive::ContractParams;

use super::delegation::{DelegationChallenge, DelegationChallengeState};
use super::dispute::{BisectRangeParams, ExitBisect1, ExitBisect1State};
use super::pending_exit::{PendingExit, PendingExitState};
use super::stack::StackScript;
use super::{spec, spec_num, step_h, w32, wnum, ChallengeContext, ExitClaim, PoolParams};

define_pushable!();

// ============================================================================
// KeyPayout: bare-key (and burn) outputs as clause-output targets
// ============================================================================

/// A clause-output target paying `pk` directly as the taproot witness program.
#[derive(Debug, Clone)]
pub struct KeyPayout {
    pk: XOnlyPublicKey,
    name: &'static str,
    params_bytes: Vec<u8>,
    taptree: Arc<TapTree>,
}

impl KeyPayout {
    /// A payout to `pk` (spendable by its owner via the key path).
    pub fn new(pk: XOnlyPublicKey) -> Self {
        Self::named("KeyPayout", pk)
    }

    /// A provably unspendable output: the NUMS key, verbatim, no script path.
    pub fn burn() -> Self {
        Self::named("Burn", mattrs::nums_key())
    }

    fn named(name: &'static str, pk: XOnlyPublicKey) -> Self {
        KeyPayout {
            pk,
            name,
            params_bytes: pk.serialize().to_vec(),
            // Placeholder: a KeyPayout has no script paths; the taptree is
            // never part of its scriptPubKey (the key is used verbatim).
            taptree: Arc::new(TapTree::leaf("none", ScriptBuf::new())),
        }
    }
}

impl ErasedContract for KeyPayout {
    fn clauses(&self) -> &[Arc<dyn ErasedClause>] {
        &[]
    }

    fn params_bytes(&self) -> &[u8] {
        &self.params_bytes
    }

    fn get_clause(&self, _name: &str) -> Option<&Arc<dyn ErasedClause>> {
        None
    }

    fn execute_clause_from_witness(
        &self,
        clause_name: &str,
        _witness: &[Vec<u8>],
        _state: Option<&dyn ErasedState>,
    ) -> Result<NextOutputs, ClauseError> {
        Err(ClauseError::Other(format!(
            "{} has no clause {clause_name}",
            self.name
        )))
    }

    fn contract_type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<Self>()
    }

    fn contract_name(&self) -> &'static str {
        self.name
    }

    fn script_pubkey(&self, _state_bytes: Option<&[u8]>) -> Result<ScriptBuf, ContractError> {
        Ok(opaque_p2tr(self.pk))
    }

    fn control_block_internal_key(
        &self,
        _state_bytes: Option<&[u8]>,
    ) -> Result<XOnlyPublicKey, ContractError> {
        Ok(self.pk)
    }

    fn taptree(&self) -> &Arc<TapTree> {
        &self.taptree
    }

    fn clone_boxed(&self) -> Box<dyn ErasedContract> {
        Box::new(self.clone())
    }
}

/// A deduct-amount payout to `pk` at output `index` (the caller supplies the
/// amount via `SpendBuilder::output_amount`).
pub fn key_payout_output(pk: XOnlyPublicKey, index: u32) -> ClauseOutput {
    let contract: Arc<dyn ErasedContract> = Arc::new(KeyPayout::new(pk));
    ClauseOutput::at(index).to(contract).deduct_amount().build()
}

/// A deduct-amount burn at output `index`.
pub fn burn_output(index: u32) -> ClauseOutput {
    let contract: Arc<dyn ErasedContract> = Arc::new(KeyPayout::burn());
    ClauseOutput::at(index).to(contract).deduct_amount().build()
}

// ============================================================================
// ExitBond
// ============================================================================

/// A bond UTXO's parameters: the pool it can stake into and its owner.
#[derive(Debug, Clone, ContractParams)]
pub struct ExitBondParams {
    pub pool: PoolParams,
    pub owner_pk: XOnlyPublicKey,
}

contract! {
    /// A pre-funded bond. Each clause co-signs the bond into one kind of pot:
    /// a claim ([`PendingExit`]), a state challenge ([`ExitBisect1`]), or a
    /// delegation challenge ([`DelegationChallenge`]). The witness carries the
    /// target's state fields only so `next()` reproduces the pool-side clause
    /// output exactly (the manager then merges the two into one accumulated
    /// output); the script just verifies the owner's signature.
    contract ExitBond {
        params ExitBondParams;

        // witness: <ut> <r> <r_prime> <s_root> <ipk> <trace_i> <x> <sig>
        clause stake_claim {
            args raw |p| ExitBond::stake_claim_specs(p);
            script |p| ExitBond::stake_script(p, 7);
            next(p, a) {
                ExitBond::stake_claim_outputs(p, &a.0)
            }
        }

        // witness: <ut> <r> <r_prime> <s_root> <ipk> <trace_i> <x>
        //          <pe_tt> <cpk> <h_end_c> <trace_c> <sig>
        clause stake_state_challenge {
            args raw |p| ExitBond::stake_state_challenge_specs(p);
            script |p| ExitBond::stake_script(p, 11);
            next(p, a) {
                ExitBond::stake_state_challenge_outputs(p, &a.0)
            }
        }

        // witness: <ut> <r> <r_prime> <s_root> <ipk> <trace_i> <x>
        //          <pe_tt> <cpk> <user_pk> <sig>
        clause stake_delegation_challenge {
            args raw |p| ExitBond::stake_delegation_challenge_specs(p);
            script |p| ExitBond::stake_script(p, 10);
            next(p, a) {
                ExitBond::stake_delegation_challenge_outputs(p, &a.0)
            }
        }

        tree [stake_claim, [stake_state_challenge, stake_delegation_challenge]];
    }
}

impl ExitBond {
    fn claim_field_specs() -> Vec<ArgSpec> {
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

    fn sig_spec(p: &ExitBondParams) -> ArgSpec {
        ArgSpec {
            name: "sig".to_string(),
            arg_type: Arc::new(SignerType::new(p.owner_pk.serialize())),
        }
    }

    fn stake_claim_specs(p: &ExitBondParams) -> Vec<ArgSpec> {
        let mut specs = Self::claim_field_specs();
        specs.push(Self::sig_spec(p));
        specs
    }

    fn stake_state_challenge_specs(p: &ExitBondParams) -> Vec<ArgSpec> {
        let mut specs = Self::claim_field_specs();
        specs.extend([spec("pe_taptree"), spec("challenger_pk"), spec("h_end_c"), spec("trace_c")]);
        specs.push(Self::sig_spec(p));
        specs
    }

    fn stake_delegation_challenge_specs(p: &ExitBondParams) -> Vec<ArgSpec> {
        let mut specs = Self::claim_field_specs();
        specs.extend([spec("pe_taptree"), spec("challenger_pk"), spec("user_pk")]);
        specs.push(Self::sig_spec(p));
        specs
    }

    /// `<data> x n_data <sig>` — check the owner's signature, drop the data.
    fn stake_script(p: &ExitBondParams, n_data: usize) -> ScriptBuf {
        let names: Vec<String> = (0..n_data)
            .map(|i| format!("data_{i}"))
            .chain(["sig".to_string()])
            .collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut s = StackScript::with_witness(&name_refs);
        let owner = p.owner_pk;
        s.raw(script! { { owner } OP_CHECKSIGVERIFY }, 1, &[]);
        s.into_script()
    }

    /// The claim state carried by a stake witness (elements `0..7`).
    fn witness_claim_state(witness: &[Vec<u8>]) -> Result<PendingExitState, ClauseError> {
        Ok(PendingExitState {
            unwind_taptree: w32(witness, 0)?,
            r: w32(witness, 1)?,
            r_prime: w32(witness, 2)?,
            s_root: w32(witness, 3)?,
            ingrid_pk: w32(witness, 4)?,
            trace_i: w32(witness, 5)?,
            x: wnum(witness, 6)?,
        })
    }

    fn stake_claim_outputs(
        p: &ExitBondParams,
        witness: &[Vec<u8>],
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let state = Self::witness_claim_state(witness)?;
        Ok(vec![ClauseOutput::at(0)
            .to(PendingExit::new(p.pool.clone()).as_erased())
            .with_state(&state)
            .preserve_amount()
            .build()])
    }

    fn stake_state_challenge_outputs(
        p: &ExitBondParams,
        witness: &[Vec<u8>],
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let resume = Self::witness_claim_state(witness)?;
        let b1_state = ExitBisect1State {
            h_start: step_h(&resume.r, 0),
            h_end_i: step_h(&resume.r_prime, resume.x),
            h_end_c: w32(witness, 9)?,
            trace_i: resume.trace_i,
            trace_c: w32(witness, 10)?,
            ctx: ChallengeContext {
                resume_state: resume,
                pe_taptree: w32(witness, 7)?,
                challenger_pk: w32(witness, 8)?,
            },
        };
        Ok(vec![ClauseOutput::at(0)
            .to(ExitBisect1::new(BisectRangeParams::entry(&p.pool)).as_erased())
            .with_state(&b1_state)
            .preserve_amount()
            .build()])
    }

    fn stake_delegation_challenge_outputs(
        p: &ExitBondParams,
        witness: &[Vec<u8>],
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let resume = Self::witness_claim_state(witness)?;
        let dc_state = DelegationChallengeState {
            user_pk: w32(witness, 9)?,
            ctx: ChallengeContext {
                resume_state: resume,
                pe_taptree: w32(witness, 7)?,
                challenger_pk: w32(witness, 8)?,
            },
        };
        Ok(vec![ClauseOutput::at(0)
            .to(DelegationChallenge::new(p.pool.clone()).as_erased())
            .with_state(&dc_state)
            .preserve_amount()
            .build()])
    }
}

impl ExitBondHandle {
    fn pe_taptree(&self) -> [u8; 32] {
        PendingExit::new(self.params().expect("params decode").pool).taptree_root()
    }

    /// Stake this bond into Ingrid's claim (batch with `Unwind::start_exit`).
    /// Sign with the bond owner's key.
    pub fn stake_claim(&self, claim_state: &PendingExitState) -> SpendBuilder {
        let mut witness = claim_state.to_witness();
        witness.push(Vec::new()); // signature, filled at spend time
        self.0.spend_clause("stake_claim", witness)
    }

    /// Stake this bond into a state challenge (batch with
    /// `PendingExit::challenge_state`).
    pub fn stake_state_challenge(
        &self,
        claim_state: &PendingExitState,
        honest: &ExitClaim,
        challenger_pk: &XOnlyPublicKey,
    ) -> SpendBuilder {
        let mut witness = claim_state.to_witness();
        witness.push(self.pe_taptree().to_vec());
        witness.push(challenger_pk.serialize().to_vec());
        witness.push(honest.hs[honest.hs.len() - 1].to_vec());
        witness.push(honest.trace.to_vec());
        witness.push(Vec::new());
        self.0.spend_clause("stake_state_challenge", witness)
    }

    /// Stake this bond into a delegation challenge (batch with
    /// `PendingExit::challenge_delegation`).
    pub fn stake_delegation_challenge(
        &self,
        claim_state: &PendingExitState,
        user_pk: &XOnlyPublicKey,
        challenger_pk: &XOnlyPublicKey,
    ) -> SpendBuilder {
        let mut witness = claim_state.to_witness();
        witness.push(self.pe_taptree().to_vec());
        witness.push(challenger_pk.serialize().to_vec());
        witness.push(user_pk.serialize().to_vec());
        witness.push(Vec::new());
        self.0.spend_clause("stake_delegation_challenge", witness)
    }
}
