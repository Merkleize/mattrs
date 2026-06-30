//! Vault contract example.
//!
//! A two-stage vault with trigger and recovery mechanisms. This lives in the test
//! support tree (not the library) and is written exactly as a downstream user
//! would write it against the public `mattrs` API.
#![allow(dead_code)]

use std::sync::Arc;

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{
    ClauseArgs, ClauseError, ClauseOutput, ClauseTree, ContractParams, ContractState, ErasedClause,
    ErasedContract, StandardAugmentedP2TR, StandardP2TR, TapTree, WitnessEncodable, WitnessError,
};
use mattrs::{
    clause, clause_tree, internal_key_or_nums, optional_key_script,
    contracts::CCV_FLAG_CHECK_INPUT, contracts::CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
};
use mattrs_derive::{ClauseArgs, ContractParams, ContractState};

define_pushable!();

// ============================================================================
// Vault Parameters & Clause Arguments
// ============================================================================

#[derive(Debug, Clone, ContractParams)]
pub struct VaultParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
    pub unvault_pk: XOnlyPublicKey,
}

#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = VaultParams)]
pub struct TriggerArgs {
    #[signer(|p| p.unvault_pk.serialize())]
    pub sig: Vec<u8>,
    pub ctv_hash: [u8; 32],
    pub out_i: i64,
}

#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = VaultParams)]
pub struct TriggerAndRevaultArgs {
    #[signer(|p| p.unvault_pk.serialize())]
    pub sig: Vec<u8>,
    pub ctv_hash: [u8; 32],
    pub out_i: i64,
    pub revault_out_i: i64,
}

#[derive(Debug, Clone, ClauseArgs)]
pub struct RecoverArgs {
    pub out_i: i64,
}

// ============================================================================
// Vault Contract
// ============================================================================

pub struct Vault {
    pub params: VaultParams,
    pub contract: StandardP2TR<VaultParams>,
}

impl Vault {
    pub fn new(params: VaultParams) -> Self {
        let internal_key = internal_key_or_nums(params.alternate_pk);

        let trigger: Arc<dyn ErasedClause> = clause!(
            "trigger",
            TriggerArgs,
            Self::trigger_script(&params),
            &params, // arg specs depend on params (the signer pubkey)
            |p: &VaultParams, args: &TriggerArgs, _s: Option<&()>| {
                Vault::new(p.clone()).trigger_outputs(args.ctv_hash, args.out_i as i32)
            }
        );

        let trigger_and_revault: Arc<dyn ErasedClause> = clause!(
            "trigger_and_revault",
            TriggerAndRevaultArgs,
            Self::trigger_and_revault_script(&params),
            &params,
            |p: &VaultParams, args: &TriggerAndRevaultArgs, _s: Option<&()>| {
                Vault::new(p.clone()).trigger_and_revault_outputs(
                    args.ctv_hash,
                    args.out_i as i32,
                    args.revault_out_i as i32,
                )
            }
        );

        let recover: Arc<dyn ErasedClause> = clause!(
            "recover",
            RecoverArgs,
            Self::recover_script(&params),
            |p: &VaultParams, _args: &RecoverArgs, _s: Option<&()>| {
                Vault::new(p.clone()).recover_outputs()
            }
        );

        let contract = StandardP2TR::new(
            internal_key,
            &params,
            clause_tree![trigger, [trigger_and_revault, recover]],
        );

        Self { params, contract }
    }

    fn trigger_script(params: &VaultParams) -> ScriptBuf {
        let unvaulting_taptree_root =
            Unvaulting::build_taptree(&Self::unvaulting_params(params)).root_hash();

        script! {
            { optional_key_script(params.alternate_pk) }
            { unvaulting_taptree_root }
            0
            CHECKCONTRACTVERIFY
            { params.unvault_pk }
            CHECKSIG
        }
    }

    fn trigger_and_revault_script(params: &VaultParams) -> ScriptBuf {
        let unvaulting_taptree_root =
            Unvaulting::build_taptree(&Self::unvaulting_params(params)).root_hash();

        script! {
            0 OP_SWAP
            -1
            -1
            { CCV_FLAG_DEDUCT_OUTPUT_AMOUNT }
            CHECKCONTRACTVERIFY
            { optional_key_script(params.alternate_pk) }
            { unvaulting_taptree_root }
            0
            CHECKCONTRACTVERIFY
            { params.unvault_pk }
            CHECKSIG
        }
    }

    fn recover_script(params: &VaultParams) -> ScriptBuf {
        script! {
            0
            SWAP
            { params.recover_pk }
            0
            0
            CHECKCONTRACTVERIFY
            TRUE
        }
    }

    /// The Unvaulting params derived from this vault's params.
    fn unvaulting_params(params: &VaultParams) -> UnvaultingParams {
        UnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        }
    }

    /// Get the contract as a type-erased ErasedContract.
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        Arc::new(self.contract.clone())
    }

    pub fn trigger_outputs(
        &self,
        ctv_hash: [u8; 32],
        out_i: i32,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let unvaulting = Unvaulting::new(Self::unvaulting_params(&self.params));
        let state = UnvaultingState { ctv_hash };

        Ok(vec![ClauseOutput::at(out_i as u32)
            .to(unvaulting.as_erased())
            .with_state(&state)
            .preserve_amount()
            .build()])
    }

    pub fn trigger_and_revault_outputs(
        &self,
        ctv_hash: [u8; 32],
        out_i: i32,
        revault_out_i: i32,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let unvaulting = Unvaulting::new(Self::unvaulting_params(&self.params));
        let state = UnvaultingState { ctv_hash };

        Ok(vec![
            ClauseOutput::at(revault_out_i as u32)
                .to(Arc::new(Vault::new(self.params.clone()).contract))
                .deduct_amount()
                .build(),
            ClauseOutput::at(out_i as u32)
                .to(unvaulting.as_erased())
                .with_state(&state)
                .preserve_amount()
                .build(),
        ])
    }

    pub fn recover_outputs(&self) -> Result<Vec<ClauseOutput>, ClauseError> {
        Ok(ClauseOutput::terminal())
    }
}

// ============================================================================
// Unvaulting Contract (Augmented with State)
// ============================================================================

#[derive(Debug, Clone, ContractParams)]
pub struct UnvaultingParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
}

#[derive(Debug, Clone, ContractState)]
pub struct UnvaultingState {
    pub ctv_hash: [u8; 32],
}

#[derive(Debug, Clone, ClauseArgs)]
pub struct WithdrawArgs {
    pub ctv_hash: [u8; 32],
}

#[derive(Debug, Clone, ClauseArgs)]
pub struct UnvaultingRecoverArgs {
    pub out_i: i64,
}

pub struct Unvaulting {
    pub params: UnvaultingParams,
}

impl Unvaulting {
    pub fn new(params: UnvaultingParams) -> Self {
        Unvaulting { params }
    }

    /// The single source of truth for the Unvaulting tapscript layout: both the
    /// taptree (via [`Unvaulting::build_taptree`]) and the spendable contract (via
    /// [`Unvaulting::as_erased`]) are derived from this clause tree.
    fn clause_tree(params: &UnvaultingParams) -> ClauseTree {
        let withdraw: Arc<dyn ErasedClause> = clause!(
            "withdraw",
            WithdrawArgs,
            Self::withdraw_script(params);
            UnvaultingParams,
            UnvaultingState
        );

        let recover: Arc<dyn ErasedClause> = clause!(
            "recover",
            UnvaultingRecoverArgs,
            Self::recover_script(params);
            UnvaultingParams,
            UnvaultingState
        );

        clause_tree![withdraw, recover]
    }

    pub fn build_taptree(params: &UnvaultingParams) -> Arc<TapTree> {
        Arc::new(Self::clause_tree(params).to_script_tree())
    }

    fn withdraw_script(params: &UnvaultingParams) -> ScriptBuf {
        script! {
            DUP
            -1
            { optional_key_script(params.alternate_pk) }
            -1
            { CCV_FLAG_CHECK_INPUT }
            CHECKCONTRACTVERIFY
            { params.spend_delay }
            CSV
            DROP
            CHECKTEMPLATEVERIFY
        }
    }

    fn recover_script(params: &UnvaultingParams) -> ScriptBuf {
        script! {
            0
            SWAP
            { params.recover_pk }
            0
            0
            CHECKCONTRACTVERIFY
            TRUE
        }
    }

    /// Get the contract as a type-erased augmented ErasedContract.
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        let naked_key = internal_key_or_nums(self.params.alternate_pk);
        Arc::new(StandardAugmentedP2TR::<UnvaultingParams, UnvaultingState>::new(
            naked_key,
            &self.params,
            Self::clause_tree(&self.params),
        ))
    }

    pub fn withdraw_outputs(&self, _ctv_hash: [u8; 32]) -> Result<Vec<ClauseOutput>, ClauseError> {
        Ok(ClauseOutput::terminal())
    }

    pub fn recover_outputs(&self) -> Result<Vec<ClauseOutput>, ClauseError> {
        Ok(ClauseOutput::terminal())
    }
}
