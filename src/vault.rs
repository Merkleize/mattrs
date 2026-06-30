//! Vault contract implementation
//!
//! A two-stage vault with trigger and recovery mechanisms.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs_derive::{ClauseArgs, Contract, ContractParams, ContractState};

use crate::contracts::{
    ClauseArgs, ClauseError, ClauseOutput, ContractParams,
    ContractState, ErasedClause, ErasedContract, StandardAugmentedP2TR, StandardP2TR, TapTree,
    WitnessEncodable, WitnessError,
};

define_pushable!();

// NUMS key (nothing-up-my-sleeve)
const NUMS_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Helper function to handle optional pubkey (NUMS if None)
fn optional_key(key: Option<XOnlyPublicKey>) -> XOnlyPublicKey {
    key.unwrap_or_else(|| XOnlyPublicKey::from_slice(&NUMS_KEY).expect("Valid NUMS key"))
}

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
    pub ctv_hash: [u8; 32],  // Fixed-size array with auto-validation
    pub out_i: i64,
}

#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = VaultParams)]
pub struct TriggerAndRevaultArgs {
    #[signer(|p| p.unvault_pk.serialize())]
    pub sig: Vec<u8>,
    pub ctv_hash: [u8; 32],  // Fixed-size array with auto-validation
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

#[derive(Contract)]
pub struct Vault {
    pub params: VaultParams,
    pub contract: StandardP2TR<VaultParams>,
    pub taptree: Arc<TapTree>,
    pub clauses: HashMap<String, Arc<dyn ErasedClause>>,
}

impl Vault {
    pub fn new(params: VaultParams) -> Self {
        let internal_key = optional_key(params.alternate_pk);

        // Build scripts
        let trigger_script = Self::trigger_script(&params);
        let trigger_and_revault_script = Self::trigger_and_revault_script(&params);
        let recover_script = Self::recover_script(&params);

        // Create clauses - explicitly cast to Arc<dyn ErasedClause>
        let trigger: Arc<dyn ErasedClause> = clause!(
            "trigger",
            TriggerArgs,
            trigger_script,
            &params,  // Auto-calls TriggerArgs::arg_specs_for_params(&params)
            |p: &VaultParams, args: &TriggerArgs, _s: Option<&()>| {
                Vault::new(p.clone()).trigger_outputs(args.ctv_hash, args.out_i as i32)
            }
        );

        let trigger_and_revault: Arc<dyn ErasedClause> = clause!(
            "trigger_and_revault",
            TriggerAndRevaultArgs,
            trigger_and_revault_script,
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
            recover_script,
            |p: &VaultParams, _args: &RecoverArgs, _s: Option<&()>| {
                Vault::new(p.clone()).recover_outputs()
            }
        );

        // Build taptree with macro - returns (Arc<TapTree>, HashMap<String, Arc<dyn ErasedClause>>)
        let (taptree, clauses) = taptree![
            trigger,
            [trigger_and_revault, recover]
        ];

        // Build contract
        let clause_vec: Vec<Arc<dyn ErasedClause>> = clauses.values().cloned().collect();
        let contract = StandardP2TR::new(internal_key, taptree.clone(), clause_vec);

        Self {
            params,
            contract,
            taptree,
            clauses,
        }
    }

    fn trigger_script(params: &VaultParams) -> ScriptBuf {
        let unvaulting_params = UnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        };
        let unvaulting_taptree_root = Unvaulting::build_taptree(&unvaulting_params).root_hash();

        script! {
            { crate::optional_key(params.alternate_pk) }
            { unvaulting_taptree_root }
            0
            CHECKCONTRACTVERIFY
            { params.unvault_pk }
            CHECKSIG
        }
    }

    fn trigger_and_revault_script(params: &VaultParams) -> ScriptBuf {
        let unvaulting_params = UnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        };
        let unvaulting_taptree_root = Unvaulting::build_taptree(&unvaulting_params).root_hash();

        script! {
            0 OP_SWAP
            -1
            -1
            { crate::contracts::CCV_FLAG_DEDUCT_OUTPUT_AMOUNT }
            CHECKCONTRACTVERIFY
            { crate::optional_key(params.alternate_pk) }
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

    /// Get the contract as a type-erased ErasedContract
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        Arc::new(self.contract.clone())
    }

    pub fn trigger_outputs(
        &self,
        ctv_hash: [u8; 32],
        out_i: i32,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let unvaulting_params = UnvaultingParams {
            alternate_pk: self.params.alternate_pk,
            spend_delay: self.params.spend_delay,
            recover_pk: self.params.recover_pk,
        };

        let unvaulting = Unvaulting::new(unvaulting_params.clone());
        let state = UnvaultingState { ctv_hash };

        Ok(vec![
            ClauseOutput::at(out_i)
                .to_with_params(unvaulting.as_erased(state.clone()), &unvaulting_params)
                .with_state(&state)
                .preserve_amount()
                .build()
        ])
    }

    pub fn trigger_and_revault_outputs(
        &self,
        ctv_hash: [u8; 32],
        out_i: i32,
        revault_out_i: i32,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let unvaulting_params = UnvaultingParams {
            alternate_pk: self.params.alternate_pk,
            spend_delay: self.params.spend_delay,
            recover_pk: self.params.recover_pk,
        };

        let unvaulting = Unvaulting::new(unvaulting_params.clone());
        let state = UnvaultingState { ctv_hash };

        Ok(vec![
            ClauseOutput::at(revault_out_i)
                .to(Arc::new(Vault::new(self.params.clone()).contract))
                .deduct_amount()
                .build(),
            ClauseOutput::at(out_i)
                .to_with_params(unvaulting.as_erased(state.clone()), &unvaulting_params)
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
    pub ctv_hash: [u8; 32],  // Fixed-size array
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

    pub fn build_taptree(params: &UnvaultingParams) -> Arc<TapTree> {
        let withdraw_script = Self::withdraw_script(params);
        let recover_script = Self::recover_script(params);

        let withdraw: Arc<dyn ErasedClause> = clause!(
            "withdraw",
            WithdrawArgs,
            withdraw_script;
            UnvaultingParams,
            UnvaultingState
        );

        let recover: Arc<dyn ErasedClause> = clause!(
            "recover",
            UnvaultingRecoverArgs,
            recover_script;
            UnvaultingParams,
            UnvaultingState
        );

        let (taptree, _clauses) = taptree![withdraw, recover];
        taptree
    }

    fn withdraw_script(params: &UnvaultingParams) -> ScriptBuf {
        script! {
            DUP
            -1
            { crate::optional_key(params.alternate_pk) }
            -1
            { crate::contracts::CCV_FLAG_CHECK_INPUT }
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

    pub fn as_erased(&self, _state: UnvaultingState) -> Arc<dyn ErasedContract> {
        let naked_key = optional_key(self.params.alternate_pk);
        let taptree = Self::build_taptree(&self.params);

        let withdraw: Arc<dyn ErasedClause> = clause!(
            "withdraw",
            WithdrawArgs,
            Self::withdraw_script(&self.params);
            UnvaultingParams,
            UnvaultingState
        );

        let recover: Arc<dyn ErasedClause> = clause!(
            "recover",
            UnvaultingRecoverArgs,
            Self::recover_script(&self.params);
            UnvaultingParams,
            UnvaultingState
        );

        let clauses = vec![withdraw, recover];

        Arc::new(
            StandardAugmentedP2TR::<UnvaultingParams, UnvaultingState>::new(
                naked_key, taptree, clauses,
            ),
        )
    }

    pub fn withdraw_outputs(&self, _ctv_hash: [u8; 32]) -> Result<Vec<ClauseOutput>, ClauseError> {
        Ok(ClauseOutput::terminal())
    }

    pub fn recover_outputs(&self) -> Result<Vec<ClauseOutput>, ClauseError> {
        Ok(ClauseOutput::terminal())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_creation() {
        let params = VaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap(),
            unvault_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
        };

        let vault = Vault::new(params);
        let _contract = vault.as_erased();
    }
}
