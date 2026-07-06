//! MiniVault: a stripped-down vault using only `OP_CHECKCONTRACTVERIFY` (no
//! `OP_CTV`), with individually toggleable clauses.
//!
//! The full [vault](../../examples/vault/contracts.rs) commits the withdrawal
//! outputs with a CTV template; the minivault instead commits a single
//! *withdrawal key* as the Unvaulting state, and its `withdraw` clause pays that
//! key via CCV after the delay. Two features are chosen at construction time:
//!
//! - `has_partial_revault` adds the `trigger_and_revault` clause (partial
//!   withdrawals that send the remainder back into a new MiniVault),
//! - `has_early_recover` adds the `recover` clause to the vault state itself
//!   (immediate recovery without triggering first).
//!
//! Because the clause set — and therefore the taptree shape — depends on runtime
//! params, `MiniVault` cannot use the `contract!` DSL's static `tree [..]`. It is
//! the worked example of the runtime escape hatch instead: [`StandardClause`]s
//! assembled into a [`ClauseTree`] by hand, exactly like [`mattrs::fraud`]. The
//! fixed-shape `MiniUnvaulting` stays in the DSL.
//!
//! ```text
//! MiniVault{alternate_pk?, spend_delay, recover_pk, unvault_pk, features..}
//!   - trigger(sig, withdrawal_pk, out_i)       => MiniUnvaulting[withdrawal_pk]
//!   - trigger_and_revault(sig, withdrawal_pk,
//!             out_i, revault_out_i)  [optional] => MiniVault (deduct)
//!                                                 + MiniUnvaulting[withdrawal_pk]
//!   - recover(out_i)                 [optional] => recover_pk          (terminal)
//!
//! MiniUnvaulting{alternate_pk?, spend_delay, recover_pk}[withdrawal_pk]
//!   - withdraw(withdrawal_pk), after spend_delay => withdrawal_pk      (terminal)
//!   - recover(out_i)                             => recover_pk         (terminal)
//! ```

use std::sync::Arc;

use bitcoin::{Amount, ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{
    ClauseArgs as _, ClauseOutput, ClauseTree, ErasedClause, ErasedContract, NextOutputs,
    NextOutputsFn, StandardClause, StandardP2TR, CCV_FLAG_CHECK_INPUT,
    CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
};
use mattrs::manager::{
    ContractManager, InstanceHandle, ManagerError, SpendBuilder, WrongContractType,
};
use mattrs::{contract, internal_key_or_nums, optional_key_script, Signature};
use mattrs_derive::{ClauseArgs, ContractParams, ContractState};

define_pushable!();

// ============================================================================
// MiniUnvaulting — fixed clause set, so the contract! DSL applies
// ============================================================================

#[derive(Debug, Clone, ContractParams)]
pub struct MiniUnvaultingParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
}

#[derive(Debug, Clone, ContractState)]
pub struct MiniUnvaultingState {
    pub withdrawal_pk: [u8; 32],
}

contract! {
    contract MiniUnvaulting {
        params MiniUnvaultingParams;
        state MiniUnvaultingState;
        internal_key |p| internal_key_or_nums(p.alternate_pk);

        // witness: <withdrawal_pk> — terminal (pays the committed key after the delay)
        clause withdraw {
            args {
                withdrawal_pk: [u8; 32],
            }
            script MiniUnvaulting::withdraw_script;
        }

        // witness: <out_i> — terminal (spends to recover_pk)
        clause recover {
            args {
                out_i: i64,
            }
            script MiniUnvaulting::recover_script;
        }

        tree [withdraw, recover];
    }
}

impl MiniUnvaulting {
    // Prove the committed withdrawal key, wait out the delay, then constrain
    // output 0 to pay that key (empty data, no taptweak). The DUPed key is left
    // on the stack as the truthy result.
    fn withdraw_script(params: &MiniUnvaultingParams) -> ScriptBuf {
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
            0
            0
            2 OP_PICK
            0
            0
            CHECKCONTRACTVERIFY
        }
    }

    fn recover_script(params: &MiniUnvaultingParams) -> ScriptBuf {
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
}

// ============================================================================
// MiniVault — runtime-shaped clause set, assembled without the DSL
// ============================================================================

#[derive(Debug, Clone, ContractParams)]
pub struct MiniVaultParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
    pub unvault_pk: XOnlyPublicKey,
    pub has_partial_revault: bool,
    pub has_early_recover: bool,
}

// witness: <sig> <withdrawal-pk> <out_i>
#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = MiniVaultParams)]
pub struct MiniVaultTriggerArgs {
    #[signer(|p| p.unvault_pk.serialize())]
    pub sig: Signature,
    pub withdrawal_pk: [u8; 32],
    pub out_i: i64,
}

// witness: <sig> <withdrawal-pk> <out_i> <revault_out_i>
#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = MiniVaultParams)]
pub struct MiniVaultTriggerAndRevaultArgs {
    #[signer(|p| p.unvault_pk.serialize())]
    pub sig: Signature,
    pub withdrawal_pk: [u8; 32],
    pub out_i: i64,
    pub revault_out_i: i64,
}

// witness: <out_i>
#[derive(Debug, Clone, ClauseArgs)]
#[clause_args(params = MiniVaultParams)]
pub struct MiniVaultRecoverArgs {
    pub out_i: i64,
}

/// The vault stage. Its clause set (and so its taptree shape and address)
/// depends on the two feature flags in the params.
pub struct MiniVault {
    pub params: MiniVaultParams,
    pub contract: StandardP2TR<MiniVaultParams>,
}

impl MiniVault {
    /// The MiniUnvaulting params derived from this vault's params.
    fn unvaulting_params(params: &MiniVaultParams) -> MiniUnvaultingParams {
        MiniUnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        }
    }

    pub fn new(params: MiniVaultParams) -> Self {
        let unvaulting_root =
            MiniUnvaulting::new(Self::unvaulting_params(&params)).taptree_root();

        let next_trigger: NextOutputsFn<MiniVaultParams, (), MiniVaultTriggerArgs> =
            Arc::new(|p, a, _s| {
                let unvaulting = MiniUnvaulting::new(MiniVault::unvaulting_params(p));
                Ok(NextOutputs::Contracts(vec![ClauseOutput::at(a.out_i as u32)
                    .to(unvaulting.as_erased())
                    .with_state(&MiniUnvaultingState {
                        withdrawal_pk: a.withdrawal_pk,
                    })
                    .preserve_amount()
                    .build()]))
            });
        let trigger: Arc<dyn ErasedClause> = Arc::new(StandardClause::new(
            "trigger".to_string(),
            Self::trigger_script(&params, unvaulting_root),
            MiniVaultTriggerArgs::arg_specs_for_params(&params),
            Some(next_trigger),
        ));

        let next_tar: NextOutputsFn<MiniVaultParams, (), MiniVaultTriggerAndRevaultArgs> =
            Arc::new(|p, a, _s| {
                let unvaulting = MiniUnvaulting::new(MiniVault::unvaulting_params(p));
                Ok(NextOutputs::Contracts(vec![
                    ClauseOutput::at(a.revault_out_i as u32)
                        .to(MiniVault::new(p.clone()).as_erased())
                        .deduct_amount()
                        .build(),
                    ClauseOutput::at(a.out_i as u32)
                        .to(unvaulting.as_erased())
                        .with_state(&MiniUnvaultingState {
                            withdrawal_pk: a.withdrawal_pk,
                        })
                        .preserve_amount()
                        .build(),
                ]))
            });
        let trigger_and_revault: Arc<dyn ErasedClause> = Arc::new(StandardClause::new(
            "trigger_and_revault".to_string(),
            Self::trigger_and_revault_script(&params, unvaulting_root),
            MiniVaultTriggerAndRevaultArgs::arg_specs_for_params(&params),
            Some(next_tar),
        ));

        let recover: Arc<dyn ErasedClause> = Arc::new(StandardClause::<
            MiniVaultParams,
            (),
            MiniVaultRecoverArgs,
        >::new(
            "recover".to_string(),
            Self::recover_script(&params),
            MiniVaultRecoverArgs::arg_specs_for_params(&params),
            None,
        ));

        // The runtime-shaped taptree: which clauses exist — and where they sit —
        // follows from the feature flags.
        let tree = match (params.has_partial_revault, params.has_early_recover) {
            (true, true) => ClauseTree::branch(
                ClauseTree::leaf(trigger),
                ClauseTree::branch(
                    ClauseTree::leaf(trigger_and_revault),
                    ClauseTree::leaf(recover),
                ),
            ),
            (true, false) => ClauseTree::branch(
                ClauseTree::leaf(trigger),
                ClauseTree::leaf(trigger_and_revault),
            ),
            (false, true) => {
                ClauseTree::branch(ClauseTree::leaf(trigger), ClauseTree::leaf(recover))
            }
            (false, false) => ClauseTree::leaf(trigger),
        };

        let contract = StandardP2TR::new(
            "MiniVault",
            internal_key_or_nums(params.alternate_pk),
            &params,
            tree,
        );
        Self { params, contract }
    }

    /// The contract as a type-erased `ErasedContract`.
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        Arc::new(self.contract.clone())
    }

    /// The merkle root of the contract's script taptree.
    pub fn taptree_root(&self) -> [u8; 32] {
        self.contract.taptree().root_hash()
    }

    /// Fund a new on-chain instance of this contract, returning its typed handle.
    pub fn fund(
        &self,
        manager: &mut ContractManager,
        amount: Amount,
    ) -> Result<MiniVaultHandle, ManagerError> {
        let handle = manager.fund_instance(self.as_erased(), None, amount)?;
        Ok(MiniVaultHandle(handle))
    }

    fn trigger_script(params: &MiniVaultParams, unvaulting_root: [u8; 32]) -> ScriptBuf {
        script! {
            { optional_key_script(params.alternate_pk) }
            { unvaulting_root }
            0
            CHECKCONTRACTVERIFY
            { params.unvault_pk }
            CHECKSIG
        }
    }

    fn trigger_and_revault_script(
        params: &MiniVaultParams,
        unvaulting_root: [u8; 32],
    ) -> ScriptBuf {
        script! {
            0 OP_SWAP
            -1
            -1
            { CCV_FLAG_DEDUCT_OUTPUT_AMOUNT }
            CHECKCONTRACTVERIFY
            { optional_key_script(params.alternate_pk) }
            { unvaulting_root }
            0
            CHECKCONTRACTVERIFY
            { params.unvault_pk }
            CHECKSIG
        }
    }

    fn recover_script(params: &MiniVaultParams) -> ScriptBuf {
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
}

/// Typed handle to a funded [`MiniVault`] instance. Hand-written (the DSL only
/// generates handles for static clause sets); spending a clause the instance's
/// feature flags exclude fails at spend time with an unknown-clause error.
#[derive(Clone)]
pub struct MiniVaultHandle(InstanceHandle);

impl MiniVaultHandle {
    /// The underlying generic instance handle.
    pub fn handle(&self) -> &InstanceHandle {
        &self.0
    }

    /// Move the funds to a MiniUnvaulting committing `withdrawal_pk`, at output
    /// `out_i`.
    pub fn trigger(&self, withdrawal_pk: [u8; 32], out_i: i64) -> SpendBuilder {
        let args = MiniVaultTriggerArgs::new(withdrawal_pk, out_i);
        self.0
            .spend_clause("trigger", args.encode_to_witness())
    }

    /// Partial withdrawal: deduct output `revault_out_i` back into a new
    /// MiniVault, the rest to a MiniUnvaulting at `out_i`.
    pub fn trigger_and_revault(
        &self,
        withdrawal_pk: [u8; 32],
        out_i: i64,
        revault_out_i: i64,
    ) -> SpendBuilder {
        let args = MiniVaultTriggerAndRevaultArgs::new(withdrawal_pk, out_i, revault_out_i);
        self.0
            .spend_clause("trigger_and_revault", args.encode_to_witness())
    }

    /// Immediate recovery to the recovery key (requires `has_early_recover`).
    pub fn recover(&self, out_i: i64) -> SpendBuilder {
        let args = MiniVaultRecoverArgs::new(out_i);
        self.0
            .spend_clause("recover", args.encode_to_witness())
    }
}

impl TryFrom<InstanceHandle> for MiniVaultHandle {
    type Error = WrongContractType;

    fn try_from(handle: InstanceHandle) -> Result<Self, Self::Error> {
        if handle.contract_type_id()
            == std::any::TypeId::of::<StandardP2TR<MiniVaultParams>>()
        {
            Ok(MiniVaultHandle(handle))
        } else {
            Err(WrongContractType {
                expected: "MiniVault",
            })
        }
    }
}
