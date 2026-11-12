//! Vault contract example.
//!
//! A two-stage vault with trigger and recovery mechanisms, written with the
//! `contract!` DSL exactly as a downstream user would write it against the public
//! `mattrs` API. Each contract's clauses, taptree, typed handle, and per-clause
//! spend methods are generated from one `contract!` block; the tapscripts stay as
//! ordinary, reviewable functions referenced by the DSL.
//!
//! ```text
//! Vault{alternate_pk?, spend_delay, recover_pk, unvault_pk}
//!   - trigger(sig, ctv_hash, out_i)          => Unvaulting[ctv_hash]
//!   - trigger_and_revault(sig, ctv_hash,
//!                         out_i, revault_i)  => Vault (deduct) + Unvaulting[ctv_hash]
//!   - recover(out_i)                         => recover_pk          (terminal)
//!
//! Unvaulting{alternate_pk?, spend_delay, recover_pk}[ctv_hash]
//!   - withdraw(), after spend_delay          => the CTV template    (terminal)
//!   - recover(out_i)                         => recover_pk          (terminal)
//! ```

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{ClauseError, ClauseOutput, PaymentOutput};
use mattrs::{
    ContractState, Signature, contract, contracts::CCV_FLAG_CHECK_INPUT,
    contracts::CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, internal_key_or_nums, optional_key_script,
};

define_pushable!();

fn output_index(value: i64, name: &str) -> Result<u32, ClauseError> {
    u32::try_from(value)
        .map_err(|_| ClauseError::Other(format!("{name} must be between 0 and u32::MAX")))
}

fn recovery_output(index: i64, key: XOnlyPublicKey) -> Result<PaymentOutput, ClauseError> {
    // CCV with empty data and taptree pays the output key without a tweak.
    let script = mattrs::script_helpers::opaque_p2tr(key);
    Ok(if index == -1 {
        PaymentOutput::at_same_index(script)
    } else {
        PaymentOutput::at(output_index(index, "out_i")?, script)
    })
}

// ============================================================================
// Vault Parameters & State
// ============================================================================

#[derive(Debug, Clone)]
pub struct VaultParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
    pub unvault_pk: XOnlyPublicKey,
}

#[derive(Debug, Clone)]
pub struct UnvaultingParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
}

#[derive(Debug, Clone, ContractState)]
#[commit(identity)]
pub struct UnvaultingState {
    pub ctv_hash: [u8; 32],
}

// ============================================================================
// Vault Contract
// ============================================================================

contract! {
    contract Vault {
        params VaultParams;
        validate |p| mattrs::BlockDelay::new(p.spend_delay).map(|_| ());
        internal_key |p| internal_key_or_nums(p.alternate_pk);

        // witness: <sig> <ctv-hash> <out_i>
        clause trigger {
            args {
                #[signer(p.unvault_pk)]
                sig: Signature,
                ctv_hash: [u8; 32],
                out_i: i64,
            }
            script Vault::trigger_script;
            next(p, a) {
                Vault::new(p.clone())?.trigger_outputs(
                    a.ctv_hash,
                    output_index(a.out_i, "out_i")?,
                )
            }
        }

        // witness: <sig> <ctv-hash> <out_i> <revault_out_i>
        clause trigger_and_revault {
            args {
                #[signer(p.unvault_pk)]
                sig: Signature,
                ctv_hash: [u8; 32],
                out_i: i64,
                revault_out_i: i64,
            }
            script Vault::trigger_and_revault_script;
            next(p, a) {
                Vault::new(p.clone())?.trigger_and_revault_outputs(
                    a.ctv_hash,
                    output_index(a.out_i, "out_i")?,
                    output_index(a.revault_out_i, "revault_out_i")?,
                )
            }
        }

        // witness: <out_i> — terminal (spends to recover_pk)
        clause recover {
            args {
                out_i: i64,
            }
            script Vault::recover_script;
            next(p, a) { recovery_output(a.out_i, p.recover_pk) }
        }

        tree [trigger, [trigger_and_revault, recover]];
    }
}

impl Vault {
    /// The Unvaulting params derived from this vault's params.
    fn unvaulting_params(params: &VaultParams) -> UnvaultingParams {
        UnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        }
    }

    pub fn trigger_outputs(
        &self,
        ctv_hash: [u8; 32],
        out_i: u32,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let params = self.params();
        let unvaulting = Unvaulting::new(Self::unvaulting_params(&params))?;
        let state = UnvaultingState { ctv_hash };

        Ok(vec![
            ClauseOutput::at(out_i)
                .to(unvaulting.as_erased())
                .with_state(&state)
                .preserve_amount()
                .build(),
        ])
    }

    pub fn trigger_and_revault_outputs(
        &self,
        ctv_hash: [u8; 32],
        out_i: u32,
        revault_out_i: u32,
    ) -> Result<Vec<ClauseOutput>, ClauseError> {
        let params = self.params();
        let unvaulting = Unvaulting::new(Self::unvaulting_params(&params))?;
        let state = UnvaultingState { ctv_hash };

        Ok(vec![
            ClauseOutput::at(revault_out_i)
                .to(Vault::new(params)?.as_erased())
                .deduct_amount()
                .build(),
            ClauseOutput::at(out_i)
                .to(unvaulting.as_erased())
                .with_state(&state)
                .preserve_amount()
                .build(),
        ])
    }

    fn trigger_script(params: &VaultParams) -> Result<ScriptBuf, mattrs::contracts::ContractError> {
        let unvaulting_taptree_root =
            Unvaulting::new(Self::unvaulting_params(params))?.taptree_root();

        Ok(script! {
            { optional_key_script(params.alternate_pk) }
            { unvaulting_taptree_root }
            0
            CHECKCONTRACTVERIFY
            { params.unvault_pk }
            CHECKSIG
        })
    }

    fn trigger_and_revault_script(
        params: &VaultParams,
    ) -> Result<ScriptBuf, mattrs::contracts::ContractError> {
        let unvaulting_taptree_root =
            Unvaulting::new(Self::unvaulting_params(params))?.taptree_root();

        Ok(script! {
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
        })
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
}

// ============================================================================
// Unvaulting Contract (Augmented with State)
// ============================================================================

contract! {
    contract Unvaulting {
        params UnvaultingParams;
        state UnvaultingState;
        internal_key |p| internal_key_or_nums(p.alternate_pk);

        // witness: <ctv_hash> — terminal (CTV withdraw)
        clause withdraw {
            args {
                #[from_state]
                ctv_hash: [u8; 32],
            }
            timelock |p| p.spend_delay;
            script Unvaulting::withdraw_script;
            next(_p, a, s) {
                if a.ctv_hash != s.ctv_hash {
                    return Err(ClauseError::Other("withdrawal hash does not match committed state".into()));
                }
                Ok(mattrs::contracts::NextOutputs::TemplateHash(s.ctv_hash))
            }
        }

        // witness: <out_i> — terminal (spends to recover_pk)
        clause recover {
            args {
                out_i: i64,
            }
            script Unvaulting::recover_script;
            next(p, a) { recovery_output(a.out_i, p.recover_pk) }
        }

        tree [withdraw, recover];
    }
}

impl Unvaulting {
    fn withdraw_script(params: &UnvaultingParams) -> ScriptBuf {
        script! {
            DUP
            -1
            { optional_key_script(params.alternate_pk) }
            -1
            { CCV_FLAG_CHECK_INPUT }
            CHECKCONTRACTVERIFY
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
}
