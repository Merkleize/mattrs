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
//! params, `MiniVault` is the worked example of the `contract!` DSL's dynamic
//! `tree |p| { .. }` form: the taptree is computed from the params with an
//! ordinary `match` over the feature flags, while everything else (clauses, the
//! typed handle, `TryFrom`) is generated as for any DSL contract. The fixed-shape
//! `MiniUnvaulting` uses the static `tree [..]`.
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

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs::contracts::{
    CCV_FLAG_CHECK_INPUT, CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, ClauseError, ClauseOutput,
};
use mattrs::{
    ContractParams, ContractState, Signature, clause_tree, contract, internal_key_or_nums,
    optional_key_script,
};

define_pushable!();

fn output_index(value: i64, name: &str) -> Result<u32, ClauseError> {
    u32::try_from(value)
        .map_err(|_| ClauseError::Other(format!("{name} must be between 0 and u32::MAX")))
}

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
// MiniVault — runtime-shaped clause set, via the DSL's dynamic `tree |p| {..}`
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

contract! {
    contract MiniVault {
        params MiniVaultParams;
        internal_key |p| internal_key_or_nums(p.alternate_pk);

        // witness: <sig> <withdrawal-pk> <out_i>
        clause trigger {
            args {
                #[signer(p.unvault_pk)]
                sig: Signature,
                withdrawal_pk: [u8; 32],
                out_i: i64,
            }
            script MiniVault::trigger_script;
            next(p, a) {
                let unvaulting = MiniUnvaulting::new(MiniVault::unvaulting_params(p))?;
                Ok(vec![ClauseOutput::at(output_index(a.out_i, "out_i")?)
                    .to(unvaulting.as_erased())
                    .with_state(&MiniUnvaultingState {
                        withdrawal_pk: a.withdrawal_pk,
                    })
                    .preserve_amount()
                    .build()])
            }
        }

        // witness: <sig> <withdrawal-pk> <out_i> <revault_out_i>
        clause trigger_and_revault {
            args {
                #[signer(p.unvault_pk)]
                sig: Signature,
                withdrawal_pk: [u8; 32],
                out_i: i64,
                revault_out_i: i64,
            }
            script MiniVault::trigger_and_revault_script;
            next(p, a) {
                let unvaulting = MiniUnvaulting::new(MiniVault::unvaulting_params(p))?;
                Ok(vec![
                    ClauseOutput::at(output_index(a.revault_out_i, "revault_out_i")?)
                        .to(MiniVault::new(p.clone())?.as_erased())
                        .deduct_amount()
                        .build(),
                    ClauseOutput::at(output_index(a.out_i, "out_i")?)
                        .to(unvaulting.as_erased())
                        .with_state(&MiniUnvaultingState {
                            withdrawal_pk: a.withdrawal_pk,
                        })
                        .preserve_amount()
                        .build(),
                ])
            }
        }

        // witness: <out_i> — terminal (immediate recovery to the recovery key)
        clause recover {
            args {
                out_i: i64,
            }
            script MiniVault::recover_script;
        }

        // The runtime-shaped taptree: which clauses exist — and where they sit —
        // follows from the feature flags. Spending a clause the instance's flags
        // exclude fails at spend time with an unknown-clause error.
        tree |p| {
            match (p.has_partial_revault, p.has_early_recover) {
                (true, true) => clause_tree![trigger, [trigger_and_revault, recover]],
                (true, false) => clause_tree![trigger, trigger_and_revault],
                (false, true) => clause_tree![trigger, recover],
                (false, false) => clause_tree![trigger],
            }
        };
    }
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

    fn trigger_script(params: &MiniVaultParams) -> ScriptBuf {
        let unvaulting_root = MiniUnvaulting::new(Self::unvaulting_params(params))
            .expect("MiniUnvaulting contract definition is valid")
            .taptree_root();
        script! {
            { optional_key_script(params.alternate_pk) }
            { unvaulting_root }
            0
            CHECKCONTRACTVERIFY
            { params.unvault_pk }
            CHECKSIG
        }
    }

    fn trigger_and_revault_script(params: &MiniVaultParams) -> ScriptBuf {
        let unvaulting_root = MiniUnvaulting::new(Self::unvaulting_params(params))
            .expect("MiniUnvaulting contract definition is valid")
            .taptree_root();
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
