//! Roles for the two-stage vault (`support::vault`) — the *forking* protocol
//! demo: `trigger_and_revault` splits one vault UTXO into a revaulted `Vault`
//! child and an `Unvaulting` child, and a runner follows **both**, resolving
//! one [`VaultOutcome`] per branch.
//!
//! Two parties:
//! - the **owner** (holder of `unvault_pk`) works through a plan of triggers —
//!   a revaulted child re-arrives at `Vault` and consumes the next planned
//!   step, a data-driven self-loop — and withdraws each `Unvaulting` through
//!   its CTV template once the CSV delay matures;
//! - a **watchtower** knows the CTV hashes the owner sanctioned and sweeps any
//!   other unvaulting to the recovery address. The `recover` clause carries no
//!   signature check, so the watchtower holds no key at all.

use std::collections::{HashMap, HashSet};

use bitcoin::bip32::Xpriv;
use bitcoin::{Amount, Sequence, TxOut};
use mattrs::ctv::compute_ctv_hash;
use mattrs::manager::{InstanceHandle, ManagerError};
use mattrs::protocol::{Action, ProtocolError, Role, StepCtx};
use mattrs::script_helpers::opaque_p2tr;
use mattrs::signer::HotSigner;

use super::vault::{
    Unvaulting, UnvaultingClause, UnvaultingHandle, Vault, VaultClause, VaultHandle,
};

/// How one branch (token) of the vault protocol resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultOutcome {
    /// The unvaulting matured and was withdrawn through its CTV template.
    Withdrawn {
        /// The branch's UTXO value.
        amount: Amount,
    },
    /// The branch was swept to the recovery address.
    Recovered {
        /// The branch's UTXO value.
        amount: Amount,
    },
}

/// One planned trigger of a (possibly revaulted) vault UTXO.
pub struct TriggerStep {
    /// The CTV withdrawal committed to at trigger time (must total the amount
    /// being unvaulted — fees are zero by the regtest convention).
    pub outputs: Vec<TxOut>,
    /// `Some(amount)`: split first, keeping `amount` in a revaulted `Vault`
    /// child and unvaulting the remainder; `None`: unvault the whole UTXO.
    pub revault: Option<Amount>,
}

/// The vault owner's private data.
pub struct OwnerData {
    /// The key behind the vault's `unvault_pk`.
    pub xpriv: Xpriv,
    /// Planned triggers, consumed front to back — one per `Vault` arrival
    /// (with none left, the owner just holds the vault and watches).
    pub plan: Vec<TriggerStep>,
    /// CTV outputs committed by sent triggers, keyed by CTV hash: written by
    /// the `Vault` handler, consumed by the `Unvaulting` handler.
    withdrawals: HashMap<[u8; 32], Vec<TxOut>>,
}

impl OwnerData {
    pub fn new(xpriv: Xpriv, plan: Vec<TriggerStep>) -> Self {
        OwnerData {
            xpriv,
            plan,
            withdrawals: HashMap::new(),
        }
    }
}

/// The owner: trigger per plan, withdraw each unvaulting at CSV maturity.
pub fn owner_role() -> Role<OwnerData, VaultOutcome> {
    Role::new()
        .on::<Vault, _>(|d: &mut OwnerData, h: VaultHandle, _cx| {
            if d.plan.is_empty() {
                return Ok(Action::Wait);
            }
            let step = d.plan.remove(0);
            let p = h.params()?;
            let ctv_hash = compute_ctv_hash(&step.outputs, Sequence(p.spend_delay));
            d.withdrawals.insert(ctv_hash, step.outputs);
            let signer = HotSigner::new(d.xpriv);
            Ok(Action::Send(match step.revault {
                // Output 0 is the unvaulting, output 1 the revaulted remainder.
                Some(amount) => h
                    .trigger_and_revault(ctv_hash, 0, 1)
                    .output_amount(1, amount)
                    .sign(signer),
                None => h.trigger(ctv_hash, 0).sign(signer),
            }))
        })
        .on::<Unvaulting, _>(|d: &mut OwnerData, h: UnvaultingHandle, _cx| {
            let p = h.params()?;
            let state = h.state().ok_or_else(|| {
                ProtocolError::Other("an Unvaulting instance carries its CTV hash".into())
            })?;
            // Looked up, not consumed: two planned branches may commit to the
            // *same* template (equal outputs ⇒ equal CTV hash), and each must
            // still find its withdrawal here.
            let outputs = d.withdrawals.get(&state.ctv_hash).cloned().ok_or_else(|| {
                ProtocolError::Other("unvaulting with a CTV hash the owner never planned".into())
            })?;
            let amount = h.handle().prevout().ok_or(ManagerError::NotFunded)?.value;
            // Nobody should spend this branch before us; the CSV delay is what
            // gates the withdrawal, so it rides the timeout fallback (which
            // also sets the withdrawal's sequence to the same delay).
            Ok(Action::wait_or_send_final(
                p.spend_delay,
                h.withdraw(state.ctv_hash).outputs(outputs),
                VaultOutcome::Withdrawn { amount },
            ))
        })
        .on_settled::<Vault, _>(settled_vault)
        .on_settled::<Unvaulting, _>(settled_unvaulting)
}

/// The watchtower's private data.
pub struct WatchtowerData {
    /// The CTV hashes the owner is entitled to withdraw through.
    pub authorized: HashSet<[u8; 32]>,
}

/// The watchtower: watch every branch, sweep any unvaulting whose CTV hash the
/// owner never sanctioned.
pub fn watchtower_role() -> Role<WatchtowerData, VaultOutcome> {
    Role::new()
        .on::<Vault, _>(|_d: &mut WatchtowerData, _h: VaultHandle, _cx| Ok(Action::Wait))
        .on::<Unvaulting, _>(|d: &mut WatchtowerData, h: UnvaultingHandle, _cx| {
            let state = h.state().ok_or_else(|| {
                ProtocolError::Other("an Unvaulting instance carries its CTV hash".into())
            })?;
            if d.authorized.contains(&state.ctv_hash) {
                return Ok(Action::Wait);
            }
            let p = h.params()?;
            let amount = h.handle().prevout().ok_or(ManagerError::NotFunded)?.value;
            let sweep = TxOut {
                script_pubkey: opaque_p2tr(p.recover_pk),
                value: amount,
            };
            Ok(Action::SendFinal(
                h.recover(0).outputs(vec![sweep]),
                VaultOutcome::Recovered { amount },
            ))
        })
        .on_settled::<Vault, _>(settled_vault)
        .on_settled::<Unvaulting, _>(settled_unvaulting)
}

/// Classify someone else's terminal spend of a `Vault` (only `recover` is
/// terminal there — the trigger clauses produce children).
fn settled_vault(
    _d: &mut impl Sized,
    h: VaultHandle,
    _cx: &StepCtx<'_>,
) -> Result<VaultOutcome, ProtocolError> {
    let amount = branch_amount(h.handle())?;
    match h.spent_clause() {
        Some(VaultClause::Recover) => Ok(VaultOutcome::Recovered { amount }),
        other => Err(ProtocolError::Other(format!(
            "unexpected terminal clause {other:?} on a Vault"
        ))),
    }
}

/// Classify someone else's terminal spend of an `Unvaulting`.
fn settled_unvaulting(
    _d: &mut impl Sized,
    h: UnvaultingHandle,
    _cx: &StepCtx<'_>,
) -> Result<VaultOutcome, ProtocolError> {
    let amount = branch_amount(h.handle())?;
    match h.spent_clause() {
        Some(UnvaultingClause::Withdraw) => Ok(VaultOutcome::Withdrawn { amount }),
        Some(UnvaultingClause::Recover) => Ok(VaultOutcome::Recovered { amount }),
        other => Err(ProtocolError::Other(format!(
            "unexpected terminal clause {other:?} on an Unvaulting"
        ))),
    }
}

/// The branch's UTXO value.
fn branch_amount(handle: &InstanceHandle) -> Result<Amount, ProtocolError> {
    Ok(handle.prevout().ok_or(ManagerError::NotFunded)?.value)
}
