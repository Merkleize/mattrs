//! The bisection packaged as a reusable protocol component: one
//! [`Role`] per party, driving [`Bisect1`]/[`Bisect2`]/[`Leaf`] from the
//! challenge to a [`FraudOutcome`].
//!
//! An embedding protocol mounts a party's role with
//! [`Role::embed`], mapping [`FraudOutcome`] into its own outcome
//! type, and hands the token off on-chain with
//! [`Bisect1::state_output_script`] / [`Bisect1::entry_output`]. It never
//! touches the bisection's internal states or turn order — see
//! `tests/support/game256_roles.rs` for a complete embedding.
//!
//! The roles implement the *honest* strategy over the party's claimed
//! computation trace ([`FraudPartyData`]): reveal your midstates when it is
//! your turn, recurse into the half you dispute, re-run the final step
//! on-chain when your claim survives it, and collect the pot via `forfait`
//! when the counterparty stalls past the timeout. A party whose claim is wrong
//! at the disputed step simply waits at the [`Leaf`] and loses the
//! adjudication (there is nothing better it can do).

use std::rc::Rc;

use bitcoin::bip32::Xpriv;
use bitcoin::{ScriptBuf, TxOut};

use crate::manager::{InstanceHandle, ManagerError, SpendBuilder};
use crate::protocol::{Action, ProtocolError, Role, StepCtx};
use crate::signer::HotSigner;

use super::{
    Bisect1, Bisect1Clause, Bisect1Handle, Bisect2, Bisect2Clause, Bisect2Handle, BisectParams,
    Leaf, LeafClause, LeafHandle, trace,
};

/// The party a fraud-proof outcome favors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FraudWinner {
    Alice,
    Bob,
}

/// How a fraud proof resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FraudResolution {
    /// The single disputed step was re-run on-chain by the winner's reveal.
    LeafAdjudicated {
        /// The step the dispute narrowed down to.
        step: i64,
    },
    /// The party holding the turn stalled past the timeout while the dispute
    /// covered the step range `[i, j]`.
    Forfait { i: i64, j: i64 },
}

/// The result of a fraud proof, as seen by either party.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FraudOutcome {
    pub winner: FraudWinner,
    pub resolution: FraudResolution,
}

/// A step value, as the witness elements one
/// [`Computer`](super::Computer) spec consumes.
pub type StepValue = Vec<Vec<u8>>;

/// The off-chain mirror of a [`Computer`](super::Computer)'s script fragments,
/// used by a role to derive its commitments and to decide whether its own
/// reveal wins the disputed step. Must agree with the on-chain fragments on
/// every protocol-valid value.
#[derive(Clone)]
#[allow(clippy::type_complexity)] // the closure signatures ARE the documentation
pub struct OffChainComputer {
    /// Maps a step value (its witness elements) to the next value —
    /// [`Computer::func`](super::Computer::func) off-chain.
    pub func: Rc<dyn Fn(&StepValue) -> StepValue>,
    /// Maps a step value to its commitment —
    /// [`Computer::encoder`](super::Computer::encoder) off-chain.
    pub encode: Rc<dyn Fn(&StepValue) -> [u8; 32]>,
}

/// One party's view of the disputed computation, plus its spending config.
///
/// `hs`/`xs` describe the party's *claimed* trace; an embedding protocol may
/// leave them empty at construction and fill them in once the computation's
/// input becomes known on-chain.
pub struct FraudPartyData {
    /// The claimed step commitments `h_0 ..= h_n` (`n + 1` entries).
    pub hs: Vec<[u8; 32]>,
    /// The claimed step values `x_0 .. x_{n-1}`.
    pub xs: Vec<StepValue>,
    /// The step function and commitment, off-chain.
    pub computer: OffChainComputer,
    /// This party's signing key.
    pub xpriv: Xpriv,
    /// Where this party's terminal wins pay.
    pub payout: ScriptBuf,
    /// The forfait timeout (blocks); must match the contracts'
    /// [`BisectCtx`](super::BisectCtx).
    pub forfait_timeout: u32,
}

impl FraudPartyData {
    /// Whether this party's claim survives re-running `step`: its claimed
    /// output commitment matches what its own claimed input actually computes
    /// to.
    fn honest_at(&self, step: i64) -> bool {
        let k = step as usize;
        if k >= self.xs.len() || k + 1 >= self.hs.len() {
            return false;
        }
        let y = (self.computer.func)(&self.xs[k]);
        (self.computer.encode)(&y) == self.hs[k + 1]
    }

    /// This party's reveal arguments for the range `[i, j]`: the midstate
    /// commitment and the two sub-traces backing it.
    fn reveal_args(&self, p: &BisectParams) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let (i, j, m) = (p.i as usize, p.j as usize, p.m() as usize);
        (
            self.hs[i + m],
            trace(&self.hs, i, i + m - 1),
            trace(&self.hs, i + m, j),
        )
    }
}

/// Alice's (the claimant's) role: reveal at [`Bisect1`], watch [`Bisect2`]
/// with a forfait fallback, re-run the disputed step at the [`Leaf`].
pub fn alice_role() -> Role<FraudPartyData, FraudOutcome> {
    with_settlements(
        Role::new()
            .on::<Bisect1, _>(|d: &mut FraudPartyData, h: Bisect1Handle, _cx| {
                let (h_mid, t_left, t_right) = d.reveal_args(&h.params());
                let builder = h
                    .alice_reveal(h_mid, t_left, t_right)?
                    .sign(HotSigner::new(d.xpriv));
                Ok(Action::Send(builder))
            })
            .on::<Bisect2, _>(|d, h: Bisect2Handle, _cx| {
                let p = h.params();
                wait_or_forfait(d, h.forfait(), h.handle(), FraudWinner::Alice, &p)
            })
            .on::<Leaf, _>(|d, h: LeafHandle, cx| {
                let step = leaf_step(cx)?;
                if d.honest_at(step) {
                    let builder = h.alice_reveal(d.xs[step as usize].clone())?;
                    Ok(win_leaf(d, builder, h.handle(), FraudWinner::Alice, step)?)
                } else {
                    // Our claim cannot survive this step; the counterparty's
                    // reveal will settle it.
                    Ok(Action::Wait)
                }
            }),
    )
}

/// Bob's (the challenger's) role: watch [`Bisect1`] with a forfait fallback,
/// recurse into the disputed half at [`Bisect2`], re-run the disputed step at
/// the [`Leaf`].
pub fn bob_role() -> Role<FraudPartyData, FraudOutcome> {
    with_settlements(
        Role::new()
            .on::<Bisect1, _>(|d: &mut FraudPartyData, h: Bisect1Handle, _cx| {
                let p = h.params();
                wait_or_forfait(d, h.forfait(), h.handle(), FraudWinner::Bob, &p)
            })
            .on::<Bisect2, _>(|d, h: Bisect2Handle, _cx| {
                let p = h.params();
                let state = h.state().ok_or_else(|| {
                    ProtocolError::Other("a Bisect2 instance carries its revealed state".into())
                })?;
                let (h_mid, t_left, t_right) = d.reveal_args(&p);
                // Recurse into the left half when the midstates differ, the right
                // when they agree (the same comparison the scripts enforce).
                let builder = if state.h_mid_a != h_mid {
                    h.bob_reveal_left(h_mid, t_left, t_right)?
                } else {
                    h.bob_reveal_right(h_mid, t_left, t_right)?
                };
                Ok(Action::Send(builder.sign(HotSigner::new(d.xpriv))))
            })
            .on::<Leaf, _>(|d, h: LeafHandle, cx| {
                let step = leaf_step(cx)?;
                if d.honest_at(step) {
                    let builder = h.bob_reveal(d.xs[step as usize].clone())?;
                    Ok(win_leaf(d, builder, h.handle(), FraudWinner::Bob, step)?)
                } else {
                    Ok(Action::Wait)
                }
            }),
    )
}

/// The settlement classifiers both parties share: the counterparty's terminal
/// reveal at a [`Leaf`], or its `forfait` collection on a stalled stage (a
/// stalled [`Bisect1`] was Alice's turn, so it forfaits to Bob — and the other
/// way around for [`Bisect2`]).
fn with_settlements(
    role: Role<FraudPartyData, FraudOutcome>,
) -> Role<FraudPartyData, FraudOutcome> {
    role.on_settled::<Leaf, _>(|_d, h: LeafHandle, cx| settled_leaf(&h, cx))
        .on_settled::<Bisect1, _>(|_d, h: Bisect1Handle, _cx| match h.spent_clause() {
            Some(Bisect1Clause::Forfait) => Ok(forfait_outcome(&h.params(), FraudWinner::Bob)),
            other => Err(unexpected_terminal(other, "Bisect1")),
        })
        .on_settled::<Bisect2, _>(|_d, h: Bisect2Handle, _cx| match h.spent_clause() {
            Some(Bisect2Clause::Forfait) => Ok(forfait_outcome(&h.params(), FraudWinner::Alice)),
            other => Err(unexpected_terminal(other, "Bisect2")),
        })
}

/// The step a [`Leaf`] adjudicates, derived from how the token got there: its
/// parent [`Bisect2`]'s range and which half Bob's reveal recursed into.
fn leaf_step(cx: &StepCtx<'_>) -> Result<i64, ProtocolError> {
    let parent = cx.parent.ok_or_else(|| {
        ProtocolError::Other("a Leaf arises from a Bisect2 reveal, not as an entry".into())
    })?;
    let b2: Bisect2Handle = parent.clone().try_into()?;
    let p = b2.params();
    match b2.spent_clause() {
        Some(Bisect2Clause::BobRevealLeft) => Ok(p.i),
        Some(Bisect2Clause::BobRevealRight) => Ok(p.i + p.m()),
        other => Err(ProtocolError::Other(format!(
            "unexpected clause {:?} produced a Leaf",
            other
        ))),
    }
}

/// The whole pot — the spent instance's full value — paid to this party's
/// payout script (zero fee, as everywhere in this crate's regtest flows).
/// Shared by any protocol whose terminal spends sweep the UTXO (the game256
/// roles use it too).
pub fn pot(handle: &InstanceHandle, payout: &ScriptBuf) -> Result<Vec<TxOut>, ProtocolError> {
    let prevout = handle.prevout().ok_or(ManagerError::NotFunded)?;
    Ok(vec![TxOut {
        script_pubkey: payout.clone(),
        value: prevout.value,
    }])
}

/// Wait for the counterparty's reveal; if it stalls past the timeout, collect
/// the pot through the stage's `forfait` clause.
fn wait_or_forfait(
    d: &FraudPartyData,
    forfait: SpendBuilder,
    handle: &InstanceHandle,
    winner: FraudWinner,
    p: &BisectParams,
) -> Result<Action<FraudOutcome>, ProtocolError> {
    let builder = forfait
        .outputs(pot(handle, &d.payout)?)
        .sign(HotSigner::new(d.xpriv));
    let outcome = FraudOutcome {
        winner,
        resolution: FraudResolution::Forfait { i: p.i, j: p.j },
    };
    // `wait_or_send_final` sets the builder's CSV sequence from the same
    // timeout that drives the deadline.
    Ok(Action::wait_or_send_final(
        d.forfait_timeout,
        builder,
        outcome,
    ))
}

/// Re-run the disputed step on-chain and take the pot.
fn win_leaf(
    d: &FraudPartyData,
    builder: SpendBuilder,
    handle: &InstanceHandle,
    winner: FraudWinner,
    step: i64,
) -> Result<Action<FraudOutcome>, ProtocolError> {
    let builder = builder
        .outputs(pot(handle, &d.payout)?)
        .sign(HotSigner::new(d.xpriv));
    let outcome = FraudOutcome {
        winner,
        resolution: FraudResolution::LeafAdjudicated { step },
    };
    Ok(Action::SendFinal(builder, outcome))
}

/// Classify the counterparty's terminal reveal of a [`Leaf`].
fn settled_leaf(h: &LeafHandle, cx: &StepCtx<'_>) -> Result<FraudOutcome, ProtocolError> {
    let winner = match h.spent_clause() {
        Some(LeafClause::AliceReveal) => FraudWinner::Alice,
        Some(LeafClause::BobReveal) => FraudWinner::Bob,
        other => return Err(unexpected_terminal(other, "Leaf")),
    };
    Ok(FraudOutcome {
        winner,
        resolution: FraudResolution::LeafAdjudicated {
            step: leaf_step(cx)?,
        },
    })
}

/// The outcome of a `forfait` collection on a stalled stage covering `[i, j]`.
fn forfait_outcome(p: &BisectParams, winner: FraudWinner) -> FraudOutcome {
    FraudOutcome {
        winner,
        resolution: FraudResolution::Forfait { i: p.i, j: p.j },
    }
}

fn unexpected_terminal(clause: impl std::fmt::Debug, contract: &str) -> ProtocolError {
    ProtocolError::Other(format!(
        "unexpected terminal clause {clause:?} on a {contract}"
    ))
}
