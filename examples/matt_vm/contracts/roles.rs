//! The MATT-VM parties as protocol [`Role`]s, with the bisection fraud proof
//! mounted via [`Role::embed`] — the same shape as the game256 roles: the VM
//! code below never names a `Bisect` state.

use bitcoin::ScriptBuf;
use bitcoin::bip32::Xpriv;

use mattrs::fraud::roles::{
    FraudOutcome, FraudPartyData, alice_role as fraud_alice_role, bob_role as fraud_bob_role, pot,
};
use mattrs::fraud::trace;
use mattrs::protocol::{Action, ProtocolError, Role};
use mattrs::signer::HotSigner;

use super::computer::off_chain_computer;
use super::stages::{FORFAIT_TIMEOUT, VmS0, VmS0Handle, VmS1, VmS1Clause, VmS1Handle};
use super::vm::{VmSpec, VmTrace, state_commit};

/// How the game ended, from one party's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmOutcome {
    /// Nobody disputed Alice's claim; she withdrew the pot after the timeout.
    AliceWithdrew,
    /// Bob found Alice's claimed final state correct and walked away.
    AliceHonest,
    /// The claim was disputed and the fraud proof resolved it.
    Fraud(FraudOutcome),
}

/// Alice's (the prover's) private data: her claimed trace — honest or not.
pub struct AliceVmData {
    pub trace: VmTrace,
    pub fraud: FraudPartyData,
    pub xpriv: Xpriv,
}

/// Bob's (the verifier's) private data: his honest trace of the same spec.
pub struct BobVmData {
    pub trace: VmTrace,
    pub fraud: FraudPartyData,
    pub xpriv: Xpriv,
}

/// A party's fraud-proof view of its claimed trace. Unlike game256 there is
/// no on-chain input to wait for — the computation is fixed by the spec — so
/// the trace is filled in upfront.
pub fn vm_fraud_data(
    spec: &VmSpec,
    trace: &VmTrace,
    xpriv: Xpriv,
    payout: ScriptBuf,
) -> FraudPartyData {
    FraudPartyData {
        hs: trace.hs.clone(),
        xs: trace.xs.clone(),
        computer: off_chain_computer(spec),
        xpriv,
        payout,
        forfait_timeout: FORFAIT_TIMEOUT,
    }
}

/// The party's commitment to its whole claimed trace (`t` in the stage
/// contracts).
fn full_trace_commitment(d: &FraudPartyData) -> Result<[u8; 32], ProtocolError> {
    let n = d.hs.len() - 1;
    trace(&d.hs, 0, n - 1).map_err(|error| ProtocolError::Other(error.to_string()))
}

/// Alice: post the claim, withdraw after the timeout unless challenged — and
/// defend through the mounted fraud-proof role if she is.
pub fn alice_vm_role() -> Role<AliceVmData, VmOutcome> {
    Role::new()
        .on::<VmS0, _>(|d: &mut AliceVmData, h: VmS0Handle, _cx| {
            let t_a = full_trace_commitment(&d.fraud)?;
            let (y, pc_a, m_a) = d.trace.claim();
            let builder = h.claim(t_a, y, pc_a, m_a).sign(HotSigner::new(d.xpriv));
            Ok(Action::Send(builder))
        })
        .on::<VmS1, _>(|d, h: VmS1Handle, _cx| {
            let builder = h
                .withdraw()
                .outputs(pot(h.handle(), &d.fraud.payout)?)
                .sign(HotSigner::new(d.xpriv));
            Ok(Action::wait_or_send_final(
                FORFAIT_TIMEOUT,
                builder,
                VmOutcome::AliceWithdrew,
            ))
        })
        .embed(
            fraud_alice_role(),
            |d: &mut AliceVmData| &mut d.fraud,
            |_d, outcome| Ok(VmOutcome::Fraud(outcome)),
        )
}

/// Bob: check Alice's claimed final state — walk away if it matches his own
/// trace, otherwise challenge and dispute through the mounted fraud-proof
/// role.
pub fn bob_vm_role() -> Role<BobVmData, VmOutcome> {
    Role::new()
        .on::<VmS0, _>(|_d: &mut BobVmData, _h: VmS0Handle, _cx| Ok(Action::Wait))
        .on::<VmS1, _>(|d, h: VmS1Handle, _cx| {
            let s = h
                .state()
                .ok_or_else(|| ProtocolError::Other("VmS1 carries Alice's claim".into()))?;
            let (z, pc_b, m_b) = d.trace.claim();
            // Compare the full end states, not just the result: a claim with
            // the right accumulator but a wrong memory root is still fraud.
            if state_commit(s.pc_a, s.y, &s.m_a) == state_commit(pc_b, z, &m_b) {
                return Ok(Action::Finish(VmOutcome::AliceHonest));
            }
            let t_b = full_trace_commitment(&d.fraud)?;
            let builder = h.challenge(z, pc_b, m_b, t_b)?.sign(HotSigner::new(d.xpriv));
            Ok(Action::Send(builder))
        })
        .on_settled::<VmS1, _>(|_d, h: VmS1Handle, _cx| match h.spent_clause() {
            Some(VmS1Clause::Withdraw) => Ok(VmOutcome::AliceWithdrew),
            other => Err(ProtocolError::Other(format!(
                "unexpected terminal clause {other:?} on VmS1"
            ))),
        })
        .embed(
            fraud_bob_role(),
            |d: &mut BobVmData| &mut d.fraud,
            |_d, outcome| Ok(VmOutcome::Fraud(outcome)),
        )
}
