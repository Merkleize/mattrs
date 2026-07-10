//! The game256 parties as protocol [`Role`]s, with the bisection fraud proof
//! mounted as a component.
//!
//! The game roles only handle the three top-level stages (`G256S0`/`S1`/`S2`);
//! everything from the challenge on — turn order, midstate reveals, dispute
//! routing, forfait timeouts, the on-chain re-run of the disputed step — comes
//! from [`mattrs::fraud::roles`] via [`Role::embed`]. The game code never
//! mentions a `Bisect` state: it sees the sub-protocol only as
//! [`GameOutcome::Fraud`].

use std::rc::Rc;

use bitcoin::bip32::Xpriv;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::ScriptBuf;

use mattrs::fraud::roles::{
    alice_role as fraud_alice_role, bob_role as fraud_bob_role, pot, FraudOutcome, FraudPartyData,
    OffChainComputer,
};
use mattrs::fraud::trace;
use mattrs::protocol::{Action, ProtocolError, Role};
use mattrs::script_utils::{bn2vch, commit_int, vch2bn};
use mattrs::signer::HotSigner;

use super::game256::{
    G256S0, G256S0Handle, G256S1, G256S1Handle, G256S2, G256S2Clause, G256S2Handle,
    FORFAIT_TIMEOUT,
};

/// How the game ended, from one party's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GameOutcome {
    /// Nobody challenged Alice's claim; she withdrew the pot after the timeout.
    AliceWithdrew,
    /// Bob checked Alice's claimed result, found it correct, and walked away.
    AliceHonest,
    /// The claim was disputed and the fraud proof resolved it.
    Fraud(FraudOutcome),
}

/// Alice's private data: how she claims the computation went, and her
/// fraud-proof view (whose `hs`/`xs` are filled in once Bob's chosen input is
/// known on-chain).
pub struct AliceGameData {
    /// Alice's claimed step values for a given input `x` (the tests inject the
    /// fraudulent claim here).
    pub claim: Box<dyn Fn(i64) -> Vec<i64>>,
    pub fraud: FraudPartyData,
    pub xpriv: Xpriv,
}

/// Bob's private data: his chosen input and his (honest) fraud-proof view.
pub struct BobGameData {
    /// The input Bob picks at `G256S0`.
    pub x: i64,
    /// Bob's own step values (honest doubling from `x`).
    pub vals: Vec<i64>,
    pub fraud: FraudPartyData,
    pub xpriv: Xpriv,
}

/// The off-chain mirror of [`compute2x`](super::game256::compute2x):
/// `f(x) = 2x`, values committed as `sha256(bn(x))`.
pub fn off_chain_compute2x() -> OffChainComputer {
    OffChainComputer {
        func: Rc::new(|x| {
            let v = vch2bn(&x[0]).expect("a step value is a valid script number");
            vec![bn2vch(2 * v)]
        }),
        encode: Rc::new(|x| sha256::Hash::hash(&x[0]).to_byte_array()),
    }
}

/// A [`FraudPartyData`] for game256 with an empty (fill-in-later) trace.
pub fn game_fraud_data(xpriv: Xpriv, payout: ScriptBuf) -> FraudPartyData {
    FraudPartyData {
        hs: Vec::new(),
        xs: Vec::new(),
        computer: off_chain_compute2x(),
        xpriv,
        payout,
        forfait_timeout: FORFAIT_TIMEOUT,
    }
}

/// Fill a party's fraud-proof view from its claimed step values.
pub fn fill_fraud_data(fraud: &mut FraudPartyData, vals: &[i64]) {
    fraud.hs = vals.iter().map(|&v| commit_int(v)).collect();
    fraud.xs = vals[..vals.len() - 1]
        .iter()
        .map(|&v| vec![bn2vch(v)])
        .collect();
}

/// The honest 8-step doubling trace from `x` (9 values).
pub fn honest_vals(x: i64) -> Vec<i64> {
    let mut vals = vec![x];
    for _ in 0..8 {
        vals.push(vals.last().unwrap() * 2);
    }
    vals
}

/// The reference fraud scenario (pymatt's `test_fraud_proof_full`): honest
/// doubling gone wrong at step 5 (`64 -> 127` instead of `128`), doubled
/// consistently from there.
pub fn cheating_vals(x: i64) -> Vec<i64> {
    let mut vals = honest_vals(x);
    vals[6] -= 1;
    for k in 7..vals.len() {
        vals[k] = vals[k - 1] * 2;
    }
    vals
}

/// Alice: wait for Bob's input, reveal her claimed result, withdraw after the
/// timeout unless challenged — and, if challenged, defend through the mounted
/// fraud-proof role.
pub fn alice_game_role() -> Role<AliceGameData, GameOutcome> {
    Role::new()
        .on::<G256S0, _>(|_d: &mut AliceGameData, _h: G256S0Handle, _cx| Ok(Action::Wait))
        .on::<G256S1, _>(|d, h: G256S1Handle, _cx| {
            let x = h
                .state()
                .ok_or_else(|| ProtocolError::Other("S1 carries Bob's chosen input".into()))?
                .x;
            let vals = (d.claim)(x);
            let n = vals.len() - 1;
            fill_fraud_data(&mut d.fraud, &vals);
            let t_a = trace(&d.fraud.hs, 0, n - 1);
            let builder = h
                .reveal(t_a, vals[n], vals[0])
                .sign(HotSigner::new(d.xpriv));
            Ok(Action::Send(builder))
        })
        .on::<G256S2, _>(|d, h: G256S2Handle, _cx| {
            let builder = h
                .withdraw()
                .outputs(pot(h.handle(), &d.fraud.payout)?)
                .sign(HotSigner::new(d.xpriv));
            Ok(Action::wait_or_send_final(
                FORFAIT_TIMEOUT,
                builder,
                GameOutcome::AliceWithdrew,
            ))
        })
        .embed(
            fraud_alice_role(),
            |d: &mut AliceGameData| &mut d.fraud,
            |_d, outcome| Ok(GameOutcome::Fraud(outcome)),
        )
}

/// Bob: pick the input, wait for Alice's claim, check it — walk away if it is
/// correct, otherwise challenge and dispute through the mounted fraud-proof
/// role.
pub fn bob_game_role() -> Role<BobGameData, GameOutcome> {
    Role::new()
        .on::<G256S0, _>(|d: &mut BobGameData, h: G256S0Handle, _cx| {
            Ok(Action::Send(
                h.choose(d.x).sign(HotSigner::new(d.xpriv)),
            ))
        })
        .on::<G256S1, _>(|_d, _h: G256S1Handle, _cx| Ok(Action::Wait))
        .on::<G256S2, _>(|d, h: G256S2Handle, _cx| {
            let s = h
                .state()
                .ok_or_else(|| ProtocolError::Other("S2 carries Alice's claim".into()))?;
            let n = d.vals.len() - 1;
            if s.y == d.vals[n] {
                // Alice's claim checks out: nothing to dispute.
                return Ok(Action::Finish(GameOutcome::AliceHonest));
            }
            let t_b = trace(&d.fraud.hs, 0, n - 1);
            let builder = h
                .start_challenge(s.t_a, s.y, s.x, d.vals[n], t_b)
                .sign(HotSigner::new(d.xpriv));
            Ok(Action::Send(builder))
        })
        .on_settled::<G256S2, _>(|_d, h: G256S2Handle, _cx| match h.spent_clause() {
            Some(G256S2Clause::Withdraw) => Ok(GameOutcome::AliceWithdrew),
            other => Err(ProtocolError::Other(format!(
                "unexpected terminal clause {:?} on G256S2",
                other
            ))),
        })
        .embed(
            fraud_bob_role(),
            |d: &mut BobGameData| &mut d.fraud,
            |_d, outcome| Ok(GameOutcome::Fraud(outcome)),
        )
}
