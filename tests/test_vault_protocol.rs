//! The vault protocol driven by multi-token [`Runner`]s: `trigger_and_revault`
//! forks one UTXO into a revaulted `Vault` child and an `Unvaulting` child,
//! and the runner follows both branches to their own outcomes.
//!
//! The offline tests run the roles from `support::vault_roles` over the
//! in-memory `LocalChain` (no scripts executed: they validate the protocol
//! logic — forking, turn order, CSV-deadline timing, settlement
//! classification). The `#[ignore]`d test replays the fork-and-withdraw
//! scenario against a regtest node, where CTV, CSV, and the CCV covenants are
//! enforced by the real script interpreter.

mod support;

use std::collections::HashSet;
use std::rc::Rc;
use std::time::Duration;

use bitcoin::{Amount, Sequence, TxOut};
use mattrs::ctv::compute_ctv_hash;
use mattrs::manager::ContractManager;
use mattrs::protocol::{Action, LocalChain, Progress, ProtocolError, Role, RpcChain, Runner};
use mattrs::script_helpers::opaque_p2tr;
use mattrs::signer::HotSigner;
use mattrs::testutil::fund_fake;

use support::testkit::{alice_pk, alice_xpriv, bob_pk, drive_both, offline_manager, regtest_client};
use support::vault::{Unvaulting, Vault, VaultHandle, VaultParams};
use support::vault_roles::{
    owner_role, watchtower_role, OwnerData, TriggerStep, VaultOutcome, WatchtowerData,
};

const AMOUNT: u64 = 100_000;
const SPEND_DELAY: u32 = 10;
const SEED: u8 = 51;

fn params() -> VaultParams {
    VaultParams {
        alternate_pk: None,
        spend_delay: SPEND_DELAY,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    }
}

fn fake_vault(seed: u8) -> mattrs::manager::InstanceHandle {
    fund_fake(
        Vault::new(params()).as_erased(),
        None,
        Amount::from_sat(AMOUNT),
        seed,
    )
}

/// A single-output CTV withdrawal template paying `amount` to the owner.
fn withdrawal(amount: Amount) -> Vec<TxOut> {
    vec![TxOut {
        script_pubkey: opaque_p2tr(alice_pk()),
        value: amount,
    }]
}

#[test]
fn revault_forks_and_both_branches_withdraw() {
    let chain = Rc::new(LocalChain::new());
    let revault = Amount::from_sat(30_000);
    let rest = Amount::from_sat(AMOUNT) - revault;

    // The owner's plan: split the vault (unvaulting 70k, revaulting 30k), then
    // unvault the revaulted remainder too, and withdraw both when they mature.
    let plan = vec![
        TriggerStep {
            outputs: withdrawal(rest),
            revault: Some(revault),
        },
        TriggerStep {
            outputs: withdrawal(revault),
            revault: None,
        },
    ];
    let entry = fake_vault(SEED);
    let mut owner = Runner::new(
        offline_manager(),
        chain.clone(),
        owner_role(),
        OwnerData::new(alice_xpriv(), plan),
        entry.clone(),
    );

    // The runner triggers both plan steps by itself: the first spend forks the
    // token (Unvaulting + revaulted Vault), the Vault child re-arrives and
    // triggers again. It then sits waiting out two CSV delays.
    loop {
        match owner.step().expect("owner steps") {
            Progress::Advanced => continue,
            Progress::Waiting => break,
            Progress::Done(_) => panic!("nothing can resolve before the CSV delay"),
        }
    }
    assert_eq!(owner.tokens().len(), 2, "the trigger_and_revault forked");
    assert!(owner.current().is_none(), "several tokens in flight");

    // Confirm the triggers and let both delays mature: the timeout fallbacks
    // fire and withdraw each branch through its CTV template.
    chain.mine(SPEND_DELAY + 1);
    let outcomes = owner.run().expect("owner resolves");
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.contains(&VaultOutcome::Withdrawn { amount: rest }));
    assert!(outcomes.contains(&VaultOutcome::Withdrawn { amount: revault }));

    // The recorded spend tree: entry --trigger_and_revault--> {Unvaulting(70k),
    // Vault(30k) --trigger--> Unvaulting(30k)}, both unvaultings withdrawn.
    assert_eq!(entry.clause_name().as_deref(), Some("trigger_and_revault"));
    let children = entry.outputs();
    assert_eq!(children.len(), 2);
    let big = children
        .iter()
        .find(|c| c.contract_name() == "Unvaulting")
        .expect("the unvaulting branch");
    assert_eq!(big.clause_name().as_deref(), Some("withdraw"));
    assert_eq!(big.spending_tx().expect("withdrawn").output, withdrawal(rest));
    let revaulted = children
        .iter()
        .find(|c| c.contract_name() == "Vault")
        .expect("the revaulted branch");
    assert_eq!(revaulted.clause_name().as_deref(), Some("trigger"));
    let mut grandchildren = revaulted.outputs();
    assert_eq!(grandchildren.len(), 1);
    let small = grandchildren.remove(0);
    assert_eq!(small.contract_name(), "Unvaulting");
    assert_eq!(small.clause_name().as_deref(), Some("withdraw"));
    assert_eq!(
        small.spending_tx().expect("withdrawn").output,
        withdrawal(revault)
    );
}

#[test]
fn identical_templates_on_both_branches_withdraw() {
    // A 50/50 split where both branches commit to the *same* withdrawal
    // template: the two unvaultings share one CTV hash, and each must still
    // find its outputs in the owner's plan (regression: the lookup used to
    // consume the entry, stranding the second branch).
    let chain = Rc::new(LocalChain::new());
    let half = Amount::from_sat(AMOUNT / 2);

    let plan = vec![
        TriggerStep {
            outputs: withdrawal(half),
            revault: Some(half),
        },
        TriggerStep {
            outputs: withdrawal(half),
            revault: None,
        },
    ];
    let mut owner = Runner::new(
        offline_manager(),
        chain.clone(),
        owner_role(),
        OwnerData::new(alice_xpriv(), plan),
        fake_vault(SEED),
    );

    while let Progress::Advanced = owner.step().expect("owner steps") {}
    assert_eq!(owner.tokens().len(), 2, "the trigger_and_revault forked");

    chain.mine(SPEND_DELAY + 1);
    let outcomes = owner.run().expect("both branches withdraw");
    assert_eq!(
        outcomes,
        vec![
            VaultOutcome::Withdrawn { amount: half },
            VaultOutcome::Withdrawn { amount: half },
        ]
    );
}

#[test]
fn watchtower_recovers_an_unauthorized_unvaulting() {
    let chain = Rc::new(LocalChain::new());
    let amount = Amount::from_sat(AMOUNT);

    // The owner's key is compromised: the thief triggers a withdrawal whose
    // CTV hash the watchtower was never told about.
    let mut thief = Runner::new(
        offline_manager(),
        chain.clone(),
        owner_role(),
        OwnerData::new(
            alice_xpriv(),
            vec![TriggerStep {
                outputs: withdrawal(amount),
                revault: None,
            }],
        ),
        fake_vault(SEED),
    );
    let tower_entry = fake_vault(SEED);
    let mut tower = Runner::new(
        offline_manager(),
        chain.clone(),
        watchtower_role(),
        WatchtowerData {
            authorized: HashSet::new(),
        },
        tower_entry.clone(),
    );

    // Interleave the two parties: the watchtower sweeps the unvaulting well
    // before its CSV delay could mature (no blocks are mined at all), and the
    // thief's own runner classifies the sweep it observes.
    let (thief_out, tower_out) =
        drive_both(&mut thief, &mut tower, 20, Duration::ZERO).expect("both step");
    assert_eq!(tower_out, Some(VaultOutcome::Recovered { amount }));
    assert_eq!(thief_out, Some(VaultOutcome::Recovered { amount }));

    // The unvaulting was spent through `recover`, paying the recovery key.
    let mut children = tower_entry.outputs();
    assert_eq!(children.len(), 1);
    let unvaulting = children.remove(0);
    assert_eq!(unvaulting.contract_name(), "Unvaulting");
    assert_eq!(unvaulting.clause_name().as_deref(), Some("recover"));
    let sweep = &unvaulting.spending_tx().expect("swept").output[0];
    assert_eq!(sweep.script_pubkey, opaque_p2tr(bob_pk()));
    assert_eq!(sweep.value, amount);
}

#[test]
fn watchtower_keeps_watching_the_revaulted_branch() {
    let chain = Rc::new(LocalChain::new());
    let revault = Amount::from_sat(30_000);
    let rest = Amount::from_sat(AMOUNT) - revault;

    // The thief splits the vault, stealing the larger branch (and leaving the
    // revaulted remainder alone — for now).
    let mut thief = Runner::new(
        offline_manager(),
        chain.clone(),
        owner_role(),
        OwnerData::new(
            alice_xpriv(),
            vec![TriggerStep {
                outputs: withdrawal(rest),
                revault: Some(revault),
            }],
        ),
        fake_vault(SEED),
    );
    let mut tower = Runner::new(
        offline_manager(),
        chain.clone(),
        watchtower_role(),
        WatchtowerData {
            authorized: HashSet::new(),
        },
        fake_vault(SEED),
    );

    // Drive until the watchtower has swept the unauthorized branch.
    for _ in 0..20 {
        thief.step().expect("thief steps");
        tower.step().expect("tower steps");
        if !tower.outcomes().is_empty() {
            break;
        }
    }

    // The sweep resolved one token, peekable mid-run — while the other token
    // keeps watching the revaulted Vault: the watchtower never finishes.
    assert_eq!(
        tower.outcomes(),
        &[VaultOutcome::Recovered { amount: rest }]
    );
    assert_eq!(tower.tokens().len(), 1);
    assert_eq!(
        tower.current().map(|h| h.contract_name()),
        Some("Vault"),
        "the revaulted branch is still live"
    );

    // The thief observes the sweep of its waiting branch the same way, and its
    // other token (the revaulted vault, with an exhausted plan) stays live too.
    for _ in 0..5 {
        thief.step().expect("thief steps");
    }
    assert_eq!(
        thief.outcomes(),
        &[VaultOutcome::Recovered { amount: rest }]
    );
    assert_eq!(
        thief.current().map(|h| h.contract_name()),
        Some("Vault")
    );
}

/// A role that knows how to trigger a `Vault` but nothing else.
fn trigger_only() -> Role<OwnerData, VaultOutcome> {
    Role::new().on::<Vault, _>(|d: &mut OwnerData, h: VaultHandle, _cx| {
        let step = d.plan.remove(0);
        let p = h.params()?;
        let ctv_hash = compute_ctv_hash(&step.outputs, Sequence(p.spend_delay));
        Ok(Action::Send(
            h.trigger(ctv_hash, 0).sign(HotSigner::new(d.xpriv)),
        ))
    })
}

#[test]
fn unhandled_fork_children_are_loud_unless_ignored() {
    let plan = || {
        vec![TriggerStep {
            outputs: withdrawal(Amount::from_sat(AMOUNT)),
            revault: None,
        }]
    };

    // Handling Vault but not Unvaulting: the spend's child is a loud error...
    let mut runner = Runner::new(
        offline_manager(),
        Rc::new(LocalChain::new()),
        trigger_only(),
        OwnerData::new(alice_xpriv(), plan()),
        fake_vault(SEED),
    );
    let err = runner.step().expect_err("the Unvaulting child is unhandled");
    assert!(
        matches!(err, ProtocolError::NoHandler { ref contract } if contract == "Unvaulting"),
        "got: {err}"
    );

    // ...unless the role explicitly ignores it: then every branch of the spend
    // is somebody else's business and the token resolves silently.
    let mut runner = Runner::new(
        offline_manager(),
        Rc::new(LocalChain::new()),
        trigger_only().ignore::<Unvaulting>(),
        OwnerData::new(alice_xpriv(), plan()),
        fake_vault(SEED),
    );
    match runner.step().expect("steps") {
        Progress::Done(outcomes) => assert!(outcomes.is_empty(), "every branch was ignored"),
        _ => panic!("expected the protocol to resolve"),
    }
}

// Integration test — requires a running regtest bitcoind (see testkit).
#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_vault_fork_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    let revault = Amount::from_sat(30_000);
    let rest = Amount::from_sat(AMOUNT) - revault;

    let mut manager = ContractManager::new(regtest_client("testwallet"), bitcoin::Network::Regtest);
    let vault = Vault::new(params()).fund(&mut manager, Amount::from_sat(AMOUNT))?;
    let entry = vault.handle().clone();

    let plan = vec![
        TriggerStep {
            outputs: withdrawal(rest),
            revault: Some(revault),
        },
        TriggerStep {
            outputs: withdrawal(revault),
            revault: None,
        },
    ];
    let mut owner = Runner::new(
        manager,
        Rc::new(RpcChain::new(regtest_client("testwallet"))),
        owner_role(),
        OwnerData::new(alice_xpriv(), plan),
        entry.clone(),
    );

    // Drive to resolution; when the runner reports Waiting, only the CSV
    // delays are left — mine a block to move them along. This exercises the
    // deadline arithmetic against real BIP68 enforcement: fire one block early
    // and the node rejects the withdrawal as non-BIP68-final.
    let mut done = None;
    for _ in 0..100 {
        match owner.step()? {
            Progress::Done(os) => {
                done = Some(os);
                break;
            }
            Progress::Advanced => {}
            Progress::Waiting => owner.manager_mut().mine_blocks(1)?,
        }
    }
    let outcomes = done.expect("the protocol resolves");
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.contains(&VaultOutcome::Withdrawn { amount: rest }));
    assert!(outcomes.contains(&VaultOutcome::Withdrawn { amount: revault }));

    // Same tree shape as the offline test — this time consensus-validated.
    assert_eq!(entry.clause_name().as_deref(), Some("trigger_and_revault"));
    let children = entry.outputs();
    assert_eq!(children.len(), 2);
    let revaulted = children
        .iter()
        .find(|c| c.contract_name() == "Vault")
        .expect("the revaulted branch");
    assert_eq!(revaulted.clause_name().as_deref(), Some("trigger"));
    for unvaulting in [
        children
            .iter()
            .find(|c| c.contract_name() == "Unvaulting")
            .expect("the unvaulting branch"),
        &revaulted.outputs()[0],
    ] {
        assert_eq!(unvaulting.clause_name().as_deref(), Some("withdraw"));
    }
    Ok(())
}
