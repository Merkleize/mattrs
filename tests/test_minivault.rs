//! MiniVault tests: the CCV-only vault with a feature-dependent clause set.
//!
//! The offline tests pin the clause layout of all four feature combinations and
//! verify the trigger's output commitment at the build level. The `#[ignore]`d
//! regtest tests then drive each combination's distinctive flow on-chain — so
//! every one of the four taptree shapes (including the single-leaf one) is
//! validated by a real script interpreter.

mod support;

use bitcoin::{Amount, TxOut, XOnlyPublicKey};
use mattrs::contracts::ClauseError;
use mattrs::manager::{ContractManager, ManagerError};
use mattrs::report::Report;
use mattrs::script_helpers::opaque_p2tr;
use mattrs::signer::HotSigner;
use support::minivault::{
    MiniUnvaulting, MiniUnvaultingHandle, MiniVault, MiniVaultHandle, MiniVaultParams,
};
use support::testkit::{
    alice_pk, alice_xpriv, bob_pk, fund_fake, offline_client, regtest_client, report_spend,
    try_handle,
};

const SPEND_DELAY: u32 = 10;

fn make_params(has_partial_revault: bool, has_early_recover: bool) -> MiniVaultParams {
    MiniVaultParams {
        alternate_pk: None,
        spend_delay: SPEND_DELAY,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
        has_partial_revault,
        has_early_recover,
    }
}

/// A fixed withdrawal key (its x-only pubkey), distinct from the test parties'.
fn withdrawal_pk() -> [u8; 32] {
    hex::decode("0981368165440d4fe866f84d75ae53a95b192aa45155735d4cb2a8894b340b8f")
        .unwrap()
        .try_into()
        .unwrap()
}

// ----------------------------------------------------------------------------
// Offline: clause layout per feature combination, and the trigger commitment.
// ----------------------------------------------------------------------------

#[test]
fn test_minivault_clause_set_follows_features() {
    let clause_names = |pr: bool, er: bool| -> Vec<String> {
        MiniVault::new(make_params(pr, er))
            .unwrap()
            .as_erased()
            .clauses()
            .iter()
            .map(|c| c.name().to_string())
            .collect()
    };

    assert_eq!(
        clause_names(true, true),
        ["trigger", "trigger_and_revault", "recover"]
    );
    assert_eq!(
        clause_names(true, false),
        ["trigger", "trigger_and_revault"]
    );
    assert_eq!(clause_names(false, true), ["trigger", "recover"]);
    assert_eq!(clause_names(false, false), ["trigger"]);
}

#[test]
fn test_minivault_combos_have_distinct_taptrees() {
    let combos = [(true, true), (true, false), (false, true), (false, false)];
    let roots: Vec<[u8; 32]> = combos
        .iter()
        .map(|&(pr, er)| MiniVault::new(make_params(pr, er)).unwrap().taptree_root())
        .collect();

    for a in 0..roots.len() {
        for b in (a + 1)..roots.len() {
            assert_ne!(
                roots[a], roots[b],
                "combos {:?} and {:?} must not share an address",
                combos[a], combos[b]
            );
        }
    }
}

#[test]
fn test_minivault_trigger_commits_unvaulting_state() {
    // Build (no node) a trigger spend and check output 0 commits a
    // MiniUnvaulting carrying the withdrawal key, preserving the amount.
    let params = make_params(false, false);
    let wpk = withdrawal_pk();

    let handle = try_handle::<MiniVaultHandle>(fund_fake(
        MiniVault::new(params.clone()).unwrap().as_erased(),
        None,
        100_000,
        0,
    ));

    let manager = ContractManager::new(offline_client(), bitcoin::Network::Regtest);
    let tx = handle
        .trigger(wpk, 0)
        .sign(HotSigner::new(alice_xpriv()))
        .build_tx(&manager)
        .unwrap();

    let unvaulting = MiniUnvaulting::new(support::minivault::MiniUnvaultingParams {
        alternate_pk: None,
        spend_delay: SPEND_DELAY,
        recover_pk: bob_pk(),
    })
    .unwrap();
    let expected = unvaulting
        .as_erased()
        .script_pubkey(Some(wpk.as_slice()))
        .unwrap();

    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].script_pubkey, expected);
    assert_eq!(tx.output[0].value, Amount::from_sat(100_000));
}

#[test]
fn test_minivault_rejects_negative_output_indices() {
    let params = make_params(true, false);
    let handle = try_handle::<MiniVaultHandle>(fund_fake(
        MiniVault::new(params).unwrap().as_erased(),
        None,
        100_000,
        8,
    ));
    let manager = ContractManager::new(offline_client(), bitcoin::Network::Regtest);

    let err = handle
        .trigger_and_revault(withdrawal_pk(), 0, -1)
        .build_tx(&manager)
        .unwrap_err();
    assert!(matches!(
        err,
        ManagerError::ClauseError(ClauseError::Other(message))
            if message.contains("revault_out_i")
    ));
}

// ----------------------------------------------------------------------------
// End-to-end (regtest): each feature combination's distinctive flow.
//
// The tests share one chain and some mine blocks, which would race the
// timelock assertions of the others under the default parallel test runner —
// so they serialize on this lock.
// ----------------------------------------------------------------------------

static E2E_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn e2e_lock() -> std::sync::MutexGuard<'static, ()> {
    E2E_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The withdrawal key's opaque-P2TR output, as the withdraw clause's CCV
/// (empty data, no taptweak) constrains output 0.
fn withdrawal_txout(value: Amount) -> TxOut {
    let wpk = XOnlyPublicKey::from_slice(&withdrawal_pk()).unwrap();
    TxOut {
        script_pubkey: opaque_p2tr(wpk),
        value,
    }
}

/// The recovery output the recover clauses' CCV constrains output 0 to.
fn recovery_txout(value: Amount) -> TxOut {
    TxOut {
        script_pubkey: opaque_p2tr(bob_pk()),
        value,
    }
}

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_minivault_early_recover_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = e2e_lock();
    // Combo (false, true): tree [trigger, recover] — recover straight from the
    // vault state, no trigger.
    let amount = Amount::from_sat(20_000);
    let mut manager = ContractManager::new(regtest_client("testwallet"), bitcoin::Network::Regtest);
    let mut report = Report::new();

    let vault = MiniVault::new(make_params(false, true))?.fund(&mut manager, amount)?;
    vault
        .recover(0)
        .outputs(vec![recovery_txout(amount)])
        .exec_none(&mut manager)?;

    report_spend(
        &mut report,
        "MiniVault",
        "recover (straight from the vault)",
        vault.handle(),
    );
    report.finalize("reports/report_minivault_recover.md")?;
    Ok(())
}

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_minivault_trigger_and_recover_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = e2e_lock();
    // Combo (true, true): the full tree [trigger, [trigger_and_revault, recover]];
    // trigger, then recover from the unvaulting state.
    let amount = Amount::from_sat(20_000);
    let mut manager = ContractManager::new(regtest_client("testwallet"), bitcoin::Network::Regtest);
    let mut report = Report::new();
    let wpk = withdrawal_pk();

    let vault = MiniVault::new(make_params(true, true))?.fund(&mut manager, amount)?;

    let unvaulting: MiniUnvaultingHandle = vault
        .trigger(wpk, 0)
        .sign(HotSigner::new(alice_xpriv()))
        .exec_one(&mut manager)?
        .try_into()?;
    report_spend(&mut report, "MiniVault", "trigger", vault.handle());

    let state = unvaulting.state().expect("MiniUnvaulting state");
    assert_eq!(state.withdrawal_pk, wpk);

    unvaulting
        .recover(0)
        .outputs(vec![recovery_txout(amount)])
        .exec_none(&mut manager)?;
    report_spend(
        &mut report,
        "MiniVault",
        "recover (from the unvaulting)",
        unvaulting.handle(),
    );
    report.finalize("reports/report_minivault_trigger_recover.md")?;
    Ok(())
}

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_minivault_trigger_and_withdraw_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = e2e_lock();
    // Combo (false, false): the lightest vault — a single-leaf taptree with only
    // the trigger clause — then the timelocked withdraw to the committed key.
    let amount = Amount::from_sat(20_000);
    let mut manager = ContractManager::new(regtest_client("testwallet"), bitcoin::Network::Regtest);
    let mut report = Report::new();
    let wpk = withdrawal_pk();

    let vault = MiniVault::new(make_params(false, false))?.fund(&mut manager, amount)?;

    let unvaulting: MiniUnvaultingHandle = vault
        .trigger(wpk, 0)
        .sign(HotSigner::new(alice_xpriv()))
        .exec_one(&mut manager)?
        .try_into()?;
    report_spend(&mut report, "MiniVault", "trigger", vault.handle());

    // Withdrawing before the delay must be rejected as non-BIP68-final.
    let early = unvaulting
        .withdraw(wpk)
        .outputs(vec![withdrawal_txout(amount)])
        .sequence(SPEND_DELAY)
        .exec_none(&mut manager);
    let err = early
        .expect_err("withdraw must fail before spend_delay")
        .to_string();
    assert!(
        err.contains("non-BIP68-final") || err.contains("non-final"),
        "expected a non-final rejection, got: {err}"
    );

    manager.mine_blocks(SPEND_DELAY as u64)?;

    unvaulting
        .withdraw(wpk)
        .outputs(vec![withdrawal_txout(amount)])
        .sequence(SPEND_DELAY)
        .exec_none(&mut manager)?;
    report_spend(
        &mut report,
        "MiniVault",
        "withdraw (after the delay)",
        unvaulting.handle(),
    );
    report.finalize("reports/report_minivault_trigger_withdraw.md")?;
    Ok(())
}

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_minivault_revault_batch_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = e2e_lock();
    // Combo (true, false): tree [trigger, trigger_and_revault]. Three vaults in
    // one transaction — one triggers with a partial revault, two trigger
    // normally; the unvaulting outputs merge at index 0, the revault is the
    // deducted output at index 1. Then withdraw the merged pot.
    let amount = Amount::from_sat(100_000);
    let revault_amount = Amount::from_sat(30_000);
    let mut manager = ContractManager::new(regtest_client("testwallet"), bitcoin::Network::Regtest);
    let mut report = Report::new();
    let wpk = withdrawal_pk();

    let minivault = MiniVault::new(make_params(true, false))?;
    let v1 = minivault.fund(&mut manager, amount)?;
    let v2 = minivault.fund(&mut manager, amount)?;
    let v3 = minivault.fund(&mut manager, amount)?;

    let children = manager.spend_batch(&[
        v1.trigger_and_revault(wpk, 0, 1)
            .sign(HotSigner::new(alice_xpriv()))
            .output_amount(1, revault_amount),
        v2.trigger(wpk, 0).sign(HotSigner::new(alice_xpriv())),
        v3.trigger(wpk, 0).sign(HotSigner::new(alice_xpriv())),
    ])?;
    report_spend(
        &mut report,
        "MiniVault",
        "trigger_and_revault + 2x trigger (3 vault inputs)",
        v1.handle(),
    );

    // Two children: the merged MiniUnvaulting (output 0) and the revaulted
    // MiniVault (deducted output 1). Their order follows the clauses'
    // next-outputs order, so look them up by contract.
    assert_eq!(children.len(), 2);
    let unvaulting_child = children
        .iter()
        .find(|c| c.contract_name() == "MiniUnvaulting")
        .expect("merged unvaulting child");
    let revault_child = children
        .iter()
        .find(|c| c.contract_name() == "MiniVault")
        .expect("revaulted vault child");
    let merged = Amount::from_sat(3 * 100_000 - 30_000);
    assert_eq!(unvaulting_child.prevout().unwrap().value, merged);
    assert_eq!(revault_child.prevout().unwrap().value, revault_amount);

    let unvaulting: MiniUnvaultingHandle = unvaulting_child.clone().try_into()?;
    assert_eq!(unvaulting.state().expect("state").withdrawal_pk, wpk);

    manager.mine_blocks(SPEND_DELAY as u64)?;
    unvaulting
        .withdraw(wpk)
        .outputs(vec![withdrawal_txout(merged)])
        .sequence(SPEND_DELAY)
        .exec_none(&mut manager)?;
    report_spend(
        &mut report,
        "MiniVault",
        "withdraw of the merged unvaulting",
        unvaulting.handle(),
    );
    report.finalize("reports/report_minivault_revault.md")?;
    Ok(())
}
