mod common;

use std::collections::HashMap;

use bitcoin::Sequence;
use bitcoincore_rpc::RpcApi;

use mattrs::{
    contracts::{ClauseArg, ContractInstanceStatus},
    hub::minivault::*,
    manager::{ContractManager, SpendOptions},
    report::{format_tx_markdown, Report},
};

fn withdrawal_pk() -> [u8; 32] {
    let bytes = hex::decode("0981368165440d4fe866f84d75ae53a95b192aa45155735d4cb2a8894b340b8f").unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

fn make_test_vault(has_partial_revault: bool, has_early_recover: bool) -> (MiniVaultParams, mattrs::contracts::Contract) {
    let (_unvault_privkey, unvault_pubkey, _recover_privkey, recover_pubkey) = common::get_keys();

    let params = MiniVaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
        has_partial_revault,
        has_early_recover,
    };
    let contract = make_minivault(&params);
    (params, contract)
}

#[test]
fn test_minivault_recover() -> Result<(), Box<dyn std::error::Error>> {
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);

    let (_params, vault_contract) = make_test_vault(true, true);
    let amount = 20_000u64;

    let mut manager = ContractManager::new(&client, 0.1, true);
    let mut report = Report::new();

    let vault = MiniVaultInstance::fund(&mut manager, vault_contract, vec![], amount)?;
    let vault_idx = vault.idx();

    vault.recover(&mut manager, 0, Default::default())?;

    assert_eq!(manager.instances[vault_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[vault_idx].spending_clause.as_deref(), Some("recover"));

    let spending_tx = manager.instances[vault_idx].spending_tx.as_ref().unwrap();
    assert_eq!(spending_tx.output.len(), 1);
    assert_eq!(spending_tx.output[0].value.to_sat(), amount);

    report.write("MiniVault", format_tx_markdown(spending_tx, "Recovery from vault"));
    report.finalize("reports/report_minivault_recover.md");

    println!("MiniVault recover test passed!");
    Ok(())
}

#[test]
fn test_minivault_trigger_and_recover() -> Result<(), Box<dyn std::error::Error>> {
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);
    let (unvault_privkey, unvault_pubkey, _recover_privkey, _recover_pubkey) = common::get_keys();

    let (_params, vault_contract) = make_test_vault(true, true);
    let amount = 49_999_900u64;

    let mut manager = ContractManager::new(&client, 0.1, true);
    let mut report = Report::new();

    let vault = MiniVaultInstance::fund(&mut manager, vault_contract, vec![], amount)?;
    let vault_idx = vault.idx();

    let signers = common::make_signers(&[(unvault_pubkey, unvault_privkey)]);
    let wpk = withdrawal_pk();

    let (unvaulting,) = vault.trigger(&mut manager, wpk, 0, &signers)?;

    assert_eq!(manager.instances[vault_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[vault_idx].spending_clause.as_deref(), Some("trigger"));
    report.write("MiniVault", format_tx_markdown(
        manager.instances[vault_idx].spending_tx.as_ref().unwrap(),
        "Trigger",
    ));

    let unvaulting_inst = &manager.instances[unvaulting.idx()];
    assert_eq!(unvaulting_inst.status, ContractInstanceStatus::Funded);
    assert_eq!(unvaulting_inst.contract.name(), "MiniUnvaulting");
    assert_eq!(unvaulting_inst.data, wpk.to_vec());

    let unvaulting_idx = unvaulting.idx();
    unvaulting.recover(&mut manager, 0, Default::default())?;

    assert_eq!(manager.instances[unvaulting_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[unvaulting_idx].spending_clause.as_deref(), Some("recover"));

    report.write("MiniVault", format_tx_markdown(
        manager.instances[unvaulting_idx].spending_tx.as_ref().unwrap(),
        "Recovery from trigger",
    ));
    report.finalize("reports/report_minivault_trigger_recover.md");

    println!("MiniVault trigger + recover test passed!");
    Ok(())
}

#[test]
fn test_minivault_trigger_and_withdraw() -> Result<(), Box<dyn std::error::Error>> {
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);
    let (unvault_privkey, unvault_pubkey, _recover_privkey, _recover_pubkey) = common::get_keys();

    let (_params, vault_contract) = make_test_vault(true, true);
    let spend_delay = 10u32;
    let amount = 49_999_900u64;

    let mut manager = ContractManager::new(&client, 0.1, true);
    let mut report = Report::new();

    let vault = MiniVaultInstance::fund(&mut manager, vault_contract, vec![], amount)?;
    let signers = common::make_signers(&[(unvault_pubkey, unvault_privkey)]);
    let wpk = withdrawal_pk();

    let (unvaulting,) = vault.trigger(&mut manager, wpk, 0, &signers)?;

    // Attempt early withdraw — build tx and try to broadcast (should fail)
    let early_tx = manager.build_spend_tx(
        unvaulting.idx(),
        "withdraw",
        {
            let mut args = HashMap::new();
            args.insert("withdrawal_pk".to_string(), wpk.to_vec());
            args
        },
        None,
        None,
        Some(Sequence(spend_delay)),
    )?;
    let send_result = client.send_raw_transaction(&early_tx);
    assert!(send_result.is_err(), "Expected early withdraw to fail due to timelock");

    // Mine blocks for timelock
    manager.mine_blocks((spend_delay - 1).into())?;

    // Now withdraw should succeed
    let unvaulting_idx = unvaulting.idx();
    unvaulting.withdraw(&mut manager, wpk, SpendOptions {
        sequence: Some(Sequence(spend_delay)),
        ..Default::default()
    })?;

    assert_eq!(manager.instances[unvaulting_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[unvaulting_idx].spending_clause.as_deref(), Some("withdraw"));

    report.write("MiniVault", format_tx_markdown(
        manager.instances[unvaulting_idx].spending_tx.as_ref().unwrap(),
        "Withdraw",
    ));
    report.finalize("reports/report_minivault_trigger_withdraw.md");

    println!("MiniVault trigger + withdraw test passed!");
    Ok(())
}

#[test]
fn test_minivault_trigger_with_revault_and_withdraw() -> Result<(), Box<dyn std::error::Error>> {
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);
    let (unvault_privkey, unvault_pubkey, _recover_privkey, _recover_pubkey) = common::get_keys();

    let (_params, vault_contract) = make_test_vault(true, true);
    let spend_delay = 10u32;
    let amount = 49_999_900u64;

    let mut manager = ContractManager::new(&client, 0.1, true);
    let mut report = Report::new();

    // Fund 3 vault instances
    let v1 = MiniVaultInstance::fund(&mut manager, vault_contract.clone(), vec![], amount)?;
    let v2 = MiniVaultInstance::fund(&mut manager, vault_contract.clone(), vec![], amount)?;
    let v3 = MiniVaultInstance::fund(&mut manager, vault_contract.clone(), vec![], amount)?;

    let signers = common::make_signers(&[(unvault_pubkey, unvault_privkey)]);
    let wpk = withdrawal_pk();
    let revault_amount = 20_000_000u64;

    let mut output_amounts = HashMap::new();
    output_amounts.insert(1, revault_amount);

    let wpk_vec = wpk.to_vec();

    let spends: Vec<(usize, &str, mattrs::contracts::ClauseArgs)> = vec![
        (v1.idx(), "trigger_and_revault", {
            let mut args = HashMap::new();
            args.insert("out_i".to_string(), <i32 as ClauseArg>::to_bytes(&0));
            args.insert("revault_out_i".to_string(), <i32 as ClauseArg>::to_bytes(&1));
            args.insert("withdrawal_pk".to_string(), wpk_vec.clone());
            args
        }),
        (v2.idx(), "trigger", {
            let mut args = HashMap::new();
            args.insert("out_i".to_string(), <i32 as ClauseArg>::to_bytes(&0));
            args.insert("withdrawal_pk".to_string(), wpk_vec.clone());
            args
        }),
        (v3.idx(), "trigger", {
            let mut args = HashMap::new();
            args.insert("out_i".to_string(), <i32 as ClauseArg>::to_bytes(&0));
            args.insert("withdrawal_pk".to_string(), wpk_vec.clone());
            args
        }),
    ];

    let new_indices = manager.spend_instances(
        spends,
        Some(&signers),
        output_amounts,
        Sequence::ZERO,
    )?;

    assert_eq!(new_indices.len(), 2);

    let unvaulting_idx = new_indices[0];
    let revault_idx = new_indices[1];

    assert_eq!(manager.instances[unvaulting_idx].contract.name(), "MiniUnvaulting");
    assert_eq!(manager.instances[unvaulting_idx].status, ContractInstanceStatus::Funded);
    assert_eq!(manager.instances[revault_idx].contract.name(), "MiniVault");
    assert_eq!(manager.instances[revault_idx].status, ContractInstanceStatus::Funded);

    report.write("MiniVault", format_tx_markdown(
        manager.instances[v1.idx()].spending_tx.as_ref().unwrap(),
        "Trigger (with revault) [3 vault inputs]",
    ));

    // Mine blocks for timelock, then withdraw
    manager.mine_blocks((spend_delay - 1).into())?;

    let unvaulting = MiniUnvaultingInstance(unvaulting_idx);
    unvaulting.withdraw(&mut manager, wpk, SpendOptions {
        sequence: Some(Sequence(spend_delay)),
        ..Default::default()
    })?;

    assert_eq!(manager.instances[unvaulting_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[unvaulting_idx].spending_clause.as_deref(), Some("withdraw"));

    report.write("MiniVault", format_tx_markdown(
        manager.instances[unvaulting_idx].spending_tx.as_ref().unwrap(),
        "Withdraw after revault trigger",
    ));
    report.finalize("reports/report_minivault_revault.md");

    println!("MiniVault trigger with revault + withdraw test passed!");
    Ok(())
}
