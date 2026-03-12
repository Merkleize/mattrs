mod common;

use std::str::FromStr;

use bitcoin::{
    hashes::Hash,
    hex::DisplayHex,
    key::Secp256k1,
    Address, Amount, KnownHrp, Sequence, TapNodeHash, TxOut,
};

use mattrs::{
    contracts::ContractInstanceStatus,
    ctv::make_ctv_template_hash,
    manager::{ContractManager, SpendOptions},
    report::{format_tx_markdown, Report},
};
use mattrs_examples::vault::*;

#[test]
fn test_vault_trigger_and_withdraw() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);
    let (unvault_privkey, unvault_pubkey, recover_privkey, recover_pubkey) = common::get_keys();
    let _ = recover_privkey; // unused in this test

    let vault_params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    };
    let vault_contract = make_vault(&vault_params);

    // Verify address matches pymatt
    let internal_key = vault_contract.naked_internal_pubkey();
    let taptree_hash = TapNodeHash::from_byte_array(vault_contract.get_taptree_merkle_root());
    let address = Address::p2tr(&secp, *internal_key, Some(taptree_hash), KnownHrp::Regtest);
    assert_eq!(
        address.to_string(),
        "bcrt1plkh3clum5e2rynql75ufxxqxw898arfumqnua60hwr76q4y0jeksu88u3m"
    );

    let amount = 49_999_900u64;
    let mut manager = ContractManager::new(&client, 0.1, true);
    let mut report = Report::new();

    // --- Step 1: Fund the vault (typed API) ---
    let vault = VaultInstance::fund(&mut manager, vault_contract.clone(), vec![], amount)?;
    assert_eq!(manager.instances[vault.idx()].status, ContractInstanceStatus::Funded);
    assert!(manager.instances[vault.idx()].outpoint.is_some());
    println!("Vault funded at {:?}", manager.instances[vault.idx()].outpoint.unwrap());

    // --- Step 2: Set up signers ---
    let signers = common::make_signers(&[(unvault_pubkey, unvault_privkey)]);

    // --- Step 3: Compute CTV hash ---
    let ctv_template = vec![
        (
            Address::from_str("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437")?.assume_checked(),
            Amount::from_sat(16_663_333u64),
        ),
        (
            Address::from_str("bcrt1qpnpjyzkfe7n5eppp2ktwpvuxfw5qfn2zjdum83")?.assume_checked(),
            Amount::from_sat(16_663_333u64),
        ),
        (
            Address::from_str("bcrt1q6vqduw24yjjll6nfkxlfy2twwt52w58tnvnd46")?.assume_checked(),
            Amount::from_sat(16_663_334u64),
        ),
    ];

    let ctv_hash = make_ctv_template_hash(&ctv_template, Sequence(10))?;
    assert_eq!(
        ctv_hash.to_hex_string(bitcoin::hex::Case::Lower),
        "b288279b3012acaedfde4e4e347ad6f3147d416edbebf76668f16b91f2969215"
    );

    // --- Step 4: Spend vault with "trigger" clause (typed API) ---
    let vault_idx = vault.idx();
    let (unvaulting,) = vault.trigger(&mut manager, ctv_hash, 0, &signers)?;

    // Verify the vault instance is now spent
    assert_eq!(manager.instances[vault_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[vault_idx].spending_clause.as_deref(), Some("trigger"));
    report.write("Vault", format_tx_markdown(
        manager.instances[vault_idx].spending_tx.as_ref().unwrap(),
        "Trigger",
    ));

    // Verify unvaulting instance
    let unvaulting_inst = &manager.instances[unvaulting.idx()];
    assert_eq!(unvaulting_inst.status, ContractInstanceStatus::Funded);
    assert_eq!(unvaulting_inst.contract.name(), "Unvaulting");
    assert_eq!(unvaulting_inst.data, ctv_hash.to_vec());
    println!("Unvaulting funded at {:?}", unvaulting_inst.outpoint.unwrap());

    // --- Step 5: Mine blocks for timelock ---
    manager.mine_blocks(10)?;

    // --- Step 6: Withdraw from unvaulting ---
    let unvaulting_idx = unvaulting.idx();

    let ctv_outputs: Vec<TxOut> = ctv_template
        .iter()
        .map(|(addr, amount)| TxOut {
            script_pubkey: addr.script_pubkey(),
            value: *amount,
        })
        .collect();

    unvaulting.withdraw(&mut manager, ctv_hash, SpendOptions {
        outputs: Some(&ctv_outputs),
        sequence: Some(Sequence(10)),
    })?;

    // Withdraw is terminal (no next outputs)
    assert_eq!(manager.instances[unvaulting_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[unvaulting_idx].spending_clause.as_deref(), Some("withdraw"));

    report.write("Vault", format_tx_markdown(
        manager.instances[unvaulting_idx].spending_tx.as_ref().unwrap(),
        "Withdraw [3 outputs]",
    ));
    report.finalize("reports/report_vault.md");

    println!("Vault trigger + withdraw test passed!");
    Ok(())
}

#[test]
fn test_vault_trigger_and_revault() -> Result<(), Box<dyn std::error::Error>> {
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);
    let (unvault_privkey, unvault_pubkey, _recover_privkey, recover_pubkey) = common::get_keys();

    let vault_params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    };
    let vault_contract = make_vault(&vault_params);

    let amount = 49_999_900u64;
    let mut manager = ContractManager::new(&client, 0.1, true);

    // Fund the vault (typed API)
    let vault = VaultInstance::fund(&mut manager, vault_contract.clone(), vec![], amount)?;
    println!("Vault funded at {:?}", manager.instances[vault.idx()].outpoint.unwrap());

    // Set up signers
    let signers = common::make_signers(&[(unvault_pubkey, unvault_privkey)]);

    // Compute CTV hash
    let ctv_template = vec![
        (
            Address::from_str("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437")?.assume_checked(),
            Amount::from_sat(16_663_333u64),
        ),
        (
            Address::from_str("bcrt1qpnpjyzkfe7n5eppp2ktwpvuxfw5qfn2zjdum83")?.assume_checked(),
            Amount::from_sat(16_663_333u64),
        ),
        (
            Address::from_str("bcrt1q6vqduw24yjjll6nfkxlfy2twwt52w58tnvnd46")?.assume_checked(),
            Amount::from_sat(16_663_334u64),
        ),
    ];
    let ctv_hash = make_ctv_template_hash(&ctv_template, Sequence(10))?;

    // Spend with "trigger" clause (typed API)
    let vault_idx = vault.idx();
    let (unvaulting,) = vault.trigger(&mut manager, ctv_hash, 0, &signers)?;

    assert_eq!(manager.instances[unvaulting.idx()].contract.name(), "Unvaulting");

    // Verify the unvaulting instance has the correct CTV hash as state data
    let decoded_state = UnvaultingState::decode(&manager.instances[unvaulting.idx()].data)
        .map_err(|e| -> Box<dyn std::error::Error> { e })?;
    assert_eq!(decoded_state.ctv_hash, ctv_hash);

    // Verify vault is spent
    assert_eq!(manager.instances[vault_idx].status, ContractInstanceStatus::Spent);

    println!("Vault trigger_and_revault test passed! (trigger step verified)");
    Ok(())
}

#[test]
fn test_vault_recover() -> Result<(), Box<dyn std::error::Error>> {
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);
    let (_unvault_privkey, unvault_pubkey, _recover_privkey, recover_pubkey) = common::get_keys();

    let vault_params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    };
    let vault_contract = make_vault(&vault_params);

    let amount = 49_999_900u64;
    let mut manager = ContractManager::new(&client, 0.1, true);

    // Fund the vault (typed API)
    let vault = VaultInstance::fund(&mut manager, vault_contract.clone(), vec![], amount)?;
    let vault_idx = vault.idx();
    println!("Vault funded at {:?}", manager.instances[vault_idx].outpoint.unwrap());

    // Spend with "recover" clause (typed API, no signers needed)
    vault.recover(&mut manager, 0, Default::default())?;

    // Recover produces an opaque P2TR output
    assert_eq!(manager.instances[vault_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[vault_idx].spending_clause.as_deref(), Some("recover"));

    let mut report = Report::new();
    report.write("Vault", format_tx_markdown(
        manager.instances[vault_idx].spending_tx.as_ref().unwrap(),
        "Recovery from vault",
    ));
    report.finalize("reports/report_vault_recover.md");

    println!("Vault recover test passed!");
    Ok(())
}
