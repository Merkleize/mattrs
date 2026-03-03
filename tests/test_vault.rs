use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::{
    bip32::Xpriv,
    hashes::Hash,
    hex::DisplayHex,
    key::Secp256k1,
    sighash::SighashCache,
    taproot::LeafVersion,
    Address, Amount, KnownHrp, Sequence, TapLeafHash, TapNodeHash, TxOut, XOnlyPublicKey,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use mattrs::{
    contracts::ContractInstanceStatus,
    ctv::make_ctv_template_hash,
    hub::vault::*,
    manager::ContractManager,
    signer::{HotSigner, SignerMap},
    tx,
};

fn get_rpc_client(wallet_name: &str) -> Client {
    let rpc_url = std::env::var("BITCOIN_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_user = std::env::var("BITCOIN_RPC_USER")
        .unwrap_or_else(|_| "rpcuser".to_string());
    let rpc_pass = std::env::var("BITCOIN_RPC_PASS")
        .unwrap_or_else(|_| "rpcpass".to_string());

    let url = format!("{}/wallet/{}", rpc_url, wallet_name);
    Client::new(&url, Auth::UserPass(rpc_user, rpc_pass)).expect("Failed to create RPC client")
}

#[test]
fn test_vault_trigger_and_withdraw() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let client = get_rpc_client("testwallet");

    // Ensure wallet has funds
    let balance = client.get_balance(None, None)?;
    if balance < Amount::from_sat(100_000_000) {
        // Mine some blocks to get funds
        let addr = client.get_new_address(None, None)?.assume_checked();
        client.generate_to_address(101, &addr)?;
    }

    let unvault_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )?;
    let unvault_pubkey: XOnlyPublicKey = unvault_privkey.to_priv().public_key(&secp).into();

    let recover_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )?;
    let recover_pubkey: XOnlyPublicKey = recover_privkey.to_priv().public_key(&secp).into();

    let vault_params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    };
    let vault = make_vault(&vault_params);

    // Verify address matches pymatt
    let internal_key = vault.naked_internal_pubkey();
    let taptree_hash = TapNodeHash::from_byte_array(vault.get_taptree_merkle_root());
    let address = Address::p2tr(&secp, *internal_key, Some(taptree_hash), KnownHrp::Regtest);
    assert_eq!(
        address.to_string(),
        "bcrt1plkh3clum5e2rynql75ufxxqxw898arfumqnua60hwr76q4y0jeksu88u3m"
    );

    let amount = 49_999_900u64;
    let mut manager = ContractManager::new(&client, 0.1, true);

    // --- Step 1: Fund the vault ---
    let vault_idx = manager.fund_instance(vault.clone(), vec![], amount)?;
    assert_eq!(manager.instances[vault_idx].status, ContractInstanceStatus::Funded);
    assert!(manager.instances[vault_idx].outpoint.is_some());
    println!("Vault funded at {:?}", manager.instances[vault_idx].outpoint.unwrap());

    // --- Step 2: Set up signers ---
    let mut signers: SignerMap = HashMap::new();
    signers.insert(
        unvault_pubkey,
        Box::new(HotSigner { privkey: unvault_privkey }),
    );

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

    // --- Step 4: Spend vault with "trigger" clause ---
    let trigger_args = TriggerArgs {
        sig: [0u8; 64], // placeholder, will be filled by signer
        ctv_hash,
        out_i: 0,
    };
    let trigger_clause_args = trigger_args.to_clause_args();

    let new_indices = manager.spend_instance(
        vault_idx,
        "trigger",
        trigger_clause_args,
        Some(&signers),
    )?;

    assert_eq!(new_indices.len(), 1);
    let unvaulting_idx = new_indices[0];

    // Verify the vault instance is now spent
    assert_eq!(manager.instances[vault_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[vault_idx].spending_clause.as_deref(), Some("trigger"));

    // Verify unvaulting instance
    let unvaulting_inst = &manager.instances[unvaulting_idx];
    assert_eq!(unvaulting_inst.status, ContractInstanceStatus::Funded);
    assert_eq!(unvaulting_inst.contract.name(), "Unvaulting");
    assert_eq!(unvaulting_inst.data, ctv_hash.to_vec());
    println!("Unvaulting funded at {:?}", unvaulting_inst.outpoint.unwrap());

    // --- Step 5: Mine blocks for timelock ---
    manager.mine_blocks(10)?;

    // --- Step 6: Withdraw from unvaulting ---
    // The withdraw clause uses CTV, so we need to manually construct the transaction
    // with the exact CTV template outputs.
    let withdraw_args = WithdrawArgs { ctv_hash };
    let mut clause_args = withdraw_args.to_clause_args();

    // Build the spend tx with CTV template outputs
    let ctv_outputs: Vec<TxOut> = ctv_template
        .iter()
        .map(|(addr, amount)| TxOut {
            script_pubkey: addr.script_pubkey(),
            value: *amount,
        })
        .collect();

    let spend_spec = tx::SpendSpec {
        instance_idx: unvaulting_idx,
        clause_name: "withdraw".to_string(),
        args: clause_args.clone(),
    };

    let (mut spend_tx, _sighashes) = tx::create_spend_tx(
        &manager.instances,
        &[spend_spec],
        &HashMap::new(),
        &ctv_outputs,
    )?;

    // Set CTV-required tx fields
    spend_tx.lock_time = bitcoin::absolute::LockTime::ZERO;
    spend_tx.input[0].sequence = Sequence(10);
    spend_tx.version = bitcoin::transaction::Version::TWO;

    // The sighash must be recomputed after modifying the tx
    let spent_utxos: Vec<TxOut> = {
        let inst = &manager.instances[unvaulting_idx];
        let funding_tx = inst.funding_tx.as_ref().unwrap();
        let outpoint = inst.outpoint.unwrap();
        vec![funding_tx.output[outpoint.vout as usize].clone()]
    };

    let leaf_script = manager.instances[unvaulting_idx]
        .contract
        .get_clause("withdraw")
        .unwrap()
        .script
        .clone();

    let mut sighash_cache = SighashCache::new(spend_tx.clone());
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&spent_utxos),
            TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript),
            bitcoin::TapSighashType::Default,
        )
        .map(|h| h.to_byte_array())
        .map_err(|e| format!("Sighash failed: {}", e))?;

    // Build witness (withdraw has no signer_args, so no signing needed)
    spend_tx.input[0].witness = tx::build_witness(
        &manager.instances[unvaulting_idx],
        "withdraw",
        &mut clause_args,
        &sighash,
        None,
    )?;

    println!("Withdraw tx witness: {:?}", spend_tx.input[0].witness);

    // Broadcast and wait
    let final_indices = manager.spend_and_wait(&[unvaulting_idx], &spend_tx)?;

    // Withdraw is terminal (no next outputs)
    assert_eq!(final_indices.len(), 0);
    assert_eq!(manager.instances[unvaulting_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[unvaulting_idx].spending_clause.as_deref(), Some("withdraw"));

    println!("Vault trigger + withdraw test passed!");
    Ok(())
}

#[test]
fn test_vault_trigger_and_revault() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let client = get_rpc_client("testwallet");

    let unvault_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )?;
    let unvault_pubkey: XOnlyPublicKey = unvault_privkey.to_priv().public_key(&secp).into();

    let recover_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )?;
    let recover_pubkey: XOnlyPublicKey = recover_privkey.to_priv().public_key(&secp).into();

    let vault_params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    };
    let vault = make_vault(&vault_params);

    let amount = 49_999_900u64;
    let mut manager = ContractManager::new(&client, 0.1, true);

    // Fund the vault
    let vault_idx = manager.fund_instance(vault.clone(), vec![], amount)?;
    println!("Vault funded at {:?}", manager.instances[vault_idx].outpoint.unwrap());

    // Set up signers
    let mut signers: SignerMap = HashMap::new();
    signers.insert(
        unvault_pubkey,
        Box::new(HotSigner { privkey: unvault_privkey }),
    );

    // Compute CTV hash (same as above)
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

    // Spend with "trigger" clause
    let trigger_args = TriggerArgs {
        sig: [0u8; 64],
        ctv_hash,
        out_i: 0,
    };
    let new_indices = manager.spend_instance(
        vault_idx,
        "trigger",
        trigger_args.to_clause_args(),
        Some(&signers),
    )?;

    assert_eq!(new_indices.len(), 1);
    let unvaulting_idx = new_indices[0];
    assert_eq!(manager.instances[unvaulting_idx].contract.name(), "Unvaulting");

    // Verify the unvaulting instance has the correct CTV hash as state data
    let decoded_state = UnvaultingState::decode(&manager.instances[unvaulting_idx].data)
        .map_err(|e| -> Box<dyn std::error::Error> { e })?;
    assert_eq!(decoded_state.ctv_hash, ctv_hash);

    println!("Vault trigger_and_revault test passed! (trigger step verified)");
    Ok(())
}

#[test]
fn test_vault_recover() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let client = get_rpc_client("testwallet");

    let unvault_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )?;
    let unvault_pubkey: XOnlyPublicKey = unvault_privkey.to_priv().public_key(&secp).into();

    let recover_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )?;
    let recover_pubkey: XOnlyPublicKey = recover_privkey.to_priv().public_key(&secp).into();

    let vault_params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    };
    let vault = make_vault(&vault_params);

    let amount = 49_999_900u64;
    let mut manager = ContractManager::new(&client, 0.1, true);

    // Fund the vault
    let vault_idx = manager.fund_instance(vault.clone(), vec![], amount)?;
    println!("Vault funded at {:?}", manager.instances[vault_idx].outpoint.unwrap());

    // Spend with "recover" clause (no signers needed)
    // The recover clause expects out_i as the output index
    let mut recover_args = HashMap::new();
    recover_args.insert("out_i".to_string(), vec![]); // out_i = 0 (scriptint: empty = 0)

    let new_indices = manager.spend_instance(
        vault_idx,
        "recover",
        recover_args,
        None,
    )?;

    // Recover produces an opaque P2TR output
    assert_eq!(new_indices.len(), 1);
    assert_eq!(manager.instances[new_indices[0]].contract.name(), "OpaqueP2TR");
    assert_eq!(manager.instances[vault_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[vault_idx].spending_clause.as_deref(), Some("recover"));

    println!("Vault recover test passed!");
    Ok(())
}
