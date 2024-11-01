mod common;

use std::{collections::HashMap, str::FromStr};

use bitcoin::{
    bip32::Xpriv, hashes::Hash, hex::DisplayHex, key::Secp256k1, Address, Amount, KnownHrp,
    TapNodeHash, TxOut, XOnlyPublicKey,
};

use mattrs::{
    contracts::*,
    ctv::make_ctv_template_hash,
    hub::vault::*,
    manager::ContractManager,
    signer::{HotSigner, SchnorrSigner},
};

#[tokio::test]
async fn test_vault_trigger_and_withdraw() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    // Initialize the RPC client
    let client = common::get_rpc_client();

    let unvault_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )?;
    let unvault_pubkey = unvault_privkey.to_priv().public_key(&secp);

    let recover_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )?;
    let recover_pubkey = recover_privkey.to_priv().public_key(&secp);

    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey.into(),
        unvault_pk: unvault_pubkey.into(),
    });

    let internal_key = vault.get_naked_internal_key();
    let taptree_hash = TapNodeHash::from_byte_array(vault.get_taptree().get_root_hash());

    let address = Address::p2tr(&secp, internal_key, Some(taptree_hash), KnownHrp::Regtest);

    // compare with pymatt's address
    assert_eq!(
        address.to_string(),
        "bcrt1plkh3clum5e2rynql75ufxxqxw898arfumqnua60hwr76q4y0jeksu88u3m"
    );

    let amount = 49999900;

    let mut manager = ContractManager::new(&client, 0.1, true);

    // Create and fund a Vault UTXO
    let inst = manager
        .fund_instance(Box::new(vault.clone()), None, amount)
        .await
        .expect("Failed to fund instance");

    let mut signers: HashMap<XOnlyPublicKey, Box<dyn SchnorrSigner>> = HashMap::new();

    signers.insert(
        unvault_pubkey.into(),
        Box::new(HotSigner {
            privkey: unvault_privkey,
        }),
    );

    let ctv_template = vec![
        (
            Address::from_str("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437")?.assume_checked(),
            Amount::from_sat(16663333u64),
        ),
        (
            Address::from_str("bcrt1qpnpjyzkfe7n5eppp2ktwpvuxfw5qfn2zjdum83")?.assume_checked(),
            Amount::from_sat(16663333u64),
        ),
        (
            Address::from_str("bcrt1q6vqduw24yjjll6nfkxlfy2twwt52w58tnvnd46")?.assume_checked(),
            Amount::from_sat(16663334u64),
        ),
    ];

    let ctv_hash = make_ctv_template_hash(&ctv_template, bitcoin::Sequence(10))?;

    assert_eq!(
        ctv_hash.to_hex_string(bitcoin::hex::Case::Lower),
        "b288279b3012acaedfde4e4e347ad6f3147d416edbebf76668f16b91f2969215"
    );

    // Spend the Vault UTXO with the "trigger" clause; an Unvaulting UTXO is created
    let out_instances = manager
        .spend_instance(
            inst,
            "trigger",
            Box::new(VaultTriggerClauseArgs {
                // TODO: put real data
                sig: Signature::default(),
                ctv_hash,
                out_i: 0,
            }),
            None,
            Some(&signers),
        )
        .await
        .expect("Failed to spend instance");

    assert_eq!(out_instances.len(), 1);

    let unvaulting_inst = out_instances[0].clone();

    {
        let unvaulting_inst = unvaulting_inst.borrow();

        let unvaulting = unvaulting_inst
            .get_contract::<Unvaulting>()
            .expect("Wrong contract type");

        assert_eq!(unvaulting.params.spend_delay, vault.params.spend_delay);
        assert!(unvaulting.params.recover_pk == vault.params.recover_pk);
        assert!(unvaulting.params.alternate_pk == vault.params.alternate_pk);

        let unvaulting_state = unvaulting_inst
            .get_state::<UnvaultingState>()
            .expect("Wrong state type");

        assert!(unvaulting_state.ctv_hash == ctv_hash);
    }

    manager.mine_blocks(10)?;

    // spend the Unvaulting UTXO with the "withdraw" clause
    let mut tx = mattrs::manager::get_spend_tx(
        &unvaulting_inst,
        "withdraw",
        Box::new(UnvaultingWithdrawClauseArgs { ctv_hash }),
        Some(
            ctv_template
                .iter()
                .map(|(addr, amount)| TxOut {
                    script_pubkey: addr.script_pubkey(),
                    value: *amount,
                })
                .collect(),
        ),
        None,
    )
    .expect("Failed to spend instance");

    tx.lock_time = bitcoin::absolute::LockTime::ZERO;
    tx.input[0].sequence = bitcoin::Sequence(10);
    tx.version = bitcoin::transaction::Version::TWO;
    tx.output = ctv_template
        .iter()
        .map(|(addr, amount)| TxOut {
            script_pubkey: addr.script_pubkey(),
            value: *amount,
        })
        .collect();

    // TODO: a lot of this code is duplicated create_spend_tx in ContractManager; refactor

    // Compute sighashes for each input
    let mut sighashes: Vec<[u8; 32]> = Vec::new();

    let withdraw_args = UnvaultingWithdrawClauseArgs { ctv_hash };
    let spends_vec: Vec<_> = vec![(&unvaulting_inst, "withdraw".to_string(), &withdraw_args)];
    let spent_utxos: Vec<TxOut> = spends_vec
        .iter()
        .map(|(instance_rc, _, _)| {
            let instance = instance_rc.borrow();
            let funding_tx = instance.funding_tx.as_ref().unwrap();
            let outpoint = instance.outpoint.as_ref().unwrap();
            funding_tx.output[outpoint.vout as usize].clone()
        })
        .collect();

    let mut sighash_cache = bitcoin::sighash::SighashCache::new(tx.clone());

    let leaf_script = {
        let contract = &unvaulting_inst.borrow().contract;

        let leaves = contract.get_taptree().get_leaves();
        let clause = leaves
            .iter()
            .find(|&leaf| leaf.name == "withdraw")
            .ok_or_else(|| "Clause not found")?;
        clause.script.clone()
    };

    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&spent_utxos),
            bitcoin::TapLeafHash::from_script(
                &leaf_script,
                bitcoin::taproot::LeafVersion::TapScript,
            ),
            bitcoin::TapSighashType::Default,
        )
        .map(|h| h.to_byte_array())
        .map_err(|_| "Sighash computation failed")?;

    sighashes.push(sighash);

    // add witness
    tx.input[0].witness = {
        mattrs::manager::get_spend_witness(
            &unvaulting_inst.borrow(),
            "withdraw",
            &withdraw_args,
            &sighash,
            Some(&signers),
        )?
    };

    println!("Witness: {:?}", tx.input[0].witness);

    // send tx, update manager
    let final_insts = manager.spend_and_wait(&[&unvaulting_inst], &tx).await?;

    // Withdraw tx is terminal.
    assert_eq!(final_insts.len(), 0);

    Ok(())
}
