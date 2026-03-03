use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::{
    bip32::Xpriv,
    hashes::Hash,
    key::Secp256k1,
    sighash::SighashCache,
    taproot::LeafVersion,
    Amount, Sequence, TapLeafHash, TxOut, XOnlyPublicKey,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use mattrs::{
    contracts::{ClauseArg, ContractInstanceStatus, Contract},
    hub::rps::*,
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

/// Build a fully-signed spend tx for a terminal CTV clause on S1.
fn build_s1_spend_tx(
    manager: &ContractManager,
    s1_idx: usize,
    clause_name: &str,
    m_b: i32,
    m_a: i32,
    r_a: &[u8],
    ctv_outputs: &[TxOut],
) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
    let mut clause_args = HashMap::new();
    clause_args.insert("m_b".to_string(), <i32 as ClauseArg>::to_bytes(&m_b));
    clause_args.insert("m_a".to_string(), <i32 as ClauseArg>::to_bytes(&m_a));
    clause_args.insert("r_a".to_string(), r_a.to_vec());

    let spend_spec = tx::SpendSpec {
        instance_idx: s1_idx,
        clause_name: clause_name.to_string(),
        args: clause_args.clone(),
    };

    let (mut spend_tx, _) = tx::create_spend_tx(
        &manager.instances,
        &[spend_spec],
        &HashMap::new(),
        ctv_outputs,
    )?;

    // CTV requires these specific values
    spend_tx.lock_time = bitcoin::absolute::LockTime::ZERO;
    spend_tx.input[0].sequence = Sequence::ZERO;
    spend_tx.version = bitcoin::transaction::Version::TWO;

    // Recompute sighash after setting CTV fields
    let spent_utxos: Vec<TxOut> = {
        let inst = &manager.instances[s1_idx];
        let funding_tx = inst.funding_tx.as_ref().unwrap();
        let outpoint = inst.outpoint.unwrap();
        vec![funding_tx.output[outpoint.vout as usize].clone()]
    };

    let leaf_script = manager.instances[s1_idx]
        .contract
        .get_clause(clause_name)
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

    spend_tx.input[0].witness = tx::build_witness(
        &manager.instances[s1_idx],
        clause_name,
        &mut clause_args,
        &sighash,
        None,
    )?;

    Ok(spend_tx)
}

#[test]
fn test_rps() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let client = get_rpc_client("testwallet");

    // Ensure wallet has funds
    let balance = client.get_balance(None, None)?;
    if balance < Amount::from_sat(100_000_000) {
        let addr = client.get_new_address(None, None)?.assume_checked();
        client.generate_to_address(101, &addr)?;
    }

    // Keys: alice = unvault_privkey, bob = recover_privkey (matching vault test keys)
    let alice_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )?;
    let alice_pk: XOnlyPublicKey = alice_privkey.to_priv().public_key(&secp).into();

    let bob_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )?;
    let bob_pk: XOnlyPublicKey = bob_privkey.to_priv().public_key(&secp).into();

    // Alice picks rock (m_a=0), generates random r_a, computes commitment
    let m_a: i32 = 0; // rock
    let r_a: [u8; 32] = {
        use bitcoin::secp256k1::rand::{thread_rng, RngCore};
        let mut buf = [0u8; 32];
        thread_rng().fill_bytes(&mut buf);
        buf
    };
    let c_a = calculate_hash(m_a, &r_a);

    let stake: u64 = 1000;
    let params = RpsParams {
        alice_pk,
        bob_pk,
        c_a,
        stake,
    };

    let s0_contract = make_rps_s0(&params);
    let mut manager = ContractManager::new(&client, 0.1, true);

    // --- Step 1: Fund S0 ---
    let s0 = RpsS0Instance::fund(&mut manager, s0_contract, vec![], 2 * stake)?;
    assert_eq!(manager.instances[s0.idx()].status, ContractInstanceStatus::Funded);
    println!("S0 funded at {:?}", manager.instances[s0.idx()].outpoint.unwrap());

    // --- Step 2: Bob plays paper (m_b=1) ---
    let mut signers: SignerMap = HashMap::new();
    signers.insert(
        bob_pk,
        Box::new(HotSigner { privkey: bob_privkey }),
    );

    let m_b: i32 = 1; // paper
    let s0_idx = s0.idx();
    let (s1,) = s0.bob_move(&mut manager, m_b, &signers)?;

    // Verify S0 is spent
    assert_eq!(manager.instances[s0_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[s0_idx].spending_clause.as_deref(), Some("bob_move"));

    // Verify S1 instance is funded with correct state: SHA256(scriptint(m_b))
    let s1_inst = &manager.instances[s1.idx()];
    assert_eq!(s1_inst.status, ContractInstanceStatus::Funded);
    assert_eq!(s1_inst.contract.name(), "RpsS1");
    let expected_state = mattrs::sha256(&<i32 as ClauseArg>::to_bytes(&m_b));
    assert_eq!(s1_inst.data, expected_state.to_vec());
    println!("S1 funded at {:?}", s1_inst.outpoint.unwrap());

    // --- Step 3: Precompute CTV outputs for each outcome ---
    let alice_addr = Contract::new_opaque_p2tr(alice_pk).get_address(&vec![]);
    let bob_addr = Contract::new_opaque_p2tr(bob_pk).get_address(&vec![]);

    let alice_wins_outputs = vec![TxOut {
        script_pubkey: alice_addr.script_pubkey(),
        value: Amount::from_sat(2 * stake),
    }];
    let bob_wins_outputs = vec![TxOut {
        script_pubkey: bob_addr.script_pubkey(),
        value: Amount::from_sat(2 * stake),
    }];
    let tie_outputs = vec![
        TxOut {
            script_pubkey: alice_addr.script_pubkey(),
            value: Amount::from_sat(stake),
        },
        TxOut {
            script_pubkey: bob_addr.script_pubkey(),
            value: Amount::from_sat(stake),
        },
    ];

    let s1_idx = s1.idx();

    // --- Step 4: Cheating attempt — alice_wins (should fail) ---
    // (m_b - m_a) % 3 = (1 - 0) % 3 = 1, but alice_wins expects diff=2
    {
        let cheat_tx = build_s1_spend_tx(
            &manager, s1_idx, "alice_wins", m_b, m_a, &r_a, &alice_wins_outputs,
        )?;
        let result = client.send_raw_transaction(&cheat_tx);
        assert!(result.is_err(), "alice_wins should fail: diff=1 but clause expects 2");
        println!("alice_wins correctly rejected: {}", result.unwrap_err());
    }

    // --- Step 5: Cheating attempt — tie (should fail) ---
    // (m_b - m_a) % 3 = 1, but tie expects diff=0
    {
        let cheat_tx = build_s1_spend_tx(
            &manager, s1_idx, "tie", m_b, m_a, &r_a, &tie_outputs,
        )?;
        let result = client.send_raw_transaction(&cheat_tx);
        assert!(result.is_err(), "tie should fail: diff=1 but clause expects 0");
        println!("tie correctly rejected: {}", result.unwrap_err());
    }

    // --- Step 6: Correct adjudication — bob_wins ---
    // (m_b - m_a) % 3 = 1, bob_wins expects diff=1 ✓
    assert_eq!(adjudicate(m_a, m_b), "bob_wins");
    {
        let spend_tx = build_s1_spend_tx(
            &manager, s1_idx, "bob_wins", m_b, m_a, &r_a, &bob_wins_outputs,
        )?;
        let final_indices = manager.spend_and_wait(&[s1_idx], &spend_tx)?;

        // Terminal clause: no tracked outputs
        assert_eq!(final_indices.len(), 0);
        assert_eq!(manager.instances[s1_idx].status, ContractInstanceStatus::Spent);
        assert_eq!(manager.instances[s1_idx].spending_clause.as_deref(), Some("bob_wins"));
    }

    println!("RPS test passed! Rock vs Paper => Bob wins correctly adjudicated.");
    Ok(())
}
