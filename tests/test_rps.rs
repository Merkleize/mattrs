mod common;

use std::collections::HashMap;

use bitcoin::{Amount, TxOut};
use bitcoincore_rpc::RpcApi;

use mattrs::{
    contracts::{ClauseArg, ClauseArgs, ContractInstanceStatus, Contract},
    hub::rps::*,
    manager::{ContractManager, SpendOptions},
    report::{format_tx_markdown, Report},
    signer::SignerMap,
};

fn build_s1_spend_tx(
    manager: &ContractManager,
    s1_idx: usize,
    clause_name: &str,
    m_b: i32,
    m_a: i32,
    r_a: &[u8],
    ctv_outputs: &[TxOut],
) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
    let mut clause_args: ClauseArgs = HashMap::new();
    clause_args.insert("m_b".to_string(), <i32 as ClauseArg>::to_bytes(&m_b));
    clause_args.insert("m_a".to_string(), <i32 as ClauseArg>::to_bytes(&m_a));
    clause_args.insert("r_a".to_string(), r_a.to_vec());

    manager.build_spend_tx(
        s1_idx,
        clause_name,
        clause_args,
        Some(ctv_outputs),
        None,
        None,
    )
}

#[test]
fn test_rps() -> Result<(), Box<dyn std::error::Error>> {
    let client = common::get_rpc_client("testwallet");
    common::ensure_funds(&client);
    let (_alice_privkey, alice_pk, bob_privkey, bob_pk) = common::get_keys();

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
    let mut report = Report::new();

    // --- Step 1: Fund S0 ---
    let s0 = RpsS0Instance::fund(&mut manager, s0_contract, vec![], 2 * stake)?;
    assert_eq!(manager.instances[s0.idx()].status, ContractInstanceStatus::Funded);
    println!("S0 funded at {:?}", manager.instances[s0.idx()].outpoint.unwrap());

    // --- Step 2: Bob plays paper (m_b=1) ---
    let signers: SignerMap = common::make_signers(&[(bob_pk, bob_privkey)]);

    let m_b: i32 = 1; // paper
    let s0_idx = s0.idx();
    let (s1,) = s0.bob_move(&mut manager, m_b, &signers)?;

    // Verify S0 is spent
    assert_eq!(manager.instances[s0_idx].status, ContractInstanceStatus::Spent);
    assert_eq!(manager.instances[s0_idx].spending_clause.as_deref(), Some("bob_move"));
    report.write("RPS", format_tx_markdown(
        manager.instances[s0_idx].spending_tx.as_ref().unwrap(),
        "Bob move",
    ));

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
        let s1 = RpsS1Instance(s1_idx);
        s1.bob_wins(&mut manager, m_b, m_a, r_a.to_vec(), SpendOptions {
            outputs: Some(&bob_wins_outputs),
            ..Default::default()
        })?;

        // Terminal clause: no tracked outputs
        assert_eq!(manager.instances[s1_idx].status, ContractInstanceStatus::Spent);
        assert_eq!(manager.instances[s1_idx].spending_clause.as_deref(), Some("bob_wins"));

        report.write("RPS", format_tx_markdown(
            manager.instances[s1_idx].spending_tx.as_ref().unwrap(),
            "Bob wins",
        ));
    }

    report.finalize("reports/report_rps.md");
    println!("RPS test passed! Rock vs Paper => Bob wins correctly adjudicated.");
    Ok(())
}
