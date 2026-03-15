use mattrs_test_utils::{get_rpc_client, ensure_funds, make_keypair, make_signers, ALICE_TPRV, BOB_TPRV};

use std::time::Duration;

use bitcoin::{Amount, TxOut};

use mattrs::{
    contracts::{ClauseArg, Contract, ContractInstanceStatus},
    hub::fraud::{
        Bisect1Instance, Bisect2Instance, LeafInstance,
        bisect1_state, leaf_state, make_leaf,
    },
    manager::{ContractManager, SpendOptions},
    merkle::is_power_of_2,
    report::{format_tx_markdown, Report},
    sha256,
};
use mattrs_game256::*;

const AMOUNT: Amount = Amount::from_sat(20_000);

// ---------------------------------------------------------------------------
// Trace computation helper
// ---------------------------------------------------------------------------

fn h(x: i32) -> [u8; 32] {
    sha256(&<i32 as ClauseArg>::to_bytes(&x))
}

/// Compute the trace commitment for a range [i, j] given hashed trace values.
fn t_from_trace(trace: &[[u8; 32]], i: usize, j: usize) -> [u8; 32] {
    assert!(j >= i && is_power_of_2(j - i + 1));
    let m = (j - i + 1) / 2;

    if i == j {
        // Leaf: sha256(trace[i] || trace[i+1])
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&trace[i]);
        data[32..].copy_from_slice(&trace[i + 1]);
        sha256(&data)
    } else {
        // Internal: sha256(trace[i] || trace[j+1] || t(i, i+m-1) || t(i+m, j))
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&trace[i]);
        data.extend_from_slice(&trace[j + 1]);
        data.extend_from_slice(&t_from_trace(trace, i, i + m - 1));
        data.extend_from_slice(&t_from_trace(trace, i + m, j));
        sha256(&data)
    }
}

fn winner_outputs(winner_pk: bitcoin::XOnlyPublicKey) -> Vec<TxOut> {
    let winner_addr = Contract::new_opaque_p2tr(winner_pk).get_address(&vec![]);
    vec![TxOut {
        script_pubkey: winner_addr.script_pubkey(),
        value: AMOUNT,
    }]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_leaf_reveal_alice() -> Result<(), Box<dyn std::error::Error>> {
    let client = get_rpc_client("testwallet");
    ensure_funds(&client);
    let (alice_privkey, alice_pk) = make_keypair(ALICE_TPRV);
    let (_bob_privkey, bob_pk) = make_keypair(BOB_TPRV);

    let computer = compute_2x();
    let leaf = make_leaf(alice_pk, bob_pk, &computer);

    let x_start = 347;
    let x_end_alice = 2 * x_start; // correct
    let x_end_bob = 2 * x_start - 1; // wrong

    let h_start = h(x_start);
    let h_end_alice = h(x_end_alice);
    let h_end_bob = h(x_end_bob);

    let state = leaf_state(h_start, h_end_alice, h_end_bob);
    let mut manager = ContractManager::new(&client, Duration::from_secs_f64(0.1), true);
    let leaf = LeafInstance::fund(&mut manager, leaf, state, AMOUNT)?;
    let leaf_idx = leaf.idx();

    let signers = make_signers(&[(alice_pk, alice_privkey)]);
    let outputs = winner_outputs(alice_pk);

    leaf.alice_reveal(&mut manager, x_start, h_end_bob, &signers, SpendOptions {
        outputs: Some(&outputs),
        ..Default::default()
    })?;

    assert_eq!(
        manager.instance(leaf_idx).status(),
        ContractInstanceStatus::Spent
    );

    let mut report = Report::new();
    report.write("Leaf reveal (Alice)", format_tx_markdown(
        manager.instance(leaf_idx).spending_tx().unwrap(),
        "Leaf reveal (Alice wins)",
    ));
    report.finalize("reports/report_fraud_leaf_alice.md");

    println!("test_leaf_reveal_alice passed!");
    Ok(())
}

#[test]
fn test_leaf_reveal_bob() -> Result<(), Box<dyn std::error::Error>> {
    let client = get_rpc_client("testwallet");
    ensure_funds(&client);
    let (_alice_privkey, alice_pk) = make_keypair(ALICE_TPRV);
    let (bob_privkey, bob_pk) = make_keypair(BOB_TPRV);

    let computer = compute_2x();
    let leaf = make_leaf(alice_pk, bob_pk, &computer);

    let x_start = 347;
    let x_end_alice = 2 * x_start - 1; // wrong
    let x_end_bob = 2 * x_start; // correct

    let h_start = h(x_start);
    let h_end_alice = h(x_end_alice);
    let h_end_bob = h(x_end_bob);

    let state = leaf_state(h_start, h_end_alice, h_end_bob);
    let mut manager = ContractManager::new(&client, Duration::from_secs_f64(0.1), true);
    let leaf = LeafInstance::fund(&mut manager, leaf, state, AMOUNT)?;
    let leaf_idx = leaf.idx();

    let signers = make_signers(&[(bob_pk, bob_privkey)]);
    let outputs = winner_outputs(bob_pk);

    leaf.bob_reveal(&mut manager, x_start, h_end_alice, &signers, SpendOptions {
        outputs: Some(&outputs),
        ..Default::default()
    })?;

    assert_eq!(
        manager.instance(leaf_idx).status(),
        ContractInstanceStatus::Spent
    );

    let mut report = Report::new();
    report.write("Leaf reveal (Bob)", format_tx_markdown(
        manager.instance(leaf_idx).spending_tx().unwrap(),
        "Leaf reveal (Bob wins)",
    ));
    report.finalize("reports/report_fraud_leaf_bob.md");

    println!("test_leaf_reveal_bob passed!");
    Ok(())
}

#[test]
fn test_fraud_proof_full() -> Result<(), Box<dyn std::error::Error>> {
    let client = get_rpc_client("testwallet");
    ensure_funds(&client);
    let (alice_privkey, alice_pk) = make_keypair(ALICE_TPRV);
    let (bob_privkey, bob_pk) = make_keypair(BOB_TPRV);

    let alice_trace: Vec<i32> = vec![2, 4, 8, 16, 32, 64, 127, 254, 508]; // diverges at step 6
    let bob_trace: Vec<i32> = vec![2, 4, 8, 16, 32, 64, 128, 256, 512]; // correct

    assert_eq!(alice_trace[0], bob_trace[0]);
    assert_eq!(alice_trace.len(), bob_trace.len());

    let n = alice_trace.len() - 1; // 8
    assert!(is_power_of_2(n));

    let h_a: Vec<[u8; 32]> = alice_trace.iter().map(|&x| h(x)).collect();
    let h_b: Vec<[u8; 32]> = bob_trace.iter().map(|&x| h(x)).collect();

    let t_a = |i: usize, j: usize| -> [u8; 32] { t_from_trace(&h_a, i, j) };
    let t_b = |i: usize, j: usize| -> [u8; 32] { t_from_trace(&h_b, i, j) };

    let x = 2i32;
    let y = *alice_trace.last().unwrap(); // 508 (Alice's claim)
    let z = *bob_trace.last().unwrap(); // 512 (Bob's claim)

    let params = G256Params {
        alice_pk,
        bob_pk,
        forfait_timeout: 10,
    };

    let alice_signers = make_signers(&[(alice_pk, alice_privkey)]);
    let bob_signers = make_signers(&[(bob_pk, bob_privkey)]);

    let s0_contract = make_g256_s0(&params);
    let mut manager = ContractManager::new(&client, Duration::from_secs_f64(0.1), true);
    let mut report = Report::new();

    // --- Step 1: Fund S0, Bob chooses x=2 ---
    let s0 = G256S0Instance::fund(&mut manager, s0_contract, vec![], AMOUNT)?;
    let s0_idx = s0.idx();
    let (s1,) = s0.choose(&mut manager, x, &bob_signers)?;
    report.write("Fraud proof", format_tx_markdown(
        manager.instance(s0_idx).spending_tx().unwrap(),
        "S0 → S1 (Bob chooses x)",
    ));

    assert_eq!(manager.instance(s1.idx()).contract().name(), "G256_S1");
    let expected_s1_state = sha256(&<i32 as ClauseArg>::to_bytes(&x));
    assert_eq!(manager.instance(s1.idx()).data(), &expected_s1_state.to_vec());
    println!("S0 → S1 (Bob chose x={})", x);

    // --- Step 2: Alice reveals y=508 ---
    let t_a_root = t_a(0, n - 1);
    let s1_idx = s1.idx();
    let (s2,) = s1.reveal(
        &mut manager,
        t_a_root.to_vec(),
        y,
        x,
        &alice_signers,
    )?;

    assert_eq!(manager.instance(s2.idx()).contract().name(), "G256_S2");
    let expected_s2_state = g256_s2_state(&t_a_root, y, x);
    assert_eq!(manager.instance(s2.idx()).data(), &expected_s2_state);
    println!("S1 → S2 (Alice claims y={})", y);
    report.write("Fraud proof", format_tx_markdown(
        manager.instance(s1_idx).spending_tx().unwrap(),
        "S1 → S2 (Alice reveals y)",
    ));

    // --- Step 3: Bob starts challenge with z=512 ---
    let s2_idx = s2.idx();
    let t_b_root = t_b(0, n - 1);

    let (bisect1,) = s2.start_challenge(
        &mut manager, t_a_root.to_vec(), y, x, z, t_b_root.to_vec(), &bob_signers,
    )?;

    assert_eq!(manager.instance(bisect1.idx()).contract().name(), "Bisect_1");
    let expected_state = bisect1_state(h_a[0], h_a[n], h_b[n], t_a(0, n - 1), t_b(0, n - 1));
    assert_eq!(manager.instance(bisect1.idx()).data(), &expected_state);
    println!("S2 → Bisect_1[0,7]");
    report.write("Fraud proof", format_tx_markdown(
        manager.instance(s2_idx).spending_tx().unwrap(),
        "S2 → Bisect_1 (Bob starts challenge)",
    ));

    // --- Bisection protocol ---
    // Interval [0, 7], m = 4
    let (mut cur_i, mut cur_j) = (0usize, 7usize);
    let mut cur_idx = bisect1.idx();

    // Step 4: Alice reveals → Bisect_2[0,7]
    {
        let prev_idx = cur_idx;
        let m = (cur_j - cur_i + 1) / 2;
        let bisect1 = Bisect1Instance(cur_idx);
        let (bisect2,) = bisect1.alice_reveal(
            &mut manager,
            h_a[cur_i], h_a[cur_j + 1], h_b[cur_j + 1],
            t_a(cur_i, cur_j), t_b(cur_i, cur_j),
            h_a[cur_i + m], t_a(cur_i, cur_i + m - 1), t_a(cur_i + m, cur_j),
            &alice_signers,
        )?;
        cur_idx = bisect2.idx();
        assert_eq!(manager.instance(cur_idx).contract().name(), "Bisect_2");
        println!("Bisect_1[{},{}] → Bisect_2[{},{}] (Alice reveals)", cur_i, cur_j, cur_i, cur_j);
        report.write("Fraud proof", format_tx_markdown(
            manager.instance(prev_idx).spending_tx().unwrap(),
            &format!("Bisection (Alice) [{},{}]", cur_i, cur_j),
        ));
    }

    // Step 5: Bob reveals right (midstates agree at index 4) → Bisect_1[4,7]
    {
        let prev_idx = cur_idx;
        let m = (cur_j - cur_i + 1) / 2;
        assert_eq!(h_a[cur_i + m], h_b[cur_i + m]); // they agree at midpoint 4

        let bisect2 = Bisect2Instance(cur_idx);
        let (child,) = bisect2.bob_reveal_right(
            &mut manager,
            h_a[cur_i], h_a[cur_j + 1], h_b[cur_j + 1],
            t_a(cur_i, cur_j), t_b(cur_i, cur_j),
            h_a[cur_i + m], t_a(cur_i, cur_i + m - 1), t_a(cur_i + m, cur_j),
            h_b[cur_i + m], t_b(cur_i, cur_i + m - 1), t_b(cur_i + m, cur_j),
            &bob_signers,
        )?;

        // Update interval to right child [i+m, j]
        cur_i = cur_i + m;
        cur_idx = child.idx();
        let bisect1 = child.as_bisect1();
        assert_eq!(manager.instance(bisect1.idx()).contract().name(), "Bisect_1");
        assert_eq!((cur_i, cur_j), (4, 7));
        println!("Bisect_2[0,7] → Bisect_1[4,7] (Bob reveals right)");
        report.write("Fraud proof", format_tx_markdown(
            manager.instance(prev_idx).spending_tx().unwrap(),
            "Bisection (Bob, right child)",
        ));
    }

    // Step 6: Alice reveals → Bisect_2[4,7]
    {
        let prev_idx = cur_idx;
        let m = (cur_j - cur_i + 1) / 2;
        let bisect1 = Bisect1Instance(cur_idx);
        let (bisect2,) = bisect1.alice_reveal(
            &mut manager,
            h_a[cur_i], h_a[cur_j + 1], h_b[cur_j + 1],
            t_a(cur_i, cur_j), t_b(cur_i, cur_j),
            h_a[cur_i + m], t_a(cur_i, cur_i + m - 1), t_a(cur_i + m, cur_j),
            &alice_signers,
        )?;
        cur_idx = bisect2.idx();
        assert_eq!(manager.instance(cur_idx).contract().name(), "Bisect_2");
        println!("Bisect_1[4,7] → Bisect_2[4,7] (Alice reveals)");
        report.write("Fraud proof", format_tx_markdown(
            manager.instance(prev_idx).spending_tx().unwrap(),
            &format!("Bisection (Alice) [{},{}]", cur_i, cur_j),
        ));
    }

    // Step 7: Bob reveals left (midstates differ at index 6) → Bisect_1[4,5]
    {
        let prev_idx = cur_idx;
        let m = (cur_j - cur_i + 1) / 2;
        assert_ne!(h_a[cur_i + m], h_b[cur_i + m]); // they differ at midpoint 6

        let bisect2 = Bisect2Instance(cur_idx);
        let (child,) = bisect2.bob_reveal_left(
            &mut manager,
            h_a[cur_i], h_a[cur_j + 1], h_b[cur_j + 1],
            t_a(cur_i, cur_j), t_b(cur_i, cur_j),
            h_a[cur_i + m], t_a(cur_i, cur_i + m - 1), t_a(cur_i + m, cur_j),
            h_b[cur_i + m], t_b(cur_i, cur_i + m - 1), t_b(cur_i + m, cur_j),
            &bob_signers,
        )?;

        // Update interval to left child [i, i+m-1]
        cur_j = cur_i + m - 1;
        cur_idx = child.idx();
        let bisect1 = child.as_bisect1();
        assert_eq!(manager.instance(bisect1.idx()).contract().name(), "Bisect_1");
        assert_eq!((cur_i, cur_j), (4, 5));
        println!("Bisect_2[4,7] → Bisect_1[4,5] (Bob reveals left)");
        report.write("Fraud proof", format_tx_markdown(
            manager.instance(prev_idx).spending_tx().unwrap(),
            "Bisection (Bob, left child)",
        ));
    }

    // Step 8: Alice reveals → Bisect_2[4,5]
    {
        let prev_idx = cur_idx;
        let m = (cur_j - cur_i + 1) / 2;
        let bisect1 = Bisect1Instance(cur_idx);
        let (bisect2,) = bisect1.alice_reveal(
            &mut manager,
            h_a[cur_i], h_a[cur_j + 1], h_b[cur_j + 1],
            t_a(cur_i, cur_j), t_b(cur_i, cur_j),
            h_a[cur_i + m], t_a(cur_i, cur_i + m - 1), t_a(cur_i + m, cur_j),
            &alice_signers,
        )?;
        cur_idx = bisect2.idx();
        assert_eq!(manager.instance(cur_idx).contract().name(), "Bisect_2");
        println!("Bisect_1[4,5] → Bisect_2[4,5] (Alice reveals)");
        report.write("Fraud proof", format_tx_markdown(
            manager.instance(prev_idx).spending_tx().unwrap(),
            &format!("Bisection (Alice) [{},{}]", cur_i, cur_j),
        ));
    }

    // Step 9: Bob reveals right (midstates agree at index 5) → Leaf
    {
        let prev_idx = cur_idx;
        let m = (cur_j - cur_i + 1) / 2;
        assert_eq!(h_a[cur_i + m], h_b[cur_i + m]); // agree at 5

        let bisect2 = Bisect2Instance(cur_idx);
        let (child,) = bisect2.bob_reveal_right(
            &mut manager,
            h_a[cur_i], h_a[cur_j + 1], h_b[cur_j + 1],
            t_a(cur_i, cur_j), t_b(cur_i, cur_j),
            h_a[cur_i + m], t_a(cur_i, cur_i + m - 1), t_a(cur_i + m, cur_j),
            h_b[cur_i + m], t_b(cur_i, cur_i + m - 1), t_b(cur_i + m, cur_j),
            &bob_signers,
        )?;
        cur_idx = child.idx();
        assert_eq!(manager.instance(cur_idx).contract().name(), "Leaf");
        println!("Bisect_2[4,5] → Leaf (Bob reveals right)");
        report.write("Fraud proof", format_tx_markdown(
            manager.instance(prev_idx).spending_tx().unwrap(),
            "Bisection (Bob, right child)",
        ));
    }

    // Step 10: Bob proves correct computation on the leaf
    assert_eq!(alice_trace[5], bob_trace[5]); // agree on x_start
    assert_ne!(alice_trace[6], bob_trace[6]); // differ on x_end

    {
        let leaf = LeafInstance(cur_idx);
        let outputs = winner_outputs(bob_pk);
        leaf.bob_reveal(&mut manager, bob_trace[5], h_a[6], &bob_signers, SpendOptions {
            outputs: Some(&outputs),
            ..Default::default()
        })?;
        println!("Leaf → Bob wins! (proved 2*64=128)");
        report.write("Fraud proof", format_tx_markdown(
            manager.instance(cur_idx).spending_tx().unwrap(),
            "Leaf reveal",
        ));
    }

    report.finalize("reports/report_fraud.md");
    println!("test_fraud_proof_full passed!");
    Ok(())
}
