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
    contracts::{ClauseArg, ClauseArgs, Contract, ContractInstanceStatus},
    hub::fraud::{
        bisect1_state, compute_2x, leaf_state, make_leaf,
    },
    hub::game256::*,
    manager::ContractManager,
    merkle::is_power_of_2,
    signer::{HotSigner, SignerMap},
    sha256, tx,
};

const AMOUNT: u64 = 20_000;

fn get_rpc_client(wallet_name: &str) -> Client {
    let rpc_url = std::env::var("BITCOIN_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_user =
        std::env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "rpcuser".to_string());
    let rpc_pass =
        std::env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "rpcpass".to_string());

    let url = format!("{}/wallet/{}", rpc_url, wallet_name);
    Client::new(&url, Auth::UserPass(rpc_user, rpc_pass)).expect("Failed to create RPC client")
}

fn ensure_funds(client: &Client) {
    let balance = client.get_balance(None, None).unwrap();
    if balance < Amount::from_sat(100_000_000) {
        let addr = client.get_new_address(None, None).unwrap().assume_checked();
        client.generate_to_address(101, &addr).unwrap();
    }
}

fn get_keys() -> (Xpriv, XOnlyPublicKey, Xpriv, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let alice_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )
    .unwrap();
    let alice_pk: XOnlyPublicKey = alice_privkey.to_priv().public_key(&secp).into();

    let bob_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )
    .unwrap();
    let bob_pk: XOnlyPublicKey = bob_privkey.to_priv().public_key(&secp).into();

    (alice_privkey, alice_pk, bob_privkey, bob_pk)
}

/// Build a terminal spend tx for a Leaf contract (no tracked CCV outputs).
fn build_leaf_spend_tx(
    manager: &ContractManager,
    instance_idx: usize,
    clause_name: &str,
    mut clause_args: ClauseArgs,
    winner_pk: XOnlyPublicKey,
    signers: &SignerMap,
) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
    let winner_addr = Contract::new_opaque_p2tr(winner_pk).get_address(&vec![]);
    let outputs = vec![TxOut {
        script_pubkey: winner_addr.script_pubkey(),
        value: Amount::from_sat(AMOUNT),
    }];

    let spend_spec = tx::SpendSpec {
        instance_idx,
        clause_name: clause_name.to_string(),
        args: clause_args.clone(),
    };

    let (mut spend_tx, _) =
        tx::create_spend_tx(&manager.instances, &[spend_spec], &HashMap::new(), &outputs)?;

    spend_tx.lock_time = bitcoin::absolute::LockTime::ZERO;
    spend_tx.input[0].sequence = Sequence::ZERO;
    spend_tx.version = bitcoin::transaction::Version::TWO;

    // Recompute sighash
    let inst = &manager.instances[instance_idx];
    let funding_tx = inst.funding_tx.as_ref().unwrap();
    let outpoint = inst.outpoint.unwrap();
    let spent_utxos = vec![funding_tx.output[outpoint.vout as usize].clone()];

    let leaf_script = inst
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
        inst,
        clause_name,
        &mut clause_args,
        &sighash,
        Some(signers),
    )?;

    Ok(spend_tx)
}

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_leaf_reveal_alice() -> Result<(), Box<dyn std::error::Error>> {
    let client = get_rpc_client("testwallet");
    ensure_funds(&client);
    let (alice_privkey, alice_pk, _bob_privkey, bob_pk) = get_keys();

    let computer = compute_2x();
    let leaf = make_leaf(alice_pk, bob_pk, &computer);

    let x_start = 347;
    let x_end_alice = 2 * x_start; // correct
    let x_end_bob = 2 * x_start - 1; // wrong

    let h_start = h(x_start);
    let h_end_alice = h(x_end_alice);
    let h_end_bob = h(x_end_bob);

    let state = leaf_state(h_start, h_end_alice, h_end_bob);
    let mut manager = ContractManager::new(&client, 0.1, true);
    let leaf_idx = manager.fund_instance(leaf, state, AMOUNT)?;

    // Build args for alice_reveal: alice_sig x h_y_b
    let mut args: ClauseArgs = HashMap::new();
    args.insert("x".to_string(), <i32 as ClauseArg>::to_bytes(&x_start));
    args.insert("h_y_b".to_string(), h_end_bob.to_vec());

    let mut signers: SignerMap = HashMap::new();
    signers.insert(
        alice_pk,
        Box::new(HotSigner {
            privkey: alice_privkey,
        }),
    );

    let spend_tx =
        build_leaf_spend_tx(&manager, leaf_idx, "alice_reveal", args, alice_pk, &signers)?;
    let result = manager.spend_and_wait(&[leaf_idx], &spend_tx)?;

    assert_eq!(result.len(), 0); // terminal
    assert_eq!(
        manager.instances[leaf_idx].status,
        ContractInstanceStatus::Spent
    );
    println!("test_leaf_reveal_alice passed!");
    Ok(())
}

#[test]
fn test_leaf_reveal_bob() -> Result<(), Box<dyn std::error::Error>> {
    let client = get_rpc_client("testwallet");
    ensure_funds(&client);
    let (_alice_privkey, alice_pk, bob_privkey, bob_pk) = get_keys();

    let computer = compute_2x();
    let leaf = make_leaf(alice_pk, bob_pk, &computer);

    let x_start = 347;
    let x_end_alice = 2 * x_start - 1; // wrong
    let x_end_bob = 2 * x_start; // correct

    let h_start = h(x_start);
    let h_end_alice = h(x_end_alice);
    let h_end_bob = h(x_end_bob);

    let state = leaf_state(h_start, h_end_alice, h_end_bob);
    let mut manager = ContractManager::new(&client, 0.1, true);
    let leaf_idx = manager.fund_instance(leaf, state, AMOUNT)?;

    let mut args: ClauseArgs = HashMap::new();
    args.insert("x".to_string(), <i32 as ClauseArg>::to_bytes(&x_start));
    args.insert("h_y_a".to_string(), h_end_alice.to_vec());

    let mut signers: SignerMap = HashMap::new();
    signers.insert(
        bob_pk,
        Box::new(HotSigner {
            privkey: bob_privkey,
        }),
    );

    let spend_tx =
        build_leaf_spend_tx(&manager, leaf_idx, "bob_reveal", args, bob_pk, &signers)?;
    let result = manager.spend_and_wait(&[leaf_idx], &spend_tx)?;

    assert_eq!(result.len(), 0); // terminal
    assert_eq!(
        manager.instances[leaf_idx].status,
        ContractInstanceStatus::Spent
    );
    println!("test_leaf_reveal_bob passed!");
    Ok(())
}

#[test]
fn test_fraud_proof_full() -> Result<(), Box<dyn std::error::Error>> {
    let client = get_rpc_client("testwallet");
    ensure_funds(&client);
    let (alice_privkey, alice_pk, bob_privkey, bob_pk) = get_keys();

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

    let mut alice_signers: SignerMap = HashMap::new();
    alice_signers.insert(
        alice_pk,
        Box::new(HotSigner {
            privkey: alice_privkey,
        }),
    );

    let mut bob_signers: SignerMap = HashMap::new();
    bob_signers.insert(
        bob_pk,
        Box::new(HotSigner {
            privkey: bob_privkey,
        }),
    );

    let s0_contract = make_g256_s0(&params);
    let mut manager = ContractManager::new(&client, 0.1, true);

    // --- Step 1: Fund S0, Bob chooses x=2 ---
    let s0 = G256S0Instance::fund(&mut manager, s0_contract, vec![], AMOUNT)?;
    let (s1,) = s0.choose(&mut manager, x, &bob_signers)?;

    assert_eq!(manager.instances[s1.idx()].contract.name(), "G256_S1");
    let expected_s1_state = sha256(&<i32 as ClauseArg>::to_bytes(&x));
    assert_eq!(manager.instances[s1.idx()].data, expected_s1_state.to_vec());
    println!("S0 → S1 (Bob chose x={})", x);

    // --- Step 2: Alice reveals y=508 ---
    let t_a_root = t_a(0, n - 1);
    let (s2,) = s1.reveal(
        &mut manager,
        t_a_root.to_vec(),
        y,
        x,
        &alice_signers,
    )?;

    assert_eq!(manager.instances[s2.idx()].contract.name(), "G256_S2");
    let expected_s2_state = g256_s2_state(&t_a_root, y, x);
    assert_eq!(manager.instances[s2.idx()].data, expected_s2_state);
    println!("S1 → S2 (Alice claims y={})", y);

    // --- Step 3: Bob starts challenge with z=512 ---
    let s2_idx = s2.idx();
    let t_b_root = t_b(0, n - 1);
    {
        let mut args: ClauseArgs = HashMap::new();
        args.insert("t_a".to_string(), t_a_root.to_vec());
        args.insert("y".to_string(), <i32 as ClauseArg>::to_bytes(&y));
        args.insert("x".to_string(), <i32 as ClauseArg>::to_bytes(&x));
        args.insert("z".to_string(), <i32 as ClauseArg>::to_bytes(&z));
        args.insert("t_b".to_string(), t_b_root.to_vec());

        let new_indices =
            manager.spend_instance(s2_idx, "start_challenge", args, Some(&bob_signers))?;
        assert_eq!(new_indices.len(), 1);

        let bisect_idx = new_indices[0];
        assert_eq!(manager.instances[bisect_idx].contract.name(), "Bisect_1");
        let expected_state = bisect1_state(h_a[0], h_a[n], h_b[n], t_a(0, n - 1), t_b(0, n - 1));
        assert_eq!(manager.instances[bisect_idx].data, expected_state);
        println!("S2 → Bisect_1[0,7]");

        // --- Bisection protocol ---
        // Interval [0, 7], m = 4
        let (mut cur_i, mut cur_j) = (0usize, 7usize);
        let mut cur_idx = bisect_idx;

        // Step 4: Alice reveals → Bisect_2[0,7]
        {
            let m = (cur_j - cur_i + 1) / 2;
            let mut args: ClauseArgs = HashMap::new();
            args.insert("h_start".to_string(), h_a[cur_i].to_vec());
            args.insert("h_end_a".to_string(), h_a[cur_j + 1].to_vec());
            args.insert("h_end_b".to_string(), h_b[cur_j + 1].to_vec());
            args.insert("trace_a".to_string(), t_a(cur_i, cur_j).to_vec());
            args.insert("trace_b".to_string(), t_b(cur_i, cur_j).to_vec());
            args.insert("h_mid_a".to_string(), h_a[cur_i + m].to_vec());
            args.insert("trace_left_a".to_string(), t_a(cur_i, cur_i + m - 1).to_vec());
            args.insert("trace_right_a".to_string(), t_a(cur_i + m, cur_j).to_vec());

            let new_indices =
                manager.spend_instance(cur_idx, "alice_reveal", args, Some(&alice_signers))?;
            assert_eq!(new_indices.len(), 1);
            cur_idx = new_indices[0];
            assert_eq!(manager.instances[cur_idx].contract.name(), "Bisect_2");
            println!("Bisect_1[{},{}] → Bisect_2[{},{}] (Alice reveals)", cur_i, cur_j, cur_i, cur_j);
        }

        // Step 5: Bob reveals right (midstates agree at index 4) → Bisect_1[4,7]
        {
            let m = (cur_j - cur_i + 1) / 2;
            // h_a[cur_i+m] == h_b[cur_i+m] (both are h(32)), so right child
            assert_eq!(h_a[cur_i + m], h_b[cur_i + m]); // they agree at midpoint 4

            let mut args: ClauseArgs = HashMap::new();
            args.insert("h_start".to_string(), h_a[cur_i].to_vec());
            args.insert("h_end_a".to_string(), h_a[cur_j + 1].to_vec());
            args.insert("h_end_b".to_string(), h_b[cur_j + 1].to_vec());
            args.insert("trace_a".to_string(), t_a(cur_i, cur_j).to_vec());
            args.insert("trace_b".to_string(), t_b(cur_i, cur_j).to_vec());
            args.insert("h_mid_a".to_string(), h_a[cur_i + m].to_vec());
            args.insert("trace_left_a".to_string(), t_a(cur_i, cur_i + m - 1).to_vec());
            args.insert("trace_right_a".to_string(), t_a(cur_i + m, cur_j).to_vec());
            args.insert("h_mid_b".to_string(), h_b[cur_i + m].to_vec());
            args.insert("trace_left_b".to_string(), t_b(cur_i, cur_i + m - 1).to_vec());
            args.insert("trace_right_b".to_string(), t_b(cur_i + m, cur_j).to_vec());

            let new_indices =
                manager.spend_instance(cur_idx, "bob_reveal_right", args, Some(&bob_signers))?;
            assert_eq!(new_indices.len(), 1);

            // Update interval to right child [i+m, j]
            cur_i = cur_i + m;
            cur_idx = new_indices[0];
            assert_eq!(manager.instances[cur_idx].contract.name(), "Bisect_1");
            assert_eq!((cur_i, cur_j), (4, 7));
            println!("Bisect_2[0,7] → Bisect_1[4,7] (Bob reveals right)");
        }

        // Step 6: Alice reveals → Bisect_2[4,7]
        {
            let m = (cur_j - cur_i + 1) / 2;
            let mut args: ClauseArgs = HashMap::new();
            args.insert("h_start".to_string(), h_a[cur_i].to_vec());
            args.insert("h_end_a".to_string(), h_a[cur_j + 1].to_vec());
            args.insert("h_end_b".to_string(), h_b[cur_j + 1].to_vec());
            args.insert("trace_a".to_string(), t_a(cur_i, cur_j).to_vec());
            args.insert("trace_b".to_string(), t_b(cur_i, cur_j).to_vec());
            args.insert("h_mid_a".to_string(), h_a[cur_i + m].to_vec());
            args.insert("trace_left_a".to_string(), t_a(cur_i, cur_i + m - 1).to_vec());
            args.insert("trace_right_a".to_string(), t_a(cur_i + m, cur_j).to_vec());

            let new_indices =
                manager.spend_instance(cur_idx, "alice_reveal", args, Some(&alice_signers))?;
            assert_eq!(new_indices.len(), 1);
            cur_idx = new_indices[0];
            assert_eq!(manager.instances[cur_idx].contract.name(), "Bisect_2");
            println!("Bisect_1[4,7] → Bisect_2[4,7] (Alice reveals)");
        }

        // Step 7: Bob reveals left (midstates differ at index 6) → Bisect_1[4,5]
        {
            let m = (cur_j - cur_i + 1) / 2;
            // h_a[cur_i+m] = h_a[6] = h(127), h_b[cur_i+m] = h_b[6] = h(128)
            assert_ne!(h_a[cur_i + m], h_b[cur_i + m]); // they differ at midpoint 6

            let mut args: ClauseArgs = HashMap::new();
            args.insert("h_start".to_string(), h_a[cur_i].to_vec());
            args.insert("h_end_a".to_string(), h_a[cur_j + 1].to_vec());
            args.insert("h_end_b".to_string(), h_b[cur_j + 1].to_vec());
            args.insert("trace_a".to_string(), t_a(cur_i, cur_j).to_vec());
            args.insert("trace_b".to_string(), t_b(cur_i, cur_j).to_vec());
            args.insert("h_mid_a".to_string(), h_a[cur_i + m].to_vec());
            args.insert("trace_left_a".to_string(), t_a(cur_i, cur_i + m - 1).to_vec());
            args.insert("trace_right_a".to_string(), t_a(cur_i + m, cur_j).to_vec());
            args.insert("h_mid_b".to_string(), h_b[cur_i + m].to_vec());
            args.insert("trace_left_b".to_string(), t_b(cur_i, cur_i + m - 1).to_vec());
            args.insert("trace_right_b".to_string(), t_b(cur_i + m, cur_j).to_vec());

            let new_indices =
                manager.spend_instance(cur_idx, "bob_reveal_left", args, Some(&bob_signers))?;
            assert_eq!(new_indices.len(), 1);

            // Update interval to left child [i, i+m-1]
            cur_j = cur_i + m - 1;
            cur_idx = new_indices[0];
            assert_eq!(manager.instances[cur_idx].contract.name(), "Bisect_1");
            assert_eq!((cur_i, cur_j), (4, 5));
            println!("Bisect_2[4,7] → Bisect_1[4,5] (Bob reveals left)");
        }

        // Step 8: Alice reveals → Bisect_2[4,5]
        {
            let m = (cur_j - cur_i + 1) / 2;
            let mut args: ClauseArgs = HashMap::new();
            args.insert("h_start".to_string(), h_a[cur_i].to_vec());
            args.insert("h_end_a".to_string(), h_a[cur_j + 1].to_vec());
            args.insert("h_end_b".to_string(), h_b[cur_j + 1].to_vec());
            args.insert("trace_a".to_string(), t_a(cur_i, cur_j).to_vec());
            args.insert("trace_b".to_string(), t_b(cur_i, cur_j).to_vec());
            args.insert("h_mid_a".to_string(), h_a[cur_i + m].to_vec());
            args.insert("trace_left_a".to_string(), t_a(cur_i, cur_i + m - 1).to_vec());
            args.insert("trace_right_a".to_string(), t_a(cur_i + m, cur_j).to_vec());

            let new_indices =
                manager.spend_instance(cur_idx, "alice_reveal", args, Some(&alice_signers))?;
            assert_eq!(new_indices.len(), 1);
            cur_idx = new_indices[0];
            assert_eq!(manager.instances[cur_idx].contract.name(), "Bisect_2");
            println!("Bisect_1[4,5] → Bisect_2[4,5] (Alice reveals)");
        }

        // Step 9: Bob reveals right (midstates agree at index 5) → Leaf
        {
            let m = (cur_j - cur_i + 1) / 2;
            assert_eq!(h_a[cur_i + m], h_b[cur_i + m]); // agree at 5

            let mut args: ClauseArgs = HashMap::new();
            args.insert("h_start".to_string(), h_a[cur_i].to_vec());
            args.insert("h_end_a".to_string(), h_a[cur_j + 1].to_vec());
            args.insert("h_end_b".to_string(), h_b[cur_j + 1].to_vec());
            args.insert("trace_a".to_string(), t_a(cur_i, cur_j).to_vec());
            args.insert("trace_b".to_string(), t_b(cur_i, cur_j).to_vec());
            args.insert("h_mid_a".to_string(), h_a[cur_i + m].to_vec());
            args.insert("trace_left_a".to_string(), t_a(cur_i, cur_i + m - 1).to_vec());
            args.insert("trace_right_a".to_string(), t_a(cur_i + m, cur_j).to_vec());
            args.insert("h_mid_b".to_string(), h_b[cur_i + m].to_vec());
            args.insert("trace_left_b".to_string(), t_b(cur_i, cur_i + m - 1).to_vec());
            args.insert("trace_right_b".to_string(), t_b(cur_i + m, cur_j).to_vec());

            let new_indices =
                manager.spend_instance(cur_idx, "bob_reveal_right", args, Some(&bob_signers))?;
            assert_eq!(new_indices.len(), 1);
            cur_idx = new_indices[0];
            assert_eq!(manager.instances[cur_idx].contract.name(), "Leaf");
            println!("Bisect_2[4,5] → Leaf (Bob reveals right)");
        }

        // Step 10: Bob proves correct computation on the leaf
        // Both agree h_start = h(bob_trace[5]) = h(64), but differ on h_end
        // Bob computes: 2*64 = 128 = bob_trace[6], which matches h_end_bob
        assert_eq!(alice_trace[5], bob_trace[5]); // agree on x_start
        assert_ne!(alice_trace[6], bob_trace[6]); // differ on x_end

        {
            let mut args: ClauseArgs = HashMap::new();
            args.insert("x".to_string(), <i32 as ClauseArg>::to_bytes(&bob_trace[5]));
            args.insert("h_y_a".to_string(), h_a[6].to_vec());

            let spend_tx = build_leaf_spend_tx(
                &manager,
                cur_idx,
                "bob_reveal",
                args,
                bob_pk,
                &bob_signers,
            )?;
            let result = manager.spend_and_wait(&[cur_idx], &spend_tx)?;
            assert_eq!(result.len(), 0); // terminal
            println!("Leaf → Bob wins! (proved 2*64=128)");
        }
    }

    println!("test_fraud_proof_full passed!");
    Ok(())
}
