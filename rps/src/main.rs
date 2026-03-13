use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::time::Duration;

use bitcoin::{
    bip32::Xpriv,
    key::Secp256k1,
    secp256k1::rand::{thread_rng, RngCore},
    Amount, TxOut, XOnlyPublicKey,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clap::Parser;

use mattrs::{
    contracts::{ClauseArg, ClauseArgs, Contract, ContractInstance},
    manager::{ContractManager, SpendOptions},
    signer::{HotSigner, SignerMap},
};
use mattrs_examples::rps::*;

const ALICE_TPRV: &str = "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN";
const BOB_TPRV: &str = "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ";
const DEFAULT_STAKE: u64 = 1000;

fn move_str(m: i32) -> &'static str {
    match m {
        0 => "rock",
        1 => "paper",
        2 => "scissors",
        _ => "unknown",
    }
}

#[derive(Parser)]
#[command(name = "rps", about = "Rock-Paper-Scissors over Bitcoin")]
struct Cli {
    /// Play as Alice
    #[arg(long, group = "player")]
    alice: bool,

    /// Play as Bob
    #[arg(long, group = "player")]
    bob: bool,

    /// Play Rock
    #[arg(long, group = "move_choice")]
    rock: bool,

    /// Play Paper
    #[arg(long, group = "move_choice")]
    paper: bool,

    /// Play Scissors
    #[arg(long, group = "move_choice")]
    scissors: bool,

    /// Mine blocks automatically
    #[arg(short, long)]
    mine_automatically: bool,

    /// Host address
    #[arg(long, default_value = "localhost")]
    host: String,

    /// Port number
    #[arg(long, default_value_t = 12345)]
    port: u16,
}

impl Cli {
    fn chosen_move(&self) -> i32 {
        if self.rock {
            0
        } else if self.paper {
            1
        } else if self.scissors {
            2
        } else {
            let mut rng = thread_rng();
            (rng.next_u32() % 3) as i32
        }
    }
}

fn get_rpc_client(wallet_name: &str) -> Client {
    let rpc_url =
        std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_user = std::env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "rpcuser".to_string());
    let rpc_pass = std::env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "rpcpass".to_string());

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
    let alice_privkey = Xpriv::from_str(ALICE_TPRV).unwrap();
    let alice_pk: XOnlyPublicKey = alice_privkey.to_priv().public_key(&secp).into();
    let bob_privkey = Xpriv::from_str(BOB_TPRV).unwrap();
    let bob_pk: XOnlyPublicKey = bob_privkey.to_priv().public_key(&secp).into();
    (alice_privkey, alice_pk, bob_privkey, bob_pk)
}

fn run_alice(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let (_alice_privkey, alice_pk, _bob_privkey, _bob_pk) = get_keys();
    let m_a = cli.chosen_move();

    println!("Alice's move: {} ({})", m_a, move_str(m_a));

    // Generate random commitment
    let r_a: [u8; 32] = {
        let mut buf = [0u8; 32];
        thread_rng().fill_bytes(&mut buf);
        buf
    };
    let c_a = calculate_hash(m_a, &r_a);

    println!("Waiting for Bob...");

    // TCP: listen and accept
    let listener = TcpListener::bind(format!("{}:{}", cli.host, cli.port))?;
    let (mut stream, _) = listener.accept()?;

    // Send c_a and pk_a to Bob
    let msg = serde_json::json!({
        "c_a": hex::encode(c_a),
        "pk_a": hex::encode(alice_pk.serialize()),
    });
    stream.write_all(msg.to_string().as_bytes())?;

    // Receive pk_b from Bob
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let bob_msg: serde_json::Value = serde_json::from_slice(&buf[..n])?;
    let pk_b_bytes = hex::decode(bob_msg["pk_b"].as_str().unwrap())?;
    let bob_pk = XOnlyPublicKey::from_slice(&pk_b_bytes)?;

    println!(
        "Alice's state: m_a={}, r_a={}, c_a={}, pk_a={}, pk_b={}",
        m_a,
        hex::encode(r_a),
        hex::encode(c_a),
        hex::encode(alice_pk.serialize()),
        hex::encode(bob_pk.serialize()),
    );

    let stake = DEFAULT_STAKE;
    let params = RpsParams {
        alice_pk,
        bob_pk,
        c_a,
        stake,
    };

    let client = get_rpc_client("testwallet");
    ensure_funds(&client);
    let mut mgr = ContractManager::new(&client, Duration::from_secs_f64(0.1), cli.mine_automatically);

    let s0_contract = make_rps_s0(&params);

    let s0_idx = if cli.mine_automatically {
        mgr.fund_instance(s0_contract, vec![], Amount::from_sat(2 * stake))?
    } else {
        let inst = ContractInstance::new(s0_contract, vec![]);
        let idx = mgr.add_instance(inst);
        println!("Waiting for funding to: {}", mgr.instance(idx).get_address());
        mgr.wait_for_output(idx, None, None)?
    };

    println!(
        "Outpoint: {}",
        mgr.instance(s0_idx).outpoint().unwrap()
    );
    println!("Waiting for Bob's move...");

    // Wait for Bob to spend S0
    let height = mgr.instance(s0_idx).last_height().unwrap_or(0);
    let s1_indices = mgr.wait_for_spend(&[s0_idx], height)?;

    // Read Bob's move from spending args
    let m_b = {
        let args = mgr.instance(s0_idx).spending_args().unwrap();
        let m_b_bytes = args.get("m_b").unwrap();
        bitcoin::script::read_scriptint(m_b_bytes).unwrap() as i32
    };

    println!("Bob's move: {} ({})", m_b, move_str(m_b));

    let outcome = adjudicate(m_a, m_b);
    println!("Game result: {}", outcome);

    // Build CTV outputs for outcome
    let alice_addr = Contract::new_opaque_p2tr(alice_pk).get_address(&vec![]);
    let bob_addr = Contract::new_opaque_p2tr(bob_pk).get_address(&vec![]);

    let ctv_outputs = match outcome {
        "alice_wins" => vec![TxOut {
            script_pubkey: alice_addr.script_pubkey(),
            value: Amount::from_sat(2 * stake),
        }],
        "bob_wins" => vec![TxOut {
            script_pubkey: bob_addr.script_pubkey(),
            value: Amount::from_sat(2 * stake),
        }],
        "tie" => vec![
            TxOut {
                script_pubkey: alice_addr.script_pubkey(),
                value: Amount::from_sat(stake),
            },
            TxOut {
                script_pubkey: bob_addr.script_pubkey(),
                value: Amount::from_sat(stake),
            },
        ],
        _ => unreachable!(),
    };

    // Build and broadcast the S1 adjudication tx
    let s1_idx = s1_indices[0];
    let mut clause_args: ClauseArgs = HashMap::new();
    clause_args.insert("m_b".to_string(), <i32 as ClauseArg>::to_bytes(&m_b));
    clause_args.insert("m_a".to_string(), <i32 as ClauseArg>::to_bytes(&m_a));
    clause_args.insert("r_a".to_string(), r_a.to_vec());

    mgr.spend_instance(s1_idx, outcome, clause_args, SpendOptions {
        outputs: Some(&ctv_outputs),
        ..Default::default()
    })?;

    let spend_tx = mgr.instance(s1_idx).spending_tx().unwrap();
    println!("Adjudication broadcasted. txid: {}", spend_tx.compute_txid());

    Ok(())
}

fn run_bob(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let (_alice_privkey, _alice_pk, bob_privkey, bob_pk) = get_keys();
    let m_b = cli.chosen_move();

    // TCP: connect to Alice
    let mut stream = TcpStream::connect(format!("{}:{}", cli.host, cli.port))?;

    // Receive c_a and pk_a from Alice
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let alice_msg: serde_json::Value = serde_json::from_slice(&buf[..n])?;
    let c_a_bytes = hex::decode(alice_msg["c_a"].as_str().unwrap())?;
    let pk_a_bytes = hex::decode(alice_msg["pk_a"].as_str().unwrap())?;
    let alice_pk = XOnlyPublicKey::from_slice(&pk_a_bytes)?;
    let mut c_a = [0u8; 32];
    c_a.copy_from_slice(&c_a_bytes);

    // Send pk_b to Alice
    let msg = serde_json::json!({
        "pk_b": hex::encode(bob_pk.serialize()),
    });
    stream.write_all(msg.to_string().as_bytes())?;

    println!(
        "Bob's state: c_a={}, pk_a={}, pk_b={}",
        hex::encode(c_a),
        hex::encode(alice_pk.serialize()),
        hex::encode(bob_pk.serialize()),
    );

    let stake = DEFAULT_STAKE;
    let params = RpsParams {
        alice_pk,
        bob_pk,
        c_a,
        stake,
    };

    let client = get_rpc_client("testwallet");
    let mut mgr = ContractManager::new(&client, Duration::from_secs_f64(0.1), cli.mine_automatically);

    let s0_contract = make_rps_s0(&params);
    let inst = ContractInstance::new(s0_contract, vec![]);
    let s0_idx = mgr.add_instance(inst);

    let address = mgr.instance(s0_idx).get_address();
    println!("Bob waiting for output: {}", address);

    // Wait for Alice's funding tx
    mgr.wait_for_output(s0_idx, None, None)?;

    // Play Bob's move
    let m_b_hash = mattrs::sha256(&<i32 as ClauseArg>::to_bytes(&m_b));
    println!("Bob's move: {} ({})", m_b, move_str(m_b));
    println!("Bob's move's hash: {}", hex::encode(m_b_hash));

    let mut signers: SignerMap = HashMap::new();
    signers.insert(bob_pk, Box::new(HotSigner { privkey: bob_privkey }));

    let mut args: ClauseArgs = HashMap::new();
    args.insert("m_b".to_string(), <i32 as ClauseArg>::to_bytes(&m_b));

    let s1_indices = mgr.spend_instance(s0_idx, "bob_move", args, SpendOptions {
        signers: Some(&signers),
        ..Default::default()
    })?;

    let txid = mgr.instance(s0_idx)
        .spending_tx()
        .unwrap()
        .compute_txid();
    println!("Bob's move broadcasted: {}. txid: {}", m_b, txid);

    println!("Waiting for adjudication");

    // Wait for Alice to adjudicate S1
    let s1_idx = s1_indices[0];
    let s1_height = mgr.instance(s1_idx).last_height().unwrap_or(0);
    mgr.wait_for_spend(&[s1_idx], s1_height)?;

    let outcome = mgr.instance(s1_idx)
        .spending_clause()
        .unwrap()
        .to_string();
    println!("Outcome: {}", outcome);

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if !cli.alice && !cli.bob {
        eprintln!("Error: must specify --alice or --bob");
        std::process::exit(1);
    }

    let result = if cli.alice {
        run_alice(&cli)
    } else {
        run_bob(&cli)
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
