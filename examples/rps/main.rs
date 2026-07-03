//! Two-player Rock-Paper-Scissors over a MATT covenant (regtest).
//!
//! Ports pymatt's `examples/rps/rps.py`: two processes negotiate a game over a
//! TCP socket, then play it entirely on-chain — each side drives its own turn
//! with the typed spend API and follows the counterparty's turn with chain
//! observation (`track_instance` / `wait_for_spend`).
//!
//! Protocol (see `contracts.rs` for the two on-chain stages):
//! 1. Alice picks a move `m_a` and a random nonce `r_a`, and sends Bob the
//!    hiding commitment `c_a = sha256(bn(m_a) || r_a)` plus her pubkey.
//! 2. Bob replies with his pubkey; both sides now construct the same
//!    `RpsGameS0` contract. Alice funds it with both stakes and sends Bob the
//!    funding outpoint, which he verifies and tracks.
//! 3. Bob reveals his move on-chain (`bob_move`, signed), committing
//!    `sha256(bn(m_b))` into `RpsGameS1`'s state. Alice observes the spend and
//!    decodes `m_b` from its witness.
//! 4. Alice adjudicates on-chain: revealing `(m_a, r_a)` satisfies exactly one
//!    of `alice_wins` / `bob_wins` / `tie`, whose CTV template pays the pot.
//!    Bob observes it, learns the outcome, and checks Alice's commitment.
//!
//! Run against a regtest bitcoind with a funded `testwallet` (cookie auth or
//! `BITCOIN_RPC_*` env vars), in two terminals:
//!
//! ```sh
//! cargo run --example rps -- --alice --rock
//! cargo run --example rps -- --bob --paper
//! ```

#[allow(dead_code)]
mod contracts;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;

use bitcoin::bip32::Xpriv;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, OutPoint, Txid, XOnlyPublicKey};
use bitcoincore_rpc::Client;
use mattrs::contracts::ClauseArgs;
use mattrs::manager::ContractManager;
use mattrs::signer::HotSigner;

use contracts::{
    alice_move_commitment, RpsGameS0, RpsGameS0BobMoveArgs, RpsGameS0Handle, RpsGameS1Handle,
    RpsGameS1TieArgs, RpsParams, DEFAULT_STAKE,
};

// Demo keys (the pymatt reference fixtures; never use on mainnet).
const ALICE_XPRIV: &str = "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN";
const BOB_XPRIV: &str = "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ";

fn move_str(m: i64) -> &'static str {
    match m {
        0 => "rock",
        1 => "paper",
        2 => "scissors",
        _ => unreachable!("moves are 0..=2"),
    }
}

/// The adjudication clause satisfied by `(m_a, m_b)`, per the contract's rule
/// `diff = (m_b - m_a) mod 3`: 0 = tie, 1 = Bob wins, 2 = Alice wins.
fn outcome_clause(m_a: i64, m_b: i64) -> &'static str {
    match (m_b - m_a).rem_euclid(3) {
        0 => "tie",
        1 => "bob_wins",
        _ => "alice_wins",
    }
}

fn urandom<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .expect("open /dev/urandom")
        .read_exact(&mut buf)
        .expect("read /dev/urandom");
    buf
}

/// RPC client for the local regtest node (see `mattrs::manager::regtest_rpc_client`).
fn rpc_client(wallet_name: &str) -> Client {
    mattrs::manager::regtest_rpc_client(wallet_name)
}

fn xonly(xpriv: &Xpriv) -> XOnlyPublicKey {
    xpriv.to_priv().public_key(&Secp256k1::new()).into()
}

// ----------------------------------------------------------------------------
// Socket messages (newline-delimited JSON)
// ----------------------------------------------------------------------------

fn send_json(stream: &mut TcpStream, value: serde_json::Value) -> std::io::Result<()> {
    let mut line = value.to_string();
    line.push('\n');
    stream.write_all(line.as_bytes())
}

fn recv_json(reader: &mut BufReader<TcpStream>) -> std::io::Result<serde_json::Value> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    serde_json::from_str(&line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn hex32(value: &serde_json::Value, key: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(
        value
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("missing '{}' in peer message", key))?,
    )?;
    Ok(bytes
        .try_into()
        .map_err(|_| format!("'{}' is not 32 bytes", key))?)
}

// ----------------------------------------------------------------------------
// Alice: commits to a hidden move, funds the game, adjudicates
// ----------------------------------------------------------------------------

fn run_alice(m_a: i64, addr: &str, wallet: &str) -> Result<(), Box<dyn std::error::Error>> {
    let xpriv = Xpriv::from_str(ALICE_XPRIV)?;
    let pk_a = xonly(&xpriv);

    let r_a: [u8; 32] = urandom();
    let c_a = alice_move_commitment(m_a, &r_a);
    println!("Alice plays {} (hidden behind commitment {})", move_str(m_a), hex::encode(c_a));

    println!("Waiting for Bob on {addr}...");
    let listener = TcpListener::bind(addr)?;
    let (mut stream, peer) = listener.accept()?;
    println!("Bob connected from {peer}");
    let mut reader = BufReader::new(stream.try_clone()?);

    send_json(
        &mut stream,
        serde_json::json!({ "c_a": hex::encode(c_a), "pk_a": pk_a.to_string() }),
    )?;
    let msg = recv_json(&mut reader)?;
    let pk_b = XOnlyPublicKey::from_slice(&hex32(&msg, "pk_b")?)?;

    let params = RpsParams {
        alice_pk: pk_a,
        bob_pk: pk_b,
        c_a,
        stake: DEFAULT_STAKE,
    };

    // Fund the game with both stakes and tell Bob where it lives.
    let client = rpc_client(wallet);
    let mut manager = ContractManager::new(client);
    let s0 = RpsGameS0::fund(
        &mut manager,
        Amount::from_sat((2 * DEFAULT_STAKE) as u64),
        params,
    )?;
    let outpoint = s0.handle().outpoint().expect("just funded");
    println!("Game funded at {outpoint}");
    send_json(
        &mut stream,
        serde_json::json!({ "txid": outpoint.txid.to_string(), "vout": outpoint.vout }),
    )?;

    // Follow Bob's turn: his spend reveals m_b in the witness.
    println!("Waiting for Bob's move on-chain...");
    // Wait with no time limit: a human counterparty takes their time.
    let children = manager.wait_for_spend_within(s0.handle(), None)?;
    let s1: RpsGameS1Handle = children
        .into_iter()
        .next()
        .expect("bob_move creates the S1 instance")
        .try_into()?;
    let bob_args =
        RpsGameS0BobMoveArgs::decode_from_witness(&s0.handle().spending_args().expect("spent"))?;
    let m_b = bob_args.m_b;
    println!("Bob played {}", move_str(m_b));

    // Adjudicate: reveal (m_a, r_a); only the true outcome's clause validates.
    let clause = outcome_clause(m_a, m_b);
    println!("Outcome: {clause} — broadcasting the adjudication");
    let builder = match clause {
        "tie" => s1.tie(m_b, m_a, r_a),
        "bob_wins" => s1.bob_wins(m_b, m_a, r_a),
        _ => s1.alice_wins(m_b, m_a, r_a),
    };
    builder.exec_none(&mut manager)?;
    println!("Game over: {clause} (pot: {} sats)", 2 * DEFAULT_STAKE);
    Ok(())
}

// ----------------------------------------------------------------------------
// Bob: tracks the funded game, reveals his move, observes the outcome
// ----------------------------------------------------------------------------

fn run_bob(m_b: i64, addr: &str, wallet: &str) -> Result<(), Box<dyn std::error::Error>> {
    let xpriv = Xpriv::from_str(BOB_XPRIV)?;
    let pk_b = xonly(&xpriv);

    println!("Connecting to Alice at {addr}...");
    let mut stream = TcpStream::connect(addr)?;
    let mut reader = BufReader::new(stream.try_clone()?);

    let msg = recv_json(&mut reader)?;
    let c_a = hex32(&msg, "c_a")?;
    let pk_a = XOnlyPublicKey::from_slice(&hex32(&msg, "pk_a")?)?;
    println!("Alice's commitment: {}", hex::encode(c_a));
    send_json(&mut stream, serde_json::json!({ "pk_b": pk_b.to_string() }))?;

    let params = RpsParams {
        alice_pk: pk_a,
        bob_pk: pk_b,
        c_a,
        stake: DEFAULT_STAKE,
    };

    // Track the game instance Alice funded (verifies it pays our contract).
    let msg = recv_json(&mut reader)?;
    let outpoint = OutPoint {
        txid: Txid::from_str(
            msg.get("txid")
                .and_then(|v| v.as_str())
                .ok_or("missing 'txid' in peer message")?,
        )?,
        vout: msg
            .get("vout")
            .and_then(|v| v.as_u64())
            .ok_or("missing 'vout' in peer message")? as u32,
    };
    let client = rpc_client(wallet);
    let mut manager = ContractManager::new(client);
    let s0: RpsGameS0Handle = manager
        .track_instance(RpsGameS0::new(params).as_erased(), None, outpoint)?
        .try_into()?;
    println!("Tracking the game at {outpoint}");

    // Bob's turn: reveal the move on-chain (signed).
    println!("Bob plays {} — broadcasting the move", move_str(m_b));
    let s1: RpsGameS1Handle = s0
        .bob_move(m_b)
        .sign(HotSigner::new(xpriv))
        .exec_one(&mut manager)?
        .try_into()?;

    // Follow Alice's adjudication and check her revealed commitment.
    println!("Waiting for Alice's adjudication on-chain...");
    manager.wait_for_spend_within(s1.handle(), None)?;
    let clause = s1.handle().clause_name().expect("spent");
    // The three adjudication clauses share one witness layout (m_b, m_a, r_a).
    let args =
        RpsGameS1TieArgs::decode_from_witness(&s1.handle().spending_args().expect("spent"))?;
    println!("Alice played {}", move_str(args.m_a));
    assert_eq!(
        alice_move_commitment(args.m_a, &args.r_a),
        c_a,
        "Alice's revealed move must match her commitment",
    );
    assert_eq!(clause, outcome_clause(args.m_a, m_b));
    println!("Game over: {clause} (pot: {} sats)", 2 * DEFAULT_STAKE);
    Ok(())
}

// ----------------------------------------------------------------------------
// CLI
// ----------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut role: Option<&str> = None;
    let mut mv: Option<i64> = None;
    let mut addr = "127.0.0.1:12345".to_string();
    let mut wallet = "testwallet".to_string();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--alice" | "-A" => role = Some("alice"),
            "--bob" | "-B" => role = Some("bob"),
            "--rock" => mv = Some(0),
            "--paper" => mv = Some(1),
            "--scissors" => mv = Some(2),
            "--addr" => addr = it.next().ok_or("--addr needs a value")?.clone(),
            "--wallet" => wallet = it.next().ok_or("--wallet needs a value")?.clone(),
            other => return Err(format!("unknown argument `{other}` (see --help in the module doc)").into()),
        }
    }

    let mv = mv.unwrap_or_else(|| {
        let m = (urandom::<1>()[0] % 3) as i64;
        println!("No move given; picking one at random.");
        m
    });

    match role {
        Some("alice") => run_alice(mv, &addr, &wallet),
        Some("bob") => run_bob(mv, &addr, &wallet),
        _ => Err("pass --alice or --bob (and optionally --rock/--paper/--scissors, --addr host:port, --wallet name)".into()),
    }
}
