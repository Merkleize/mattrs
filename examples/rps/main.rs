//! Two-player Rock-Paper-Scissors over a MATT covenant (regtest).
//!
//! Ports pymatt's `examples/rps/rps.py`: two processes negotiate a game over a
//! TCP socket, then play it entirely on-chain. Each side is a declarative
//! protocol role (see `contracts::roles`) — a table of "at this game state,
//! send this transaction / watch for the counterparty's" — driven by a
//! [`Runner`] that builds, broadcasts, and observes the spends.
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
//!
//! Omit the move flag to be prompted for one. With `--inspector` (and a build
//! with `--features inspector`) the manager also serves live state snapshots
//! for the `mattrs-inspector` TUI:
//!
//! ```sh
//! cargo run --example rps --features inspector -- --alice --inspector
//! cargo run -p mattrs-inspector
//! ```

#[allow(dead_code)]
mod contracts;

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::str::FromStr;

use bitcoin::bip32::Xpriv;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, OutPoint, Txid, XOnlyPublicKey};
use bitcoincore_rpc::Client;
use mattrs::manager::ContractManager;
use mattrs::protocol::{ProtocolError, RpcChain, Runner};

use contracts::roles::{AliceData, BobData, alice_role, bob_role, clause_of};
use contracts::{DEFAULT_STAKE, RpsGameS0, RpsParams, alice_move_commitment};

type AppResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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

fn urandom<const N: usize>() -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
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
    serde_json::from_str(&line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn hex32(value: &serde_json::Value, key: &str) -> AppResult<[u8; 32]> {
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

fn u32_field(value: &serde_json::Value, key: &str) -> AppResult<u32> {
    let value = value
        .get(key)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| format!("missing or invalid '{key}' in peer message"))?;
    Ok(u32::try_from(value).map_err(|_| format!("'{key}' exceeds u32::MAX"))?)
}

// ----------------------------------------------------------------------------
// Alice: commits to a hidden move, funds the game, adjudicates
// ----------------------------------------------------------------------------

fn run_alice(m_a: i64, addr: &str, wallet: &str, inspector: Option<u16>) -> AppResult {
    let xpriv = Xpriv::from_str(ALICE_XPRIV)?;
    let pk_a = xonly(&xpriv);

    let r_a: [u8; 32] = urandom()?;
    let c_a = alice_move_commitment(m_a, &r_a);
    println!(
        "Alice plays {} (hidden behind commitment {})",
        move_str(m_a),
        hex::encode(c_a)
    );

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
    let mut manager = ContractManager::new(client, bitcoin::Network::Regtest);
    maybe_enable_inspector(&mut manager, inspector);
    let s0 =
        RpsGameS0::new(params)?.fund(&mut manager, Amount::from_sat((2 * DEFAULT_STAKE) as u64))?;
    let entry = s0.handle().clone();
    let outpoint = entry.outpoint().expect("just funded");
    println!("Game funded at {outpoint}");
    send_json(
        &mut stream,
        serde_json::json!({ "txid": outpoint.txid.to_string(), "vout": outpoint.vout }),
    )?;

    // Alice's role does the rest: watch S0 for Bob's move (revealed in his
    // spend's witness), then adjudicate by revealing (m_a, r_a) — only the
    // true outcome's clause validates, and its CTV template pays the pot.
    println!("Waiting for Bob's move on-chain...");
    let data = AliceData {
        m_a,
        r_a,
        before_adjudicating: Some(Box::new(|m_b, result| {
            println!("Bob played {}", move_str(m_b));
            println!("Outcome: {}", clause_of(result).name());
            wait_for_enter("Press ENTER to broadcast the adjudication transaction...")
                .map_err(|e| ProtocolError::Other(format!("failed to read confirmation: {e}")))
        })),
    };
    let chain = Rc::new(RpcChain::new(rpc_client(wallet)));
    // Run with no time limit: a human counterparty takes their time.
    let outcome = Runner::new(manager, chain, alice_role(), data, entry).run_one()?;
    println!(
        "Game over: {} (pot: {} sats)",
        clause_of(outcome.result).name(),
        2 * DEFAULT_STAKE
    );
    Ok(())
}

// ----------------------------------------------------------------------------
// Bob: tracks the funded game, reveals his move, observes the outcome
// ----------------------------------------------------------------------------

fn run_bob(m_b: i64, addr: &str, wallet: &str, inspector: Option<u16>) -> AppResult {
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
        vout: u32_field(&msg, "vout")?,
    };
    let client = rpc_client(wallet);
    let mut manager = ContractManager::new(client, bitcoin::Network::Regtest);
    maybe_enable_inspector(&mut manager, inspector);
    let entry = manager.track_instance(RpsGameS0::new(params)?.as_erased(), None, outpoint)?;
    println!("Tracking the game at {outpoint}");

    // Bob's role does the rest: reveal the move on-chain (signed), then follow
    // Alice's adjudication — checking her revealed move against her commitment
    // and the outcome against the game rule.
    println!("Bob plays {} — broadcasting the move", move_str(m_b));
    println!("Then waiting for Alice's adjudication on-chain...");
    let data = BobData { m_b, c_a, xpriv };
    let chain = Rc::new(RpcChain::new(rpc_client(wallet)));
    let outcome = Runner::new(manager, chain, bob_role(), data, entry).run_one()?;
    println!("Alice played {}", move_str(outcome.m_a));
    println!(
        "Game over: {} (pot: {} sats)",
        clause_of(outcome.result).name(),
        2 * DEFAULT_STAKE
    );
    Ok(())
}

// ----------------------------------------------------------------------------
// CLI
// ----------------------------------------------------------------------------

fn prompt_move() -> io::Result<i64> {
    let stdin = io::stdin();
    loop {
        print!("Choose your move [r]ock, [p]aper, [s]cissors: ");
        io::stdout().flush()?;

        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        match line.trim().to_lowercase().as_str() {
            "r" | "rock" => return Ok(0),
            "p" | "paper" => return Ok(1),
            "s" | "scissors" => return Ok(2),
            _ => println!("Invalid choice. Please enter r, p, or s."),
        }
    }
}

fn wait_for_enter(msg: &str) -> io::Result<()> {
    print!("{msg}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(())
}

/// Start the manager's inspector server when `--inspector` was given (and the
/// binary was built with the `inspector` feature).
#[cfg(feature = "inspector")]
fn maybe_enable_inspector(manager: &mut ContractManager, port: Option<u16>) {
    if let Some(port) = port {
        manager.enable_inspector(port);
        println!("Inspector server on 127.0.0.1:{port} (run `cargo run -p mattrs-inspector`)");
    }
}

#[cfg(not(feature = "inspector"))]
fn maybe_enable_inspector(_manager: &mut ContractManager, port: Option<u16>) {
    if port.is_some() {
        eprintln!("warning: built without the `inspector` feature; --inspector is ignored");
        eprintln!("         (rebuild with `--features inspector`)");
    }
}

fn main() -> AppResult {
    let mut role: Option<&str> = None;
    let mut mv: Option<i64> = None;
    let mut addr = "127.0.0.1:12345".to_string();
    let mut wallet = "testwallet".to_string();
    let mut inspector: Option<u16> = None;

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
            "--inspector" => inspector = inspector.or(Some(34443)),
            "--inspector-port" => {
                inspector = Some(it.next().ok_or("--inspector-port needs a value")?.parse()?)
            }
            other => {
                return Err(
                    format!("unknown argument `{other}` (see --help in the module doc)").into(),
                );
            }
        }
    }

    let mv = match mv {
        Some(mv) => mv,
        None => prompt_move()?,
    };

    match role {
        Some("alice") => run_alice(mv, &addr, &wallet, inspector),
        Some("bob") => run_bob(mv, &addr, &wallet, inspector),
        _ => Err("pass --alice or --bob (and optionally --rock/--paper/--scissors, --addr host:port, --wallet name, --inspector)".into()),
    }
}
