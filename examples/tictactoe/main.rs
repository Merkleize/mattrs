//! Two-player tic-tac-toe over a MATT covenant (regtest).
//!
//! Two processes negotiate a game over a TCP socket, then play it entirely
//! on-chain: the board lives in the UTXO (see `contracts.rs`), every move is a
//! covenant spend re-committing the updated board, and the finished game is
//! adjudicated by a win/tie clause whose CTV template pays the pot. Each side
//! is a declarative protocol role (`contracts::roles`) driven by a [`Runner`];
//! the human only picks cells.
//!
//! Protocol:
//! 1. Alice sends Bob her pubkey and the game parameters (stake, timeout);
//!    Bob replies with his pubkey. Both build the same `TicTacToe` contract.
//! 2. Alice funds it with both stakes and sends Bob the outpoint, which he
//!    tracks (verifying it pays the contract).
//! 3. Moves alternate on-chain (Alice is X and starts). When the board shows
//!    a line — or fills up — the runner of whoever benefits broadcasts the
//!    claim; if a player idles past the timeout, the opponent's runner claims
//!    the forfait instead (blocks must be mined for that clock to run).
//!
//! Run against a regtest bitcoind with a funded `testwallet` (cookie auth or
//! `BITCOIN_RPC_*` env vars), in two terminals:
//!
//! ```sh
//! cargo run --example tictactoe -- --alice
//! cargo run --example tictactoe -- --bob
//! ```
//!
//! With `--inspector` (and a build with `--features inspector`) the manager
//! also serves live state snapshots for the `mattrs-inspector` TUI.

#[allow(dead_code)]
mod contracts;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::str::FromStr;

use bitcoin::bip32::Xpriv;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, OutPoint, Txid, XOnlyPublicKey};
use bitcoincore_rpc::Client;
use mattrs::contracts::ErasedState;
use mattrs::manager::ContractManager;
use mattrs::protocol::{ProtocolError, RpcChain, Runner};

use contracts::roles::{PlayerData, Strategy, TttOutcome, TttResult, alice_role, bob_role};
use contracts::{
    DEFAULT_STAKE, DEFAULT_TIMEOUT_BLOCKS, EMPTY, MARK_ALICE, MARK_BOB, TicTacToe, TttParams,
    TttState,
};

type AppResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Demo keys (the pymatt reference fixtures; never use on mainnet).
const ALICE_XPRIV: &str = "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN";
const BOB_XPRIV: &str = "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ";

/// RPC client for the local regtest node (see `mattrs::manager::regtest_rpc_client`).
fn rpc_client(wallet_name: &str) -> Client {
    mattrs::manager::regtest_rpc_client(wallet_name)
}

fn xonly(xpriv: &Xpriv) -> XOnlyPublicKey {
    xpriv.to_priv().public_key(&Secp256k1::new()).into()
}

// ----------------------------------------------------------------------------
// Board rendering and the human strategy
// ----------------------------------------------------------------------------

/// The board as a grid: marks show as X/O, empty cells as their index.
fn render_board(board: &[u8; 9]) -> String {
    let cell = |i: usize| match board[i] {
        MARK_ALICE => "X".to_string(),
        MARK_BOB => "O".to_string(),
        _ => i.to_string(),
    };
    format!(
        " {} | {} | {}\n---+---+---\n {} | {} | {}\n---+---+---\n {} | {} | {}",
        cell(0),
        cell(1),
        cell(2),
        cell(3),
        cell(4),
        cell(5),
        cell(6),
        cell(7),
        cell(8),
    )
}

/// A [`Strategy`] prompting the human for an empty cell index.
fn prompt_strategy() -> Strategy {
    Box::new(|board: &[u8; 9]| {
        println!("\n{}\n", render_board(board));
        let stdin = std::io::stdin();
        loop {
            print!("Your move [0-8]: ");
            std::io::stdout()
                .flush()
                .map_err(|e| ProtocolError::Other(format!("failed to flush the prompt: {e}")))?;
            let mut line = String::new();
            stdin
                .lock()
                .read_line(&mut line)
                .map_err(|e| ProtocolError::Other(format!("failed to read a move: {e}")))?;
            match line.trim().parse::<usize>() {
                Ok(cell) if cell < 9 && board[cell] == EMPTY => return Ok(cell),
                _ => println!("Invalid or taken cell — pick an empty one from the grid."),
            }
        }
    })
}

fn print_outcome(outcome: &TttOutcome, stake: i64) {
    println!("\nFinal board:\n{}\n", render_board(&outcome.board));
    let how = if outcome.by_timeout {
        " (the opponent idled past the timeout)"
    } else {
        ""
    };
    match outcome.result {
        TttResult::AliceWins => println!("Alice (X) takes the pot: {} sats{how}", 2 * stake),
        TttResult::BobWins => println!("Bob (O) takes the pot: {} sats{how}", 2 * stake),
        TttResult::Tie => println!("Tie: each player gets their {stake} sats back"),
    }
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

fn pubkey_of(value: &serde_json::Value, key: &str) -> AppResult<XOnlyPublicKey> {
    Ok(XOnlyPublicKey::from_str(
        value
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("missing '{}' in peer message", key))?,
    )?)
}

fn u32_field(value: &serde_json::Value, key: &str) -> AppResult<u32> {
    let value = value
        .get(key)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| format!("missing or invalid '{key}' in peer message"))?;
    Ok(u32::try_from(value).map_err(|_| format!("'{key}' exceeds u32::MAX"))?)
}

fn validate_terms(stake: i64, timeout_blocks: u32) -> AppResult {
    if stake <= 0 || stake > i64::MAX / 2 {
        return Err("stake must be positive and small enough to double".into());
    }
    if timeout_blocks == 0 {
        return Err("timeout must be at least one block".into());
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// Alice: proposes the game, funds it, plays X
// ----------------------------------------------------------------------------

fn run_alice(
    addr: &str,
    wallet: &str,
    stake: i64,
    timeout_blocks: u32,
    inspector: Option<u16>,
) -> AppResult {
    validate_terms(stake, timeout_blocks)?;
    let xpriv = Xpriv::from_str(ALICE_XPRIV)?;
    let pk_a = xonly(&xpriv);

    println!("Waiting for Bob on {addr}...");
    let listener = TcpListener::bind(addr)?;
    let (mut stream, peer) = listener.accept()?;
    println!("Bob connected from {peer}");
    let mut reader = BufReader::new(stream.try_clone()?);

    send_json(
        &mut stream,
        serde_json::json!({
            "pk_a": pk_a.to_string(),
            "stake": stake,
            "timeout_blocks": timeout_blocks,
        }),
    )?;
    let msg = recv_json(&mut reader)?;
    let pk_b = pubkey_of(&msg, "pk_b")?;

    let params = TttParams {
        alice_pk: pk_a,
        bob_pk: pk_b,
        stake,
        timeout_blocks,
    };

    // Fund the game with both stakes and tell Bob where it lives.
    let client = rpc_client(wallet);
    let mut manager = ContractManager::new(client, bitcoin::Network::Regtest);
    maybe_enable_inspector(&mut manager, inspector)?;
    let game = TicTacToe::new(params)?.fund(
        &mut manager,
        Amount::from_sat((2 * stake) as u64),
        TttState::initial(),
    )?;
    let entry = game.handle().clone();
    let outpoint = entry.outpoint().expect("just funded");
    println!("Game funded at {outpoint}");
    send_json(
        &mut stream,
        serde_json::json!({ "txid": outpoint.txid.to_string(), "vout": outpoint.vout }),
    )?;

    println!("You are X and you move first.");
    let data = PlayerData {
        xpriv,
        strategy: prompt_strategy(),
    };
    let chain = Rc::new(RpcChain::new(rpc_client(wallet)));
    let outcome = Runner::new(manager, chain, alice_role(), data, entry).run_one()?;
    print_outcome(&outcome, stake);
    Ok(())
}

// ----------------------------------------------------------------------------
// Bob: accepts the game, tracks the funding, plays O
// ----------------------------------------------------------------------------

fn run_bob(addr: &str, wallet: &str, inspector: Option<u16>) -> AppResult {
    let xpriv = Xpriv::from_str(BOB_XPRIV)?;
    let pk_b = xonly(&xpriv);

    println!("Connecting to Alice at {addr}...");
    let mut stream = TcpStream::connect(addr)?;
    let mut reader = BufReader::new(stream.try_clone()?);

    let msg = recv_json(&mut reader)?;
    let pk_a = pubkey_of(&msg, "pk_a")?;
    let stake = msg
        .get("stake")
        .and_then(|v| v.as_i64())
        .ok_or("missing 'stake' in peer message")?;
    let timeout_blocks = u32_field(&msg, "timeout_blocks")?;
    validate_terms(stake, timeout_blocks)?;
    println!("Game proposal: stake {stake} sats, forfait timeout {timeout_blocks} blocks");
    send_json(&mut stream, serde_json::json!({ "pk_b": pk_b.to_string() }))?;

    let params = TttParams {
        alice_pk: pk_a,
        bob_pk: pk_b,
        stake,
        timeout_blocks,
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
    maybe_enable_inspector(&mut manager, inspector)?;
    let entry = manager.track_instance(
        TicTacToe::new(params)?.as_erased(),
        Some(Box::new(TttState::initial()) as Box<dyn ErasedState>),
        outpoint,
    )?;
    println!("Tracking the game at {outpoint}");

    println!("You are O; waiting for Alice's first move on-chain...");
    let data = PlayerData {
        xpriv,
        strategy: prompt_strategy(),
    };
    let chain = Rc::new(RpcChain::new(rpc_client(wallet)));
    let outcome = Runner::new(manager, chain, bob_role(), data, entry).run_one()?;
    print_outcome(&outcome, stake);
    Ok(())
}

// ----------------------------------------------------------------------------
// CLI
// ----------------------------------------------------------------------------

/// Start the manager's inspector server when `--inspector` was given (and the
/// binary was built with the `inspector` feature).
#[cfg(feature = "inspector")]
fn maybe_enable_inspector(manager: &mut ContractManager, port: Option<u16>) -> AppResult {
    if let Some(port) = port {
        manager.enable_inspector(port)?;
        println!("Inspector server on 127.0.0.1:{port} (run `cargo run -p mattrs-inspector`)");
    }
    Ok(())
}

#[cfg(not(feature = "inspector"))]
fn maybe_enable_inspector(_manager: &mut ContractManager, port: Option<u16>) -> AppResult {
    if port.is_some() {
        eprintln!("warning: built without the `inspector` feature; --inspector is ignored");
        eprintln!("         (rebuild with `--features inspector`)");
    }
    Ok(())
}

fn main() -> AppResult {
    let mut role: Option<&str> = None;
    let mut addr = "127.0.0.1:12345".to_string();
    let mut wallet = "testwallet".to_string();
    let mut stake = DEFAULT_STAKE;
    let mut timeout_blocks = DEFAULT_TIMEOUT_BLOCKS;
    let mut inspector: Option<u16> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--alice" | "-A" => role = Some("alice"),
            "--bob" | "-B" => role = Some("bob"),
            "--addr" => addr = it.next().ok_or("--addr needs a value")?.clone(),
            "--wallet" => wallet = it.next().ok_or("--wallet needs a value")?.clone(),
            "--stake" => stake = it.next().ok_or("--stake needs a value")?.parse()?,
            "--timeout" => timeout_blocks = it.next().ok_or("--timeout needs a value")?.parse()?,
            "--inspector" => inspector = inspector.or(Some(34443)),
            "--inspector-port" => {
                inspector = Some(it.next().ok_or("--inspector-port needs a value")?.parse()?)
            }
            other => {
                return Err(format!(
                    "unknown argument `{other}` (see the module doc; --stake/--timeout are Alice's)"
                )
                .into());
            }
        }
    }

    match role {
        Some("alice") => run_alice(&addr, &wallet, stake, timeout_blocks, inspector),
        Some("bob") => run_bob(&addr, &wallet, inspector),
        _ => Err(
            "pass --alice or --bob (and optionally --addr host:port, --wallet name, \
             --stake sats, --timeout blocks, --inspector)"
                .into(),
        ),
    }
}
