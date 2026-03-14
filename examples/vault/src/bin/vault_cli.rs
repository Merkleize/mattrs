//! Interactive CLI for vault contracts, mirroring pymatt's vault.py.
//!
//! Commands:
//!   fund amount=<sats>         Fund a new vault instance
//!   list                       List all contract instances
//!   mine [n]                   Mine n blocks (default 1)
//!   printall                   Print markdown details of all spending txs
//!   trigger items="[i,...]" outputs="['addr:amt',...]"
//!                              Trigger vault(s) into unvaulting state
//!   recover item=<idx>         Recover from a funded vault or unvaulting instance
//!   withdraw item=<idx>        Withdraw from a funded unvaulting instance

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::{
    bip32::Xpriv, key::Secp256k1, Address, Amount, Sequence, TxOut, XOnlyPublicKey,
};
use bitcoincore_rpc::{Auth, Client};

use mattrs::{
    contracts::ContractInstanceStatus,
    ctv::make_ctv_template_hash,
    manager::{ContractManager, SpendOptions},
    report::format_tx_markdown,
    signer::{HotSigner, SignerMap},
};
use mattrs_vault::*;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Config, Editor, Helper};

// ---------------------------------------------------------------------------
// Readline helper with command completion
// ---------------------------------------------------------------------------

#[derive(Default)]
struct VaultHelper;

impl Helper for VaultHelper {}
impl Validator for VaultHelper {}
impl Highlighter for VaultHelper {}
impl Hinter for VaultHelper {
    type Hint = String;
}

impl Completer for VaultHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let commands = [
            ("fund", &["amount="][..]),
            ("list", &[][..]),
            ("mine", &[][..]),
            ("printall", &[][..]),
            ("trigger", &["items=\"[", "outputs=\"["][..]),
            ("recover", &["item="][..]),
            ("withdraw", &["item="][..]),
        ];

        let prefix = &line[..pos];
        if !prefix.contains(' ') {
            // Complete command names
            let matches: Vec<Pair> = commands
                .iter()
                .filter(|(cmd, _)| cmd.starts_with(prefix))
                .map(|(cmd, _)| Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                })
                .collect();
            Ok((0, matches))
        } else {
            // Complete arguments
            let cmd = prefix.split_whitespace().next().unwrap_or("");
            let word_start = prefix.rfind(' ').map(|i| i + 1).unwrap_or(0);
            let word = &prefix[word_start..];

            if let Some((_, args)) = commands.iter().find(|(c, _)| *c == cmd) {
                let matches: Vec<Pair> = args
                    .iter()
                    .filter(|a| a.starts_with(word) && !prefix[..word_start].contains(*a))
                    .map(|a| Pair {
                        display: a.to_string(),
                        replacement: a.to_string(),
                    })
                    .collect();
                Ok((word_start, matches))
            } else {
                Ok((pos, vec![]))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Argument parsing (matches pymatt's key=value style)
// ---------------------------------------------------------------------------

fn parse_args(input: &str) -> (String, HashMap<String, String>) {
    // Use shell-style splitting
    let parts: Vec<String> = shell_words(input);
    let action = parts.first().cloned().unwrap_or_default();
    let mut args = HashMap::new();
    let mut pos = 0usize;
    for item in &parts[1..] {
        if let Some((k, v)) = item.split_once('=') {
            args.insert(k.to_string(), v.to_string());
        } else {
            args.insert(format!("@{}", pos), item.clone());
            pos += 1;
        }
    }
    (action, args)
}

/// Simple shell-word splitting that respects double quotes and brackets.
fn shell_words(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut bracket_depth: i32 = 0;

    for ch in input.chars() {
        match ch {
            '"' if bracket_depth == 0 => {
                in_quotes = !in_quotes;
            }
            '[' if !in_quotes => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' if !in_quotes => {
                bracket_depth -= 1;
                current.push(ch);
            }
            ' ' | '\t' if !in_quotes && bracket_depth == 0 => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

// ---------------------------------------------------------------------------
// Output parsing: "addr:amount" strings
// ---------------------------------------------------------------------------

fn parse_outputs(output_strings: &[String]) -> Result<Vec<(Address, Amount)>, String> {
    let mut outputs = Vec::new();
    for s in output_strings {
        // address may contain colons (bech32 doesn't, but be safe); amount is after the last ':'
        let colon_pos = s
            .rfind(':')
            .ok_or_else(|| format!("Invalid output format (expected addr:amount): {}", s))?;
        let addr_str = &s[..colon_pos];
        let amount_str = &s[colon_pos + 1..];
        let amount: u64 = amount_str
            .parse()
            .map_err(|_| format!("Invalid amount: {}", amount_str))?;
        if amount == 0 {
            return Err(format!("Invalid amount for address {}: 0", addr_str));
        }
        let addr = Address::from_str(addr_str)
            .map_err(|e| format!("Invalid address {}: {}", addr_str, e))?
            .assume_checked();
        outputs.push((addr, Amount::from_sat(amount)));
    }
    Ok(outputs)
}

/// Parse a JSON array string like `["foo", "bar"]` or `[1, 2]` into a Vec of strings.
/// Also accepts single quotes for convenience (e.g. `['foo', 'bar']`).
fn parse_json_array(s: &str) -> Result<Vec<String>, String> {
    let normalized = s.replace('\'', "\"");
    let val: serde_json::Value =
        serde_json::from_str(&normalized).map_err(|e| format!("Invalid JSON: {}", e))?;
    match val {
        serde_json::Value::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                serde_json::Value::String(s) => Ok(s),
                serde_json::Value::Number(n) => Ok(n.to_string()),
                other => Err(format!("Unexpected array element: {}", other)),
            })
            .collect(),
        _ => Err("Expected a JSON array".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Instance value helper
// ---------------------------------------------------------------------------

fn instance_value(manager: &ContractManager, idx: usize) -> Amount {
    let inst = manager.instance(idx);
    match (inst.funding_tx(), inst.outpoint()) {
        (Some(tx), Some(op)) => tx.output[op.vout as usize].value,
        _ => Amount::ZERO,
    }
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

struct CliState<'a> {
    manager: ContractManager<'a>,
    vault_contract: mattrs::contracts::Contract,
    signers: SignerMap,
    spend_delay: u32,
    /// Maps CTV hash -> (ctv_template outputs, sequence) for later withdrawal
    ctv_templates: HashMap<[u8; 32], (Vec<(Address, Amount)>, Sequence)>,
}

fn execute_command(state: &mut CliState, input: &str) -> Result<(), Box<dyn std::error::Error>> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(());
    }

    let (action, args) = parse_args(trimmed);

    match action.as_str() {
        "fund" => cmd_fund(state, &args),
        "list" => cmd_list(state),
        "mine" => cmd_mine(state, &args),
        "printall" => cmd_printall(state),
        "trigger" => cmd_trigger(state, &args),
        "recover" => cmd_recover(state, &args),
        "withdraw" => cmd_withdraw(state, &args),
        _ => {
            println!("Unknown command: {}", action);
            Ok(())
        }
    }
}

fn cmd_fund(
    state: &mut CliState,
    args: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let amount: u64 = args
        .get("amount")
        .ok_or("Missing argument: amount")?
        .parse()?;
    let idx = state.manager.fund_instance(
        state.vault_contract.clone(),
        vec![],
        Amount::from_sat(amount),
    )?;
    let outpoint = state.manager.instance(idx).outpoint().unwrap();
    println!("Funded vault instance {} at {}", idx, outpoint);
    Ok(())
}

fn cmd_list(state: &mut CliState) -> Result<(), Box<dyn std::error::Error>> {
    for i in 0..state.manager.instance_count() {
        let inst = state.manager.instance(i);
        let status = match inst.status() {
            ContractInstanceStatus::Abstract => "ABSTRACT",
            ContractInstanceStatus::Funded => "FUNDED",
            ContractInstanceStatus::Spent => "SPENT",
        };
        let data = if inst.data().is_empty() {
            "None".to_string()
        } else {
            hex::encode(inst.data())
        };
        let value = instance_value(&state.manager, i);
        let outpoint = inst
            .outpoint()
            .map(|o| format!("{}:{}", o.txid, o.vout))
            .unwrap_or_else(|| "N/A".to_string());
        println!(
            "{} {} {} data={} value={} outpoint={}",
            i,
            status,
            inst.contract().name(),
            data,
            value.to_sat(),
            outpoint,
        );
    }
    Ok(())
}

fn cmd_mine(
    state: &mut CliState,
    args: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let n: u64 = args
        .get("@0")
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(1);
    state.manager.mine_blocks(n)?;
    println!("Mined {} block(s)", n);
    Ok(())
}

fn cmd_printall(state: &mut CliState) -> Result<(), Box<dyn std::error::Error>> {
    let mut seen = std::collections::HashSet::new();
    for i in 0..state.manager.instance_count() {
        let inst = state.manager.instance(i);
        if let Some(tx) = inst.spending_tx() {
            let txid = tx.compute_txid();
            if seen.insert(txid) {
                let label = inst.contract().name();
                println!("{}", format_tx_markdown(tx, label));
            }
        }
    }
    Ok(())
}

fn cmd_trigger(
    state: &mut CliState,
    args: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let items_str = args.get("items").ok_or("Missing argument: items")?;
    let items_idx: Vec<usize> = parse_json_array(items_str)?
        .iter()
        .map(|s| s.parse::<usize>())
        .collect::<Result<Vec<_>, _>>()?;

    println!("Triggering: {:?}", items_idx);

    if items_idx.is_empty() {
        return Err("Empty items list".into());
    }

    // Validate all items
    for &idx in &items_idx {
        if idx >= state.manager.instance_count() {
            return Err(format!("No such instance: {}", idx).into());
        }
        let inst = state.manager.instance(idx);
        if inst.status() != ContractInstanceStatus::Funded {
            return Err(format!("Instance {} is not FUNDED", idx).into());
        }
        if inst.contract().name() != "Vault" {
            return Err(format!("Instance {} is not a Vault", idx).into());
        }
    }

    // Parse outputs
    let outputs_str = args.get("outputs").ok_or("Missing argument: outputs")?;
    let output_strings = parse_json_array(outputs_str)?;
    let outputs = parse_outputs(&output_strings)?;

    let outputs_total: u64 = outputs.iter().map(|(_, a)| a.to_sat()).sum();
    let inputs_total: u64 = items_idx
        .iter()
        .map(|&i| instance_value(&state.manager, i).to_sat())
        .sum();

    if outputs_total > inputs_total {
        return Err("Outputs amount exceeds inputs amount".into());
    }

    let revault_amount = inputs_total - outputs_total;

    let sequence = Sequence(state.spend_delay as u32);
    let ctv_hash = make_ctv_template_hash(&outputs, sequence)?;

    // Sort by decreasing value
    let mut sorted_items: Vec<usize> = items_idx.clone();
    sorted_items.sort_by(|a, b| {
        instance_value(&state.manager, *b)
            .cmp(&instance_value(&state.manager, *a))
    });

    // Build spend specs
    let mut spends = Vec::new();
    for (i, &idx) in sorted_items.iter().enumerate() {
        if i == 0 && revault_amount > 0 {
            let v = instance_value(&state.manager, idx).to_sat();
            if revault_amount > v {
                return Err(format!(
                    "Input amount {} is not enough for revault amount {}",
                    v, revault_amount
                )
                .into());
            }
            let mut clause_args = HashMap::new();
            clause_args.insert("ctv_hash".to_string(), ctv_hash.to_vec());
            clause_args.insert("out_i".to_string(), encode_scriptint(0));
            clause_args.insert("revault_out_i".to_string(), encode_scriptint(1));

            spends.push(mattrs::manager::SpendSpec {
                instance_idx: idx,
                clause_name: "trigger_and_revault".to_string(),
                args: clause_args,
                sequence: Sequence::ZERO,
            });
        } else {
            let mut clause_args = HashMap::new();
            clause_args.insert("ctv_hash".to_string(), ctv_hash.to_vec());
            clause_args.insert("out_i".to_string(), encode_scriptint(0));

            spends.push(mattrs::manager::SpendSpec {
                instance_idx: idx,
                clause_name: "trigger".to_string(),
                args: clause_args,
                sequence: Sequence::ZERO,
            });
        }
    }

    let mut output_amounts = HashMap::new();
    if revault_amount > 0 {
        output_amounts.insert(1usize, Amount::from_sat(revault_amount));
    }

    println!("Waiting for trigger transaction to be confirmed...");
    state.manager.spend_instances(
        &spends,
        SpendOptions {
            signers: Some(&state.signers),
            ..Default::default()
        },
        output_amounts,
    )?;

    // Store the template for later withdrawal
    state
        .ctv_templates
        .insert(ctv_hash, (outputs, sequence));

    println!("Done");
    Ok(())
}

fn cmd_recover(
    state: &mut CliState,
    args: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let idx: usize = args
        .get("item")
        .ok_or("Missing argument: item")?
        .parse()?;

    let inst = state.manager.instance(idx);
    if inst.status() != ContractInstanceStatus::Funded {
        return Err("Only FUNDED instances can be recovered".into());
    }
    let name = inst.contract().name().to_string();
    if name != "Vault" && name != "Unvaulting" {
        return Err("Only Vault or Unvaulting instances can be recovered".into());
    }

    let mut clause_args = HashMap::new();
    clause_args.insert("out_i".to_string(), encode_scriptint(0));

    state.manager.spend_instance(
        idx,
        "recover",
        clause_args,
        Default::default(),
    )?;
    println!("Recovered instance {}", idx);
    Ok(())
}

fn cmd_withdraw(
    state: &mut CliState,
    args: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let idx: usize = args
        .get("item")
        .ok_or("Missing argument: item")?
        .parse()?;

    let inst = state.manager.instance(idx);
    if inst.status() != ContractInstanceStatus::Funded {
        return Err("Only FUNDED Unvaulting instances can be withdrawn".into());
    }
    if inst.contract().name() != "Unvaulting" {
        return Err("Only Unvaulting instances can be withdrawn".into());
    }

    let ctv_hash_data = inst.data().clone();
    let ctv_hash: [u8; 32] = ctv_hash_data
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid CTV hash length in instance data")?;

    let (template_outputs, sequence) = state
        .ctv_templates
        .get(&ctv_hash)
        .ok_or("No stored CTV template for this hash (was this vault triggered in this session?)")?
        .clone();

    let ctv_txouts: Vec<TxOut> = template_outputs
        .iter()
        .map(|(addr, amount)| TxOut {
            script_pubkey: addr.script_pubkey(),
            value: *amount,
        })
        .collect();

    let mut clause_args = HashMap::new();
    clause_args.insert("ctv_hash".to_string(), ctv_hash.to_vec());

    println!("Waiting for withdrawal to be confirmed...");
    state.manager.spend_instance(
        idx,
        "withdraw",
        clause_args,
        SpendOptions {
            outputs: Some(&ctv_txouts),
            sequence: Some(sequence),
            ..Default::default()
        },
    )?;
    println!("Done");
    Ok(())
}

/// Encode an i32 as bitcoin script integer bytes.
fn encode_scriptint(val: i32) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let len = bitcoin::script::write_scriptint(&mut buf, val as i64);
    buf[..len].to_vec()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut mine_automatically = false;
    let mut script_file: Option<String> = None;
    let mut inspector_port: Option<u16> = None;

    // Simple arg parsing (no heavy deps)
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--mine-automatically" => mine_automatically = true,
            "-s" | "--script" => {
                i += 1;
                script_file = Some(
                    args.get(i)
                        .ok_or("--script requires a filename")?
                        .clone(),
                );
            }
            "--inspector" => inspector_port = Some(34443),
            "--inspector-port" => {
                i += 1;
                inspector_port = Some(
                    args.get(i)
                        .ok_or("--inspector-port requires a port number")?
                        .parse()?,
                );
            }
            "-h" | "--help" => {
                println!("Usage: vault-cli [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -m, --mine-automatically    Mine a block after each operation");
                println!("  -s, --script <FILE>         Execute commands from a script file");
                println!("  --inspector                 Enable inspector server (port 34443)");
                println!("  --inspector-port <PORT>     Enable inspector server on custom port");
                println!("  -h, --help                  Show this help");
                println!();
                println!("Commands:");
                println!("  fund amount=<sats>                          Fund a new vault");
                println!("  list                                        List all instances");
                println!("  mine [n]                                    Mine n blocks (default 1)");
                println!("  printall                                    Print all spending txs");
                println!("  trigger items=\"[i,...]\" outputs=\"[...]\"     Trigger vault(s)");
                println!("  recover item=<idx>                          Recover from vault/unvaulting");
                println!("  withdraw item=<idx>                         Withdraw from unvaulting");
                return Ok(());
            }
            other => {
                return Err(format!("Unknown argument: {}", other).into());
            }
        }
        i += 1;
    }

    // Setup keys (same as pymatt)
    let secp = Secp256k1::new();

    let unvault_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )?;
    let unvault_pubkey: XOnlyPublicKey = unvault_privkey.to_priv().public_key(&secp).into();

    let recover_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )?;
    let recover_pubkey: XOnlyPublicKey = recover_privkey.to_priv().public_key(&secp).into();

    let spend_delay = 10u32;

    let vault_contract = make_vault(&VaultParams {
        alternate_pk: None,
        spend_delay,
        recover_pk: recover_pubkey,
        unvault_pk: unvault_pubkey,
    });

    // Setup RPC
    let rpc_url =
        std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_user =
        std::env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "rpcuser".to_string());
    let rpc_pass =
        std::env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "rpcpass".to_string());
    let wallet_name =
        std::env::var("WALLET_NAME").unwrap_or_else(|_| "testwallet".to_string());

    let url = format!("{}/wallet/{}", rpc_url, wallet_name);
    let client = Client::new(&url, Auth::UserPass(rpc_user, rpc_pass))?;

    #[allow(unused_mut)]
    let mut manager = ContractManager::new(&client, Duration::from_secs_f64(0.1), mine_automatically);

    #[cfg(feature = "inspector")]
    if let Some(port) = inspector_port {
        manager.enable_inspector(port);
        println!("Inspector server listening on 127.0.0.1:{}", port);
    }

    #[cfg(not(feature = "inspector"))]
    if inspector_port.is_some() {
        eprintln!("Warning: --inspector requires the 'inspector' feature. Ignoring.");
    }

    let mut signers: SignerMap = HashMap::new();
    signers.insert(
        unvault_pubkey,
        Box::new(HotSigner {
            privkey: unvault_privkey,
        }),
    );

    let vault_address = vault_contract.get_address(&vec![]);
    println!("Vault address: {}\n", vault_address);

    let mut state = CliState {
        manager,
        vault_contract,
        signers,
        spend_delay,
        ctv_templates: HashMap::new(),
    };

    if let Some(filename) = script_file {
        // Script mode
        let contents = std::fs::read_to_string(&filename)?;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            println!("₿ {}", trimmed);
            if let Err(e) = execute_command(&mut state, trimmed) {
                println!("Error: {}", e);
                break;
            }
        }
    } else {
        // Interactive mode
        let config = Config::builder().auto_add_history(true).build();
        let mut rl = Editor::with_config(config)?;
        rl.set_helper(Some(VaultHelper));
        let _ = rl.load_history(".vault-cli-history");

        loop {
            match rl.readline("₿ ") {
                Ok(line) => {
                    if let Err(e) = execute_command(&mut state, &line) {
                        println!("Error: {}", e);
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
                Err(e) => {
                    println!("Error: {}", e);
                    break;
                }
            }
        }

        let _ = rl.save_history(".vault-cli-history");
    }

    Ok(())
}
