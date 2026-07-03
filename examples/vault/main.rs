//! Interactive vault REPL (regtest), ported from pymatt's `examples/vault/vault.py`.
//!
//! Drives the two-stage vault of `contracts.rs` from a small command line:
//! vaults are funded, triggered (optionally many at once, with a partial
//! revault), and then withdrawn via their CTV template after the timelock — or
//! pushed to the recovery key at any time.
//!
//! Run against a regtest bitcoind with a funded `testwallet` (cookie auth or
//! `BITCOIN_RPC_*` env vars):
//!
//! ```sh
//! cargo run --example vault                                  # interactive
//! cargo run --example vault -- --script examples/vault/scripts/normal.txt
//! ```
//!
//! Commands:
//!
//! ```text
//! fund <amount>                            fund a new vault with <amount> sats
//! list                                     list the tracked instances
//! trigger <ids> <addr:amt> [<addr:amt>..]  unvault the (comma-separated) vaults
//!                                          towards a withdrawal template; any
//!                                          leftover amount is revaulted
//! withdraw <id>                            finish an unvaulting via its CTV
//!                                          template (after 10 blocks)
//! recover <id>                             push a vault or unvaulting to the
//!                                          recovery key
//! mine [n]                                 mine n blocks (default 1)
//! printall                                 show each instance's lifecycle
//! help | exit
//! ```

#[allow(dead_code)]
mod contracts;

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::str::FromStr;

use bitcoin::bip32::Xpriv;
use bitcoin::key::Secp256k1;
use bitcoin::{Address, Amount, ScriptBuf, Sequence, TxOut, XOnlyPublicKey};
use mattrs::contracts::InstanceStatus;
use mattrs::ctv::create_ctv_template;
use mattrs::manager::{regtest_rpc_client, ContractManager, InstanceHandle};
use mattrs::signer::HotSigner;

use contracts::{UnvaultingHandle, UnvaultingState, Vault, VaultHandle, VaultParams};

// Demo keys (the pymatt reference fixtures; never use on mainnet).
const UNVAULT_XPRIV: &str = "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN";
const RECOVER_XPRIV: &str = "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ";

const SPEND_DELAY: u32 = 10;

struct Repl {
    manager: ContractManager,
    params: VaultParams,
    unvault_xpriv: Xpriv,
    /// Every instance ever shown to the user, addressed by its `list` index.
    items: Vec<InstanceHandle>,
    /// The withdrawal outputs behind each CTV hash committed by a trigger.
    templates: HashMap<[u8; 32], Vec<TxOut>>,
}

enum Kind {
    Vault,
    Unvaulting,
}

impl Repl {
    fn kind(&self, handle: &InstanceHandle) -> Option<Kind> {
        match handle.contract_name() {
            "Vault" => Some(Kind::Vault),
            "Unvaulting" => Some(Kind::Unvaulting),
            _ => None,
        }
    }

    fn kind_str(&self, handle: &InstanceHandle) -> &'static str {
        handle.contract_name()
    }

    fn item(&self, idx_str: &str) -> Result<(usize, InstanceHandle), String> {
        let idx: usize = idx_str.parse().map_err(|_| format!("bad index `{idx_str}`"))?;
        let handle = self
            .items
            .get(idx)
            .ok_or_else(|| format!("no such instance: {idx}"))?;
        Ok((idx, handle.clone()))
    }

    fn track(&mut self, handle: InstanceHandle) {
        println!(
            "  -> instance {}: {} at {}",
            self.items.len(),
            self.kind_str(&handle),
            handle
                .outpoint()
                .map(|o| o.to_string())
                .unwrap_or_default()
        );
        self.items.push(handle);
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    fn fund(&mut self, amount_str: &str) -> Result<(), Box<dyn std::error::Error>> {
        let amount: u64 = amount_str.parse()?;
        let vault =
            Vault::new(self.params.clone()).fund(&mut self.manager, Amount::from_sat(amount))?;
        self.track(vault.handle().clone());
        Ok(())
    }

    fn list(&self) {
        for (i, handle) in self.items.iter().enumerate() {
            let value = handle
                .prevout()
                .map(|p| p.value.to_sat().to_string())
                .unwrap_or_default();
            let outpoint = handle
                .outpoint()
                .map(|o| o.to_string())
                .unwrap_or_default();
            let state = handle
                .state::<UnvaultingState>()
                .map(|s| format!(" ctv_hash={}", hex::encode(s.ctv_hash)))
                .unwrap_or_default();
            println!(
                "{i} {:?} {} value={value} outpoint={outpoint}{state}",
                handle.status(),
                self.kind_str(handle),
            );
        }
    }

    fn printall(&self) {
        for (i, handle) in self.items.iter().enumerate() {
            match (handle.clause_name(), handle.spent_in_tx()) {
                (Some(clause), Some(txid)) => {
                    println!("{i} {} spent via `{clause}` in {txid}", self.kind_str(handle))
                }
                _ => println!("{i} {} {:?}", self.kind_str(handle), handle.status()),
            }
        }
    }

    fn trigger(
        &mut self,
        ids: &str,
        outputs: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The vaults being unvaulted.
        let mut vaults: Vec<(usize, InstanceHandle)> = Vec::new();
        for id in ids.split(',') {
            let (idx, handle) = self.item(id)?;
            if handle.status() != InstanceStatus::Funded
                || !matches!(self.kind(&handle), Some(Kind::Vault))
            {
                return Err(format!("instance {idx} is not a funded Vault").into());
            }
            vaults.push((idx, handle));
        }
        if vaults.is_empty() {
            return Err("no vaults given".into());
        }

        // The withdrawal template; whatever is not withdrawn gets revaulted.
        let mut template: Vec<(Address, Amount)> = Vec::new();
        for out in outputs {
            let (addr, amt) = out
                .rsplit_once(':')
                .ok_or_else(|| format!("expected addr:amount, got `{out}`"))?;
            template.push((
                Address::from_str(addr)?.assume_checked(),
                Amount::from_sat(amt.parse()?),
            ));
        }
        let inputs_total: Amount = vaults
            .iter()
            .map(|(_, h)| h.prevout().expect("funded").value)
            .sum();
        let outputs_total: Amount = template.iter().map(|(_, a)| *a).sum();
        let revault = inputs_total
            .checked_sub(outputs_total)
            .ok_or("outputs exceed the vaults' total amount")?;

        let tmpl = create_ctv_template(&template, Sequence(SPEND_DELAY));
        let ctv_hash = tmpl.ctv_hash();
        self.templates.insert(ctv_hash, tmpl.outputs);
        println!(
            "Triggering {} vault(s) towards template {} (revault: {} sats)",
            vaults.len(),
            hex::encode(ctv_hash),
            revault.to_sat(),
        );

        // The largest vault revaults the leftover; the others trigger plainly.
        vaults.sort_by_key(|(_, h)| std::cmp::Reverse(h.prevout().expect("funded").value));
        let mut builders = Vec::new();
        for (i, (_, handle)) in vaults.iter().enumerate() {
            let vault: VaultHandle = handle.clone().try_into().expect("kind checked");
            let builder = if i == 0 && revault > Amount::ZERO {
                vault
                    .trigger_and_revault(ctv_hash, 0, 1)
                    .output_amount(1, revault)
            } else {
                vault.trigger(ctv_hash, 0)
            };
            builders.push(builder.sign(HotSigner::new(self.unvault_xpriv)));
        }

        let children = self.manager.spend_batch(&builders)?;
        for child in children {
            self.track(child);
        }
        Ok(())
    }

    fn withdraw(&mut self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (idx, handle) = self.item(id)?;
        if handle.status() != InstanceStatus::Funded
            || !matches!(self.kind(&handle), Some(Kind::Unvaulting))
        {
            return Err(format!("instance {idx} is not a funded Unvaulting").into());
        }
        let ctv_hash = handle
            .state::<UnvaultingState>()
            .expect("unvaulting has state")
            .ctv_hash;
        let outputs = self
            .templates
            .get(&ctv_hash)
            .ok_or("unknown CTV template (trigger it in this session first)")?
            .clone();

        let unvaulting: UnvaultingHandle = handle.try_into().expect("kind checked");
        unvaulting
            .withdraw(ctv_hash)
            .outputs(outputs)
            .sequence(SPEND_DELAY)
            .exec_none(&mut self.manager)?;
        println!("Withdrawn via the CTV template {}", hex::encode(ctv_hash));
        Ok(())
    }

    fn recover(&mut self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (idx, handle) = self.item(id)?;
        if handle.status() != InstanceStatus::Funded {
            return Err(format!("instance {idx} is not funded").into());
        }
        let value = handle.prevout().expect("funded").value;
        // The recover clauses' CCV (empty data, empty taptree) constrains output 0
        // to pay the recovery key *as the witness program*, with no further tweak.
        let recover_out = vec![TxOut {
            script_pubkey: ScriptBuf::new_p2tr_tweaked(
                bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(self.params.recover_pk),
            ),
            value,
        }];

        match self.kind(&handle) {
            Some(Kind::Vault) => {
                let vault: VaultHandle = handle.try_into().expect("kind checked");
                vault
                    .recover(0)
                    .outputs(recover_out)
                    .exec_none(&mut self.manager)?
            }
            Some(Kind::Unvaulting) => {
                let unvaulting: UnvaultingHandle = handle.try_into().expect("kind checked");
                unvaulting
                    .recover(0)
                    .outputs(recover_out)
                    .exec_none(&mut self.manager)?
            }
            None => return Err(format!("instance {idx} is not recoverable").into()),
        }
        println!("Recovered {} sats to the recovery key", value.to_sat());
        Ok(())
    }

    fn mine(&self, n_str: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        let n: u64 = n_str.map(str::parse).transpose()?.unwrap_or(1);
        self.manager.mine_blocks(n)?;
        println!("Mined {n} block(s)");
        Ok(())
    }

    fn execute(&mut self, line: &str) -> Result<(), Box<dyn std::error::Error>> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["fund", amount] => self.fund(amount),
            ["list"] => {
                self.list();
                Ok(())
            }
            ["printall"] => {
                self.printall();
                Ok(())
            }
            ["trigger", ids, outputs @ ..] if !outputs.is_empty() => self.trigger(ids, outputs),
            ["withdraw", id] => self.withdraw(id),
            ["recover", id] => self.recover(id),
            ["mine"] => self.mine(None),
            ["mine", n] => self.mine(Some(n)),
            ["help"] => {
                println!("commands: fund <amount> | list | trigger <ids> <addr:amt>.. | withdraw <id> | recover <id> | mine [n] | printall | exit");
                Ok(())
            }
            _ => Err(format!("invalid command `{line}` (try `help`)").into()),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut script: Option<String> = None;
    let mut wallet = "testwallet".to_string();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--script" | "-s" => script = Some(it.next().ok_or("--script needs a file")?.clone()),
            "--wallet" => wallet = it.next().ok_or("--wallet needs a value")?.clone(),
            other => return Err(format!("unknown argument `{other}`").into()),
        }
    }

    let secp = Secp256k1::new();
    let unvault_xpriv = Xpriv::from_str(UNVAULT_XPRIV)?;
    let unvault_pk: XOnlyPublicKey = unvault_xpriv.to_priv().public_key(&secp).into();
    let recover_pk: XOnlyPublicKey = Xpriv::from_str(RECOVER_XPRIV)?
        .to_priv()
        .public_key(&secp)
        .into();

    let params = VaultParams {
        alternate_pk: None,
        spend_delay: SPEND_DELAY,
        recover_pk,
        unvault_pk,
    };
    println!(
        "Vault address: {}\n",
        Vault::new(params.clone()).address(bitcoin::Network::Regtest)
    );

    let client = regtest_rpc_client(&wallet);
    let mut repl = Repl {
        manager: ContractManager::new(client),
        params,
        unvault_xpriv,
        items: Vec::new(),
        templates: HashMap::new(),
    };

    if let Some(path) = script {
        for line in std::fs::read_to_string(path)?.lines() {
            if !line.trim().is_empty() && !line.trim().starts_with('#') {
                println!("₿ {line}");
            }
            if let Err(err) = repl.execute(line) {
                eprintln!("Error executing `{}`: {err}", line.trim());
                return Err(err);
            }
        }
    } else {
        let stdin = std::io::stdin();
        loop {
            print!("₿ ");
            std::io::stdout().flush()?;
            let mut line = String::new();
            if stdin.lock().read_line(&mut line)? == 0 {
                break; // EOF
            }
            if line.trim() == "exit" {
                break;
            }
            if let Err(err) = repl.execute(&line) {
                eprintln!("Error: {err}");
            }
        }
    }
    Ok(())
}
