//! Markdown reports of the transactions produced by a test or demo run.
//!
//! [`format_tx_markdown`] renders one transaction as a collapsible `<details>`
//! block (inputs, outputs, per-input witness size breakdown); [`Report`] collects
//! such blocks by section and writes them to a file — see the `reports/` output
//! of the regtest end-to-end tests.

use std::collections::BTreeMap;
use std::fs;

use bitcoin::consensus::encode::serialize;
use bitcoin::hex::DisplayHex;
use bitcoin::Transaction;

/// Format a transaction as a collapsible markdown `<details>` block.
pub fn format_tx_markdown(tx: &Transaction, title: &str) -> String {
    let vsize = tx.weight().to_vbytes_ceil();
    let raw_bytes = serialize(tx).len();

    let mut s = format!(
        "CTransaction: (nVersion={}, {} bytes)\n",
        tx.version.0, raw_bytes
    );
    s += "  vin:\n";
    for (i, inp) in tx.input.iter().enumerate() {
        s += &format!(
            "    - [{}] CTxIn(prevout=COutPoint(hash={} n={}) scriptSig={} nSequence={})\n",
            i,
            inp.previous_output.txid,
            inp.previous_output.vout,
            inp.script_sig.to_hex_string(),
            inp.sequence.0,
        );
    }
    s += "  vout:\n";
    for (i, out) in tx.output.iter().enumerate() {
        s += &format!(
            "    - [{}] CTxOut(nValue={:.8} scriptPubKey={})\n",
            i,
            out.value.to_btc(),
            out.script_pubkey.to_hex_string(),
        );
    }
    s += "  witnesses:\n";
    for (i, inp) in tx.input.iter().enumerate() {
        let items = inp.witness.to_vec();
        let wit_bytes: usize = items
            .iter()
            .map(|item| if item.is_empty() { 1 } else { item.len() })
            .sum();
        let wit_vb = wit_bytes as f64 / 4.0;
        s += &format!("    - [{}] ({} bytes, {} vB)\n", i, wit_bytes, wit_vb);
        for (j, item) in items.iter().enumerate() {
            s += &format!(
                "      - [{}.{}] ({} bytes) {}\n",
                i,
                j,
                item.len(),
                item.to_lower_hex_string(),
            );
        }
    }
    s += &format!("  nLockTime: {}\n", tx.lock_time.to_consensus_u32());

    format!(
        "\n<details><summary>{} <i>({} vB)</i></summary>\n\n```\n{}```\n\n</details>\n\n",
        title, vsize, s
    )
}

/// Collects markdown report entries by section, then writes them to a file.
#[derive(Default)]
pub struct Report {
    sections: BTreeMap<String, Vec<String>>,
}

impl Report {
    pub fn new() -> Self {
        Report::default()
    }

    /// Append a markdown block to a section (sections are emitted in name order).
    pub fn write(&mut self, section: &str, content: String) {
        self.sections
            .entry(section.to_string())
            .or_default()
            .push(content);
    }

    /// Shorthand for `write(section, format_tx_markdown(tx, title))`.
    pub fn write_tx(&mut self, section: &str, title: &str, tx: &Transaction) {
        self.write(section, format_tx_markdown(tx, title));
    }

    /// Write the report to `path`, creating parent directories as needed.
    pub fn finalize(&self, path: &str) {
        let mut out = String::new();
        for (section, contents) in &self.sections {
            out += &format!("## {}\n", section);
            for content in contents {
                out += content;
                out += "\n";
            }
            out += "\n";
        }

        let path = std::path::Path::new(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("Failed to create parent directory");
        }
        fs::write(path, out).expect("Failed to write report");
    }
}
