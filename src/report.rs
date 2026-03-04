use std::collections::BTreeMap;
use std::fs;

use bitcoin::consensus::encode::serialize;
use bitcoin::hex::DisplayHex;
use bitcoin::Transaction;

/// Format a transaction as a collapsible markdown `<details>` block.
pub fn format_tx_markdown(tx: &Transaction, title: &str) -> String {
    let vsize = tx.weight().to_vbytes_ceil();
    let raw_bytes = serialize(tx).len();

    let mut s = format!("CTransaction: (nVersion={}, {} bytes)\n", tx.version.0, raw_bytes);
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
        let wit_bytes: usize = items.iter().map(|item| if item.is_empty() { 1 } else { item.len() }).sum();
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
        "\n<details><summary>{}<i>({} vB)</i></summary>\n\n```\n{}```\n\n</details>\n\n",
        title, vsize, s
    )
}

/// Collects markdown report entries by section, then writes to a file.
pub struct Report {
    sections: BTreeMap<String, Vec<String>>,
}

impl Report {
    pub fn new() -> Self {
        Report {
            sections: BTreeMap::new(),
        }
    }

    pub fn write(&mut self, section: &str, content: String) {
        self.sections
            .entry(section.to_string())
            .or_default()
            .push(content);
    }

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

        // Ensure the parent directory exists (creates it recursively if needed).
        let path = std::path::Path::new(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("Failed to create parent directory");
        }
        fs::write(path, out).expect("Failed to write report");
    }
}
