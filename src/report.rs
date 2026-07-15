//! Markdown reports of the transactions produced by a test or demo run.
//!
//! [`format_tx_markdown`] renders one transaction as a collapsible `<details>`
//! block (inputs, outputs, per-input witness size breakdown); [`Report`] collects
//! such blocks by section and writes them to a file — see the `reports/` output
//! of the regtest end-to-end tests.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::Path;

use bitcoin::Transaction;
use bitcoin::consensus::encode::serialize;
use bitcoin::hex::DisplayHex;

/// Format a transaction as a collapsible markdown `<details>` block.
pub fn format_tx_markdown(tx: &Transaction, title: &str) -> String {
    let vsize = tx.weight().to_vbytes_ceil();
    let raw_bytes = serialize(tx).len();

    let mut s = format!(
        "CTransaction: (nVersion={}, {} bytes)\n",
        tx.version.0, raw_bytes
    );
    s.push_str("  vin:\n");
    for (i, inp) in tx.input.iter().enumerate() {
        writeln!(
            &mut s,
            "    - [{}] CTxIn(prevout=COutPoint(hash={} n={}) scriptSig={} nSequence={})",
            i,
            inp.previous_output.txid,
            inp.previous_output.vout,
            inp.script_sig.to_hex_string(),
            inp.sequence.0,
        )
        .expect("writing to a String cannot fail");
    }
    s.push_str("  vout:\n");
    for (i, out) in tx.output.iter().enumerate() {
        writeln!(
            &mut s,
            "    - [{}] CTxOut(nValue={:.8} scriptPubKey={})",
            i,
            out.value.to_btc(),
            out.script_pubkey.to_hex_string(),
        )
        .expect("writing to a String cannot fail");
    }
    s.push_str("  witnesses:\n");
    for (i, inp) in tx.input.iter().enumerate() {
        let items = inp.witness.to_vec();
        let wit_bytes: usize = items
            .iter()
            .map(|item| if item.is_empty() { 1 } else { item.len() })
            .sum();
        let wit_vb = wit_bytes as f64 / 4.0;
        writeln!(&mut s, "    - [{i}] ({wit_bytes} bytes, {wit_vb} vB)")
            .expect("writing to a String cannot fail");
        for (j, item) in items.iter().enumerate() {
            writeln!(
                &mut s,
                "      - [{}.{}] ({} bytes) {}",
                i,
                j,
                item.len(),
                item.to_lower_hex_string(),
            )
            .expect("writing to a String cannot fail");
        }
    }
    writeln!(&mut s, "  nLockTime: {}", tx.lock_time.to_consensus_u32())
        .expect("writing to a String cannot fail");

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
    ///
    /// # Errors
    ///
    /// Returns an error if a parent directory cannot be created or the report
    /// cannot be written.
    pub fn finalize(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut out = String::new();
        for (section, contents) in &self.sections {
            writeln!(&mut out, "## {section}").expect("writing to a String cannot fail");
            for content in contents {
                out.push_str(content);
                out.push('\n');
            }
            out.push('\n');
        }

        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_markdown_has_stable_layout() {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        assert_eq!(
            format_tx_markdown(&tx, "empty"),
            concat!(
                "\n<details><summary>empty <i>(11 vB)</i></summary>\n\n```\n",
                "CTransaction: (nVersion=2, 12 bytes)\n",
                "  vin:\n",
                "  vout:\n",
                "  witnesses:\n",
                "  nLockTime: 0\n",
                "```\n\n</details>\n\n",
            ),
        );
    }

    #[test]
    fn finalize_creates_parent_directories_and_writes_the_report() -> io::Result<()> {
        let temp_dir = std::env::temp_dir().join(format!(
            "mattrs-report-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after Unix epoch")
                .as_nanos(),
        ));
        let path = temp_dir.join("nested/report.md");

        let mut report = Report::new();
        report.write("Example", "content".to_string());
        report.finalize(&path)?;

        assert_eq!(fs::read_to_string(path)?, "## Example\ncontent\n\n");
        fs::remove_dir_all(temp_dir)?;
        Ok(())
    }
}
