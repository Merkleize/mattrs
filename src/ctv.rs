use bitcoin::{
    absolute::LockTime,
    consensus::Encodable,
    hashes::{sha256, Hash},
    transaction::Version,
    Address, Amount, Sequence, Transaction, TxIn, TxOut,
};
use std::io::Write;

/// Create a CTV template hash for a given set of outputs and a single input with a certain nSequence.
pub fn make_ctv_template_hash(
    outputs: &[(Address, Amount)],
    n_sequence: Sequence,
) -> Result<[u8; 32], bitcoin::io::Error> {
    let mut txin = TxIn::default();
    txin.sequence = n_sequence;

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: outputs
            .iter()
            .map(|(addr, amount)| TxOut {
                script_pubkey: addr.script_pubkey(),
                value: *amount,
            })
            .collect(),
    };

    let mut hasher = sha256::Hash::engine();

    tx.version.consensus_encode(&mut hasher)?;
    tx.lock_time.consensus_encode(&mut hasher)?;

    let mut has_script_sig = false;
    let mut script_sig_hash = sha256::Hash::engine();
    for txin in tx.input.iter() {
        if !txin.script_sig.is_empty() {
            has_script_sig = true;
            txin.script_sig.consensus_encode(&mut script_sig_hash)?;
        }
    }
    if has_script_sig {
        hasher.write_all(&sha256::Hash::from_engine(script_sig_hash)[..])?;
    }

    hasher.write_all(&(tx.input.len() as u32).to_le_bytes())?;
    let mut n_sequence_hash = sha256::Hash::engine();
    for txin in tx.input.iter() {
        n_sequence_hash.write_all(&txin.sequence.0.to_le_bytes())?;
    }
    let n_sequence_hash_bytes = sha256::Hash::from_engine(n_sequence_hash);
    hasher.write_all(&n_sequence_hash_bytes.to_byte_array())?;

    hasher.write_all(&(tx.output.len() as u32).to_le_bytes())?;
    let mut outputs_hash = sha256::Hash::engine();
    for txout in tx.output.iter() {
        txout.consensus_encode(&mut outputs_hash)?;
    }
    hasher.write_all(&sha256::Hash::from_engine(outputs_hash).to_byte_array())?;

    let n_in = 0u32;
    hasher.write_all(&n_in.to_le_bytes())?;

    Ok(sha256::Hash::from_engine(hasher).to_byte_array())
}
