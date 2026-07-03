//! CheckTemplateVerify (CTV) utilities implementing BIP-119.

use bitcoin::{
    Address, Amount, Sequence, TxOut,
    consensus::encode::serialize,
    hashes::{Hash, sha256},
};

/// Compute the CTV hash for a set of outputs and sequence number.
///
/// Implements BIP-119 hash computation:
/// SHA256(nVersion || nLockTime || scriptSig_hash || num_inputs ||
///        sequences_hash || num_outputs || outputs_hash || nIn)
///
/// For standard CTV usage in clauses, we use simplified parameters:
/// - nVersion: 2
/// - nLockTime: 0
/// - scriptSig_hash: 0 (all empty)
/// - num_inputs: 1
/// - nIn: 0xFFFFFFFF
///
/// # Arguments
/// * `outputs` - The transaction outputs
/// * `sequence` - The sequence number for the input
///
/// # Returns
/// The 32-byte CTV hash
pub fn compute_ctv_hash(outputs: &[TxOut], sequence: Sequence) -> [u8; 32] {
    let mut data = Vec::new();

    // nVersion (4 bytes, little-endian)
    data.extend_from_slice(&2u32.to_le_bytes());

    // nLockTime (4 bytes, little-endian)
    data.extend_from_slice(&0u32.to_le_bytes());

    // scriptSig hash (32 bytes) - omitted when all scriptSigs are empty
    // According to BIP-119, this field is only included if there are non-empty scriptSigs

    // num_inputs (4 bytes, little-endian)
    data.extend_from_slice(&1u32.to_le_bytes());

    // sequences hash (32 bytes) - SHA256 of single sequence
    let sequences_hash = sha256::Hash::hash(&sequence.to_consensus_u32().to_le_bytes());
    data.extend_from_slice(sequences_hash.as_byte_array());

    // num_outputs (4 bytes, little-endian)
    data.extend_from_slice(&(outputs.len() as u32).to_le_bytes());

    // outputs hash (32 bytes) - SHA256 of serialized outputs
    let mut outputs_data = Vec::new();
    for output in outputs {
        outputs_data.extend_from_slice(&serialize(output));
    }
    let outputs_hash = sha256::Hash::hash(&outputs_data);
    data.extend_from_slice(outputs_hash.as_byte_array());

    // nIn (4 bytes, little-endian) - index of input being checked (0 for first input)
    data.extend_from_slice(&0u32.to_le_bytes());

    // Final hash
    let hash = sha256::Hash::hash(&data);
    *hash.as_byte_array()
}

/// Create a CTV template from a list of addresses and amounts.
///
/// This is a convenience function for building a
/// [`CtvTemplate`](crate::contracts::CtvTemplate), which carries both the
/// outputs and (via [`ctv_hash`](crate::contracts::CtvTemplate::ctv_hash))
/// the BIP-119 hash a clause script commits to.
pub fn create_ctv_template(
    template: &[(Address, Amount)],
    sequence: Sequence,
) -> crate::contracts::CtvTemplate {
    let outputs: Vec<TxOut> = template
        .iter()
        .map(|(addr, amount)| TxOut {
            script_pubkey: addr.script_pubkey(),
            value: *amount,
        })
        .collect();

    crate::contracts::CtvTemplate::new(outputs, sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Address;
    use std::str::FromStr;

    #[test]
    fn test_ctv_hash_computation() {
        // Test against known values from mattrs_old tests
        let template = vec![
            (
                Address::from_str("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437")
                    .unwrap()
                    .assume_checked(),
                Amount::from_sat(16663333),
            ),
            (
                Address::from_str("bcrt1qpnpjyzkfe7n5eppp2ktwpvuxfw5qfn2zjdum83")
                    .unwrap()
                    .assume_checked(),
                Amount::from_sat(16663333),
            ),
            (
                Address::from_str("bcrt1q6vqduw24yjjll6nfkxlfy2twwt52w58tnvnd46")
                    .unwrap()
                    .assume_checked(),
                Amount::from_sat(16663334),
            ),
        ];

        let ctv_hash = create_ctv_template(&template, Sequence(10)).ctv_hash();

        // Expected hash from mattrs_old test
        let expected_hex = "b288279b3012acaedfde4e4e347ad6f3147d416edbebf76668f16b91f2969215";
        let expected: [u8; 32] = hex::decode(expected_hex).unwrap().try_into().unwrap();

        assert_eq!(ctv_hash, expected);
    }
}
