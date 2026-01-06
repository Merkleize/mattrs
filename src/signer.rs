//! Signing infrastructure for contract transactions.

use bitcoin::{
    Transaction, TxOut, XOnlyPublicKey,
    bip32::Xpriv,
    hashes::Hash,
    key::Secp256k1,
    secp256k1::{Message, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
};

/// Trait for signing Bitcoin transactions.
pub trait Signer {
    /// Sign a message (sighash) and return the signature bytes.
    ///
    /// # Arguments
    /// * `sighash` - The 32-byte sighash to sign
    ///
    /// # Returns
    /// The signature as a byte vector (64 bytes for schnorr)
    fn sign(&self, sighash: &[u8]) -> Vec<u8>;

    /// Get the public key associated with this signer.
    fn public_key(&self) -> XOnlyPublicKey;
}

/// A hot wallet signer using an extended private key.
pub struct HotSigner {
    privkey: Xpriv,
}

impl HotSigner {
    /// Create a new hot signer from an extended private key.
    pub fn new(privkey: Xpriv) -> Self {
        Self { privkey }
    }

    /// Get the secret key for signing.
    fn secret_key(&self) -> SecretKey {
        self.privkey.to_priv().inner
    }
}

impl Signer for HotSigner {
    fn sign(&self, sighash: &[u8]) -> Vec<u8> {
        let secp = Secp256k1::new();
        let secret_key = self.secret_key();
        let keypair = bitcoin::key::Keypair::from_secret_key(&secp, &secret_key);

        // Create message from sighash
        let msg = Message::from_digest_slice(sighash).expect("sighash is 32 bytes");

        // Sign with schnorr
        let sig = secp.sign_schnorr(&msg, &keypair);

        // Return signature bytes (64 bytes, no sighash type byte for SIGHASH_DEFAULT)
        sig.as_ref().to_vec()
    }

    fn public_key(&self) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        self.privkey.to_priv().public_key(&secp).into()
    }
}

/// Helper to compute taproot sighash for a transaction input.
pub fn compute_tap_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf_hash: Option<bitcoin::taproot::TapLeafHash>,
    sighash_type: TapSighashType,
) -> Result<[u8; 32], String> {
    let prevouts = Prevouts::All(prevouts);

    let mut sighash_cache = SighashCache::new(tx);

    let sighash = if let Some(leaf) = leaf_hash {
        sighash_cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf, sighash_type)
            .map_err(|e| format!("Failed to compute sighash: {}", e))?
    } else {
        sighash_cache
            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
            .map_err(|e| format!("Failed to compute sighash: {}", e))?
    };

    Ok(*sighash.as_byte_array())
}
