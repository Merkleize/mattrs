use std::collections::HashMap;
use std::fmt::Debug;

use bitcoin::{
    bip32::Xpriv,
    secp256k1::{Message, Secp256k1},
    XOnlyPublicKey,
};

pub trait SchnorrSigner: Debug {
    fn sign(&self, sighash: [u8; 32]) -> bitcoin::secp256k1::schnorr::Signature;
}

#[derive(Debug, Clone)]
pub struct HotSigner {
    pub privkey: Xpriv,
}

impl SchnorrSigner for HotSigner {
    fn sign(&self, sighash: [u8; 32]) -> bitcoin::secp256k1::schnorr::Signature {
        let secp = Secp256k1::new();
        let keypair = self.privkey.to_keypair(&secp);
        let msg = Message::from_digest(sighash);
        secp.sign_schnorr(&msg, &keypair)
    }
}

pub type SignerMap = HashMap<XOnlyPublicKey, Box<dyn SchnorrSigner>>;
