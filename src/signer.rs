use bitcoin::{
    bip32::Xpriv,
    secp256k1::{Message, Secp256k1},
};
use std::fmt::Debug;

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

// pub struct SchnorrSignerMaker<P: ?Sized> {
//     closure: Box<dyn Fn(&P) -> ([u8; 32], Box<dyn SchnorrSigner>)>,
// }

// impl<P: ?Sized> SchnorrSignerMaker<P> {
//     fn new(closure: impl Fn(&P) -> ([u8; 32], Box<dyn SchnorrSigner>) + 'static) -> Self {
//         Self {
//             closure: Box::new(closure),
//         }
//     }
// }

// impl Fn<>
