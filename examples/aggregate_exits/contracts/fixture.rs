//! The demo cast, shared by the demo binary and the tests: a six-user pool
//! (padded to eight slots), Ingrid, and the standard exit set.

use bitcoin::bip32::Xpriv;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{Network, XOnlyPublicKey};

use super::{PoolParams, PoolTree};

/// The bond posted with every claim or challenge, in sats.
pub const BOND: i64 = 10_000;
/// The users' balances: 1000, 2000, ..., 6000 — total 21_000, with every
/// partial sum well under 2^31 (the 32-bit `OP_ADD` limit).
pub const BALANCES: [i64; 6] = [1_000, 2_000, 3_000, 4_000, 5_000, 6_000];
/// The pool's total value, in sats.
pub const POOL_TOTAL: u64 = 21_000;

pub fn params() -> PoolParams {
    PoolParams {
        pool_id: [7u8; 32],
        n_users: 6, // padded to 8 slots
        challenge_period: 10,
        response_timeout: 5,
        bond: BOND,
    }
}

pub fn user_xpriv(i: usize) -> Xpriv {
    Xpriv::new_master(Network::Regtest, &[10 + i as u8]).unwrap()
}

pub fn ingrid_xpriv() -> Xpriv {
    Xpriv::new_master(Network::Regtest, &[99]).unwrap()
}

pub fn xonly(xpriv: &Xpriv) -> XOnlyPublicKey {
    xpriv.to_priv().public_key(&Secp256k1::new()).into()
}

pub fn keypair(xpriv: &Xpriv) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &xpriv.to_priv().inner)
}

/// The demo pool: six users holding [`BALANCES`].
pub fn pool() -> PoolTree {
    let accounts: Vec<(XOnlyPublicKey, i64)> = (0..6)
        .map(|i| (xonly(&user_xpriv(i)), BALANCES[i]))
        .collect();
    PoolTree::new(&params(), &accounts)
}

/// The demo exit set: users 1, 2 and 4 (aggregate 10_000 sats).
pub fn exit_bits() -> Vec<bool> {
    let mut bits = vec![false; params().padded_size()];
    bits[1] = true;
    bits[2] = true;
    bits[4] = true;
    bits
}
