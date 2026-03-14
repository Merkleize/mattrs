use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::{
    bip32::Xpriv,
    key::Secp256k1,
    Amount, XOnlyPublicKey,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use mattrs::signer::{HotSigner, SignerMap};

pub fn get_rpc_client(wallet_name: &str) -> Client {
    let rpc_url = std::env::var("BITCOIN_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_user =
        std::env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "rpcuser".to_string());
    let rpc_pass =
        std::env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "rpcpass".to_string());

    let url = format!("{}/wallet/{}", rpc_url, wallet_name);
    Client::new(&url, Auth::UserPass(rpc_user, rpc_pass)).expect("Failed to create RPC client")
}

pub fn ensure_funds(client: &Client) {
    let balance = client.get_balance(None, None).unwrap();
    if balance < Amount::from_sat(100_000_000) {
        let addr = client.get_new_address(None, None).unwrap().assume_checked();
        client.generate_to_address(101, &addr).unwrap();
    }
}

/// Standard test keys matching pymatt.
pub const ALICE_TPRV: &str = "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN";
pub const BOB_TPRV: &str = "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ";

/// Derive an `(Xpriv, XOnlyPublicKey)` pair from a tprv string.
pub fn make_keypair(tprv: &str) -> (Xpriv, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let privkey = Xpriv::from_str(tprv).unwrap();
    let pubkey: XOnlyPublicKey = privkey.to_priv().public_key(&secp).into();
    (privkey, pubkey)
}

pub fn make_signers(entries: &[(XOnlyPublicKey, Xpriv)]) -> SignerMap {
    let mut signers: SignerMap = HashMap::new();
    for &(pk, privkey) in entries {
        signers.insert(pk, Box::new(HotSigner { privkey }));
    }
    signers
}
