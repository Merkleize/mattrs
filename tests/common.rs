use bitcoincore_rpc::{Auth, Client};
use std::env;

/// Initializes and returns a Bitcoin RPC client connected to the local regtest node.
///
/// It reads the RPC credentials and URL from environment variables, falling back to defaults
/// if they are not set.
///
/// The `wallet_name` wallet must be already loaded and funded.
///
/// # Environment Variables
///
/// - `BITCOIN_RPC_URL`: The URL of the Bitcoin RPC server (default: `http://localhost:18443/wallet/testwallet`).
/// - `BITCOIN_RPC_USER`: The RPC username (default: `user`).
/// - `BITCOIN_RPC_PASSWORD`: The RPC password (default: `password`).
pub fn get_rpc_client(wallet_name: &str) -> Client {
    let rpc_url =
        env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_url_full = format!("{}/wallet/{}", rpc_url, wallet_name);
    let rpc_user = env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "rpcuser".to_string());
    let rpc_password = env::var("BITCOIN_RPC_PASSWORD").unwrap_or_else(|_| "rpcpass".to_string());

    let auth = Auth::UserPass(rpc_user, rpc_password);
    Client::new(&rpc_url_full, auth).expect("Failed to create RPC client")
}
