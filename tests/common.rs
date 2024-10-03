use bitcoin::{Address, Amount, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::env;
use std::error::Error;
use std::str::FromStr;

/// Initializes and returns a Bitcoin RPC client connected to the local regtest node.
///
/// It reads the RPC credentials and URL from environment variables, falling back to defaults
/// if they are not set.
///
/// # Environment Variables
///
/// - `BITCOIN_RPC_URL`: The URL of the Bitcoin RPC server (default: `http://localhost:18443`).
/// - `BITCOIN_RPC_USER`: The RPC username (default: `user`).
/// - `BITCOIN_RPC_PASSWORD`: The RPC password (default: `password`).
pub fn get_rpc_client() -> Client {
    let rpc_url =
        env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
    let rpc_user = env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "rpcuser".to_string());
    let rpc_password = env::var("BITCOIN_RPC_PASSWORD").unwrap_or_else(|_| "rpcpass".to_string());

    let auth = Auth::UserPass(rpc_user, rpc_password);
    Client::new(&rpc_url, auth).expect("Failed to create RPC client")
}

/// Sends a specified amount of Bitcoin to a given address using the Bitcoin RPC.
///
/// # Arguments
///
/// * `address` - A string slice that holds the Bitcoin address to send funds to.
/// * `amount` - The amount of sats to send.
///
/// # Returns
///
/// * `Ok(String)` containing the transaction ID (txid) if successful.
/// * `Err(Box<dyn Error>)` if an error occurs during the process.
pub fn send_to_address(address: &str, amount: u64) -> Result<String, Box<dyn Error>> {
    let client = get_rpc_client();

    let address: Address = Address::from_str(address)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();

    // Send the specified amount to the address
    let amount = Amount::from_sat(amount);
    let txid = client.send_to_address(&address, amount, None, None, None, None, None, None)?;

    Ok(txid.to_string())
}
