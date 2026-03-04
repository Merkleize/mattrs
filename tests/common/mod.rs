use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::{
    bip32::Xpriv,
    hashes::Hash,
    key::Secp256k1,
    sighash::SighashCache,
    taproot::LeafVersion,
    Amount, Sequence, TapLeafHash, TxOut, XOnlyPublicKey,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use mattrs::{
    contracts::ClauseArgs,
    manager::ContractManager,
    signer::{HotSigner, SignerMap},
    tx,
};

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

pub fn get_keys() -> (Xpriv, XOnlyPublicKey, Xpriv, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let alice_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )
    .unwrap();
    let alice_pk: XOnlyPublicKey = alice_privkey.to_priv().public_key(&secp).into();

    let bob_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    )
    .unwrap();
    let bob_pk: XOnlyPublicKey = bob_privkey.to_priv().public_key(&secp).into();

    (alice_privkey, alice_pk, bob_privkey, bob_pk)
}

pub fn make_signers(entries: &[(XOnlyPublicKey, Xpriv)]) -> SignerMap {
    let mut signers: SignerMap = HashMap::new();
    for &(pk, privkey) in entries {
        signers.insert(pk, Box::new(HotSigner { privkey }));
    }
    signers
}

/// Build a terminal spend tx (no tracked CCV outputs).
///
/// Consolidates the duplicated pattern of building a spend tx, setting
/// lock_time/version/sequence, computing the sighash, and building the witness.
pub fn build_terminal_spend_tx(
    manager: &ContractManager,
    instance_idx: usize,
    clause_name: &str,
    mut clause_args: ClauseArgs,
    outputs: &[TxOut],
    signers: Option<&SignerMap>,
    sequence: Sequence,
) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
    let spend_spec = tx::SpendSpec {
        instance_idx,
        clause_name: clause_name.to_string(),
        args: clause_args.clone(),
    };

    let (mut spend_tx, _) =
        tx::create_spend_tx(&manager.instances, &[spend_spec], &HashMap::new(), outputs)?;

    spend_tx.lock_time = bitcoin::absolute::LockTime::ZERO;
    spend_tx.input[0].sequence = sequence;
    spend_tx.version = bitcoin::transaction::Version::TWO;

    // Compute sighash
    let inst = &manager.instances[instance_idx];
    let funding_tx = inst.funding_tx.as_ref().unwrap();
    let outpoint = inst.outpoint.unwrap();
    let spent_utxos = vec![funding_tx.output[outpoint.vout as usize].clone()];

    let leaf_script = inst
        .contract
        .get_clause(clause_name)
        .unwrap()
        .script
        .clone();

    let mut sighash_cache = SighashCache::new(spend_tx.clone());
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&spent_utxos),
            TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript),
            bitcoin::TapSighashType::Default,
        )
        .map(|h| h.to_byte_array())
        .map_err(|e| format!("Sighash failed: {}", e))?;

    spend_tx.input[0].witness = tx::build_witness(
        inst,
        clause_name,
        &mut clause_args,
        &sighash,
        signers,
    )?;

    Ok(spend_tx)
}
