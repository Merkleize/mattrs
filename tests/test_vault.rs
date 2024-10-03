mod common;

use std::str::FromStr;

use bitcoin::{bip32::Xpriv, hashes::Hash, key::Secp256k1, Address, KnownHrp, TapNodeHash};

use mattrs::{contracts::*, hub::vault::*, manager::ContractManager};

#[tokio::test]
async fn test_fund_vault() {
    let secp = Secp256k1::new();
    // Initialize the RPC client
    let client = common::get_rpc_client();

    let unvault_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    ).unwrap();
    let unvault_pubkey = unvault_privkey.to_priv().public_key(&secp);

    let recover_privkey = Xpriv::from_str(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ",
    ).unwrap();
    let recover_pubkey = recover_privkey.to_priv().public_key(&secp);

    let vault = Vault::new(VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: recover_pubkey.into(),
        unvault_pk: unvault_pubkey.into(),
    });

    let internal_key = vault.get_naked_internal_key();
    let taptree_hash = TapNodeHash::from_byte_array(vault.get_taptree().get_root_hash());

    let address = Address::p2tr(&secp, internal_key, Some(taptree_hash), KnownHrp::Regtest);

    // Define the amount to send (in BTC)
    let amount = 20_000;

    let mut manager = ContractManager::new(&client);

    let inst = manager
        .fund_instance(Box::new(vault.clone()), None, amount)
        .await
        .expect("Failed to fund instance");

    let out_inst = manager
        .spend_instance(
            inst,
            "trigger",
            Box::new(VaultTriggerClauseArgs {
                sig: [0u8; 64],
                ctv_hash: [0u8; 32],
                out_i: 0,
            }),
            None,
        )
        .await
        .expect("Failed to spend instance");

    // TODO: spend vault using the recover clause
}
