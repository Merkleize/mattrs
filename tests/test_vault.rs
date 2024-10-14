mod common;

use std::{collections::HashMap, str::FromStr};

use bitcoin::{
    bip32::Xpriv, hashes::Hash, key::Secp256k1, Address, KnownHrp, TapNodeHash, XOnlyPublicKey,
};

use mattrs::{
    contracts::*,
    hub::vault::*,
    manager::ContractManager,
    signer::{HotSigner, SchnorrSigner},
};

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

    let mut signers: HashMap<XOnlyPublicKey, Box<dyn SchnorrSigner>> = HashMap::new();

    signers.insert(
        unvault_pubkey.into(),
        Box::new(HotSigner {
            privkey: unvault_privkey,
        }),
    );

    let out_inst = manager
        .spend_instance(
            inst,
            "trigger",
            Box::new(VaultTriggerClauseArgs {
                // TODO: put real data
                sig: Signature::default(),
                ctv_hash: [
                    0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8, 11u8, 12u8, 13u8, 14u8,
                    15u8, 16u8, 17u8, 18u8, 19u8, 20u8, 21u8, 22u8, 23u8, 24u8, 25u8, 26u8, 27u8,
                    28u8, 29u8, 30u8, 31u8,
                ],
                out_i: 0,
            }),
            None,
            Some(&signers),
        )
        .await
        .expect("Failed to spend instance");

    // TODO: spend vault using the recover clause
}
