//! Wallet-funded vault batch on a CCV-enabled regtest node.
//!
//! Run with a funded `testwallet` and the usual BITCOIN_RPC_* authentication:
//! `cargo run --example wallet_funding`. Broadcasts transactions and mines blocks.
//! The fixed contract keys below are public demo keys: REGTEST ONLY.

#[allow(dead_code)]
#[path = "vault/contracts.rs"]
mod vault;

use bitcoin::{Amount, Network, ScriptBuf, Sequence, Transaction, TxOut, Txid, bip32::Xpriv};
use bitcoincore_rpc::RpcApi;
use mattrs::contracts::InstanceStatus;
use mattrs::manager::{ContractManager, ExternalInput, InstanceHandle, regtest_rpc_client};
use mattrs::signer::HotSigner;
use serde_json::{Value, json};
use vault::{Vault, VaultParams};

/// Shared with the live integration test so the documented workflow is tested.
pub fn run() -> Result<Txid, Box<dyn std::error::Error>> {
    let wallet = regtest_rpc_client("testwallet")?;
    let mut manager = ContractManager::new(regtest_rpc_client("testwallet")?, Network::Regtest)
        .with_auto_mining();
    if wallet.get_blockchain_info()?.chain != Network::Regtest {
        return Err("this example must only run on regtest".into());
    }
    let key = Xpriv::new_master(Network::Regtest, &[42])?;
    let recovery = Xpriv::new_master(Network::Regtest, &[43])?;
    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: HotSigner::new(recovery).public_key(),
        unvault_pk: HotSigner::new(key).public_key(),
    };
    let first = Vault::new(params.clone())?.fund(&mut manager, Amount::from_sat(100_000))?;
    let second = Vault::new(params.clone())?.fund(&mut manager, Amount::from_sat(200_000))?;
    manager.mine_blocks(1)?;

    // A separate observer knows the contracts, but not the actor's wallet coins.
    let mut observer = ContractManager::new(regtest_rpc_client("testwallet")?, Network::Regtest)
        .with_auto_mining();
    let vault = Vault::new(params)?;
    let observed_first: InstanceHandle = vault.track(&mut observer, first.outpoint())?.into();
    let observed_second: InstanceHandle = vault.track(&mut observer, second.outpoint())?.into();

    // The trigger commits to a later withdrawal. This example only triggers;
    // extending a fixed CTV withdrawal with fee inputs requires a compatible
    // template designed in advance, not a bypass of CTV validation.
    let destination = wallet
        .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32))?
        .require_network(Network::Regtest)?;
    let ctv_hash =
        mattrs::ctv::create_ctv_template(&[(destination, Amount::from_sat(300_000))], Sequence(10))
            .ctv_hash();
    let prepared = manager.prepare_wallet_spend(vec![
        first.trigger(ctv_hash, 0).sign(HotSigner::new(key)),
        second.trigger(ctv_hash, 0).sign(HotSigner::new(key)),
    ])?;
    let input_weights: Vec<_> = prepared.transaction().input.iter().zip(prepared.input_weights()).map(|(input, weight)| json!({
        "txid": input.previous_output.txid, "vout": input.previous_output.vout, "weight": weight,
    })).collect();

    // Coin selection, fee estimation, and change belong to the wallet. Core
    // needs the contract input weights because it cannot solve our tapscripts.
    // Force change to the end; never subtract fees from contract outputs.
    let result: Value = wallet.call(
        "fundrawtransaction",
        &[
            json!(bitcoin::consensus::encode::serialize_hex(
                prepared.transaction()
            )),
            json!({ "add_inputs": true, "changePosition": prepared.transaction().output.len(),
            "change_type": "bech32", "fee_rate": 1, "input_weights": input_weights }),
        ],
    )?;
    let funded: Transaction = bitcoin::consensus::deserialize(&hex::decode(
        result["hex"].as_str().ok_or("missing funded hex")?,
    )?)?;
    if funded.input.len() <= prepared.transaction().input.len() {
        return Err("expected the wallet to add at least one fee input".into());
    }
    let mut external = Vec::new();
    for input in &funded.input[prepared.transaction().input.len()..] {
        // Resolve before broadcast while these wallet outputs are unspent.
        let prevout = wallet
            .get_tx_out(
                &input.previous_output.txid,
                input.previous_output.vout,
                Some(true),
            )?
            .ok_or("wallet funding input is no longer unspent")?;
        external.push(ExternalInput {
            outpoint: input.previous_output,
            prevout: TxOut {
                value: prevout.value,
                script_pubkey: ScriptBuf::from_bytes(prevout.script_pub_key.hex),
            },
        });
    }
    // Validate everything before asking contract signers to authorize the final
    // body. An absolute cap also catches accidental sat/vB vs BTC/kvB mistakes.
    let signed =
        prepared.sign_funded(&manager, funded, external.clone(), Amount::from_sat(10_000))?;
    // The wallet only needs to sign the inputs it added. Hand it the
    // transaction *without* the covenant witnesses: it cannot evaluate those
    // scripts, and witnesses are not part of any signature hash, so they can
    // be put back afterwards unchanged.
    let is_wallet_input =
        |outpoint: &bitcoin::OutPoint| external.iter().any(|x| x.outpoint == *outpoint);
    let mut for_wallet = signed.transaction().clone();
    for input in &mut for_wallet.input {
        if !is_wallet_input(&input.previous_output) {
            input.witness.clear();
        }
    }
    let wallet_signed = wallet.sign_raw_transaction_with_wallet(&for_wallet, None, None)?;
    // The wallet reports the covenant inputs as unsigned, which is expected;
    // an error on one of *its* inputs is a failure.
    let unsigned_wallet_inputs: Vec<_> = wallet_signed
        .errors
        .iter()
        .flatten()
        .filter(|e| {
            is_wallet_input(&bitcoin::OutPoint {
                txid: e.txid,
                vout: e.vout,
            })
        })
        .collect();
    if !unsigned_wallet_inputs.is_empty() {
        return Err(format!("wallet signing incomplete: {unsigned_wallet_inputs:?}").into());
    }
    let mut final_tx: Transaction = bitcoin::consensus::deserialize(&wallet_signed.hex)?;
    for (input, ours) in final_tx.input.iter_mut().zip(&signed.transaction().input) {
        if !is_wallet_input(&input.previous_output) {
            input.witness = ours.witness.clone();
        }
    }
    signed.validate_final(&final_tx)?;
    let txid = wallet.send_raw_transaction(&final_tx)?;
    // The observer below only follows a confirmed spend.
    manager.mine_blocks(1)?;
    let result = signed.observe_final(&mut manager, &final_tx)?;
    assert_eq!(result.children.len(), 1);
    assert_eq!(
        result.children[0].prevout().value,
        Amount::from_sat(300_000)
    );
    assert_eq!(first.status(), InstanceStatus::Spent);
    assert_eq!(second.status(), InstanceStatus::Spent);

    // A passive observer can resolve spent wallet prevouts from a trusted cache
    // or funding transactions. `gettxout` alone no longer works after broadcast.
    let observed = observer.wait_for_batch_with_external_inputs(
        &[&observed_second, &observed_first],
        |outpoint| {
            external
                .iter()
                .find(|e| e.outpoint == outpoint)
                .map(|e| e.prevout.clone())
                .ok_or_else(|| {
                    mattrs::manager::ManagerError::other(format!(
                        "missing cached prevout {outpoint}"
                    ))
                })
        },
    )?;
    assert_eq!(observed.fee, result.fee);
    assert_eq!(observed.children.len(), 1);
    assert_eq!(
        observed.children[0].outpoint(),
        result.children[0].outpoint()
    );
    println!(
        "Wallet-funded batch {txid}: preserved 300000 sats; external wallet paid {} sats",
        result.fee.to_sat()
    );
    Ok(txid)
}

#[allow(dead_code)] // Also compiled as a module by the live integration test.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().map(|_| ())
}
