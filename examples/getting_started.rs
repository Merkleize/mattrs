//! Getting started with `mattrs`: define a contract with the `contract!` DSL,
//! derive its address, and build a spending transaction — all offline.
//!
//! The contract is a minimal timelocked payment with two clauses:
//! - `withdraw`: after `delay` blocks, the owner signs and takes the funds;
//! - `recover`: anyone can push the funds to the recovery key (via
//!   `CHECKCONTRACTVERIFY`), e.g. if the owner key is compromised.
//!
//! Run with `cargo run --example getting_started`. No Bitcoin node is needed:
//! the instance is fake-funded and the spend is built (signed) but not broadcast.

use std::str::FromStr;

use bitcoin::{Amount, ScriptBuf, TxOut, XOnlyPublicKey};
use bitcoin::bip32::Xpriv;
use bitcoin_script::{define_pushable, script};
use mattrs::manager::ContractManager;
use mattrs::signer::HotSigner;
use mattrs::testutil::{fund_fake, offline_client};
use mattrs::{contract, ContractParams, Signature};

define_pushable!();

// ============================================================================
// Contract definition
// ============================================================================

#[derive(Debug, Clone, ContractParams)]
pub struct TimeLockParams {
    pub owner_pk: XOnlyPublicKey,
    pub recover_pk: XOnlyPublicKey,
    pub delay: u32,
}

contract! {
    contract TimeLock {
        params TimeLockParams;

        // witness: <sig> — owner withdraws after the CSV delay
        clause withdraw {
            args {
                #[signer(p.owner_pk)]
                sig: Signature,
            }
            script TimeLock::withdraw_script;
        }

        // witness: <out_i> — push the funds to the recovery key
        clause recover {
            args {
                out_i: i64,
            }
            script TimeLock::recover_script;
        }

        tree [withdraw, recover];
    }
}

impl TimeLock {
    fn withdraw_script(params: &TimeLockParams) -> ScriptBuf {
        script! {
            { params.delay }
            CSV
            DROP
            { params.owner_pk }
            CHECKSIG
        }
    }

    fn recover_script(params: &TimeLockParams) -> ScriptBuf {
        script! {
            0
            SWAP
            { params.recover_pk }
            0
            0
            CHECKCONTRACTVERIFY
            TRUE
        }
    }
}

// ============================================================================
// Demo
// ============================================================================

fn main() {
    // Demo keys (never use these on mainnet).
    let owner_xpriv = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )
    .unwrap();
    let owner_signer = HotSigner::new(owner_xpriv);
    let owner_pk = {
        use mattrs::signer::Signer;
        owner_signer.public_key()
    };
    let recover_pk = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .unwrap();

    // 1. Instantiate the contract and derive its address.
    let params = TimeLockParams {
        owner_pk,
        recover_pk,
        delay: 10,
    };
    let timelock = TimeLock::new(params.clone());
    println!(
        "TimeLock address (regtest): {}",
        timelock.address(bitcoin::Network::Regtest)
    );

    // 2. Fund it. Here we fake the funding so the example runs offline (see
    //    `mattrs::testutil`); against a real node you would use
    //    `timelock.fund(&mut manager, amount)` instead.
    let handle: TimeLockHandle =
        fund_fake(timelock.as_erased(), None, Amount::from_sat(100_000), 1)
            .try_into()
            .unwrap();

    // 3. Build the withdraw spend. The signature argument is filled automatically
    //    from the registered signer — no placeholder is ever written by hand.
    //    Building performs no RPC, so an unreachable client works offline.
    let manager = ContractManager::new(offline_client(), bitcoin::Network::Regtest);

    let dest = bitcoin::Address::from_str("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437")
        .unwrap()
        .assume_checked();
    let tx = handle
        .withdraw()
        .sign(owner_signer)
        .sequence(params.delay) // satisfy the CSV timelock
        .outputs(vec![TxOut {
            script_pubkey: dest.script_pubkey(),
            value: Amount::from_sat(99_000),
        }])
        .build_tx(&manager)
        .unwrap();

    println!("withdraw tx: {}", bitcoin::consensus::encode::serialize_hex(&tx));
    println!(
        "witness: {} elements (signature, tapscript, control block)",
        tx.input[0].witness.len()
    );
    assert_eq!(tx.input[0].witness.len(), 3);
    assert!(!tx.input[0].witness.iter().next().unwrap().is_empty());
    println!("done — the signature was auto-filled and the spend is fully signed.");
}
