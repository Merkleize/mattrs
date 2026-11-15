//! Getting started with `mattrs`: define a contract with the `contract!` DSL,
//! derive its address, fund it and spend it — all without a Bitcoin node.
//!
//! The contract is a minimal timelocked payment with two clauses:
//! - `withdraw`: after `delay` blocks, the owner signs and takes the funds;
//! - `recover`: anyone can push the funds to the recovery key (via
//!   `CHECKCONTRACTVERIFY`), e.g. if the owner key is compromised.
//!
//! Run with `cargo run --example getting_started`. The manager here runs on an
//! in-memory chain ([`LocalChain`]), which mints the funding and records the
//! spend without executing scripts. Against a real node the code is the same
//! with `ContractManager::new(rpc_client, network)` — minus the auto-mining,
//! on a chain that has miners.

use std::str::FromStr;

use std::rc::Rc;

use bitcoin::bip32::Xpriv;
use bitcoin::{Amount, ScriptBuf, TxOut, XOnlyPublicKey};
use mattrs::prelude::*;
use mattrs::script::check_output_pays_key;

// ============================================================================
// Contract definition
// ============================================================================

#[derive(Debug, Clone)]
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
            timelock |p| p.delay;
            script TimeLock::withdraw_script;
        }

        // witness: <out_i> — push the funds to the recovery key
        clause recover {
            args {
                out_i: CcvIndex,
            }
            script TimeLock::recover_script;
        }

        tree [withdraw, recover];
    }
}

impl TimeLock {
    fn withdraw_script(params: &TimeLockParams) -> ScriptBuf {
        script! {
            { params.owner_pk }
            CHECKSIG
        }
    }

    fn recover_script(params: &TimeLockParams) -> ScriptBuf {
        script! {
            { check_output_pays_key(params.recover_pk) }
            TRUE
        }
    }
}

// ============================================================================
// Demo
// ============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Demo keys (never use these on mainnet).
    let owner_xpriv = Xpriv::from_str(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN",
    )?;
    let owner_signer = HotSigner::new(owner_xpriv);
    let owner_pk = owner_signer.public_key();
    let recover_pk = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )?;

    // 1. Instantiate the contract and derive its address.
    let params = TimeLockParams {
        owner_pk,
        recover_pk,
        delay: 10,
    };
    let timelock = TimeLock::new(params.clone())?;
    println!(
        "TimeLock address (regtest): {}",
        timelock.address(bitcoin::Network::Regtest)
    );

    // 2. A manager tracks instances and executes spends. The owner's key is
    //    registered once; every spend it executes is signed from it. A
    //    manager records a funding or a spend only once it is confirmed, and
    //    nobody mines on this chain: have it mine a block after each
    //    transaction it sends.
    let chain = Rc::new(LocalChain::new());
    let mut manager = ContractManager::on(chain.clone(), bitcoin::Network::Regtest)
        .with_signer(owner_signer)
        .with_auto_mining();

    // 3. Fund it: `fund` returns a typed handle with one method per clause,
    //    once the funding transaction is confirmed.
    let handle = timelock.fund(&mut manager, Amount::from_sat(100_000))?;

    // 4. Spend it. `withdraw` is timelocked, so the funding must first be
    //    `delay` blocks deep. The signature argument is filled automatically —
    //    no placeholder is ever written by hand.
    chain.mine(params.delay);
    let dest = bitcoin::Address::from_str("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437")?
        .assume_checked();
    handle
        .withdraw()
        .outputs(vec![TxOut {
            script_pubkey: dest.script_pubkey(),
            value: Amount::from_sat(99_000),
        }])
        .exec_none(&mut manager)?;

    // The manager recorded the spend, and the handle decodes it.
    assert_eq!(handle.status(), InstanceStatus::Spent);
    assert_eq!(handle.spent_clause(), Some(TimeLockClause::Withdraw));
    let tx = handle.spending_tx().ok_or("no spending tx")?;

    println!(
        "withdraw tx: {}",
        bitcoin::consensus::encode::serialize_hex(&tx)
    );
    println!(
        "witness: {} elements (signature, tapscript, control block)",
        tx.input[0].witness.len()
    );
    assert_eq!(tx.input[0].witness.len(), 3);
    assert!(
        !tx.input[0]
            .witness
            .iter()
            .next()
            .ok_or("the signed witness is empty")?
            .is_empty()
    );
    println!("done — funded, signed and spent on the in-memory chain.");
    Ok(())
}
