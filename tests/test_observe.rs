//! Chain observation end-to-end test: an observer follows a covenant that a
//! different manager drives, learning each spend's clause and typed arguments
//! and receiving the materialized child instances.

mod support;

use std::str::FromStr;

use bitcoin::{Address, Amount};
use mattrs::contracts::{ClauseArgs, InstanceStatus};
use mattrs::ctv::create_ctv_template;
use mattrs::manager::ContractManager;
use mattrs::signer::HotSigner;
use support::testkit::{alice_pk, alice_xpriv, bob_pk, regtest_client};
use support::vault::{UnvaultingHandle, Vault, VaultParams, VaultTriggerArgs};

#[test]
#[ignore = "requires a running regtest bitcoind"]
fn test_observer_follows_vault_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let params = VaultParams {
        alternate_pk: None,
        spend_delay: 10,
        recover_pk: bob_pk(),
        unvault_pk: alice_pk(),
    };

    // ---- The actor drives the whole vault lifecycle. ----
    let actor_client = regtest_client("testwallet");
    let mut actor = ContractManager::new(actor_client);

    let amount = 49_999_900u64;
    let vault_a = Vault::new(params.clone()).fund(&mut actor, Amount::from_sat(amount))?;
    let funding_outpoint = vault_a.handle().outpoint().unwrap();

    let ctv_template = vec![(
        Address::from_str("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437")?.assume_checked(),
        Amount::from_sat(amount),
    )];
    let ctv_hash = create_ctv_template(&ctv_template, bitcoin::Sequence(10)).ctv_hash();

    let unvaulting_a: UnvaultingHandle = vault_a
        .trigger(ctv_hash, 0)
        .sign(HotSigner::new(alice_xpriv()))
        .exec_one(&mut actor)?
        .try_into()?;

    // Confirm the trigger and satisfy the CSV delay, then withdraw via CTV.
    actor.mine_blocks(10)?;
    let withdraw_outputs: Vec<bitcoin::TxOut> = ctv_template
        .iter()
        .map(|(addr, amount)| bitcoin::TxOut {
            script_pubkey: addr.script_pubkey(),
            value: *amount,
        })
        .collect();
    unvaulting_a
        .withdraw(ctv_hash)
        .outputs(withdraw_outputs)
        .sequence(10)
        .exec_none(&mut actor)?;

    // ---- The observer follows it, after the fact. ----
    // The trigger spend is buried in a block by now (block-scan path); the
    // withdraw is still in the mempool (gettxspendingprevout path).
    let observer_client = regtest_client("testwallet");
    let mut observer = ContractManager::new(observer_client);

    let vault_b = observer.track_instance(
        Vault::new(params.clone()).as_erased(),
        None,
        funding_outpoint,
    )?;

    let children = observer.wait_for_spend(&vault_b)?;
    assert_eq!(children.len(), 1);
    assert_eq!(vault_b.clause_name().as_deref(), Some("trigger"));
    let args = VaultTriggerArgs::decode_from_witness(&vault_b.spending_args().unwrap())?;
    assert_eq!(args.ctv_hash, ctv_hash);
    assert!(!args.sig.is_empty());

    // The observed child matches the actor's, including its logical state.
    let unvaulting_b: UnvaultingHandle = children[0].clone().try_into().unwrap();
    assert_eq!(
        unvaulting_b.handle().outpoint(),
        unvaulting_a.handle().outpoint()
    );
    assert_eq!(unvaulting_b.state().unwrap().ctv_hash, ctv_hash);

    // Follow the terminal withdraw: no children, clause + args recorded.
    let final_children = observer.wait_for_spend(unvaulting_b.handle())?;
    assert!(final_children.is_empty());
    assert_eq!(
        unvaulting_b.handle().clause_name().as_deref(),
        Some("withdraw")
    );
    assert_eq!(unvaulting_b.handle().status(), InstanceStatus::Spent);

    Ok(())
}
