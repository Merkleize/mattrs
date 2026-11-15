use super::*;
use crate::manager::{signing, transaction};

#[test]
fn pure_preparation_and_signing_need_no_manager() {
    let (handle, builder, calls) = signed_spend_fixture(true);
    let builders = [builder];
    let prepared = transaction::prepare(&builders).unwrap();
    assert_eq!(calls.get(), 0);
    assert_eq!(prepared.child_count(), 1);
    let tx = signing::sign_prepared(&builders, prepared, &Default::default()).unwrap();
    assert_eq!(calls.get(), 1);
    assert!(!tx.input[0].witness.is_empty());
    assert_eq!(handle.status(), InstanceStatus::Funded);
    assert!(handle.outputs().is_empty());
}

#[test]
fn staged_updates_do_nothing_until_consumed_by_commit() {
    let mut manager = offline_manager();
    let (defining, joining) = join_fixture();
    let tx = crate::manager::build_batch_tx(&[spend(&joining), spend(&defining)]).unwrap();
    let handles = [&joining, &defining];
    let staged = manager.stage_batch(&handles, &[], &tx).unwrap();
    for h in handles {
        assert_eq!(h.status(), InstanceStatus::Funded);
        assert!(h.outputs().is_empty());
    }
    assert!(manager.instances.is_empty());
    drop(staged);
    assert!(manager.instances.is_empty());
    assert_eq!(joining.status(), InstanceStatus::Funded);

    let staged = manager.stage_batch(&handles, &[], &tx).unwrap();
    let children = staged.commit(&mut manager);
    assert_eq!(children.len(), 1);
    assert_eq!(manager.instances.len(), 1);
    assert_eq!(defining.outputs()[0], joining.outputs()[0]);
    for h in handles {
        assert_eq!(h.status(), InstanceStatus::Spent);
    }
}

#[test]
fn rejected_broadcast_discards_all_staged_changes() {
    let (rpc, server) = broadcast_rpc_with_error(Some(
        serde_json::json!({"code": -26, "message": "test rejection"}),
    ));
    let mut manager = ContractManager::new(rpc, bitcoin::Network::Regtest);
    let (handle, builder, calls) = signed_spend_fixture(true);
    assert!(matches!(
        builder.exec(&mut manager),
        Err(ManagerError::Chain(crate::chain::ChainError::Rpc(_)))
    ));
    let submitted = server.join().unwrap();
    assert!(!submitted.input[0].witness.is_empty());
    assert_eq!(calls.get(), 1);
    assert_eq!(handle.status(), InstanceStatus::Funded);
    assert!(handle.outputs().is_empty());
    assert!(handle.spending_tx().is_none());
    assert!(manager.instances.is_empty());
}

#[test]
fn late_registry_conflict_is_rejected_before_broadcast() {
    let mut manager = offline_manager(); // Any attempted broadcast would fail with NoNode.
    let child = test_contract(90, None);
    let first = fund_fake(
        contract_yielding(1, vec![ClauseOutput::at(0).to(child.clone()).build()]),
        (),
        sat(10_000),
        1,
    );
    let second = fund_fake(
        contract_yielding(2, vec![ClauseOutput::at(1).to(child).build()]),
        (),
        sat(20_000),
        2,
    );
    let builders = [spend(&first), spend(&second)];
    let tx = crate::manager::build_batch_tx(&builders).unwrap();
    let conflicting = ContractInstance::funded(
        test_contract(91, None),
        Box::new(()),
        OutPoint {
            txid: tx.compute_txid(),
            vout: 1,
        },
        Arc::new(tx),
    )
    .unwrap();
    manager.instances.push(Rc::new(RefCell::new(conflicting)));
    assert!(matches!(
        manager.spend_batch(&builders),
        Err(ManagerError::ConflictingOutputContract { index: 1 })
    ));
    assert_eq!(manager.instances.len(), 1); // The first child was staged, not registered.
    for h in [&first, &second] {
        assert_eq!(h.status(), InstanceStatus::Funded);
        assert!(h.outputs().is_empty());
        assert!(h.spend_record().is_none());
    }
}

#[test]
fn execution_and_observation_record_the_same_joined_batch() {
    let mut actor = chain_manager();
    let (actor_defining, actor_joining) = join_fixture();
    let actor_children = actor
        .spend_batch(&[spend(&actor_joining), spend(&actor_defining)])
        .unwrap();
    let tx = recorded_tx(&actor_joining);
    let mut observer = offline_manager();
    let (observer_defining, observer_joining) = join_fixture();
    let observer_children = observer
        .observe_batch(&[&observer_defining, &observer_joining], &tx)
        .unwrap();
    assert_eq!(actor_children.len(), observer_children.len());
    assert_eq!(
        actor_children[0].outpoint(),
        observer_children[0].outpoint()
    );
    assert_eq!(actor_children[0].prevout(), observer_children[0].prevout());
    for (actor_parent, observer_parent) in [
        (actor_defining, observer_defining),
        (actor_joining, observer_joining),
    ] {
        assert_eq!(actor_parent.spend_record(), observer_parent.spend_record());
        assert_eq!(
            actor_parent.outputs()[0].outpoint(),
            observer_parent.outputs()[0].outpoint()
        );
    }
}

/// A rival transaction spending only *some* inputs of a pending batch rules
/// the batch out: settling finds it through whichever input it spends, not
/// only the first, records it, and leaves the other inputs unspent.
#[test]
fn a_rival_spending_one_input_settles_the_whole_pending_batch() {
    let mut manager = chain_manager();
    let chain = manager.chain().unwrap().clone();
    let (defining, joining) = join_fixture();
    // Ours spends both, the joining input first; nothing sends it.
    let pending = manager
        .broadcast_batch_with(&[spend(&joining), spend(&defining)], |_| {
            Ok::<_, ManagerError>(())
        })
        .unwrap();

    // The rival spends the second input alone, and confirms.
    let rival = spend(&defining).build_tx().unwrap();
    chain.broadcast(&rival).unwrap();
    chain.mine_blocks(1).unwrap();

    let err = pending
        .settle_within(&mut manager, Duration::ZERO)
        .unwrap_err();
    assert!(matches!(
        err,
        ManagerError::SpentByAnother { outpoint, txid }
            if outpoint == defining.outpoint() && txid == rival.compute_txid()
    ));
    assert_eq!(defining.status(), InstanceStatus::Spent);
    assert_eq!(defining.outputs().len(), 1);
    assert_eq!(joining.status(), InstanceStatus::Funded);
}

/// A rival batch confirmed in place of ours is recorded for all the inputs
/// it shares with ours at once: a joining input listed before its defining
/// input still ends up linked to the child.
#[test]
fn a_rival_batch_is_recorded_with_its_join_links() {
    let mut manager = chain_manager();
    let chain = manager.chain().unwrap().clone();
    let (defining, joining) = join_fixture();
    let pending = manager
        .broadcast_batch_with(&[spend(&joining), spend(&defining)], |_| {
            Ok::<_, ManagerError>(())
        })
        .unwrap();

    // The same spend under another txid.
    let mut rival = pending.transaction().clone();
    rival.lock_time = bitcoin::absolute::LockTime::from_consensus(7);
    chain.broadcast(&rival).unwrap();
    chain.mine_blocks(1).unwrap();

    assert!(matches!(
        pending.settle(&mut manager),
        Err(ManagerError::SpentByAnother { outpoint, txid })
            if outpoint == joining.outpoint() && txid == rival.compute_txid()
    ));
    let child = defining.outputs().into_vec();
    assert_eq!(child.len(), 1);
    assert_eq!(joining.outputs().into_vec(), child);
    assert_eq!(manager.instances.len(), 1);
}

/// A txid does not cover the witness. A confirmed transaction with our txid
/// but another witness is not ours: it is recorded as it is, and settling
/// says so.
#[test]
fn a_spend_with_our_txid_and_another_witness_is_not_ours() {
    let mut manager = chain_manager();
    let chain = manager.chain().unwrap().clone();
    let (handle, builder, _) = signed_spend_fixture(true);
    let pending = manager
        .broadcast_batch_with(&[builder], |_| Ok::<_, ManagerError>(()))
        .unwrap();

    // The same transaction body, spent with a different signature argument.
    let mut rival = pending.transaction().clone();
    let mut witness = rival.input[0].witness.to_vec();
    witness[0] = vec![9; 64];
    rival.input[0].witness = bitcoin::Witness::from_slice(&witness);
    assert_eq!(rival.compute_txid(), pending.txid());
    assert!(!pending.is(&rival));
    assert!(pending.is(pending.transaction()));
    chain.broadcast(&rival).unwrap();
    chain.mine_blocks(1).unwrap();

    assert!(matches!(
        pending.settle(&mut manager),
        Err(ManagerError::SpentByAnother { txid, .. }) if txid == pending.txid()
    ));
    // What is recorded is the witness that confirmed, not the one we signed.
    assert_eq!(handle.spend_record().unwrap().args()[0], vec![9; 64]);
    assert_eq!(handle.outputs().len(), 1);
}
