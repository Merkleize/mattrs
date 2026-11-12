use super::*;
use crate::manager::{signing, transaction};

#[test]
fn pure_preparation_and_signing_need_no_manager() {
    let (handle, builder, calls) = signed_spend_fixture(true);
    let builders = [builder];
    let prepared = transaction::prepare(&builders).unwrap();
    assert_eq!(calls.get(), 0);
    assert_eq!(prepared.child_count(), 1);
    let tx = signing::sign_prepared(&builders, prepared).unwrap();
    assert_eq!(calls.get(), 1);
    assert!(!tx.input[0].witness.is_empty());
    assert_eq!(handle.status(), InstanceStatus::Funded);
    assert!(handle.outputs().is_empty());
}

#[test]
fn staged_updates_do_nothing_until_consumed_by_commit() {
    let mut manager = offline_manager();
    let (defining, joining) = join_fixture();
    let tx = manager
        .build_batch_tx(&[spend(&joining), spend(&defining)])
        .unwrap();
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
        Err(ManagerError::RpcError(_))
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
    let mut manager = offline_manager(); // Any attempted broadcast would fail with RpcError.
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
    let tx = manager.build_batch_tx(&builders).unwrap();
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
        assert!(h.spending_args().is_none());
    }
}

#[test]
fn execution_and_observation_record_the_same_joined_batch() {
    let (rpc, server) = broadcast_rpc();
    let mut actor = ContractManager::new(rpc, bitcoin::Network::Regtest);
    let (actor_defining, actor_joining) = join_fixture();
    let actor_children = actor
        .spend_batch(&[spend(&actor_joining), spend(&actor_defining)])
        .unwrap();
    let tx = server.join().unwrap();
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
        assert_eq!(actor_parent.spending_tx(), observer_parent.spending_tx());
        assert_eq!(
            actor_parent.spending_args(),
            observer_parent.spending_args()
        );
        assert_eq!(actor_parent.spending_vin(), observer_parent.spending_vin());
        assert_eq!(
            actor_parent.outputs()[0].outpoint(),
            observer_parent.outputs()[0].outpoint()
        );
    }
}
