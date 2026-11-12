//! Constructor and spending regressions for CSV block durations.

mod support;

use bitcoin::{Amount, ScriptBuf, Sequence, TxOut};
use mattrs::contract;
use mattrs::contracts::{
    ClauseTree, ContractError, CtvTemplate, RawArgs, StandardClause, StandardP2TR,
};
use support::testkit::{alice_pk, bob_pk};
use support::vault::{Unvaulting, UnvaultingParams, Vault, VaultParams};

#[derive(Debug, Clone)]
struct DelayParams {
    blocks: u32,
}

contract! {
    contract Timed {
        params DelayParams;
        clause spend {
            timelock |p| p.blocks;
            script |_| ScriptBuf::from_bytes(vec![0x51]);
        }
        tree [spend];
    }
}

contract! {
    contract Validated {
        params DelayParams;
        ctx u32;
        validate |p, minimum| {
            mattrs::BlockDelay::new(p.blocks)?;
            mattrs::BlockDelay::new(*minimum)?;
            Ok(())
        };
        clause spend {
            script |_, _| -> ScriptBuf {
                panic!("validation must run before script construction")
            };
        }
        tree [spend];
    }
}

#[test]
fn invalid_delays_fail_before_nested_scripts_are_built() {
    for blocks in [0, 65_536, 1 << 22, 1 << 31, u32::MAX] {
        assert!(matches!(
            Timed::new(DelayParams { blocks }),
            Err(ContractError::InvalidBlockDelay { .. })
        ));
        assert!(matches!(
            Validated::new(DelayParams { blocks }, 1),
            Err(ContractError::InvalidBlockDelay { .. })
        ));
        assert!(matches!(
            Vault::new(VaultParams {
                alternate_pk: None,
                spend_delay: blocks,
                recover_pk: bob_pk(),
                unvault_pk: alice_pk(),
            }),
            Err(ContractError::InvalidBlockDelay { .. })
        ));
        assert!(matches!(
            Unvaulting::new(UnvaultingParams {
                alternate_pk: None,
                spend_delay: blocks,
                recover_pk: bob_pk(),
            }),
            Err(ContractError::InvalidBlockDelay { .. })
        ));
        let mut pool = support::aggregate_exits::fixture::params();
        pool.response_timeout = blocks;
        assert!(matches!(
            support::aggregate_exits::Unwind::new(pool),
            Err(ContractError::InvalidBlockDelay { .. })
        ));
    }
    assert!(Validated::new(DelayParams { blocks: 1 }, 0).is_err());
}

#[test]
fn low_level_clause_metadata_is_validated_too() {
    let clause = StandardClause::<(), (), RawArgs>::new(
        "spend".into(),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
        None,
    )
    .with_csv_blocks(65_536);
    assert!(matches!(
        StandardP2TR::<_>::new(
            "Invalid",
            mattrs::nums_key(),
            &(),
            ClauseTree::leaf(std::sync::Arc::new(clause))
        ),
        Err(ContractError::InvalidBlockDelay { .. })
    ));
}

#[test]
fn explicit_sequence_may_lengthen_but_not_bypass_the_delay() {
    let handle: TimedHandle = mattrs::testutil::fund_fake(
        Timed::new(DelayParams { blocks: 10 }).unwrap().as_erased(),
        (),
        Amount::from_sat(10_000),
        1,
    )
    .try_into()
    .unwrap();
    let outputs = vec![TxOut {
        value: Amount::from_sat(9_000),
        script_pubkey: ScriptBuf::new(),
    }];
    assert_eq!(
        handle
            .spend()
            .outputs(outputs.clone())
            .build_tx()
            .unwrap()
            .input[0]
            .sequence,
        Sequence(10)
    );
    for sequence in [0, 9, 1 << 31, (1 << 22) | 10] {
        assert!(
            handle
                .spend()
                .sequence(sequence)
                .outputs(outputs.clone())
                .build_tx()
                .is_err()
        );
    }
    assert!(
        handle
            .spend()
            .sequence(11)
            .outputs(outputs)
            .build_tx()
            .is_ok()
    );
}

#[test]
fn ctv_sequence_cannot_bypass_declared_csv() {
    contract! {
        contract ConflictingTemplate {
            params ();
            clause spend {
                timelock |_| 10;
                script |_| ScriptBuf::from_bytes(vec![0x51]);
                next(_p, _a) { Ok(CtvTemplate::new(vec![TxOut {
                    value: Amount::from_sat(9_000), script_pubkey: ScriptBuf::new(),
                }], Sequence(5))) }
            }
            tree [spend];
        }
    }
    let h: ConflictingTemplateHandle = mattrs::testutil::fund_fake(
        ConflictingTemplate::new(()).unwrap().as_erased(),
        (),
        Amount::from_sat(10_000),
        1,
    )
    .try_into()
    .unwrap();
    // Match the template's sequence explicitly, to exercise CSV validation
    // after template resolution rather than the template/override conflict.
    assert!(h.spend().sequence(5).build_tx().is_err());
}
