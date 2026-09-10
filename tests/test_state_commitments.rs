use std::sync::Arc;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Amount, Network, ScriptBuf, TxOut, XOnlyPublicKey};
use mattrs::contracts::{
    ClauseError, ClauseTree, ContractError, ContractState, ErasedContract, ErasedState, RawArgs,
    StandardAugmentedP2TR, StandardClause, StateCodec, StateCommitment,
};
use mattrs::manager::ContractManager;
use mattrs::testutil::{fund_fake, offline_client};

#[derive(Debug, Clone, mattrs::ContractState)]
#[commit(identity)]
struct RawState {
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, mattrs::ContractState)]
#[commit(sha256)]
struct HashedState {
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, mattrs::ContractState)]
#[commit(merkle)]
struct MerkleState {
    first: [u8; 32],
    #[leaf(sha256)]
    number: i64,
    #[leaf(each)]
    rest: Vec<[u8; 32]>,
}

fn contract<S: ContractState + 'static>() -> StandardAugmentedP2TR<(), S> {
    StandardAugmentedP2TR::new(
        "CommitmentTest",
        mattrs::nums_key(),
        &(),
        ClauseTree::leaf(Arc::new(StandardClause::<(), S, RawArgs>::new(
            "spend".into(),
            ScriptBuf::from_hex("51").unwrap(),
            vec![],
            None,
        ))),
    )
    .unwrap()
}

// Independent transcription of BIP-443's tweak_embed_data, with no use of the
// library's commitment or key-tweak helpers.
fn reference_key(data: &[u8]) -> XOnlyPublicKey {
    let key = mattrs::nums_key();
    if data.is_empty() {
        return key;
    }
    let preimage = [key.serialize().as_slice(), data].concat();
    let scalar =
        bitcoin::secp256k1::Scalar::from_be_bytes(sha256::Hash::hash(&preimage).to_byte_array())
            .unwrap();
    key.add_tweak(&bitcoin::secp256k1::Secp256k1::verification_only(), &scalar)
        .unwrap()
        .0
}

#[test]
fn explicit_commitments_do_not_depend_on_byte_length() {
    let raw_contract = contract::<RawState>();
    let hashed_contract = contract::<HashedState>();
    for len in [0, 1, 31, 32, 33, 520] {
        let bytes = vec![0x42; len];
        let raw = RawState {
            bytes: bytes.clone(),
        };
        let hashed = HashedState {
            bytes: bytes.clone(),
        };
        let digest = sha256::Hash::hash(&bytes).to_byte_array();
        assert_eq!(raw.commitment().as_bytes(), bytes);
        assert_eq!(hashed.commitment().as_bytes(), digest);
        assert_eq!(raw.encode(), hashed.encode());
        assert_eq!(RawState::decode(&raw.encode()).unwrap().bytes, bytes);
        assert_eq!(HashedState::decode(&hashed.encode()).unwrap().bytes, bytes);
        assert_eq!(
            raw_contract.compute_internal_key(&raw).unwrap(),
            reference_key(&bytes)
        );
        assert_eq!(
            hashed_contract.compute_internal_key(&hashed).unwrap(),
            reference_key(&digest)
        );
        assert_ne!(
            raw_contract.output_key(&raw).unwrap(),
            hashed_contract.output_key(&hashed).unwrap()
        );

        let commitment = raw.commitment();
        let erased: &dyn ErasedContract = &raw_contract;
        assert_eq!(
            raw_contract.script_pubkey(&raw).unwrap(),
            erased.script_pubkey(Some(&commitment)).unwrap()
        );
        assert_eq!(
            erased
                .control_block_internal_key(Some(&commitment))
                .unwrap(),
            reference_key(&bytes)
        );
    }
}

#[test]
fn empty_data_is_distinct_from_missing_state_and_sha256_of_empty() {
    let contract = contract::<RawState>();
    let erased: &dyn ErasedContract = &contract;
    let empty = StateCommitment::identity(Vec::new());
    assert_eq!(
        erased.control_block_internal_key(Some(&empty)).unwrap(),
        mattrs::nums_key()
    );
    assert!(matches!(
        erased.script_pubkey(None),
        Err(ContractError::MissingState)
    ));
    assert!(matches!(
        erased.control_block_internal_key(None),
        Err(ContractError::MissingState)
    ));
    assert_ne!(
        erased.script_pubkey(Some(&empty)).unwrap(),
        erased
            .script_pubkey(Some(&StateCommitment::sha256(&[])))
            .unwrap()
    );
}

#[test]
fn merkle_commitments_keep_expanded_state_without_a_codec() {
    let state = MerkleState {
        first: [1; 32],
        number: 42,
        rest: vec![[2; 32], [3; 32]],
    };
    let root = mattrs::merkle::MerkleTree::new(vec![
        state.first,
        mattrs::script_utils::commit_int(state.number),
        [2; 32],
        [3; 32],
    ])
    .root();
    assert_eq!(state.commitment().as_bytes(), root);
    let handle = fund_fake(
        Arc::new(contract::<MerkleState>()),
        Some(Box::new(state)),
        Amount::from_sat(1_000),
        0,
    );
    let recovered = handle.state::<MerkleState>().unwrap();
    assert_eq!(recovered.number, 42);
    assert_eq!(recovered.rest, [[2; 32], [3; 32]]);
}

#[test]
fn commitments_never_recover_a_different_logical_state_type() {
    let state = RawState {
        bytes: vec![0x42; 32],
    };
    let handle = fund_fake(
        Arc::new(contract::<RawState>()),
        Some(Box::new(state.clone())),
        Amount::from_sat(1_000),
        0,
    );
    // HashedState's codec could decode these bytes, but the logical type differs.
    assert!(HashedState::decode(&state.encode()).is_ok());
    assert!(handle.state::<HashedState>().is_none());
    let contract = contract::<HashedState>();
    let clause = contract.clauses().first().unwrap();
    assert!(matches!(
        clause.next_outputs_from_witness(&[], &[], Some(&state)),
        Err(ClauseError::Contract(ContractError::WrongStateType))
    ));
}

#[test]
fn commitments_are_independent_of_optional_serialization() {
    #[derive(Debug, Clone)]
    struct NoCodecAccess;
    impl ContractState for NoCodecAccess {
        fn commitment(&self) -> StateCommitment {
            StateCommitment::identity([7; 32].to_vec())
        }
    }
    impl StateCodec for NoCodecAccess {
        fn encode(&self) -> Vec<u8> {
            panic!("serialization is not a commitment")
        }
        fn decode(_: &[u8]) -> Result<Self, mattrs::contracts::WitnessError> {
            panic!("do not decode commitments")
        }
    }
    let contract = Arc::new(contract::<NoCodecAccess>());
    let state = NoCodecAccess;
    assert_eq!(state.committed_bytes(), [7; 32]);
    let handle = fund_fake(contract, Some(Box::new(state)), Amount::from_sat(1_000), 0);
    assert!(handle.state::<NoCodecAccess>().is_some());
    let mut manager = ContractManager::new(offline_client(), Network::Regtest);
    let tx = handle
        .spend_clause("spend", vec![])
        .outputs(vec![TxOut {
            value: Amount::from_sat(900),
            script_pubkey: mattrs::script_helpers::opaque_p2tr(mattrs::nums_key()),
        }])
        .build_tx(&manager)
        .unwrap();
    assert!(manager.observe_spend(&handle, &tx).unwrap().is_empty());
}

#[test]
#[ignore = "requires a running MATT-enabled regtest bitcoind"]
fn raw_state_commitments_validate_on_regtest() -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_script::{define_pushable, script};
    use mattrs::ccv::CcvIndex;
    use mattrs::contracts::ArgSpec;
    define_pushable!();
    let contract = Arc::new(StandardAugmentedP2TR::<(), RawState>::new(
        "RawData",
        mattrs::nums_key(),
        &(),
        ClauseTree::leaf(Arc::new(StandardClause::<(), RawState, RawArgs>::new(
            "reveal".into(),
            script! {
                { mattrs::script_helpers::check_input_contract(CcvIndex::CURRENT, None) } OP_TRUE
            },
            vec![ArgSpec {
                name: "data".into(),
                arg_type: Arc::new(mattrs::argtypes::BytesType),
            }],
            None,
        ))),
    )?);
    let mut manager = ContractManager::new(
        mattrs::manager::regtest_rpc_client("testwallet"),
        Network::Regtest,
    );
    for len in [0, 1, 31, 32, 33] {
        let bytes = vec![0x42; len];
        let handle = manager.fund_instance(
            contract.clone(),
            Some(Box::new(RawState {
                bytes: bytes.clone(),
            })),
            Amount::from_sat(10_000),
        )?;
        manager.mine_blocks(1)?;
        handle
            .spend_clause("reveal", vec![bytes])
            .outputs(vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: mattrs::script_helpers::opaque_p2tr(mattrs::nums_key()),
            }])
            .exec_none(&mut manager)?;
    }
    Ok(())
}
