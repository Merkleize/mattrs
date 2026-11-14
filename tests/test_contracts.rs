use bitcoin::{ScriptBuf, XOnlyPublicKey};
use mattrs::argtypes::IntType;
use mattrs::contracts::*;
use mattrs::script;
use mattrs::{ClauseArgs as DeriveClauseArgs, ContractState as DeriveContractState};
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;

// ============================================================================
// Simple Vault Contract Example
// ============================================================================

// Contract parameters: owner's public key
#[derive(Debug, Clone, PartialEq)]
struct VaultParams {
    owner_pubkey: XOnlyPublicKey,
}

// Contract state: vault amount
#[derive(Debug, Clone)]
struct VaultState {
    amount: u64,
}

impl ContractState for VaultState {
    fn commitment(&self) -> StateCommitment {
        StateCommitment::sha256(&self.encode())
    }
}

impl StateCodec for VaultState {
    fn encode(&self) -> Vec<u8> {
        // Encode amount as 8-byte big-endian
        self.amount.to_be_bytes().to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() != 8 {
            return Err(WitnessError::InvalidValue(format!(
                "Expected 8 bytes for amount, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        let amount = u64::from_be_bytes(arr);
        Ok(VaultState { amount })
    }
}

// Trigger clause arguments
#[derive(Debug, Clone)]
struct TriggerArgs {
    withdraw_amount: i64,
}

impl ClauseArgs for TriggerArgs {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![script::bn2vch(self.withdraw_amount)]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        let withdraw_amount =
            script::vch2bn(&witness[0]).map_err(|e| WitnessError::DecodingFailed(e.to_string()))?;
        Ok(TriggerArgs { withdraw_amount })
    }
}

#[test]
fn test_vault_contract_creation() {
    // Create a test pubkey
    let owner_pubkey = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .unwrap();

    let params = VaultParams { owner_pubkey };

    // Create trigger clause script (simplified)
    let trigger_script = ScriptBuf::from_hex("51").unwrap(); // OP_TRUE for testing

    // Build the trigger clause
    let trigger_clause: StandardClause<VaultParams, VaultState, TriggerArgs> = StandardClause::new(
        "trigger".to_string(),
        trigger_script.clone(),
        vec![ArgSpec {
            name: "withdraw_amount".to_string(),
            arg_type: Arc::new(IntType),
        }],
        None, // No next_outputs for this simple test
    );

    // Build the contract from a single-leaf clause tree.
    let trigger_erased: Arc<dyn ErasedClause> = Arc::new(trigger_clause.clone());
    let contract = StandardP2TR::<VaultParams, VaultState>::new(
        "TestVault",
        owner_pubkey,
        &params,
        ClauseTree::leaf(trigger_erased),
    )
    .expect("contract definition is valid");

    // Create initial state
    let state = VaultState { amount: 100000 };

    // Get output key and scriptPubKey
    let output_key = contract
        .output_key(&state)
        .expect("Failed to compute output key");
    let script_pubkey = contract
        .script_pubkey(&state)
        .expect("Failed to compute scriptPubKey");

    println!("Output key: {}", output_key);
    println!("ScriptPubKey: {}", script_pubkey);
    assert!(!script_pubkey.is_empty());

    // The contract hands its params back as the typed value it was built from.
    assert_eq!(
        contract.params_any().downcast_ref::<VaultParams>(),
        Some(&params)
    );
}

fn test_clause(name: &str, script_hex: &str) -> Arc<dyn ErasedClause> {
    Arc::new(StandardClause::<(), (), TriggerArgs>::new(
        name.to_string(),
        ScriptBuf::from_hex(script_hex).unwrap(),
        vec![],
        None,
    ))
}

#[test]
fn contract_rejects_duplicate_clause_names() {
    let owner = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .unwrap();
    let result = StandardP2TR::<_>::new(
        "DuplicateNames",
        owner,
        &(),
        ClauseTree::branch(
            ClauseTree::leaf(test_clause("spend", "51")),
            ClauseTree::leaf(test_clause("spend", "52")),
        ),
    );

    assert!(matches!(
        result,
        Err(ContractError::DuplicateClauseName(name)) if name == "spend"
    ));
}

#[test]
fn contract_rejects_duplicate_clause_scripts() {
    let owner = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .unwrap();
    let result = StandardP2TR::<_>::new(
        "DuplicateScripts",
        owner,
        &(),
        ClauseTree::branch(
            ClauseTree::leaf(test_clause("first", "51")),
            ClauseTree::leaf(test_clause("second", "51")),
        ),
    );

    assert!(matches!(
        result,
        Err(ContractError::DuplicateClauseScript { first, second })
            if first == "first" && second == "second"
    ));
}

#[test]
fn test_taptree_operations() {
    // Create a simple taptree
    let script1 = ScriptBuf::from_hex("51").unwrap();
    let script2 = ScriptBuf::from_hex("52").unwrap();

    let leaf1 = TapTree::leaf("clause1", script1.clone());
    let leaf2 = TapTree::leaf("clause2", script2.clone());

    let tree = TapTree::branch(leaf1, leaf2);

    // Test finding leaves
    let found_leaf = tree.find_leaf("clause1");
    assert!(found_leaf.is_some());
    assert_eq!(found_leaf.unwrap().name, "clause1");

    let not_found = tree.find_leaf("clause3");
    assert!(not_found.is_none());

    // Test getting all leaves
    let leaves = tree.leaves();
    assert_eq!(leaves.len(), 2);

    // Test root hash computation
    let root_hash = tree.root_hash();
    assert_eq!(root_hash.len(), 32);
}

#[test]
fn test_taptree_merkle_proof_is_leaf_to_root() {
    // tree = branch(a, branch(b, c)): the proof for b must list its siblings
    // deepest-first (c's leaf hash, then a's subtree hash), which is the order
    // a BIP341 control block expects. A root-to-leaf ordering only shows up
    // on-chain for leaves at depth >= 2, so pin it here.
    let a = TapTree::leaf("a", ScriptBuf::from_hex("51").unwrap());
    let b = TapTree::leaf("b", ScriptBuf::from_hex("52").unwrap());
    let c = TapTree::leaf("c", ScriptBuf::from_hex("53").unwrap());
    let a_hash = a.root_hash();
    let c_hash = c.root_hash();
    let tree = TapTree::branch(a, TapTree::branch(b, c));
    let b_leaf = tree.find_leaf("b").unwrap().clone();
    assert_eq!(tree.merkle_proof(&b_leaf), Some(vec![c_hash, a_hash]));
}

#[test]
fn test_clause_witness_encoding() {
    let args = TriggerArgs {
        withdraw_amount: 50000,
    };

    // Encode to witness
    let witness = args.encode_to_witness();
    assert!(!witness.is_empty());

    // Decode back
    let decoded = TriggerArgs::decode_from_witness(&witness).expect("Failed to decode");
    assert_eq!(decoded.withdraw_amount, 50000);
}

#[test]
fn test_state_encoding() {
    let state = VaultState { amount: 100000 };

    // Encode
    let encoded = state.encode();
    assert_eq!(encoded.len(), 8);

    // Decode
    let decoded = VaultState::decode(&encoded).expect("Failed to decode state");
    assert_eq!(decoded.amount, 100000);
}

// Field types the derive once refused ("cannot infer an ArgType"): the layout
// now comes from each field's own codec, whatever the type is spelled.
type Hash = [u8; 32];

#[derive(Debug, Clone, PartialEq, DeriveClauseArgs)]
struct AnyEncodableArgs {
    flag: bool,
    key: XOnlyPublicKey,
    maybe: Option<i64>,
    hash: Hash,
    proof: mattrs::merkle::WitProof<2>,
}

#[test]
fn test_arg_layout_comes_from_the_field_codec() {
    let specs = AnyEncodableArgs::arg_specs();
    let counts: Vec<_> = specs
        .iter()
        .map(|s| s.arg_type.witness_elements())
        .collect();
    assert_eq!(counts, [Some(1), Some(1), None, Some(1), Some(5)]);

    // Walking a real witness spec by spec consumes exactly what was encoded,
    // including the value-dependent `Option`.
    let tree = mattrs::merkle::MerkleTree::new(vec![[1u8; 32], [2; 32], [3; 32], [4; 32]]);
    for maybe in [None, Some(-5)] {
        let args = AnyEncodableArgs {
            flag: true,
            key: mattrs::nums_key(),
            maybe,
            hash: [9; 32],
            proof: tree.prove_leaf(1).unwrap().to_wit_proof().unwrap(),
        };
        let witness = <AnyEncodableArgs as ClauseArgs>::encode_to_witness(&args);
        let mut offset = 0;
        for spec in &specs {
            offset += spec.arg_type.consume(&witness[offset..]).unwrap();
        }
        assert_eq!(offset, witness.len());
        assert_eq!(
            <AnyEncodableArgs as ClauseArgs>::decode_from_witness(&witness).unwrap(),
            args
        );
    }

    // A spec rejects what its field's codec would reject.
    assert!(specs[3].arg_type.consume(&[vec![0; 31]]).is_err());
    assert!(specs[0].arg_type.consume(&[vec![0]]).is_err());
}

// State whose encoding/decoding is generated by #[derive(ContractState)].
#[derive(Debug, Clone, DeriveContractState)]
#[commit(identity)]
struct DerivedState {
    commitment: [u8; 32],
}

// Args whose encoding + arg_specs are generated by #[derive(ClauseArgs)].
#[derive(Debug, Clone, DeriveClauseArgs)]
struct SampleArgs {
    amount: i64,
    blob: Vec<u8>,
    hash: [u8; 32],
}

// A type may intentionally be used both as a witness argument and as nested
// contract parameters. These derives must not create overlapping impls.
#[derive(Debug, Clone, DeriveClauseArgs)]
struct DualCodec {
    value: i64,
}

#[derive(Debug, Clone, DeriveClauseArgs)]
struct GenericArgs<T>
where
    T: WitnessEncodable + Debug + Clone + Send + Sync,
{
    #[arg_type(mattrs::argtypes::BytesType)]
    value: T,
}

#[derive(Debug, Clone, DeriveContractState)]
#[commit(identity)]
struct GenericState<T>
where
    T: SingleWitnessElement + Debug + Clone + Send + Sync,
{
    value: T,
}

#[test]
fn test_derived_codecs_support_generics_and_multiple_roles() {
    let dual = DualCodec { value: 17 };
    let witness = <DualCodec as ClauseArgs>::encode_to_witness(&dual);
    assert_eq!(
        <DualCodec as ClauseArgs>::decode_from_witness(&witness)
            .unwrap()
            .value,
        dual.value
    );
    let args = GenericArgs::new(vec![1u8, 2, 3]);
    let witness = <GenericArgs<Vec<u8>> as ClauseArgs>::encode_to_witness(&args);
    assert_eq!(
        <GenericArgs<Vec<u8>> as ClauseArgs>::decode_from_witness(&witness)
            .unwrap()
            .value,
        args.value
    );

    let state = GenericState { value: [7u8; 32] };
    let encoded = state.encode();
    assert_eq!(
        GenericState::<[u8; 32]>::decode(&encoded).unwrap().value,
        state.value
    );
}

#[test]
fn test_arg_specs_match_struct_and_witness_order() {
    let args = SampleArgs {
        amount: 7,
        blob: vec![1, 2, 3],
        hash: [9u8; 32],
    };

    // arg_specs() are generated in declared field order.
    let specs = SampleArgs::arg_specs();
    let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["amount", "blob", "hash"]);

    // Walking the specs' consume() must partition the typed witness encoding
    // exactly — spec by spec, in field order, covering every element. This is
    // the invariant the manager relies on to locate signature slots.
    let typed = <SampleArgs as ClauseArgs>::encode_to_witness(&args);

    let mut offset = 0usize;
    for spec in &specs {
        let consumed = spec.arg_type.consume(&typed[offset..]).unwrap();
        assert_eq!(consumed, 1, "each SampleArgs field is one witness element");
        offset += consumed;
    }
    assert_eq!(offset, typed.len());

    // And the typed decode round-trips.
    let decoded = <SampleArgs as ClauseArgs>::decode_from_witness(&typed).unwrap();
    assert_eq!(decoded.amount, args.amount);
    assert_eq!(decoded.blob, args.blob);
    assert_eq!(decoded.hash, args.hash);
}

// Args with a param-dependent signature field, to exercise the generated `new()`.
#[derive(Debug, Clone, DeriveClauseArgs)]
#[clause_args(params = SignerParams)]
struct SignedArgs {
    #[signer(|p| p.unvault_pk)]
    sig: mattrs::Signature,
    amount: i64,
}

#[test]
fn test_generated_new_omits_signer_fields() {
    // A struct with no signer fields: new() takes every field.
    let sample = SampleArgs::new(7, vec![1, 2, 3], [9u8; 32]);
    assert_eq!(sample.amount, 7);
    assert_eq!(sample.blob, vec![1, 2, 3]);

    // A struct with a signer field: new() omits it. The signature defaults to empty
    // and is filled in by the manager at spend time (no placeholder from the caller).
    let args = SignedArgs::new(42);
    assert!(args.sig.is_empty());
    assert_eq!(args.amount, 42);

    // The encoded witness still carries the (empty) signature element in position 0,
    // so the witness layout matches the declared field order.
    let witness = <SignedArgs as ClauseArgs>::encode_to_witness(&args);
    assert_eq!(witness.len(), 2);
    assert!(witness[0].is_empty());

    let decoded = <SignedArgs as ClauseArgs>::decode_from_witness(&witness).unwrap();
    assert_eq!(decoded.amount, 42);
}

#[test]
fn test_derived_state_roundtrip() {
    let state = DerivedState {
        commitment: [0xab; 32],
    };

    let encoded = state.encode();
    // Single-element state remains the raw element bytes: covenant scripts
    // re-reveal this exact value as the state tweak.
    assert_eq!(encoded.len(), 32);

    let decoded = DerivedState::decode(&encoded).expect("Failed to decode derived state");
    assert_eq!(decoded.commitment, state.commitment);

    assert!(DerivedState::decode(&encoded[..encoded.len() - 1]).is_err());
    let mut with_tail = encoded.clone();
    with_tail.push(0);
    assert!(DerivedState::decode(&with_tail).is_err());
}

#[test]
fn test_ctv_template_clause_fixes_tx_outputs_and_sequence() {
    let mut manager = mattrs::testutil::local_manager();
    use bitcoin::{Address, Amount, Sequence, TxOut};

    // The exact outputs + input sequence the clause commits to.
    let dest = Address::from_str("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437")
        .unwrap()
        .assume_checked();
    let template_outputs = vec![TxOut {
        script_pubkey: dest.script_pubkey(),
        value: Amount::from_sat(90_000),
    }];
    let template_seq = Sequence(10);

    // A one-clause contract whose clause returns a CTV template.
    let outs = template_outputs.clone();
    let clause: Arc<dyn ErasedClause> = Arc::new(StandardClause::<(), (), TriggerArgs>::new(
        "pay".to_string(),
        ScriptBuf::from_hex("51").unwrap(),
        vec![ArgSpec {
            name: "withdraw_amount".to_string(),
            arg_type: Arc::new(IntType),
        }],
        Some(Arc::new(move |_p: &(), _a: &TriggerArgs, _s: &()| {
            Ok(NextOutputs::Template(CtvTemplate::new(
                outs.clone(),
                template_seq,
            )))
        })),
    ));

    let owner = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .unwrap();
    let erased: Arc<dyn ErasedContract> = Arc::new(
        StandardP2TR::<()>::new("Pay", owner, &(), ClauseTree::leaf(clause))
            .expect("contract definition is valid"),
    );
    // Fake a funded instance (building the tx does no RPC).
    let handle = manager
        .fund_instance(erased, (), Amount::from_sat(100_000))
        .unwrap();

    let witness =
        <TriggerArgs as ClauseArgs>::encode_to_witness(&TriggerArgs { withdraw_amount: 1 });
    let tx = handle.spend_clause("pay", witness).build_tx().unwrap();

    // The template fixes the outputs and the input sequence.
    assert_eq!(tx.output, template_outputs);
    assert_eq!(tx.input[0].sequence, template_seq);
}

#[test]
fn test_expanded_state_flows_to_next_outputs() {
    // A lossy commitment cannot recover `secret`. No codec is needed: a clause's
    // next_outputs must see the instance's expanded logical state.
    #[derive(Debug, Clone)]
    struct CounterState {
        secret: i64,
    }
    impl ContractState for CounterState {
        fn commitment(&self) -> StateCommitment {
            StateCommitment::identity(script::commit_int(self.secret).to_vec())
        }
    }

    // Succeeds only when next_outputs observes secret == 42.
    let clause: StandardClause<(), CounterState, SampleArgs> = StandardClause::new(
        "check".to_string(),
        ScriptBuf::from_hex("51").unwrap(),
        SampleArgs::arg_specs(),
        Some(Arc::new(
            |_p: &(), _a: &SampleArgs, s: &CounterState| match s {
                st if st.secret == 42 => Ok(NextOutputs::Outputs(vec![])),
                other => Err(ClauseError::Other(format!("unexpected state: {:?}", other))),
            },
        )),
    );
    let erased: &dyn ErasedClause = &clause;

    let witness =
        <SampleArgs as ClauseArgs>::encode_to_witness(&SampleArgs::new(1, vec![], [0u8; 32]));

    // The commitment is a 32-byte hash and decode cannot recover the secret.
    let state = CounterState { secret: 42 };
    assert_eq!(state.commitment().as_bytes().len(), 32);

    // With the expanded state, next_outputs sees the real secret (via downcast).
    assert!(
        erased
            .next_outputs_from_witness(&(), &witness, &state)
            .is_ok()
    );

    // A state of any other type (here the stateless `()`) is rejected rather
    // than reinterpreted.
    assert!(matches!(
        erased.next_outputs_from_witness(&(), &witness, &()),
        Err(ClauseError::Contract(
            mattrs::contracts::ContractError::WrongStateType
        ))
    ));

    // Likewise params of another type: they are downcast, never decoded.
    assert!(matches!(
        erased.next_outputs_from_witness(&7u32, &witness, &state),
        Err(ClauseError::Contract(
            mattrs::contracts::ContractError::WrongParamsType
        ))
    ));
}

#[test]
fn test_erased_clause_operations() {
    let trigger_script = ScriptBuf::from_hex("51").unwrap();

    let trigger_clause: StandardClause<VaultParams, VaultState, TriggerArgs> = StandardClause::new(
        "trigger".to_string(),
        trigger_script,
        vec![ArgSpec {
            name: "withdraw_amount".to_string(),
            arg_type: Arc::new(IntType),
        }],
        None,
    );

    // Use as ErasedClause: the erased view exposes the name, script, and the
    // arg specs that account for the typed witness encoding.
    let erased: &dyn ErasedClause = &trigger_clause;
    assert_eq!(erased.name(), "trigger");

    let witness = TriggerArgs {
        withdraw_amount: 50000,
    }
    .encode_to_witness();
    assert!(!witness.is_empty());

    // The specs consume exactly the typed encoding...
    let specs = erased.arg_specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].name, "withdraw_amount");
    assert_eq!(specs[0].arg_type.consume(&witness).unwrap(), witness.len());

    // ...and the typed decode recovers the arguments.
    let decoded = TriggerArgs::decode_from_witness(&witness).expect("Failed to decode args");
    assert_eq!(decoded.withdraw_amount, 50000);
}

// Params named by a `#[signer(..)]` expression; only its type is used.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct SignerParams {
    unvault_pk: XOnlyPublicKey,
}

#[test]
fn unit_state_rejects_trailing_serialized_bytes() {
    assert!(<() as StateCodec>::decode(&[0]).is_err());
}

#[test]
fn test_derived_clause_args_reject_trailing_elements() {
    let args = SampleArgs::new(7, vec![1, 2, 3], [9u8; 32]);
    let mut witness = <SampleArgs as ClauseArgs>::encode_to_witness(&args);
    witness.push(vec![0xaa]);
    assert!(<SampleArgs as ClauseArgs>::decode_from_witness(&witness).is_err());
}

#[test]
fn test_canonical_option_flags_and_checked_script_numbers() {
    let none = <Option<i64> as WitnessEncodable>::encode_to_witness(&None);
    assert_eq!(none, vec![Vec::<u8>::new()]);
    assert_eq!(
        <Option<i64> as WitnessEncodable>::decode_from_witness(&none)
            .unwrap()
            .0,
        None
    );

    assert!(<Option<i64> as WitnessEncodable>::decode_from_witness(&[vec![0]]).is_err());
    assert!(<Option<i64> as WitnessEncodable>::decode_from_witness(&[vec![2]]).is_err());

    let too_large = script::bn2vch(i64::from(i32::MAX) + 1);
    assert!(<i32 as WitnessEncodable>::decode_from_witness(&[too_large]).is_err());
}
