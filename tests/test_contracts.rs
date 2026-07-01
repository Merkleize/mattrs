use bitcoin::{ScriptBuf, XOnlyPublicKey};
use mattrs::argtypes::{ArgValue, IntType};
use mattrs::contracts::*;
use mattrs::script_utils;
use mattrs_derive::{ClauseArgs as DeriveClauseArgs, ContractParams, ContractState as DeriveContractState};
use std::str::FromStr;
use std::sync::Arc;

// ============================================================================
// Simple Vault Contract Example
// ============================================================================

// Contract parameters: owner's public key
#[derive(Debug, Clone, ContractParams)]
struct VaultParams {
    owner_pubkey: XOnlyPublicKey,
}

// Contract state: vault amount
#[derive(Debug, Clone)]
struct VaultState {
    amount: u64,
}

impl ContractState for VaultState {
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
        vec![script_utils::bn2vch(self.withdraw_amount)]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        let withdraw_amount = script_utils::vch2bn(&witness[0])
            .map_err(|e| WitnessError::DecodingFailed(e.to_string()))?;
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
    let contract = StandardAugmentedP2TR::<VaultParams, VaultState>::new(
        owner_pubkey,
        &params,
        ClauseTree::leaf(trigger_erased),
    );

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

// State whose encoding/decoding is generated by #[derive(ContractState)].
#[derive(Debug, Clone, DeriveContractState)]
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

#[test]
fn test_arg_specs_match_struct_and_witness_order() {
    use std::collections::HashMap;

    let args = SampleArgs {
        amount: 7,
        blob: vec![1, 2, 3],
        hash: [9u8; 32],
    };

    // arg_specs() are generated in declared field order.
    let specs = SampleArgs::arg_specs();
    let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["amount", "blob", "hash"]);

    // The typed witness encoding must equal encoding a matching ArgValue map
    // through the per-spec ArgType chain, element for element and in the same
    // order. This is the invariant the manager relies on.
    let typed = <SampleArgs as ClauseArgs>::encode_to_witness(&args);

    let mut map: HashMap<String, ArgValue> = HashMap::new();
    map.insert("amount".to_string(), ArgValue::Int(7));
    map.insert("blob".to_string(), ArgValue::Bytes(vec![1, 2, 3]));
    map.insert("hash".to_string(), ArgValue::Bytes(vec![9u8; 32]));

    let mut via_specs: Vec<Vec<u8>> = Vec::new();
    for spec in &specs {
        via_specs.extend(spec.arg_type.encode_to_witness(&map[&spec.name]).unwrap());
    }
    assert_eq!(typed, via_specs);

    // And the typed decode round-trips.
    let decoded = <SampleArgs as ClauseArgs>::decode_from_witness(&typed).unwrap();
    assert_eq!(decoded.amount, args.amount);
    assert_eq!(decoded.blob, args.blob);
    assert_eq!(decoded.hash, args.hash);
}

// Args with a param-dependent signature field, to exercise the generated `new()`.
#[derive(Debug, Clone, DeriveClauseArgs)]
#[clause_args(params = RoundtripParams)]
struct SignedArgs {
    #[signer(|p| p.unvault_pk.serialize())]
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
    // Single 32-byte field encodes to exactly its 32 raw bytes (no framing),
    // which is what augmented contracts commit to as the state tweak.
    assert_eq!(encoded.len(), 32);

    let decoded = DerivedState::decode(&encoded).expect("Failed to decode derived state");
    assert_eq!(decoded.commitment, state.commitment);
}

#[test]
fn test_params_encoding() {
    let owner_pubkey = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .unwrap();

    let params = VaultParams { owner_pubkey };

    // Encode (includes length prefixes: 4 bytes count + 4 bytes len + 32 bytes data = 40)
    let encoded = params.encode();
    assert_eq!(encoded.len(), 40);

    // Decode
    let decoded = VaultParams::decode(&encoded).expect("Failed to decode params");
    assert_eq!(decoded.owner_pubkey, owner_pubkey);
}

#[test]
fn test_erased_clause_operations() {
    use std::collections::HashMap;

    let _owner_pubkey = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .unwrap();

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

    // Use as ErasedClause
    let erased: &dyn ErasedClause = &trigger_clause;

    // Test encoding args to witness via HashMap
    let mut args_map = HashMap::new();
    args_map.insert("withdraw_amount".to_string(), ArgValue::Int(50000));

    let witness = erased
        .encode_args_to_witness(&args_map)
        .expect("Failed to encode args");
    assert!(!witness.is_empty());

    // Test decoding witness to args
    let decoded_map = erased
        .decode_witness_to_args(&witness)
        .expect("Failed to decode args");

    match decoded_map.get("withdraw_amount") {
        Some(ArgValue::Int(val)) => assert_eq!(*val, 50000),
        _ => panic!("Expected Int value"),
    }
}

// Params exercising the derived encoding for Option<XOnlyPublicKey>, u32 and
// XOnlyPublicKey fields (the shapes used by real contracts).
#[derive(Debug, Clone, ContractParams)]
struct RoundtripParams {
    alternate_pk: Option<XOnlyPublicKey>,
    spend_delay: u32,
    recover_pk: XOnlyPublicKey,
    unvault_pk: XOnlyPublicKey,
}

#[test]
fn test_contract_params_roundtrip() {
    let key = XOnlyPublicKey::from_slice(&[
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ])
    .unwrap();

    // alternate_pk = None
    let params = RoundtripParams {
        alternate_pk: None,
        spend_delay: 144,
        recover_pk: key,
        unvault_pk: key,
    };
    let decoded = RoundtripParams::decode(&params.encode()).expect("decode (None)");
    assert_eq!(params.alternate_pk, decoded.alternate_pk);
    assert_eq!(params.spend_delay, decoded.spend_delay);
    assert_eq!(params.recover_pk, decoded.recover_pk);
    assert_eq!(params.unvault_pk, decoded.unvault_pk);

    // alternate_pk = Some(..)
    let params = RoundtripParams {
        alternate_pk: Some(key),
        spend_delay: 288,
        recover_pk: key,
        unvault_pk: key,
    };
    let decoded = RoundtripParams::decode(&params.encode()).expect("decode (Some)");
    assert_eq!(params.alternate_pk, decoded.alternate_pk);
    assert_eq!(params.spend_delay, decoded.spend_delay);
    assert_eq!(params.recover_pk, decoded.recover_pk);
    assert_eq!(params.unvault_pk, decoded.unvault_pk);
}
