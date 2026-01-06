use bitcoin::{ScriptBuf, XOnlyPublicKey};
use mattrs::argtypes::{ArgValue, IntType};
use mattrs::contracts::*;
use mattrs::script_utils;
use mattrs_derive::ContractParams;
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

    let _params = VaultParams { owner_pubkey };

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

    // Create TapTree with single leaf
    let taptree = Arc::new(TapTree::leaf("trigger", trigger_script));

    // Build the contract
    let contract = StandardAugmentedP2TR::<VaultParams, VaultState>::new(
        owner_pubkey,
        taptree.clone(),
        vec![Arc::new(trigger_clause.clone())],
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

#[test]
fn test_contract_params_roundtrip() {
    use mattrs::vault::{UnvaultingParams, VaultParams};

    // NUMS key (nothing-up-my-sleeve point)
    let nums_key_bytes = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ];
    let nums_key = XOnlyPublicKey::from_slice(&nums_key_bytes).unwrap();

    // Test VaultParams with None
    let params1 = VaultParams {
        alternate_pk: None,
        spend_delay: 144,
        recover_pk: nums_key,
        unvault_pk: nums_key,
    };

    let encoded1 = params1.encode();
    let decoded1 = VaultParams::decode(&encoded1).expect("Failed to decode VaultParams with None");

    assert_eq!(params1.alternate_pk, decoded1.alternate_pk);
    assert_eq!(params1.spend_delay, decoded1.spend_delay);
    assert_eq!(
        params1.recover_pk.serialize(),
        decoded1.recover_pk.serialize()
    );
    assert_eq!(
        params1.unvault_pk.serialize(),
        decoded1.unvault_pk.serialize()
    );

    // Test VaultParams with Some
    let params2 = VaultParams {
        alternate_pk: Some(nums_key),
        spend_delay: 288,
        recover_pk: nums_key,
        unvault_pk: nums_key,
    };

    let encoded2 = params2.encode();
    let decoded2 = VaultParams::decode(&encoded2).expect("Failed to decode VaultParams with Some");

    assert_eq!(
        params2.alternate_pk.unwrap().serialize(),
        decoded2.alternate_pk.unwrap().serialize()
    );
    assert_eq!(params2.spend_delay, decoded2.spend_delay);
    assert_eq!(
        params2.recover_pk.serialize(),
        decoded2.recover_pk.serialize()
    );
    assert_eq!(
        params2.unvault_pk.serialize(),
        decoded2.unvault_pk.serialize()
    );

    // Test UnvaultingParams with None
    let params3 = UnvaultingParams {
        alternate_pk: None,
        spend_delay: 100,
        recover_pk: nums_key,
    };

    let encoded3 = params3.encode();
    let decoded3 =
        UnvaultingParams::decode(&encoded3).expect("Failed to decode UnvaultingParams with None");

    assert_eq!(params3.alternate_pk, decoded3.alternate_pk);
    assert_eq!(params3.spend_delay, decoded3.spend_delay);
    assert_eq!(
        params3.recover_pk.serialize(),
        decoded3.recover_pk.serialize()
    );

    // Test UnvaultingParams with Some
    let params4 = UnvaultingParams {
        alternate_pk: Some(nums_key),
        spend_delay: 200,
        recover_pk: nums_key,
    };

    let encoded4 = params4.encode();
    let decoded4 =
        UnvaultingParams::decode(&encoded4).expect("Failed to decode UnvaultingParams with Some");

    assert_eq!(
        params4.alternate_pk.unwrap().serialize(),
        decoded4.alternate_pk.unwrap().serialize()
    );
    assert_eq!(params4.spend_delay, decoded4.spend_delay);
    assert_eq!(
        params4.recover_pk.serialize(),
        decoded4.recover_pk.serialize()
    );
}
