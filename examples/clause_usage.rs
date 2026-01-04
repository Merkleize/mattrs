//! Example demonstrating the usage of Clause and StandardClause with type erasure.
//!
//! This example shows how to:
//! 1. Define contract-specific types (Params, State, Args)
//! 2. Create clauses with compile-time type safety
//! 3. Store them in type-erased form for use by a manager
//! 4. Work with clauses polymorphically at runtime

use mattrs::argtypes::{ArgValue, BytesType, IntType, SignerType};
use mattrs::contracts::*;
use bitcoin::ScriptBuf;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// Define Contract-Specific Types
// ============================================================================

/// Parameters for a simple vault contract
#[derive(Debug, Clone)]
struct VaultParams {
    owner_pubkey: [u8; 32],
    recovery_pubkey: [u8; 32],
}

impl ContractParams for VaultParams {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.owner_pubkey);
        bytes.extend_from_slice(&self.recovery_pubkey);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() != 64 {
            return Err(WitnessError::InvalidData(
                format!("Expected 64 bytes for VaultParams, got {}", bytes.len())
            ));
        }

        let mut owner_pubkey = [0u8; 32];
        let mut recovery_pubkey = [0u8; 32];
        owner_pubkey.copy_from_slice(&bytes[0..32]);
        recovery_pubkey.copy_from_slice(&bytes[32..64]);

        Ok(VaultParams {
            owner_pubkey,
            recovery_pubkey,
        })
    }
}

/// State for a vault contract
#[derive(Debug, Clone)]
struct VaultState {
    amount: u64,
    unlock_time: u32,
}

impl ContractState for VaultState {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.unlock_time.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() != 12 {
            return Err(WitnessError::InvalidData(
                format!("Expected 12 bytes, got {}", bytes.len())
            ));
        }

        let amount = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let unlock_time = u32::from_le_bytes(bytes[8..12].try_into().unwrap());

        Ok(VaultState {
            amount,
            unlock_time,
        })
    }
}

/// Arguments for the "trigger" clause
#[derive(Debug, Clone)]
struct TriggerArgs {
    signature: Vec<u8>,
}

impl ClauseArgs for TriggerArgs {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.signature.clone()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::InsufficientData);
        }
        Ok(TriggerArgs {
            signature: witness[0].clone(),
        })
    }
}

/// Arguments for the "withdraw" clause
#[derive(Debug, Clone)]
struct WithdrawArgs {
    signature: Vec<u8>,
    amount: i64,
}

impl ClauseArgs for WithdrawArgs {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        use mattrs::script_utils::bn2vch;
        vec![
            self.signature.clone(),
            bn2vch(self.amount),
        ]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError> {
        use mattrs::script_utils::vch2bn;
        
        if witness.len() < 2 {
            return Err(WitnessError::InsufficientData);
        }
        
        let signature = witness[0].clone();
        let amount = vch2bn(&witness[1])?;

        Ok(WithdrawArgs { signature, amount })
    }
}

fn main() {
    println!("=== Clause and Contract Type Erasure Example ===\n");

    // ============================================================================
    // 1. Create Clauses with Compile-Time Types
    // ============================================================================

    let owner_pubkey = [0x02; 32];
    let recovery_pubkey = [0x03; 32];

    // Create the "trigger" clause
    let trigger_clause = StandardClause::<VaultParams, VaultState, TriggerArgs>::new(
        "trigger".to_string(),
        ScriptBuf::new(), // Placeholder script
        vec![
            ArgSpec {
                name: "sig".to_string(),
                arg_type: Arc::new(SignerType::new(owner_pubkey)),
            },
        ],
        Some(Arc::new(|params: &VaultParams, args: &TriggerArgs, state: Option<&VaultState>| {
            println!("  Computing next outputs for 'trigger' clause");
            println!("    Owner pubkey: {:02x?}", &params.owner_pubkey[..4]);
            println!("    Signature length: {} bytes", args.signature.len());
            if let Some(state) = state {
                println!("    Current amount: {}", state.amount);
                println!("    Unlock time: {}", state.unlock_time);
            }
            
            // Return empty outputs for this example
            Ok(Vec::new())
        })),
    );

    // Create the "withdraw" clause
    let withdraw_clause = StandardClause::<VaultParams, VaultState, WithdrawArgs>::new(
        "withdraw".to_string(),
        ScriptBuf::new(), // Placeholder script
        vec![
            ArgSpec {
                name: "sig".to_string(),
                arg_type: Arc::new(SignerType::new(owner_pubkey)),
            },
            ArgSpec {
                name: "amount".to_string(),
                arg_type: Arc::new(IntType),
            },
        ],
        Some(Arc::new(|params: &VaultParams, args: &WithdrawArgs, state: Option<&VaultState>| {
            println!("  Computing next outputs for 'withdraw' clause");
            println!("    Owner pubkey: {:02x?}", &params.owner_pubkey[..4]);
            println!("    Signature length: {} bytes", args.signature.len());
            println!("    Withdraw amount: {}", args.amount);
            if let Some(state) = state {
                println!("    Remaining: {}", state.amount as i64 - args.amount);
            }
            
            Ok(Vec::new())
        })),
    );

    // ============================================================================
    // 2. Type Erasure - Store as Arc<dyn ErasedClause>
    // ============================================================================

    let trigger_erased: Arc<dyn ErasedClause> = Arc::new(trigger_clause);
    let withdraw_erased: Arc<dyn ErasedClause> = Arc::new(withdraw_clause);

    // ============================================================================
    // 3. Create a Contract with Type-Erased Clauses
    // ============================================================================

    let contract = StandardAugmentedP2TR::<VaultParams, VaultState>::new(
        owner_pubkey,
        vec![trigger_erased.clone(), withdraw_erased.clone()],
    );

    println!("Created contract with {} clauses:", contract.clauses().len());
    for clause in contract.clauses() {
        println!("  - {}", clause.name());
    }
    println!();

    // ============================================================================
    // 4. Work with Clauses Polymorphically
    // ============================================================================

    // Simulate a manager working with type-erased clauses
    println!("=== Simulating Manager Operations ===\n");

    // Create test state
    let params = VaultParams {
        owner_pubkey,
        recovery_pubkey,
    };
    let params_bytes = params.encode();
    
    let state = VaultState {
        amount: 100_000,
        unlock_time: 1000,
    };
    let state_bytes = state.encode();

    // Test 1: Trigger clause
    println!("1. Using 'trigger' clause:");
    {
        let clause = contract.get_clause("trigger").unwrap();
        
        let mut args = HashMap::new();
        args.insert("sig".to_string(), ArgValue::Signature(vec![0xaa; 64]));

        // Encode args to witness
        let witness = clause.encode_args_to_witness(&args).unwrap();
        println!("  Encoded to {} witness elements", witness.len());

        // Decode witness back to args
        let decoded_args = clause.decode_witness_to_args(&witness).unwrap();
        println!("  Decoded {} arguments", decoded_args.len());

        // Compute next outputs
        let _outputs = clause.next_outputs_erased(&params_bytes, &args, Some(&state_bytes)).unwrap();
        println!();
    }

    // Test 2: Withdraw clause
    println!("2. Using 'withdraw' clause:");
    {
        let clause = contract.get_clause("withdraw").unwrap();
        
        let mut args = HashMap::new();
        args.insert("sig".to_string(), ArgValue::Signature(vec![0xbb; 64]));
        args.insert("amount".to_string(), ArgValue::Int(25_000));

        // Encode args to witness
        let witness = clause.encode_args_to_witness(&args).unwrap();
        println!("  Encoded to {} witness elements", witness.len());

        // Decode witness back to args
        let decoded_args = clause.decode_witness_to_args(&witness).unwrap();
        println!("  Decoded {} arguments", decoded_args.len());

        // Compute next outputs
        let _outputs = clause.next_outputs_erased(&params_bytes, &args, Some(&state_bytes)).unwrap();
        println!();
    }

    // ============================================================================
    // 5. Demonstrate Contract List Without Knowing Types
    // ============================================================================

    println!("=== Working with Heterogeneous Contracts ===\n");

    let contracts: Vec<Arc<dyn ErasedContract>> = vec![
        Arc::new(contract.clone()),
        Arc::new(StandardP2TR::<VaultParams>::new(
            owner_pubkey,
            vec![trigger_erased.clone()],
        )),
    ];

    println!("Manager has {} contracts:", contracts.len());
    for (i, contract) in contracts.iter().enumerate() {
        println!("  Contract {}: {} clauses", i, contract.clauses().len());
        for clause in contract.clauses() {
            println!("    - {}", clause.name());
        }
    }
    println!();

    println!("✓ Example completed successfully!");
    println!("\nKey takeaways:");
    println!("  1. Clauses are defined with full type safety");
    println!("  2. Type erasure allows polymorphic storage and usage");
    println!("  3. The manager can work with any clause without knowing its types");
    println!("  4. Runtime argument encoding/decoding works transparently");
}
