//! Vault contract implementation
//!
//! A two-stage vault with trigger and recovery mechanisms.

use std::sync::Arc;

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};

use crate::argtypes::{BytesType, IntType, SignerType};
use crate::contracts::{
    ArgSpec, ClauseArgs, ClauseError, ClauseOutput, ClauseOutputAmountBehaviour, ContractParams,
    ContractState, ErasedClause, ErasedContract, StandardAugmentedP2TR, StandardClause,
    StandardP2TR, TapTree, WitnessEncodable, WitnessError,
};

define_pushable!();

// NUMS key (nothing-up-my-sleeve)
const NUMS_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Helper function to handle optional pubkey (NUMS if None)
fn optional_key(key: Option<XOnlyPublicKey>) -> XOnlyPublicKey {
    key.unwrap_or_else(|| XOnlyPublicKey::from_slice(&NUMS_KEY).expect("Valid NUMS key"))
}

// ============================================================================
// Clause Argument Types for Vault
// ============================================================================

/// Empty state type for contracts without state
#[derive(Debug, Clone)]
pub struct NoState;

impl ContractState for NoState {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode(_bytes: &[u8]) -> Result<Self, WitnessError> {
        Ok(NoState)
    }
}

impl WitnessEncodable for NoState {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn decode_from_witness(_witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        Ok((NoState, 0))
    }
}

/// Arguments for the trigger clause
#[derive(Debug, Clone)]
pub struct TriggerArgs {
    pub sig: Vec<u8>,
    pub ctv_hash: Vec<u8>,
    pub out_i: i64,
}

impl ClauseArgs for TriggerArgs {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![
            self.sig.clone(),
            self.ctv_hash.clone(),
            crate::script_utils::bn2vch(self.out_i),
        ]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError> {
        if witness.len() < 3 {
            return Err(WitnessError::InsufficientData);
        }
        Ok(TriggerArgs {
            sig: witness[0].clone(),
            ctv_hash: witness[1].clone(),
            out_i: crate::script_utils::vch2bn(&witness[2])
                .map_err(|e| WitnessError::DecodingFailed(e.to_string()))?,
        })
    }
}

/// Arguments for the trigger_and_revault clause
#[derive(Debug, Clone)]
pub struct TriggerAndRevaultArgs {
    pub sig: Vec<u8>,
    pub ctv_hash: Vec<u8>,
    pub out_i: i64,
    pub revault_out_i: i64,
}

impl ClauseArgs for TriggerAndRevaultArgs {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![
            crate::script_utils::bn2vch(self.revault_out_i),
            crate::script_utils::bn2vch(self.out_i),
            self.ctv_hash.clone(),
            self.sig.clone(),
        ]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError> {
        if witness.len() < 4 {
            return Err(WitnessError::InsufficientData);
        }
        Ok(TriggerAndRevaultArgs {
            sig: witness[3].clone(),
            ctv_hash: witness[2].clone(),
            out_i: crate::script_utils::vch2bn(&witness[1])
                .map_err(|e| WitnessError::DecodingFailed(e.to_string()))?,
            revault_out_i: crate::script_utils::vch2bn(&witness[0])
                .map_err(|e| WitnessError::DecodingFailed(e.to_string()))?,
        })
    }
}

/// Arguments for the recover clause
#[derive(Debug, Clone)]
pub struct RecoverArgs {
    pub out_i: i64,
}

impl ClauseArgs for RecoverArgs {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![crate::script_utils::bn2vch(self.out_i)]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::InsufficientData);
        }
        Ok(RecoverArgs {
            out_i: crate::script_utils::vch2bn(&witness[0])
                .map_err(|e| WitnessError::DecodingFailed(e.to_string()))?,
        })
    }
}

/// Arguments for the Unvaulting withdraw clause
#[derive(Debug, Clone)]
pub struct WithdrawArgs {
    pub ctv_hash: Vec<u8>,
}

impl ClauseArgs for WithdrawArgs {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.ctv_hash.clone()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::InsufficientData);
        }
        Ok(WithdrawArgs {
            ctv_hash: witness[0].clone(),
        })
    }
}

/// Arguments for the Unvaulting recover clause
#[derive(Debug, Clone)]
pub struct UnvaultingRecoverArgs {
    pub out_i: i64,
}

impl ClauseArgs for UnvaultingRecoverArgs {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![crate::script_utils::bn2vch(self.out_i)]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<Self, WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::InsufficientData);
        }
        Ok(UnvaultingRecoverArgs {
            out_i: crate::script_utils::vch2bn(&witness[0])
                .map_err(|e| WitnessError::DecodingFailed(e.to_string()))?,
        })
    }
}

// ============================================================================
// Vault Contract (Non-Augmented)
// ============================================================================

#[derive(Debug, Clone)]
pub struct VaultParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
    pub unvault_pk: XOnlyPublicKey,
}

impl ContractParams for VaultParams {
    fn encode(&self) -> Vec<u8> {
        // Simple encoding - in practice you'd want proper serialization
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &self
                .alternate_pk
                .map(|k| k.serialize())
                .unwrap_or([0u8; 32]),
        );
        bytes.extend_from_slice(&self.spend_delay.to_le_bytes());
        bytes.extend_from_slice(&self.recover_pk.serialize());
        bytes.extend_from_slice(&self.unvault_pk.serialize());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() != 32 + 4 + 32 + 32 {
            return Err(WitnessError::DecodingFailed(
                "VaultParams must be 100 bytes".to_string(),
            ));
        }

        let mut alternate_pk_bytes = [0u8; 32];
        alternate_pk_bytes.copy_from_slice(&bytes[0..32]);
        let alternate_pk = if alternate_pk_bytes == [0u8; 32] {
            None
        } else {
            Some(
                XOnlyPublicKey::from_slice(&alternate_pk_bytes).map_err(|e| {
                    WitnessError::DecodingFailed(format!("Invalid alternate_pk: {}", e))
                })?,
            )
        };

        let mut spend_delay_bytes = [0u8; 4];
        spend_delay_bytes.copy_from_slice(&bytes[32..36]);
        let spend_delay = u32::from_le_bytes(spend_delay_bytes);

        let recover_pk = XOnlyPublicKey::from_slice(&bytes[36..68])
            .map_err(|e| WitnessError::DecodingFailed(format!("Invalid recover_pk: {}", e)))?;

        let unvault_pk = XOnlyPublicKey::from_slice(&bytes[68..100])
            .map_err(|e| WitnessError::DecodingFailed(format!("Invalid unvault_pk: {}", e)))?;

        Ok(VaultParams {
            alternate_pk,
            spend_delay,
            recover_pk,
            unvault_pk,
        })
    }
}

/// Vault contract structure
pub struct Vault {
    pub params: VaultParams,
    pub contract: StandardP2TR<VaultParams>,
}

impl Vault {
    pub fn new(params: VaultParams) -> Self {
        let internal_key = optional_key(params.alternate_pk);

        // Build taptree
        let trigger = Self::trigger_script(&params);
        let trigger_and_revault = Self::trigger_and_revault_script(&params);
        let recover = Self::recover_script(&params);

        let taptree = Arc::new(TapTree::Branch {
            left: Arc::new(TapTree::Leaf(crate::contracts::TapLeaf {
                name: "trigger".to_string(),
                script: trigger.clone(),
            })),
            right: Arc::new(TapTree::Branch {
                left: Arc::new(TapTree::Leaf(crate::contracts::TapLeaf {
                    name: "trigger_and_revault".to_string(),
                    script: trigger_and_revault.clone(),
                })),
                right: Arc::new(TapTree::Leaf(crate::contracts::TapLeaf {
                    name: "recover".to_string(),
                    script: recover.clone(),
                })),
            }),
        });

        // Create clause objects
        let trigger_clause: Arc<dyn ErasedClause> =
            Arc::new(StandardClause::<VaultParams, NoState, TriggerArgs>::new(
                "trigger".to_string(),
                trigger,
                vec![
                    ArgSpec {
                        name: "sig".to_string(),
                        arg_type: Arc::new(SignerType::new(params.unvault_pk.serialize())),
                    },
                    ArgSpec {
                        name: "ctv_hash".to_string(),
                        arg_type: Arc::new(BytesType),
                    },
                    ArgSpec {
                        name: "out_i".to_string(),
                        arg_type: Arc::new(IntType),
                    },
                ],
                Some(Arc::new(
                    move |p: &VaultParams, args: &TriggerArgs, _state: Option<&NoState>| {
                        let mut ctv_hash = [0u8; 32];
                        if args.ctv_hash.len() != 32 {
                            return Err(ClauseError::Other("Invalid ctv_hash length".to_string()));
                        }
                        ctv_hash.copy_from_slice(&args.ctv_hash);

                        let vault = Vault::new(p.clone());
                        vault
                            .trigger_outputs(ctv_hash, args.out_i as i32)
                            .map_err(|e| ClauseError::Other(e))
                    },
                )),
            ));

        let trigger_and_revault_clause: Arc<dyn ErasedClause> = Arc::new(StandardClause::<
            VaultParams,
            NoState,
            TriggerAndRevaultArgs,
        >::new(
            "trigger_and_revault".to_string(),
            trigger_and_revault,
            vec![
                ArgSpec {
                    name: "sig".to_string(),
                    arg_type: Arc::new(SignerType::new(params.unvault_pk.serialize())),
                },
                ArgSpec {
                    name: "ctv_hash".to_string(),
                    arg_type: Arc::new(BytesType),
                },
                ArgSpec {
                    name: "out_i".to_string(),
                    arg_type: Arc::new(IntType),
                },
                ArgSpec {
                    name: "revault_out_i".to_string(),
                    arg_type: Arc::new(IntType),
                },
            ],
            Some(Arc::new(
                move |p: &VaultParams, args: &TriggerAndRevaultArgs, _state: Option<&NoState>| {
                    let mut ctv_hash = [0u8; 32];
                    if args.ctv_hash.len() != 32 {
                        return Err(ClauseError::Other("Invalid ctv_hash length".to_string()));
                    }
                    ctv_hash.copy_from_slice(&args.ctv_hash);

                    let vault = Vault::new(p.clone());
                    vault
                        .trigger_and_revault_outputs(
                            ctv_hash,
                            args.out_i as i32,
                            args.revault_out_i as i32,
                        )
                        .map_err(|e| ClauseError::Other(e))
                },
            )),
        ));

        let recover_clause: Arc<dyn ErasedClause> =
            Arc::new(StandardClause::<VaultParams, NoState, RecoverArgs>::new(
                "recover".to_string(),
                recover,
                vec![ArgSpec {
                    name: "out_i".to_string(),
                    arg_type: Arc::new(IntType),
                }],
                Some(Arc::new(
                    move |p: &VaultParams, _args: &RecoverArgs, _state: Option<&NoState>| {
                        let vault = Vault::new(p.clone());
                        vault.recover_outputs().map_err(|e| ClauseError::Other(e))
                    },
                )),
            ));

        let clauses = vec![trigger_clause, trigger_and_revault_clause, recover_clause];

        let contract = StandardP2TR::new(internal_key, taptree, clauses);

        Vault { params, contract }
    }

    fn trigger_script(params: &VaultParams) -> ScriptBuf {
        let unvaulting_params = UnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        };
        let unvaulting_taptree_root = Unvaulting::build_taptree(&unvaulting_params).root_hash();

        script! {
            { crate::optional_key(params.alternate_pk) }
            { unvaulting_taptree_root }
            0
            CHECKCONTRACTVERIFY

            { params.unvault_pk }
            CHECKSIG
        }
    }

    fn trigger_and_revault_script(params: &VaultParams) -> ScriptBuf {
        let unvaulting_params = UnvaultingParams {
            alternate_pk: params.alternate_pk,
            spend_delay: params.spend_delay,
            recover_pk: params.recover_pk,
        };
        let unvaulting_taptree_root = Unvaulting::build_taptree(&unvaulting_params).root_hash();

        script! {
            0 OP_SWAP // no data tweak
            -1 // current input's taptweak
            -1 // taptree
            { crate::contracts::CCV_FLAG_DEDUCT_OUTPUT_AMOUNT }
            CHECKCONTRACTVERIFY

            { crate::optional_key(params.alternate_pk) }
            { unvaulting_taptree_root }
            0
            CHECKCONTRACTVERIFY

            { params.unvault_pk }
            CHECKSIG
        }
    }

    fn recover_script(params: &VaultParams) -> ScriptBuf {
        script! {
            0 // data
            SWAP // <out_i> (from witness)
            { params.recover_pk }
            0 // taptree
            0 // flags
            CHECKCONTRACTVERIFY
            TRUE
        }
    }

    /// Get the contract as a type-erased ErasedContract
    pub fn as_erased(&self) -> Arc<dyn ErasedContract> {
        Arc::new(self.contract.clone())
    }

    /// Execute trigger clause - creates unvaulting instance
    pub fn trigger_outputs(
        &self,
        _ctv_hash: [u8; 32],
        out_i: i32,
    ) -> Result<Vec<ClauseOutput>, String> {
        let unvaulting_params = UnvaultingParams {
            alternate_pk: self.params.alternate_pk,
            spend_delay: self.params.spend_delay,
            recover_pk: self.params.recover_pk,
        };

        let unvaulting = Unvaulting::new(unvaulting_params.clone());

        let state = UnvaultingState {
            ctv_hash: _ctv_hash,
        };
        let state_bytes = state.encode();

        Ok(vec![ClauseOutput {
            n: out_i,
            next_contract: unvaulting.as_erased(state.clone()),
            next_params: Some(unvaulting_params.encode()),
            next_state: Some(state_bytes),
            next_amount: ClauseOutputAmountBehaviour::PreserveOutput,
        }])
    }

    /// Execute trigger_and_revault clause
    pub fn trigger_and_revault_outputs(
        &self,
        ctv_hash: [u8; 32],
        out_i: i32,
        revault_out_i: i32,
    ) -> Result<Vec<ClauseOutput>, String> {
        let unvaulting_params = UnvaultingParams {
            alternate_pk: self.params.alternate_pk,
            spend_delay: self.params.spend_delay,
            recover_pk: self.params.recover_pk,
        };

        let unvaulting = Unvaulting::new(unvaulting_params.clone());

        let state = UnvaultingState { ctv_hash };
        let state_bytes = state.encode();

        Ok(vec![
            ClauseOutput {
                n: revault_out_i,
                next_contract: Arc::new(Vault::new(self.params.clone()).contract),
                next_params: None, // Revault uses same params as parent
                next_state: None,
                next_amount: ClauseOutputAmountBehaviour::DeductOutput,
            },
            ClauseOutput {
                n: out_i,
                next_contract: unvaulting.as_erased(state.clone()),
                next_params: Some(unvaulting_params.encode()),
                next_state: Some(state_bytes),
                next_amount: ClauseOutputAmountBehaviour::PreserveOutput,
            },
        ])
    }

    /// Execute recover clause - no outputs
    pub fn recover_outputs(&self) -> Result<Vec<ClauseOutput>, String> {
        Ok(Vec::new())
    }
}

// ============================================================================
// Unvaulting Contract (Augmented)
// ============================================================================

#[derive(Debug, Clone)]
pub struct UnvaultingParams {
    pub alternate_pk: Option<XOnlyPublicKey>,
    pub spend_delay: u32,
    pub recover_pk: XOnlyPublicKey,
}

impl ContractParams for UnvaultingParams {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &self
                .alternate_pk
                .map(|k| k.serialize())
                .unwrap_or([0u8; 32]),
        );
        bytes.extend_from_slice(&self.spend_delay.to_le_bytes());
        bytes.extend_from_slice(&self.recover_pk.serialize());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() != 32 + 4 + 32 {
            return Err(WitnessError::DecodingFailed(
                "UnvaultingParams must be 68 bytes".to_string(),
            ));
        }

        let mut alternate_pk_bytes = [0u8; 32];
        alternate_pk_bytes.copy_from_slice(&bytes[0..32]);
        let alternate_pk = if alternate_pk_bytes == [0u8; 32] {
            None
        } else {
            Some(
                XOnlyPublicKey::from_slice(&alternate_pk_bytes).map_err(|e| {
                    WitnessError::DecodingFailed(format!("Invalid alternate_pk: {}", e))
                })?,
            )
        };

        let mut spend_delay_bytes = [0u8; 4];
        spend_delay_bytes.copy_from_slice(&bytes[32..36]);
        let spend_delay = u32::from_le_bytes(spend_delay_bytes);

        let recover_pk = XOnlyPublicKey::from_slice(&bytes[36..68])
            .map_err(|e| WitnessError::DecodingFailed(format!("Invalid recover_pk: {}", e)))?;

        Ok(UnvaultingParams {
            alternate_pk,
            spend_delay,
            recover_pk,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UnvaultingState {
    pub ctv_hash: [u8; 32],
}

impl ContractState for UnvaultingState {
    fn encode(&self) -> Vec<u8> {
        self.ctv_hash.to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() != 32 {
            return Err(WitnessError::InvalidData(
                "UnvaultingState must be 32 bytes".to_string(),
            ));
        }
        let mut ctv_hash = [0u8; 32];
        ctv_hash.copy_from_slice(bytes);
        Ok(UnvaultingState { ctv_hash })
    }
}

impl WitnessEncodable for UnvaultingState {
    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.ctv_hash.to_vec()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::InsufficientData);
        }
        let state = Self::decode(&witness[0])?;
        Ok((state, 1))
    }
}

pub struct Unvaulting {
    pub params: UnvaultingParams,
}

impl Unvaulting {
    pub fn new(params: UnvaultingParams) -> Self {
        Unvaulting { params }
    }

    pub fn build_taptree(params: &UnvaultingParams) -> Arc<TapTree> {
        let withdraw = Self::withdraw_script(params);
        let recover = Self::recover_script(params);

        Arc::new(TapTree::Branch {
            left: Arc::new(TapTree::Leaf(crate::contracts::TapLeaf {
                name: "withdraw".to_string(),
                script: withdraw,
            })),
            right: Arc::new(TapTree::Leaf(crate::contracts::TapLeaf {
                name: "recover".to_string(),
                script: recover,
            })),
        })
    }

    fn withdraw_script(params: &UnvaultingParams) -> ScriptBuf {
        script! {
            DUP
            -1 { crate::optional_key(params.alternate_pk) } -1 { crate::contracts::CCV_FLAG_CHECK_INPUT } CHECKCONTRACTVERIFY

            // check timelock
            { params.spend_delay }
            CSV
            DROP

            // Check that the transaction output is as expected
            CHECKTEMPLATEVERIFY
        }
    }

    fn recover_script(params: &UnvaultingParams) -> ScriptBuf {
        script! {
            0 // data
            SWAP // <out_i> (from witness)
            { params.recover_pk }
            0 // taptree
            0 // flags
            CHECKCONTRACTVERIFY
            TRUE
        }
    }

    /// Get the contract as a type-erased ErasedContract with state
    pub fn as_erased(&self, _state: UnvaultingState) -> Arc<dyn ErasedContract> {
        let naked_key = optional_key(self.params.alternate_pk);
        let taptree = Self::build_taptree(&self.params);

        // Create clause objects
        let withdraw_script = Self::withdraw_script(&self.params);
        let recover_script = Self::recover_script(&self.params);

        let withdraw_clause: Arc<dyn ErasedClause> = Arc::new(StandardClause::<
            UnvaultingParams,
            UnvaultingState,
            WithdrawArgs,
        >::new(
            "withdraw".to_string(),
            withdraw_script,
            vec![ArgSpec {
                name: "ctv_hash".to_string(),
                arg_type: Arc::new(BytesType),
            }],
            Some(Arc::new(
                |_p: &UnvaultingParams, _args: &WithdrawArgs, _state: Option<&UnvaultingState>| {
                    // Withdraw is terminal - outputs are specified explicitly
                    Ok(Vec::new())
                },
            )),
        ));

        let recover_clause: Arc<dyn ErasedClause> = Arc::new(StandardClause::<
            UnvaultingParams,
            UnvaultingState,
            UnvaultingRecoverArgs,
        >::new(
            "recover".to_string(),
            recover_script,
            vec![ArgSpec {
                name: "out_i".to_string(),
                arg_type: Arc::new(IntType),
            }],
            Some(Arc::new(
                |_p: &UnvaultingParams,
                 _args: &UnvaultingRecoverArgs,
                 _state: Option<&UnvaultingState>| {
                    // Recover is terminal
                    Ok(Vec::new())
                },
            )),
        ));

        let clauses = vec![withdraw_clause, recover_clause];

        Arc::new(
            StandardAugmentedP2TR::<UnvaultingParams, UnvaultingState>::new(
                naked_key, taptree, clauses,
            ),
        )
    }

    /// Execute withdraw clause - terminal (no outputs)
    pub fn withdraw_outputs(&self, _ctv_hash: [u8; 32]) -> Result<Vec<ClauseOutput>, String> {
        // Withdraw is terminal - outputs are specified explicitly as CTV template
        Ok(Vec::new())
    }

    /// Execute recover clause - no outputs
    pub fn recover_outputs(&self) -> Result<Vec<ClauseOutput>, String> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_creation() {
        let params = VaultParams {
            alternate_pk: None,
            spend_delay: 10,
            recover_pk: XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap(),
            unvault_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
        };

        let vault = Vault::new(params);
        let _contract = vault.as_erased();
    }
}
