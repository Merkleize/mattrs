//! Bare-key payout (and burn) outputs as clause-output targets.
//!
//! A `CHECKCONTRACTVERIFY` with empty data and an empty taptree constrains an
//! output to pay a key *verbatim* as the taproot witness program
//! ([`opaque_p2tr`]). [`KeyPayout`] is the minimal [`ErasedContract`] for such
//! an output, so covenant clauses can declare "output `i` pays this key" (or
//! "output `i` is burned") as an ordinary [`ClauseOutput`] — see the
//! [`ClauseOutput::pay_key`] / [`ClauseOutput::burn`] constructors.
//!
//! [`KeyPayout::burn`] targets the NUMS key: with no known discrete log and no
//! script path, the output is provably unspendable — the "burned" half of a
//! slashed bond, for instance.

use std::sync::Arc;

use bitcoin::{ScriptBuf, XOnlyPublicKey};

use crate::contracts::{
    ClauseError, ClauseOutput, ContractError, ErasedClause, ErasedContract, ErasedState,
    NextOutputs, TapTree,
};
use crate::script_helpers::opaque_p2tr;

/// A clause-output target paying `pk` directly as the taproot witness program.
#[derive(Debug, Clone)]
pub struct KeyPayout {
    pk: XOnlyPublicKey,
    name: &'static str,
    params_bytes: Vec<u8>,
    taptree: Arc<TapTree>,
}

impl KeyPayout {
    /// A payout to `pk` (spendable by its owner via the key path — note the
    /// key is the *output* key, untweaked; see [`opaque_p2tr`]).
    pub fn new(pk: XOnlyPublicKey) -> Self {
        Self::named("KeyPayout", pk)
    }

    /// A provably unspendable output: the NUMS key, verbatim, no script path.
    pub fn burn() -> Self {
        Self::named("Burn", crate::nums_key())
    }

    fn named(name: &'static str, pk: XOnlyPublicKey) -> Self {
        KeyPayout {
            pk,
            name,
            params_bytes: pk.serialize().to_vec(),
            // Placeholder: a KeyPayout has no script paths; the taptree is
            // never part of its scriptPubKey (the key is used verbatim).
            taptree: Arc::new(TapTree::leaf("none", ScriptBuf::new())),
        }
    }
}

impl ErasedContract for KeyPayout {
    fn clauses(&self) -> &[Arc<dyn ErasedClause>] {
        &[]
    }

    fn params_bytes(&self) -> &[u8] {
        &self.params_bytes
    }

    fn get_clause(&self, _name: &str) -> Option<&Arc<dyn ErasedClause>> {
        None
    }

    fn execute_clause_from_witness(
        &self,
        clause_name: &str,
        _witness: &[Vec<u8>],
        _state: Option<&dyn ErasedState>,
    ) -> Result<NextOutputs, ClauseError> {
        Err(ClauseError::Other(format!(
            "{} has no clause {clause_name}",
            self.name
        )))
    }

    fn contract_type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<Self>()
    }

    fn contract_name(&self) -> &'static str {
        self.name
    }

    fn script_pubkey(&self, _state_bytes: Option<&[u8]>) -> Result<ScriptBuf, ContractError> {
        Ok(opaque_p2tr(self.pk))
    }

    fn control_block_internal_key(
        &self,
        _state_bytes: Option<&[u8]>,
    ) -> Result<XOnlyPublicKey, ContractError> {
        Ok(self.pk)
    }

    fn taptree(&self) -> &Arc<TapTree> {
        &self.taptree
    }

    fn clone_boxed(&self) -> Box<dyn ErasedContract> {
        Box::new(self.clone())
    }
}

impl ClauseOutput {
    /// A deduct-amount payout to `pk` at output `index` (the spender supplies
    /// the amount via
    /// [`SpendBuilder::output_amount`](crate::manager::SpendBuilder::output_amount)).
    pub fn pay_key(index: u32, pk: XOnlyPublicKey) -> ClauseOutput {
        let contract: Arc<dyn ErasedContract> = Arc::new(KeyPayout::new(pk));
        ClauseOutput::at(index).to(contract).deduct_amount().build()
    }

    /// A deduct-amount, provably unspendable (NUMS-key) output at `index`.
    pub fn burn(index: u32) -> ClauseOutput {
        let contract: Arc<dyn ErasedContract> = Arc::new(KeyPayout::burn());
        ClauseOutput::at(index).to(contract).deduct_amount().build()
    }
}
