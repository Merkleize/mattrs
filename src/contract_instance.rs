use std::{cell::RefCell, rc::Rc};

use bitcoin::{
    hashes::Hash, key::Secp256k1, secp256k1::Scalar, Address, KnownHrp, OutPoint, ScriptBuf,
    TapNodeHash, Transaction, XOnlyPublicKey,
};

use crate::contracts::{ClauseArguments, Contract, ContractState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractInstanceStatus {
    Abstract,
    Funded,
    Spent,
}

// TODO: we might want to use types to enforce the state machine
// (that is, AbstractContractInstance ==> FundedContractInstance ==> SpentContractInstance)
#[derive(Debug)]
pub struct ContractInstance {
    pub contract: Box<dyn Contract>,
    pub status: ContractInstanceStatus,

    pub state: Option<Box<dyn ContractState>>,
    pub state_hash: Option<[u8; 32]>,

    pub outpoint: Option<OutPoint>,
    pub funding_tx: Option<Transaction>,

    pub spending_tx: Option<Transaction>,
    pub spending_vin: Option<usize>,
    pub spending_clause_name: Option<String>,
    pub spending_args: Option<Box<dyn ClauseArguments>>,

    // When the instance is spent, the next instances produced by the clause
    pub next: Option<Vec<Rc<RefCell<ContractInstance>>>>,
    pub last_height: Option<u64>,
}

impl ContractInstance {
    pub fn new(contract: Box<dyn Contract>) -> Self {
        ContractInstance {
            contract,
            status: ContractInstanceStatus::Abstract,
            state: None,
            state_hash: None,
            outpoint: None,
            funding_tx: None,
            spending_tx: None,
            spending_vin: None,
            spending_clause_name: None,
            spending_args: None,
            next: None,
            last_height: None,
        }
    }

    pub fn set_state(&mut self, state: Box<dyn ContractState>) {
        if !self.contract.is_augmented() {
            panic!("Can only set the state for augmented contracts");
        }

        if self.state.is_some() {
            panic!("State was already set");
        }

        self.state_hash = Some(state.encode());
        self.state = Some(state);
    }

    pub fn get_script(&self) -> ScriptBuf {
        ScriptBuf::from(self.get_address())
    }

    pub fn get_internal_pubkey(&self) -> XOnlyPublicKey {
        let naked_key = self.contract.get_naked_internal_key();
        let secp = Secp256k1::new();

        if self.contract.is_augmented() {
            let data = self.state_hash.unwrap();
            // tweak with the state hash
            let (pk, _) = naked_key
                .add_tweak(&secp, &Scalar::from_be_bytes(data).unwrap())
                .unwrap();
            pk
        } else {
            naked_key
        }
    }

    pub fn get_address(&self) -> Address {
        if self.contract.is_augmented() && self.state_hash.is_none() {
            panic!("Can't get the address of a stateful contract if the state is not set")
        }

        let taptree_hash = self.contract.get_taptree().get_root_hash();
        let secp = Secp256k1::new();

        Address::p2tr(
            &secp,
            self.get_internal_pubkey(),
            Some(TapNodeHash::from_slice(&taptree_hash).unwrap()),
            KnownHrp::Regtest,
        )
    }

    pub fn instance_of<T: Contract>(&self) -> bool {
        self.contract.as_any().downcast_ref::<T>().is_some()
    }

    pub fn get_contract<T: Contract>(&self) -> Result<&T, Box<dyn std::error::Error>> {
        self.contract
            .as_any()
            .downcast_ref::<T>()
            .ok_or_else(|| format!("Contract is not of type {}", std::any::type_name::<T>()).into())
    }

    pub fn get_state<T: ContractState>(&self) -> Result<&T, Box<dyn std::error::Error>> {
        self.state
            .as_ref()
            .ok_or_else(|| "State is not set".into())
            .and_then(|state| {
                state.as_any().downcast_ref::<T>().ok_or_else(|| {
                    format!("State is not of type {}", std::any::type_name::<T>()).into()
                })
            })
    }
}
