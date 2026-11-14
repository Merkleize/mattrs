//! The names nearly every contract and protocol file needs, in one import:
//!
//! ```
//! use mattrs::prelude::*;
//! ```
//!
//! That covers defining a contract (`contract!`, `script!` and the
//! [`script`](mod@crate::script) fragments module, `ContractState`, `Signature`,
//! `CcvIndex`, `ClauseOutput`, `NextOutputs`), spending it
//! (`ContractManager`, `HotSigner`, `LocalChain`) and playing a protocol on it
//! (`Role`, `Action`, `Runner`). Less common items stay in their modules.

pub use crate::ccv::{CcvIndex, CcvMode};
pub use crate::chain::{ChainView, LocalChain};
pub use crate::contracts::{ClauseError, ClauseOutput, ContractError, InstanceStatus, NextOutputs};
pub use crate::manager::{ContractManager, InstanceHandle, ManagerError, SpendBuilder};
pub use crate::protocol::{Action, ProtocolError, Role, Runner, StepCtx};
pub use crate::signer::HotSigner;
pub use crate::{BlockDelay, ContractState, Signature, contract, script};
