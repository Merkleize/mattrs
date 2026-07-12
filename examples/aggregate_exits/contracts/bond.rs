//! [`ExitBond`]: a plain UTXO its owner pre-funds and then co-spends (via
//! [`mattrs::manager::ContractManager::spend_batch`]) into a claim or challenge
//! transaction. Its single clause checks the owner's signature — which covers
//! the whole transaction — and contributes the bond's amount to output 0, the
//! pot the batched pool-side clause defines
//! ([`NextOutputs::Join`](mattrs::contracts::NextOutputs::Join)); nothing
//! about the target is re-declared or carried in the bond's witness.

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitcoin_script::{define_pushable, script};
use mattrs::contract;
use mattrs::contracts::NextOutputs;
use mattrs::Signature;
use mattrs_derive::ContractParams;

use super::PoolParams;

define_pushable!();

/// A bond UTXO's parameters: the pool it stakes into and its owner. The pool
/// params ride along for self-description; only the owner key reaches the
/// script.
#[derive(Debug, Clone, ContractParams)]
pub struct ExitBondParams {
    pub pool: PoolParams,
    pub owner_pk: XOnlyPublicKey,
}

contract! {
    /// A pre-funded bond. `stake` co-signs the bond into whatever pot the
    /// batched pool-side clause defines at output 0 — a claim's
    /// [`PendingExit`](super::PendingExit), a state challenge's
    /// [`ExitBisect1`](super::ExitBisect1), or a
    /// [`DelegationChallenge`](super::DelegationChallenge). The owner's
    /// signature covers the whole transaction, so it is also their consent to
    /// the specific pot the batch builds.
    contract ExitBond {
        params ExitBondParams;

        // witness: <sig>
        clause stake {
            args {
                #[signer(p.owner_pk)]
                sig: Signature,
            }
            script ExitBond::stake_script;
            next(_p, _a) { Ok(NextOutputs::join(0)) }
        }

        tree [stake];
    }
}

impl ExitBond {
    fn stake_script(p: &ExitBondParams) -> ScriptBuf {
        script! {
            { p.owner_pk }
            OP_CHECKSIG
        }
    }
}
