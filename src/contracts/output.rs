//! What a clause produces when spent: covenant outputs, payments, or a CTV template.

use std::sync::Arc;

use super::{ContractError, ContractState, ErasedContract, ErasedState, StateCommitment};
use crate::{ccv::AmountMode, ccv::CcvIndex};
use bitcoin::{ScriptBuf, Sequence, TxOut, XOnlyPublicKey};

/// Opcode for CHECKTEMPLATEVERIFY
pub const OP_CHECKTEMPLATEVERIFY: u8 = 0xb3;

/// Where a clause output goes.
#[derive(Debug, Clone)]
pub enum OutputTarget {
    /// A contract instance, which the manager tracks as a child. The contract
    /// carries its own params (see [`ErasedContract::params_any`]); `state` is
    /// the instance's logical state (`()` for a stateless contract), from
    /// which its commitment — and so its address — derives.
    Contract {
        /// The contract of this output.
        contract: Arc<dyn ErasedContract>,
        /// The new instance's logical state.
        state: Box<dyn ErasedState>,
    },
    /// An exact destination script (including any key tweaks). Constrained
    /// like any other output, but not tracked: it creates no child instance.
    Script(ScriptBuf),
}

/// One transaction output a clause constrains: which output, where it goes,
/// and how its amount relates to the spending input.
///
/// A clause may freely mix contract outputs and plain payments. This is
/// host-side metadata: it adds no script checks, so the clause's script must
/// enforce the same destination and amount mode.
///
/// ```
/// use mattrs::contracts::{ClauseOutput, NextOutputs};
/// let payment = ClauseOutput::at(0).pay(mattrs::script::opaque_p2tr(mattrs::nums_key()));
/// let next: NextOutputs = payment.into();
/// ```
#[derive(Debug, Clone)]
pub struct ClauseOutput {
    /// Which transaction output this refers to.
    pub index: CcvIndex,
    /// Where the output goes.
    pub target: OutputTarget,
    /// How the output's amount relates to the input's residual amount.
    pub amount: AmountMode,
}

impl ClauseOutput {
    /// Start building a clause output at an explicit output index.
    ///
    /// # Example
    /// ```ignore
    /// let output = ClauseOutput::at(0)
    ///     .to(contract)
    ///     .with_state(&state)
    ///     .preserve_amount()
    ///     .build();
    /// ```
    pub fn at(index: impl Into<CcvIndex>) -> ClauseOutputTo {
        ClauseOutputTo(index.into())
    }

    /// Start building a clause output whose index matches the spending input.
    pub fn at_same_index() -> ClauseOutputTo {
        ClauseOutputTo(CcvIndex::CURRENT)
    }

    /// Declare no output constraints in the host-side model (and no children).
    ///
    /// This does not mean the script is unconstrained. For a childless CTV
    /// withdrawal, use [`NextOutputs::Template`] or [`NextOutputs::TemplateHash`].
    /// For a script-constrained payment, use [`ClauseOutputTo::pay`]. These let
    /// the manager validate the transaction even though no children are tracked.
    pub fn terminal() -> Vec<ClauseOutput> {
        Vec::new()
    }

    /// A deduct-amount payout to `pk` at output `index`: the key is the
    /// *output* key, used verbatim (see
    /// [`opaque_p2tr`](crate::script::opaque_p2tr)). The spender
    /// supplies the amount via
    /// [`SpendBuilder::output_amount`](crate::manager::SpendBuilder::output_amount).
    pub fn pay_key(index: impl Into<CcvIndex>, pk: XOnlyPublicKey) -> ClauseOutput {
        ClauseOutput::at(index)
            .pay(crate::script::opaque_p2tr(pk))
            .deduct_amount()
    }

    /// A deduct-amount, provably unspendable (NUMS-key) output at `index`.
    pub fn burn(index: impl Into<CcvIndex>) -> ClauseOutput {
        ClauseOutput::pay_key(index, crate::nums_key())
    }

    /// The output's contract and state, when it is a tracked contract output.
    pub fn contract(&self) -> Option<(&Arc<dyn ErasedContract>, &dyn ErasedState)> {
        match &self.target {
            OutputTarget::Contract { contract, state } => Some((contract, state.as_ref())),
            OutputTarget::Script(_) => None,
        }
    }

    /// The output's explicit CCV data commitment: its contract state's, or
    /// empty for a stateless contract and for a plain payment.
    pub fn state_commitment(&self) -> StateCommitment {
        match &self.target {
            OutputTarget::Contract { state, .. } => state.state_commitment(),
            OutputTarget::Script(_) => StateCommitment::empty(),
        }
    }

    /// The exact scriptPubKey this output must carry.
    pub fn script_pubkey(&self) -> Result<ScriptBuf, ContractError> {
        match &self.target {
            OutputTarget::Contract { contract, state } => {
                contract.script_pubkey(&state.state_commitment())
            }
            OutputTarget::Script(script_pubkey) => Ok(script_pubkey.clone()),
        }
    }

    /// The output receives the input's residual amount (the default).
    pub fn preserve_amount(mut self) -> Self {
        self.amount = AmountMode::Preserve;
        self
    }

    /// The output's amount is not constrained. This does not protect the
    /// input's value.
    pub fn ignore_amount(mut self) -> Self {
        self.amount = AmountMode::Ignore;
        self
    }

    /// The output's amount is deducted from the input's residual amount.
    pub fn deduct_amount(mut self) -> Self {
        self.amount = AmountMode::Deduct;
        self
    }
}

/// First stage of the [`ClauseOutput`] builder: the output's destination must
/// be set (with [`to`](Self::to) or [`pay`](Self::pay)) before anything else,
/// so a finished output can never lack one.
pub struct ClauseOutputTo(CcvIndex);

impl ClauseOutputTo {
    /// Send this output to a contract, creating a tracked child instance.
    pub fn to(self, contract: Arc<dyn ErasedContract>) -> ClauseOutputBuilder {
        ClauseOutputBuilder {
            index: self.0,
            contract,
            state: Box::new(()),
            amount: AmountMode::Preserve,
        }
    }

    /// Pay this output to an exact script, preserving the input's residual
    /// amount unless changed with [`ClauseOutput::deduct_amount`] or
    /// [`ClauseOutput::ignore_amount`]. No child instance is tracked.
    pub fn pay(self, script_pubkey: ScriptBuf) -> ClauseOutput {
        ClauseOutput {
            index: self.0,
            target: OutputTarget::Script(script_pubkey),
            amount: AmountMode::Preserve,
        }
    }
}

/// Builder for a contract [`ClauseOutput`] with a fluent API.
pub struct ClauseOutputBuilder {
    index: CcvIndex,
    contract: Arc<dyn ErasedContract>,
    state: Box<dyn ErasedState>,
    amount: AmountMode,
}

impl ClauseOutputBuilder {
    /// Set the state for the next contract. The committed bytes (for addressing)
    /// derive from it, and the child instance carries it for its own future spends.
    pub fn with_state<S: ContractState + 'static>(mut self, state: &S) -> Self {
        self.state = Box::new(state.clone());
        self
    }

    /// Set amount behaviour to preserve output (default).
    pub fn preserve_amount(mut self) -> Self {
        self.amount = AmountMode::Preserve;
        self
    }

    /// Set amount behaviour to ignore output.
    pub fn ignore_amount(mut self) -> Self {
        self.amount = AmountMode::Ignore;
        self
    }

    /// Set amount behaviour to deduct from input.
    pub fn deduct_amount(mut self) -> Self {
        self.amount = AmountMode::Deduct;
        self
    }

    /// Build the [`ClauseOutput`].
    pub fn build(self) -> ClauseOutput {
        ClauseOutput {
            index: self.index,
            target: OutputTarget::Contract {
                contract: self.contract,
                state: self.state,
            },
            amount: self.amount,
        }
    }
}

/// A CTV (`CHECKTEMPLATEVERIFY`) transaction template: the exact outputs and input
/// sequence that a clause commits its spending transaction to.
///
/// A clause whose `next_outputs` returns [`NextOutputs::Template`] fixes the whole
/// spending transaction (its outputs and `nSequence`), rather than declaring
/// per-output child contracts. Such a spend is terminal — it creates no tracked
/// child instances.
#[derive(Debug, Clone)]
pub struct CtvTemplate {
    /// The transaction outputs the template commits to.
    pub outputs: Vec<TxOut>,
    /// The `nSequence` of the (single) spending input the template commits to.
    pub sequence: Sequence,
}

impl CtvTemplate {
    /// Build a template from its outputs and input sequence.
    pub fn new(outputs: Vec<TxOut>, sequence: Sequence) -> Self {
        Self { outputs, sequence }
    }

    /// The BIP-119 standard template hash for this template (single-input spend).
    pub fn ctv_hash(&self) -> [u8; 32] {
        crate::ctv::compute_ctv_hash(&self.outputs, self.sequence)
    }
}

/// What a clause produces when spent.
///
/// Output constraints and child tracking are distinct: payments and CTV spends
/// have no tracked children but still constrain their transactions. A clause with no
/// next-outputs function yields `Outputs(vec![])`, which declares no
/// host-side output checks; it does not imply its script is unconstrained.
#[derive(Debug, Clone)]
pub enum NextOutputs {
    /// `CHECKCONTRACTVERIFY` outputs with CCV amount semantics: (possibly
    /// stateful) contracts, which become tracked children, and plain payments,
    /// which do not. Payments can aggregate with other payments to the same
    /// script and index, but the builder rejects a payment sharing an index
    /// with a contract output or a `Join`, because the output's tracking
    /// identity would be ambiguous.
    Outputs(Vec<ClauseOutput>),
    /// A fixed `CHECKTEMPLATEVERIFY` template — terminal (no child instances).
    Template(CtvTemplate),
    /// A CTV commitment whose outputs are supplied at spending time, e.g. a
    /// template hash stored in contract state. Creates no child instances.
    ///
    /// The builder requires explicit `.outputs(...)` and supports single-input
    /// spends (version 2, locktime 0). The final transaction must match this
    /// BIP-119 hash before signing. Observation checks the actual transaction's
    /// hash, including its input index. The script must enforce the same hash;
    /// this metadata alone adds no on-chain constraint.
    TemplateHash([u8; 32]),
    /// Contribute this input's whole amount to the transaction output at
    /// `index`, whose contract and state must be defined by *another input's*
    /// clause in the same batch spend — the "bond joins the pot" pattern: the
    /// joining input's script typically just checks its owner's signature
    /// (which covers the whole transaction), so nothing about the target needs
    /// to be re-declared or carried in its witness.
    Join {
        /// The transaction output index the amount joins.
        index: u32,
    },
}

impl NextOutputs {
    /// A [`Join`](NextOutputs::Join) contribution to output `index`.
    pub fn join(index: u32) -> Self {
        NextOutputs::Join { index }
    }
}

impl From<Vec<ClauseOutput>> for NextOutputs {
    fn from(outputs: Vec<ClauseOutput>) -> Self {
        NextOutputs::Outputs(outputs)
    }
}

impl From<CtvTemplate> for NextOutputs {
    fn from(template: CtvTemplate) -> Self {
        NextOutputs::Template(template)
    }
}

impl From<ClauseOutput> for NextOutputs {
    fn from(output: ClauseOutput) -> Self {
        Self::Outputs(vec![output])
    }
}
