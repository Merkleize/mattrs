//! Errors shared by the manager facade and its components.
use crate::contracts::{ClauseError, ContractError, WitnessError};
use crate::signer::SignerError;
use bitcoin::{Amount, OutPoint, Txid, XOnlyPublicKey};

/// Error type for manager operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum ManagerError {
    /// The operation needs a node, but this manager was created
    /// [`offline`](super::ContractManager::offline).
    NoNode,
    /// The chain backend failed (node unreachable, transaction rejected, ...).
    Chain(crate::chain::ChainError),
    /// A clause could not compute its outputs.
    Clause(ClauseError),
    /// A contract could not be built, or its state did not fit it.
    Contract(ContractError),
    /// A spend's witness does not match the clause's declared arguments.
    Witness(WitnessError),
    /// A signer refused or failed to sign.
    Signer(SignerError),
    /// The inputs handed to an observation are unusable as a set (empty,
    /// duplicated, not inputs of the transaction, or already spent
    /// elsewhere).
    InvalidObservation(String),
    /// The funding transaction has no output at the given index.
    OutputNotFound,
    /// The instance at this outpoint was already spent, so it cannot be spent
    /// (or awaited) again.
    AlreadySpent(OutPoint),
    /// The named clause does not exist on the contract being spent.
    ClauseNotFound(String),
    /// A deduct output at this index needs an amount, supplied via
    /// [`SpendBuilder::output_amount`](super::SpendBuilder::output_amount).
    MissingDeductAmount { index: u32 },
    /// An ignore-amount output needs an explicit amount; silently using zero would
    /// donate the input value to fees.
    MissingIgnoredAmount { index: u32 },
    /// The merged clause outputs skip a transaction output index.
    NonContiguousOutputs { missing_index: u32 },
    /// Deducted output amounts exceed the input amount.
    DeductExceedsInput,
    /// An observed spending transaction could not be decoded back into a clause
    /// (key-path spend, unknown tapscript, or a witness/spec mismatch).
    UnrecognizedSpend(String),
    /// No transaction spending this outpoint was found within the polling window.
    SpendNotFound(OutPoint),
    /// The transaction did not appear on the node within the polling window.
    TransactionNotFound(Txid),
    /// The outpoint given to [`ContractManager::track_instance`](super::ContractManager::track_instance) does not pay
    /// the contract's expected script (wrong contract, params, or state).
    WrongFundingScript(OutPoint),
    /// The transaction does not satisfy the clause's declared CTV commitment.
    CtvTemplateMismatch { input_index: usize },
    /// The spend produces no transaction outputs. Childless clauses without a
    /// full template need outputs supplied with [`SpendBuilder::outputs`](super::SpendBuilder::outputs).
    NoOutputs,
    /// Two spends of a batch set a different amount for the same output index.
    ConflictingOutputAmount { index: u32 },
    /// An output index receives both preserve and deduct
    /// contributions (from the same or different inputs); the two amount
    /// semantics cannot hold for one output.
    MixedOutputSemantics { index: u32 },
    /// An amount was supplied via [`SpendBuilder::output_amount`](super::SpendBuilder::output_amount) for an output
    /// index that no deduct output uses.
    UnusedOutputAmount { index: u32 },
    /// Contributions merged at one output index disagree on their destination
    /// or tracking identity (contract type/params/state, or untracked payment).
    ConflictingOutputContract { index: u32 },
    /// A clause describes a child at an output that the observed transaction
    /// does not contain.
    MissingContractOutput(OutPoint),
    /// A clause's derived child script does not match the corresponding output
    /// in the observed transaction.
    WrongContractOutput(OutPoint),
    /// An untracked payment output is missing or has the wrong script.
    PaymentOutputMismatch { index: u32 },
    /// Strict batch observation lacks contract or external context for these inputs.
    IncompleteObservation { missing: Vec<OutPoint> },
    /// An output holds less than the preserve/join contributions it must carry
    /// (one input's residual, or several inputs' combined).
    InsufficientOutputAmount {
        index: u32,
        required: Amount,
        actual: Amount,
    },
    /// Amount accounting overflowed instead of representing a valid sum.
    AmountOverflow,
    /// An external input is not a supported native wallet spend.
    UnsupportedExternalInput { outpoint: OutPoint },
    /// Supplied input contexts are duplicated, unrelated, or contradictory.
    InvalidInputContext(String),
    /// The transaction spends more than its supplied prevouts provide.
    OutputsExceedInputs,
    /// Wallet funding changed protected transaction fields or input context.
    InvalidWalletFunding(String),
    /// The actual absolute fee exceeds the caller's authorization.
    FeeTooHigh { fee: Amount, maximum: Amount },
    /// The requested spend cannot be turned into a transaction (an empty or
    /// duplicated batch, outputs the clause does not allow, a sequence that
    /// contradicts the clause, ...). The message says which rule it breaks.
    InvalidSpend(String),
    /// A clause requires a signature from this key, but no signer was registered
    /// and no signature was pre-filled.
    MissingSigner(XOnlyPublicKey),
    /// A spend produced a different number of child instances than the caller
    /// asserted via `exec_one` / `exec_none` / [`Children::one`](super::Children::one).
    UnexpectedOutputCount { expected: usize, got: usize },
    /// A child instance was not of the requested contract type
    /// ([`Children::at`](super::Children::at) / [`Children::one`](super::Children::one)).
    WrongContract(WrongContractType),
    /// The spend created no tracked contract instance at this output index
    /// (the output is a plain payment, or the clause does not produce it).
    NoChildAtOutput {
        /// The transaction output index asked for.
        index: u32,
    },
    /// A `NextOutputs::Join` contribution targets an output index no other
    /// input's clause defines.
    JoinWithoutTarget { index: u32 },
    /// A failure reported by caller-supplied code (a funding or broadcast
    /// callback), or one with no more specific variant.
    Other(String),
}

impl ManagerError {
    /// An [`Other`](ManagerError::Other) failure, from anything printable:
    /// `.map_err(ManagerError::other)`.
    pub fn other(message: impl std::fmt::Display) -> Self {
        ManagerError::Other(message.to_string())
    }
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerError::NoNode => {
                write!(f, "this manager is offline: the operation needs a node")
            }
            ManagerError::Chain(e) => write!(f, "chain error: {}", e),
            ManagerError::Clause(e) => write!(f, "Clause error: {}", e),
            ManagerError::Contract(e) => write!(f, "Contract error: {}", e),
            ManagerError::Witness(e) => write!(f, "Witness error: {}", e),
            ManagerError::Signer(e) => write!(f, "Signer error: {}", e),
            ManagerError::InvalidObservation(msg) => write!(f, "Invalid observation: {}", msg),
            ManagerError::OutputNotFound => write!(f, "Output not found on blockchain"),
            ManagerError::AlreadySpent(outpoint) => {
                write!(f, "The instance at {outpoint} was already spent")
            }
            ManagerError::ClauseNotFound(name) => write!(f, "Clause '{}' not found", name),
            ManagerError::MissingDeductAmount { index } => write!(
                f,
                "Deduct output at index {} needs an amount (SpendBuilder::output_amount)",
                index
            ),
            ManagerError::MissingIgnoredAmount { index } => write!(
                f,
                "Ignore-amount output at index {} needs an explicit amount \
                 (SpendBuilder::output_amount)",
                index
            ),
            ManagerError::NonContiguousOutputs { missing_index } => write!(
                f,
                "Clause outputs are not contiguous (missing index {})",
                missing_index
            ),
            ManagerError::DeductExceedsInput => {
                write!(f, "Deducted output amounts exceed the input amount")
            }
            ManagerError::UnrecognizedSpend(msg) => {
                write!(f, "Cannot decode the observed spend: {}", msg)
            }
            ManagerError::SpendNotFound(outpoint) => {
                write!(
                    f,
                    "No transaction spending {} found while polling",
                    outpoint
                )
            }
            ManagerError::TransactionNotFound(txid) => {
                write!(f, "Transaction {} not found while polling", txid)
            }
            ManagerError::WrongFundingScript(outpoint) => write!(
                f,
                "Outpoint {} does not pay the contract's expected script \
                 (wrong contract, params, or state?)",
                outpoint
            ),
            ManagerError::NoOutputs => write!(
                f,
                "The spend produces no outputs; provide nonempty outputs \
                 (SpendBuilder::outputs or the clause's output constraints)"
            ),
            ManagerError::CtvTemplateMismatch { input_index } => write!(
                f,
                "Transaction does not match the CTV commitment at input {input_index}"
            ),
            ManagerError::ConflictingOutputAmount { index } => {
                write!(f, "Conflicting amounts were set for output index {}", index)
            }
            ManagerError::MixedOutputSemantics { index } => write!(
                f,
                "Output index {} mixes preserve and deduct contributions",
                index
            ),
            ManagerError::UnusedOutputAmount { index } => write!(
                f,
                "An amount was set for output index {}, but no DeductOutput uses it",
                index
            ),
            ManagerError::ConflictingOutputContract { index } => write!(
                f,
                "Output index {} merges incompatible destinations or tracking identities",
                index
            ),
            ManagerError::MissingContractOutput(outpoint) => write!(
                f,
                "The observed transaction has no contract output at {}",
                outpoint
            ),
            ManagerError::WrongContractOutput(outpoint) => write!(
                f,
                "The observed output at {} does not pay the clause's child contract",
                outpoint
            ),
            ManagerError::PaymentOutputMismatch { index } => write!(
                f,
                "Payment output {index} is missing or has the wrong script"
            ),
            ManagerError::IncompleteObservation { missing } => write!(
                f,
                "Batch observation needs contract context for {} input(s): {missing:?}",
                missing.len()
            ),
            ManagerError::InsufficientOutputAmount {
                index,
                required,
                actual,
            } => write!(
                f,
                "Output {index} has {actual}, below the combined required amount {required}"
            ),
            ManagerError::AmountOverflow => write!(f, "Output amount accounting overflow"),
            ManagerError::UnsupportedExternalInput { outpoint } => write!(
                f,
                "Unsupported external input {outpoint}: expected native P2WPKH or Taproot key-path spending"
            ),
            ManagerError::InvalidInputContext(msg) => write!(f, "Invalid input context: {msg}"),
            ManagerError::OutputsExceedInputs => {
                write!(f, "Transaction outputs exceed supplied input value")
            }
            ManagerError::InvalidWalletFunding(msg) => write!(f, "Invalid wallet funding: {msg}"),
            ManagerError::FeeTooHigh { fee, maximum } => write!(
                f,
                "Transaction fee {fee} exceeds authorized maximum {maximum}"
            ),
            ManagerError::InvalidSpend(msg) => write!(f, "Invalid spend: {}", msg),
            ManagerError::MissingSigner(pk) => {
                write!(f, "No signer registered for required key {}", pk)
            }
            ManagerError::UnexpectedOutputCount { expected, got } => write!(
                f,
                "Unexpected number of spend outputs: expected {}, got {}",
                expected, got
            ),
            ManagerError::WrongContract(e) => write!(f, "{}", e),
            ManagerError::NoChildAtOutput { index } => {
                write!(
                    f,
                    "the spend created no contract instance at output {index}"
                )
            }
            ManagerError::JoinWithoutTarget { index } => write!(
                f,
                "a Join contribution targets output index {}, which no other input defines",
                index
            ),
            ManagerError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ManagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ManagerError::Chain(e) => Some(e),
            ManagerError::Clause(e) => Some(e),
            ManagerError::Contract(e) => Some(e),
            ManagerError::Witness(e) => Some(e),
            ManagerError::Signer(e) => Some(e),
            ManagerError::WrongContract(e) => Some(e),
            _ => None,
        }
    }
}

/// Converting a handle to itself cannot fail; this lets the typed-child
/// accessors also return the untyped handle.
impl From<std::convert::Infallible> for ManagerError {
    fn from(never: std::convert::Infallible) -> Self {
        match never {}
    }
}

impl From<WitnessError> for ManagerError {
    fn from(e: WitnessError) -> Self {
        ManagerError::Witness(e)
    }
}

impl From<SignerError> for ManagerError {
    fn from(e: SignerError) -> Self {
        ManagerError::Signer(e)
    }
}

impl From<crate::chain::ChainError> for ManagerError {
    fn from(e: crate::chain::ChainError) -> Self {
        ManagerError::Chain(e)
    }
}

impl From<ClauseError> for ManagerError {
    fn from(e: ClauseError) -> Self {
        ManagerError::Clause(e)
    }
}

impl From<ContractError> for ManagerError {
    fn from(e: ContractError) -> Self {
        ManagerError::Contract(e)
    }
}

impl From<WrongContractType> for ManagerError {
    fn from(e: WrongContractType) -> Self {
        ManagerError::WrongContract(e)
    }
}
/// Error returned when converting an [`InstanceHandle`](super::InstanceHandle) into a typed per-contract
/// handle whose contract does not match the instance's actual contract.
#[derive(Debug, Clone)]
pub struct WrongContractType {
    /// The contract type the conversion expected.
    pub expected: &'static str,
}

impl std::fmt::Display for WrongContractType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "instance is not a `{}` contract", self.expected)
    }
}

impl std::error::Error for WrongContractType {}
