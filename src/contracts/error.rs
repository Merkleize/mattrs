//! Errors of the contract model: witness decoding, clause execution, contract construction.

use std::fmt;

use bitcoin::OutPoint;

/// Errors from encoding/decoding values to and from the witness stack.
#[derive(Debug)]
pub enum WitnessError {
    /// The witness stack (or a value's bytes) ended before a complete value
    /// could be decoded.
    Missing,
    /// The data is there but is not a valid encoding of the expected type
    /// (wrong length, a non-minimal integer, an out-of-range value, ...).
    Invalid(String),
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WitnessError::Missing => write!(f, "the witness ends before the value does"),
            WitnessError::Invalid(msg) => write!(f, "invalid witness data: {}", msg),
        }
    }
}

impl std::error::Error for WitnessError {}

/// Errors from executing a clause (computing its next outputs).
#[derive(Debug)]
#[non_exhaustive]
pub enum ClauseError {
    /// The spend's witness stack could not be decoded into the clause's arguments.
    Witness(WitnessError),
    /// Constructing a child contract exposed an invalid contract definition.
    Contract(ContractError),
    /// Any other clause-specific failure.
    Other(String),
}

impl fmt::Display for ClauseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClauseError::Witness(e) => write!(f, "Witness error: {}", e),
            ClauseError::Contract(e) => write!(f, "Contract error: {}", e),
            ClauseError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ClauseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClauseError::Witness(e) => Some(e),
            ClauseError::Contract(e) => Some(e),
            ClauseError::Other(_) => None,
        }
    }
}

impl ClauseError {
    /// An [`Other`](ClauseError::Other) failure, from anything printable: the
    /// way a `next` block rejects arguments its script would reject.
    pub fn other(message: impl fmt::Display) -> Self {
        ClauseError::Other(message.to_string())
    }
}

impl From<WitnessError> for ClauseError {
    fn from(e: WitnessError) -> Self {
        ClauseError::Witness(e)
    }
}

impl From<crate::ccv::InvalidCcvIndex> for ClauseError {
    fn from(e: crate::ccv::InvalidCcvIndex) -> Self {
        ClauseError::Other(e.to_string())
    }
}

impl From<ContractError> for ClauseError {
    fn from(e: ContractError) -> Self {
        ClauseError::Contract(e)
    }
}

/// Errors from contract address / key-derivation operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum ContractError {
    /// A block-based CSV delay is outside 1..=65,535.
    InvalidBlockDelay { blocks: u32 },
    /// The logical state has a different concrete type from the contract's
    /// declared state type (`()` for a stateless contract).
    WrongStateType,
    /// A clause was executed against params of a different concrete type from
    /// the one its contract was built with.
    WrongParamsType,
    /// An instance was placed at an output its funding transaction does not
    /// have.
    MissingFundingOutput(OutPoint),
    /// Failed to decode the contract state.
    StateDecoding(WitnessError),
    /// A taproot / secp256k1 key operation failed (tweak, parse, ...).
    Key(String),
    /// Two clauses in one contract have the same lookup name.
    DuplicateClauseName(String),
    /// Two clauses in one contract have the same tapscript and cannot be
    /// distinguished when observing a spend.
    DuplicateClauseScript {
        /// The first clause with this script.
        first: String,
        /// The second clause with this script.
        second: String,
    },
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::InvalidBlockDelay { blocks } => {
                write!(
                    f,
                    "CSV block delay must be between 1 and 65535, got {blocks}"
                )
            }
            ContractError::WrongStateType => {
                write!(f, "logical state type does not match the contract")
            }
            ContractError::WrongParamsType => {
                write!(f, "params type does not match the contract")
            }
            ContractError::MissingFundingOutput(outpoint) => {
                write!(f, "the funding transaction has no output {outpoint}")
            }
            ContractError::StateDecoding(e) => write!(f, "failed to decode state: {}", e),
            ContractError::Key(msg) => write!(f, "key operation failed: {}", msg),
            ContractError::DuplicateClauseName(name) => {
                write!(f, "duplicate clause name in contract: {name}")
            }
            ContractError::DuplicateClauseScript { first, second } => write!(
                f,
                "clauses '{first}' and '{second}' have the same tapscript"
            ),
        }
    }
}

impl std::error::Error for ContractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ContractError::StateDecoding(e) => Some(e),
            _ => None,
        }
    }
}

impl From<WitnessError> for ContractError {
    fn from(e: WitnessError) -> Self {
        ContractError::StateDecoding(e)
    }
}
