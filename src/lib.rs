use std::fmt;

pub mod argtypes;
pub mod script_utils;

#[derive(Debug)]
pub enum WitnessError {
    InvalidData(String),
    InsufficientData,
    DecodingFailed(String),
    /// A required argument is missing from the arguments map.
    MissingArgument(String),
    /// An argument value has a type that doesn't match the expected ArgType.
    TypeMismatch {
        expected: String,
        got: String,
    },
    /// The witness stack doesn't have enough elements to deserialize.
    StackUnderflow,
    /// A value is invalid for its type (e.g., oversized integer, wrong-length pubkey).
    InvalidValue(String),
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WitnessError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            WitnessError::InsufficientData => write!(f, "Insufficient data in witness"),
            WitnessError::DecodingFailed(msg) => write!(f, "Decoding failed: {}", msg),
            WitnessError::MissingArgument(name) => write!(f, "Missing required argument: {}", name),
            WitnessError::TypeMismatch { expected, got } => {
                write!(f, "Type mismatch: expected {}, got {}", expected, got)
            }
            WitnessError::StackUnderflow => write!(f, "Witness stack underflow"),
            WitnessError::InvalidValue(msg) => write!(f, "Invalid value: {}", msg),
        }
    }
}

impl std::error::Error for WitnessError {}

/// Trait for types that can be encoded/decoded to/from a Bitcoin witness stack.
///
/// This trait provides a standardized interface for serializing and deserializing
/// types to and from the witness stack format used in Bitcoin transactions.
///
/// # Witness Stack Format
///
/// The witness stack is represented as a vector of byte vectors (`Vec<Vec<u8>>`),
/// where each inner `Vec<u8>` represents a single witness element.
pub trait WitnessEncodable {
    /// Encodes the value into one or more witness stack elements.
    ///
    /// # Returns
    ///
    /// A vector of byte vectors, where each inner vector represents a single
    /// witness element. The elements should be ordered as they would appear
    /// on the witness stack.
    fn encode_to_witness(&self) -> Vec<Vec<u8>>;

    /// Decodes a value from the witness stack.
    ///
    /// # Arguments
    ///
    /// * `witness` - A slice of witness elements to decode from
    ///
    /// # Returns
    ///
    /// * `Ok((value, consumed))` - The decoded value and the number of witness
    ///   elements consumed from the input slice
    /// * `Err(e)` - An error if decoding fails (e.g., invalid format, insufficient elements)
    ///
    /// # Errors
    ///
    /// This method should return an error if:
    /// - The witness stack doesn't contain enough elements
    /// - The witness elements have invalid format or size
    /// - The data cannot be properly decoded
    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
