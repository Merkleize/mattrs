//! Argument types for witness stack serialization and deserialization.
//!
//! This module provides a type-safe framework for converting between high-level Rust values
//! and Bitcoin witness stack elements. It mirrors the Python ArgType system from pymatt.

use crate::contracts::{ArgType as ArgTypeTrait, WitnessError};
use crate::script_utils::{bn2vch, vch2bn};
use std::any::Any;

/// Represents a value that can be used as a contract clause argument.
///
/// This enum provides a type-safe wrapper for the different kinds of values
/// that can appear in witness stacks, with special handling for signatures.
#[derive(Debug)]
pub enum ArgValue {
    /// A signed 64-bit integer.
    Int(i64),

    /// Arbitrary byte data (hashes, commitments, nonces, etc.).
    Bytes(Vec<u8>),

    /// A cryptographic signature (semantically distinct from arbitrary bytes).
    /// This allows the ContractManager to identify and auto-fill signature arguments.
    Signature(Vec<u8>),

    /// A custom value type for extensibility.
    /// Users can box their own types here and downcast in custom ArgType implementations.
    Custom(Box<dyn Any + Send + Sync>),
}

// Manual Clone implementation that doesn't require Custom to be cloneable
impl Clone for ArgValue {
    fn clone(&self) -> Self {
        match self {
            ArgValue::Int(n) => ArgValue::Int(*n),
            ArgValue::Bytes(b) => ArgValue::Bytes(b.clone()),
            ArgValue::Signature(s) => ArgValue::Signature(s.clone()),
            ArgValue::Custom(_) => {
                panic!("Cannot clone ArgValue::Custom - custom types must be cloned explicitly")
            }
        }
    }
}

impl ArgValue {
    /// Returns true if this is an Int variant.
    pub fn is_int(&self) -> bool {
        matches!(self, ArgValue::Int(_))
    }

    /// Returns true if this is a Bytes variant.
    pub fn is_bytes(&self) -> bool {
        matches!(self, ArgValue::Bytes(_))
    }

    /// Returns true if this is a Signature variant.
    pub fn is_signature(&self) -> bool {
        matches!(self, ArgValue::Signature(_))
    }

    /// Returns true if this is a Custom variant.
    pub fn is_custom(&self) -> bool {
        matches!(self, ArgValue::Custom(_))
    }

    /// Returns a string describing the variant type.
    pub fn type_name(&self) -> &'static str {
        match self {
            ArgValue::Int(_) => "Int",
            ArgValue::Bytes(_) => "Bytes",
            ArgValue::Signature(_) => "Signature",
            ArgValue::Custom(_) => "Custom",
        }
    }
}

// ============================================================================
// Basic Argument Types
// ============================================================================

/// Standard argument type for signed integers.
///
/// Serializes i64 values using Bitcoin Script's little-endian signed format.
#[derive(Debug, Clone)]
pub struct IntType;

impl ArgTypeTrait for IntType {
    fn encode_to_witness(&self, value: &ArgValue) -> Result<Vec<Vec<u8>>, WitnessError> {
        match value {
            ArgValue::Int(n) => Ok(vec![bn2vch(*n)]),
            _ => Err(WitnessError::TypeMismatch {
                expected: "Int".to_string(),
                got: value.type_name().to_string(),
            }),
        }
    }

    fn decode_from_witness(&self, stack: &[Vec<u8>]) -> Result<(ArgValue, usize), WitnessError> {
        if stack.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }

        let value = vch2bn(&stack[0])?;
        Ok((ArgValue::Int(value), 1))
    }

    fn clone_boxed(&self) -> Box<dyn ArgTypeTrait> {
        Box::new(self.clone())
    }
}

/// Standard argument type for arbitrary byte arrays.
///
/// Used for hashes, commitments, nonces, and other unstructured data.
#[derive(Debug, Clone)]
pub struct BytesType;

impl ArgTypeTrait for BytesType {
    fn encode_to_witness(&self, value: &ArgValue) -> Result<Vec<Vec<u8>>, WitnessError> {
        match value {
            ArgValue::Bytes(bytes) => Ok(vec![bytes.clone()]),
            _ => Err(WitnessError::TypeMismatch {
                expected: "Bytes".to_string(),
                got: value.type_name().to_string(),
            }),
        }
    }

    fn decode_from_witness(&self, stack: &[Vec<u8>]) -> Result<(ArgValue, usize), WitnessError> {
        if stack.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }

        Ok((ArgValue::Bytes(stack[0].clone()), 1))
    }

    fn clone_boxed(&self) -> Box<dyn ArgTypeTrait> {
        Box::new(self.clone())
    }
}

/// Argument type for Schnorr signatures in tapscripts.
///
/// This is semantically a byte array but carries additional metadata (the public key)
/// that allows the ContractManager to automatically generate signatures.
#[derive(Debug, Clone)]
pub struct SignerType {
    /// The x-only public key (32 bytes) for Taproot/Schnorr signatures.
    pub pubkey: [u8; 32],
}

impl SignerType {
    /// Creates a new SignerType with the given public key.
    pub fn new(pubkey: [u8; 32]) -> Self {
        SignerType { pubkey }
    }

    /// Creates a new SignerType from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn from_slice(pubkey: &[u8]) -> Result<Self, WitnessError> {
        if pubkey.len() != 32 {
            return Err(WitnessError::InvalidValue(format!(
                "SignerType requires 32-byte x-only pubkey, got {} bytes",
                pubkey.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(pubkey);
        Ok(SignerType { pubkey: key })
    }
}

impl ArgTypeTrait for SignerType {
    fn encode_to_witness(&self, value: &ArgValue) -> Result<Vec<Vec<u8>>, WitnessError> {
        match value {
            ArgValue::Signature(sig) => Ok(vec![sig.clone()]),
            _ => Err(WitnessError::TypeMismatch {
                expected: "Signature".to_string(),
                got: value.type_name().to_string(),
            }),
        }
    }

    fn decode_from_witness(&self, stack: &[Vec<u8>]) -> Result<(ArgValue, usize), WitnessError> {
        if stack.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }

        Ok((ArgValue::Signature(stack[0].clone()), 1))
    }

    fn signer_pubkey(&self) -> Option<[u8; 32]> {
        Some(self.pubkey)
    }

    fn clone_boxed(&self) -> Box<dyn ArgTypeTrait> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_type_roundtrip() {
        let int_type = IntType;
        let value = ArgValue::Int(42);

        let serialized = int_type.encode_to_witness(&value).unwrap();
        assert_eq!(serialized.len(), 1);

        let (deserialized, consumed) = int_type.decode_from_witness(&serialized).unwrap();
        assert_eq!(consumed, 1);
        match deserialized {
            ArgValue::Int(n) => assert_eq!(n, 42),
            _ => panic!("Expected Int"),
        }
    }

    #[test]
    fn test_bytes_type_roundtrip() {
        let bytes_type = BytesType;
        let data = vec![1, 2, 3, 4, 5];
        let value = ArgValue::Bytes(data.clone());

        let serialized = bytes_type.encode_to_witness(&value).unwrap();
        assert_eq!(serialized.len(), 1);
        assert_eq!(serialized[0], data);

        let (deserialized, consumed) = bytes_type.decode_from_witness(&serialized).unwrap();
        assert_eq!(consumed, 1);
        match deserialized {
            ArgValue::Bytes(b) => assert_eq!(b, data),
            _ => panic!("Expected Bytes"),
        }
    }

    #[test]
    fn test_signer_type_roundtrip() {
        let pubkey = [0x42; 32];
        let signer_type = SignerType::new(pubkey);
        let sig = vec![0xaa; 64];
        let value = ArgValue::Signature(sig.clone());

        let serialized = signer_type.encode_to_witness(&value).unwrap();
        assert_eq!(serialized.len(), 1);
        assert_eq!(serialized[0], sig);

        let (deserialized, consumed) = signer_type.decode_from_witness(&serialized).unwrap();
        assert_eq!(consumed, 1);
        match deserialized {
            ArgValue::Signature(s) => assert_eq!(s, sig),
            _ => panic!("Expected Signature"),
        }
    }

    #[test]
    fn test_type_mismatch_error() {
        let int_type = IntType;
        let wrong_value = ArgValue::Bytes(vec![1, 2, 3]);

        let result = int_type.encode_to_witness(&wrong_value);
        assert!(matches!(result, Err(WitnessError::TypeMismatch { .. })));
    }
}
