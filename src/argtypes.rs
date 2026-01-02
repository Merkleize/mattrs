//! Argument types for witness stack serialization and deserialization.
//!
//! This module provides a type-safe framework for converting between high-level Rust values
//! and Bitcoin witness stack elements. It mirrors the Python ArgType system from pymatt.

use crate::WitnessError;
use crate::script_utils::{bn2vch, vch2bn};
use std::any::Any;
use std::collections::HashMap;

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

/// Trait for types that can serialize and deserialize witness stack arguments.
///
/// This trait allows library users to define custom argument types while maintaining
/// type safety and consistent error handling. Implementations should validate that
/// the provided ArgValue matches the expected type.
///
/// # Object Safety
///
/// This trait is object-safe to allow `Box<dyn ArgType>` for runtime polymorphism.
pub trait ArgType: Send + Sync {
    /// Serializes a value into one or more witness stack elements.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to serialize
    ///
    /// # Returns
    ///
    /// A vector of byte vectors, where each inner vector is a witness element.
    /// Most types return a single element, but complex types (like MerkleProof)
    /// may return multiple elements.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The value variant doesn't match the expected type
    /// - The value is invalid for this type
    fn serialize_to_wit(&self, value: &ArgValue) -> Result<Vec<Vec<u8>>, WitnessError>;

    /// Deserializes a value from the witness stack.
    ///
    /// # Arguments
    ///
    /// * `stack` - A slice of witness elements to deserialize from
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The number of elements consumed from the stack
    /// - The deserialized value
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The stack doesn't have enough elements
    /// - The elements are malformed
    /// - Deserialization fails
    fn deserialize_from_wit(&self, stack: &[Vec<u8>]) -> Result<(usize, ArgValue), WitnessError>;
}

/// Standard argument type for signed integers.
///
/// Serializes i64 values using Bitcoin Script's little-endian signed format.
#[derive(Debug, Clone)]
pub struct IntType;

impl ArgType for IntType {
    fn serialize_to_wit(&self, value: &ArgValue) -> Result<Vec<Vec<u8>>, WitnessError> {
        match value {
            ArgValue::Int(n) => Ok(vec![bn2vch(*n)]),
            _ => Err(WitnessError::TypeMismatch {
                expected: "Int".to_string(),
                got: value.type_name().to_string(),
            }),
        }
    }

    fn deserialize_from_wit(&self, stack: &[Vec<u8>]) -> Result<(usize, ArgValue), WitnessError> {
        if stack.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }

        let value = vch2bn(&stack[0])?;
        Ok((1, ArgValue::Int(value)))
    }
}

/// Standard argument type for arbitrary byte arrays.
///
/// Used for hashes, commitments, nonces, and other unstructured data.
#[derive(Debug, Clone)]
pub struct BytesType;

impl ArgType for BytesType {
    fn serialize_to_wit(&self, value: &ArgValue) -> Result<Vec<Vec<u8>>, WitnessError> {
        match value {
            ArgValue::Bytes(bytes) => Ok(vec![bytes.clone()]),
            _ => Err(WitnessError::TypeMismatch {
                expected: "Bytes".to_string(),
                got: value.type_name().to_string(),
            }),
        }
    }

    fn deserialize_from_wit(&self, stack: &[Vec<u8>]) -> Result<(usize, ArgValue), WitnessError> {
        if stack.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }

        Ok((1, ArgValue::Bytes(stack[0].clone())))
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
    ///
    /// # Arguments
    ///
    /// * `pubkey` - A 32-byte x-only public key
    ///
    /// # Errors
    ///
    /// Returns an error if the pubkey is not exactly 32 bytes.
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

impl ArgType for SignerType {
    fn serialize_to_wit(&self, value: &ArgValue) -> Result<Vec<Vec<u8>>, WitnessError> {
        match value {
            ArgValue::Signature(sig) => Ok(vec![sig.clone()]),
            _ => Err(WitnessError::TypeMismatch {
                expected: "Signature".to_string(),
                got: value.type_name().to_string(),
            }),
        }
    }

    fn deserialize_from_wit(&self, stack: &[Vec<u8>]) -> Result<(usize, ArgValue), WitnessError> {
        if stack.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }

        Ok((1, ArgValue::Signature(stack[0].clone())))
    }
}

/// A specification for a contract clause argument.
///
/// Pairs an argument name with its type definition.
pub type ArgSpec = Vec<(String, Box<dyn ArgType>)>;

/// Converts a map of argument values into witness stack elements.
///
/// # Arguments
///
/// * `specs` - The argument specifications (names and types)
/// * `args` - Map of argument names to their values
///
/// # Returns
///
/// A flat vector of witness stack elements in the correct order.
///
/// # Errors
///
/// Returns an error if:
/// - A required argument is missing
/// - An argument has the wrong type
/// - Serialization fails
pub fn stack_elements_from_args(
    specs: &ArgSpec,
    args: &HashMap<String, ArgValue>,
) -> Result<Vec<Vec<u8>>, WitnessError> {
    let mut result = Vec::new();

    for (arg_name, arg_type) in specs {
        let value = args
            .get(arg_name)
            .ok_or_else(|| WitnessError::MissingArgument(arg_name.clone()))?;

        let elements = arg_type.serialize_to_wit(value)?;
        result.extend(elements);
    }

    Ok(result)
}

/// Converts witness stack elements into a map of argument values.
///
/// # Arguments
///
/// * `specs` - The argument specifications (names and types)
/// * `elements` - The witness stack elements to deserialize
///
/// # Returns
///
/// A map of argument names to their deserialized values.
///
/// # Errors
///
/// Returns an error if:
/// - There are too few elements in the stack
/// - There are too many elements (not all consumed)
/// - Deserialization fails
pub fn args_from_stack_elements(
    specs: &ArgSpec,
    elements: &[Vec<u8>],
) -> Result<HashMap<String, ArgValue>, WitnessError> {
    let mut result = HashMap::new();
    let mut cursor = 0;

    for (arg_name, arg_type) in specs {
        if cursor >= elements.len() {
            return Err(WitnessError::StackUnderflow);
        }

        let (consumed, value) = arg_type.deserialize_from_wit(&elements[cursor..])?;
        result.insert(arg_name.clone(), value);
        cursor += consumed;
    }

    // Ensure all elements were consumed
    if cursor != elements.len() {
        return Err(WitnessError::InvalidData(format!(
            "Too many witness elements: expected {}, got {}",
            cursor,
            elements.len()
        )));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_type_roundtrip() {
        let int_type = IntType;
        let value = ArgValue::Int(42);

        let serialized = int_type.serialize_to_wit(&value).unwrap();
        assert_eq!(serialized.len(), 1);

        let (consumed, deserialized) = int_type.deserialize_from_wit(&serialized).unwrap();
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

        let serialized = bytes_type.serialize_to_wit(&value).unwrap();
        assert_eq!(serialized.len(), 1);
        assert_eq!(serialized[0], data);

        let (consumed, deserialized) = bytes_type.deserialize_from_wit(&serialized).unwrap();
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

        let serialized = signer_type.serialize_to_wit(&value).unwrap();
        assert_eq!(serialized.len(), 1);
        assert_eq!(serialized[0], sig);

        let (consumed, deserialized) = signer_type.deserialize_from_wit(&serialized).unwrap();
        assert_eq!(consumed, 1);
        match deserialized {
            ArgValue::Signature(s) => assert_eq!(s, sig),
            _ => panic!("Expected Signature"),
        }
    }

    #[test]
    fn test_type_mismatch() {
        let int_type = IntType;
        let wrong_value = ArgValue::Bytes(vec![1, 2, 3]);

        let result = int_type.serialize_to_wit(&wrong_value);
        assert!(matches!(result, Err(WitnessError::TypeMismatch { .. })));
    }

    #[test]
    fn test_stack_elements_from_args() {
        let specs: ArgSpec = vec![
            ("x".to_string(), Box::new(IntType)),
            ("y".to_string(), Box::new(BytesType)),
        ];

        let mut args = HashMap::new();
        args.insert("x".to_string(), ArgValue::Int(100));
        args.insert("y".to_string(), ArgValue::Bytes(vec![0xaa, 0xbb]));

        let elements = stack_elements_from_args(&specs, &args).unwrap();
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0], bn2vch(100));
        assert_eq!(elements[1], vec![0xaa, 0xbb]);
    }

    #[test]
    fn test_args_from_stack_elements() {
        let specs: ArgSpec = vec![
            ("x".to_string(), Box::new(IntType)),
            ("y".to_string(), Box::new(BytesType)),
        ];

        let elements = vec![bn2vch(100), vec![0xaa, 0xbb]];

        let args = args_from_stack_elements(&specs, &elements).unwrap();
        assert_eq!(args.len(), 2);

        match args.get("x").unwrap() {
            ArgValue::Int(n) => assert_eq!(*n, 100),
            _ => panic!("Expected Int"),
        }

        match args.get("y").unwrap() {
            ArgValue::Bytes(b) => assert_eq!(b, &vec![0xaa, 0xbb]),
            _ => panic!("Expected Bytes"),
        }
    }

    #[test]
    fn test_roundtrip_full() {
        let specs: ArgSpec = vec![
            ("a".to_string(), Box::new(IntType)),
            ("b".to_string(), Box::new(BytesType)),
            ("c".to_string(), Box::new(SignerType::new([0x01; 32]))),
        ];

        let mut original_args = HashMap::new();
        original_args.insert("a".to_string(), ArgValue::Int(-42));
        original_args.insert("b".to_string(), ArgValue::Bytes(vec![1, 2, 3]));
        original_args.insert("c".to_string(), ArgValue::Signature(vec![0xff; 64]));

        let elements = stack_elements_from_args(&specs, &original_args).unwrap();
        let recovered_args = args_from_stack_elements(&specs, &elements).unwrap();

        assert_eq!(original_args.len(), recovered_args.len());

        match (
            original_args.get("a").unwrap(),
            recovered_args.get("a").unwrap(),
        ) {
            (ArgValue::Int(a), ArgValue::Int(b)) => assert_eq!(a, b),
            _ => panic!("Type mismatch"),
        }
    }

    #[test]
    fn test_missing_argument_error() {
        let specs: ArgSpec = vec![("x".to_string(), Box::new(IntType))];

        let args = HashMap::new(); // Empty!

        let result = stack_elements_from_args(&specs, &args);
        assert!(matches!(result, Err(WitnessError::MissingArgument(_))));
    }

    #[test]
    fn test_too_many_elements_error() {
        let specs: ArgSpec = vec![("x".to_string(), Box::new(IntType))];

        let elements = vec![bn2vch(1), bn2vch(2)]; // Too many!

        let result = args_from_stack_elements(&specs, &elements);
        assert!(matches!(result, Err(WitnessError::InvalidData(_))));
    }
}
