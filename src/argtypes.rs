//! Argument types describing a clause's witness layout.
//!
//! Argument *values* are encoded and decoded by the typed `*Args` structs (see
//! [`ClauseArgs`](crate::contracts::ClauseArgs)); the [`ArgType`](crate::contracts::ArgType)
//! implementations here only account for the witness elements each argument
//! occupies, and mark which arguments are signatures (so the manager knows which
//! key must sign them). It mirrors the Python ArgType system from pymatt.

use crate::contracts::{ArgType as ArgTypeTrait, WitnessEncodable, WitnessError};
use crate::script_utils::vch2bn;
use bitcoin::XOnlyPublicKey;
use std::marker::PhantomData;

/// Standard argument type for signed integers.
///
/// One witness element in Bitcoin Script's little-endian signed format.
#[derive(Debug, Clone)]
pub struct IntType;

impl ArgTypeTrait for IntType {
    fn consume(&self, witness: &[Vec<u8>]) -> Result<usize, WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        vch2bn(&witness[0])?;
        Ok(1)
    }
}

/// Standard argument type for arbitrary byte arrays.
///
/// One witness element: hashes, commitments, nonces, and other unstructured data.
#[derive(Debug, Clone)]
pub struct BytesType;

impl ArgTypeTrait for BytesType {
    fn consume(&self, witness: &[Vec<u8>]) -> Result<usize, WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        Ok(1)
    }
}

/// The argument type of any [`WitnessEncodable`] value: its layout is whatever
/// the type's own codec consumes, so an argument's spec can never disagree
/// with how its value is encoded. `#[derive(ClauseArgs)]` uses it for every
/// field that is not a `#[signer(..)]` signature.
pub struct TypedArg<T>(PhantomData<fn() -> T>);

impl<T> TypedArg<T> {
    /// The argument type of a `T`.
    pub fn new() -> Self {
        TypedArg(PhantomData)
    }
}

impl<T> Default for TypedArg<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> std::fmt::Debug for TypedArg<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TypedArg<{}>", std::any::type_name::<T>())
    }
}

impl<T: WitnessEncodable> ArgTypeTrait for TypedArg<T> {
    fn consume(&self, witness: &[Vec<u8>]) -> Result<usize, WitnessError> {
        T::decode_from_witness(witness).map(|(_, consumed)| consumed)
    }

    fn witness_elements(&self) -> Option<usize> {
        T::ELEMENTS
    }
}

/// Argument type for Schnorr signatures in tapscripts.
///
/// One witness element, carrying the public key that must sign it so the
/// ContractManager can automatically fill the signature at spend time. The
/// element may be empty until then.
#[derive(Debug, Clone)]
pub struct SignerType {
    /// The x-only public key that must sign this argument.
    pub pubkey: XOnlyPublicKey,
}

impl SignerType {
    /// Creates a new SignerType with the given public key.
    pub fn new(pubkey: XOnlyPublicKey) -> Self {
        SignerType { pubkey }
    }
}

impl ArgTypeTrait for SignerType {
    fn consume(&self, witness: &[Vec<u8>]) -> Result<usize, WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::StackUnderflow);
        }
        Ok(1)
    }

    fn signer_pubkey(&self) -> Option<XOnlyPublicKey> {
        Some(self.pubkey)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script_utils::bn2vch;

    #[test]
    fn test_int_type_consume() {
        let int_type = IntType;

        let witness = vec![bn2vch(42)];
        assert_eq!(int_type.consume(&witness).unwrap(), 1);

        // An over-long number is rejected.
        let bad = vec![vec![0u8; 9]];
        assert!(int_type.consume(&bad).is_err());

        assert!(matches!(
            int_type.consume(&[]),
            Err(WitnessError::StackUnderflow)
        ));
    }

    #[test]
    fn test_bytes_type_consume() {
        let bytes_type = BytesType;

        let witness = vec![vec![1, 2, 3, 4, 5]];
        assert_eq!(bytes_type.consume(&witness).unwrap(), 1);

        assert!(matches!(
            bytes_type.consume(&[]),
            Err(WitnessError::StackUnderflow)
        ));
    }

    #[test]
    fn test_signer_type_consume_and_pubkey() {
        let pubkey = crate::nums_key();
        let signer_type = SignerType::new(pubkey);

        // A signature element — or the empty placeholder before signing — is one slot.
        assert_eq!(signer_type.consume(&[vec![0xaa; 64]]).unwrap(), 1);
        assert_eq!(signer_type.consume(&[vec![]]).unwrap(), 1);

        assert_eq!(signer_type.signer_pubkey(), Some(pubkey));
        assert_eq!(IntType.signer_pubkey(), None);
    }
}
