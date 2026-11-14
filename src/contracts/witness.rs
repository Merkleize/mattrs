//! Witness encoding: how typed values become the stack elements a tapscript reads.

use super::WitnessError;
use bitcoin::XOnlyPublicKey;

/// Encoding of a value as one or more **witness-stack elements** — the
/// script-facing, consensus-relevant format a tapscript actually reads.
///
/// This is the role for a clause's arguments ([`ClauseArgs`](super::ClauseArgs)) and for a state
/// commitment's Merkle leaves ([`ContractState`](super::ContractState)): the bytes produced here are the
/// bytes the covenant sees. Signed integers therefore use Bitcoin Script's number
/// format (`bn2vch`), so scripts can do arithmetic on them; other types map to the
/// bytes a script would push (a 32-byte hash, an x-only key, ...).
pub trait WitnessEncodable {
    /// The number of witness elements every value of this type occupies, or
    /// `None` when it varies with the value (e.g. `Option<T>`). Symbolic
    /// script builders lay out a witness from this before any value exists.
    const ELEMENTS: Option<usize>;

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

/// The combined [`WitnessEncodable::ELEMENTS`] of a sequence of fields: their
/// sum, or `None` if any field's count varies. Used by the derives.
#[doc(hidden)]
pub const fn __sum_elements(parts: &[Option<usize>]) -> Option<usize> {
    let mut total = 0;
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            Some(n) => total += n,
            None => return None,
        }
        i += 1;
    }
    Some(total)
}

/// Marker for values whose [`WitnessEncodable`] representation is always
/// exactly one element.
///
/// Identity [`ContractState`](super::ContractState) commitments use that element's bytes directly,
/// because covenant scripts re-reveal those same bytes as the Taproot state
/// tweak. Variable- or multi-element encodings cannot be flattened without
/// losing their element boundaries and therefore must not implement this trait.
///
/// Implementors opt into identity-state use. The checked helpers verify that
/// the underlying codec actually produces and consumes exactly one element,
/// so an incorrect implementation is an ordinary decoding error rather than
/// an unsafe-code contract.
///
/// Types with variable-width witness layouts cannot be used as identity state:
///
/// ```compile_fail
/// use mattrs::ContractState;
///
/// #[derive(Debug, Clone, ContractState)]
/// #[commit(identity)]
/// struct InvalidState {
///     value: Option<[u8; 32]>,
/// }
/// ```
pub trait SingleWitnessElement: WitnessEncodable {
    /// Encode and verify that exactly one element was produced.
    fn encode_single(&self) -> Result<Vec<u8>, WitnessError> {
        let mut elements = self.encode_to_witness();
        if elements.len() != 1 {
            return Err(WitnessError::Invalid(format!(
                "single-element codec produced {} elements",
                elements.len()
            )));
        }
        Ok(elements.pop().expect("length checked"))
    }

    /// Decode and verify that exactly one element was consumed.
    fn decode_single(element: Vec<u8>) -> Result<Self, WitnessError>
    where
        Self: Sized,
    {
        let (value, consumed) = Self::decode_from_witness(&[element])?;
        if consumed != 1 {
            return Err(WitnessError::Invalid(format!(
                "single-element codec consumed {consumed} elements"
            )));
        }
        Ok(value)
    }
}

/// Signed integers use Bitcoin Script's number format (`bn2vch`), one element.
macro_rules! impl_scriptnum_witness {
    ($($t:ty),+ $(,)?) => {$(
        impl WitnessEncodable for $t {
            const ELEMENTS: Option<usize> = Some(1);

            fn encode_to_witness(&self) -> Vec<Vec<u8>> {
                vec![crate::script::bn2vch(*self as i64)]
            }

            fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
                if witness.is_empty() {
                    return Err(WitnessError::Missing);
                }
                let val = crate::script::vch2bn(&witness[0])
                    .map_err(|e| WitnessError::Invalid(e.to_string()))?;
                let value = <$t>::try_from(val).map_err(|_| {
                    WitnessError::Invalid(format!(
                        "Script number {val} is out of range for {}",
                        stringify!($t),
                    ))
                })?;
                Ok((value, 1))
            }
        }
    )+};
}

impl_scriptnum_witness!(i32, i64);

impl SingleWitnessElement for i32 {}
impl SingleWitnessElement for i64 {}

impl<const N: usize> WitnessEncodable for [u8; N] {
    const ELEMENTS: Option<usize> = Some(1);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.to_vec()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::Missing);
        }
        if witness[0].len() != N {
            return Err(WitnessError::Invalid(format!(
                "Expected array of length {}, got {}",
                N,
                witness[0].len()
            )));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&witness[0]);
        Ok((arr, 1))
    }
}

impl<const N: usize> SingleWitnessElement for [u8; N] {}

impl WitnessEncodable for Vec<u8> {
    const ELEMENTS: Option<usize> = Some(1);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.clone()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::Missing);
        }
        Ok((witness[0].clone(), 1))
    }
}

impl SingleWitnessElement for Vec<u8> {}

/// Booleans use the *canonical* script encoding — `[]` for false, `[0x01]` for
/// true — the only values tapscript's consensus `MINIMALIF` accepts as `OP_IF`
/// operands (a `[0x00]` false would be invalid on-chain).
impl WitnessEncodable for bool {
    const ELEMENTS: Option<usize> = Some(1);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![if *self { vec![1] } else { Vec::new() }]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        match witness.first().ok_or(WitnessError::Missing)?.as_slice() {
            [] => Ok((false, 1)),
            [1] => Ok((true, 1)),
            other => Err(WitnessError::Invalid(format!(
                "not a canonical bool encoding: {other:02x?}"
            ))),
        }
    }
}

impl SingleWitnessElement for bool {}

impl WitnessEncodable for XOnlyPublicKey {
    const ELEMENTS: Option<usize> = Some(1);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.serialize().to_vec()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::Missing);
        }
        if witness[0].len() != 32 {
            return Err(WitnessError::Invalid(format!(
                "Expected 32 bytes for XOnlyPublicKey, got {}",
                witness[0].len()
            )));
        }
        let key = XOnlyPublicKey::from_slice(&witness[0])
            .map_err(|e| WitnessError::Invalid(e.to_string()))?;
        Ok((key, 1))
    }
}

impl SingleWitnessElement for XOnlyPublicKey {}

impl<T: WitnessEncodable> WitnessEncodable for Option<T> {
    /// One flag element, plus the value's elements when present.
    const ELEMENTS: Option<usize> = None;

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        match self {
            Some(value) => {
                let mut result = vec![vec![1u8]]; // presence flag
                result.extend(value.encode_to_witness());
                result
            }
            None => vec![Vec::new()], // canonical false / absence flag
        }
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        if witness.is_empty() {
            return Err(WitnessError::Missing);
        }

        match witness[0].as_slice() {
            [] => Ok((None, 1)),
            [1] => {
                let (value, consumed) = T::decode_from_witness(&witness[1..])?;
                Ok((Some(value), consumed + 1))
            }
            other => Err(WitnessError::Invalid(format!(
                "not a canonical option flag: {other:02x?}",
            ))),
        }
    }
}

/// A Schnorr signature witness element.
///
/// Signature fields in a clause's `*Args` struct use this type. It defaults to
/// empty (unsigned): the manager fills it in at spend time by matching the
/// clause's `SignerType` pubkey against the registered signers, so callers never
/// build a placeholder signature by hand. It occupies exactly one witness element.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Wrap raw signature bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, WitnessError> {
        if !bytes.is_empty() && !matches!(bytes.len(), 64 | 65) {
            return Err(WitnessError::Invalid(format!(
                "taproot signature must be 64 or 65 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Signature(bytes))
    }

    /// The signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether the signature is unset (the default, to be filled by the manager).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = WitnessError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Signature::new(bytes)
    }
}

impl WitnessEncodable for Signature {
    const ELEMENTS: Option<usize> = Some(1);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        vec![self.0.clone()]
    }

    fn decode_from_witness(witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        let first = witness.first().ok_or(WitnessError::Missing)?;
        Ok((Signature::new(first.clone())?, 1))
    }
}

impl SingleWitnessElement for Signature {}

/// A sequential reader over a clause's witness elements, for raw-args clauses'
/// `next()` bodies: each read consumes elements in order, so argument
/// extraction follows the clause's `ArgSpec` order by construction instead of
/// hand-counted indices, and errors name the failing element's position.
///
/// ```ignore
/// let mut r = WitnessReader::new(witness);
/// let taptree = r.bytes32()?;
/// let root = r.bytes32()?;
/// let x = r.num()?;
/// ```
#[derive(Debug)]
pub struct WitnessReader<'a> {
    witness: &'a [Vec<u8>],
    pos: usize,
}

impl<'a> WitnessReader<'a> {
    /// Start reading at the first element.
    pub fn new(witness: &'a [Vec<u8>]) -> Self {
        WitnessReader { witness, pos: 0 }
    }

    fn take(&mut self) -> Result<&'a [u8], WitnessError> {
        let element = self.witness.get(self.pos).ok_or_else(|| {
            WitnessError::Invalid(format!(
                "witness element {} requested, but the stack has {}",
                self.pos,
                self.witness.len()
            ))
        })?;
        self.pos += 1;
        Ok(element)
    }

    /// The next element, as raw bytes.
    pub fn bytes(&mut self) -> Result<&'a [u8], WitnessError> {
        self.take()
    }

    /// The next element, as exactly 32 bytes.
    pub fn bytes32(&mut self) -> Result<[u8; 32], WitnessError> {
        let pos = self.pos;
        self.take()?
            .try_into()
            .map_err(|_| WitnessError::Invalid(format!("witness element {pos} is not 32 bytes")))
    }

    /// The next element, as a Bitcoin script number.
    pub fn num(&mut self) -> Result<i64, WitnessError> {
        let pos = self.pos;
        crate::script::vch2bn(self.take()?)
            .map_err(|e| WitnessError::Invalid(format!("witness element {pos}: {e}")))
    }

    /// The next element, as an x-only public key.
    pub fn xonly(&mut self) -> Result<XOnlyPublicKey, WitnessError> {
        let pos = self.pos;
        XOnlyPublicKey::from_slice(&self.bytes32()?).map_err(|e| {
            WitnessError::Invalid(format!("witness element {pos} is not an x-only key: {e}"))
        })
    }

    /// Skip the next `n` elements.
    pub fn skip(&mut self, n: usize) -> Result<(), WitnessError> {
        for _ in 0..n {
            self.take()?;
        }
        Ok(())
    }

    /// How many elements are left.
    pub fn remaining(&self) -> usize {
        self.witness.len().saturating_sub(self.pos)
    }

    /// Assert every element was consumed.
    pub fn expect_end(&self) -> Result<(), WitnessError> {
        if self.remaining() != 0 {
            return Err(WitnessError::Invalid(format!(
                "{} unread witness elements past position {}",
                self.remaining(),
                self.pos
            )));
        }
        Ok(())
    }
}

impl WitnessEncodable for () {
    const ELEMENTS: Option<usize> = Some(0);

    fn encode_to_witness(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn decode_from_witness(_witness: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        Ok(((), 0))
    }
}
