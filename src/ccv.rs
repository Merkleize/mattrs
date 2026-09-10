//! Typed arguments for `OP_CHECKCONTRACTVERIFY` (BIP-443).
//!
//! These types distinguish the opcode's argument slots and defined modes. They
//! do not execute scripts or validate values copied from witness stack items.
//! See [`StackScript::ccv`](crate::stack::StackScript::ccv) for assembly and
//! [`StackScript::ccv_raw`](crate::stack::StackScript::ccv_raw) for the explicit
//! low-level escape hatch.

use bitcoin::{XOnlyPublicKey, script::PushBytes};

/// The four defined CCV modes. These are alternatives, **not bit flags**.
///
/// Undefined modes immediately succeed validation of the current input under
/// [BIP-443](https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki).
/// The typed API deliberately cannot represent them.
///
/// ```compile_fail
/// use mattrs::ccv::CcvMode;
/// let mode = CcvMode::CheckInput | CcvMode::DeductAmount;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CcvMode {
    /// Check an input's script, without amount accounting.
    CheckInput = -1,
    /// Check an output and assign the input's residual amount to it. Contributions
    /// from multiple inputs are added together.
    Preserve = 0,
    /// Check an output's script without constraining its amount. This alone does
    /// not protect the input's value and is not a safe way to pay fees.
    IgnoreAmount = 1,
    /// Subtract the checked output's actual amount from the input's residual.
    /// This does not constrain that output to a particular amount.
    DeductAmount = 2,
}

impl CcvMode {
    /// The minimally encoded script-number operand's value.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// A raw integer was not one of the four defined CCV modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCcvMode(pub i32);

impl std::fmt::Display for InvalidCcvMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "undefined CCV mode {} would bypass input validation",
            self.0
        )
    }
}

impl std::error::Error for InvalidCcvMode {}

impl TryFrom<i32> for CcvMode {
    type Error = InvalidCcvMode;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            -1 => Ok(Self::CheckInput),
            0 => Ok(Self::Preserve),
            1 => Ok(Self::IgnoreAmount),
            2 => Ok(Self::DeductAmount),
            _ => Err(InvalidCcvMode(value)),
        }
    }
}

/// A fixed CCV input/output index, or the current input's index.
///
/// Explicit indices fit a nonnegative four-byte Script number. Transaction
/// bounds are checked by the node, not by this type. The mode determines whether
/// the index selects an input or an output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcvIndex(i32);

impl CcvIndex {
    /// Use the executing input's index (the `-1` operand). In output modes this
    /// selects the output at that same index, not an input.
    pub const CURRENT: Self = Self(-1);

    /// Select an explicit index. Rejects indices above `i32::MAX`, which need
    /// more than four bytes as a positive Script number.
    pub const fn at(index: u32) -> Result<Self, InvalidCcvIndex> {
        if index <= i32::MAX as u32 {
            Ok(Self(index as i32))
        } else {
            Err(InvalidCcvIndex(index as i64))
        }
    }

    /// The minimally encoded script-number operand's value.
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }
}

/// An index was neither `-1` nor a nonnegative four-byte Script number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCcvIndex(pub i64);

impl std::fmt::Display for InvalidCcvIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CCV index {} must be -1 or between 0 and {}",
            self.0,
            i32::MAX
        )
    }
}

impl std::error::Error for InvalidCcvIndex {}

impl TryFrom<i64> for CcvIndex {
    type Error = InvalidCcvIndex;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if (-1..=i64::from(i32::MAX)).contains(&value) {
            Ok(Self(value as i32))
        } else {
            Err(InvalidCcvIndex(value))
        }
    }
}

/// Data to commit to. Unlike the key and taptree slots, this slot has no
/// special "current input" sentinel. Nonempty bytes are passed verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcvData<'a> {
    /// Copy a named stack item; the script is responsible for binding its value.
    Item(&'a str),
    /// A common 32-byte commitment, pushed verbatim (not hashed here).
    Const([u8; 32]),
    /// Arbitrary data, pushed verbatim. Normal script element-size limits apply.
    Bytes(&'a PushBytes),
    /// Empty data: omit the data tweak.
    Empty,
}

/// The key before CCV's optional data and taptree tweaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcvKey<'a> {
    /// Copy a named stack item. The node validates the resulting key/operand;
    /// this does not statically validate witness-supplied bytes.
    Item(&'a str),
    /// A validated x-only public key.
    Const(XOnlyPublicKey),
    /// The BIP-341 NUMS key (empty operand).
    Nums,
    /// The executing input's **internal key**, not its untweaked naked key.
    /// In particular, adding data here can tweak an already data-tweaked key.
    CurrentInternalKey,
}

/// The taptree tweak to apply after the optional data tweak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcvTaptree<'a> {
    /// Copy a named stack item; the node validates its length/operand.
    Item(&'a str),
    /// A 32-byte taptree Merkle root.
    Const([u8; 32]),
    /// Reuse the executing input's taptree (`-1`).
    Current,
    /// Omit the taptree tweak entirely. This is not BIP-341's key-only tweak.
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_accept_only_defined_values() {
        for (number, mode) in [
            (-1, CcvMode::CheckInput),
            (0, CcvMode::Preserve),
            (1, CcvMode::IgnoreAmount),
            (2, CcvMode::DeductAmount),
        ] {
            assert_eq!(CcvMode::try_from(number), Ok(mode));
            assert_eq!(mode.as_i32(), number);
        }
        for number in [i32::MIN, -2, 3, 4, 255, i32::MAX] {
            assert_eq!(CcvMode::try_from(number), Err(InvalidCcvMode(number)));
        }
    }

    #[test]
    fn indices_validate_script_number_boundaries() {
        assert_eq!(CcvIndex::try_from(-1), Ok(CcvIndex::CURRENT));
        assert_eq!(CcvIndex::CURRENT.as_i64(), -1);
        for number in [0, 1, 127, 128, i32::MAX as u32] {
            let index = CcvIndex::at(number).unwrap();
            assert_eq!(index.as_i64(), i64::from(number));
            assert_eq!(CcvIndex::try_from(i64::from(number)), Ok(index));
        }
        for number in [i64::MIN, -2, i64::from(i32::MAX) + 1, i64::MAX] {
            assert_eq!(CcvIndex::try_from(number), Err(InvalidCcvIndex(number)));
        }
        assert!(CcvIndex::at(i32::MAX as u32 + 1).is_err());
        assert!(CcvIndex::at(u32::MAX).is_err());
    }
}
