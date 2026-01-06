//! Bitcoin Script encoding utilities.
//!
//! This module provides functions for encoding and decoding values to/from
//! Bitcoin Script format, particularly for witness stack manipulation.

use crate::contracts::WitnessError;

/// Converts a Rust i64 to Bitcoin Script's little-endian signed integer format.
///
/// Bitcoin Script represents integers as variable-length byte arrays in little-endian
/// format with the most significant bit used as a sign bit.
///
/// # Examples
///
/// ```
/// use mattrs::script_utils::bn2vch;
///
/// // Small positive numbers
/// assert_eq!(bn2vch(0), Vec::<u8>::new());
/// assert_eq!(bn2vch(1), vec![0x01]);
/// assert_eq!(bn2vch(127), vec![0x7f]);
///
/// // Negative numbers use the sign bit
/// assert_eq!(bn2vch(-1), vec![0x81]);
/// assert_eq!(bn2vch(-127), vec![0xff]);
/// ```
pub fn bn2vch(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }

    let mut result = Vec::new();
    let negative = value < 0;
    let mut abs_value = value.unsigned_abs();

    while abs_value > 0 {
        result.push((abs_value & 0xff) as u8);
        abs_value >>= 8;
    }

    // If the most significant bit is set, we need an extra byte for the sign
    if result[result.len() - 1] & 0x80 != 0 {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        // Set the sign bit on the most significant byte
        *result.last_mut().unwrap() |= 0x80;
    }

    result
}

/// Converts Bitcoin Script's little-endian signed integer format to a Rust i64.
///
/// This is the inverse operation of `bn2vch`.
///
/// # Errors
///
/// Returns `WitnessError::InvalidValue` if:
/// - The byte array is too long to fit in an i64
/// - The encoding is malformed
///
/// # Examples
///
/// ```
/// use mattrs::script_utils::vch2bn;
///
/// assert_eq!(vch2bn(&[]).unwrap(), 0);
/// assert_eq!(vch2bn(&[0x01]).unwrap(), 1);
/// assert_eq!(vch2bn(&[0x7f]).unwrap(), 127);
/// assert_eq!(vch2bn(&[0x81]).unwrap(), -1);
/// assert_eq!(vch2bn(&[0xff]).unwrap(), -127);
/// ```
pub fn vch2bn(vch: &[u8]) -> Result<i64, WitnessError> {
    if vch.is_empty() {
        return Ok(0);
    }

    // Bitcoin script integers can be at most 4 bytes for standard operations,
    // but we allow up to 8 bytes for i64, plus one extra byte for the sign bit if needed
    if vch.len() > 9 {
        return Err(WitnessError::InvalidValue(
            "Integer value too large for i64".to_string(),
        ));
    }

    // Special case: check for minimal encoding issues
    // The last byte should not be 0x00 or 0x80 unless it's needed for the sign bit
    if vch.len() > 1 {
        let last_byte = vch[vch.len() - 1];
        let second_last_byte = vch[vch.len() - 2];

        // If last byte is 0x00 and second-to-last doesn't have high bit set, non-minimal
        if last_byte == 0x00 && (second_last_byte & 0x80) == 0 {
            return Err(WitnessError::InvalidValue(
                "Non-minimal integer encoding".to_string(),
            ));
        }
        // If last byte is 0x80 and second-to-last doesn't have high bit set, non-minimal
        if last_byte == 0x80 && (second_last_byte & 0x80) == 0 {
            return Err(WitnessError::InvalidValue(
                "Non-minimal integer encoding".to_string(),
            ));
        }
    }

    let last_byte = *vch.last().unwrap();
    let negative = (last_byte & 0x80) != 0;

    // Build the absolute value
    let mut result: u64 = 0;
    for (i, &byte) in vch.iter().enumerate() {
        // Prevent shift overflow - we can have at most 8 bytes of data plus 1 sign byte
        if i >= 8 {
            // This is the 9th byte (index 8), which should only contain the sign bit
            if i == 8 && byte == 0x00 {
                // Valid: just a sign extension byte
                continue;
            } else if i == 8 && byte == 0x80 {
                // Valid: negative sign extension byte
                continue;
            } else {
                // Too much data
                return Err(WitnessError::InvalidValue(
                    "Integer value too large for i64".to_string(),
                ));
            }
        }

        if i == vch.len() - 1 {
            // For the last byte, mask off the sign bit
            result |= ((byte & 0x7f) as u64) << (8 * i);
        } else {
            result |= (byte as u64) << (8 * i);
        }
    }

    // Check for overflow when converting to i64
    if negative {
        // For negative numbers, result should be <= i64::MAX + 1 (which is i64::MIN's absolute value)
        if result > (i64::MAX as u64) + 1 {
            return Err(WitnessError::InvalidValue(
                "Negative integer value too large for i64".to_string(),
            ));
        }
        // Handle i64::MIN specially to avoid overflow
        if result == (i64::MAX as u64) + 1 {
            Ok(i64::MIN)
        } else {
            Ok(-(result as i64))
        }
    } else {
        if result > i64::MAX as u64 {
            return Err(WitnessError::InvalidValue(
                "Positive integer value too large for i64".to_string(),
            ));
        }
        Ok(result as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bn2vch_zero() {
        assert_eq!(bn2vch(0), Vec::<u8>::new());
    }

    #[test]
    fn test_bn2vch_positive() {
        assert_eq!(bn2vch(1), vec![0x01]);
        assert_eq!(bn2vch(127), vec![0x7f]);
        assert_eq!(bn2vch(128), vec![0x80, 0x00]);
        assert_eq!(bn2vch(255), vec![0xff, 0x00]);
        assert_eq!(bn2vch(256), vec![0x00, 0x01]);
    }

    #[test]
    fn test_bn2vch_negative() {
        assert_eq!(bn2vch(-1), vec![0x81]);
        assert_eq!(bn2vch(-127), vec![0xff]);
        assert_eq!(bn2vch(-128), vec![0x80, 0x80]);
        assert_eq!(bn2vch(-255), vec![0xff, 0x80]);
    }

    #[test]
    fn test_vch2bn_zero() {
        assert_eq!(vch2bn(&[]).unwrap(), 0);
    }

    #[test]
    fn test_vch2bn_positive() {
        assert_eq!(vch2bn(&[0x01]).unwrap(), 1);
        assert_eq!(vch2bn(&[0x7f]).unwrap(), 127);
        assert_eq!(vch2bn(&[0x80, 0x00]).unwrap(), 128);
        assert_eq!(vch2bn(&[0xff, 0x00]).unwrap(), 255);
    }

    #[test]
    fn test_vch2bn_negative() {
        assert_eq!(vch2bn(&[0x81]).unwrap(), -1);
        assert_eq!(vch2bn(&[0xff]).unwrap(), -127);
        assert_eq!(vch2bn(&[0x80, 0x80]).unwrap(), -128);
    }

    #[test]
    fn test_roundtrip() {
        let test_values = vec![
            0,
            1,
            -1,
            127,
            -127,
            128,
            -128,
            255,
            -255,
            256,
            -256,
            32767,
            -32767,
            32768,
            -32768,
            65535,
            -65535,
            i64::MAX,
            i64::MIN,
        ];

        for &value in &test_values {
            let encoded = bn2vch(value);
            let decoded = vch2bn(&encoded).unwrap();
            assert_eq!(value, decoded, "Roundtrip failed for {}", value);
        }
    }

    #[test]
    fn test_vch2bn_non_minimal() {
        // 0x00 0x00 is non-minimal encoding of 0
        assert!(vch2bn(&[0x00, 0x00]).is_err());

        // 0x01 0x00 is non-minimal encoding of 1
        assert!(vch2bn(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn test_vch2bn_overflow() {
        // 10 bytes is too large for i64
        let too_large = vec![0xff; 10];
        assert!(vch2bn(&too_large).is_err());
    }
}
