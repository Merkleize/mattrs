//! Validated block-based relative timelocks (BIP68/BIP112).

use bitcoin::{ScriptBuf, Sequence};

use crate::contracts::{ContractError, ParamEncodable, WitnessError};

/// A non-zero CSV delay in blocks, without sequence flags or reserved bits.
///
/// Only the low 16 bits of a sequence encode its duration. Accepting arbitrary
/// `u32` values as block counts can truncate the delay, select time-based locks,
/// or disable CSV entirely. Validate configuration before building scripts.
///
/// Can be stored in derived contract parameters. Its parameter encoding is the
/// same four-byte value as a `u32`; decoding also checks the duration.
///
/// ```
/// use mattrs::{BlockDelay, ContractParams};
/// #[derive(Debug, Clone, ContractParams)]
/// struct Params { delay: BlockDelay }
/// let params = Params { delay: BlockDelay::new(10)? };
/// assert_eq!(params.delay.sequence().to_consensus_u32(), 10);
/// # Ok::<(), mattrs::contracts::ContractError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockDelay(u16);

impl BlockDelay {
    /// Construct a delay of 1 through 65,535 blocks.
    pub fn new(blocks: u32) -> Result<Self, ContractError> {
        match u16::try_from(blocks) {
            Ok(value) if value > 0 => Ok(Self(value)),
            _ => Err(ContractError::InvalidBlockDelay { blocks }),
        }
    }

    /// The delay in blocks.
    pub fn blocks(self) -> u32 {
        u32::from(self.0)
    }

    /// The minimum input sequence satisfying this delay.
    pub fn sequence(self) -> Sequence {
        Sequence::from_height(self.0)
    }

    /// The matching `CSV DROP` script fragment.
    pub fn script(self) -> ScriptBuf {
        crate::script_helpers::older(self.blocks())
    }

    /// Whether a transaction input's sequence satisfies this block constraint.
    /// Transaction version and confirmation age must be checked separately.
    pub fn is_satisfied_by(self, sequence: Sequence) -> bool {
        let value = sequence.to_consensus_u32();
        value & ((1 << 31) | (1 << 22)) == 0 && (value & 0xffff) >= self.blocks()
    }
}

impl ParamEncodable for BlockDelay {
    fn encode_param(&self) -> Vec<Vec<u8>> {
        self.blocks().encode_param()
    }

    fn decode_param(elements: &[Vec<u8>]) -> Result<(Self, usize), WitnessError> {
        let (blocks, consumed) = u32::decode_param(elements)?;
        let delay = Self::new(blocks).map_err(|e| WitnessError::InvalidValue(e.to_string()))?;
        Ok((delay, consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_decoding_preserves_the_validated_type() {
        for blocks in [1u32, 10, 65_535] {
            let encoded = BlockDelay::new(blocks).unwrap().encode_param();
            assert_eq!(encoded, blocks.encode_param());
            assert_eq!(
                BlockDelay::decode_param(&encoded).unwrap(),
                (BlockDelay::new(blocks).unwrap(), 1)
            );
        }
        for blocks in [0u32, 65_536, 1 << 31] {
            assert!(BlockDelay::decode_param(&blocks.encode_param()).is_err());
        }
    }

    #[test]
    fn rejects_values_that_are_not_block_durations() {
        for blocks in [0, 65_536, 1 << 22, 1 << 31, u32::MAX] {
            assert!(matches!(
                BlockDelay::new(blocks),
                Err(ContractError::InvalidBlockDelay { .. })
            ));
        }
        for blocks in [1, 10, 65_535] {
            let delay = BlockDelay::new(blocks).unwrap();
            assert_eq!(delay.sequence().to_consensus_u32(), blocks);
            assert_eq!(delay.script(), crate::script_helpers::older(blocks));
        }
    }

    #[test]
    fn checks_duration_and_sequence_flags() {
        let delay = BlockDelay::new(10).unwrap();
        for value in [0, 9, (1 << 22) | 10, (1 << 31) | 10, u32::MAX] {
            assert!(!delay.is_satisfied_by(Sequence(value)));
        }
        for value in [10, 11, 65_535, (1 << 16) | 10] {
            assert!(delay.is_satisfied_by(Sequence(value)));
        }
    }
}
