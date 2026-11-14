//! Validated block-based relative timelocks (BIP68/BIP112).

use bitcoin::{ScriptBuf, Sequence};

use crate::contracts::ContractError;

/// A non-zero CSV delay in blocks, without sequence flags or reserved bits.
///
/// Only the low 16 bits of a sequence encode its duration. Accepting arbitrary
/// `u32` values as block counts can truncate the delay, select time-based locks,
/// or disable CSV entirely. Validate configuration before building scripts.
///
/// Store it in a contract's params to carry an already-validated delay:
///
/// ```
/// use mattrs::BlockDelay;
/// #[derive(Debug, Clone)]
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
        crate::script::older(self.blocks())
    }

    /// Whether a transaction input's sequence satisfies this block constraint.
    /// Transaction version and confirmation age must be checked separately.
    pub fn is_satisfied_by(self, sequence: Sequence) -> bool {
        let value = sequence.to_consensus_u32();
        value & ((1 << 31) | (1 << 22)) == 0 && (value & 0xffff) >= self.blocks()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(delay.script(), crate::script::older(blocks));
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
