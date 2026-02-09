//! This module contains the [ExtendedHintType], which adds an EigenDACommitment case to kona's [HintType] enum.

use alloc::vec::Vec;
use alloy_primitives::Bytes;
use kona_proof::HintType;

/// The [ExtendedHintType] extends the [HintType] enum and is used to specify the type of hint that was received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExtendedHintType {
    Original(HintType),
    EigenDACert,
}

impl From<ExtendedHintType> for u8 {
    fn from(v: ExtendedHintType) -> Self {
        match v {
            ExtendedHintType::Original(h) => h.into(),
            ExtendedHintType::EigenDACert => 0xda,
        }
    }
}

impl TryFrom<u8> for ExtendedHintType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xda => Ok(ExtendedHintType::EigenDACert),
            other => {
                let original = HintType::try_from(other)?;
                Ok(ExtendedHintType::Original(original))
            }
        }
    }
}

impl ExtendedHintType {
    /// Encodes the hint type as a string.
    pub fn encode_with(&self, data: &[&[u8]]) -> Bytes {
        let total_len = 1 + data.iter().map(|d| d.len()).sum::<usize>();
        let mut buffer = Vec::with_capacity(total_len);
        buffer.push(u8::from(self.clone()));
        for slice in data {
            buffer.extend_from_slice(slice);
        }
        Bytes::from(buffer)
    }
}
