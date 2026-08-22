//! Checked source and recovery shard geometry.

use crate::fingerprint::ChunkSize;
use std::fmt;

/// Number of elements in the selected Leopard GF(2^16) field.
pub const LEOPARD_FIELD_ORDER: u64 = 65_536;

/// An exact positive recovery-to-data ratio.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Redundancy {
    numerator: u64,
    denominator: u64,
}

impl Redundancy {
    /// Creates a reduced positive ratio.
    ///
    /// For example, `Redundancy::new(15, 100)` represents 15% and is stored as
    /// `3 / 20`.
    ///
    /// # Errors
    ///
    /// Returns an error if either value is zero.
    pub const fn new(numerator: u64, denominator: u64) -> Result<Self, RedundancyError> {
        if numerator == 0 {
            return Err(RedundancyError::ZeroNumerator);
        }
        if denominator == 0 {
            return Err(RedundancyError::ZeroDenominator);
        }
        let divisor = gcd(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    #[must_use]
    pub const fn numerator(self) -> u64 {
        self.numerator
    }

    #[must_use]
    pub const fn denominator(self) -> u64 {
        self.denominator
    }

    /// Calculates `ceil(data_chunks * numerator / denominator)` exactly.
    ///
    /// # Errors
    ///
    /// Returns an error if the result cannot be represented as `u64`.
    pub fn recovery_chunks(self, data_chunks: u64) -> Result<u64, GeometryError> {
        if data_chunks == 0 {
            return Ok(0);
        }
        let product = u128::from(data_chunks) * u128::from(self.numerator);
        let denominator = u128::from(self.denominator);
        let quotient = product / denominator;
        let rounded = quotient + u128::from(product % denominator != 0);
        u64::try_from(rounded).map_err(|_| GeometryError::RecoveryCountOverflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedundancyError {
    ZeroNumerator,
    ZeroDenominator,
}

impl fmt::Display for RedundancyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroNumerator => formatter.write_str("redundancy numerator must be positive"),
            Self::ZeroDenominator => formatter.write_str("redundancy denominator must be positive"),
        }
    }
}

impl std::error::Error for RedundancyError {}

/// Geometry for one global Leopard coding group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub source_len: u64,
    pub chunk_size: ChunkSize,
    pub data_chunks: u32,
    pub recovery_chunks: u32,
    pub final_data_chunk_len: u32,
}

impl Geometry {
    /// Computes a single coding group for a nonempty source.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty source, an unrepresentable recovery count,
    /// or a data/recovery combination unsupported by the experimental Leopard
    /// GF(2^16) backend.
    pub fn new(
        source_len: u64,
        chunk_size: ChunkSize,
        redundancy: Redundancy,
    ) -> Result<Self, GeometryError> {
        if source_len == 0 {
            return Err(GeometryError::EmptySource);
        }
        let chunk_bytes = u64::from(chunk_size.bytes());
        let data_chunks = ((source_len - 1) / chunk_bytes) + 1;
        let recovery_chunks = redundancy.recovery_chunks(data_chunks)?;
        let remainder = source_len % chunk_bytes;
        let final_data_chunk_len = if remainder == 0 {
            chunk_size.bytes()
        } else {
            u32::try_from(remainder).map_err(|_| GeometryError::LengthOverflow)?
        };

        let data_chunks =
            u32::try_from(data_chunks).map_err(|_| GeometryError::UnsupportedShardCounts {
                data_chunks,
                recovery_chunks,
            })?;
        let recovery_chunks =
            u32::try_from(recovery_chunks).map_err(|_| GeometryError::UnsupportedShardCounts {
                data_chunks: u64::from(data_chunks),
                recovery_chunks,
            })?;
        Self::from_stored(
            source_len,
            chunk_size,
            data_chunks,
            recovery_chunks,
            final_data_chunk_len,
        )
    }

    /// Validates geometry decoded from a manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored counts or final chunk length disagree
    /// with the source length and chunk size, or the backend cannot support
    /// the shard counts.
    pub fn from_stored(
        source_len: u64,
        chunk_size: ChunkSize,
        data_chunks: u32,
        recovery_chunks: u32,
        final_data_chunk_len: u32,
    ) -> Result<Self, GeometryError> {
        if source_len == 0 {
            return Err(GeometryError::EmptySource);
        }
        let chunk_bytes = u64::from(chunk_size.bytes());
        let expected_data_chunks = ((source_len - 1) / chunk_bytes) + 1;
        if u64::from(data_chunks) != expected_data_chunks {
            return Err(GeometryError::DataChunkCountMismatch {
                actual: data_chunks,
                expected: expected_data_chunks,
            });
        }
        let remainder = source_len % chunk_bytes;
        let expected_final_len = if remainder == 0 {
            chunk_size.bytes()
        } else {
            u32::try_from(remainder).map_err(|_| GeometryError::LengthOverflow)?
        };
        if final_data_chunk_len != expected_final_len {
            return Err(GeometryError::FinalDataChunkLengthMismatch {
                actual: final_data_chunk_len,
                expected: expected_final_len,
            });
        }
        if !leopard_supports(u64::from(data_chunks), u64::from(recovery_chunks)) {
            return Err(GeometryError::UnsupportedShardCounts {
                data_chunks: u64::from(data_chunks),
                recovery_chunks: u64::from(recovery_chunks),
            });
        }

        Ok(Self {
            source_len,
            chunk_size,
            data_chunks,
            recovery_chunks,
            final_data_chunk_len,
        })
    }

    #[must_use]
    pub const fn total_shards(self) -> u64 {
        self.data_chunks as u64 + self.recovery_chunks as u64
    }

    #[must_use]
    pub const fn padded_source_len(self) -> u64 {
        self.data_chunks as u64 * self.chunk_size.bytes() as u64
    }

    #[must_use]
    pub const fn recovery_storage_len(self) -> u64 {
        self.recovery_chunks as u64 * self.chunk_size.bytes() as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeometryError {
    EmptySource,
    RecoveryCountOverflow,
    UnsupportedShardCounts {
        data_chunks: u64,
        recovery_chunks: u64,
    },
    DataChunkCountMismatch {
        actual: u32,
        expected: u64,
    },
    FinalDataChunkLengthMismatch {
        actual: u32,
        expected: u32,
    },
    LengthOverflow,
}

impl fmt::Display for GeometryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySource => formatter.write_str("cannot parity-protect an empty source"),
            Self::RecoveryCountOverflow => {
                formatter.write_str("calculated recovery count exceeds u64")
            }
            Self::UnsupportedShardCounts {
                data_chunks,
                recovery_chunks,
            } => write!(
                formatter,
                "Leopard backend does not support {data_chunks} data and {recovery_chunks} recovery shards"
            ),
            Self::DataChunkCountMismatch { actual, expected } => write!(
                formatter,
                "stored data chunk count {actual} does not match expected count {expected}"
            ),
            Self::FinalDataChunkLengthMismatch { actual, expected } => write!(
                formatter,
                "stored final data chunk length {actual} does not match expected length {expected}"
            ),
            Self::LengthOverflow => formatter.write_str("coding geometry length overflows"),
        }
    }
}

impl std::error::Error for GeometryError {}

/// Returns whether one group has geometry supported by the selected Leopard
/// GF(2^16) construction.
#[must_use]
pub fn leopard_supports(data_chunks: u64, recovery_chunks: u64) -> bool {
    if data_chunks == 0
        || recovery_chunks == 0
        || data_chunks >= LEOPARD_FIELD_ORDER
        || recovery_chunks >= LEOPARD_FIELD_ORDER
    {
        return false;
    }

    let data_power = data_chunks.next_power_of_two();
    let recovery_power = recovery_chunks.next_power_of_two();
    data_power.min(recovery_power) + data_chunks.max(recovery_chunks) <= LEOPARD_FIELD_ORDER
}

const fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{DEFAULT_CHUNK_SIZE, MIN_CHUNK_SIZE};

    fn chunks(bytes: u32) -> ChunkSize {
        ChunkSize::new(u64::from(bytes)).unwrap()
    }

    fn fifteen_percent() -> Redundancy {
        Redundancy::new(15, 100).unwrap()
    }

    #[test]
    fn redundancy_is_positive_and_canonical() {
        let redundancy = fifteen_percent();
        assert_eq!(redundancy.numerator(), 3);
        assert_eq!(redundancy.denominator(), 20);
        assert_eq!(
            Redundancy::new(0, 1).unwrap_err(),
            RedundancyError::ZeroNumerator
        );
        assert_eq!(
            Redundancy::new(1, 0).unwrap_err(),
            RedundancyError::ZeroDenominator
        );
    }

    #[test]
    fn recovery_count_uses_exact_ceiling_arithmetic() {
        assert_eq!(fifteen_percent().recovery_chunks(1_000).unwrap(), 150);
        assert_eq!(fifteen_percent().recovery_chunks(1).unwrap(), 1);
        assert_eq!(
            Redundancy::new(1, 3).unwrap().recovery_chunks(7).unwrap(),
            3
        );
        assert_eq!(
            Redundancy::new(3, 2).unwrap().recovery_chunks(2).unwrap(),
            3
        );
        assert_eq!(fifteen_percent().recovery_chunks(0).unwrap(), 0);
    }

    #[test]
    fn recovery_count_detects_result_overflow() {
        assert_eq!(
            Redundancy::new(u64::MAX, 1)
                .unwrap()
                .recovery_chunks(2)
                .unwrap_err(),
            GeometryError::RecoveryCountOverflow
        );
    }

    #[test]
    fn geometry_handles_partial_and_exact_final_chunks() {
        let chunk_size = chunks(MIN_CHUNK_SIZE);
        let partial =
            Geometry::new(u64::from(MIN_CHUNK_SIZE) + 7, chunk_size, fifteen_percent()).unwrap();
        assert_eq!(partial.data_chunks, 2);
        assert_eq!(partial.recovery_chunks, 1);
        assert_eq!(partial.final_data_chunk_len, 7);
        assert_eq!(partial.padded_source_len(), u64::from(MIN_CHUNK_SIZE) * 2);

        let exact =
            Geometry::new(u64::from(MIN_CHUNK_SIZE) * 2, chunk_size, fifteen_percent()).unwrap();
        assert_eq!(exact.data_chunks, 2);
        assert_eq!(exact.final_data_chunk_len, MIN_CHUNK_SIZE);
    }

    #[test]
    fn geometry_reports_storage_and_total_shards() {
        let geometry = Geometry::new(
            u64::from(DEFAULT_CHUNK_SIZE) * 1_000,
            chunks(DEFAULT_CHUNK_SIZE),
            fifteen_percent(),
        )
        .unwrap();

        assert_eq!(geometry.data_chunks, 1_000);
        assert_eq!(geometry.recovery_chunks, 150);
        assert_eq!(geometry.total_shards(), 1_150);
        assert_eq!(
            geometry.recovery_storage_len(),
            u64::from(DEFAULT_CHUNK_SIZE) * 150
        );
    }

    #[test]
    fn empty_sources_are_rejected() {
        assert_eq!(
            Geometry::new(0, chunks(DEFAULT_CHUNK_SIZE), fifteen_percent()).unwrap_err(),
            GeometryError::EmptySource
        );
    }

    #[test]
    fn leopard_support_matches_published_boundary_examples() {
        assert!(leopard_supports(60_000, 4_000));
        assert!(!leopard_supports(60_000, 5_000));
        assert!(leopard_supports(32_768, 32_768));
        assert!(leopard_supports(1, 65_535));
        assert!(leopard_supports(65_535, 1));
        assert!(!leopard_supports(0, 1));
        assert!(!leopard_supports(1, 0));
        assert!(!leopard_supports(65_536, 1));
        assert!(!leopard_supports(1, 65_536));
    }

    #[test]
    fn unsupported_global_geometry_is_explicit() {
        let source_len = u64::from(DEFAULT_CHUNK_SIZE) * 60_000;
        assert!(matches!(
            Geometry::new(
                source_len,
                chunks(DEFAULT_CHUNK_SIZE),
                Redundancy::new(1, 12).unwrap(),
            ),
            Err(GeometryError::UnsupportedShardCounts {
                data_chunks: 60_000,
                recovery_chunks: 5_000
            })
        ));
    }

    #[test]
    fn stored_geometry_must_be_canonical() {
        let chunk_size = chunks(MIN_CHUNK_SIZE);
        let source_len = u64::from(MIN_CHUNK_SIZE) + 7;
        assert!(matches!(
            Geometry::from_stored(source_len, chunk_size, 3, 1, 7),
            Err(GeometryError::DataChunkCountMismatch { .. })
        ));
        assert!(matches!(
            Geometry::from_stored(source_len, chunk_size, 2, 1, 8),
            Err(GeometryError::FinalDataChunkLengthMismatch { .. })
        ));
        assert_eq!(
            Geometry::from_stored(source_len, chunk_size, 2, 1, 7).unwrap(),
            Geometry::new(source_len, chunk_size, fifteen_percent()).unwrap()
        );
    }
}
