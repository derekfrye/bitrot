//! Checked source and recovery shard geometry.

use std::fmt;

pub const MIN_CHUNK_SIZE: u32 = 64 * 1024;
pub const DEFAULT_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024;

/// Number of elements in the selected Leopard GF(2^16) field.
pub const LEOPARD_FIELD_ORDER: u64 = 65_536;

/// A format-valid data chunk size.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChunkSize(u32);

impl ChunkSize {
    /// Validates an experimental v1 chunk size.
    ///
    /// # Errors
    ///
    /// Returns an error unless `bytes` is a power of two from 64 KiB through
    /// 64 MiB, inclusive.
    pub fn new(bytes: u64) -> Result<Self, ChunkSizeError> {
        if bytes < u64::from(MIN_CHUNK_SIZE) {
            return Err(ChunkSizeError::TooSmall(bytes));
        }
        if bytes > u64::from(MAX_CHUNK_SIZE) {
            return Err(ChunkSizeError::TooLarge(bytes));
        }
        if !bytes.is_power_of_two() {
            return Err(ChunkSizeError::NotPowerOfTwo(bytes));
        }
        let bytes = u32::try_from(bytes).map_err(|_| ChunkSizeError::TooLarge(bytes))?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.0
    }
}

impl Default for ChunkSize {
    fn default() -> Self {
        Self(DEFAULT_CHUNK_SIZE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkSizeError {
    TooSmall(u64),
    TooLarge(u64),
    NotPowerOfTwo(u64),
}

impl fmt::Display for ChunkSizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall(value) => write!(
                formatter,
                "chunk size {value} is below the minimum of {MIN_CHUNK_SIZE} bytes"
            ),
            Self::TooLarge(value) => write!(
                formatter,
                "chunk size {value} exceeds the maximum of {MAX_CHUNK_SIZE} bytes"
            ),
            Self::NotPowerOfTwo(value) => {
                write!(formatter, "chunk size {value} is not a power of two")
            }
        }
    }
}

impl std::error::Error for ChunkSizeError {}

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

#[derive(Clone, Copy)]
struct SourceLayout {
    data_chunks: u64,
    final_data_chunk_len: u32,
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
        let layout = source_layout(source_len, chunk_size)?;
        let recovery_chunks = redundancy.recovery_chunks(layout.data_chunks)?;

        let data_chunks = u32::try_from(layout.data_chunks).map_err(|_| {
            GeometryError::UnsupportedShardCounts {
                data_chunks: layout.data_chunks,
                recovery_chunks,
            }
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
            layout.final_data_chunk_len,
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
        let layout = source_layout(source_len, chunk_size)?;
        if u64::from(data_chunks) != layout.data_chunks {
            return Err(GeometryError::DataChunkCountMismatch {
                actual: data_chunks,
                expected: layout.data_chunks,
            });
        }
        if final_data_chunk_len != layout.final_data_chunk_len {
            return Err(GeometryError::FinalDataChunkLengthMismatch {
                actual: final_data_chunk_len,
                expected: layout.final_data_chunk_len,
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

    /// Returns the number of data chunks that occupy a complete chunk-sized
    /// rolling window.
    #[must_use]
    pub const fn full_data_chunks(self) -> u64 {
        let short_final = self.final_data_chunk_len < self.chunk_size.bytes();
        self.data_chunks.saturating_sub(short_final as u32) as u64
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

fn source_layout(source_len: u64, chunk_size: ChunkSize) -> Result<SourceLayout, GeometryError> {
    if source_len == 0 {
        return Err(GeometryError::EmptySource);
    }
    let chunk_bytes = u64::from(chunk_size.bytes());
    let data_chunks = ((source_len - 1) / chunk_bytes) + 1;
    let remainder = source_len % chunk_bytes;
    let final_data_chunk_len = if remainder == 0 {
        chunk_size.bytes()
    } else {
        u32::try_from(remainder).map_err(|_| GeometryError::LengthOverflow)?
    };
    Ok(SourceLayout {
        data_chunks,
        final_data_chunk_len,
    })
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
    fn chunks(bytes: u32) -> ChunkSize {
        ChunkSize::new(u64::from(bytes)).unwrap()
    }

    fn fifteen_percent() -> Redundancy {
        Redundancy::new(15, 100).unwrap()
    }

    #[test]
    fn validates_experimental_chunk_size_bounds() {
        assert_eq!(ChunkSize::default().bytes(), DEFAULT_CHUNK_SIZE);
        assert!(ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).is_ok());
        assert!(ChunkSize::new(u64::from(MAX_CHUNK_SIZE)).is_ok());
        assert!(matches!(
            ChunkSize::new(u64::from(MIN_CHUNK_SIZE) - 1),
            Err(ChunkSizeError::TooSmall(_))
        ));
        assert!(matches!(
            ChunkSize::new(u64::from(MAX_CHUNK_SIZE) + 1),
            Err(ChunkSizeError::TooLarge(_))
        ));
        assert!(matches!(
            ChunkSize::new(u64::from(MIN_CHUNK_SIZE) + 1),
            Err(ChunkSizeError::NotPowerOfTwo(_))
        ));
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
        assert_eq!(partial.full_data_chunks(), 1);
        assert_eq!(partial.padded_source_len(), u64::from(MIN_CHUNK_SIZE) * 2);

        let exact =
            Geometry::new(u64::from(MIN_CHUNK_SIZE) * 2, chunk_size, fifteen_percent()).unwrap();
        assert_eq!(exact.data_chunks, 2);
        assert_eq!(exact.final_data_chunk_len, MIN_CHUNK_SIZE);
        assert_eq!(exact.full_data_chunks(), 2);
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
