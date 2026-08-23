//! Bounded authentication and indexing of available recovery records.

use crate::digest::Digest;
use crate::manifest::Manifest;
use crate::record::Record;
use crate::recovery_chunk::{self, RecoveryChunk};
use std::fmt;

/// Caller-selected resource bounds for recovery-record assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyLimits {
    pub max_records: u64,
    pub max_chunks: u32,
}

impl AssemblyLimits {
    #[must_use]
    pub const fn new(max_records: u64, max_chunks: u32) -> Self {
        Self {
            max_records,
            max_chunks,
        }
    }
}

/// One recovery record rejected during otherwise successful assembly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedRecord {
    pub logical_id: u64,
    pub reason: Rejection,
}

/// Why a physically intact recovery record could not be used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rejection {
    LogicalIdOutOfRange { actual: u64, chunk_count: u32 },
    Invalid(recovery_chunk::Error),
}

/// Authenticated recovery shards indexed by their coding index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySet {
    chunks: Vec<Option<RecoveryChunk>>,
    rejected: Vec<RejectedRecord>,
    duplicate_records: u64,
}

impl RecoverySet {
    /// Indexes a freshly generated complete recovery set without copying its
    /// parity bytes through encoded records.
    ///
    /// # Errors
    ///
    /// Returns an error unless there is exactly one correctly indexed chunk
    /// for every manifest recovery index and every digest matches.
    pub fn from_complete<I>(
        chunks: Vec<RecoveryChunk>,
        manifest: Manifest,
        expected_digests: I,
    ) -> Result<Self, CompleteError>
    where
        I: IntoIterator<Item = Digest>,
    {
        let expected_count = usize::try_from(manifest.geometry().recovery_chunks)
            .map_err(|_| CompleteError::CountUnrepresentable)?;
        if chunks.len() != expected_count {
            return Err(CompleteError::ChunkCountMismatch {
                actual: chunks.len(),
                expected: expected_count,
            });
        }
        let digests = expected_digests.into_iter().collect::<Vec<_>>();
        if digests.len() != expected_count {
            return Err(CompleteError::DigestCountMismatch {
                actual: digests.len(),
                expected: expected_count,
            });
        }

        let mut indexed = vec![None; expected_count];
        for chunk in chunks {
            let recovery_index = chunk.recovery_index();
            let index =
                usize::try_from(recovery_index).map_err(|_| CompleteError::CountUnrepresentable)?;
            let expected = digests.get(index).ok_or(CompleteError::IndexOutOfRange {
                actual: recovery_index,
                chunk_count: manifest.geometry().recovery_chunks,
            })?;
            if chunk.digest() != *expected {
                return Err(CompleteError::DigestMismatch {
                    index: recovery_index,
                });
            }
            let slot = indexed
                .get_mut(index)
                .ok_or(CompleteError::CountUnrepresentable)?;
            if slot.replace(chunk).is_some() {
                return Err(CompleteError::DuplicateIndex {
                    index: recovery_index,
                });
            }
        }

        Ok(Self {
            chunks: indexed,
            rejected: Vec::new(),
            duplicate_records: 0,
        })
    }

    /// Authenticates and indexes all type-5 records for `manifest`.
    ///
    /// Records of other types are ignored. A malformed, foreign, or
    /// digest-mismatched recovery record is reported and does not prevent a
    /// different valid copy from satisfying the same index. Identical valid
    /// copies collapse to one available chunk.
    ///
    /// # Errors
    ///
    /// Returns an error before allocating chunk slots when caller limits or
    /// the supplied recovery digest count disagree with the manifest.
    pub fn assemble<I>(
        records: &[Record],
        manifest: Manifest,
        recovery_digests: I,
        limits: AssemblyLimits,
    ) -> Result<Self, AssemblyError>
    where
        I: IntoIterator<Item = Digest>,
    {
        enforce_record_limit(records, limits.max_records)?;
        let chunk_count = manifest.geometry().recovery_chunks;
        if chunk_count > limits.max_chunks {
            return Err(AssemblyError::ChunkLimitExceeded {
                actual: chunk_count,
                maximum: limits.max_chunks,
            });
        }
        let chunk_count =
            usize::try_from(chunk_count).map_err(|_| AssemblyError::CountUnrepresentable)?;
        let mut expected_digests = recovery_digests.into_iter();
        let mut digests = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            digests.push(
                expected_digests
                    .next()
                    .ok_or(AssemblyError::DigestCountMismatch)?,
            );
        }
        if expected_digests.next().is_some() {
            return Err(AssemblyError::DigestCountMismatch);
        }

        let mut chunks = vec![None; chunk_count];
        let mut rejected = Vec::new();
        let mut duplicate_records = 0_u64;
        for record in records
            .iter()
            .filter(|record| record.record_type == recovery_chunk::RECORD_TYPE)
        {
            let Ok(index) = usize::try_from(record.logical_id) else {
                rejected.push(RejectedRecord {
                    logical_id: record.logical_id,
                    reason: Rejection::LogicalIdOutOfRange {
                        actual: record.logical_id,
                        chunk_count: manifest.geometry().recovery_chunks,
                    },
                });
                continue;
            };
            let Some(expected_digest) = digests.get(index).copied() else {
                rejected.push(RejectedRecord {
                    logical_id: record.logical_id,
                    reason: Rejection::LogicalIdOutOfRange {
                        actual: record.logical_id,
                        chunk_count: manifest.geometry().recovery_chunks,
                    },
                });
                continue;
            };
            match RecoveryChunk::from_record(record, manifest, expected_digest) {
                Ok(chunk) => {
                    let slot = chunks
                        .get_mut(index)
                        .ok_or(AssemblyError::CountUnrepresentable)?;
                    if slot.is_some() {
                        duplicate_records = duplicate_records.saturating_add(1);
                    } else {
                        *slot = Some(chunk);
                    }
                }
                Err(error) => rejected.push(RejectedRecord {
                    logical_id: record.logical_id,
                    reason: Rejection::Invalid(error),
                }),
            }
        }

        Ok(Self {
            chunks,
            rejected,
            duplicate_records,
        })
    }

    #[must_use]
    pub fn chunk(&self, recovery_index: u32) -> Option<&RecoveryChunk> {
        usize::try_from(recovery_index)
            .ok()
            .and_then(|index| self.chunks.get(index))
            .and_then(Option::as_ref)
    }

    #[must_use]
    pub fn available_count(&self) -> usize {
        self.chunks.iter().flatten().count()
    }

    pub fn available(&self) -> impl Iterator<Item = &RecoveryChunk> {
        self.chunks.iter().flatten()
    }

    pub fn missing_indexes(&self) -> impl Iterator<Item = u32> + '_ {
        self.chunks
            .iter()
            .enumerate()
            .filter(|(_, chunk)| chunk.is_none())
            .filter_map(|(index, _)| u32::try_from(index).ok())
    }

    #[must_use]
    pub fn rejected(&self) -> &[RejectedRecord] {
        &self.rejected
    }

    #[must_use]
    pub const fn duplicate_records(&self) -> u64 {
        self.duplicate_records
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompleteError {
    CountUnrepresentable,
    ChunkCountMismatch { actual: usize, expected: usize },
    DigestCountMismatch { actual: usize, expected: usize },
    IndexOutOfRange { actual: u32, chunk_count: u32 },
    DuplicateIndex { index: u32 },
    DigestMismatch { index: u32 },
}

impl fmt::Display for CompleteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountUnrepresentable => {
                formatter.write_str("recovery chunk count cannot be represented")
            }
            Self::ChunkCountMismatch { actual, expected } => write!(
                formatter,
                "generated recovery chunk count {actual} does not match expected count {expected}"
            ),
            Self::DigestCountMismatch { actual, expected } => write!(
                formatter,
                "generated recovery digest count {actual} does not match expected count {expected}"
            ),
            Self::IndexOutOfRange {
                actual,
                chunk_count,
            } => write!(
                formatter,
                "generated recovery index {actual} is outside chunk count {chunk_count}"
            ),
            Self::DuplicateIndex { index } => {
                write!(formatter, "generated recovery index {index} is duplicated")
            }
            Self::DigestMismatch { index } => {
                write!(
                    formatter,
                    "generated recovery chunk {index} has the wrong digest"
                )
            }
        }
    }
}

impl std::error::Error for CompleteError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssemblyError {
    RecordLimitExceeded { actual: u64, maximum: u64 },
    ChunkLimitExceeded { actual: u32, maximum: u32 },
    CountUnrepresentable,
    DigestCountMismatch,
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordLimitExceeded { actual, maximum } => write!(
                formatter,
                "recovery record count {actual} exceeds limit {maximum}"
            ),
            Self::ChunkLimitExceeded { actual, maximum } => write!(
                formatter,
                "recovery chunk count {actual} exceeds limit {maximum}"
            ),
            Self::CountUnrepresentable => {
                formatter.write_str("recovery chunk count cannot be represented")
            }
            Self::DigestCountMismatch => {
                formatter.write_str("recovery digest count does not match the manifest geometry")
            }
        }
    }
}

impl std::error::Error for AssemblyError {}

fn enforce_record_limit(records: &[Record], maximum: u64) -> Result<(), AssemblyError> {
    let actual = records.iter().fold(0_u64, |count, record| {
        if record.record_type == recovery_chunk::RECORD_TYPE {
            count.saturating_add(1)
        } else {
            count
        }
    });
    if actual > maximum {
        Err(AssemblyError::RecordLimitExceeded { actual, maximum })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest_page::{Kind, Table};
    use crate::fingerprint::recovery_chunk_digest;
    use crate::geometry::Geometry;
    use crate::geometry::{ChunkSize, MIN_CHUNK_SIZE};
    use crate::rolling_page;

    struct Fixture {
        manifest: Manifest,
        digests: Vec<Digest>,
        records: Vec<Record>,
    }

    fn fixture() -> Fixture {
        let chunk_size = ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap();
        let geometry = Geometry::from_stored(
            u64::from(chunk_size.bytes()),
            chunk_size,
            1,
            2,
            chunk_size.bytes(),
        )
        .unwrap();
        let bytes = [
            vec![0xa5; chunk_size.bytes() as usize],
            vec![0x5a; chunk_size.bytes() as usize],
        ];
        let digests: Vec<_> = bytes
            .iter()
            .map(|bytes| recovery_chunk_digest(bytes))
            .collect();
        let data_table = Table::new(Kind::Data, vec![Digest::from_bytes([1; 32])]).unwrap();
        let recovery_table = Table::new(Kind::Recovery, digests.clone()).unwrap();
        let rolling_table = rolling_page::Table::new(vec![7]).unwrap();
        let manifest = Manifest::new(
            geometry,
            Digest::from_bytes([3; 32]),
            &data_table,
            &recovery_table,
            &rolling_table,
        )
        .unwrap();
        let records = bytes
            .into_iter()
            .enumerate()
            .map(|(index, bytes)| {
                RecoveryChunk::new(manifest, u32::try_from(index).unwrap(), bytes)
                    .unwrap()
                    .to_record(manifest)
                    .unwrap()
            })
            .collect();
        Fixture {
            manifest,
            digests,
            records,
        }
    }

    fn limits() -> AssemblyLimits {
        AssemblyLimits::new(8, 8)
    }

    #[test]
    fn indexes_authenticated_records_and_ignores_other_types() {
        let fixture = fixture();
        let mut records = fixture.records.clone();
        records.reverse();
        records.push(Record {
            record_type: 99,
            flags: 0,
            protection_set_id: [0; 32],
            logical_id: 0,
            header_extension: Vec::new(),
            payload: Vec::new(),
        });
        let actual =
            RecoverySet::assemble(&records, fixture.manifest, fixture.digests, limits()).unwrap();

        assert_eq!(actual.available_count(), 2);
        assert!(actual.chunk(0).is_some());
        assert!(actual.chunk(1).is_some());
        assert_eq!(actual.available().count(), 2);
        assert_eq!(actual.missing_indexes().count(), 0);
        assert!(actual.rejected().is_empty());
    }

    #[test]
    fn retains_good_shards_while_reporting_bad_records_and_gaps() {
        let fixture = fixture();
        let mut bad_digest = fixture.records[1].clone();
        *bad_digest.payload.last_mut().unwrap() ^= 1;
        let mut out_of_range = fixture.records[0].clone();
        out_of_range.logical_id = 9;
        let records = vec![fixture.records[0].clone(), bad_digest, out_of_range];

        let actual =
            RecoverySet::assemble(&records, fixture.manifest, fixture.digests, limits()).unwrap();

        assert_eq!(actual.available_count(), 1);
        assert_eq!(actual.missing_indexes().collect::<Vec<_>>(), vec![1]);
        assert_eq!(actual.rejected().len(), 2);
        assert!(matches!(
            actual.rejected()[0].reason,
            Rejection::Invalid(recovery_chunk::Error::DigestMismatch)
        ));
        assert!(matches!(
            actual.rejected()[1].reason,
            Rejection::LogicalIdOutOfRange { actual: 9, .. }
        ));
    }

    #[test]
    fn collapses_valid_duplicate_records() {
        let fixture = fixture();
        let records = [
            fixture.records[0].clone(),
            fixture.records[0].clone(),
            fixture.records[1].clone(),
        ];
        let actual =
            RecoverySet::assemble(&records, fixture.manifest, fixture.digests, limits()).unwrap();

        assert_eq!(actual.available_count(), 2);
        assert_eq!(actual.duplicate_records(), 1);
    }

    #[test]
    fn enforces_limits_and_digest_count_before_chunk_slots() {
        let fixture = fixture();
        assert_eq!(
            RecoverySet::assemble(
                &fixture.records,
                fixture.manifest,
                fixture.digests.clone(),
                AssemblyLimits::new(1, 8),
            ),
            Err(AssemblyError::RecordLimitExceeded {
                actual: 2,
                maximum: 1,
            })
        );
        assert_eq!(
            RecoverySet::assemble(
                &fixture.records,
                fixture.manifest,
                fixture.digests.clone(),
                AssemblyLimits::new(8, 1),
            ),
            Err(AssemblyError::ChunkLimitExceeded {
                actual: 2,
                maximum: 1,
            })
        );
        assert_eq!(
            RecoverySet::assemble(
                &fixture.records,
                fixture.manifest,
                fixture.digests.into_iter().take(1),
                limits(),
            ),
            Err(AssemblyError::DigestCountMismatch)
        );
    }

    #[test]
    fn a_bad_copy_does_not_hide_a_good_copy() {
        let fixture = fixture();
        let mut bad = fixture.records[0].clone();
        bad.protection_set_id = [0xff; 32];
        let records = [bad, fixture.records[0].clone()];
        let actual =
            RecoverySet::assemble(&records, fixture.manifest, fixture.digests, limits()).unwrap();

        assert!(actual.chunk(0).is_some());
        assert_eq!(actual.rejected().len(), 1);
        assert!(matches!(
            actual.rejected()[0].reason,
            Rejection::Invalid(recovery_chunk::Error::ProtectionSetIdMismatch)
        ));
    }
}
