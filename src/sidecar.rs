//! Whole-sidecar logical validation over physically verified records.

use crate::creator::{self, Creator};
use crate::digest_page;
use crate::manifest;
use crate::metadata::{self, Metadata};
use crate::record::Record;
use crate::record::{self, DecodeLimits};
use crate::recovery_chunk;
use crate::recovery_set::{self, RecoverySet};
use crate::rolling_page;
use crate::scan::{Event, Scanner};
use crate::superblock::{self, Superblock};
use std::fmt;
use std::io::{Read, Seek};

/// Caller-selected resource bounds for complete sidecar assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyLimits {
    pub max_records: u64,
    pub max_unknown_optional_records: u32,
    pub max_superblock_copies: u32,
    pub max_creator_copies: u32,
    pub metadata: metadata::AssemblyLimits,
    pub recovery: recovery_set::AssemblyLimits,
}

/// One logically validated version-1 sidecar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sidecar {
    pub superblock: Superblock,
    pub metadata: Metadata,
    pub creator: Creator,
    pub recovery: RecoverySet,
    unknown_optional_records: Vec<Record>,
}

/// Bounds applied while scanning and assembling a sidecar stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadLimits {
    pub record: DecodeLimits,
    pub assembly: AssemblyLimits,
    pub max_damage_events: u32,
    pub max_unrecognized_bytes: u64,
}

/// Physical damage observed while recovering records from a sidecar.
#[derive(Debug)]
pub enum Damage {
    Unrecognized { offset: u64, length: u64 },
    InvalidRecord { offset: u64, error: record::Error },
}

/// A logically valid sidecar plus any recoverable physical damage encountered.
#[derive(Debug)]
pub struct ReadResult {
    pub sidecar: Sidecar,
    pub damage: Vec<Damage>,
}

impl Sidecar {
    /// Reconciles all required records and preserves unknown optional records.
    ///
    /// Input records must already have passed physical frame and record-digest
    /// validation. Physical order is irrelevant at this layer.
    ///
    /// # Errors
    ///
    /// Returns an error when resource limits are exceeded, an unknown required
    /// type is present, required metadata cannot be reconciled, or an unknown
    /// optional record belongs to another protection set. Individual unusable
    /// recovery records remain diagnostics in [`RecoverySet`].
    pub fn assemble(records: &[Record], limits: AssemblyLimits) -> Result<Self, Error> {
        enforce_total_limit(records, limits.max_records)?;
        reject_unknown_required(records)?;

        let metadata = Metadata::assemble(records, limits.metadata).map_err(Error::Metadata)?;
        let manifest = metadata.manifest;
        let superblock = Superblock::assemble(records, manifest, limits.max_superblock_copies)
            .map_err(Error::Superblock)?;
        let creator = Creator::assemble(
            records,
            manifest.protection_set_id(),
            limits.max_creator_copies,
        )
        .map_err(Error::Creator)?;
        let recovery = RecoverySet::assemble(
            records,
            manifest,
            metadata.recovery_digests.digests().copied(),
            limits.recovery,
        )
        .map_err(Error::Recovery)?;
        let unknown_optional_records = collect_unknown_optional(
            records,
            manifest.protection_set_id(),
            limits.max_unknown_optional_records,
        )?;

        Ok(Self {
            superblock,
            metadata,
            creator,
            recovery,
            unknown_optional_records,
        })
    }

    /// Unknown optional records retained byte-for-byte at the logical level.
    #[must_use]
    pub fn unknown_optional_records(&self) -> &[Record] {
        &self.unknown_optional_records
    }

    /// Scans a physical sidecar and assembles every recoverable valid record.
    ///
    /// Malformed candidates and bytes outside valid records are retained as
    /// bounded damage diagnostics. They do not prevent successful assembly
    /// when redundant required metadata remains available.
    ///
    /// # Errors
    ///
    /// Returns an error for input I/O failure, exceeded scan limits, or when
    /// the recovered valid records do not form a logically valid sidecar.
    pub fn read<R: Read + Seek>(reader: R, limits: ReadLimits) -> Result<ReadResult, ReadError> {
        let mut scanner = Scanner::new(reader, limits.record);
        let mut records = Vec::new();
        let mut damage = Vec::new();
        let mut unrecognized_bytes = 0_u64;

        while let Some(event) = scanner.next_event().map_err(ReadError::Scan)? {
            match event {
                Event::ValidRecord { record, .. } => {
                    let actual = u64::try_from(records.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1);
                    if actual > limits.assembly.max_records {
                        return Err(ReadError::RecordLimitExceeded {
                            actual,
                            maximum: limits.assembly.max_records,
                        });
                    }
                    records.push(record);
                }
                Event::Unrecognized { offset, length } => {
                    unrecognized_bytes = unrecognized_bytes.checked_add(length).ok_or(
                        ReadError::UnrecognizedByteLimitExceeded {
                            actual: u64::MAX,
                            maximum: limits.max_unrecognized_bytes,
                        },
                    )?;
                    if unrecognized_bytes > limits.max_unrecognized_bytes {
                        return Err(ReadError::UnrecognizedByteLimitExceeded {
                            actual: unrecognized_bytes,
                            maximum: limits.max_unrecognized_bytes,
                        });
                    }
                    push_damage(
                        &mut damage,
                        Damage::Unrecognized { offset, length },
                        limits.max_damage_events,
                    )?;
                }
                Event::InvalidRecord { offset, error } => push_damage(
                    &mut damage,
                    Damage::InvalidRecord { offset, error },
                    limits.max_damage_events,
                )?,
            }
        }

        let sidecar = Self::assemble(&records, limits.assembly).map_err(ReadError::Assembly)?;
        Ok(ReadResult { sidecar, damage })
    }
}

#[derive(Debug)]
pub enum ReadError {
    Scan(record::Error),
    RecordLimitExceeded { actual: u64, maximum: u64 },
    DamageEventLimitExceeded { actual: u64, maximum: u32 },
    UnrecognizedByteLimitExceeded { actual: u64, maximum: u64 },
    Assembly(Error),
}

impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scan(error) => write!(formatter, "sidecar scan failed: {error}"),
            Self::RecordLimitExceeded { actual, maximum } => write!(
                formatter,
                "scanned valid record count {actual} exceeds limit {maximum}"
            ),
            Self::DamageEventLimitExceeded { actual, maximum } => write!(
                formatter,
                "sidecar damage event count {actual} exceeds limit {maximum}"
            ),
            Self::UnrecognizedByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "unrecognized sidecar byte count {actual} exceeds limit {maximum}"
            ),
            Self::Assembly(error) => write!(formatter, "recovered sidecar is invalid: {error}"),
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scan(error) => Some(error),
            Self::Assembly(error) => Some(error),
            Self::RecordLimitExceeded { .. }
            | Self::DamageEventLimitExceeded { .. }
            | Self::UnrecognizedByteLimitExceeded { .. } => None,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    RecordLimitExceeded { actual: u64, maximum: u64 },
    UnknownRequiredRecord { record_type: u16, logical_id: u64 },
    UnknownOptionalLimitExceeded { actual: u64, maximum: u32 },
    ForeignUnknownOptionalRecord { record_type: u16, logical_id: u64 },
    Metadata(metadata::Error),
    Superblock(superblock::AssemblyError),
    Creator(creator::AssemblyError),
    Recovery(recovery_set::AssemblyError),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "sidecar record count {actual} exceeds limit {maximum}"
                )
            }
            Self::UnknownRequiredRecord {
                record_type,
                logical_id,
            } => write!(
                formatter,
                "unknown required record type {record_type} logical identifier {logical_id}"
            ),
            Self::UnknownOptionalLimitExceeded { actual, maximum } => write!(
                formatter,
                "unknown optional record count {actual} exceeds limit {maximum}"
            ),
            Self::ForeignUnknownOptionalRecord {
                record_type,
                logical_id,
            } => write!(
                formatter,
                "unknown optional record type {record_type} logical identifier {logical_id} belongs to a different protection set"
            ),
            Self::Metadata(error) => write!(formatter, "sidecar metadata is invalid: {error}"),
            Self::Superblock(error) => write!(formatter, "sidecar superblock is invalid: {error}"),
            Self::Creator(error) => write!(formatter, "sidecar creator is invalid: {error}"),
            Self::Recovery(error) => write!(formatter, "sidecar recovery set is invalid: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Metadata(error) => Some(error),
            Self::Superblock(error) => Some(error),
            Self::Creator(error) => Some(error),
            Self::Recovery(error) => Some(error),
            Self::RecordLimitExceeded { .. }
            | Self::UnknownRequiredRecord { .. }
            | Self::UnknownOptionalLimitExceeded { .. }
            | Self::ForeignUnknownOptionalRecord { .. } => None,
        }
    }
}

fn enforce_total_limit(records: &[Record], maximum: u64) -> Result<(), Error> {
    let actual = u64::try_from(records.len()).unwrap_or(u64::MAX);
    if actual > maximum {
        Err(Error::RecordLimitExceeded { actual, maximum })
    } else {
        Ok(())
    }
}

fn push_damage(damage: &mut Vec<Damage>, event: Damage, maximum: u32) -> Result<(), ReadError> {
    let actual = u64::try_from(damage.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    if actual > u64::from(maximum) {
        Err(ReadError::DamageEventLimitExceeded { actual, maximum })
    } else {
        damage.push(event);
        Ok(())
    }
}

fn reject_unknown_required(records: &[Record]) -> Result<(), Error> {
    for record in records {
        if record.is_required() && !is_known_type(record.record_type) {
            return Err(Error::UnknownRequiredRecord {
                record_type: record.record_type,
                logical_id: record.logical_id,
            });
        }
    }
    Ok(())
}

fn collect_unknown_optional(
    records: &[Record],
    protection_set_id: [u8; 32],
    maximum: u32,
) -> Result<Vec<Record>, Error> {
    let mut optional = Vec::new();
    for record in records
        .iter()
        .filter(|record| !is_known_type(record.record_type))
    {
        if record.protection_set_id != protection_set_id {
            return Err(Error::ForeignUnknownOptionalRecord {
                record_type: record.record_type,
                logical_id: record.logical_id,
            });
        }
        let actual = u64::try_from(optional.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if actual > u64::from(maximum) {
            return Err(Error::UnknownOptionalLimitExceeded { actual, maximum });
        }
        optional.push(record.clone());
    }
    Ok(optional)
}

const fn is_known_type(record_type: u16) -> bool {
    matches!(
        record_type,
        superblock::RECORD_TYPE
            | manifest::RECORD_TYPE
            | digest_page::RECORD_TYPE
            | rolling_page::RECORD_TYPE
            | recovery_chunk::RECORD_TYPE
            | creator::RECORD_TYPE
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Digest;
    use crate::digest_page::{Kind, Table};
    use crate::fingerprint::recovery_chunk_digest;
    use crate::geometry::Geometry;
    use crate::geometry::{ChunkSize, MIN_CHUNK_SIZE};
    use crate::record::FLAG_REQUIRED;
    use crate::recovery_chunk::RecoveryChunk;
    use std::io::Cursor;

    struct Fixture {
        records: Vec<Record>,
        limits: AssemblyLimits,
        protection_set_id: [u8; 32],
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
        let parity = [
            vec![0xa5; chunk_size.bytes() as usize],
            vec![0x5a; chunk_size.bytes() as usize],
        ];
        let data_table = Table::new(Kind::Data, vec![Digest::from_bytes([1; 32])]).unwrap();
        let recovery_table = Table::new(
            Kind::Recovery,
            parity
                .iter()
                .map(|bytes| recovery_chunk_digest(bytes))
                .collect(),
        )
        .unwrap();
        let rolling_table = rolling_page::Table::new(vec![9]).unwrap();
        let manifest = manifest::Manifest::new(
            geometry,
            Digest::from_bytes([3; 32]),
            &data_table,
            &recovery_table,
            &rolling_table,
        )
        .unwrap();
        let set_id = manifest.protection_set_id();
        let superblock = Superblock::new(manifest, 104, 400, 696)
            .unwrap()
            .to_record();
        let mut records = vec![superblock.clone(), manifest.to_record()];
        records.extend(
            data_table
                .pages
                .iter()
                .map(|page| page.to_record(set_id).unwrap()),
        );
        records.extend(
            recovery_table
                .pages
                .iter()
                .map(|page| page.to_record(set_id).unwrap()),
        );
        records.extend(
            rolling_table
                .pages
                .iter()
                .map(|page| page.to_record(set_id).unwrap()),
        );
        records.extend(parity.into_iter().enumerate().map(|(index, bytes)| {
            RecoveryChunk::new(manifest, u32::try_from(index).unwrap(), bytes)
                .unwrap()
                .to_record(manifest)
                .unwrap()
        }));
        records.push(
            Creator::new("bitrot", "0.1.0")
                .unwrap()
                .to_record(set_id)
                .unwrap(),
        );
        records.push(superblock);

        Fixture {
            records,
            limits: AssemblyLimits {
                max_records: 32,
                max_unknown_optional_records: 4,
                max_superblock_copies: 2,
                max_creator_copies: 2,
                metadata: metadata::AssemblyLimits::new(
                    16,
                    digest_page::AssemblyLimits::new(8, 8),
                    rolling_page::AssemblyLimits::new(8, 8),
                ),
                recovery: recovery_set::AssemblyLimits::new(8, 8),
            },
            protection_set_id: set_id,
        }
    }

    fn optional(set_id: [u8; 32]) -> Record {
        Record {
            record_type: 99,
            flags: 0,
            protection_set_id: set_id,
            logical_id: 7,
            header_extension: vec![1, 2],
            payload: vec![3, 4],
        }
    }

    fn read_limits(assembly: AssemblyLimits) -> ReadLimits {
        ReadLimits {
            record: DecodeLimits::new(4_096, u64::from(MIN_CHUNK_SIZE) + 4_096),
            assembly,
            max_damage_events: 8,
            max_unrecognized_bytes: 1_048_576,
        }
    }

    fn encode_records(records: &[Record]) -> Vec<Vec<u8>> {
        records
            .iter()
            .map(|record| {
                let mut encoded = Vec::new();
                record::write(&mut encoded, record).unwrap();
                encoded
            })
            .collect()
    }

    #[test]
    fn assembles_every_required_component_and_retains_optional_records() {
        let mut fixture = fixture();
        let optional = optional(fixture.protection_set_id);
        fixture.records.push(optional.clone());
        fixture.records.reverse();

        let actual = Sidecar::assemble(&fixture.records, fixture.limits).unwrap();
        assert_eq!(actual.recovery.available_count(), 2);
        assert!(actual.recovery.rejected().is_empty());
        assert_eq!(actual.unknown_optional_records(), &[optional]);
        assert_eq!(actual.creator.implementation(), "bitrot");
        assert!(actual.superblock.matches_manifest(actual.metadata.manifest));
    }

    #[test]
    fn rejects_unknown_required_records() {
        let mut fixture = fixture();
        let mut unknown = optional(fixture.protection_set_id);
        unknown.flags = FLAG_REQUIRED;
        fixture.records.push(unknown);

        assert!(matches!(
            Sidecar::assemble(&fixture.records, fixture.limits),
            Err(Error::UnknownRequiredRecord {
                record_type: 99,
                ..
            })
        ));
    }

    #[test]
    fn requires_an_agreed_creator() {
        let mut fixture = fixture();
        fixture
            .records
            .retain(|record| record.record_type != creator::RECORD_TYPE);
        assert!(matches!(
            Sidecar::assemble(&fixture.records, fixture.limits),
            Err(Error::Creator(creator::AssemblyError::Missing))
        ));

        fixture.records.push(
            Creator::new("one", "1")
                .unwrap()
                .to_record(fixture.protection_set_id)
                .unwrap(),
        );
        fixture.records.push(
            Creator::new("two", "1")
                .unwrap()
                .to_record(fixture.protection_set_id)
                .unwrap(),
        );
        assert!(matches!(
            Sidecar::assemble(&fixture.records, fixture.limits),
            Err(Error::Creator(creator::AssemblyError::ConflictingCopies))
        ));
    }

    #[test]
    fn keeps_sidecar_valid_when_a_recovery_record_is_unusable() {
        let mut fixture = fixture();
        let record = fixture
            .records
            .iter_mut()
            .find(|record| record.record_type == recovery_chunk::RECORD_TYPE)
            .unwrap();
        *record.payload.last_mut().unwrap() ^= 1;

        let actual = Sidecar::assemble(&fixture.records, fixture.limits).unwrap();
        assert_eq!(actual.recovery.available_count(), 1);
        assert_eq!(actual.recovery.rejected().len(), 1);
        assert_eq!(actual.recovery.missing_indexes().count(), 1);
    }

    #[test]
    fn enforces_total_and_unknown_optional_limits_and_identity() {
        let mut fixture = fixture();
        let actual_count = u64::try_from(fixture.records.len()).unwrap();
        fixture.limits.max_records = actual_count - 1;
        assert!(matches!(
            Sidecar::assemble(&fixture.records, fixture.limits),
            Err(Error::RecordLimitExceeded { .. })
        ));

        fixture.limits.max_records = 32;
        fixture.limits.max_unknown_optional_records = 0;
        fixture.records.push(optional(fixture.protection_set_id));
        assert!(matches!(
            Sidecar::assemble(&fixture.records, fixture.limits),
            Err(Error::UnknownOptionalLimitExceeded { .. })
        ));

        fixture.limits.max_unknown_optional_records = 1;
        let last = fixture.records.last_mut().unwrap();
        last.protection_set_id = [0xff; 32];
        assert!(matches!(
            Sidecar::assemble(&fixture.records, fixture.limits),
            Err(Error::ForeignUnknownOptionalRecord { .. })
        ));
    }

    #[test]
    fn reads_a_complete_physical_sidecar() {
        let fixture = fixture();
        let bytes: Vec<_> = encode_records(&fixture.records)
            .into_iter()
            .flatten()
            .collect();
        let actual = Sidecar::read(Cursor::new(bytes), read_limits(fixture.limits)).unwrap();

        assert!(actual.damage.is_empty());
        assert_eq!(actual.sidecar.recovery.available_count(), 2);
        assert_eq!(actual.sidecar.creator.implementation(), "bitrot");
    }

    #[test]
    fn reports_physical_damage_but_uses_remaining_records() {
        let fixture = fixture();
        let mut encoded = encode_records(&fixture.records);
        let recovery_position = fixture
            .records
            .iter()
            .position(|record| record.record_type == recovery_chunk::RECORD_TYPE)
            .unwrap();
        *encoded[recovery_position].last_mut().unwrap() ^= 1;
        let mut bytes = b"damage".to_vec();
        bytes.extend(encoded.into_iter().flatten());

        let actual = Sidecar::read(Cursor::new(bytes), read_limits(fixture.limits)).unwrap();
        assert!(actual.damage.len() >= 2);
        assert_eq!(actual.sidecar.recovery.available_count(), 1);
        assert_eq!(actual.sidecar.recovery.missing_indexes().count(), 1);
    }

    #[test]
    fn scan_limits_bound_records_damage_events_and_unrecognized_bytes() {
        let fixture = fixture();
        let encoded = encode_records(&fixture.records);
        let bytes: Vec<_> = encoded.clone().into_iter().flatten().collect();
        let mut limits = read_limits(fixture.limits);
        limits.assembly.max_records = 1;
        assert!(matches!(
            Sidecar::read(Cursor::new(bytes), limits),
            Err(ReadError::RecordLimitExceeded { .. })
        ));

        let bytes = [b"damage".as_slice(), encoded[0].as_slice()].concat();
        let mut limits = read_limits(fixture.limits);
        limits.max_damage_events = 0;
        assert!(matches!(
            Sidecar::read(Cursor::new(bytes.clone()), limits),
            Err(ReadError::DamageEventLimitExceeded { .. })
        ));

        limits.max_damage_events = 8;
        limits.max_unrecognized_bytes = 5;
        assert!(matches!(
            Sidecar::read(Cursor::new(bytes), limits),
            Err(ReadError::UnrecognizedByteLimitExceeded {
                actual: 6,
                maximum: 5
            })
        ));
    }
}
