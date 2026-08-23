//! Whole-sidecar logical validation over physically verified records.

mod record_policy;
mod write;

pub(crate) use write::CanonicalLayout;
pub use write::{WriteError, WriteSummary};

use crate::bounded_count;
use crate::creator::{self, Creator};
use crate::digest_page;
use crate::metadata::{self, Metadata};
use crate::record::Record;
use crate::record::{self, DecodeLimits};
use crate::recovery_chunk;
use crate::recovery_set::{self, RecoverySet};
use crate::rolling_page;
use crate::scan::{Event, Scanner};
use crate::superblock::{self, Superblock};
use record_policy::Disposition;
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

impl ReadLimits {
    /// Derives strict bounds for a canonical sidecar containing `metadata`.
    ///
    /// The resulting limits allow the two canonical copies of metadata,
    /// superblock, and creator records, plus one complete recovery set. They
    /// reject unknown optional records and physical damage.
    ///
    /// # Errors
    ///
    /// Returns an error if any derived count or payload bound is not
    /// representable.
    pub fn for_canonical_metadata(metadata: &Metadata) -> Result<Self, ReadLimitError> {
        metadata
            .validate()
            .map_err(ReadLimitError::InvalidMetadata)?;
        let geometry = metadata.manifest.geometry();
        let data_pages = u32::try_from(metadata.data_digests.pages.len())
            .map_err(|_| ReadLimitError::Overflow)?;
        let recovery_pages = u32::try_from(metadata.recovery_digests.pages.len())
            .map_err(|_| ReadLimitError::Overflow)?;
        let rolling_pages = u32::try_from(metadata.rolling_fingerprints.pages.len())
            .map_err(|_| ReadLimitError::Overflow)?;
        let page_records = u64::from(data_pages)
            .checked_add(u64::from(recovery_pages))
            .and_then(|count| count.checked_add(u64::from(rolling_pages)))
            .ok_or(ReadLimitError::Overflow)?;
        let metadata_records = page_records
            .checked_mul(2)
            .and_then(|count| count.checked_add(2))
            .ok_or(ReadLimitError::Overflow)?;
        let max_records = metadata_records
            .checked_add(u64::from(geometry.recovery_chunks))
            .and_then(|count| count.checked_add(4))
            .ok_or(ReadLimitError::Overflow)?;
        let max_digest_pages = data_pages
            .max(recovery_pages)
            .checked_mul(2)
            .ok_or(ReadLimitError::Overflow)?;
        let max_rolling_pages = rolling_pages
            .checked_mul(2)
            .ok_or(ReadLimitError::Overflow)?;
        let digest_payload = digest_page::PAYLOAD_HEADER_LEN
            .checked_add(
                digest_page::MAX_DIGESTS_PER_PAGE
                    .checked_mul(record::DIGEST_LEN)
                    .ok_or(ReadLimitError::Overflow)?,
            )
            .ok_or(ReadLimitError::Overflow)?;
        let recovery_payload = u64::from(geometry.chunk_size.bytes())
            .checked_add(recovery_chunk::PAYLOAD_HEADER_LEN as u64)
            .ok_or(ReadLimitError::Overflow)?;
        let max_payload_len = recovery_payload
            .max(u64::try_from(digest_payload).map_err(|_| ReadLimitError::Overflow)?);

        Ok(Self {
            record: DecodeLimits::new(record::BASE_HEADER_LEN, max_payload_len),
            assembly: AssemblyLimits {
                max_records,
                max_unknown_optional_records: 0,
                max_superblock_copies: 2,
                max_creator_copies: 2,
                metadata: metadata::AssemblyLimits::new(
                    metadata_records,
                    digest_page::AssemblyLimits::new(
                        u64::from(geometry.data_chunks.max(geometry.recovery_chunks)),
                        max_digest_pages,
                    ),
                    rolling_page::AssemblyLimits::new(
                        geometry.full_data_chunks(),
                        max_rolling_pages,
                    ),
                ),
                recovery: recovery_set::AssemblyLimits::new(
                    u64::from(geometry.recovery_chunks),
                    geometry.recovery_chunks,
                ),
            },
            max_damage_events: 0,
            max_unrecognized_bytes: 0,
        })
    }
}

/// Canonical sidecar read limits could not be derived.
#[derive(Debug)]
pub enum ReadLimitError {
    InvalidMetadata(metadata::ValidationError),
    Overflow,
}

impl fmt::Display for ReadLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata(error) => {
                write!(
                    formatter,
                    "cannot derive read limits from invalid metadata: {error}"
                )
            }
            Self::Overflow => formatter.write_str("canonical sidecar read limits overflow"),
        }
    }
}

impl std::error::Error for ReadLimitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidMetadata(error) => Some(error),
            Self::Overflow => None,
        }
    }
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
                    let actual = bounded_count::after_push(records.len());
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
    let actual = bounded_count::from_usize(records.len());
    if actual > maximum {
        Err(Error::RecordLimitExceeded { actual, maximum })
    } else {
        Ok(())
    }
}

fn push_damage(damage: &mut Vec<Damage>, event: Damage, maximum: u32) -> Result<(), ReadError> {
    let actual = bounded_count::after_push(damage.len());
    if actual > u64::from(maximum) {
        Err(ReadError::DamageEventLimitExceeded { actual, maximum })
    } else {
        damage.push(event);
        Ok(())
    }
}

fn reject_unknown_required(records: &[Record]) -> Result<(), Error> {
    for record in records {
        if record_policy::classify(record) == Disposition::UnknownRequired {
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
    for record in records {
        match record_policy::classify(record) {
            Disposition::Known => continue,
            Disposition::UnknownRequired => {
                return Err(Error::UnknownRequiredRecord {
                    record_type: record.record_type,
                    logical_id: record.logical_id,
                });
            }
            Disposition::UnknownOptional => {}
        }
        if record.protection_set_id != protection_set_id {
            return Err(Error::ForeignUnknownOptionalRecord {
                record_type: record.record_type,
                logical_id: record.logical_id,
            });
        }
        let actual = bounded_count::after_push(optional.len());
        if actual > u64::from(maximum) {
            return Err(Error::UnknownOptionalLimitExceeded { actual, maximum });
        }
        optional.push(record.clone());
    }
    Ok(optional)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Digest;
    use crate::geometry::MIN_CHUNK_SIZE;
    use crate::record::FLAG_REQUIRED;
    use crate::test_support;
    use crate::{digest_page, manifest, rolling_page};
    use std::io::Cursor;

    struct Fixture {
        records: Vec<Record>,
        limits: AssemblyLimits,
        protection_set_id: [u8; 32],
    }

    fn fixture() -> Fixture {
        let protection = test_support::recovery_fixture();
        let manifest = protection.metadata.manifest;
        let set_id = manifest.protection_set_id();
        let superblock = Superblock::new(manifest, 104, 400, 696)
            .unwrap()
            .to_record();
        let mut records = vec![superblock.clone()];
        records.extend(protection.metadata_records());
        records.extend(protection.recovery_records());
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

    #[test]
    fn canonical_writer_round_trips_with_exact_layout_hints() {
        let mut fixture = fixture();
        let preserved = optional(fixture.protection_set_id);
        fixture.records.push(preserved.clone());
        let sidecar = Sidecar::assemble(&fixture.records, fixture.limits).unwrap();
        let mut bytes = Vec::new();

        let summary = sidecar.write_canonical(&mut bytes).unwrap();
        assert_eq!(summary.bytes_written, bytes.len() as u64);

        let read = Sidecar::read(Cursor::new(bytes.clone()), read_limits(fixture.limits)).unwrap();
        assert!(read.damage.is_empty());
        assert_eq!(read.sidecar.unknown_optional_records(), &[preserved]);
        assert_eq!(
            read.sidecar.superblock.first_manifest_offset(),
            summary.first_manifest_offset
        );
        assert_eq!(
            read.sidecar.superblock.second_manifest_offset(),
            summary.second_manifest_offset
        );
        assert_eq!(
            read.sidecar.superblock.observed_sidecar_len(),
            summary.bytes_written
        );

        let mut scanner = Scanner::new(
            Cursor::new(bytes),
            DecodeLimits::new(4_096, u64::from(MIN_CHUNK_SIZE) + 4_096),
        );
        let mut observed = Vec::new();
        while let Some(event) = scanner.next_event().unwrap() {
            let Event::ValidRecord { offset, record, .. } = event else {
                panic!("canonical output contains physical damage");
            };
            observed.push((offset, record.record_type));
        }
        assert_eq!(
            observed.iter().map(|(_, kind)| *kind).collect::<Vec<_>>(),
            vec![1, 6, 2, 3, 3, 4, 99, 5, 5, 3, 3, 4, 2, 6, 1]
        );
        let manifest_offsets: Vec<_> = observed
            .iter()
            .filter(|(_, kind)| *kind == manifest::RECORD_TYPE)
            .map(|(offset, _)| *offset)
            .collect();
        assert_eq!(
            manifest_offsets,
            vec![
                summary.first_manifest_offset,
                summary.second_manifest_offset
            ]
        );
    }

    #[test]
    fn metadata_derived_limits_accept_the_canonical_sidecar() {
        let protection = test_support::recovery_fixture();
        let sidecar = Sidecar::from_generated_parts(
            protection.metadata,
            Creator::new("bitrot", "0.1.0").unwrap(),
            protection.recovery_chunks,
        )
        .unwrap();
        let limits = ReadLimits::for_canonical_metadata(&sidecar.metadata).unwrap();
        let mut bytes = Vec::new();
        sidecar.write_canonical(&mut bytes).unwrap();

        let read = Sidecar::read(Cursor::new(bytes), limits).unwrap();

        assert!(read.damage.is_empty());
        assert_eq!(read.sidecar.metadata, sidecar.metadata);
        assert_eq!(
            read.sidecar.recovery.available_count(),
            usize::try_from(sidecar.metadata.manifest.geometry().recovery_chunks).unwrap()
        );
    }

    #[test]
    fn canonical_writer_rejects_incomplete_recovery_before_output() {
        let mut fixture = fixture();
        fixture.records.retain(|record| {
            record.record_type != recovery_chunk::RECORD_TYPE || record.logical_id != 1
        });
        let sidecar = Sidecar::assemble(&fixture.records, fixture.limits).unwrap();
        let mut output = Vec::new();

        assert!(matches!(
            sidecar.write_canonical(&mut output),
            Err(WriteError::CompleteRecoverySet(
                recovery_set::CompleteError::MissingIndex { index: 1 }
            ))
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn canonical_writer_revalidates_public_metadata_before_output() {
        let fixture = fixture();
        let mut sidecar = Sidecar::assemble(&fixture.records, fixture.limits).unwrap();
        sidecar.metadata.data_digests.root = Digest::from_bytes([0xff; 32]);
        let mut output = Vec::new();

        assert!(matches!(
            sidecar.write_canonical(&mut output),
            Err(WriteError::Metadata(metadata::ValidationError::DataTable(
                digest_page::AssemblyError::RootMismatch { .. }
            )))
        ));
        assert!(output.is_empty());
    }
}
