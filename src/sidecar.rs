//! Whole-sidecar logical validation over physically verified records.

use crate::bounded_count;
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
use std::io::{Read, Seek, Write};

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

/// Exact locations and length produced by canonical sidecar writing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteSummary {
    pub first_manifest_offset: u64,
    pub second_manifest_offset: u64,
    pub bytes_written: u64,
}

impl Sidecar {
    /// Constructs a sidecar from freshly generated logical components.
    ///
    /// This validates the complete recovery set and computes the exact
    /// canonical superblock hints without encoding the sidecar.
    ///
    /// # Errors
    ///
    /// Returns an error unless all components form a complete, internally
    /// consistent protection set and its canonical layout is representable.
    pub fn from_generated_parts(
        metadata: Metadata,
        creator: Creator,
        recovery_chunks: Vec<recovery_chunk::RecoveryChunk>,
    ) -> Result<Self, WriteError> {
        let manifest = metadata.manifest;
        let recovery = RecoverySet::from_complete(
            recovery_chunks,
            manifest,
            metadata.recovery_digests.digests().copied(),
        )
        .map_err(WriteError::CompleteRecoverySet)?;
        let manifest_len =
            record::encoded_len(&manifest.to_record()).map_err(WriteError::Record)?;
        let second = manifest_len;
        let observed = manifest_len
            .checked_mul(2)
            .ok_or(WriteError::LengthOverflow)?;
        let superblock =
            Superblock::new(manifest, 0, second, observed).map_err(WriteError::Superblock)?;
        let mut sidecar = Self {
            superblock,
            metadata,
            creator,
            recovery,
            unknown_optional_records: Vec::new(),
        };
        let layout = WriteLayout::new(&sidecar)?;
        sidecar.superblock =
            Superblock::from_record(&layout.superblock_record).map_err(WriteError::Superblock)?;
        Ok(sidecar)
    }

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

    /// Writes this protection set in the canonical experimental-v1 layout.
    ///
    /// Layout metadata is validated and its complete length is calculated
    /// before output begins. Recovery records are then encoded one at a time,
    /// so writing does not retain a second complete copy of the parity data.
    ///
    /// # Errors
    ///
    /// Returns an error before writing if metadata is inconsistent, a recovery
    /// shard is missing or unauthenticated, an optional record is invalid, or
    /// layout arithmetic overflows. An output I/O failure may leave the caller's
    /// destination partially written; publication must use a temporary file.
    pub fn write_canonical<W: Write>(&self, writer: &mut W) -> Result<WriteSummary, WriteError> {
        let layout = WriteLayout::new(self)?;
        let mut written = 0_u64;

        write_record(writer, &layout.superblock_record, &mut written)?;
        write_record(writer, &layout.creator_record, &mut written)?;
        write_record(writer, &layout.manifest_record, &mut written)?;
        write_records(writer, &layout.page_records, &mut written)?;
        write_records(writer, &self.unknown_optional_records, &mut written)?;
        for chunk in self.recovery.available() {
            let record = chunk
                .to_record(self.metadata.manifest)
                .map_err(WriteError::RecoveryChunk)?;
            write_record(writer, &record, &mut written)?;
        }
        write_records(writer, &layout.page_records, &mut written)?;
        write_record(writer, &layout.manifest_record, &mut written)?;
        write_record(writer, &layout.creator_record, &mut written)?;
        write_record(writer, &layout.superblock_record, &mut written)?;

        if written != layout.summary.bytes_written {
            return Err(WriteError::WrittenLengthMismatch {
                actual: written,
                expected: layout.summary.bytes_written,
            });
        }
        Ok(layout.summary)
    }
}

struct WriteLayout {
    superblock_record: Record,
    creator_record: Record,
    manifest_record: Record,
    page_records: Vec<Record>,
    summary: WriteSummary,
}

impl WriteLayout {
    fn new(sidecar: &Sidecar) -> Result<Self, WriteError> {
        validate_manifest(sidecar)?;
        validate_recovery(sidecar)?;
        validate_optional_records(sidecar)?;

        let manifest = sidecar.metadata.manifest;
        let set_id = manifest.protection_set_id();
        let creator_record = sidecar
            .creator
            .to_record(set_id)
            .map_err(WriteError::Creator)?;
        let manifest_record = manifest.to_record();
        let page_records = page_records(&sidecar.metadata, set_id)?;

        let superblock_len = u64::from(record::BASE_HEADER_LEN)
            .checked_add(superblock::PAYLOAD_LEN as u64)
            .and_then(|length| length.checked_add(record::DIGEST_LEN as u64))
            .ok_or(WriteError::LengthOverflow)?;
        let creator_len = record::encoded_len(&creator_record).map_err(WriteError::Record)?;
        let manifest_len = record::encoded_len(&manifest_record).map_err(WriteError::Record)?;
        let page_len = records_len(&page_records)?;
        let optional_len = records_len(&sidecar.unknown_optional_records)?;
        let recovery_len = recovery_records_len(sidecar)?;

        let first_manifest_offset = checked_sum(&[superblock_len, creator_len])?;
        let second_manifest_offset = checked_sum(&[
            first_manifest_offset,
            manifest_len,
            page_len,
            optional_len,
            recovery_len,
            page_len,
        ])?;
        let bytes_written = checked_sum(&[
            second_manifest_offset,
            manifest_len,
            creator_len,
            superblock_len,
        ])?;
        let superblock_record = Superblock::new(
            manifest,
            first_manifest_offset,
            second_manifest_offset,
            bytes_written,
        )
        .map_err(WriteError::Superblock)?
        .to_record();
        let actual_superblock_len =
            record::encoded_len(&superblock_record).map_err(WriteError::Record)?;
        if actual_superblock_len != superblock_len {
            return Err(WriteError::LengthOverflow);
        }

        Ok(Self {
            superblock_record,
            creator_record,
            manifest_record,
            page_records,
            summary: WriteSummary {
                first_manifest_offset,
                second_manifest_offset,
                bytes_written,
            },
        })
    }
}

#[derive(Debug)]
pub enum WriteError {
    Manifest(manifest::Error),
    ManifestMismatch,
    DataTable(digest_page::AssemblyError),
    RecoveryTable(digest_page::AssemblyError),
    RollingTable(rolling_page::AssemblyError),
    Creator(creator::Error),
    DigestPage(digest_page::Error),
    RollingPage(rolling_page::Error),
    RecoveryChunk(recovery_chunk::Error),
    CompleteRecoverySet(recovery_set::CompleteError),
    Superblock(superblock::Error),
    Record(record::Error),
    MissingRecoveryChunk(u32),
    RecoveryDigestMismatch(u32),
    InvalidOptionalRecord { record_type: u16, logical_id: u64 },
    LengthOverflow,
    WrittenLengthMismatch { actual: u64, expected: u64 },
}

impl fmt::Display for WriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => write!(formatter, "sidecar manifest is invalid: {error}"),
            Self::ManifestMismatch => {
                formatter.write_str("sidecar manifest does not match its assembled tables")
            }
            Self::DataTable(error) => write!(formatter, "data digest table is invalid: {error}"),
            Self::RecoveryTable(error) => {
                write!(formatter, "recovery digest table is invalid: {error}")
            }
            Self::RollingTable(error) => {
                write!(formatter, "rolling fingerprint table is invalid: {error}")
            }
            Self::Creator(error) => write!(formatter, "creator record is invalid: {error}"),
            Self::DigestPage(error) => write!(formatter, "digest page is invalid: {error}"),
            Self::RollingPage(error) => write!(formatter, "rolling page is invalid: {error}"),
            Self::RecoveryChunk(error) => write!(formatter, "recovery chunk is invalid: {error}"),
            Self::CompleteRecoverySet(error) => {
                write!(formatter, "generated recovery set is invalid: {error}")
            }
            Self::Superblock(error) => write!(formatter, "superblock layout is invalid: {error}"),
            Self::Record(error) => write!(formatter, "record writing failed: {error}"),
            Self::MissingRecoveryChunk(index) => {
                write!(formatter, "recovery chunk {index} is missing")
            }
            Self::RecoveryDigestMismatch(index) => {
                write!(
                    formatter,
                    "recovery chunk {index} does not match its digest table"
                )
            }
            Self::InvalidOptionalRecord {
                record_type,
                logical_id,
            } => write!(
                formatter,
                "record type {record_type} logical identifier {logical_id} is not a preservable optional record"
            ),
            Self::LengthOverflow => formatter.write_str("canonical sidecar layout overflows u64"),
            Self::WrittenLengthMismatch { actual, expected } => write!(
                formatter,
                "writer produced {actual} bytes instead of planned length {expected}"
            ),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            Self::DataTable(error) | Self::RecoveryTable(error) => Some(error),
            Self::RollingTable(error) => Some(error),
            Self::Creator(error) => Some(error),
            Self::DigestPage(error) => Some(error),
            Self::RollingPage(error) => Some(error),
            Self::RecoveryChunk(error) => Some(error),
            Self::CompleteRecoverySet(error) => Some(error),
            Self::Superblock(error) => Some(error),
            Self::Record(error) => Some(error),
            Self::ManifestMismatch
            | Self::MissingRecoveryChunk(_)
            | Self::RecoveryDigestMismatch(_)
            | Self::InvalidOptionalRecord { .. }
            | Self::LengthOverflow
            | Self::WrittenLengthMismatch { .. } => None,
        }
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

fn validate_manifest(sidecar: &Sidecar) -> Result<(), WriteError> {
    let manifest = sidecar.metadata.manifest;
    let data = &sidecar.metadata.data_digests;
    let recovery = &sidecar.metadata.recovery_digests;
    let rolling = &sidecar.metadata.rolling_fingerprints;
    let digest_page_limit = u32::try_from(data.pages.len().max(recovery.pages.len()))
        .map_err(|_| WriteError::LengthOverflow)?;
    let data = digest_page::Table::assemble(
        digest_page::Kind::Data,
        data.digest_count,
        data.root,
        data.pages.clone(),
        digest_page::AssemblyLimits::new(data.digest_count, digest_page_limit),
    )
    .map_err(WriteError::DataTable)?;
    let recovery = digest_page::Table::assemble(
        digest_page::Kind::Recovery,
        recovery.digest_count,
        recovery.root,
        recovery.pages.clone(),
        digest_page::AssemblyLimits::new(recovery.digest_count, digest_page_limit),
    )
    .map_err(WriteError::RecoveryTable)?;
    let rolling_page_limit =
        u32::try_from(rolling.pages.len()).map_err(|_| WriteError::LengthOverflow)?;
    let rolling = rolling_page::Table::assemble(
        rolling.value_count,
        rolling.root,
        rolling.pages.clone(),
        rolling_page::AssemblyLimits::new(rolling.value_count, rolling_page_limit),
    )
    .map_err(WriteError::RollingTable)?;
    let rebuilt = manifest::Manifest::new(
        manifest.geometry(),
        manifest.source_digest(),
        &data,
        &recovery,
        &rolling,
    )
    .map_err(WriteError::Manifest)?;
    if rebuilt == manifest {
        Ok(())
    } else {
        Err(WriteError::ManifestMismatch)
    }
}

fn validate_recovery(sidecar: &Sidecar) -> Result<(), WriteError> {
    for (index, expected_digest) in sidecar
        .metadata
        .recovery_digests
        .digests()
        .copied()
        .enumerate()
    {
        let index = u32::try_from(index).map_err(|_| WriteError::LengthOverflow)?;
        let chunk = sidecar
            .recovery
            .chunk(index)
            .ok_or(WriteError::MissingRecoveryChunk(index))?;
        if chunk.digest() != expected_digest {
            return Err(WriteError::RecoveryDigestMismatch(index));
        }
    }
    Ok(())
}

fn validate_optional_records(sidecar: &Sidecar) -> Result<(), WriteError> {
    let set_id = sidecar.metadata.manifest.protection_set_id();
    for record in &sidecar.unknown_optional_records {
        if record.is_required()
            || is_known_type(record.record_type)
            || record.protection_set_id != set_id
        {
            return Err(WriteError::InvalidOptionalRecord {
                record_type: record.record_type,
                logical_id: record.logical_id,
            });
        }
        record::encoded_len(record).map_err(WriteError::Record)?;
    }
    Ok(())
}

fn page_records(metadata: &Metadata, set_id: [u8; 32]) -> Result<Vec<Record>, WriteError> {
    let page_count = metadata
        .data_digests
        .pages
        .len()
        .checked_add(metadata.recovery_digests.pages.len())
        .and_then(|count| count.checked_add(metadata.rolling_fingerprints.pages.len()))
        .ok_or(WriteError::LengthOverflow)?;
    let mut records = Vec::with_capacity(page_count);
    for page in &metadata.data_digests.pages {
        records.push(page.to_record(set_id).map_err(WriteError::DigestPage)?);
    }
    for page in &metadata.recovery_digests.pages {
        records.push(page.to_record(set_id).map_err(WriteError::DigestPage)?);
    }
    for page in &metadata.rolling_fingerprints.pages {
        records.push(page.to_record(set_id).map_err(WriteError::RollingPage)?);
    }
    Ok(records)
}

fn recovery_records_len(sidecar: &Sidecar) -> Result<u64, WriteError> {
    let per_record = u64::from(record::BASE_HEADER_LEN)
        .checked_add(recovery_chunk::PAYLOAD_HEADER_LEN as u64)
        .and_then(|length| {
            length.checked_add(u64::from(
                sidecar.metadata.manifest.geometry().chunk_size.bytes(),
            ))
        })
        .and_then(|length| length.checked_add(record::DIGEST_LEN as u64))
        .ok_or(WriteError::LengthOverflow)?;
    let count = u64::from(sidecar.metadata.manifest.geometry().recovery_chunks);
    per_record
        .checked_mul(count)
        .ok_or(WriteError::LengthOverflow)
}

fn records_len(records: &[Record]) -> Result<u64, WriteError> {
    records.iter().try_fold(0_u64, |total, record| {
        let length = record::encoded_len(record).map_err(WriteError::Record)?;
        total.checked_add(length).ok_or(WriteError::LengthOverflow)
    })
}

fn checked_sum(parts: &[u64]) -> Result<u64, WriteError> {
    parts.iter().try_fold(0_u64, |total, part| {
        total.checked_add(*part).ok_or(WriteError::LengthOverflow)
    })
}

fn write_records<W: Write>(
    writer: &mut W,
    records: &[Record],
    written: &mut u64,
) -> Result<(), WriteError> {
    for record in records {
        write_record(writer, record, written)?;
    }
    Ok(())
}

fn write_record<W: Write>(
    writer: &mut W,
    record: &Record,
    written: &mut u64,
) -> Result<(), WriteError> {
    let length = record::write(writer, record).map_err(WriteError::Record)?;
    *written = written
        .checked_add(length)
        .ok_or(WriteError::LengthOverflow)?;
    Ok(())
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
        let actual = bounded_count::after_push(optional.len());
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
    use crate::geometry::MIN_CHUNK_SIZE;
    use crate::record::FLAG_REQUIRED;
    use crate::test_support;
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
    fn canonical_writer_rejects_incomplete_recovery_before_output() {
        let mut fixture = fixture();
        fixture.records.retain(|record| {
            record.record_type != recovery_chunk::RECORD_TYPE || record.logical_id != 1
        });
        let sidecar = Sidecar::assemble(&fixture.records, fixture.limits).unwrap();
        let mut output = Vec::new();

        assert!(matches!(
            sidecar.write_canonical(&mut output),
            Err(WriteError::MissingRecoveryChunk(1))
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
            Err(WriteError::DataTable(
                digest_page::AssemblyError::RootMismatch { .. }
            ))
        ));
        assert!(output.is_empty());
    }
}
