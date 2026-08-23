//! Canonical sidecar layout calculation and streaming output.

use super::Sidecar;
use super::record_policy::{self, Disposition};
use crate::creator::{self, Creator};
use crate::metadata::{self, Metadata};
use crate::record::{self, Record};
use crate::recovery_chunk;
use crate::recovery_set::{self, RecoverySet};
use crate::superblock::{self, Superblock};
use std::fmt;
use std::io::Write;

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
        let layout = CanonicalLayout::new(&metadata, &creator, &[])?;
        let superblock =
            Superblock::from_record(layout.superblock_record()).map_err(WriteError::Superblock)?;
        Ok(Self {
            superblock,
            metadata,
            creator,
            recovery,
            unknown_optional_records: Vec::new(),
        })
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
        self.recovery
            .validate_complete(
                self.metadata.manifest,
                self.metadata.recovery_digests.digests().copied(),
            )
            .map_err(WriteError::CompleteRecoverySet)?;
        let layout = CanonicalLayout::new(
            &self.metadata,
            &self.creator,
            &self.unknown_optional_records,
        )?;
        let mut written = 0_u64;

        layout.write_prefix(writer, &mut written)?;
        for chunk in self.recovery.available() {
            let record = chunk
                .to_record(self.metadata.manifest)
                .map_err(WriteError::RecoveryChunk)?;
            write_record(writer, &record, &mut written)?;
        }
        layout.write_suffix(writer, &mut written)?;

        if written != layout.summary.bytes_written {
            return Err(WriteError::WrittenLengthMismatch {
                actual: written,
                expected: layout.summary.bytes_written,
            });
        }
        Ok(layout.summary)
    }
}

pub(crate) struct CanonicalLayout<'records> {
    manifest: crate::manifest::Manifest,
    superblock_record: Record,
    creator_record: Record,
    manifest_record: Record,
    page_records: Vec<Record>,
    optional_records: &'records [Record],
    summary: WriteSummary,
}

impl<'records> CanonicalLayout<'records> {
    pub(crate) fn new(
        metadata: &Metadata,
        creator: &Creator,
        optional_records: &'records [Record],
    ) -> Result<Self, WriteError> {
        metadata.validate().map_err(WriteError::Metadata)?;

        let manifest = metadata.manifest;
        let set_id = manifest.protection_set_id();
        validate_optional_records(optional_records, set_id)?;
        let creator_record = creator.to_record(set_id).map_err(WriteError::Creator)?;
        let manifest_record = manifest.to_record();
        let page_records = metadata
            .to_page_records()
            .map_err(WriteError::MetadataRecords)?;

        let superblock_len = superblock::ENCODED_RECORD_LEN;
        let creator_len = record::encoded_len(&creator_record).map_err(WriteError::Record)?;
        let manifest_len = record::encoded_len(&manifest_record).map_err(WriteError::Record)?;
        let page_len = records_len(&page_records)?;
        let optional_len = records_len(optional_records)?;
        let recovery_len = recovery_records_len(manifest)?;

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
            manifest,
            superblock_record,
            creator_record,
            manifest_record,
            page_records,
            optional_records,
            summary: WriteSummary {
                first_manifest_offset,
                second_manifest_offset,
                bytes_written,
            },
        })
    }

    pub(crate) const fn summary(&self) -> WriteSummary {
        self.summary
    }

    pub(crate) const fn manifest(&self) -> crate::manifest::Manifest {
        self.manifest
    }

    pub(crate) const fn superblock_record(&self) -> &Record {
        &self.superblock_record
    }

    pub(crate) const fn creator_record(&self) -> &Record {
        &self.creator_record
    }

    pub(crate) const fn manifest_record(&self) -> &Record {
        &self.manifest_record
    }

    pub(crate) fn page_records(&self) -> &[Record] {
        &self.page_records
    }

    pub(crate) fn write_prefix<W: Write>(
        &self,
        writer: &mut W,
        written: &mut u64,
    ) -> Result<(), WriteError> {
        write_record(writer, &self.superblock_record, written)?;
        write_record(writer, &self.creator_record, written)?;
        write_record(writer, &self.manifest_record, written)?;
        write_records(writer, &self.page_records, written)?;
        write_records(writer, self.optional_records, written)
    }

    pub(crate) fn write_suffix<W: Write>(
        &self,
        writer: &mut W,
        written: &mut u64,
    ) -> Result<(), WriteError> {
        write_records(writer, &self.page_records, written)?;
        write_record(writer, &self.manifest_record, written)?;
        write_record(writer, &self.creator_record, written)?;
        write_record(writer, &self.superblock_record, written)
    }
}

#[derive(Debug)]
pub enum WriteError {
    Metadata(metadata::ValidationError),
    MetadataRecords(metadata::RecordEncodingError),
    Creator(creator::Error),
    RecoveryChunk(recovery_chunk::Error),
    CompleteRecoverySet(recovery_set::CompleteError),
    Superblock(superblock::Error),
    Record(record::Error),
    InvalidOptionalRecord { record_type: u16, logical_id: u64 },
    LengthOverflow,
    WrittenLengthMismatch { actual: u64, expected: u64 },
}

impl fmt::Display for WriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata(error) => write!(formatter, "sidecar metadata is invalid: {error}"),
            Self::MetadataRecords(error) => {
                write!(formatter, "sidecar metadata encoding failed: {error}")
            }
            Self::Creator(error) => write!(formatter, "creator record is invalid: {error}"),
            Self::RecoveryChunk(error) => write!(formatter, "recovery chunk is invalid: {error}"),
            Self::CompleteRecoverySet(error) => {
                write!(formatter, "generated recovery set is invalid: {error}")
            }
            Self::Superblock(error) => write!(formatter, "superblock layout is invalid: {error}"),
            Self::Record(error) => write!(formatter, "record writing failed: {error}"),
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
            Self::Metadata(error) => Some(error),
            Self::MetadataRecords(error) => Some(error),
            Self::Creator(error) => Some(error),
            Self::RecoveryChunk(error) => Some(error),
            Self::CompleteRecoverySet(error) => Some(error),
            Self::Superblock(error) => Some(error),
            Self::Record(error) => Some(error),
            Self::InvalidOptionalRecord { .. }
            | Self::LengthOverflow
            | Self::WrittenLengthMismatch { .. } => None,
        }
    }
}

fn validate_optional_records(records: &[Record], set_id: [u8; 32]) -> Result<(), WriteError> {
    for record in records {
        if record_policy::classify(record) != Disposition::UnknownOptional
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

fn recovery_records_len(manifest: crate::manifest::Manifest) -> Result<u64, WriteError> {
    let per_record =
        recovery_chunk::encoded_record_len(manifest).ok_or(WriteError::LengthOverflow)?;
    let count = u64::from(manifest.geometry().recovery_chunks);
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
