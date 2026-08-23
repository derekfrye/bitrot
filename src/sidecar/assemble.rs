//! Logical sidecar reconciliation over physically validated records.

use super::Sidecar;
use super::record_policy::{self, Disposition};
use crate::bounded_count;
use crate::creator::{self, Creator};
use crate::metadata::{self, Metadata};
use crate::record::Record;
use crate::recovery_set::{self, RecoverySet};
use crate::superblock::{self, Superblock};
use std::fmt;

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
