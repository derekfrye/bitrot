//! Physical sidecar scanning and bounded damage recovery.

use super::{AssemblyLimits, Error, Sidecar};
use crate::bounded_count;
use crate::digest_page;
use crate::metadata::{self, Metadata};
use crate::record::{self, DecodeLimits};
use crate::recovery_chunk;
use crate::recovery_set;
use crate::rolling_page;
use crate::scan::{Event, Scanner};
use std::fmt;
use std::io::{Read, Seek};

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

fn push_damage(damage: &mut Vec<Damage>, event: Damage, maximum: u32) -> Result<(), ReadError> {
    let actual = bounded_count::after_push(damage.len());
    if actual > u64::from(maximum) {
        Err(ReadError::DamageEventLimitExceeded { actual, maximum })
    } else {
        damage.push(event);
        Ok(())
    }
}
