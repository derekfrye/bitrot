//! Assembly of one complete, redundantly stored logical manifest.

use crate::agreed_copies;
use crate::bounded_count;
use crate::digest::Digest;
use crate::digest_page::{self, Kind};
use crate::geometry::Geometry;
use crate::manifest::{self, Manifest};
use crate::record::Record;
use crate::rolling_page;
use std::fmt;

/// Caller-selected resource bounds for logical-manifest assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyLimits {
    pub max_metadata_records: u64,
    pub digest_tables: digest_page::AssemblyLimits,
    pub rolling_table: rolling_page::AssemblyLimits,
}

impl AssemblyLimits {
    #[must_use]
    pub const fn new(
        max_metadata_records: u64,
        digest_tables: digest_page::AssemblyLimits,
        rolling_table: rolling_page::AssemblyLimits,
    ) -> Self {
        Self {
            max_metadata_records,
            digest_tables,
            rolling_table,
        }
    }
}

/// A complete core manifest and all tables it commits to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub manifest: Manifest,
    pub data_digests: digest_page::Table,
    pub recovery_digests: digest_page::Table,
    pub rolling_fingerprints: rolling_page::Table,
}

impl Metadata {
    /// Constructs metadata whose manifest commits to the supplied tables.
    ///
    /// # Errors
    ///
    /// Returns an error when the table kinds or counts do not agree with the
    /// geometry.
    pub fn new(
        geometry: Geometry,
        source_digest: Digest,
        data_digests: digest_page::Table,
        recovery_digests: digest_page::Table,
        rolling_fingerprints: rolling_page::Table,
    ) -> Result<Self, manifest::Error> {
        let manifest = Manifest::new(
            geometry,
            source_digest,
            &data_digests,
            &recovery_digests,
            &rolling_fingerprints,
        )?;
        Ok(Self {
            manifest,
            data_digests,
            recovery_digests,
            rolling_fingerprints,
        })
    }

    /// Revalidates the public tables and their binding to the manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when a table is noncanonical or incorrectly rooted,
    /// its page count cannot be represented, or the rebuilt manifest differs
    /// from the stored manifest.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let data_page_limit = u32::try_from(self.data_digests.pages.len())
            .map_err(|_| ValidationError::PageCountUnrepresentable)?;
        let recovery_page_limit = u32::try_from(self.recovery_digests.pages.len())
            .map_err(|_| ValidationError::PageCountUnrepresentable)?;
        let rolling_page_limit = u32::try_from(self.rolling_fingerprints.pages.len())
            .map_err(|_| ValidationError::PageCountUnrepresentable)?;

        let data = digest_page::Table::assemble(
            Kind::Data,
            self.data_digests.digest_count,
            self.data_digests.root,
            self.data_digests.pages.clone(),
            digest_page::AssemblyLimits::new(self.data_digests.digest_count, data_page_limit),
        )
        .map_err(ValidationError::DataTable)?;
        let recovery = digest_page::Table::assemble(
            Kind::Recovery,
            self.recovery_digests.digest_count,
            self.recovery_digests.root,
            self.recovery_digests.pages.clone(),
            digest_page::AssemblyLimits::new(
                self.recovery_digests.digest_count,
                recovery_page_limit,
            ),
        )
        .map_err(ValidationError::RecoveryTable)?;
        let rolling = rolling_page::Table::assemble(
            self.rolling_fingerprints.value_count,
            self.rolling_fingerprints.root,
            self.rolling_fingerprints.pages.clone(),
            rolling_page::AssemblyLimits::new(
                self.rolling_fingerprints.value_count,
                rolling_page_limit,
            ),
        )
        .map_err(ValidationError::RollingTable)?;
        let rebuilt = Manifest::new(
            self.manifest.geometry(),
            self.manifest.source_digest(),
            &data,
            &recovery,
            &rolling,
        )
        .map_err(ValidationError::Manifest)?;
        if rebuilt == self.manifest {
            Ok(())
        } else {
            Err(ValidationError::ManifestMismatch)
        }
    }

    /// Encodes all table pages in canonical data, recovery, rolling order.
    ///
    /// # Errors
    ///
    /// Returns an error when the page count or an encoded page is invalid.
    pub fn to_page_records(&self) -> Result<Vec<Record>, RecordEncodingError> {
        let page_count = self
            .data_digests
            .pages
            .len()
            .checked_add(self.recovery_digests.pages.len())
            .and_then(|count| count.checked_add(self.rolling_fingerprints.pages.len()))
            .ok_or(RecordEncodingError::LengthOverflow)?;
        let mut records = Vec::with_capacity(page_count);
        let set_id = self.manifest.protection_set_id();
        for page in &self.data_digests.pages {
            records.push(
                page.to_record(set_id)
                    .map_err(RecordEncodingError::DigestPage)?,
            );
        }
        for page in &self.recovery_digests.pages {
            records.push(
                page.to_record(set_id)
                    .map_err(RecordEncodingError::DigestPage)?,
            );
        }
        for page in &self.rolling_fingerprints.pages {
            records.push(
                page.to_record(set_id)
                    .map_err(RecordEncodingError::RollingPage)?,
            );
        }
        Ok(records)
    }

    /// Encodes the core manifest followed by every canonical table page.
    ///
    /// # Errors
    ///
    /// Returns an error when table-page record encoding fails.
    pub fn to_records(&self) -> Result<Vec<Record>, RecordEncodingError> {
        let pages = self.to_page_records()?;
        let capacity = pages
            .len()
            .checked_add(1)
            .ok_or(RecordEncodingError::LengthOverflow)?;
        let mut records = Vec::with_capacity(capacity);
        records.push(self.manifest.to_record());
        records.extend(pages);
        Ok(records)
    }

    /// Reconciles redundant metadata records into one authenticated manifest.
    ///
    /// Records of unrelated types are ignored. All core-manifest copies must
    /// be identical, and every digest- or rolling-page record must belong to
    /// that manifest's protection set. Identical page copies are collapsed by
    /// the table assemblers; conflicting copies are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error when resource limits are exceeded, the core manifest
    /// is absent or conflicting, a logical record is invalid or belongs to a
    /// different set, or a committed table cannot be assembled and verified.
    pub fn assemble(records: &[Record], limits: AssemblyLimits) -> Result<Self, Error> {
        enforce_record_limit(records, limits.max_metadata_records)?;

        let manifest = agreed_copies::assemble(
            records
                .iter()
                .filter(|record| record.record_type == manifest::RECORD_TYPE),
            None,
            Manifest::from_record,
        )
        .map_err(map_agreed_copies_error)?;

        let mut data_pages = Vec::new();
        let mut recovery_pages = Vec::new();
        let mut rolling_pages = Vec::new();
        for record in records {
            match record.record_type {
                digest_page::RECORD_TYPE => {
                    validate_set(record, manifest)?;
                    let page = digest_page::Page::from_record(record).map_err(Error::DigestPage)?;
                    match page.kind {
                        Kind::Data => data_pages.push(page),
                        Kind::Recovery => recovery_pages.push(page),
                    }
                }
                rolling_page::RECORD_TYPE => {
                    validate_set(record, manifest)?;
                    rolling_pages
                        .push(rolling_page::Page::from_record(record).map_err(Error::RollingPage)?);
                }
                _ => {}
            }
        }

        let geometry = manifest.geometry();
        let data_digests = digest_page::Table::assemble(
            Kind::Data,
            u64::from(geometry.data_chunks),
            manifest.data_table_root(),
            data_pages,
            limits.digest_tables,
        )
        .map_err(Error::DataTable)?;
        let recovery_digests = digest_page::Table::assemble(
            Kind::Recovery,
            u64::from(geometry.recovery_chunks),
            manifest.recovery_table_root(),
            recovery_pages,
            limits.digest_tables,
        )
        .map_err(Error::RecoveryTable)?;
        let rolling_fingerprints = rolling_page::Table::assemble(
            geometry.full_data_chunks(),
            manifest.rolling_table_root(),
            rolling_pages,
            limits.rolling_table,
        )
        .map_err(Error::RollingTable)?;

        Ok(Self {
            manifest,
            data_digests,
            recovery_digests,
            rolling_fingerprints,
        })
    }
}

#[derive(Debug)]
pub enum ValidationError {
    PageCountUnrepresentable,
    DataTable(digest_page::AssemblyError),
    RecoveryTable(digest_page::AssemblyError),
    RollingTable(rolling_page::AssemblyError),
    Manifest(manifest::Error),
    ManifestMismatch,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PageCountUnrepresentable => {
                formatter.write_str("metadata page count cannot be represented")
            }
            Self::DataTable(error) => write!(formatter, "data digest table is invalid: {error}"),
            Self::RecoveryTable(error) => {
                write!(formatter, "recovery digest table is invalid: {error}")
            }
            Self::RollingTable(error) => {
                write!(formatter, "rolling fingerprint table is invalid: {error}")
            }
            Self::Manifest(error) => write!(formatter, "core manifest is invalid: {error}"),
            Self::ManifestMismatch => {
                formatter.write_str("core manifest does not match the metadata tables")
            }
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DataTable(error) | Self::RecoveryTable(error) => Some(error),
            Self::RollingTable(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::PageCountUnrepresentable | Self::ManifestMismatch => None,
        }
    }
}

#[derive(Debug)]
pub enum RecordEncodingError {
    LengthOverflow,
    DigestPage(digest_page::Error),
    RollingPage(rolling_page::Error),
}

impl fmt::Display for RecordEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow => formatter.write_str("metadata record count overflows"),
            Self::DigestPage(error) => write!(formatter, "cannot encode digest page: {error}"),
            Self::RollingPage(error) => write!(formatter, "cannot encode rolling page: {error}"),
        }
    }
}

impl std::error::Error for RecordEncodingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DigestPage(error) => Some(error),
            Self::RollingPage(error) => Some(error),
            Self::LengthOverflow => None,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    MetadataRecordLimitExceeded { actual: u64, maximum: u64 },
    MissingCoreManifest,
    ConflictingCoreManifest,
    ForeignMetadataRecord { record_type: u16, logical_id: u64 },
    CoreManifest(manifest::Error),
    DigestPage(digest_page::Error),
    RollingPage(rolling_page::Error),
    DataTable(digest_page::AssemblyError),
    RecoveryTable(digest_page::AssemblyError),
    RollingTable(rolling_page::AssemblyError),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetadataRecordLimitExceeded { actual, maximum } => write!(
                formatter,
                "metadata record count {actual} exceeds limit {maximum}"
            ),
            Self::MissingCoreManifest => formatter.write_str("core manifest is missing"),
            Self::ConflictingCoreManifest => {
                formatter.write_str("valid core-manifest copies conflict")
            }
            Self::ForeignMetadataRecord {
                record_type,
                logical_id,
            } => write!(
                formatter,
                "metadata record type {record_type} logical identifier {logical_id} belongs to a different protection set"
            ),
            Self::CoreManifest(error) => write!(formatter, "invalid core manifest: {error}"),
            Self::DigestPage(error) => write!(formatter, "invalid digest page: {error}"),
            Self::RollingPage(error) => write!(formatter, "invalid rolling page: {error}"),
            Self::DataTable(error) => write!(formatter, "data digest table is invalid: {error}"),
            Self::RecoveryTable(error) => {
                write!(formatter, "recovery digest table is invalid: {error}")
            }
            Self::RollingTable(error) => {
                write!(formatter, "rolling fingerprint table is invalid: {error}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CoreManifest(error) => Some(error),
            Self::DigestPage(error) => Some(error),
            Self::RollingPage(error) => Some(error),
            Self::DataTable(error) | Self::RecoveryTable(error) => Some(error),
            Self::RollingTable(error) => Some(error),
            _ => None,
        }
    }
}

fn map_agreed_copies_error(error: agreed_copies::Error<manifest::Error>) -> Error {
    match error {
        agreed_copies::Error::CopyLimitExceeded { actual, maximum } => {
            Error::MetadataRecordLimitExceeded {
                actual,
                maximum: u64::from(maximum),
            }
        }
        agreed_copies::Error::Missing => Error::MissingCoreManifest,
        agreed_copies::Error::InvalidCopy(error) => Error::CoreManifest(error),
        agreed_copies::Error::ConflictingCopies => Error::ConflictingCoreManifest,
    }
}

fn enforce_record_limit(records: &[Record], maximum: u64) -> Result<(), Error> {
    let actual = bounded_count::items(records.iter().filter(|record| {
        matches!(
            record.record_type,
            manifest::RECORD_TYPE | digest_page::RECORD_TYPE | rolling_page::RECORD_TYPE
        )
    }));
    if actual > maximum {
        Err(Error::MetadataRecordLimitExceeded { actual, maximum })
    } else {
        Ok(())
    }
}

fn validate_set(record: &Record, manifest: Manifest) -> Result<(), Error> {
    if record.protection_set_id == manifest.protection_set_id() {
        Ok(())
    } else {
        Err(Error::ForeignMetadataRecord {
            record_type: record.record_type,
            logical_id: record.logical_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Digest;
    use crate::geometry::Geometry;
    use crate::geometry::{ChunkSize, MIN_CHUNK_SIZE};

    struct Fixture {
        expected: Metadata,
        records: Vec<Record>,
    }

    fn fixture() -> Fixture {
        let chunk_size = ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap();
        let geometry = Geometry::from_stored(
            u64::from(chunk_size.bytes()) * 2,
            chunk_size,
            2,
            2,
            chunk_size.bytes(),
        )
        .unwrap();
        let data_digests = digest_page::Table::new(
            Kind::Data,
            vec![Digest::from_bytes([1; 32]), Digest::from_bytes([2; 32])],
        )
        .unwrap();
        let recovery_digests = digest_page::Table::new(
            Kind::Recovery,
            vec![Digest::from_bytes([3; 32]), Digest::from_bytes([4; 32])],
        )
        .unwrap();
        let rolling_fingerprints = rolling_page::Table::new(vec![5, 6]).unwrap();
        let expected = Metadata::new(
            geometry,
            Digest::from_bytes([7; 32]),
            data_digests,
            recovery_digests,
            rolling_fingerprints,
        )
        .unwrap();
        let records = expected.to_records().unwrap();
        Fixture { expected, records }
    }

    fn limits(maximum: u64) -> AssemblyLimits {
        AssemblyLimits::new(
            maximum,
            digest_page::AssemblyLimits::new(10, 10),
            rolling_page::AssemblyLimits::new(10, 10),
        )
    }

    #[test]
    fn assembles_reordered_redundant_metadata() {
        let mut fixture = fixture();
        let copies = fixture.records.clone();
        fixture.records.extend(copies);
        fixture.records.reverse();
        fixture.records.push(Record {
            record_type: 99,
            flags: 0,
            protection_set_id: [0; 32],
            logical_id: 0,
            header_extension: Vec::new(),
            payload: Vec::new(),
        });

        assert_eq!(
            Metadata::assemble(&fixture.records, limits(20)).unwrap(),
            fixture.expected
        );
    }

    #[test]
    fn owns_validation_and_canonical_record_encoding() {
        let fixture = fixture();
        fixture.expected.validate().unwrap();
        assert_eq!(
            fixture
                .expected
                .to_records()
                .unwrap()
                .iter()
                .map(|record| record.record_type)
                .collect::<Vec<_>>(),
            vec![
                manifest::RECORD_TYPE,
                digest_page::RECORD_TYPE,
                digest_page::RECORD_TYPE,
                rolling_page::RECORD_TYPE,
            ]
        );

        let mut invalid = fixture.expected;
        invalid.data_digests.root = Digest::from_bytes([0xff; 32]);
        assert!(matches!(
            invalid.validate(),
            Err(ValidationError::DataTable(
                digest_page::AssemblyError::RootMismatch { .. }
            ))
        ));
    }

    #[test]
    fn requires_one_agreed_core_manifest() {
        let fixture = fixture();
        assert!(matches!(
            Metadata::assemble(&fixture.records[1..], limits(10)),
            Err(Error::MissingCoreManifest)
        ));

        let mut records = fixture.records.clone();
        let mut conflicting = fixture.expected.manifest.to_record();
        conflicting.payload[120] ^= 1;
        records.push(conflicting);
        assert!(matches!(
            Metadata::assemble(&records, limits(10)),
            Err(Error::ConflictingCoreManifest)
        ));
    }

    #[test]
    fn rejects_foreign_and_malformed_pages() {
        let fixture = fixture();
        let mut foreign = fixture.records.clone();
        foreign[1].protection_set_id[0] ^= 1;
        assert!(matches!(
            Metadata::assemble(&foreign, limits(10)),
            Err(Error::ForeignMetadataRecord { .. })
        ));

        let mut malformed = fixture.records;
        let page = malformed
            .iter_mut()
            .find(|record| record.record_type == digest_page::RECORD_TYPE)
            .unwrap();
        page.logical_id ^= 1;
        assert!(matches!(
            Metadata::assemble(&malformed, limits(10)),
            Err(Error::DigestPage(_))
        ));
    }

    #[test]
    fn detects_missing_and_conflicting_pages() {
        let fixture = fixture();
        let mut missing = fixture.records.clone();
        missing.retain(|record| record.record_type != rolling_page::RECORD_TYPE);
        assert!(matches!(
            Metadata::assemble(&missing, limits(10)),
            Err(Error::RollingTable(
                rolling_page::AssemblyError::MissingPages(_)
            ))
        ));

        let mut conflicting = fixture.records;
        let mut page = conflicting
            .iter()
            .find(|record| record.record_type == digest_page::RECORD_TYPE)
            .unwrap()
            .clone();
        page.payload[24] ^= 1;
        conflicting.push(page);
        assert!(matches!(
            Metadata::assemble(&conflicting, limits(10)),
            Err(
                Error::DataTable(digest_page::AssemblyError::ConflictingPage(_))
                    | Error::RecoveryTable(digest_page::AssemblyError::ConflictingPage(_))
            )
        ));
    }

    #[test]
    fn applies_record_and_table_limits() {
        let fixture = fixture();
        assert!(matches!(
            Metadata::assemble(&fixture.records, limits(1)),
            Err(Error::MetadataRecordLimitExceeded { .. })
        ));

        let small_tables = AssemblyLimits::new(
            10,
            digest_page::AssemblyLimits::new(1, 10),
            rolling_page::AssemblyLimits::new(10, 10),
        );
        assert!(matches!(
            Metadata::assemble(&fixture.records, small_tables),
            Err(Error::DataTable(
                digest_page::AssemblyError::DigestLimitExceeded { .. }
            ))
        ));
    }
}
