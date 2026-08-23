//! Assembly of one complete, redundantly stored logical manifest.

use crate::digest_page::{self, Kind};
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

        let mut manifest = None;
        for record in records
            .iter()
            .filter(|record| record.record_type == manifest::RECORD_TYPE)
        {
            let candidate = Manifest::from_record(record).map_err(Error::CoreManifest)?;
            if let Some(existing) = manifest {
                if existing != candidate {
                    return Err(Error::ConflictingCoreManifest);
                }
            } else {
                manifest = Some(candidate);
            }
        }
        let manifest = manifest.ok_or(Error::MissingCoreManifest)?;

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
            expected_rolling_count(manifest),
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

fn enforce_record_limit(records: &[Record], maximum: u64) -> Result<(), Error> {
    let actual = records.iter().try_fold(0_u64, |count, record| {
        if matches!(
            record.record_type,
            manifest::RECORD_TYPE | digest_page::RECORD_TYPE | rolling_page::RECORD_TYPE
        ) {
            count.checked_add(1)
        } else {
            Some(count)
        }
    });
    let actual = actual.unwrap_or(u64::MAX);
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

fn expected_rolling_count(manifest: Manifest) -> u64 {
    let geometry = manifest.geometry();
    let short_final = geometry.final_data_chunk_len < geometry.chunk_size.bytes();
    u64::from(geometry.data_chunks) - u64::from(short_final)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{ChunkSize, Digest, MIN_CHUNK_SIZE};
    use crate::geometry::Geometry;

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
        let manifest = Manifest::new(
            geometry,
            Digest::from_bytes([7; 32]),
            &data_digests,
            &recovery_digests,
            &rolling_fingerprints,
        )
        .unwrap();

        let mut records = vec![manifest.to_record()];
        records.extend(
            recovery_digests
                .pages
                .iter()
                .map(|page| page.to_record(manifest.protection_set_id()).unwrap()),
        );
        records.extend(
            rolling_fingerprints
                .pages
                .iter()
                .map(|page| page.to_record(manifest.protection_set_id()).unwrap()),
        );
        records.extend(
            data_digests
                .pages
                .iter()
                .map(|page| page.to_record(manifest.protection_set_id()).unwrap()),
        );
        Fixture {
            expected: Metadata {
                manifest,
                data_digests,
                recovery_digests,
                rolling_fingerprints,
            },
            records,
        }
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
