//! Whole-sidecar logical validation over physically verified records.

mod assemble;
mod read;
mod record_policy;
mod write;

pub use assemble::{AssemblyLimits, Error};
pub use read::{Damage, ReadError, ReadLimitError, ReadLimits, ReadResult};
pub(crate) use write::CanonicalLayout;
pub use write::{WriteError, WriteSummary};

use crate::creator::Creator;
use crate::metadata::Metadata;
use crate::record::Record;
use crate::recovery_set::RecoverySet;
use crate::superblock::Superblock;

/// One logically validated version-1 sidecar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sidecar {
    pub superblock: Superblock,
    pub metadata: Metadata,
    pub creator: Creator,
    pub recovery: RecoverySet,
    unknown_optional_records: Vec<Record>,
}

impl Sidecar {
    /// Unknown optional records retained byte-for-byte at the logical level.
    #[must_use]
    pub fn unknown_optional_records(&self) -> &[Record] {
        &self.unknown_optional_records
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creator;
    use crate::digest::Digest;
    use crate::geometry::MIN_CHUNK_SIZE;
    use crate::metadata;
    use crate::record::{self, DecodeLimits, FLAG_REQUIRED};
    use crate::recovery_chunk;
    use crate::recovery_set;
    use crate::scan::{Event, Scanner};
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
