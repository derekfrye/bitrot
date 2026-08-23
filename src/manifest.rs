//! Canonical core-manifest records for one protection set.

use crate::algorithm::{CODING_LEOPARD_GF16, ROLLING_CRC64_GO_ISO, STRONG_HASH_BLAKE3_256};
use crate::digest::Digest;
use crate::digest_page::{Kind, Table};
use crate::geometry::{ChunkSize, ChunkSizeError, Geometry, GeometryError};
use crate::record::{self, FLAG_REQUIRED, Record};
use crate::rolling_page::Table as RollingTable;
use crate::wire;
use std::fmt;

pub const RECORD_TYPE: u16 = 2;
pub const PAYLOAD_VERSION: u16 = 1;
pub const PAYLOAD_LEN: usize = 192;
pub(crate) const ENCODED_RECORD_LEN: u64 = match record::unextended_encoded_len(PAYLOAD_LEN as u64)
{
    Some(length) => length,
    None => panic!("manifest record length overflows u64"),
};

const SET_ID_CONTEXT: &str = "bitrot format v1 protection set identifier";

/// The small, duplicated manifest that binds source identity and coding data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Manifest {
    geometry: Geometry,
    source_digest: Digest,
    data_table_root: Digest,
    recovery_table_root: Digest,
    rolling_table_root: Digest,
    protection_set_id: [u8; 32],
}

impl Manifest {
    /// Constructs a manifest from validated geometry and fingerprint tables.
    ///
    /// # Errors
    ///
    /// Returns an error unless the supplied tables have the expected kinds,
    /// exactly one digest per corresponding shard, and exactly one rolling
    /// value per full-size data chunk.
    pub fn new(
        geometry: Geometry,
        source_digest: Digest,
        data_table: &Table,
        recovery_table: &Table,
        rolling_table: &RollingTable,
    ) -> Result<Self, Error> {
        validate_table(data_table, Kind::Data, u64::from(geometry.data_chunks))?;
        validate_table(
            recovery_table,
            Kind::Recovery,
            u64::from(geometry.recovery_chunks),
        )?;
        let expected_rolling_count = geometry.full_data_chunks();
        if rolling_table.value_count != expected_rolling_count {
            return Err(Error::RollingCountMismatch {
                actual: rolling_table.value_count,
                expected: expected_rolling_count,
            });
        }
        Ok(Self::from_validated_parts(
            geometry,
            source_digest,
            data_table.root,
            recovery_table.root,
            rolling_table.root,
        ))
    }

    #[must_use]
    pub const fn geometry(self) -> Geometry {
        self.geometry
    }

    #[must_use]
    pub const fn source_digest(self) -> Digest {
        self.source_digest
    }

    #[must_use]
    pub const fn data_table_root(self) -> Digest {
        self.data_table_root
    }

    #[must_use]
    pub const fn recovery_table_root(self) -> Digest {
        self.recovery_table_root
    }

    #[must_use]
    pub const fn rolling_table_root(self) -> Digest {
        self.rolling_table_root
    }

    #[must_use]
    pub const fn protection_set_id(self) -> [u8; 32] {
        self.protection_set_id
    }

    /// Encodes this manifest as a canonical required record.
    #[must_use]
    pub fn to_record(self) -> Record {
        Record::required(RECORD_TYPE, self.protection_set_id, 0, self.payload())
    }

    /// Strictly decodes and validates a core-manifest record.
    ///
    /// # Errors
    ///
    /// Returns an error unless all physical metadata, algorithms, geometry,
    /// payload fields, and the derived protection-set identifier are canonical.
    pub fn from_record(record: &Record) -> Result<Self, Error> {
        if record.record_type != RECORD_TYPE {
            return Err(Error::WrongRecordType(record.record_type));
        }
        if record.flags != FLAG_REQUIRED {
            return Err(Error::InvalidRecordFlags(record.flags));
        }
        if record.logical_id != 0 {
            return Err(Error::InvalidLogicalId(record.logical_id));
        }
        if !record.header_extension.is_empty() {
            return Err(Error::UnsupportedHeaderExtension);
        }
        if record.payload.len() != PAYLOAD_LEN {
            return Err(Error::PayloadLengthMismatch {
                actual: record.payload.len(),
                expected: PAYLOAD_LEN,
            });
        }

        let version = parse_u16(&record.payload, 0)?;
        if version != PAYLOAD_VERSION {
            return Err(Error::UnsupportedPayloadVersion(version));
        }
        let required_features = parse_u16(&record.payload, 2)?;
        if required_features != 0 {
            return Err(Error::UnsupportedRequiredFeatures(required_features));
        }
        validate_algorithm(
            "coding",
            parse_u16(&record.payload, 4)?,
            CODING_LEOPARD_GF16,
        )?;
        validate_algorithm(
            "strong hash",
            parse_u16(&record.payload, 6)?,
            STRONG_HASH_BLAKE3_256,
        )?;
        validate_algorithm(
            "rolling",
            parse_u16(&record.payload, 8)?,
            ROLLING_CRC64_GO_ISO,
        )?;
        if parse_u16(&record.payload, 10)? != 0 || parse_u32(&record.payload, 36)? != 0 {
            return Err(Error::ReservedField);
        }

        let chunk_size = ChunkSize::new(u64::from(parse_u32(&record.payload, 12)?))?;
        let source_len = parse_u64(&record.payload, 16)?;
        let data_chunks = parse_u32(&record.payload, 24)?;
        let recovery_chunks = parse_u32(&record.payload, 28)?;
        let final_data_chunk_len = parse_u32(&record.payload, 32)?;
        let geometry = Geometry::from_stored(
            source_len,
            chunk_size,
            data_chunks,
            recovery_chunks,
            final_data_chunk_len,
        )?;
        let data_digest_count = parse_u64(&record.payload, 72)?;
        if data_digest_count != u64::from(data_chunks) {
            return Err(Error::DigestCountMismatch {
                kind: Kind::Data,
                actual: data_digest_count,
                expected: u64::from(data_chunks),
            });
        }
        let recovery_digest_count = parse_u64(&record.payload, 112)?;
        if recovery_digest_count != u64::from(recovery_chunks) {
            return Err(Error::DigestCountMismatch {
                kind: Kind::Recovery,
                actual: recovery_digest_count,
                expected: u64::from(recovery_chunks),
            });
        }
        let expected_rolling_count = geometry.full_data_chunks();
        let rolling_count = parse_u64(&record.payload, 152)?;
        if rolling_count != expected_rolling_count {
            return Err(Error::RollingCountMismatch {
                actual: rolling_count,
                expected: expected_rolling_count,
            });
        }

        let manifest = Self::from_validated_parts(
            geometry,
            digest(&record.payload, 40)?,
            digest(&record.payload, 80)?,
            digest(&record.payload, 120)?,
            digest(&record.payload, 160)?,
        );
        if record.protection_set_id != manifest.protection_set_id {
            return Err(Error::ProtectionSetIdMismatch {
                expected: manifest.protection_set_id,
                actual: record.protection_set_id,
            });
        }
        Ok(manifest)
    }

    fn from_validated_parts(
        geometry: Geometry,
        source_digest: Digest,
        data_table_root: Digest,
        recovery_table_root: Digest,
        rolling_table_root: Digest,
    ) -> Self {
        let protection_set_id = set_id(geometry, source_digest, data_table_root);
        Self {
            geometry,
            source_digest,
            data_table_root,
            recovery_table_root,
            rolling_table_root,
            protection_set_id,
        }
    }

    fn payload(self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.extend_from_slice(&PAYLOAD_VERSION.to_le_bytes());
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(&CODING_LEOPARD_GF16.to_le_bytes());
        payload.extend_from_slice(&STRONG_HASH_BLAKE3_256.to_le_bytes());
        payload.extend_from_slice(&ROLLING_CRC64_GO_ISO.to_le_bytes());
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(&self.geometry.chunk_size.bytes().to_le_bytes());
        payload.extend_from_slice(&self.geometry.source_len.to_le_bytes());
        payload.extend_from_slice(&self.geometry.data_chunks.to_le_bytes());
        payload.extend_from_slice(&self.geometry.recovery_chunks.to_le_bytes());
        payload.extend_from_slice(&self.geometry.final_data_chunk_len.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        payload.extend_from_slice(self.source_digest.as_bytes());
        payload.extend_from_slice(&u64::from(self.geometry.data_chunks).to_le_bytes());
        payload.extend_from_slice(self.data_table_root.as_bytes());
        payload.extend_from_slice(&u64::from(self.geometry.recovery_chunks).to_le_bytes());
        payload.extend_from_slice(self.recovery_table_root.as_bytes());
        payload.extend_from_slice(&self.geometry.full_data_chunks().to_le_bytes());
        payload.extend_from_slice(self.rolling_table_root.as_bytes());
        debug_assert_eq!(payload.len(), PAYLOAD_LEN);
        payload
    }
}

fn validate_table(table: &Table, expected_kind: Kind, expected_count: u64) -> Result<(), Error> {
    if table.kind != expected_kind {
        return Err(Error::WrongTableKind {
            actual: table.kind,
            expected: expected_kind,
        });
    }
    if table.digest_count != expected_count {
        return Err(Error::DigestCountMismatch {
            kind: expected_kind,
            actual: table.digest_count,
            expected: expected_count,
        });
    }
    Ok(())
}

fn set_id(geometry: Geometry, source_digest: Digest, data_table_root: Digest) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SET_ID_CONTEXT);
    hasher.update(&PAYLOAD_VERSION.to_le_bytes());
    hasher.update(&CODING_LEOPARD_GF16.to_le_bytes());
    hasher.update(&STRONG_HASH_BLAKE3_256.to_le_bytes());
    hasher.update(&ROLLING_CRC64_GO_ISO.to_le_bytes());
    hasher.update(&geometry.chunk_size.bytes().to_le_bytes());
    hasher.update(&geometry.source_len.to_le_bytes());
    hasher.update(&geometry.data_chunks.to_le_bytes());
    hasher.update(&geometry.recovery_chunks.to_le_bytes());
    hasher.update(&geometry.final_data_chunk_len.to_le_bytes());
    hasher.update(source_digest.as_bytes());
    hasher.update(&u64::from(geometry.data_chunks).to_le_bytes());
    hasher.update(data_table_root.as_bytes());
    hasher.finalize().into()
}

fn validate_algorithm(name: &'static str, actual: u16, expected: u16) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::UnsupportedAlgorithm { name, actual })
    }
}

fn parse_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    wire::u16(bytes, offset).ok_or_else(|| invalid_payload_length(bytes))
}

fn parse_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    wire::u32(bytes, offset).ok_or_else(|| invalid_payload_length(bytes))
}

fn parse_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    wire::u64(bytes, offset).ok_or_else(|| invalid_payload_length(bytes))
}

fn digest(bytes: &[u8], offset: usize) -> Result<Digest, Error> {
    wire::array(bytes, offset)
        .map(Digest::from_bytes)
        .ok_or_else(|| invalid_payload_length(bytes))
}

fn invalid_payload_length(bytes: &[u8]) -> Error {
    Error::PayloadLengthMismatch {
        actual: bytes.len(),
        expected: PAYLOAD_LEN,
    }
}

#[derive(Debug)]
pub enum Error {
    WrongTableKind {
        actual: Kind,
        expected: Kind,
    },
    DigestCountMismatch {
        kind: Kind,
        actual: u64,
        expected: u64,
    },
    RollingCountMismatch {
        actual: u64,
        expected: u64,
    },
    WrongRecordType(u16),
    InvalidRecordFlags(u32),
    InvalidLogicalId(u64),
    UnsupportedHeaderExtension,
    PayloadLengthMismatch {
        actual: usize,
        expected: usize,
    },
    UnsupportedPayloadVersion(u16),
    UnsupportedRequiredFeatures(u16),
    UnsupportedAlgorithm {
        name: &'static str,
        actual: u16,
    },
    ReservedField,
    InvalidChunkSize(ChunkSizeError),
    InvalidGeometry(GeometryError),
    ProtectionSetIdMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongTableKind { actual, expected } => {
                write!(
                    formatter,
                    "manifest expected {expected:?} table, got {actual:?}"
                )
            }
            Self::DigestCountMismatch {
                kind,
                actual,
                expected,
            } => write!(
                formatter,
                "manifest {kind:?} digest count {actual} does not match shard count {expected}"
            ),
            Self::RollingCountMismatch { actual, expected } => write!(
                formatter,
                "manifest rolling value count {actual} does not match full data chunk count {expected}"
            ),
            Self::WrongRecordType(actual) => {
                write!(formatter, "record type {actual} is not a core manifest")
            }
            Self::InvalidRecordFlags(actual) => {
                write!(
                    formatter,
                    "core-manifest record has invalid flags {actual:#x}"
                )
            }
            Self::InvalidLogicalId(actual) => {
                write!(
                    formatter,
                    "core-manifest logical identifier must be zero, got {actual}"
                )
            }
            Self::UnsupportedHeaderExtension => {
                formatter.write_str("core-manifest record has an unsupported header extension")
            }
            Self::PayloadLengthMismatch { actual, expected } => write!(
                formatter,
                "core-manifest payload length is {actual}, expected {expected}"
            ),
            Self::UnsupportedPayloadVersion(actual) => {
                write!(
                    formatter,
                    "unsupported core-manifest payload version {actual}"
                )
            }
            Self::UnsupportedRequiredFeatures(actual) => write!(
                formatter,
                "unsupported core-manifest required features {actual:#x}"
            ),
            Self::UnsupportedAlgorithm { name, actual } => {
                write!(
                    formatter,
                    "unsupported core-manifest {name} algorithm {actual}"
                )
            }
            Self::ReservedField => {
                formatter.write_str("core-manifest payload has a nonzero reserved field")
            }
            Self::InvalidChunkSize(error) => write!(formatter, "invalid manifest {error}"),
            Self::InvalidGeometry(error) => write!(formatter, "invalid manifest geometry: {error}"),
            Self::ProtectionSetIdMismatch { .. } => {
                formatter.write_str("core-manifest protection-set identifier does not match")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidChunkSize(error) => Some(error),
            Self::InvalidGeometry(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ChunkSizeError> for Error {
    fn from(error: ChunkSizeError) -> Self {
        Self::InvalidChunkSize(error)
    }
}

impl From<GeometryError> for Error {
    fn from(error: GeometryError) -> Self {
        Self::InvalidGeometry(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint;
    use crate::geometry::MIN_CHUNK_SIZE;
    use crate::geometry::Redundancy;
    use crate::record::{self, DecodeLimits};
    use crate::rolling_page::Table as RollingTable;
    use std::io::Cursor;

    fn fixture() -> Manifest {
        let chunk_size = ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap();
        let bytes = vec![0x5a; usize::try_from(MIN_CHUNK_SIZE).unwrap() + 17];
        let fingerprint = fingerprint::source(&mut Cursor::new(bytes), chunk_size).unwrap();
        let geometry = Geometry::new(
            fingerprint.source_len,
            chunk_size,
            Redundancy::new(1, 2).unwrap(),
        )
        .unwrap();
        let rolling_table = RollingTable::new(fingerprint.full_chunk_rolling).unwrap();
        let data_table = Table::new(Kind::Data, fingerprint.data_chunk_digests).unwrap();
        let recovery_table = Table::new(
            Kind::Recovery,
            vec![Digest::from_bytes([0xa5; 32]); geometry.recovery_chunks as usize],
        )
        .unwrap();
        Manifest::new(
            geometry,
            fingerprint.source_digest,
            &data_table,
            &recovery_table,
            &rolling_table,
        )
        .unwrap()
    }

    #[test]
    fn manifest_round_trips_through_physical_record_codec() {
        let manifest = fixture();
        let mut encoded = Vec::new();
        record::write(&mut encoded, &manifest.to_record()).unwrap();
        assert_eq!(encoded.len() as u64, ENCODED_RECORD_LEN);
        let record = record::read(
            &mut Cursor::new(encoded),
            DecodeLimits::new(record::BASE_HEADER_LEN, PAYLOAD_LEN as u64),
        )
        .unwrap()
        .unwrap();

        assert_eq!(Manifest::from_record(&record).unwrap(), manifest);
        assert_eq!(record.protection_set_id, manifest.protection_set_id());
    }

    #[test]
    fn table_kinds_and_counts_must_match_geometry() {
        let manifest = fixture();
        let geometry = manifest.geometry();
        let data = Table::new(Kind::Data, vec![Digest::from_bytes([1; 32])]).unwrap();
        let recovery = Table::new(
            Kind::Recovery,
            vec![Digest::from_bytes([2; 32]); geometry.recovery_chunks as usize],
        )
        .unwrap();
        let rolling = RollingTable::new(vec![7]).unwrap();
        assert!(matches!(
            Manifest::new(
                geometry,
                manifest.source_digest(),
                &data,
                &recovery,
                &rolling
            ),
            Err(Error::DigestCountMismatch {
                kind: Kind::Data,
                ..
            })
        ));
        assert!(matches!(
            Manifest::new(
                geometry,
                manifest.source_digest(),
                &recovery,
                &data,
                &rolling
            ),
            Err(Error::WrongTableKind { .. })
        ));
        let empty_rolling = RollingTable::new(Vec::new()).unwrap();
        assert!(matches!(
            Manifest::new(
                geometry,
                manifest.source_digest(),
                &Table::new(
                    Kind::Data,
                    vec![Digest::from_bytes([1; 32]); geometry.data_chunks as usize]
                )
                .unwrap(),
                &recovery,
                &empty_rolling
            ),
            Err(Error::RollingCountMismatch { .. })
        ));
    }

    #[test]
    fn decoder_rejects_noncanonical_metadata_and_identity() {
        let manifest = fixture();
        let canonical = manifest.to_record();

        let mut wrong_type = canonical.clone();
        wrong_type.record_type = 9;
        assert!(matches!(
            Manifest::from_record(&wrong_type),
            Err(Error::WrongRecordType(9))
        ));
        let mut wrong_flags = canonical.clone();
        wrong_flags.flags = 0;
        assert!(matches!(
            Manifest::from_record(&wrong_flags),
            Err(Error::InvalidRecordFlags(0))
        ));
        let mut wrong_id = canonical.clone();
        wrong_id.protection_set_id[0] ^= 1;
        assert!(matches!(
            Manifest::from_record(&wrong_id),
            Err(Error::ProtectionSetIdMismatch { .. })
        ));
        let mut extension = canonical.clone();
        extension.header_extension.push(0);
        assert!(matches!(
            Manifest::from_record(&extension),
            Err(Error::UnsupportedHeaderExtension)
        ));
    }

    #[test]
    fn decoder_rejects_unknown_algorithms_reserved_bytes_and_bad_geometry() {
        let canonical = fixture().to_record();
        for (offset, error) in [
            (
                4,
                Error::UnsupportedAlgorithm {
                    name: "coding",
                    actual: 2,
                },
            ),
            (
                6,
                Error::UnsupportedAlgorithm {
                    name: "strong hash",
                    actual: 2,
                },
            ),
            (
                8,
                Error::UnsupportedAlgorithm {
                    name: "rolling",
                    actual: 2,
                },
            ),
        ] {
            let mut record = canonical.clone();
            record.payload[offset..offset + 2].copy_from_slice(&2_u16.to_le_bytes());
            assert_eq!(
                Manifest::from_record(&record).unwrap_err().to_string(),
                error.to_string()
            );
        }

        let mut features = canonical.clone();
        features.payload[2] = 1;
        assert!(matches!(
            Manifest::from_record(&features),
            Err(Error::UnsupportedRequiredFeatures(1))
        ));
        let mut reserved = canonical.clone();
        reserved.payload[10] = 1;
        assert!(matches!(
            Manifest::from_record(&reserved),
            Err(Error::ReservedField)
        ));
        let mut bad_count = canonical;
        bad_count.payload[24..28].copy_from_slice(&3_u32.to_le_bytes());
        assert!(matches!(
            Manifest::from_record(&bad_count),
            Err(Error::InvalidGeometry(
                GeometryError::DataChunkCountMismatch { .. }
            ))
        ));
    }

    #[test]
    fn recovery_digests_do_not_change_source_set_identity() {
        let manifest = fixture();
        let mut changed_record = manifest.to_record();
        changed_record.payload[120] ^= 1;
        let changed = Manifest::from_record(&changed_record).unwrap();
        assert_eq!(changed.protection_set_id(), manifest.protection_set_id());
        assert_ne!(
            changed.recovery_table_root(),
            manifest.recovery_table_root()
        );
        assert_eq!(manifest.geometry(), changed.geometry());
    }

    #[test]
    fn rolling_table_does_not_change_source_set_identity() {
        let manifest = fixture();
        let mut changed_record = manifest.to_record();
        changed_record.payload[160] ^= 1;
        let changed = Manifest::from_record(&changed_record).unwrap();
        assert_eq!(changed.protection_set_id(), manifest.protection_set_id());
        assert_ne!(changed.rolling_table_root(), manifest.rolling_table_root());
    }

    #[test]
    fn exact_final_chunk_requires_its_rolling_value() {
        let chunk_size = ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap();
        let geometry = Geometry::new(
            u64::from(MIN_CHUNK_SIZE) * 2,
            chunk_size,
            Redundancy::new(1, 2).unwrap(),
        )
        .unwrap();
        assert_eq!(geometry.full_data_chunks(), 2);

        let data = Table::new(
            Kind::Data,
            vec![Digest::from_bytes([1; 32]); geometry.data_chunks as usize],
        )
        .unwrap();
        let recovery = Table::new(
            Kind::Recovery,
            vec![Digest::from_bytes([2; 32]); geometry.recovery_chunks as usize],
        )
        .unwrap();
        let short = RollingTable::new(vec![7]).unwrap();
        assert!(matches!(
            Manifest::new(
                geometry,
                Digest::from_bytes([3; 32]),
                &data,
                &recovery,
                &short
            ),
            Err(Error::RollingCountMismatch {
                actual: 1,
                expected: 2
            })
        ));
    }

    #[test]
    fn protection_identity_changes_with_source_or_coding_parameters() {
        let manifest = fixture();
        let mut changed_source = manifest.to_record();
        changed_source.payload[40] ^= 1;
        changed_source.protection_set_id = set_id(
            manifest.geometry(),
            digest(&changed_source.payload, 40).unwrap(),
            manifest.data_table_root(),
        );
        let changed_source = Manifest::from_record(&changed_source).unwrap();
        assert_ne!(
            changed_source.protection_set_id(),
            manifest.protection_set_id()
        );

        let mut changed_root = manifest.to_record();
        changed_root.payload[80] ^= 1;
        changed_root.protection_set_id = set_id(
            manifest.geometry(),
            manifest.source_digest(),
            digest(&changed_root.payload, 80).unwrap(),
        );
        let changed_root = Manifest::from_record(&changed_root).unwrap();
        assert_ne!(
            changed_root.protection_set_id(),
            manifest.protection_set_id()
        );

        let geometry = manifest.geometry();
        let changed_geometry = Geometry::from_stored(
            geometry.source_len,
            geometry.chunk_size,
            geometry.data_chunks,
            geometry.recovery_chunks + 1,
            geometry.final_data_chunk_len,
        )
        .unwrap();
        let mut changed_coding = manifest.to_record();
        changed_coding.payload[28..32]
            .copy_from_slice(&changed_geometry.recovery_chunks.to_le_bytes());
        changed_coding.payload[112..120]
            .copy_from_slice(&u64::from(changed_geometry.recovery_chunks).to_le_bytes());
        changed_coding.protection_set_id = set_id(
            changed_geometry,
            manifest.source_digest(),
            manifest.data_table_root(),
        );
        let changed_coding = Manifest::from_record(&changed_coding).unwrap();
        assert_ne!(
            changed_coding.protection_set_id(),
            manifest.protection_set_id()
        );
    }
}
