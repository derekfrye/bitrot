//! Canonical records containing one complete recovery shard.

use crate::algorithm::CODING_LEOPARD_GF16;
use crate::digest::Digest;
use crate::fingerprint::recovery_chunk_digest;
use crate::manifest::Manifest;
use crate::record::{FLAG_REQUIRED, Record};
use crate::wire;
use std::fmt;

pub const RECORD_TYPE: u16 = 5;
pub const PAYLOAD_VERSION: u16 = 1;
pub const PAYLOAD_HEADER_LEN: usize = 32;

/// One complete, full-size parity shard in recovery-index order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryChunk {
    recovery_index: u32,
    bytes: Vec<u8>,
}

impl RecoveryChunk {
    /// Constructs a recovery chunk for `manifest`.
    ///
    /// # Errors
    ///
    /// Returns an error when the index is outside the recovery geometry or the
    /// parity bytes are not exactly one data-chunk long.
    pub fn new(manifest: Manifest, recovery_index: u32, bytes: Vec<u8>) -> Result<Self, Error> {
        validate_index(manifest, recovery_index)?;
        validate_length(manifest, bytes.len())?;
        Ok(Self {
            recovery_index,
            bytes,
        })
    }

    #[must_use]
    pub const fn recovery_index(&self) -> u32 {
        self.recovery_index
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        recovery_chunk_digest(&self.bytes)
    }

    /// Encodes this shard as a canonical required recovery record.
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk no longer agrees with `manifest`.
    pub fn to_record(&self, manifest: Manifest) -> Result<Record, Error> {
        validate_index(manifest, self.recovery_index)?;
        validate_length(manifest, self.bytes.len())?;
        let geometry = manifest.geometry();
        let mut payload = Vec::with_capacity(PAYLOAD_HEADER_LEN + self.bytes.len());
        payload.extend_from_slice(&PAYLOAD_VERSION.to_le_bytes());
        payload.extend_from_slice(&CODING_LEOPARD_GF16.to_le_bytes());
        payload.extend_from_slice(&self.recovery_index.to_le_bytes());
        payload.extend_from_slice(&geometry.data_chunks.to_le_bytes());
        payload.extend_from_slice(&geometry.recovery_chunks.to_le_bytes());
        payload.extend_from_slice(&geometry.chunk_size.bytes().to_le_bytes());
        payload.extend_from_slice(&geometry.chunk_size.bytes().to_le_bytes());
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(&self.bytes);

        Ok(Record::required(
            RECORD_TYPE,
            manifest.protection_set_id(),
            u64::from(self.recovery_index),
            payload,
        ))
    }

    /// Strictly decodes and authenticates a recovery record against a manifest.
    ///
    /// `expected_digest` is the value at this recovery index in the manifest's
    /// assembled recovery digest table.
    ///
    /// # Errors
    ///
    /// Returns an error unless the frame metadata, duplicated coding geometry,
    /// payload length, and strong recovery digest all agree.
    pub fn from_record(
        record: &Record,
        manifest: Manifest,
        expected_digest: Digest,
    ) -> Result<Self, Error> {
        if record.record_type != RECORD_TYPE {
            return Err(Error::WrongRecordType(record.record_type));
        }
        if record.flags != FLAG_REQUIRED {
            return Err(Error::InvalidRecordFlags(record.flags));
        }
        if record.protection_set_id != manifest.protection_set_id() {
            return Err(Error::ProtectionSetIdMismatch);
        }
        if !record.header_extension.is_empty() {
            return Err(Error::UnsupportedHeaderExtension);
        }
        if record.payload.len() < PAYLOAD_HEADER_LEN {
            return Err(Error::TruncatedPayload);
        }

        let version = parse_u16(&record.payload, 0)?;
        if version != PAYLOAD_VERSION {
            return Err(Error::UnsupportedPayloadVersion(version));
        }
        let coding_algorithm = parse_u16(&record.payload, 2)?;
        if coding_algorithm != CODING_LEOPARD_GF16 {
            return Err(Error::UnsupportedCodingAlgorithm(coding_algorithm));
        }

        let recovery_index = parse_u32(&record.payload, 4)?;
        validate_index(manifest, recovery_index)?;
        if record.logical_id != u64::from(recovery_index) {
            return Err(Error::LogicalIdMismatch);
        }

        let geometry = manifest.geometry();
        validate_field(
            "data chunk count",
            parse_u32(&record.payload, 8)?,
            geometry.data_chunks,
        )?;
        validate_field(
            "recovery chunk count",
            parse_u32(&record.payload, 12)?,
            geometry.recovery_chunks,
        )?;
        validate_field(
            "chunk size",
            parse_u32(&record.payload, 16)?,
            geometry.chunk_size.bytes(),
        )?;
        validate_field(
            "logical length",
            parse_u32(&record.payload, 20)?,
            geometry.chunk_size.bytes(),
        )?;
        if parse_u64(&record.payload, 24)? != 0 {
            return Err(Error::ReservedField);
        }

        let bytes = &record.payload[PAYLOAD_HEADER_LEN..];
        validate_length(manifest, bytes.len())?;
        if recovery_chunk_digest(bytes) != expected_digest {
            return Err(Error::DigestMismatch);
        }
        Ok(Self {
            recovery_index,
            bytes: bytes.to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongRecordType(u16),
    InvalidRecordFlags(u32),
    ProtectionSetIdMismatch,
    UnsupportedHeaderExtension,
    TruncatedPayload,
    UnsupportedPayloadVersion(u16),
    UnsupportedCodingAlgorithm(u16),
    RecoveryIndexOutOfRange {
        index: u32,
        count: u32,
    },
    LogicalIdMismatch,
    GeometryMismatch {
        field: &'static str,
        actual: u32,
        expected: u32,
    },
    ReservedField,
    PayloadLengthMismatch {
        actual: usize,
        expected: usize,
    },
    DigestMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRecordType(actual) => {
                write!(formatter, "record type {actual} is not a recovery chunk")
            }
            Self::InvalidRecordFlags(actual) => {
                write!(formatter, "recovery record has invalid flags {actual:#x}")
            }
            Self::ProtectionSetIdMismatch => {
                formatter.write_str("recovery record belongs to a different protection set")
            }
            Self::UnsupportedHeaderExtension => {
                formatter.write_str("recovery record has an unsupported header extension")
            }
            Self::TruncatedPayload => formatter.write_str("recovery payload is truncated"),
            Self::UnsupportedPayloadVersion(version) => {
                write!(formatter, "unsupported recovery payload version {version}")
            }
            Self::UnsupportedCodingAlgorithm(algorithm) => {
                write!(
                    formatter,
                    "unsupported recovery coding algorithm {algorithm}"
                )
            }
            Self::RecoveryIndexOutOfRange { index, count } => {
                write!(
                    formatter,
                    "recovery index {index} is outside chunk count {count}"
                )
            }
            Self::LogicalIdMismatch => {
                formatter.write_str("recovery logical identifier does not match its payload")
            }
            Self::GeometryMismatch {
                field,
                actual,
                expected,
            } => write!(
                formatter,
                "recovery {field} is {actual}, expected {expected} from manifest"
            ),
            Self::ReservedField => {
                formatter.write_str("recovery payload has a nonzero reserved field")
            }
            Self::PayloadLengthMismatch { actual, expected } => write!(
                formatter,
                "recovery parity length is {actual}, expected {expected}"
            ),
            Self::DigestMismatch => {
                formatter.write_str("recovery chunk digest does not match manifest table")
            }
        }
    }
}

impl std::error::Error for Error {}

fn validate_index(manifest: Manifest, index: u32) -> Result<(), Error> {
    let count = manifest.geometry().recovery_chunks;
    if index < count {
        Ok(())
    } else {
        Err(Error::RecoveryIndexOutOfRange { index, count })
    }
}

fn validate_length(manifest: Manifest, actual: usize) -> Result<(), Error> {
    let expected = manifest.geometry().chunk_size.bytes() as usize;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::PayloadLengthMismatch { actual, expected })
    }
}

fn validate_field(field: &'static str, actual: u32, expected: u32) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::GeometryMismatch {
            field,
            actual,
            expected,
        })
    }
}

fn parse_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    wire::u16(bytes, offset).ok_or(Error::TruncatedPayload)
}

fn parse_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    wire::u32(bytes, offset).ok_or(Error::TruncatedPayload)
}

fn parse_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    wire::u64(bytes, offset).ok_or(Error::TruncatedPayload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{self, BASE_HEADER_LEN, DecodeLimits};
    use crate::test_support;
    use std::io::Cursor;

    fn fixture() -> (Manifest, RecoveryChunk) {
        let fixture = test_support::recovery_fixture();
        let manifest = fixture.metadata.manifest;
        let chunk = fixture.recovery_chunks[0].clone();
        (manifest, chunk)
    }

    #[test]
    fn record_round_trip_authenticates_parity() {
        let (manifest, expected) = fixture();
        let record = expected.to_record(manifest).unwrap();
        assert_eq!(record.record_type, RECORD_TYPE);
        assert_eq!(record.logical_id, 0);
        assert_eq!(
            record.payload.len(),
            PAYLOAD_HEADER_LEN + expected.bytes.len()
        );

        let payload_limit = u64::try_from(record.payload.len()).unwrap();
        let mut encoded = Vec::new();
        record::write(&mut encoded, &record).unwrap();
        let decoded_record = record::read(
            &mut Cursor::new(encoded),
            DecodeLimits::new(BASE_HEADER_LEN, payload_limit),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            RecoveryChunk::from_record(&decoded_record, manifest, expected.digest()).unwrap(),
            expected
        );
    }

    #[test]
    fn constructor_rejects_bad_index_and_length() {
        let (manifest, chunk) = fixture();
        assert!(matches!(
            RecoveryChunk::new(manifest, 2, chunk.bytes.clone()),
            Err(Error::RecoveryIndexOutOfRange { .. })
        ));
        assert!(matches!(
            RecoveryChunk::new(manifest, 0, vec![0; chunk.bytes.len() - 1]),
            Err(Error::PayloadLengthMismatch { .. })
        ));
    }

    #[test]
    fn decoder_rejects_noncanonical_frame_metadata() {
        let (manifest, chunk) = fixture();
        let record = chunk.to_record(manifest).unwrap();

        let mut wrong_type = record.clone();
        wrong_type.record_type = 99;
        assert!(matches!(
            RecoveryChunk::from_record(&wrong_type, manifest, chunk.digest()),
            Err(Error::WrongRecordType(99))
        ));

        let mut wrong_flags = record.clone();
        wrong_flags.flags = 0;
        assert!(matches!(
            RecoveryChunk::from_record(&wrong_flags, manifest, chunk.digest()),
            Err(Error::InvalidRecordFlags(0))
        ));

        let mut wrong_set = record.clone();
        wrong_set.protection_set_id[0] ^= 1;
        assert!(matches!(
            RecoveryChunk::from_record(&wrong_set, manifest, chunk.digest()),
            Err(Error::ProtectionSetIdMismatch)
        ));

        let mut extension = record.clone();
        extension.header_extension.push(1);
        assert!(matches!(
            RecoveryChunk::from_record(&extension, manifest, chunk.digest()),
            Err(Error::UnsupportedHeaderExtension)
        ));
    }

    #[test]
    fn decoder_rejects_noncanonical_payload_metadata() {
        let (manifest, chunk) = fixture();
        let record = chunk.to_record(manifest).unwrap();

        for (offset, value) in [(0, 2_u16), (2, 2_u16)] {
            let mut changed = record.clone();
            changed.payload[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            assert!(RecoveryChunk::from_record(&changed, manifest, chunk.digest()).is_err());
        }

        let mut logical_id = record.clone();
        logical_id.logical_id = 1;
        assert!(matches!(
            RecoveryChunk::from_record(&logical_id, manifest, chunk.digest()),
            Err(Error::LogicalIdMismatch)
        ));

        for offset in [8, 12, 16, 20] {
            let mut changed = record.clone();
            changed.payload[offset..offset + 4].copy_from_slice(&99_u32.to_le_bytes());
            assert!(matches!(
                RecoveryChunk::from_record(&changed, manifest, chunk.digest()),
                Err(Error::GeometryMismatch { .. })
            ));
        }

        let mut reserved = record.clone();
        reserved.payload[24] = 1;
        assert!(matches!(
            RecoveryChunk::from_record(&reserved, manifest, chunk.digest()),
            Err(Error::ReservedField)
        ));
    }

    #[test]
    fn decoder_rejects_truncation_and_digest_substitution() {
        let (manifest, chunk) = fixture();
        let record = chunk.to_record(manifest).unwrap();

        let mut short_header = record.clone();
        short_header.payload.truncate(PAYLOAD_HEADER_LEN - 1);
        assert!(matches!(
            RecoveryChunk::from_record(&short_header, manifest, chunk.digest()),
            Err(Error::TruncatedPayload)
        ));

        let mut short_parity = record.clone();
        short_parity.payload.pop();
        assert!(matches!(
            RecoveryChunk::from_record(&short_parity, manifest, chunk.digest()),
            Err(Error::PayloadLengthMismatch { .. })
        ));

        let mut substituted = record;
        substituted.payload[PAYLOAD_HEADER_LEN] ^= 1;
        assert!(matches!(
            RecoveryChunk::from_record(&substituted, manifest, chunk.digest()),
            Err(Error::DigestMismatch)
        ));
    }
}
