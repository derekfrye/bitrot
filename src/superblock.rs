//! Compact duplicated entry points for locating and authenticating metadata.

use crate::manifest::Manifest;
use crate::record::{FLAG_REQUIRED, Record};
use crate::wire;
use std::fmt;

pub const RECORD_TYPE: u16 = 1;
pub const PAYLOAD_VERSION: u16 = 1;
pub const PAYLOAD_LEN: usize = 64;

const MANIFEST_COMMITMENT_CONTEXT: &str = "bitrot format v1 core manifest commitment";
const CORE_MANIFEST_RECORD_LEN: u64 = 296;

/// Advisory locations for two exact copies of a committed core manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
    protection_set_id: [u8; 32],
    first_manifest_offset: u64,
    second_manifest_offset: u64,
    observed_sidecar_len: u64,
    manifest_commitment: [u8; 32],
}

impl Superblock {
    /// Constructs a superblock containing two bounded manifest-location hints.
    ///
    /// `observed_sidecar_len` is the file length when the hints were written,
    /// not an authoritative current length after later appends.
    ///
    /// # Errors
    ///
    /// Returns an error unless both complete core-manifest records fit within
    /// the observed length and the first hint precedes the second.
    pub fn new(
        manifest: Manifest,
        first_manifest_offset: u64,
        second_manifest_offset: u64,
        observed_sidecar_len: u64,
    ) -> Result<Self, Error> {
        validate_hints(
            first_manifest_offset,
            second_manifest_offset,
            observed_sidecar_len,
        )?;
        Ok(Self {
            protection_set_id: manifest.protection_set_id(),
            first_manifest_offset,
            second_manifest_offset,
            observed_sidecar_len,
            manifest_commitment: manifest_commitment(manifest),
        })
    }

    #[must_use]
    pub const fn protection_set_id(self) -> [u8; 32] {
        self.protection_set_id
    }

    #[must_use]
    pub const fn first_manifest_offset(self) -> u64 {
        self.first_manifest_offset
    }

    #[must_use]
    pub const fn second_manifest_offset(self) -> u64 {
        self.second_manifest_offset
    }

    #[must_use]
    pub const fn observed_sidecar_len(self) -> u64 {
        self.observed_sidecar_len
    }

    /// Returns whether the superblock commits to this exact core manifest.
    #[must_use]
    pub fn matches_manifest(self, manifest: Manifest) -> bool {
        self.protection_set_id == manifest.protection_set_id()
            && self.manifest_commitment == manifest_commitment(manifest)
    }

    /// Encodes this superblock as a canonical required record.
    #[must_use]
    pub fn to_record(self) -> Record {
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.extend_from_slice(&PAYLOAD_VERSION.to_le_bytes());
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        payload.extend_from_slice(&self.first_manifest_offset.to_le_bytes());
        payload.extend_from_slice(&self.second_manifest_offset.to_le_bytes());
        payload.extend_from_slice(&self.observed_sidecar_len.to_le_bytes());
        payload.extend_from_slice(&self.manifest_commitment);
        debug_assert_eq!(payload.len(), PAYLOAD_LEN);
        Record {
            record_type: RECORD_TYPE,
            flags: FLAG_REQUIRED,
            protection_set_id: self.protection_set_id,
            logical_id: 0,
            header_extension: Vec::new(),
            payload,
        }
    }

    /// Strictly decodes a canonical superblock record.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid frame metadata, unsupported features,
    /// malformed location hints, or a noncanonical payload.
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
        if parse_u32(&record.payload, 4)? != 0 {
            return Err(Error::ReservedField);
        }
        let first_manifest_offset = parse_u64(&record.payload, 8)?;
        let second_manifest_offset = parse_u64(&record.payload, 16)?;
        let observed_sidecar_len = parse_u64(&record.payload, 24)?;
        validate_hints(
            first_manifest_offset,
            second_manifest_offset,
            observed_sidecar_len,
        )?;
        let manifest_commitment = wire::array(&record.payload, 32)
            .ok_or_else(|| invalid_payload_length(&record.payload))?;
        Ok(Self {
            protection_set_id: record.protection_set_id,
            first_manifest_offset,
            second_manifest_offset,
            observed_sidecar_len,
            manifest_commitment,
        })
    }

    /// Reconciles all superblock copies and authenticates `manifest`.
    ///
    /// Records of other types are ignored. Identical copies collapse; valid
    /// copies with different logical contents are never guessed between.
    ///
    /// # Errors
    ///
    /// Returns an error for too many, absent, invalid, conflicting, or
    /// manifest-inconsistent superblock copies.
    pub fn assemble(
        records: &[Record],
        manifest: Manifest,
        max_copies: u32,
    ) -> Result<Self, AssemblyError> {
        let mut superblock = None;
        let mut copies = 0_u64;
        for record in records
            .iter()
            .filter(|record| record.record_type == RECORD_TYPE)
        {
            copies = copies.saturating_add(1);
            if copies > u64::from(max_copies) {
                return Err(AssemblyError::CopyLimitExceeded {
                    actual: copies,
                    maximum: max_copies,
                });
            }
            let candidate = Self::from_record(record).map_err(AssemblyError::InvalidCopy)?;
            if let Some(existing) = superblock {
                if existing != candidate {
                    return Err(AssemblyError::ConflictingCopies);
                }
            } else {
                superblock = Some(candidate);
            }
        }
        let superblock = superblock.ok_or(AssemblyError::Missing)?;
        if !superblock.matches_manifest(manifest) {
            return Err(AssemblyError::ManifestMismatch);
        }
        Ok(superblock)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongRecordType(u16),
    InvalidRecordFlags(u32),
    InvalidLogicalId(u64),
    UnsupportedHeaderExtension,
    PayloadLengthMismatch { actual: usize, expected: usize },
    UnsupportedPayloadVersion(u16),
    UnsupportedRequiredFeatures(u16),
    ReservedField,
    ManifestOffsetsNotAscending { first: u64, second: u64 },
    ManifestRecordOutsideObservedLength { offset: u64, observed_len: u64 },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRecordType(actual) => {
                write!(formatter, "record type {actual} is not a superblock")
            }
            Self::InvalidRecordFlags(actual) => {
                write!(formatter, "superblock record has invalid flags {actual:#x}")
            }
            Self::InvalidLogicalId(actual) => write!(
                formatter,
                "superblock logical identifier must be zero, got {actual}"
            ),
            Self::UnsupportedHeaderExtension => {
                formatter.write_str("superblock has an unsupported header extension")
            }
            Self::PayloadLengthMismatch { actual, expected } => write!(
                formatter,
                "superblock payload length is {actual}, expected {expected}"
            ),
            Self::UnsupportedPayloadVersion(version) => write!(
                formatter,
                "unsupported superblock payload version {version}"
            ),
            Self::UnsupportedRequiredFeatures(features) => write!(
                formatter,
                "unsupported superblock required features {features:#x}"
            ),
            Self::ReservedField => {
                formatter.write_str("superblock payload has a nonzero reserved field")
            }
            Self::ManifestOffsetsNotAscending { first, second } => write!(
                formatter,
                "superblock manifest offsets are not ascending: {first}, {second}"
            ),
            Self::ManifestRecordOutsideObservedLength {
                offset,
                observed_len,
            } => write!(
                formatter,
                "core manifest at offset {offset} does not fit observed sidecar length {observed_len}"
            ),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
pub enum AssemblyError {
    CopyLimitExceeded { actual: u64, maximum: u32 },
    Missing,
    InvalidCopy(Error),
    ConflictingCopies,
    ManifestMismatch,
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CopyLimitExceeded { actual, maximum } => write!(
                formatter,
                "superblock copy count {actual} exceeds limit {maximum}"
            ),
            Self::Missing => formatter.write_str("superblock is missing"),
            Self::InvalidCopy(error) => write!(formatter, "invalid superblock copy: {error}"),
            Self::ConflictingCopies => formatter.write_str("valid superblock copies conflict"),
            Self::ManifestMismatch => {
                formatter.write_str("superblock does not commit to the assembled core manifest")
            }
        }
    }
}

impl std::error::Error for AssemblyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCopy(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_hints(first: u64, second: u64, observed_len: u64) -> Result<(), Error> {
    if first >= second {
        return Err(Error::ManifestOffsetsNotAscending { first, second });
    }
    for offset in [first, second] {
        let end = offset.checked_add(CORE_MANIFEST_RECORD_LEN).ok_or(
            Error::ManifestRecordOutsideObservedLength {
                offset,
                observed_len,
            },
        )?;
        if end > observed_len {
            return Err(Error::ManifestRecordOutsideObservedLength {
                offset,
                observed_len,
            });
        }
    }
    Ok(())
}

fn manifest_commitment(manifest: Manifest) -> [u8; 32] {
    let record = manifest.to_record();
    let mut hasher = blake3::Hasher::new_derive_key(MANIFEST_COMMITMENT_CONTEXT);
    hasher.update(&record.protection_set_id);
    hasher.update(&record.payload);
    hasher.finalize().into()
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

fn invalid_payload_length(bytes: &[u8]) -> Error {
    Error::PayloadLengthMismatch {
        actual: bytes.len(),
        expected: PAYLOAD_LEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Digest;
    use crate::digest_page::{Kind, Table};
    use crate::geometry::Geometry;
    use crate::geometry::{ChunkSize, MIN_CHUNK_SIZE};
    use crate::record::{self, BASE_HEADER_LEN, DecodeLimits};
    use crate::rolling_page;
    use std::io::Cursor;

    const FIRST: u64 = 200;
    const SECOND: u64 = 10_000;
    const LENGTH: u64 = 20_000;
    type Mutation = Box<dyn Fn(&mut Record)>;

    fn test_manifest(seed: u8) -> Manifest {
        let size = ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap();
        let geometry =
            Geometry::from_stored(u64::from(size.bytes()), size, 1, 1, size.bytes()).unwrap();
        let data = Table::new(Kind::Data, vec![Digest::from_bytes([seed; 32])]).unwrap();
        let recovery = Table::new(Kind::Recovery, vec![Digest::from_bytes([2; 32])]).unwrap();
        let rolling = rolling_page::Table::new(vec![3]).unwrap();
        Manifest::new(
            geometry,
            Digest::from_bytes([4; 32]),
            &data,
            &recovery,
            &rolling,
        )
        .unwrap()
    }

    fn fixture(manifest: Manifest) -> Superblock {
        Superblock::new(manifest, FIRST, SECOND, LENGTH).unwrap()
    }

    #[test]
    fn round_trips_through_physical_record_codec() {
        let manifest = test_manifest(1);
        let expected = fixture(manifest);
        let record = expected.to_record();
        let mut encoded = Vec::new();
        record::write(&mut encoded, &record).unwrap();
        let decoded = record::read(
            &mut Cursor::new(encoded),
            DecodeLimits::new(BASE_HEADER_LEN, u64::try_from(PAYLOAD_LEN).unwrap()),
        )
        .unwrap()
        .unwrap();
        let actual = Superblock::from_record(&decoded).unwrap();
        assert_eq!(actual, expected);
        assert!(actual.matches_manifest(manifest));
    }

    #[test]
    fn rejects_invalid_location_hints() {
        let manifest = test_manifest(1);
        assert!(matches!(
            Superblock::new(manifest, SECOND, FIRST, LENGTH),
            Err(Error::ManifestOffsetsNotAscending { .. })
        ));
        assert!(matches!(
            Superblock::new(manifest, FIRST, SECOND, SECOND),
            Err(Error::ManifestRecordOutsideObservedLength { .. })
        ));
        assert!(matches!(
            Superblock::new(manifest, FIRST, u64::MAX - 1, u64::MAX),
            Err(Error::ManifestRecordOutsideObservedLength { .. })
        ));
    }

    #[test]
    fn decoder_rejects_noncanonical_records() {
        let manifest = test_manifest(1);
        let record = fixture(manifest).to_record();
        let mutations: Vec<Mutation> = vec![
            Box::new(|record| record.record_type = 99),
            Box::new(|record| record.flags = 0),
            Box::new(|record| record.logical_id = 1),
            Box::new(|record| record.header_extension.push(1)),
            Box::new(|record| record.payload.truncate(PAYLOAD_LEN - 1)),
            Box::new(|record| record.payload[0] = 2),
            Box::new(|record| record.payload[2] = 1),
            Box::new(|record| record.payload[4] = 1),
            Box::new(|record| record.payload[16..24].copy_from_slice(&FIRST.to_le_bytes())),
        ];
        for mutate in mutations {
            let mut changed = record.clone();
            mutate(&mut changed);
            assert!(Superblock::from_record(&changed).is_err());
        }
    }

    #[test]
    fn assembly_reconciles_copies_and_manifest() {
        let manifest = test_manifest(1);
        let record = fixture(manifest).to_record();
        assert_eq!(
            Superblock::assemble(&[record.clone(), record.clone()], manifest, 2).unwrap(),
            fixture(manifest)
        );
        assert!(matches!(
            Superblock::assemble(&[], manifest, 2),
            Err(AssemblyError::Missing)
        ));
        assert!(matches!(
            Superblock::assemble(&[record.clone(), record.clone()], manifest, 1),
            Err(AssemblyError::CopyLimitExceeded { .. })
        ));

        let changed = Superblock::new(manifest, FIRST + 1, SECOND, LENGTH)
            .unwrap()
            .to_record();
        assert!(matches!(
            Superblock::assemble(&[record.clone(), changed], manifest, 2),
            Err(AssemblyError::ConflictingCopies)
        ));
        assert!(matches!(
            Superblock::assemble(&[record], test_manifest(9), 2),
            Err(AssemblyError::ManifestMismatch)
        ));
    }
}
