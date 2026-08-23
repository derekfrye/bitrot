//! Diagnostic identification of the implementation that created a sidecar.

use crate::agreed_copies;
use crate::record::{FLAG_REQUIRED, Record};
use crate::wire;
use std::fmt;

pub const RECORD_TYPE: u16 = 6;
pub const PAYLOAD_VERSION: u16 = 1;
pub const PAYLOAD_HEADER_LEN: usize = 16;
pub const MAX_FIELD_LEN: usize = 255;

/// Human-readable implementation identification stored in a protection set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Creator {
    implementation: String,
    version: String,
}

impl Creator {
    /// Constructs diagnostic creator metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if either field is empty, too long, or contains a
    /// control character.
    pub fn new(
        implementation: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, Error> {
        let implementation = implementation.into();
        let version = version.into();
        validate_field(Field::Implementation, &implementation)?;
        validate_field(Field::Version, &version)?;
        Ok(Self {
            implementation,
            version,
        })
    }

    #[must_use]
    pub fn implementation(&self) -> &str {
        &self.implementation
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Encodes this identification as a canonical required creator record.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored fields no longer satisfy the canonical
    /// bounds.
    pub fn to_record(&self, protection_set_id: [u8; 32]) -> Result<Record, Error> {
        validate_field(Field::Implementation, &self.implementation)?;
        validate_field(Field::Version, &self.version)?;
        let implementation_len =
            u16::try_from(self.implementation.len()).map_err(|_| Error::LengthOverflow)?;
        let version_len = u16::try_from(self.version.len()).map_err(|_| Error::LengthOverflow)?;
        let mut payload =
            Vec::with_capacity(PAYLOAD_HEADER_LEN + self.implementation.len() + self.version.len());
        payload.extend_from_slice(&PAYLOAD_VERSION.to_le_bytes());
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(&implementation_len.to_le_bytes());
        payload.extend_from_slice(&version_len.to_le_bytes());
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(self.implementation.as_bytes());
        payload.extend_from_slice(self.version.as_bytes());

        Ok(Record::required(RECORD_TYPE, protection_set_id, 0, payload))
    }

    /// Strictly decodes a creator record for `expected_protection_set_id`.
    ///
    /// # Errors
    ///
    /// Returns an error unless the frame metadata and canonical payload are
    /// valid and belong to the expected protection set.
    pub fn from_record(
        record: &Record,
        expected_protection_set_id: [u8; 32],
    ) -> Result<Self, Error> {
        if record.record_type != RECORD_TYPE {
            return Err(Error::WrongRecordType(record.record_type));
        }
        if record.flags != FLAG_REQUIRED {
            return Err(Error::InvalidRecordFlags(record.flags));
        }
        if record.protection_set_id != expected_protection_set_id {
            return Err(Error::ProtectionSetIdMismatch);
        }
        if record.logical_id != 0 {
            return Err(Error::InvalidLogicalId(record.logical_id));
        }
        if !record.header_extension.is_empty() {
            return Err(Error::UnsupportedHeaderExtension);
        }
        if record.payload.len() < PAYLOAD_HEADER_LEN {
            return Err(Error::TruncatedPayload);
        }
        let payload = wire::Reader::new(&record.payload, || Error::TruncatedPayload);
        let version = payload.u16(0)?;
        if version != PAYLOAD_VERSION {
            return Err(Error::UnsupportedPayloadVersion(version));
        }
        if payload.u16(2)? != 0 || payload.u64(8)? != 0 {
            return Err(Error::ReservedField);
        }

        let implementation_len = usize::from(payload.u16(4)?);
        let version_len = usize::from(payload.u16(6)?);
        let expected_len = PAYLOAD_HEADER_LEN
            .checked_add(implementation_len)
            .and_then(|len| len.checked_add(version_len))
            .ok_or(Error::LengthOverflow)?;
        if record.payload.len() != expected_len {
            return Err(Error::PayloadLengthMismatch {
                actual: record.payload.len(),
                expected: expected_len,
            });
        }

        let implementation_end = PAYLOAD_HEADER_LEN + implementation_len;
        let implementation = parse_text(
            Field::Implementation,
            &record.payload[PAYLOAD_HEADER_LEN..implementation_end],
        )?;
        let version = parse_text(Field::Version, &record.payload[implementation_end..])?;
        Self::new(implementation, version)
    }

    /// Reconciles all creator copies for one protection set.
    ///
    /// Records of other types are ignored. Identical copies collapse; valid
    /// copies with different diagnostic identities are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for too many, absent, invalid, or conflicting copies.
    pub fn assemble(
        records: &[Record],
        expected_protection_set_id: [u8; 32],
        max_copies: u32,
    ) -> Result<Self, AssemblyError> {
        agreed_copies::assemble(
            records
                .iter()
                .filter(|record| record.record_type == RECORD_TYPE),
            Some(max_copies),
            |record| Self::from_record(record, expected_protection_set_id),
        )
        .map_err(map_agreed_copies_error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field {
    Implementation,
    Version,
}

impl fmt::Display for Field {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Implementation => formatter.write_str("implementation"),
            Self::Version => formatter.write_str("version"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    WrongRecordType(u16),
    InvalidRecordFlags(u32),
    ProtectionSetIdMismatch,
    InvalidLogicalId(u64),
    UnsupportedHeaderExtension,
    TruncatedPayload,
    UnsupportedPayloadVersion(u16),
    ReservedField,
    LengthOverflow,
    PayloadLengthMismatch {
        actual: usize,
        expected: usize,
    },
    EmptyField(Field),
    FieldTooLong {
        field: Field,
        actual: usize,
        maximum: usize,
    },
    InvalidUtf8(Field),
    ControlCharacter(Field),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRecordType(actual) => {
                write!(formatter, "record type {actual} is not a creator record")
            }
            Self::InvalidRecordFlags(actual) => {
                write!(formatter, "creator record has invalid flags {actual:#x}")
            }
            Self::ProtectionSetIdMismatch => {
                formatter.write_str("creator record belongs to a different protection set")
            }
            Self::InvalidLogicalId(actual) => {
                write!(
                    formatter,
                    "creator record has nonzero logical identifier {actual}"
                )
            }
            Self::UnsupportedHeaderExtension => {
                formatter.write_str("creator record has an unsupported header extension")
            }
            Self::TruncatedPayload => formatter.write_str("creator payload is truncated"),
            Self::UnsupportedPayloadVersion(version) => {
                write!(formatter, "unsupported creator payload version {version}")
            }
            Self::ReservedField => formatter.write_str("creator reserved field is nonzero"),
            Self::LengthOverflow => formatter.write_str("creator payload length overflows"),
            Self::PayloadLengthMismatch { actual, expected } => write!(
                formatter,
                "creator payload length {actual} does not match expected length {expected}"
            ),
            Self::EmptyField(field) => write!(formatter, "creator {field} is empty"),
            Self::FieldTooLong {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "creator {field} length {actual} exceeds maximum {maximum}"
            ),
            Self::InvalidUtf8(field) => write!(formatter, "creator {field} is not valid UTF-8"),
            Self::ControlCharacter(field) => {
                write!(formatter, "creator {field} contains a control character")
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssemblyError {
    CopyLimitExceeded { actual: u64, maximum: u32 },
    Missing,
    InvalidCopy(Error),
    ConflictingCopies,
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CopyLimitExceeded { actual, maximum } => write!(
                formatter,
                "creator copy count {actual} exceeds limit {maximum}"
            ),
            Self::Missing => formatter.write_str("creator record is missing"),
            Self::InvalidCopy(error) => write!(formatter, "invalid creator copy: {error}"),
            Self::ConflictingCopies => formatter.write_str("valid creator copies conflict"),
        }
    }
}

impl std::error::Error for AssemblyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCopy(error) => Some(error),
            Self::CopyLimitExceeded { .. } | Self::Missing | Self::ConflictingCopies => None,
        }
    }
}

fn map_agreed_copies_error(error: agreed_copies::Error<Error>) -> AssemblyError {
    match error {
        agreed_copies::Error::CopyLimitExceeded { actual, maximum } => {
            AssemblyError::CopyLimitExceeded { actual, maximum }
        }
        agreed_copies::Error::Missing => AssemblyError::Missing,
        agreed_copies::Error::InvalidCopy(error) => AssemblyError::InvalidCopy(error),
        agreed_copies::Error::ConflictingCopies => AssemblyError::ConflictingCopies,
    }
}

fn validate_field(field: Field, value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::EmptyField(field));
    }
    if value.len() > MAX_FIELD_LEN {
        return Err(Error::FieldTooLong {
            field,
            actual: value.len(),
            maximum: MAX_FIELD_LEN,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(Error::ControlCharacter(field));
    }
    Ok(())
}

fn parse_text(field: Field, bytes: &[u8]) -> Result<String, Error> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidUtf8(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{self, DecodeLimits};
    use std::io::Cursor;

    const SET_ID: [u8; 32] = [0x5a; 32];

    fn example() -> Creator {
        Creator::new("bitrot", "0.1.0").unwrap()
    }

    #[test]
    fn physical_record_round_trip() {
        let expected = example();
        let mut encoded = Vec::new();
        record::write(&mut encoded, &expected.to_record(SET_ID).unwrap()).unwrap();
        let record = record::read(
            &mut Cursor::new(encoded),
            DecodeLimits::new(72, MAX_FIELD_LEN as u64 * 2 + PAYLOAD_HEADER_LEN as u64),
        )
        .unwrap()
        .unwrap();

        assert_eq!(Creator::from_record(&record, SET_ID).unwrap(), expected);
    }

    #[test]
    fn supports_bounded_unicode_fields() {
        let expected = Creator::new("réparateur", "β1").unwrap();
        let record = expected.to_record(SET_ID).unwrap();
        assert_eq!(Creator::from_record(&record, SET_ID).unwrap(), expected);
    }

    #[test]
    fn constructor_rejects_unsafe_diagnostic_text() {
        assert_eq!(
            Creator::new("", "1").unwrap_err(),
            Error::EmptyField(Field::Implementation)
        );
        assert_eq!(
            Creator::new("bitrot\nforged", "1").unwrap_err(),
            Error::ControlCharacter(Field::Implementation)
        );
        assert!(matches!(
            Creator::new("x".repeat(MAX_FIELD_LEN + 1), "1"),
            Err(Error::FieldTooLong {
                field: Field::Implementation,
                ..
            })
        ));
    }

    #[test]
    fn decoder_rejects_noncanonical_frame_metadata() {
        let base = example().to_record(SET_ID).unwrap();
        let mut cases = Vec::new();

        let mut wrong_type = base.clone();
        wrong_type.record_type = 7;
        cases.push((wrong_type, Error::WrongRecordType(7)));
        let mut wrong_flags = base.clone();
        wrong_flags.flags = 0;
        cases.push((wrong_flags, Error::InvalidRecordFlags(0)));
        let mut wrong_set = base.clone();
        wrong_set.protection_set_id = [1; 32];
        cases.push((wrong_set, Error::ProtectionSetIdMismatch));
        let mut wrong_id = base.clone();
        wrong_id.logical_id = 1;
        cases.push((wrong_id, Error::InvalidLogicalId(1)));
        let mut extension = base;
        extension.header_extension.push(0);
        cases.push((extension, Error::UnsupportedHeaderExtension));

        for (record, expected) in cases {
            assert_eq!(Creator::from_record(&record, SET_ID), Err(expected));
        }
    }

    #[test]
    fn decoder_rejects_malformed_payloads() {
        let base = example().to_record(SET_ID).unwrap();

        let mut truncated = base.clone();
        truncated.payload.truncate(PAYLOAD_HEADER_LEN - 1);
        assert_eq!(
            Creator::from_record(&truncated, SET_ID),
            Err(Error::TruncatedPayload)
        );

        let mut unsupported = base.clone();
        unsupported.payload[0..2].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            Creator::from_record(&unsupported, SET_ID),
            Err(Error::UnsupportedPayloadVersion(2))
        );

        let mut reserved = base.clone();
        reserved.payload[8] = 1;
        assert_eq!(
            Creator::from_record(&reserved, SET_ID),
            Err(Error::ReservedField)
        );

        let mut bad_length = base.clone();
        bad_length.payload[4..6].copy_from_slice(&9_u16.to_le_bytes());
        assert!(matches!(
            Creator::from_record(&bad_length, SET_ID),
            Err(Error::PayloadLengthMismatch { .. })
        ));

        let mut bad_utf8 = base;
        bad_utf8.payload[PAYLOAD_HEADER_LEN] = 0xff;
        assert_eq!(
            Creator::from_record(&bad_utf8, SET_ID),
            Err(Error::InvalidUtf8(Field::Implementation))
        );
    }

    #[test]
    fn assembly_requires_bounded_agreed_copies() {
        let creator = example();
        let record = creator.to_record(SET_ID).unwrap();
        assert_eq!(
            Creator::assemble(&[record.clone(), record.clone()], SET_ID, 2).unwrap(),
            creator
        );
        assert_eq!(
            Creator::assemble(&[], SET_ID, 2),
            Err(AssemblyError::Missing)
        );
        assert!(matches!(
            Creator::assemble(&[record.clone(), record.clone()], SET_ID, 1),
            Err(AssemblyError::CopyLimitExceeded { .. })
        ));

        let conflicting = Creator::new("another", "2")
            .unwrap()
            .to_record(SET_ID)
            .unwrap();
        assert_eq!(
            Creator::assemble(&[record, conflicting], SET_ID, 2),
            Err(AssemblyError::ConflictingCopies)
        );
    }
}
