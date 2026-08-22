//! Encoding and decoding for independently checksummed sidecar records.

use std::fmt;
use std::io::{self, Read, Write};

/// Marker at the beginning of every record.
pub const MAGIC: [u8; 8] = *b"BITROT\r\n";
/// The record-frame version implemented by this crate.
pub const FORMAT_VERSION: u16 = 1;
/// Size of the v1 header before any extension bytes.
pub const BASE_HEADER_LEN: u32 = 72;
/// Size of the digest following each record payload.
pub const DIGEST_LEN: usize = 32;
/// Marks a record whose type must be understood to use the protection set.
pub const FLAG_REQUIRED: u32 = 1;

const KNOWN_FLAGS: u32 = FLAG_REQUIRED;
const DIGEST_CONTEXT: &str = "bitrot format v1 record digest";

/// Caller-selected limits applied before decoder allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    pub max_header_len: u32,
    pub max_payload_len: u64,
}

impl DecodeLimits {
    #[must_use]
    pub const fn new(max_header_len: u32, max_payload_len: u64) -> Self {
        Self {
            max_header_len,
            max_payload_len,
        }
    }
}

/// One physical record, including bytes not understood in its extended header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub record_type: u16,
    pub flags: u32,
    pub protection_set_id: [u8; 32],
    pub logical_id: u64,
    pub header_extension: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Record {
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.flags & FLAG_REQUIRED != 0
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Truncated,
    BadMagic([u8; 8]),
    UnsupportedVersion(u16),
    InvalidRecordType,
    UnknownFlags(u32),
    ReservedField(u32),
    InvalidHeaderLength(u32),
    HeaderTooLarge { actual: u32, maximum: u32 },
    PayloadTooLarge { actual: u64, maximum: u64 },
    LengthOverflow,
    DigestMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "record I/O failed: {error}"),
            Self::Truncated => formatter.write_str("record is truncated"),
            Self::BadMagic(actual) => write!(formatter, "invalid record magic: {actual:02x?}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported record version {version}")
            }
            Self::InvalidRecordType => formatter.write_str("record type zero is reserved"),
            Self::UnknownFlags(flags) => write!(formatter, "record has unknown flags {flags:#x}"),
            Self::ReservedField(value) => {
                write!(formatter, "record reserved field is nonzero: {value:#x}")
            }
            Self::InvalidHeaderLength(length) => {
                write!(formatter, "invalid record header length {length}")
            }
            Self::HeaderTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "record header length {actual} exceeds limit {maximum}"
                )
            }
            Self::PayloadTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "record payload length {actual} exceeds limit {maximum}"
                )
            }
            Self::LengthOverflow => formatter.write_str("record length cannot be represented"),
            Self::DigestMismatch => formatter.write_str("record digest does not match"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Writes one complete record and returns the number of bytes written.
///
/// # Errors
///
/// Returns an error when record metadata is invalid, a length cannot be
/// represented by the format, or the destination cannot be written.
pub fn write<W: Write>(writer: &mut W, record: &Record) -> Result<u64, Error> {
    validate_type_and_flags(record.record_type, record.flags)?;

    let extension_len =
        u32::try_from(record.header_extension.len()).map_err(|_| Error::LengthOverflow)?;
    let header_len = BASE_HEADER_LEN
        .checked_add(extension_len)
        .ok_or(Error::LengthOverflow)?;
    let payload_len = u64::try_from(record.payload.len()).map_err(|_| Error::LengthOverflow)?;

    let mut header = Vec::with_capacity(header_len as usize);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    header.extend_from_slice(&record.record_type.to_le_bytes());
    header.extend_from_slice(&record.flags.to_le_bytes());
    header.extend_from_slice(&header_len.to_le_bytes());
    header.extend_from_slice(&0_u32.to_le_bytes());
    header.extend_from_slice(&payload_len.to_le_bytes());
    header.extend_from_slice(&record.protection_set_id);
    header.extend_from_slice(&record.logical_id.to_le_bytes());
    header.extend_from_slice(&record.header_extension);

    let digest = digest(&header, &record.payload);
    writer.write_all(&header)?;
    writer.write_all(&record.payload)?;
    writer.write_all(digest.as_bytes())?;

    u64::from(header_len)
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(DIGEST_LEN as u64))
        .ok_or(Error::LengthOverflow)
}

/// Reads one complete record. A clean EOF before a new record returns `None`.
///
/// # Errors
///
/// Returns an error when input fails, the record is malformed or truncated,
/// its declared lengths exceed `limits`, or its digest does not match.
pub fn read<R: Read>(reader: &mut R, limits: DecodeLimits) -> Result<Option<Record>, Error> {
    let Some(magic) = read_magic(reader)? else {
        return Ok(None);
    };
    if magic != MAGIC {
        return Err(Error::BadMagic(magic));
    }

    let mut remainder = [0_u8; BASE_HEADER_LEN as usize - MAGIC.len()];
    read_exact_record(reader, &mut remainder)?;

    let version = parse_u16(&remainder, 0)?;
    if version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }

    let record_type = parse_u16(&remainder, 2)?;
    let flags = parse_u32(&remainder, 4)?;
    validate_type_and_flags(record_type, flags)?;

    let header_len = parse_u32(&remainder, 8)?;
    if header_len < BASE_HEADER_LEN {
        return Err(Error::InvalidHeaderLength(header_len));
    }
    if header_len > limits.max_header_len {
        return Err(Error::HeaderTooLarge {
            actual: header_len,
            maximum: limits.max_header_len,
        });
    }

    let reserved = parse_u32(&remainder, 12)?;
    if reserved != 0 {
        return Err(Error::ReservedField(reserved));
    }

    let payload_len = parse_u64(&remainder, 16)?;
    if payload_len > limits.max_payload_len {
        return Err(Error::PayloadTooLarge {
            actual: payload_len,
            maximum: limits.max_payload_len,
        });
    }

    let mut protection_set_id = [0_u8; 32];
    protection_set_id.copy_from_slice(&remainder[24..56]);
    let logical_id = parse_u64(&remainder, 56)?;

    let extension_len =
        usize::try_from(header_len - BASE_HEADER_LEN).map_err(|_| Error::LengthOverflow)?;
    let payload_len = usize::try_from(payload_len).map_err(|_| Error::LengthOverflow)?;
    let mut header_extension = vec![0_u8; extension_len];
    read_exact_record(reader, &mut header_extension)?;
    let mut payload = vec![0_u8; payload_len];
    read_exact_record(reader, &mut payload)?;
    let mut stored_digest = [0_u8; DIGEST_LEN];
    read_exact_record(reader, &mut stored_digest)?;

    let mut header = Vec::with_capacity(header_len as usize);
    header.extend_from_slice(&magic);
    header.extend_from_slice(&remainder);
    header.extend_from_slice(&header_extension);
    if digest(&header, &payload).as_bytes() != &stored_digest {
        return Err(Error::DigestMismatch);
    }

    Ok(Some(Record {
        record_type,
        flags,
        protection_set_id,
        logical_id,
        header_extension,
        payload,
    }))
}

fn validate_type_and_flags(record_type: u16, flags: u32) -> Result<(), Error> {
    if record_type == 0 {
        return Err(Error::InvalidRecordType);
    }
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Error::UnknownFlags(flags));
    }
    Ok(())
}

fn digest(header: &[u8], payload: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_derive_key(DIGEST_CONTEXT);
    hasher.update(header);
    hasher.update(payload);
    hasher.finalize()
}

fn read_magic<R: Read>(reader: &mut R) -> Result<Option<[u8; MAGIC.len()]>, Error> {
    let mut magic = [0_u8; MAGIC.len()];
    let mut filled = 0;
    while filled < magic.len() {
        match reader.read(&mut magic[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(Error::Truncated),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok(Some(magic))
}

fn read_exact_record<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), Error> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::Truncated
        } else {
            Error::Io(error)
        }
    })
}

fn parse_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let source = bytes.get(offset..offset + 2).ok_or(Error::Truncated)?;
    let mut encoded = [0_u8; 2];
    encoded.copy_from_slice(source);
    Ok(u16::from_le_bytes(encoded))
}

fn parse_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let source = bytes.get(offset..offset + 4).ok_or(Error::Truncated)?;
    let mut encoded = [0_u8; 4];
    encoded.copy_from_slice(source);
    Ok(u32::from_le_bytes(encoded))
}

fn parse_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let source = bytes.get(offset..offset + 8).ok_or(Error::Truncated)?;
    let mut encoded = [0_u8; 8];
    encoded.copy_from_slice(source);
    Ok(u64::from_le_bytes(encoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const LIMITS: DecodeLimits = DecodeLimits::new(4_096, 1_048_576);

    fn example() -> Record {
        Record {
            record_type: 37,
            flags: 0,
            protection_set_id: [0xa5; 32],
            logical_id: 0x0102_0304_0506_0708,
            header_extension: vec![9, 8, 7],
            payload: b"payload bytes".to_vec(),
        }
    }

    fn encoded(record: &Record) -> Vec<u8> {
        let mut bytes = Vec::new();
        write(&mut bytes, record).unwrap();
        bytes
    }

    #[test]
    fn round_trip_preserves_unknown_optional_record_and_extension() {
        let expected = example();
        let bytes = encoded(&expected);
        let mut cursor = Cursor::new(bytes);

        let actual = read(&mut cursor, LIMITS).unwrap().unwrap();

        assert_eq!(actual, expected);
        assert!(!actual.is_required());
        assert!(read(&mut cursor, LIMITS).unwrap().is_none());
    }

    #[test]
    fn writes_documented_little_endian_fields() {
        let bytes = encoded(&example());

        assert_eq!(&bytes[0..8], &MAGIC);
        assert_eq!(&bytes[8..10], &FORMAT_VERSION.to_le_bytes());
        assert_eq!(&bytes[10..12], &37_u16.to_le_bytes());
        assert_eq!(&bytes[16..20], &75_u32.to_le_bytes());
        assert_eq!(&bytes[24..32], &13_u64.to_le_bytes());
        assert_eq!(&bytes[64..72], &0x0102_0304_0506_0708_u64.to_le_bytes());
    }

    #[test]
    fn reads_consecutive_records() {
        let first = example();
        let mut second = example();
        second.logical_id = 2;
        second.flags = FLAG_REQUIRED;
        let mut bytes = encoded(&first);
        bytes.extend(encoded(&second));
        let mut cursor = Cursor::new(bytes);

        assert_eq!(read(&mut cursor, LIMITS).unwrap(), Some(first));
        assert_eq!(read(&mut cursor, LIMITS).unwrap(), Some(second));
        assert_eq!(read(&mut cursor, LIMITS).unwrap(), None);
    }

    #[test]
    fn detects_header_payload_and_digest_corruption() {
        let original = encoded(&example());
        for offset in [32, BASE_HEADER_LEN as usize + 3, original.len() - 1] {
            let mut damaged = original.clone();
            damaged[offset] ^= 0x80;
            assert!(matches!(
                read(&mut Cursor::new(damaged), LIMITS),
                Err(Error::DigestMismatch)
            ));
        }
    }

    #[test]
    fn rejects_every_truncated_prefix() {
        let bytes = encoded(&example());
        assert_eq!(
            read(&mut Cursor::new(Vec::<u8>::new()), LIMITS).unwrap(),
            None
        );
        for length in 1..bytes.len() {
            assert!(matches!(
                read(&mut Cursor::new(&bytes[..length]), LIMITS),
                Err(Error::Truncated)
            ));
        }
    }

    #[test]
    fn applies_lengths_before_allocating_or_reading_payload() {
        let mut oversized_header = encoded(&example());
        oversized_header[16..20].copy_from_slice(&4_097_u32.to_le_bytes());
        assert!(matches!(
            read(&mut Cursor::new(oversized_header), LIMITS),
            Err(Error::HeaderTooLarge { .. })
        ));

        let mut oversized_payload = encoded(&example());
        oversized_payload[24..32].copy_from_slice(&1_048_577_u64.to_le_bytes());
        assert!(matches!(
            read(&mut Cursor::new(oversized_payload), LIMITS),
            Err(Error::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_reserved_values() {
        let mut zero_type = example();
        zero_type.record_type = 0;
        assert!(matches!(
            write(&mut Vec::new(), &zero_type),
            Err(Error::InvalidRecordType)
        ));

        let mut unknown_flags = example();
        unknown_flags.flags = 2;
        assert!(matches!(
            write(&mut Vec::new(), &unknown_flags),
            Err(Error::UnknownFlags(2))
        ));

        let mut reserved_field = encoded(&example());
        reserved_field[20..24].copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            read(&mut Cursor::new(reserved_field), LIMITS),
            Err(Error::ReservedField(1))
        ));
    }
}
