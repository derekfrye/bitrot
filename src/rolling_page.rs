//! Bounded pages containing full-chunk rolling fingerprints.

use crate::digest::Digest;
use crate::paged_table;
use crate::record::{FLAG_REQUIRED, Record};
use crate::wire;
use std::convert::Infallible;
use std::fmt;

pub const RECORD_TYPE: u16 = 4;
pub const PAYLOAD_VERSION: u16 = 1;
pub const PAYLOAD_HEADER_LEN: usize = 24;
pub const MAX_VALUES_PER_PAGE: usize = 4_096;

const ROOT_CONTEXT: &str = "bitrot format v1 rolling fingerprint table root";

/// One independently checksummed portion of the rolling-fingerprint table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page {
    pub page_index: u32,
    pub first_value_index: u64,
    pub values: Vec<u64>,
}

impl paged_table::Page for Page {
    fn page_index(&self) -> u32 {
        self.page_index
    }

    fn first_item_index(&self) -> u64 {
        self.first_value_index
    }

    fn item_count(&self) -> usize {
        self.values.len()
    }
}

impl Page {
    /// Constructs and validates a page.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized page, or an overflowing
    /// value-index range.
    pub fn new(page_index: u32, first_value_index: u64, values: Vec<u64>) -> Result<Self, Error> {
        validate_value_count(values.len())?;
        validate_value_range(first_value_index, values.len())?;
        Ok(Self {
            page_index,
            first_value_index,
            values,
        })
    }

    /// Encodes this page as a canonical required record.
    ///
    /// # Errors
    ///
    /// Returns an error if public fields were changed to invalid values.
    pub fn to_record(&self, protection_set_id: [u8; 32]) -> Result<Record, Error> {
        validate_value_count(self.values.len())?;
        validate_value_range(self.first_value_index, self.values.len())?;
        let count = u32::try_from(self.values.len()).map_err(|_| Error::LengthOverflow)?;
        let value_bytes = self
            .values
            .len()
            .checked_mul(size_of::<u64>())
            .ok_or(Error::LengthOverflow)?;
        let capacity = PAYLOAD_HEADER_LEN
            .checked_add(value_bytes)
            .ok_or(Error::LengthOverflow)?;
        let mut payload = Vec::with_capacity(capacity);
        payload.extend_from_slice(&PAYLOAD_VERSION.to_le_bytes());
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(&self.page_index.to_le_bytes());
        payload.extend_from_slice(&self.first_value_index.to_le_bytes());
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        for value in &self.values {
            payload.extend_from_slice(&value.to_le_bytes());
        }

        Ok(Record {
            record_type: RECORD_TYPE,
            flags: FLAG_REQUIRED,
            protection_set_id,
            logical_id: u64::from(self.page_index),
            header_extension: Vec::new(),
            payload,
        })
    }

    /// Strictly decodes a rolling-table page record.
    ///
    /// # Errors
    ///
    /// Returns an error unless the record metadata, page geometry, and payload
    /// are canonical experimental version 1 encoding.
    pub fn from_record(record: &Record) -> Result<Self, Error> {
        if record.record_type != RECORD_TYPE {
            return Err(Error::WrongRecordType(record.record_type));
        }
        if record.flags != FLAG_REQUIRED {
            return Err(Error::InvalidRecordFlags(record.flags));
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
        if parse_u16(&record.payload, 2)? != 0 || parse_u32(&record.payload, 20)? != 0 {
            return Err(Error::ReservedField);
        }
        let page_index = parse_u32(&record.payload, 4)?;
        if record.logical_id != u64::from(page_index) {
            return Err(Error::LogicalIdMismatch);
        }
        let first_value_index = parse_u64(&record.payload, 8)?;
        let count =
            usize::try_from(parse_u32(&record.payload, 16)?).map_err(|_| Error::LengthOverflow)?;
        validate_value_count(count)?;
        let value_bytes = count
            .checked_mul(size_of::<u64>())
            .ok_or(Error::LengthOverflow)?;
        let expected_len = PAYLOAD_HEADER_LEN
            .checked_add(value_bytes)
            .ok_or(Error::LengthOverflow)?;
        if record.payload.len() != expected_len {
            return Err(Error::PayloadLengthMismatch {
                actual: record.payload.len(),
                expected: expected_len,
            });
        }

        let values = record.payload[PAYLOAD_HEADER_LEN..]
            .chunks_exact(size_of::<u64>())
            .map(|bytes| {
                wire::u64(bytes, 0).ok_or(Error::PayloadLengthMismatch {
                    actual: record.payload.len(),
                    expected: expected_len,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(page_index, first_value_index, values)
    }
}

/// A complete ordered rolling-fingerprint table in canonical pages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    pub value_count: u64,
    pub root: Digest,
    pub pages: Vec<Page>,
}

impl Table {
    /// Builds a canonical rolling table without retaining a second value copy.
    ///
    /// # Errors
    ///
    /// Returns an error if the table has too many values or pages.
    pub fn new(values: Vec<u64>) -> Result<Self, Error> {
        let value_count = u64::try_from(values.len()).map_err(|_| Error::LengthOverflow)?;
        let root = table_root(&values)?;
        let page_count = values.len().div_ceil(MAX_VALUES_PER_PAGE);
        u32::try_from(page_count).map_err(|_| Error::TooManyPages)?;

        let mut pages = Vec::with_capacity(page_count);
        let mut values = values.into_iter();
        let mut first_value_index = 0_u64;
        for page_index in 0..page_count {
            let page_values: Vec<_> = values.by_ref().take(MAX_VALUES_PER_PAGE).collect();
            let count = u64::try_from(page_values.len()).map_err(|_| Error::LengthOverflow)?;
            pages.push(Page::new(
                u32::try_from(page_index).map_err(|_| Error::TooManyPages)?,
                first_value_index,
                page_values,
            )?);
            first_value_index = first_value_index
                .checked_add(count)
                .ok_or(Error::ValueIndexOverflow)?;
        }
        Ok(Self {
            value_count,
            root,
            pages,
        })
    }

    /// Assembles validated pages, accepting identical redundant copies.
    ///
    /// # Errors
    ///
    /// Returns an error before allocation when declared limits are exceeded,
    /// or for missing, conflicting, noncanonical, or incorrectly rooted pages.
    pub fn assemble<I>(
        value_count: u64,
        expected_root: Digest,
        pages: I,
        limits: AssemblyLimits,
    ) -> Result<Self, AssemblyError>
    where
        I: IntoIterator<Item = Page>,
    {
        let pages = paged_table::assemble(
            value_count,
            MAX_VALUES_PER_PAGE,
            pages,
            paged_table::Limits {
                max_items: limits.max_values,
                max_pages: limits.max_pages,
            },
            |_| Ok::<(), Infallible>(()),
        )
        .map_err(map_paged_table_error)?;
        let actual_root = table_root_iter(
            value_count,
            pages.iter().flat_map(|page| page.values.iter().copied()),
        );
        if actual_root != expected_root {
            return Err(AssemblyError::RootMismatch {
                expected: expected_root,
                actual: actual_root,
            });
        }
        Ok(Self {
            value_count,
            root: actual_root,
            pages,
        })
    }

    pub fn values(&self) -> impl Iterator<Item = u64> + '_ {
        self.pages
            .iter()
            .flat_map(|page| page.values.iter().copied())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyLimits {
    pub max_values: u64,
    pub max_pages: u32,
}

impl AssemblyLimits {
    #[must_use]
    pub const fn new(max_values: u64, max_pages: u32) -> Self {
        Self {
            max_values,
            max_pages,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssemblyError {
    ValueLimitExceeded {
        actual: u64,
        maximum: u64,
    },
    PageLimitExceeded {
        actual: u64,
        maximum: u32,
    },
    CountUnrepresentable,
    LengthOverflow,
    PageIndexOutOfRange {
        page_index: u32,
        page_count: u32,
    },
    FirstValueIndexMismatch {
        page_index: u32,
        actual: u64,
        expected: u64,
    },
    PageValueCountMismatch {
        page_index: u32,
        actual: usize,
        expected: usize,
    },
    ConflictingPage(u32),
    MissingPages(Vec<u32>),
    RootMismatch {
        expected: Digest,
        actual: Digest,
    },
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "rolling value count {actual} exceeds limit {maximum}"
                )
            }
            Self::PageLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "rolling page count {actual} exceeds limit {maximum}"
                )
            }
            Self::CountUnrepresentable => {
                formatter.write_str("rolling-table count cannot be represented")
            }
            Self::LengthOverflow => formatter.write_str("rolling-table geometry overflows"),
            Self::PageIndexOutOfRange {
                page_index,
                page_count,
            } => write!(
                formatter,
                "rolling page index {page_index} is outside page count {page_count}"
            ),
            Self::FirstValueIndexMismatch {
                page_index,
                actual,
                expected,
            } => write!(
                formatter,
                "rolling page {page_index} starts at value {actual}, expected {expected}"
            ),
            Self::PageValueCountMismatch {
                page_index,
                actual,
                expected,
            } => write!(
                formatter,
                "rolling page {page_index} contains {actual} values, expected {expected}"
            ),
            Self::ConflictingPage(index) => {
                write!(formatter, "valid copies of rolling page {index} conflict")
            }
            Self::MissingPages(pages) => write!(formatter, "missing rolling pages {pages:?}"),
            Self::RootMismatch { .. } => formatter.write_str("rolling-table root does not match"),
        }
    }
}

impl std::error::Error for AssemblyError {}

fn map_paged_table_error(error: paged_table::Error<Infallible>) -> AssemblyError {
    match error {
        paged_table::Error::ItemLimitExceeded { actual, maximum } => {
            AssemblyError::ValueLimitExceeded { actual, maximum }
        }
        paged_table::Error::PageLimitExceeded { actual, maximum } => {
            AssemblyError::PageLimitExceeded { actual, maximum }
        }
        paged_table::Error::ItemCountUnrepresentable
        | paged_table::Error::PageCountUnrepresentable => AssemblyError::CountUnrepresentable,
        paged_table::Error::LengthOverflow => AssemblyError::LengthOverflow,
        paged_table::Error::InvalidPage(error) => match error {},
        paged_table::Error::PageIndexOutOfRange {
            page_index,
            page_count,
        } => AssemblyError::PageIndexOutOfRange {
            page_index,
            page_count,
        },
        paged_table::Error::FirstItemIndexMismatch {
            page_index,
            actual,
            expected,
        } => AssemblyError::FirstValueIndexMismatch {
            page_index,
            actual,
            expected,
        },
        paged_table::Error::PageItemCountMismatch {
            page_index,
            actual,
            expected,
        } => AssemblyError::PageValueCountMismatch {
            page_index,
            actual,
            expected,
        },
        paged_table::Error::ConflictingPage(page_index) => {
            AssemblyError::ConflictingPage(page_index)
        }
        paged_table::Error::MissingPages(pages) => AssemblyError::MissingPages(pages),
    }
}

/// Hashes a complete canonical rolling-fingerprint table.
///
/// # Errors
///
/// Returns an error if the value count cannot be represented as `u64`.
pub fn table_root(values: &[u64]) -> Result<Digest, Error> {
    let count = u64::try_from(values.len()).map_err(|_| Error::LengthOverflow)?;
    Ok(table_root_iter(count, values.iter().copied()))
}

fn table_root_iter<I>(count: u64, values: I) -> Digest
where
    I: IntoIterator<Item = u64>,
{
    let mut hasher = blake3::Hasher::new_derive_key(ROOT_CONTEXT);
    hasher.update(&count.to_le_bytes());
    for value in values {
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyPage,
    TooManyValues(usize),
    TooManyPages,
    ValueIndexOverflow,
    LengthOverflow,
    WrongRecordType(u16),
    InvalidRecordFlags(u32),
    UnsupportedHeaderExtension,
    TruncatedPayload,
    UnsupportedPayloadVersion(u16),
    ReservedField,
    LogicalIdMismatch,
    PayloadLengthMismatch { actual: usize, expected: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPage => formatter.write_str("rolling-table page is empty"),
            Self::TooManyValues(count) => write!(
                formatter,
                "rolling-table page contains {count} values; maximum is {MAX_VALUES_PER_PAGE}"
            ),
            Self::TooManyPages => formatter.write_str("rolling table has too many pages"),
            Self::ValueIndexOverflow => formatter.write_str("rolling-table index overflows u64"),
            Self::LengthOverflow => formatter.write_str("rolling-table length is unrepresentable"),
            Self::WrongRecordType(actual) => {
                write!(
                    formatter,
                    "record type {actual} is not a rolling-table page"
                )
            }
            Self::InvalidRecordFlags(actual) => {
                write!(
                    formatter,
                    "rolling-table record has invalid flags {actual:#x}"
                )
            }
            Self::UnsupportedHeaderExtension => {
                formatter.write_str("rolling-table record has an unsupported header extension")
            }
            Self::TruncatedPayload => formatter.write_str("rolling-table payload is truncated"),
            Self::UnsupportedPayloadVersion(version) => {
                write!(
                    formatter,
                    "unsupported rolling-table payload version {version}"
                )
            }
            Self::ReservedField => {
                formatter.write_str("rolling-table payload has a nonzero reserved field")
            }
            Self::LogicalIdMismatch => {
                formatter.write_str("rolling-table logical identifier does not match payload")
            }
            Self::PayloadLengthMismatch { actual, expected } => write!(
                formatter,
                "rolling-table payload length is {actual}, expected {expected}"
            ),
        }
    }
}

impl std::error::Error for Error {}

fn validate_value_count(count: usize) -> Result<(), Error> {
    if count == 0 {
        return Err(Error::EmptyPage);
    }
    if count > MAX_VALUES_PER_PAGE {
        return Err(Error::TooManyValues(count));
    }
    Ok(())
}

fn validate_value_range(first: u64, count: usize) -> Result<(), Error> {
    let count = u64::try_from(count).map_err(|_| Error::LengthOverflow)?;
    first.checked_add(count).ok_or(Error::ValueIndexOverflow)?;
    Ok(())
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
    use crate::record::{self, DecodeLimits};
    use std::io::Cursor;

    fn values(count: usize) -> Vec<u64> {
        (0..count)
            .map(|index| u64::try_from(index).unwrap().wrapping_mul(0x9e37_79b9))
            .collect()
    }

    #[test]
    fn builds_canonical_pages_and_round_trips_records() {
        let table = Table::new(values(MAX_VALUES_PER_PAGE + 3)).unwrap();
        assert_eq!(table.pages.len(), 2);
        assert_eq!(table.pages[0].values.len(), MAX_VALUES_PER_PAGE);
        assert_eq!(table.pages[1].first_value_index, MAX_VALUES_PER_PAGE as u64);

        let expected_id = [0x5a; 32];
        let mut encoded = Vec::new();
        record::write(
            &mut encoded,
            &table.pages[1].to_record(expected_id).unwrap(),
        )
        .unwrap();
        let record = record::read(
            &mut Cursor::new(encoded),
            DecodeLimits::new(record::BASE_HEADER_LEN, 64 * 1024),
        )
        .unwrap()
        .unwrap();
        assert_eq!(Page::from_record(&record).unwrap(), table.pages[1]);
        assert_eq!(record.protection_set_id, expected_id);
    }

    #[test]
    fn empty_table_has_a_root_and_no_pages() {
        let table = Table::new(Vec::new()).unwrap();
        assert_eq!(table.value_count, 0);
        assert!(table.pages.is_empty());
        assert_eq!(table.root, table_root(&[]).unwrap());
    }

    #[test]
    fn assembly_accepts_reordered_identical_copies() {
        let expected = Table::new(values(MAX_VALUES_PER_PAGE + 2)).unwrap();
        let pages = [
            expected.pages[1].clone(),
            expected.pages[0].clone(),
            expected.pages[0].clone(),
        ];
        let actual = Table::assemble(
            expected.value_count,
            expected.root,
            pages,
            AssemblyLimits::new(10_000, 3),
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn assembly_rejects_limits_missing_conflicts_and_wrong_root() {
        let expected = Table::new(values(MAX_VALUES_PER_PAGE + 1)).unwrap();
        assert!(matches!(
            Table::assemble(
                expected.value_count,
                expected.root,
                expected.pages.clone(),
                AssemblyLimits::new(1, 2)
            ),
            Err(AssemblyError::ValueLimitExceeded { .. })
        ));
        assert!(matches!(
            Table::assemble(
                expected.value_count,
                expected.root,
                [expected.pages[0].clone()],
                AssemblyLimits::new(10_000, 2)
            ),
            Err(AssemblyError::MissingPages(_))
        ));
        let mut conflict = expected.pages[0].clone();
        conflict.values[0] ^= 1;
        assert!(matches!(
            Table::assemble(
                expected.value_count,
                expected.root,
                [
                    expected.pages[0].clone(),
                    conflict,
                    expected.pages[1].clone()
                ],
                AssemblyLimits::new(10_000, 2)
            ),
            Err(AssemblyError::ConflictingPage(0))
        ));
        assert!(matches!(
            Table::assemble(
                expected.value_count,
                Digest::from_bytes([0; 32]),
                expected.pages,
                AssemblyLimits::new(10_000, 2)
            ),
            Err(AssemblyError::RootMismatch { .. })
        ));
    }

    #[test]
    fn decoder_rejects_noncanonical_record_metadata_and_payload() {
        let canonical = Table::new(vec![7])
            .unwrap()
            .pages
            .remove(0)
            .to_record([0; 32])
            .unwrap();
        let mut wrong_type = canonical.clone();
        wrong_type.record_type = 9;
        assert!(matches!(
            Page::from_record(&wrong_type),
            Err(Error::WrongRecordType(9))
        ));
        let mut wrong_flags = canonical.clone();
        wrong_flags.flags = 0;
        assert!(matches!(
            Page::from_record(&wrong_flags),
            Err(Error::InvalidRecordFlags(0))
        ));
        let mut wrong_id = canonical.clone();
        wrong_id.logical_id = 1;
        assert!(matches!(
            Page::from_record(&wrong_id),
            Err(Error::LogicalIdMismatch)
        ));
        let mut reserved = canonical.clone();
        reserved.payload[2] = 1;
        assert!(matches!(
            Page::from_record(&reserved),
            Err(Error::ReservedField)
        ));
        let mut trailing = canonical;
        trailing.payload.push(0);
        assert!(matches!(
            Page::from_record(&trailing),
            Err(Error::PayloadLengthMismatch { .. })
        ));
    }

    #[test]
    fn root_commits_to_count_order_and_little_endian_values() {
        let values = [1_u64, 2, 0x0102_0304_0506_0708];
        let root = table_root(&values).unwrap();
        assert_ne!(root, table_root(&values[..2]).unwrap());
        assert_ne!(root, table_root(&[2, 1, values[2]]).unwrap());

        let mut hasher = blake3::Hasher::new_derive_key(ROOT_CONTEXT);
        hasher.update(&3_u64.to_le_bytes());
        for value in values {
            hasher.update(&value.to_le_bytes());
        }
        assert_eq!(root, Digest::from(hasher.finalize()));
    }
}
