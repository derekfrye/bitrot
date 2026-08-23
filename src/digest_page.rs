//! Bounded pages containing strong data- or recovery-chunk digests.

use crate::digest::Digest;
use crate::paged_table;
use crate::record::{FLAG_REQUIRED, Record};
use crate::wire;
use std::fmt;

pub const RECORD_TYPE: u16 = 3;
pub const PAYLOAD_VERSION: u16 = 1;
pub const PAYLOAD_HEADER_LEN: usize = 24;
pub const MAX_DIGESTS_PER_PAGE: usize = 4_096;

const DATA_ROOT_CONTEXT: &str = "bitrot format v1 data digest table root";
const RECOVERY_ROOT_CONTEXT: &str = "bitrot format v1 recovery digest table root";
const LOGICAL_KIND_SHIFT: u32 = 56;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Data = 1,
    Recovery = 2,
}

impl Kind {
    const fn root_context(self) -> &'static str {
        match self {
            Self::Data => DATA_ROOT_CONTEXT,
            Self::Recovery => RECOVERY_ROOT_CONTEXT,
        }
    }
}

impl TryFrom<u8> for Kind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Recovery),
            _ => Err(Error::UnknownKind(value)),
        }
    }
}

/// A bounded, independently record-checksummed portion of a digest table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page {
    pub kind: Kind,
    pub page_index: u32,
    pub first_digest_index: u64,
    pub digests: Vec<Digest>,
}

impl paged_table::Page for Page {
    fn page_index(&self) -> u32 {
        self.page_index
    }

    fn first_item_index(&self) -> u64 {
        self.first_digest_index
    }

    fn item_count(&self) -> usize {
        self.digests.len()
    }
}

impl Page {
    /// Constructs and validates a page.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized page, or if its final digest
    /// index cannot be represented as `u64`.
    pub fn new(
        kind: Kind,
        page_index: u32,
        first_digest_index: u64,
        digests: Vec<Digest>,
    ) -> Result<Self, Error> {
        validate_digest_count(digests.len())?;
        validate_digest_range(first_digest_index, digests.len())?;
        Ok(Self {
            kind,
            page_index,
            first_digest_index,
            digests,
        })
    }

    /// Encodes this page as a required digest-table record.
    ///
    /// # Errors
    ///
    /// Returns an error if the page was constructed outside the validated API
    /// and now has an invalid digest count or unrepresentable length.
    pub fn to_record(&self, protection_set_id: [u8; 32]) -> Result<Record, Error> {
        validate_digest_count(self.digests.len())?;
        validate_digest_range(self.first_digest_index, self.digests.len())?;
        let count = u32::try_from(self.digests.len()).map_err(|_| Error::LengthOverflow)?;
        let digest_bytes = self
            .digests
            .len()
            .checked_mul(32)
            .ok_or(Error::LengthOverflow)?;
        let capacity = PAYLOAD_HEADER_LEN
            .checked_add(digest_bytes)
            .ok_or(Error::LengthOverflow)?;
        let mut payload = Vec::with_capacity(capacity);
        payload.extend_from_slice(&PAYLOAD_VERSION.to_le_bytes());
        payload.push(self.kind as u8);
        payload.push(0);
        payload.extend_from_slice(&self.page_index.to_le_bytes());
        payload.extend_from_slice(&self.first_digest_index.to_le_bytes());
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        for digest in &self.digests {
            payload.extend_from_slice(digest.as_bytes());
        }

        Ok(Record::required(
            RECORD_TYPE,
            protection_set_id,
            logical_id(self.kind, self.page_index),
            payload,
        ))
    }

    /// Strictly decodes a digest-table page record.
    ///
    /// # Errors
    ///
    /// Returns an error if the record type, flags, logical identifier, header
    /// extension, or payload is not canonical experimental v1 encoding.
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

        let payload = wire::Reader::new(&record.payload, || Error::TruncatedPayload);
        let version = payload.u16(0)?;
        if version != PAYLOAD_VERSION {
            return Err(Error::UnsupportedPayloadVersion(version));
        }
        let kind = Kind::try_from(record.payload[2])?;
        if record.payload[3] != 0 {
            return Err(Error::ReservedField);
        }
        let page_index = payload.u32(4)?;
        let first_digest_index = payload.u64(8)?;
        let count = payload.u32(16)? as usize;
        validate_digest_count(count)?;
        if payload.u32(20)? != 0 {
            return Err(Error::ReservedField);
        }
        if record.logical_id != logical_id(kind, page_index) {
            return Err(Error::LogicalIdMismatch);
        }

        let digest_bytes = count.checked_mul(32).ok_or(Error::LengthOverflow)?;
        let expected_len = PAYLOAD_HEADER_LEN
            .checked_add(digest_bytes)
            .ok_or(Error::LengthOverflow)?;
        if record.payload.len() != expected_len {
            return Err(Error::PayloadLengthMismatch {
                actual: record.payload.len(),
                expected: expected_len,
            });
        }

        let (encoded_digests, remainder) = record.payload[PAYLOAD_HEADER_LEN..].as_chunks::<32>();
        if !remainder.is_empty() {
            return Err(Error::PayloadLengthMismatch {
                actual: record.payload.len(),
                expected: expected_len,
            });
        }
        let digests = encoded_digests
            .iter()
            .copied()
            .map(Digest::from_bytes)
            .collect();
        Self::new(kind, page_index, first_digest_index, digests)
    }
}

/// A complete digest table split into canonical pages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    pub kind: Kind,
    pub digest_count: u64,
    pub root: Digest,
    pub pages: Vec<Page>,
}

impl Table {
    /// Builds canonical pages without retaining a second copy of the digests.
    ///
    /// # Errors
    ///
    /// Returns an error if the digest or page count cannot be represented by
    /// the format.
    pub fn new(kind: Kind, digests: Vec<Digest>) -> Result<Self, Error> {
        let root = table_root(kind, &digests)?;
        let built = paged_table::build_pages(
            digests,
            MAX_DIGESTS_PER_PAGE,
            |page_index, first_digest_index, page_digests| {
                Page::new(kind, page_index, first_digest_index, page_digests)
            },
        )
        .map_err(map_build_error)?;

        Ok(Self {
            kind,
            digest_count: built.item_count,
            root,
            pages: built.pages,
        })
    }

    /// Assembles validated pages, accepting identical redundant copies.
    ///
    /// Input order is irrelevant. Every expected page must be present, page
    /// geometry must be canonical, and the completed table must match
    /// `expected_root`.
    ///
    /// # Errors
    ///
    /// Returns an error before allocation if declared geometry exceeds
    /// `limits`, or when pages are missing, conflicting, noncanonical, of the
    /// wrong kind, or inconsistent with `expected_root`.
    pub fn assemble<I>(
        kind: Kind,
        digest_count: u64,
        expected_root: Digest,
        pages: I,
        limits: AssemblyLimits,
    ) -> Result<Self, AssemblyError>
    where
        I: IntoIterator<Item = Page>,
    {
        let pages = paged_table::assemble(
            digest_count,
            MAX_DIGESTS_PER_PAGE,
            pages,
            paged_table::Limits {
                max_items: limits.max_digests,
                max_pages: limits.max_pages,
            },
            |page| {
                if page.kind == kind {
                    Ok(())
                } else {
                    Err(AssemblyError::WrongKind {
                        page_index: page.page_index,
                        expected: kind,
                        actual: page.kind,
                    })
                }
            },
        )
        .map_err(map_paged_table_error)?;
        let actual_root = table_root_iter(
            kind,
            digest_count,
            pages.iter().flat_map(|page| page.digests.iter()),
        );
        if actual_root != expected_root {
            return Err(AssemblyError::RootMismatch {
                expected: expected_root,
                actual: actual_root,
            });
        }

        Ok(Self {
            kind,
            digest_count,
            root: actual_root,
            pages,
        })
    }

    pub fn digests(&self) -> impl Iterator<Item = &Digest> {
        self.pages.iter().flat_map(|page| page.digests.iter())
    }
}

fn map_build_error(error: paged_table::BuildError<Error>) -> Error {
    match error {
        paged_table::BuildError::InvalidItemsPerPage
        | paged_table::BuildError::ItemCountUnrepresentable => Error::LengthOverflow,
        paged_table::BuildError::PageCountUnrepresentable => Error::TooManyPages,
        paged_table::BuildError::ItemIndexOverflow => Error::DigestIndexOverflow,
        paged_table::BuildError::InvalidPage(error) => error,
    }
}

/// Caller-selected limits enforced before table assembly allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyLimits {
    pub max_digests: u64,
    pub max_pages: u32,
}

impl AssemblyLimits {
    #[must_use]
    pub const fn new(max_digests: u64, max_pages: u32) -> Self {
        Self {
            max_digests,
            max_pages,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssemblyError {
    DigestLimitExceeded {
        actual: u64,
        maximum: u64,
    },
    PageLimitExceeded {
        actual: u64,
        maximum: u32,
    },
    DigestCountUnrepresentable,
    PageCountUnrepresentable,
    LengthOverflow,
    WrongKind {
        page_index: u32,
        expected: Kind,
        actual: Kind,
    },
    PageIndexOutOfRange {
        page_index: u32,
        page_count: u32,
    },
    FirstDigestIndexMismatch {
        page_index: u32,
        actual: u64,
        expected: u64,
    },
    PageDigestCountMismatch {
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
            Self::DigestLimitExceeded { actual, maximum } => write!(
                formatter,
                "digest count {actual} exceeds assembly limit {maximum}"
            ),
            Self::PageLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "page count {actual} exceeds assembly limit {maximum}"
                )
            }
            Self::DigestCountUnrepresentable => {
                formatter.write_str("digest count cannot be represented on this platform")
            }
            Self::PageCountUnrepresentable => {
                formatter.write_str("page count cannot be represented on this platform")
            }
            Self::LengthOverflow => formatter.write_str("digest-table geometry overflows"),
            Self::WrongKind {
                page_index,
                expected,
                actual,
            } => write!(
                formatter,
                "page {page_index} has kind {actual:?}, expected {expected:?}"
            ),
            Self::PageIndexOutOfRange {
                page_index,
                page_count,
            } => write!(
                formatter,
                "page index {page_index} is outside table page count {page_count}"
            ),
            Self::FirstDigestIndexMismatch {
                page_index,
                actual,
                expected,
            } => write!(
                formatter,
                "page {page_index} starts at digest {actual}, expected {expected}"
            ),
            Self::PageDigestCountMismatch {
                page_index,
                actual,
                expected,
            } => write!(
                formatter,
                "page {page_index} contains {actual} digests, expected {expected}"
            ),
            Self::ConflictingPage(page_index) => {
                write!(formatter, "valid copies of page {page_index} conflict")
            }
            Self::MissingPages(pages) => write!(formatter, "missing digest-table pages {pages:?}"),
            Self::RootMismatch { .. } => formatter.write_str("digest-table root does not match"),
        }
    }
}

impl std::error::Error for AssemblyError {}

fn map_paged_table_error(error: paged_table::Error<AssemblyError>) -> AssemblyError {
    match error {
        paged_table::Error::ItemLimitExceeded { actual, maximum } => {
            AssemblyError::DigestLimitExceeded { actual, maximum }
        }
        paged_table::Error::PageLimitExceeded { actual, maximum } => {
            AssemblyError::PageLimitExceeded { actual, maximum }
        }
        paged_table::Error::ItemCountUnrepresentable => AssemblyError::DigestCountUnrepresentable,
        paged_table::Error::PageCountUnrepresentable => AssemblyError::PageCountUnrepresentable,
        paged_table::Error::LengthOverflow => AssemblyError::LengthOverflow,
        paged_table::Error::InvalidPage(error) => error,
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
        } => AssemblyError::FirstDigestIndexMismatch {
            page_index,
            actual,
            expected,
        },
        paged_table::Error::PageItemCountMismatch {
            page_index,
            actual,
            expected,
        } => AssemblyError::PageDigestCountMismatch {
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

/// Hashes a canonical ordered digest table independently of page boundaries.
///
/// # Errors
///
/// Returns an error if the digest count cannot be represented as `u64`.
pub fn table_root(kind: Kind, digests: &[Digest]) -> Result<Digest, Error> {
    let count = u64::try_from(digests.len()).map_err(|_| Error::LengthOverflow)?;
    Ok(table_root_iter(kind, count, digests))
}

fn table_root_iter<'a, I>(kind: Kind, count: u64, digests: I) -> Digest
where
    I: IntoIterator<Item = &'a Digest>,
{
    let mut hasher = blake3::Hasher::new_derive_key(kind.root_context());
    hasher.update(&count.to_le_bytes());
    for digest in digests {
        hasher.update(digest.as_bytes());
    }
    hasher.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyPage,
    TooManyDigests(usize),
    TooManyPages,
    DigestIndexOverflow,
    LengthOverflow,
    WrongRecordType(u16),
    InvalidRecordFlags(u32),
    UnsupportedHeaderExtension,
    TruncatedPayload,
    UnsupportedPayloadVersion(u16),
    UnknownKind(u8),
    ReservedField,
    LogicalIdMismatch,
    PayloadLengthMismatch { actual: usize, expected: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPage => formatter.write_str("digest-table page is empty"),
            Self::TooManyDigests(count) => write!(
                formatter,
                "digest-table page contains {count} digests; maximum is {MAX_DIGESTS_PER_PAGE}"
            ),
            Self::TooManyPages => formatter.write_str("digest table has too many pages"),
            Self::DigestIndexOverflow => formatter.write_str("digest-table index overflows u64"),
            Self::LengthOverflow => formatter.write_str("digest-table length is unrepresentable"),
            Self::WrongRecordType(actual) => {
                write!(formatter, "record type {actual} is not a digest-table page")
            }
            Self::InvalidRecordFlags(actual) => {
                write!(
                    formatter,
                    "digest-table record has invalid flags {actual:#x}"
                )
            }
            Self::UnsupportedHeaderExtension => {
                formatter.write_str("digest-table record has an unsupported header extension")
            }
            Self::TruncatedPayload => formatter.write_str("digest-table payload is truncated"),
            Self::UnsupportedPayloadVersion(version) => {
                write!(
                    formatter,
                    "unsupported digest-table payload version {version}"
                )
            }
            Self::UnknownKind(kind) => write!(formatter, "unknown digest-table kind {kind}"),
            Self::ReservedField => {
                formatter.write_str("digest-table payload has a nonzero reserved field")
            }
            Self::LogicalIdMismatch => {
                formatter.write_str("digest-table logical identifier does not match its payload")
            }
            Self::PayloadLengthMismatch { actual, expected } => write!(
                formatter,
                "digest-table payload length is {actual}, expected {expected}"
            ),
        }
    }
}

impl std::error::Error for Error {}

const fn logical_id(kind: Kind, page_index: u32) -> u64 {
    ((kind as u64) << LOGICAL_KIND_SHIFT) | page_index as u64
}

fn validate_digest_count(count: usize) -> Result<(), Error> {
    if count == 0 {
        return Err(Error::EmptyPage);
    }
    if count > MAX_DIGESTS_PER_PAGE {
        return Err(Error::TooManyDigests(count));
    }
    Ok(())
}

fn validate_digest_range(first_digest_index: u64, count: usize) -> Result<(), Error> {
    first_digest_index
        .checked_add(u64::try_from(count).map_err(|_| Error::LengthOverflow)?)
        .ok_or(Error::DigestIndexOverflow)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{self, DecodeLimits};
    use std::io::Cursor;

    fn digest(value: u64) -> Digest {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        Digest::from_bytes(bytes)
    }

    fn page() -> Page {
        Page::new(Kind::Data, 3, 12_288, vec![digest(1), digest(2)]).unwrap()
    }

    fn two_page_table() -> Table {
        let last_digest = u64::try_from(MAX_DIGESTS_PER_PAGE).unwrap();
        Table::new(Kind::Data, (0..=last_digest).map(digest).collect()).unwrap()
    }

    fn assembly_limits() -> AssemblyLimits {
        AssemblyLimits::new(10_000, 10)
    }

    #[test]
    fn builds_canonical_pages() {
        let last_digest = u64::try_from(MAX_DIGESTS_PER_PAGE).unwrap();
        let digests: Vec<_> = (0..=last_digest).map(digest).collect();
        let expected_root = table_root(Kind::Data, &digests).unwrap();
        let table = Table::new(Kind::Data, digests).unwrap();

        assert_eq!(table.digest_count, last_digest + 1);
        assert_eq!(table.root, expected_root);
        assert_eq!(table.pages.len(), 2);
        assert_eq!(table.pages[0].page_index, 0);
        assert_eq!(table.pages[0].first_digest_index, 0);
        assert_eq!(table.pages[0].digests.len(), MAX_DIGESTS_PER_PAGE);
        assert_eq!(table.pages[1].page_index, 1);
        assert_eq!(table.pages[1].first_digest_index, last_digest);
        assert_eq!(table.pages[1].digests, vec![digest(last_digest)]);
    }

    #[test]
    fn empty_table_has_a_root_and_no_pages() {
        let table = Table::new(Kind::Recovery, Vec::new()).unwrap();

        assert_eq!(table.digest_count, 0);
        assert!(table.pages.is_empty());
        assert_eq!(table.root, table_root(Kind::Recovery, &[]).unwrap());
    }

    #[test]
    fn assembles_out_of_order_pages_and_collapses_identical_copies() {
        let expected = two_page_table();
        let pages = vec![
            expected.pages[1].clone(),
            expected.pages[0].clone(),
            expected.pages[0].clone(),
        ];

        let actual = Table::assemble(
            expected.kind,
            expected.digest_count,
            expected.root,
            pages,
            assembly_limits(),
        )
        .unwrap();

        assert_eq!(actual, expected);
        assert_eq!(
            actual.digests().count(),
            usize::try_from(expected.digest_count).unwrap()
        );
    }

    #[test]
    fn assembly_rejects_missing_and_conflicting_pages() {
        let expected = two_page_table();
        assert_eq!(
            Table::assemble(
                expected.kind,
                expected.digest_count,
                expected.root,
                vec![expected.pages[0].clone()],
                assembly_limits(),
            )
            .unwrap_err(),
            AssemblyError::MissingPages(vec![1])
        );

        let mut conflict = expected.pages[0].clone();
        conflict.digests[0] = digest(999);
        assert_eq!(
            Table::assemble(
                expected.kind,
                expected.digest_count,
                expected.root,
                vec![
                    expected.pages[0].clone(),
                    conflict,
                    expected.pages[1].clone()
                ],
                assembly_limits(),
            )
            .unwrap_err(),
            AssemblyError::ConflictingPage(0)
        );
    }

    #[test]
    fn assembly_rejects_noncanonical_page_geometry() {
        let expected = two_page_table();

        let mut wrong_kind = expected.pages[0].clone();
        wrong_kind.kind = Kind::Recovery;
        assert!(matches!(
            Table::assemble(
                expected.kind,
                expected.digest_count,
                expected.root,
                vec![wrong_kind],
                assembly_limits(),
            ),
            Err(AssemblyError::WrongKind { .. })
        ));

        let mut wrong_start = expected.pages[0].clone();
        wrong_start.first_digest_index = 1;
        assert!(matches!(
            Table::assemble(
                expected.kind,
                expected.digest_count,
                expected.root,
                vec![wrong_start],
                assembly_limits(),
            ),
            Err(AssemblyError::FirstDigestIndexMismatch { .. })
        ));

        let mut wrong_count = expected.pages[0].clone();
        wrong_count.digests.pop();
        assert!(matches!(
            Table::assemble(
                expected.kind,
                expected.digest_count,
                expected.root,
                vec![wrong_count],
                assembly_limits(),
            ),
            Err(AssemblyError::PageDigestCountMismatch { .. })
        ));

        let out_of_range = Page::new(
            Kind::Data,
            2,
            u64::try_from(MAX_DIGESTS_PER_PAGE * 2).unwrap(),
            vec![digest(0)],
        )
        .unwrap();
        assert!(matches!(
            Table::assemble(
                expected.kind,
                expected.digest_count,
                expected.root,
                vec![out_of_range],
                assembly_limits(),
            ),
            Err(AssemblyError::PageIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn assembly_enforces_limits_before_page_slots_are_allocated() {
        let expected = two_page_table();
        assert!(matches!(
            Table::assemble(
                expected.kind,
                expected.digest_count,
                expected.root,
                Vec::new(),
                AssemblyLimits::new(expected.digest_count - 1, 10),
            ),
            Err(AssemblyError::DigestLimitExceeded { .. })
        ));
        assert!(matches!(
            Table::assemble(
                expected.kind,
                expected.digest_count,
                expected.root,
                Vec::new(),
                AssemblyLimits::new(expected.digest_count, 1),
            ),
            Err(AssemblyError::PageLimitExceeded { .. })
        ));
    }

    #[test]
    fn assembly_verifies_root_and_handles_an_empty_table() {
        let expected = two_page_table();
        assert!(matches!(
            Table::assemble(
                expected.kind,
                expected.digest_count,
                digest(999),
                expected.pages,
                assembly_limits(),
            ),
            Err(AssemblyError::RootMismatch { .. })
        ));

        let empty_root = table_root(Kind::Recovery, &[]).unwrap();
        let empty = Table::assemble(
            Kind::Recovery,
            0,
            empty_root,
            Vec::new(),
            AssemblyLimits::new(0, 0),
        )
        .unwrap();
        assert!(empty.pages.is_empty());

        assert!(matches!(
            Table::assemble(
                Kind::Recovery,
                0,
                empty_root,
                vec![Page::new(Kind::Recovery, 0, 0, vec![digest(0)]).unwrap()],
                AssemblyLimits::new(1, 1),
            ),
            Err(AssemblyError::PageIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn table_root_commits_to_kind_order_and_count() {
        let ordered = vec![digest(1), digest(2)];
        let reversed = vec![digest(2), digest(1)];

        assert_ne!(
            table_root(Kind::Data, &ordered).unwrap(),
            table_root(Kind::Recovery, &ordered).unwrap()
        );
        assert_ne!(
            table_root(Kind::Data, &ordered).unwrap(),
            table_root(Kind::Data, &reversed).unwrap()
        );
        assert_ne!(
            table_root(Kind::Data, &ordered[..1]).unwrap(),
            table_root(Kind::Data, &ordered).unwrap()
        );
    }

    #[test]
    fn page_round_trips_through_physical_record_codec() {
        let expected = page();
        let expected_set_id = [0x3c; 32];
        let record = expected.to_record(expected_set_id).unwrap();
        let mut encoded = Vec::new();
        record::write(&mut encoded, &record).unwrap();
        let decoded_record = record::read(
            &mut Cursor::new(encoded),
            DecodeLimits::new(4_096, 1024 * 1024),
        )
        .unwrap()
        .unwrap();

        assert_eq!(decoded_record.protection_set_id, expected_set_id);
        assert_eq!(Page::from_record(&decoded_record).unwrap(), expected);
    }

    #[test]
    fn page_constructor_rejects_invalid_counts_and_ranges() {
        assert_eq!(
            Page::new(Kind::Data, 0, 0, Vec::new()).unwrap_err(),
            Error::EmptyPage
        );
        assert!(matches!(
            Page::new(Kind::Data, 0, 0, vec![digest(0); MAX_DIGESTS_PER_PAGE + 1]),
            Err(Error::TooManyDigests(_))
        ));
        assert_eq!(
            Page::new(Kind::Data, 0, u64::MAX, vec![digest(0)]).unwrap_err(),
            Error::DigestIndexOverflow
        );

        let mut mutated = page();
        mutated.first_digest_index = u64::MAX;
        assert_eq!(
            mutated.to_record([0; 32]).unwrap_err(),
            Error::DigestIndexOverflow
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_record_metadata() {
        let canonical = page().to_record([0; 32]).unwrap();

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

        let mut extension = canonical.clone();
        extension.header_extension.push(1);
        assert_eq!(
            Page::from_record(&extension).unwrap_err(),
            Error::UnsupportedHeaderExtension
        );

        let mut logical_id = canonical;
        logical_id.logical_id ^= 1;
        assert_eq!(
            Page::from_record(&logical_id).unwrap_err(),
            Error::LogicalIdMismatch
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_payload() {
        let canonical = page().to_record([0; 32]).unwrap();

        for length in 0..PAYLOAD_HEADER_LEN {
            let mut truncated = canonical.clone();
            truncated.payload.truncate(length);
            assert_eq!(
                Page::from_record(&truncated).unwrap_err(),
                Error::TruncatedPayload
            );
        }

        let mut version = canonical.clone();
        version.payload[0..2].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            Page::from_record(&version).unwrap_err(),
            Error::UnsupportedPayloadVersion(2)
        );

        let mut kind = canonical.clone();
        kind.payload[2] = 99;
        assert_eq!(
            Page::from_record(&kind).unwrap_err(),
            Error::UnknownKind(99)
        );

        for offset in [3, 20] {
            let mut reserved = canonical.clone();
            reserved.payload[offset] = 1;
            assert_eq!(
                Page::from_record(&reserved).unwrap_err(),
                Error::ReservedField
            );
        }

        let mut zero_count = canonical.clone();
        zero_count.payload[16..20].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            Page::from_record(&zero_count).unwrap_err(),
            Error::EmptyPage
        );

        let mut wrong_length = canonical;
        wrong_length.payload.pop();
        assert!(matches!(
            Page::from_record(&wrong_length),
            Err(Error::PayloadLengthMismatch { .. })
        ));
    }
}
