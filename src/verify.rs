//! Read-only source verification against authenticated protection metadata.

use crate::digest::Digest;
use crate::filesystem::FileIdentity;
use crate::fingerprint;
use crate::rolling::{self, Locator, ScanSummary, Target};
use crate::sidecar::Sidecar;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::ControlFlow;

/// Verification state of one data chunk at its expected source offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkState {
    /// The complete chunk matches its authenticated strong digest.
    Good,
    /// The expected number of bytes was readable, but its digest differs.
    Corrupt,
    /// The source ended before the complete expected chunk was available.
    Missing,
    /// Reading the chunk failed before all expected bytes were available.
    Unreadable(io::ErrorKind),
    /// The complete chunk was strongly confirmed at a noncanonical offset.
    UnexpectedlyLocated { offset: u64 },
}

impl ChunkState {
    #[must_use]
    pub const fn is_good(self) -> bool {
        matches!(self, Self::Good)
    }

    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Good | Self::UnexpectedlyLocated { .. })
    }
}

/// Verification result for one expected data chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkReport {
    pub index: u32,
    pub expected_len: u32,
    pub bytes_read: u32,
    pub state: ChunkState,
}

/// Whether a complete read of the observed source matches the manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceDigestState {
    Match,
    Mismatch,
    /// At least one source byte could not be read, so no complete digest exists.
    Unavailable,
}

/// Overall source condition and repair feasibility at expected chunk offsets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceState {
    Intact,
    Repairable,
    Unrepairable,
}

/// Structured result of complete expected-offset source verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub protection_set_id: [u8; 32],
    pub expected_source_len: u64,
    pub observed_source_len: u64,
    pub source_digest: SourceDigestState,
    pub chunks: Vec<ChunkReport>,
    pub good_data_chunks: u32,
    pub unexpectedly_located_data_chunks: u32,
    pub unavailable_data_chunks: u32,
    pub available_recovery_chunks: u32,
    pub unavailable_recovery_chunks: u32,
    pub state: SourceState,
}

/// Resource bound for an optional displaced-chunk scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocateOptions {
    pub max_targets: usize,
}

impl LocateOptions {
    #[must_use]
    pub const fn new(max_targets: usize) -> Self {
        Self { max_targets }
    }
}

/// Work performed and chunks recovered by one displaced-chunk scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocationSummary {
    pub eligible_chunks: u32,
    pub located_chunks: u32,
    pub scan: ScanSummary,
}

impl Report {
    /// Returns whether complete verification confirms the protected source
    /// contents, including the whole-source digest.
    #[must_use]
    pub const fn is_intact(&self) -> bool {
        matches!(self.state, SourceState::Intact)
            && matches!(self.source_digest, SourceDigestState::Match)
            && self.unavailable_data_chunks == 0
    }

    #[must_use]
    pub const fn has_unexpected_length(&self) -> bool {
        self.expected_source_len != self.observed_source_len
    }

    #[must_use]
    pub const fn required_recovery_chunks(&self) -> u32 {
        self.unavailable_data_chunks
    }
}

/// Verifies a seekable source against an already authenticated sidecar.
///
/// Every expected chunk is read independently at its canonical offset. A read
/// failure marks that chunk unreadable and verification seeks onward, allowing
/// later chunks to be classified when the underlying reader supports it. The
/// observed source, including trailing bytes, is read completely for its
/// whole-source digest. Memory use is one data chunk plus the returned report.
///
/// Recovery records have already been physically and cryptographically
/// authenticated by [`Sidecar::read`](crate::sidecar::Sidecar::read); this
/// function incorporates their availability into repair feasibility.
///
/// # Errors
///
/// Returns an error if source positioning fails, the source length changes
/// during verification, report counts cannot be represented, or the sidecar's
/// authenticated metadata has an inconsistent data-digest count.
pub fn source<R: Read + Seek>(reader: &mut R, sidecar: &Sidecar) -> Result<Report, Error> {
    let manifest = sidecar.metadata.manifest;
    let geometry = manifest.geometry();
    let observed_source_len = reader.seek(SeekFrom::End(0)).map_err(Error::SourceSeek)?;
    let mut data = verify_data_chunks(reader, sidecar)?;

    if observed_source_len > geometry.source_len {
        reader
            .seek(SeekFrom::Start(geometry.source_len))
            .map_err(Error::SourceSeek)?;
        hash_remainder(reader, &mut data.source_hasher).map_err(Error::TrailingRead)?;
    }
    let final_source_len = reader.seek(SeekFrom::End(0)).map_err(Error::SourceSeek)?;
    if final_source_len != observed_source_len {
        return Err(Error::SourceChanged {
            before: observed_source_len,
            after: final_source_len,
        });
    }

    let source_digest = source_digest_state(&data.source_hasher, data.digest_available, sidecar);
    let available_recovery_chunks = u32::try_from(sidecar.recovery.available_count())
        .map_err(|_| Error::CountUnrepresentable)?;
    let unavailable_recovery_chunks = geometry
        .recovery_chunks
        .checked_sub(available_recovery_chunks)
        .ok_or(Error::RecoveryCountMismatch)?;
    let counts = ChunkCounts::from_chunks(&data.chunks)?;
    let state = counts.source_state(
        available_recovery_chunks,
        observed_source_len,
        geometry.source_len,
        source_digest,
    );

    Ok(Report {
        protection_set_id: manifest.protection_set_id(),
        expected_source_len: geometry.source_len,
        observed_source_len,
        source_digest,
        chunks: data.chunks,
        good_data_chunks: counts.good,
        unexpectedly_located_data_chunks: counts.unexpectedly_located,
        unavailable_data_chunks: counts.unavailable,
        available_recovery_chunks,
        unavailable_recovery_chunks,
        state,
    })
}

/// Verifies an open file and rejects metadata-visible concurrent mutation.
///
/// In addition to the length checks performed by [`source`], this snapshots
/// the file's identity, modification time, and (on Unix) status-change time
/// around the complete operation. This is the preferred entry point for real
/// files because same-length writes are otherwise invisible to a generic
/// [`Read`] + [`Seek`] interface.
///
/// The check detects ordinary concurrent filesystem writers; it is not a lock
/// and cannot provide snapshot isolation against a writer able to conceal its
/// metadata changes.
///
/// # Errors
///
/// Returns the errors documented by [`source`], a file metadata error, or
/// [`Error::SourceMetadataChanged`] when the file changed during verification.
pub fn source_file(file: &mut File, sidecar: &Sidecar) -> Result<Report, Error> {
    with_stable_file(file, |file| source(file, sidecar))
}

/// Refines an expected-offset report by finding intact full chunks elsewhere.
///
/// Only chunks previously classified as [`ChunkState::Corrupt`] or
/// [`ChunkState::Missing`] become rolling targets. Unreadable chunks remain
/// erasures because a sequential rolling scan is not able to skip their I/O
/// failures reliably. The short final data chunk has no stored rolling value
/// and is likewise ineligible.
///
/// Matches are held separately until the complete scan succeeds and the
/// source length is rechecked. The report is therefore unchanged on error.
/// Multiple expected chunks with identical content may safely reuse the same
/// strongly confirmed physical bytes.
///
/// # Errors
///
/// Returns an error if the report does not belong to this sidecar, its public
/// structure is inconsistent, the source length changed since verification,
/// the target bound is exceeded, source positioning or scanning fails, or a
/// formerly bad chunk now matches at its canonical offset.
pub fn locate_displaced<R: Read + Seek>(
    reader: &mut R,
    sidecar: &Sidecar,
    report: &mut Report,
    options: LocateOptions,
) -> Result<LocationSummary, Error> {
    validate_report(sidecar, report)?;
    let geometry = sidecar.metadata.manifest.geometry();
    let before = reader.seek(SeekFrom::End(0)).map_err(Error::SourceSeek)?;
    if before != report.observed_source_len {
        return Err(Error::SourceChanged {
            before: report.observed_source_len,
            after: before,
        });
    }

    let targets = location_targets(sidecar, report)?;
    let eligible_chunks = u32::try_from(targets.len()).map_err(|_| Error::CountUnrepresentable)?;
    let locator = Locator::new(targets, options.max_targets).map_err(Error::Rolling)?;
    let mut locations = vec![None; report.chunks.len()];
    let mut remaining = eligible_chunks;
    let mut canonical_match = false;
    reader.seek(SeekFrom::Start(0)).map_err(Error::SourceSeek)?;
    let scan = locator
        .scan(reader, geometry.chunk_size, |found| {
            for index in found.chunk_indices {
                let Ok(slot_index) = usize::try_from(index) else {
                    continue;
                };
                let Some(slot) = locations.get_mut(slot_index) else {
                    continue;
                };
                if slot.is_some() {
                    continue;
                }
                let Some(layout) = geometry.data_chunk_layout(index) else {
                    continue;
                };
                if found.offset == layout.offset {
                    canonical_match = true;
                    return ControlFlow::Break(());
                }
                *slot = Some(found.offset);
                remaining = remaining.saturating_sub(1);
            }
            if remaining == 0 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .map_err(Error::Rolling)?;
    if canonical_match {
        return Err(Error::SourceChangedDuringLocation);
    }
    let after = reader.seek(SeekFrom::End(0)).map_err(Error::SourceSeek)?;
    if after != before {
        return Err(Error::SourceChanged { before, after });
    }

    let located_chunks = apply_locations(report, locations)?;
    recompute_report(report)?;
    Ok(LocationSummary {
        eligible_chunks,
        located_chunks,
        scan,
    })
}

/// Locates displaced chunks in an open file while checking for concurrent
/// metadata-visible mutation.
///
/// This is the file-native counterpart to [`locate_displaced`] and should be
/// used when the source is a real file.
///
/// # Errors
///
/// Returns the errors documented by [`locate_displaced`], a file metadata
/// error, or [`Error::SourceMetadataChanged`] when the file changes during the
/// scan.
pub fn locate_displaced_file(
    file: &mut File,
    sidecar: &Sidecar,
    report: &mut Report,
    options: LocateOptions,
) -> Result<LocationSummary, Error> {
    with_stable_file(file, |file| {
        locate_displaced(file, sidecar, report, options)
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileSnapshot {
    identity: FileIdentity,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(windows)]
    last_write_time: u64,
}

impl FileSnapshot {
    fn capture(file: &File) -> Result<Self, Error> {
        file.metadata()
            .map(|metadata| Self::from_metadata(&metadata))
            .map_err(Error::SourceMetadata)
    }

    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        #[cfg(windows)]
        use std::os::windows::fs::MetadataExt as _;

        Self {
            identity: FileIdentity::from_std(metadata),
            #[cfg(unix)]
            changed_seconds: metadata.ctime(),
            #[cfg(unix)]
            changed_nanoseconds: metadata.ctime_nsec(),
            #[cfg(windows)]
            last_write_time: metadata.last_write_time(),
        }
    }
}

fn with_stable_file<T>(
    file: &mut File,
    operation: impl FnOnce(&mut File) -> Result<T, Error>,
) -> Result<T, Error> {
    let before = FileSnapshot::capture(file)?;
    let value = operation(file)?;
    let after = FileSnapshot::capture(file)?;
    if before != after {
        return Err(Error::SourceMetadataChanged);
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedReport {
    available_data_chunks: u32,
    unavailable_data_chunks: u32,
}

impl ValidatedReport {
    pub(crate) const fn available_data_chunks(self) -> u32 {
        self.available_data_chunks
    }

    pub(crate) const fn unavailable_data_chunks(self) -> u32 {
        self.unavailable_data_chunks
    }
}

pub(crate) fn validate_report(
    sidecar: &Sidecar,
    report: &Report,
) -> Result<ValidatedReport, Error> {
    let manifest = sidecar.metadata.manifest;
    let geometry = manifest.geometry();
    if report.protection_set_id != manifest.protection_set_id() {
        return Err(Error::ReportProtectionSetMismatch);
    }
    let expected_count =
        usize::try_from(geometry.data_chunks).map_err(|_| Error::CountUnrepresentable)?;
    if report.chunks.len() != expected_count
        || report.expected_source_len != geometry.source_len
        || report.available_recovery_chunks
            != u32::try_from(sidecar.recovery.available_count())
                .map_err(|_| Error::CountUnrepresentable)?
        || report
            .available_recovery_chunks
            .checked_add(report.unavailable_recovery_chunks)
            != Some(geometry.recovery_chunks)
    {
        return Err(Error::ReportStructureMismatch);
    }
    for (expected_index, chunk) in report.chunks.iter().enumerate() {
        let expected_index =
            u32::try_from(expected_index).map_err(|_| Error::CountUnrepresentable)?;
        let Some(layout) = geometry.data_chunk_layout(expected_index) else {
            return Err(Error::ReportStructureMismatch);
        };
        if chunk.index != expected_index || chunk.expected_len != layout.len {
            return Err(Error::ReportStructureMismatch);
        }
        if let ChunkState::UnexpectedlyLocated { offset } = chunk.state {
            let end = offset
                .checked_add(u64::from(chunk.expected_len))
                .ok_or(Error::SourceOffsetOverflow)?;
            if chunk.expected_len != geometry.chunk_size.bytes()
                || offset == layout.offset
                || end > report.observed_source_len
            {
                return Err(Error::InvalidDisplacedLocation(chunk.index));
            }
        }
    }

    let counts = ChunkCounts::from_chunks(&report.chunks)?;
    let available = counts.available()?;
    if counts.good != report.good_data_chunks
        || counts.unexpectedly_located != report.unexpectedly_located_data_chunks
        || counts.unavailable != report.unavailable_data_chunks
        || available.checked_add(counts.unavailable) != Some(geometry.data_chunks)
        || counts.source_state(
            report.available_recovery_chunks,
            report.observed_source_len,
            report.expected_source_len,
            report.source_digest,
        ) != report.state
    {
        return Err(Error::ReportStructureMismatch);
    }
    Ok(ValidatedReport {
        available_data_chunks: available,
        unavailable_data_chunks: counts.unavailable,
    })
}

fn location_targets(sidecar: &Sidecar, report: &Report) -> Result<Vec<Target>, Error> {
    let geometry = sidecar.metadata.manifest.geometry();
    if sidecar.metadata.rolling_fingerprints.value_count != geometry.full_data_chunks()
        || sidecar.metadata.data_digests.digest_count != u64::from(geometry.data_chunks)
    {
        return Err(Error::FingerprintTableCountMismatch);
    }
    let full_chunks =
        usize::try_from(geometry.full_data_chunks()).map_err(|_| Error::CountUnrepresentable)?;
    let targets = sidecar
        .metadata
        .rolling_fingerprints
        .values()
        .zip(sidecar.metadata.data_digests.digests().copied())
        .zip(report.chunks.iter())
        .take(full_chunks)
        .filter(|(_, chunk)| matches!(chunk.state, ChunkState::Corrupt | ChunkState::Missing))
        .map(|((rolling, strong), chunk)| Target {
            chunk_index: chunk.index,
            rolling,
            strong,
        })
        .collect();
    Ok(targets)
}

fn apply_locations(report: &mut Report, locations: Vec<Option<u64>>) -> Result<u32, Error> {
    if locations.len() != report.chunks.len() {
        return Err(Error::ReportStructureMismatch);
    }
    let mut located = 0_u32;
    for (chunk, offset) in report.chunks.iter_mut().zip(locations) {
        if let Some(offset) = offset {
            chunk.state = ChunkState::UnexpectedlyLocated { offset };
            located = increment(located)?;
        }
    }
    Ok(located)
}

fn recompute_report(report: &mut Report) -> Result<(), Error> {
    let counts = ChunkCounts::from_chunks(&report.chunks)?;
    report.good_data_chunks = counts.good;
    report.unexpectedly_located_data_chunks = counts.unexpectedly_located;
    report.unavailable_data_chunks = counts.unavailable;
    report.state = counts.source_state(
        report.available_recovery_chunks,
        report.observed_source_len,
        report.expected_source_len,
        report.source_digest,
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ChunkCounts {
    good: u32,
    unexpectedly_located: u32,
    unavailable: u32,
}

impl ChunkCounts {
    fn from_chunks(chunks: &[ChunkReport]) -> Result<Self, Error> {
        let mut counts = Self::default();
        for chunk in chunks {
            let counter = match chunk.state {
                ChunkState::Good => &mut counts.good,
                ChunkState::UnexpectedlyLocated { .. } => &mut counts.unexpectedly_located,
                ChunkState::Corrupt | ChunkState::Missing | ChunkState::Unreadable(_) => {
                    &mut counts.unavailable
                }
            };
            *counter = increment(*counter)?;
        }
        Ok(counts)
    }

    fn available(self) -> Result<u32, Error> {
        self.good
            .checked_add(self.unexpectedly_located)
            .ok_or(Error::CountUnrepresentable)
    }

    const fn source_state(
        self,
        available_recovery: u32,
        observed_len: u64,
        expected_len: u64,
        source_digest: SourceDigestState,
    ) -> SourceState {
        if self.unavailable == 0
            && observed_len == expected_len
            && matches!(source_digest, SourceDigestState::Match)
            && self.unexpectedly_located == 0
        {
            SourceState::Intact
        } else if self.unavailable == 0
            && observed_len == expected_len
            && matches!(source_digest, SourceDigestState::Mismatch)
            && self.unexpectedly_located == 0
        {
            // Chunk and whole-source commitments disagree, so there is no known
            // erasure whose reconstruction could satisfy both.
            SourceState::Unrepairable
        } else if self.unavailable <= available_recovery {
            SourceState::Repairable
        } else {
            SourceState::Unrepairable
        }
    }
}

struct DataVerification {
    source_hasher: blake3::Hasher,
    digest_available: bool,
    chunks: Vec<ChunkReport>,
}

fn verify_data_chunks<R: Read + Seek>(
    reader: &mut R,
    sidecar: &Sidecar,
) -> Result<DataVerification, Error> {
    let geometry = sidecar.metadata.manifest.geometry();
    let chunk_bytes =
        usize::try_from(geometry.chunk_size.bytes()).map_err(|_| Error::LengthUnrepresentable)?;
    let mut buffer = vec![0_u8; chunk_bytes];
    let mut source_hasher = fingerprint::source_digest_hasher();
    let mut digest_available = true;
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(
            usize::try_from(geometry.data_chunks).map_err(|_| Error::CountUnrepresentable)?,
        )
        .map_err(Error::ReportAllocation)?;
    let mut expected_digests = sidecar.metadata.data_digests.digests().copied();
    for index in 0..geometry.data_chunks {
        let expected_digest = expected_digests
            .next()
            .ok_or(Error::DataDigestCountMismatch)?;
        let layout = geometry
            .data_chunk_layout(index)
            .ok_or(Error::SourceOffsetOverflow)?;
        reader
            .seek(SeekFrom::Start(layout.offset))
            .map_err(Error::SourceSeek)?;
        let expected_len_usize =
            usize::try_from(layout.len).map_err(|_| Error::LengthUnrepresentable)?;
        let read = read_chunk(
            reader,
            &mut buffer[..expected_len_usize],
            &mut source_hasher,
        );
        let (bytes_read, state) = classify_chunk(
            read,
            &buffer[..expected_len_usize],
            layout.len,
            expected_digest,
        )?;
        digest_available &= !matches!(state, ChunkState::Unreadable(_));
        chunks.push(ChunkReport {
            index,
            expected_len: layout.len,
            bytes_read,
            state,
        });
    }
    if expected_digests.next().is_some() {
        return Err(Error::DataDigestCountMismatch);
    }
    Ok(DataVerification {
        source_hasher,
        digest_available,
        chunks,
    })
}

fn classify_chunk(
    read: ChunkRead,
    bytes: &[u8],
    expected_len: u32,
    expected_digest: Digest,
) -> Result<(u32, ChunkState), Error> {
    match read {
        ChunkRead::Complete => {
            let state = if fingerprint::data_chunk_digest(bytes) == expected_digest {
                ChunkState::Good
            } else {
                ChunkState::Corrupt
            };
            Ok((expected_len, state))
        }
        ChunkRead::Eof(bytes_read) => Ok((
            u32::try_from(bytes_read).map_err(|_| Error::LengthUnrepresentable)?,
            ChunkState::Missing,
        )),
        ChunkRead::Error { bytes_read, kind } => Ok((
            u32::try_from(bytes_read).map_err(|_| Error::LengthUnrepresentable)?,
            ChunkState::Unreadable(kind),
        )),
    }
}

fn source_digest_state(
    source_hasher: &blake3::Hasher,
    available: bool,
    sidecar: &Sidecar,
) -> SourceDigestState {
    if !available {
        return SourceDigestState::Unavailable;
    }
    let actual: Digest = source_hasher.finalize().into();
    if actual == sidecar.metadata.manifest.source_digest() {
        SourceDigestState::Match
    } else {
        SourceDigestState::Mismatch
    }
}

#[derive(Clone, Copy)]
enum ChunkRead {
    Complete,
    Eof(usize),
    Error {
        bytes_read: usize,
        kind: io::ErrorKind,
    },
}

fn read_chunk<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    source_hasher: &mut blake3::Hasher,
) -> ChunkRead {
    let mut filled = 0_usize;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => return ChunkRead::Eof(filled),
            Ok(count) => {
                source_hasher.update(&buffer[filled..filled + count]);
                filled += count;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return ChunkRead::Error {
                    bytes_read: filled,
                    kind: error.kind(),
                };
            }
        }
    }
    ChunkRead::Complete
}

fn hash_remainder<R: Read>(reader: &mut R, source_hasher: &mut blake3::Hasher) -> io::Result<()> {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                source_hasher.update(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn increment(value: u32) -> Result<u32, Error> {
    value.checked_add(1).ok_or(Error::CountUnrepresentable)
}

#[derive(Debug)]
pub enum Error {
    SourceSeek(io::Error),
    SourceMetadata(io::Error),
    TrailingRead(io::Error),
    SourceChanged { before: u64, after: u64 },
    SourceMetadataChanged,
    SourceChangedDuringLocation,
    ReportProtectionSetMismatch,
    ReportStructureMismatch,
    InvalidDisplacedLocation(u32),
    FingerprintTableCountMismatch,
    DataDigestCountMismatch,
    RecoveryCountMismatch,
    SourceOffsetOverflow,
    LengthUnrepresentable,
    CountUnrepresentable,
    ReportAllocation(std::collections::TryReserveError),
    Rolling(rolling::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceSeek(error) => write!(formatter, "source positioning failed: {error}"),
            Self::SourceMetadata(error) => {
                write!(formatter, "cannot inspect source file metadata: {error}")
            }
            Self::TrailingRead(error) => write!(formatter, "trailing source read failed: {error}"),
            Self::SourceChanged { before, after } => write!(
                formatter,
                "source length changed during verification from {before} to {after} bytes"
            ),
            Self::SourceMetadataChanged => {
                formatter.write_str("source file metadata changed during verification")
            }
            Self::SourceChangedDuringLocation => formatter
                .write_str("a previously unavailable chunk now matches at its canonical offset"),
            Self::ReportProtectionSetMismatch => {
                formatter.write_str("verification report belongs to another protection set")
            }
            Self::ReportStructureMismatch => {
                formatter.write_str("verification report structure disagrees with the sidecar")
            }
            Self::InvalidDisplacedLocation(index) => {
                write!(formatter, "chunk {index} has an invalid displaced location")
            }
            Self::FingerprintTableCountMismatch => {
                formatter.write_str("sidecar fingerprint table counts disagree with its geometry")
            }
            Self::DataDigestCountMismatch => {
                formatter.write_str("sidecar data-digest count disagrees with its geometry")
            }
            Self::RecoveryCountMismatch => {
                formatter.write_str("available recovery count exceeds sidecar geometry")
            }
            Self::SourceOffsetOverflow => formatter.write_str("source chunk offset overflows u64"),
            Self::LengthUnrepresentable => {
                formatter.write_str("source or chunk length is not representable")
            }
            Self::CountUnrepresentable => {
                formatter.write_str("verification report count is not representable")
            }
            Self::ReportAllocation(error) => {
                write!(
                    formatter,
                    "cannot reserve verification report storage: {error}"
                )
            }
            Self::Rolling(error) => write!(formatter, "displaced-chunk scan failed: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SourceSeek(error) | Self::SourceMetadata(error) | Self::TrailingRead(error) => {
                Some(error)
            }
            Self::ReportAllocation(error) => Some(error),
            Self::Rolling(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{self, Options};
    use crate::creator::Creator;
    use crate::geometry::{ChunkSize, MIN_CHUNK_SIZE, Redundancy};
    use crate::recovery_set::{AssemblyLimits, RecoverySet};
    use std::fs::{self, OpenOptions};
    use std::io::{Cursor, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const CHUNK_BYTES: usize = MIN_CHUNK_SIZE as usize;

    fn original() -> Vec<u8> {
        [0x11, 0x72, 0xc3]
            .into_iter()
            .flat_map(|value| vec![value; CHUNK_BYTES])
            .collect()
    }

    fn sidecar(bytes: &[u8]) -> Sidecar {
        let options = Options::new(
            ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap(),
            Redundancy::new(1, 3).unwrap(),
            1_024,
            Creator::new("bitrot", "test").unwrap(),
        );
        create::build(&mut Cursor::new(bytes), &options).unwrap()
    }

    struct TestFile {
        path: PathBuf,
        file: File,
    }

    impl TestFile {
        fn new(bytes: &[u8]) -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("bitrot-verify-test-{}-{id}", std::process::id()));
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            Self { path, file }
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn classifies_an_intact_source() {
        let bytes = original();
        let sidecar = sidecar(&bytes);
        let report = source(&mut Cursor::new(bytes), &sidecar).unwrap();

        assert!(report.is_intact());
        assert_eq!(report.state, SourceState::Intact);
        assert_eq!(report.source_digest, SourceDigestState::Match);
        assert_eq!(report.good_data_chunks, 3);
        assert_eq!(report.unexpectedly_located_data_chunks, 0);
        assert_eq!(report.unavailable_data_chunks, 0);
        assert_eq!(report.available_recovery_chunks, 1);
        assert_eq!(report.unavailable_recovery_chunks, 0);
        assert!(report.chunks.iter().all(|chunk| chunk.state.is_good()));

        let mut wrong_state = report.clone();
        wrong_state.state = SourceState::Repairable;
        let mut wrong_digest = report.clone();
        wrong_digest.source_digest = SourceDigestState::Mismatch;
        let mut unavailable_chunk = report.clone();
        unavailable_chunk.unavailable_data_chunks = 1;
        assert!(!wrong_state.is_intact());
        assert!(!wrong_digest.is_intact());
        assert!(!unavailable_chunk.is_intact());
    }

    #[test]
    fn report_validation_owns_derived_counts_state_and_locations() {
        let bytes = original();
        let sidecar = sidecar(&bytes);
        let report = source(&mut Cursor::new(&bytes), &sidecar).unwrap();
        let validated = validate_report(&sidecar, &report).unwrap();
        assert_eq!(validated.available_data_chunks(), 3);
        assert_eq!(validated.unavailable_data_chunks(), 0);

        let mut wrong_count = report.clone();
        wrong_count.good_data_chunks -= 1;
        assert!(matches!(
            validate_report(&sidecar, &wrong_count),
            Err(Error::ReportStructureMismatch)
        ));

        let mut wrong_state = report;
        wrong_state.state = SourceState::Repairable;
        assert!(matches!(
            validate_report(&sidecar, &wrong_state),
            Err(Error::ReportStructureMismatch)
        ));

        let mut damaged = bytes;
        damaged[19] ^= 1;
        let mut canonical_location = source(&mut Cursor::new(damaged), &sidecar).unwrap();
        canonical_location.chunks[0].state = ChunkState::UnexpectedlyLocated { offset: 0 };
        canonical_location.unavailable_data_chunks = 0;
        canonical_location.unexpectedly_located_data_chunks = 1;
        assert!(matches!(
            validate_report(&sidecar, &canonical_location),
            Err(Error::InvalidDisplacedLocation(0))
        ));
    }

    #[test]
    fn file_verification_accepts_an_unchanged_file() {
        let bytes = original();
        let sidecar = sidecar(&bytes);
        let mut source = TestFile::new(&bytes);

        let report = source_file(&mut source.file, &sidecar).unwrap();

        assert_eq!(report.state, SourceState::Intact);
        assert_eq!(report.source_digest, SourceDigestState::Match);
    }

    #[cfg(unix)]
    #[test]
    fn file_verification_guard_rejects_same_length_mutation() {
        let bytes = original();
        let mut source = TestFile::new(&bytes);
        let before = FileSnapshot::capture(&source.file).unwrap();
        let mut writer = OpenOptions::new().write(true).open(&source.path).unwrap();

        let result = with_stable_file(&mut source.file, |_file| {
            for value in 0_u8..=u8::MAX {
                writer.seek(SeekFrom::Start(0)).unwrap();
                writer.write_all(&[value]).unwrap();
                writer.sync_data().unwrap();
                if FileSnapshot::capture(&writer).unwrap() != before {
                    return Ok(());
                }
            }
            panic!("filesystem did not expose any metadata change");
        });

        assert!(matches!(result, Err(Error::SourceMetadataChanged)));
        assert_eq!(source.file.metadata().unwrap().len(), bytes.len() as u64);
    }

    #[test]
    fn distinguishes_repairable_and_unrepairable_corruption() {
        let original = original();
        let sidecar = sidecar(&original);
        let mut one_bad = original.clone();
        one_bad[19] ^= 1;
        let repairable = source(&mut Cursor::new(one_bad), &sidecar).unwrap();

        assert_eq!(repairable.state, SourceState::Repairable);
        assert_eq!(repairable.source_digest, SourceDigestState::Mismatch);
        assert_eq!(repairable.required_recovery_chunks(), 1);
        assert_eq!(repairable.chunks[0].state, ChunkState::Corrupt);

        let mut two_bad = original;
        two_bad[19] ^= 1;
        two_bad[CHUNK_BYTES + 23] ^= 1;
        let unrepairable = source(&mut Cursor::new(two_bad), &sidecar).unwrap();
        assert_eq!(unrepairable.state, SourceState::Unrepairable);
        assert_eq!(unrepairable.required_recovery_chunks(), 2);
    }

    #[test]
    fn unavailable_recovery_records_reduce_repair_capacity() {
        let original = original();
        let mut sidecar = sidecar(&original);
        let manifest = sidecar.metadata.manifest;
        sidecar.recovery = RecoverySet::assemble(
            &[],
            manifest,
            sidecar.metadata.recovery_digests.digests().copied(),
            AssemblyLimits::new(1, manifest.geometry().recovery_chunks),
        )
        .unwrap();
        let mut damaged = original;
        damaged[19] ^= 1;
        let report = source(&mut Cursor::new(damaged), &sidecar).unwrap();

        assert_eq!(report.available_recovery_chunks, 0);
        assert_eq!(report.unavailable_recovery_chunks, 1);
        assert_eq!(report.required_recovery_chunks(), 1);
        assert_eq!(report.state, SourceState::Unrepairable);
    }

    #[test]
    fn reports_truncation_and_extension_without_inventing_erased_chunks() {
        let original = original();
        let sidecar = sidecar(&original);
        let shortened = original[..original.len() - 17].to_vec();
        let truncated = source(&mut Cursor::new(shortened), &sidecar).unwrap();

        assert_eq!(truncated.state, SourceState::Repairable);
        assert!(truncated.has_unexpected_length());
        assert_eq!(truncated.chunks[2].state, ChunkState::Missing);
        assert_eq!(truncated.chunks[2].bytes_read, MIN_CHUNK_SIZE - 17);
        assert_eq!(truncated.required_recovery_chunks(), 1);

        let mut extended = original;
        extended.extend_from_slice(b"unexpected trailer");
        let extension = source(&mut Cursor::new(extended), &sidecar).unwrap();
        assert_eq!(extension.state, SourceState::Repairable);
        assert_eq!(extension.source_digest, SourceDigestState::Mismatch);
        assert!(extension.has_unexpected_length());
        assert_eq!(extension.good_data_chunks, 3);
        assert_eq!(extension.required_recovery_chunks(), 0);
    }

    struct UnreadableChunk {
        inner: Cursor<Vec<u8>>,
        failed: bool,
    }

    impl Read for UnreadableChunk {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let position = usize::try_from(self.inner.position()).unwrap();
            if !self.failed && (CHUNK_BYTES..CHUNK_BYTES * 2).contains(&position) {
                self.failed = true;
                return Err(io::Error::other("injected read failure"));
            }
            self.inner.read(buffer)
        }
    }

    impl Seek for UnreadableChunk {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn continues_after_an_unreadable_chunk() {
        let original = original();
        let sidecar = sidecar(&original);
        let mut reader = UnreadableChunk {
            inner: Cursor::new(original),
            failed: false,
        };
        let report = source(&mut reader, &sidecar).unwrap();

        assert_eq!(report.state, SourceState::Repairable);
        assert_eq!(report.source_digest, SourceDigestState::Unavailable);
        assert_eq!(report.chunks[0].state, ChunkState::Good);
        assert_eq!(
            report.chunks[1].state,
            ChunkState::Unreadable(io::ErrorKind::Other)
        );
        assert_eq!(report.chunks[2].state, ChunkState::Good);
    }

    #[test]
    fn locates_reordered_chunks_and_recomputes_same_length_repairability() {
        let original = original();
        let sidecar = sidecar(&original);
        let mut reordered = Vec::new();
        reordered.extend_from_slice(&original[CHUNK_BYTES..CHUNK_BYTES * 2]);
        reordered.extend_from_slice(&original[CHUNK_BYTES * 2..]);
        reordered.extend_from_slice(&original[..CHUNK_BYTES]);
        let mut reader = Cursor::new(reordered);
        let mut report = source(&mut reader, &sidecar).unwrap();
        assert_eq!(report.state, SourceState::Unrepairable);

        let summary =
            locate_displaced(&mut reader, &sidecar, &mut report, LocateOptions::new(3)).unwrap();

        assert_eq!(summary.eligible_chunks, 3);
        assert_eq!(summary.located_chunks, 3);
        assert!(summary.scan.stopped_early);
        assert_eq!(report.state, SourceState::Repairable);
        assert_eq!(report.required_recovery_chunks(), 0);
        assert_eq!(report.unexpectedly_located_data_chunks, 3);
        assert_eq!(
            report.chunks[0].state,
            ChunkState::UnexpectedlyLocated {
                offset: (CHUNK_BYTES * 2) as u64
            }
        );
        assert_eq!(
            report.chunks[1].state,
            ChunkState::UnexpectedlyLocated { offset: 0 }
        );
        assert_eq!(
            report.chunks[2].state,
            ChunkState::UnexpectedlyLocated {
                offset: CHUNK_BYTES as u64
            }
        );
    }

    #[test]
    fn locates_chunks_shifted_by_inserted_bytes() {
        let original = original();
        let sidecar = sidecar(&original);
        let prefix = b"inserted bytes that shift every chunk";
        let mut shifted = prefix.to_vec();
        shifted.extend_from_slice(&original);
        let mut reader = Cursor::new(shifted);
        let mut report = source(&mut reader, &sidecar).unwrap();

        let summary =
            locate_displaced(&mut reader, &sidecar, &mut report, LocateOptions::new(3)).unwrap();

        assert_eq!(summary.located_chunks, 3);
        assert_eq!(report.required_recovery_chunks(), 0);
        for (index, chunk) in report.chunks.iter().enumerate() {
            let expected_offset = prefix.len() as u64 + (index * CHUNK_BYTES) as u64;
            assert_eq!(
                chunk.state,
                ChunkState::UnexpectedlyLocated {
                    offset: expected_offset
                }
            );
        }
    }

    #[test]
    fn one_physical_copy_can_satisfy_duplicate_expected_content() {
        let mut original = vec![0x44; CHUNK_BYTES * 2];
        original.extend(vec![0x99; CHUNK_BYTES]);
        let sidecar = sidecar(&original);
        let mut shortened = original[..CHUNK_BYTES].to_vec();
        shortened.extend_from_slice(&original[CHUNK_BYTES * 2..]);
        let mut reader = Cursor::new(shortened);
        let mut report = source(&mut reader, &sidecar).unwrap();

        let summary =
            locate_displaced(&mut reader, &sidecar, &mut report, LocateOptions::new(2)).unwrap();

        assert_eq!(summary.located_chunks, 2);
        assert_eq!(report.good_data_chunks, 1);
        assert_eq!(report.unexpectedly_located_data_chunks, 2);
        assert_eq!(report.required_recovery_chunks(), 0);
        assert_eq!(
            report.chunks[1].state,
            ChunkState::UnexpectedlyLocated { offset: 0 }
        );
    }

    #[test]
    fn leaves_the_short_final_chunk_ineligible() {
        let mut original = vec![0x31; CHUNK_BYTES];
        original.extend(vec![0x62; CHUNK_BYTES]);
        original.extend_from_slice(b"short final chunk");
        let sidecar = sidecar(&original);
        let prefix = b"shift";
        let mut shifted = prefix.to_vec();
        shifted.extend_from_slice(&original);
        let mut reader = Cursor::new(shifted);
        let mut report = source(&mut reader, &sidecar).unwrap();

        let summary =
            locate_displaced(&mut reader, &sidecar, &mut report, LocateOptions::new(3)).unwrap();

        assert_eq!(summary.eligible_chunks, 2);
        assert_eq!(summary.located_chunks, 2);
        assert_eq!(report.unexpectedly_located_data_chunks, 2);
        assert_eq!(report.required_recovery_chunks(), 1);
        assert_eq!(report.chunks[2].state, ChunkState::Corrupt);
    }

    #[test]
    fn target_limit_failure_does_not_mutate_the_report() {
        let original = original();
        let sidecar = sidecar(&original);
        let mut reordered = original[CHUNK_BYTES..].to_vec();
        reordered.extend_from_slice(&original[..CHUNK_BYTES]);
        let mut reader = Cursor::new(reordered);
        let mut report = source(&mut reader, &sidecar).unwrap();
        let expected = report.clone();

        assert!(matches!(
            locate_displaced(&mut reader, &sidecar, &mut report, LocateOptions::new(2)),
            Err(Error::Rolling(rolling::Error::TargetLimitExceeded { .. }))
        ));
        assert_eq!(report, expected);
    }

    struct FailingScan {
        inner: Cursor<Vec<u8>>,
        fail_at: u64,
        failed: bool,
    }

    impl Read for FailingScan {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.failed && self.inner.position() >= self.fail_at {
                self.failed = true;
                return Err(io::Error::other("injected rolling scan failure"));
            }
            self.inner.read(buffer)
        }
    }

    impl Seek for FailingScan {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn scan_failure_does_not_apply_partial_locations() {
        let original = original();
        let sidecar = sidecar(&original);
        let mut reordered = original[CHUNK_BYTES..].to_vec();
        reordered.extend_from_slice(&original[..CHUNK_BYTES]);
        let mut report = source(&mut Cursor::new(reordered.clone()), &sidecar).unwrap();
        let expected = report.clone();
        let mut reader = FailingScan {
            inner: Cursor::new(reordered),
            fail_at: CHUNK_BYTES as u64,
            failed: false,
        };

        assert!(matches!(
            locate_displaced(&mut reader, &sidecar, &mut report, LocateOptions::new(3)),
            Err(Error::Rolling(rolling::Error::Io(_)))
        ));
        assert_eq!(report, expected);
    }

    #[test]
    fn does_not_target_unreadable_or_already_good_chunks() {
        let original = original();
        let sidecar = sidecar(&original);
        let mut faulty = UnreadableChunk {
            inner: Cursor::new(original.clone()),
            failed: false,
        };
        let mut report = source(&mut faulty, &sidecar).unwrap();
        let mut readable = Cursor::new(original);

        let summary =
            locate_displaced(&mut readable, &sidecar, &mut report, LocateOptions::new(3)).unwrap();

        assert_eq!(summary.eligible_chunks, 0);
        assert_eq!(summary.located_chunks, 0);
        assert_eq!(summary.scan.windows_scanned, 0);
        assert!(matches!(report.chunks[1].state, ChunkState::Unreadable(_)));
        assert_eq!(report.required_recovery_chunks(), 1);
    }
}
