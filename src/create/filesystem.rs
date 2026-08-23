//! Crash-safe publication of newly created sidecars.

use super::spool::RecoverySpool;
use super::{Error as BuildError, Options, analyze, build_metadata, encode_and_confirm};
use crate::creator::{self, Creator};
use crate::digest_page;
use crate::manifest::{self, Manifest};
use crate::metadata;
use crate::metadata::Metadata as ProtectionMetadata;
use crate::record::{self, DecodeLimits, Record};
use crate::recovery_chunk::{self, RecoveryChunk};
use crate::recovery_set;
use crate::rolling_page;
use crate::sidecar::{AssemblyLimits, ReadLimits, Sidecar, WriteSummary};
use crate::superblock::{self, Superblock};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Policy for a conflicting object already at the requested sidecar path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExistingSidecar {
    /// Keep every nonmatching existing object and report a conflict.
    #[default]
    Preserve,
    /// Atomically replace a nonmatching existing object after verification.
    Replace,
}

/// Successful result of publishing a protection set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishOutcome {
    /// A newly verified sidecar was atomically installed.
    Published(WriteSummary),
    /// A valid sidecar for the same protection set was already installed.
    AlreadyCurrent,
}

/// Creates, verifies, and atomically publishes a sidecar beside its destination.
///
/// The source must be a regular file and must not be a symbolic link. The new
/// sidecar is written to a uniquely named file in the destination directory,
/// flushed to stable storage, parsed back with format-derived resource limits,
/// and compared with the generated protection set before publication. The
/// containing directory is synchronized after publication on Unix.
///
/// An existing valid sidecar for the same protection set is a successful no-op.
/// Other existing objects are preserved unless `existing` is
/// [`ExistingSidecar::Replace`].
///
/// # Errors
///
/// Returns an error for unsafe or changing source paths, creation or format
/// failures, an existing conflict, temporary-file I/O, failed verification, or
/// publication and durability failures.
pub fn publish(
    source_path: impl AsRef<Path>,
    sidecar_path: impl AsRef<Path>,
    options: &Options,
    existing: ExistingSidecar,
) -> Result<PublishOutcome, PublishError> {
    let source_path = source_path.as_ref();
    let sidecar_path = sidecar_path.as_ref();
    if source_path == sidecar_path {
        return Err(PublishError::OverlappingPaths);
    }

    let parent = destination_parent(sidecar_path);
    let (mut source, snapshot) = open_source(source_path)?;
    let (fingerprint, geometry) = analyze(&mut source, options).map_err(PublishError::Build)?;
    let (spool_path, spool_file) =
        create_temporary(parent, sidecar_path, TemporaryKind::RecoverySpool)?;
    let _spool_guard = TemporaryGuard::new(spool_path);
    let mut spool = RecoverySpool::new(spool_file, geometry).map_err(PublishError::Spool)?;
    encode_and_confirm(
        &mut source,
        options,
        &fingerprint,
        geometry,
        |offset, index, bytes| spool.write_window(offset, index, bytes),
    )
    .map_err(PublishError::Build)?;
    snapshot.recheck(&source, source_path)?;
    if destination_is_source(sidecar_path, &snapshot)? {
        return Err(PublishError::OverlappingPaths);
    }
    let recovery_digests = spool.digests().map_err(PublishError::Spool)?;
    let generated =
        build_metadata(fingerprint, geometry, recovery_digests).map_err(PublishError::Build)?;
    let plan = CanonicalPlan::new(&generated, &options.creator)?;

    if let Some(matches) = inspect_existing(sidecar_path, &generated)? {
        if matches {
            return Ok(PublishOutcome::AlreadyCurrent);
        }
        if existing == ExistingSidecar::Preserve {
            return Err(PublishError::ExistingConflict);
        }
    }

    let (temporary_path, mut temporary) =
        create_temporary(parent, sidecar_path, TemporaryKind::Sidecar)?;
    let mut temporary_guard = TemporaryGuard::new(temporary_path);
    let summary = plan.write(&mut temporary, &mut spool)?;
    temporary.flush().map_err(PublishError::Flush)?;
    temporary.sync_all().map_err(PublishError::SyncTemporary)?;
    drop(temporary);

    verify_temporary(temporary_guard.path(), &plan, summary)?;
    let published = publish_temporary(
        &mut temporary_guard,
        sidecar_path,
        parent,
        &generated,
        existing,
    )?;
    if published {
        Ok(PublishOutcome::Published(summary))
    } else {
        Ok(PublishOutcome::AlreadyCurrent)
    }
}

#[derive(Clone, Debug)]
struct SourceSnapshot {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl SourceSnapshot {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }
    }

    fn same_file(&self, metadata: &Metadata) -> bool {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        self.len == metadata.len() && self.modified == metadata.modified().ok() && {
            #[cfg(unix)]
            {
                self.device == metadata.dev() && self.inode == metadata.ino()
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
    }

    #[cfg(unix)]
    fn same_identity(&self, metadata: &Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;

        self.device == metadata.dev() && self.inode == metadata.ino()
    }

    fn recheck(&self, source: &File, path: &Path) -> Result<(), PublishError> {
        let open_metadata = source.metadata().map_err(PublishError::SourceMetadata)?;
        let path_metadata = fs::symlink_metadata(path).map_err(PublishError::SourceMetadata)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || !self.same_file(&open_metadata)
            || !self.same_file(&path_metadata)
        {
            return Err(PublishError::SourceIdentityChanged);
        }
        Ok(())
    }
}

fn destination_is_source(
    destination: &Path,
    snapshot: &SourceSnapshot,
) -> Result<bool, PublishError> {
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(PublishError::InspectExisting(error)),
    };
    #[cfg(unix)]
    {
        Ok(snapshot.same_identity(&metadata))
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, snapshot);
        Ok(false)
    }
}

fn open_source(path: &Path) -> Result<(File, SourceSnapshot), PublishError> {
    let path_metadata = fs::symlink_metadata(path).map_err(PublishError::SourceMetadata)?;
    if path_metadata.file_type().is_symlink() {
        return Err(PublishError::SourceIsSymlink);
    }
    if !path_metadata.is_file() {
        return Err(PublishError::SourceNotRegularFile);
    }
    let source = File::open(path).map_err(PublishError::OpenSource)?;
    let open_metadata = source.metadata().map_err(PublishError::SourceMetadata)?;
    let snapshot = SourceSnapshot::from_metadata(&open_metadata);
    if !snapshot.same_file(&path_metadata) {
        return Err(PublishError::SourceIdentityChanged);
    }
    Ok((source, snapshot))
}

struct CanonicalPlan {
    logical_manifest: Manifest,
    superblock: Record,
    creator: Record,
    manifest: Record,
    pages: Vec<Record>,
    recovery_digests: Vec<crate::fingerprint::Digest>,
    summary: WriteSummary,
}

impl CanonicalPlan {
    fn new(metadata: &ProtectionMetadata, creator: &Creator) -> Result<Self, PublishError> {
        let manifest = metadata.manifest;
        let set_id = manifest.protection_set_id();
        let creator = creator.to_record(set_id).map_err(PublishError::Creator)?;
        let manifest_record = manifest.to_record();
        let pages = page_records(metadata, set_id)?;
        let page_len = records_len(&pages)?;
        let creator_len = record::encoded_len(&creator).map_err(PublishError::RecordWrite)?;
        let recovery_payload_len = (recovery_chunk::PAYLOAD_HEADER_LEN as u64)
            .checked_add(u64::from(manifest.geometry().chunk_size.bytes()))
            .ok_or(PublishError::LimitOverflow)?;
        let recovery_record_len = unextended_record_len(recovery_payload_len)?;
        let recovery_len = recovery_record_len
            .checked_mul(u64::from(manifest.geometry().recovery_chunks))
            .ok_or(PublishError::LimitOverflow)?;
        let superblock_len = unextended_record_len(superblock::PAYLOAD_LEN as u64)?;
        let first_manifest_offset = superblock_len
            .checked_add(creator_len)
            .ok_or(PublishError::LimitOverflow)?;
        let second_manifest_offset = checked_sum(&[
            first_manifest_offset,
            manifest::ENCODED_RECORD_LEN,
            page_len,
            recovery_len,
            page_len,
        ])?;
        let bytes_written = checked_sum(&[
            second_manifest_offset,
            manifest::ENCODED_RECORD_LEN,
            creator_len,
            superblock_len,
        ])?;
        let superblock = Superblock::new(
            manifest,
            first_manifest_offset,
            second_manifest_offset,
            bytes_written,
        )
        .map_err(PublishError::Superblock)?
        .to_record();
        let recovery_digests = metadata.recovery_digests.digests().copied().collect();

        Ok(Self {
            logical_manifest: manifest,
            superblock,
            creator,
            manifest: manifest_record,
            pages,
            recovery_digests,
            summary: WriteSummary {
                first_manifest_offset,
                second_manifest_offset,
                bytes_written,
            },
        })
    }

    fn write(
        &self,
        writer: &mut File,
        spool: &mut RecoverySpool,
    ) -> Result<WriteSummary, PublishError> {
        let mut written = 0_u64;
        write_record(writer, &self.superblock, &mut written)?;
        write_record(writer, &self.creator, &mut written)?;
        write_record(writer, &self.manifest, &mut written)?;
        write_records(writer, &self.pages, &mut written)?;
        let manifest = self.logical_manifest;
        for (index, expected_digest) in self.recovery_digests.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| PublishError::LimitOverflow)?;
            let bytes = spool.read_chunk(index).map_err(PublishError::Spool)?;
            let chunk =
                RecoveryChunk::new(manifest, index, bytes).map_err(PublishError::RecoveryChunk)?;
            if chunk.digest() != *expected_digest {
                return Err(PublishError::RecoveryDigestMismatch(index));
            }
            let record = chunk
                .to_record(manifest)
                .map_err(PublishError::RecoveryChunk)?;
            write_record(writer, &record, &mut written)?;
        }
        write_records(writer, &self.pages, &mut written)?;
        write_record(writer, &self.manifest, &mut written)?;
        write_record(writer, &self.creator, &mut written)?;
        write_record(writer, &self.superblock, &mut written)?;
        if written != self.summary.bytes_written {
            return Err(PublishError::WrittenLengthMismatch {
                actual: written,
                expected: self.summary.bytes_written,
            });
        }
        Ok(self.summary)
    }

    fn verify(&self, reader: &mut File) -> Result<(), PublishError> {
        let limits = DecodeLimits::new(record::BASE_HEADER_LEN, self.max_payload_len()?);
        expect_record(reader, limits, &self.superblock)?;
        expect_record(reader, limits, &self.creator)?;
        expect_record(reader, limits, &self.manifest)?;
        expect_records(reader, limits, &self.pages)?;
        let manifest = self.logical_manifest;
        for (index, expected_digest) in self.recovery_digests.iter().enumerate() {
            let record = read_required_record(reader, limits)?;
            let index = u32::try_from(index).map_err(|_| PublishError::LimitOverflow)?;
            let chunk = RecoveryChunk::from_record(&record, manifest, *expected_digest)
                .map_err(PublishError::VerifyRecovery)?;
            if chunk.recovery_index() != index {
                return Err(PublishError::VerificationMismatch);
            }
        }
        expect_records(reader, limits, &self.pages)?;
        expect_record(reader, limits, &self.manifest)?;
        expect_record(reader, limits, &self.creator)?;
        expect_record(reader, limits, &self.superblock)?;
        if record::read(reader, limits)
            .map_err(PublishError::VerifyRecord)?
            .is_some()
        {
            return Err(PublishError::VerificationMismatch);
        }
        Ok(())
    }

    fn max_payload_len(&self) -> Result<u64, PublishError> {
        let manifest = self.logical_manifest;
        let recovery = u64::from(manifest.geometry().chunk_size.bytes())
            .checked_add(recovery_chunk::PAYLOAD_HEADER_LEN as u64)
            .ok_or(PublishError::LimitOverflow)?;
        let metadata = self
            .pages
            .iter()
            .map(|record| record.payload.len())
            .max()
            .unwrap_or(0);
        Ok(recovery.max(u64::try_from(metadata).map_err(|_| PublishError::LimitOverflow)?))
    }
}

fn page_records(
    metadata: &ProtectionMetadata,
    set_id: [u8; 32],
) -> Result<Vec<Record>, PublishError> {
    let page_count = metadata
        .data_digests
        .pages
        .len()
        .checked_add(metadata.recovery_digests.pages.len())
        .and_then(|count| count.checked_add(metadata.rolling_fingerprints.pages.len()))
        .ok_or(PublishError::LimitOverflow)?;
    let mut records = Vec::with_capacity(page_count);
    for page in &metadata.data_digests.pages {
        records.push(page.to_record(set_id).map_err(PublishError::DigestPage)?);
    }
    for page in &metadata.recovery_digests.pages {
        records.push(page.to_record(set_id).map_err(PublishError::DigestPage)?);
    }
    for page in &metadata.rolling_fingerprints.pages {
        records.push(page.to_record(set_id).map_err(PublishError::RollingPage)?);
    }
    Ok(records)
}

fn unextended_record_len(payload_len: u64) -> Result<u64, PublishError> {
    u64::from(record::BASE_HEADER_LEN)
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(record::DIGEST_LEN as u64))
        .ok_or(PublishError::LimitOverflow)
}

fn records_len(records: &[Record]) -> Result<u64, PublishError> {
    records.iter().try_fold(0_u64, |total, record| {
        let length = record::encoded_len(record).map_err(PublishError::RecordWrite)?;
        total.checked_add(length).ok_or(PublishError::LimitOverflow)
    })
}

fn checked_sum(parts: &[u64]) -> Result<u64, PublishError> {
    parts.iter().try_fold(0_u64, |total, part| {
        total.checked_add(*part).ok_or(PublishError::LimitOverflow)
    })
}

fn write_records(
    writer: &mut File,
    records: &[Record],
    written: &mut u64,
) -> Result<(), PublishError> {
    for record in records {
        write_record(writer, record, written)?;
    }
    Ok(())
}

fn write_record(writer: &mut File, record: &Record, written: &mut u64) -> Result<(), PublishError> {
    let length = record::write(writer, record).map_err(PublishError::RecordWrite)?;
    *written = written
        .checked_add(length)
        .ok_or(PublishError::LimitOverflow)?;
    Ok(())
}

fn expect_records(
    reader: &mut File,
    limits: DecodeLimits,
    expected: &[Record],
) -> Result<(), PublishError> {
    for record in expected {
        expect_record(reader, limits, record)?;
    }
    Ok(())
}

fn expect_record(
    reader: &mut File,
    limits: DecodeLimits,
    expected: &Record,
) -> Result<(), PublishError> {
    if read_required_record(reader, limits)? != *expected {
        return Err(PublishError::VerificationMismatch);
    }
    Ok(())
}

fn read_required_record(reader: &mut File, limits: DecodeLimits) -> Result<Record, PublishError> {
    record::read(reader, limits)
        .map_err(PublishError::VerifyRecord)?
        .ok_or(PublishError::VerificationMismatch)
}

fn inspect_existing(
    path: &Path,
    expected: &ProtectionMetadata,
) -> Result<Option<bool>, PublishError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(PublishError::InspectExisting(error)),
    };
    let Ok(read) = Sidecar::read(file, verification_limits(expected)?) else {
        return Ok(Some(false));
    };
    Ok(Some(
        read.damage.is_empty()
            && read.sidecar.metadata.manifest.protection_set_id()
                == expected.manifest.protection_set_id(),
    ))
}

fn destination_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[derive(Clone, Copy)]
enum TemporaryKind {
    RecoverySpool,
    Sidecar,
}

impl TemporaryKind {
    const fn name(self) -> &'static str {
        match self {
            Self::RecoverySpool => "recovery",
            Self::Sidecar => "sidecar",
        }
    }
}

fn create_temporary(
    parent: &Path,
    destination: &Path,
    kind: TemporaryKind,
) -> Result<(PathBuf, File), PublishError> {
    let file_name = destination
        .file_name()
        .ok_or(PublishError::DestinationHasNoFileName)?;
    for nonce in 0_u32..128 {
        let mut temporary_name = OsString::from(file_name);
        temporary_name.push(format!(
            ".tmp-{}-{}-{nonce}",
            std::process::id(),
            kind.name()
        ));
        let path = parent.join(temporary_name);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(PublishError::CreateTemporary(error)),
        }
    }
    Err(PublishError::TemporaryNameExhausted)
}

fn verify_temporary(
    path: &Path,
    plan: &CanonicalPlan,
    summary: WriteSummary,
) -> Result<(), PublishError> {
    let mut file = File::open(path).map_err(PublishError::ReopenTemporary)?;
    let metadata = file.metadata().map_err(PublishError::TemporaryMetadata)?;
    if metadata.len() != summary.bytes_written {
        return Err(PublishError::VerificationMismatch);
    }
    plan.verify(&mut file)
}

fn verification_limits(metadata: &ProtectionMetadata) -> Result<ReadLimits, PublishError> {
    let geometry = metadata.manifest.geometry();
    let data_pages = u32::try_from(metadata.data_digests.pages.len())
        .map_err(|_| PublishError::LimitOverflow)?;
    let recovery_pages = u32::try_from(metadata.recovery_digests.pages.len())
        .map_err(|_| PublishError::LimitOverflow)?;
    let rolling_pages = u32::try_from(metadata.rolling_fingerprints.pages.len())
        .map_err(|_| PublishError::LimitOverflow)?;
    let page_records = u64::from(data_pages)
        .checked_add(u64::from(recovery_pages))
        .and_then(|count| count.checked_add(u64::from(rolling_pages)))
        .ok_or(PublishError::LimitOverflow)?;
    let metadata_records = page_records
        .checked_mul(2)
        .and_then(|count| count.checked_add(2))
        .ok_or(PublishError::LimitOverflow)?;
    let max_records = metadata_records
        .checked_add(u64::from(geometry.recovery_chunks))
        .and_then(|count| count.checked_add(4))
        .ok_or(PublishError::LimitOverflow)?;
    let max_digest_pages = data_pages
        .max(recovery_pages)
        .checked_mul(2)
        .ok_or(PublishError::LimitOverflow)?;
    let max_rolling_pages = rolling_pages
        .checked_mul(2)
        .ok_or(PublishError::LimitOverflow)?;
    let digest_payload = digest_page::PAYLOAD_HEADER_LEN
        .checked_add(
            digest_page::MAX_DIGESTS_PER_PAGE
                .checked_mul(record::DIGEST_LEN)
                .ok_or(PublishError::LimitOverflow)?,
        )
        .ok_or(PublishError::LimitOverflow)?;
    let recovery_payload = u64::from(geometry.chunk_size.bytes())
        .checked_add(recovery_chunk::PAYLOAD_HEADER_LEN as u64)
        .ok_or(PublishError::LimitOverflow)?;
    let max_payload_len = recovery_payload
        .max(u64::try_from(digest_payload).map_err(|_| PublishError::LimitOverflow)?);

    Ok(ReadLimits {
        record: DecodeLimits::new(record::BASE_HEADER_LEN, max_payload_len),
        assembly: AssemblyLimits {
            max_records,
            max_unknown_optional_records: 0,
            max_superblock_copies: 2,
            max_creator_copies: 2,
            metadata: metadata::AssemblyLimits::new(
                metadata_records,
                digest_page::AssemblyLimits::new(
                    u64::from(geometry.data_chunks.max(geometry.recovery_chunks)),
                    max_digest_pages,
                ),
                rolling_page::AssemblyLimits::new(geometry.full_data_chunks(), max_rolling_pages),
            ),
            recovery: recovery_set::AssemblyLimits::new(
                u64::from(geometry.recovery_chunks),
                geometry.recovery_chunks,
            ),
        },
        max_damage_events: 0,
        max_unrecognized_bytes: 0,
    })
}

fn publish_temporary(
    temporary: &mut TemporaryGuard,
    destination: &Path,
    parent: &Path,
    expected: &ProtectionMetadata,
    existing: ExistingSidecar,
) -> Result<bool, PublishError> {
    match existing {
        ExistingSidecar::Preserve => match fs::hard_link(temporary.path(), destination) {
            Ok(()) => temporary
                .remove()
                .map_err(PublishError::PublishedButCleanupFailed)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if inspect_existing(destination, expected)? == Some(true) {
                    return Ok(false);
                }
                return Err(PublishError::ExistingConflict);
            }
            Err(error) => return Err(PublishError::Publish(error)),
        },
        ExistingSidecar::Replace => {
            fs::rename(temporary.path(), destination).map_err(PublishError::Publish)?;
            temporary.disarm();
        }
    }
    sync_directory(parent).map_err(PublishError::SyncDirectory)?;
    Ok(true)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

struct TemporaryGuard {
    path: PathBuf,
    armed: bool,
}

impl TemporaryGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn remove(&mut self) -> io::Result<()> {
        fs::remove_file(&self.path)?;
        self.armed = false;
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug)]
pub enum PublishError {
    OverlappingPaths,
    SourceIsSymlink,
    SourceNotRegularFile,
    SourceIdentityChanged,
    DestinationHasNoFileName,
    TemporaryNameExhausted,
    ExistingConflict,
    LimitOverflow,
    VerificationMismatch,
    RecoveryDigestMismatch(u32),
    WrittenLengthMismatch { actual: u64, expected: u64 },
    OpenSource(io::Error),
    SourceMetadata(io::Error),
    Build(BuildError),
    Spool(io::Error),
    InspectExisting(io::Error),
    CreateTemporary(io::Error),
    Creator(creator::Error),
    DigestPage(digest_page::Error),
    RollingPage(rolling_page::Error),
    RecoveryChunk(recovery_chunk::Error),
    Superblock(superblock::Error),
    RecordWrite(record::Error),
    Flush(io::Error),
    SyncTemporary(io::Error),
    ReopenTemporary(io::Error),
    TemporaryMetadata(io::Error),
    VerifyRecord(record::Error),
    VerifyRecovery(recovery_chunk::Error),
    Publish(io::Error),
    PublishedButCleanupFailed(io::Error),
    SyncDirectory(io::Error),
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverlappingPaths => formatter.write_str("source and sidecar paths overlap"),
            Self::SourceIsSymlink => formatter.write_str("source path is a symbolic link"),
            Self::SourceNotRegularFile => formatter.write_str("source is not a regular file"),
            Self::SourceIdentityChanged => {
                formatter.write_str("source path identity or metadata changed during creation")
            }
            Self::DestinationHasNoFileName => {
                formatter.write_str("sidecar destination has no file name")
            }
            Self::TemporaryNameExhausted => {
                formatter.write_str("cannot allocate a unique temporary sidecar name")
            }
            Self::ExistingConflict => {
                formatter.write_str("a nonmatching object already exists at the sidecar path")
            }
            Self::LimitOverflow => formatter.write_str("verification limits overflow"),
            Self::VerificationMismatch => {
                formatter.write_str("temporary sidecar does not match generated data")
            }
            Self::RecoveryDigestMismatch(index) => {
                write!(
                    formatter,
                    "recovery chunk {index} changed in scratch storage"
                )
            }
            Self::WrittenLengthMismatch { actual, expected } => write!(
                formatter,
                "temporary writer produced {actual} bytes instead of planned length {expected}"
            ),
            Self::OpenSource(error) => write!(formatter, "cannot open source: {error}"),
            Self::SourceMetadata(error) => write!(formatter, "cannot inspect source: {error}"),
            Self::Build(error) => write!(formatter, "cannot build sidecar: {error}"),
            Self::Spool(error) => write!(formatter, "recovery spool failed: {error}"),
            Self::InspectExisting(error) => {
                write!(formatter, "cannot inspect existing sidecar: {error}")
            }
            Self::CreateTemporary(error) => {
                write!(formatter, "cannot create temporary sidecar: {error}")
            }
            Self::Creator(error) => write!(formatter, "creator encoding failed: {error}"),
            Self::DigestPage(error) => write!(formatter, "digest-page encoding failed: {error}"),
            Self::RollingPage(error) => {
                write!(formatter, "rolling-page encoding failed: {error}")
            }
            Self::RecoveryChunk(error) => {
                write!(formatter, "recovery-chunk encoding failed: {error}")
            }
            Self::Superblock(error) => write!(formatter, "superblock creation failed: {error}"),
            Self::RecordWrite(error) => write!(formatter, "record writing failed: {error}"),
            Self::Flush(error) => write!(formatter, "cannot flush temporary sidecar: {error}"),
            Self::SyncTemporary(error) => {
                write!(formatter, "cannot synchronize temporary sidecar: {error}")
            }
            Self::ReopenTemporary(error) => {
                write!(formatter, "cannot reopen temporary sidecar: {error}")
            }
            Self::TemporaryMetadata(error) => {
                write!(formatter, "cannot inspect temporary sidecar: {error}")
            }
            Self::VerifyRecord(error) => write!(formatter, "temporary record is invalid: {error}"),
            Self::VerifyRecovery(error) => {
                write!(formatter, "temporary recovery record is invalid: {error}")
            }
            Self::Publish(error) => write!(formatter, "cannot publish sidecar: {error}"),
            Self::PublishedButCleanupFailed(error) => write!(
                formatter,
                "sidecar was published but its temporary link could not be removed: {error}"
            ),
            Self::SyncDirectory(error) => {
                write!(
                    formatter,
                    "cannot synchronize destination directory: {error}"
                )
            }
        }
    }
}

impl std::error::Error for PublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenSource(error)
            | Self::SourceMetadata(error)
            | Self::Spool(error)
            | Self::InspectExisting(error)
            | Self::CreateTemporary(error)
            | Self::Flush(error)
            | Self::SyncTemporary(error)
            | Self::ReopenTemporary(error)
            | Self::TemporaryMetadata(error)
            | Self::Publish(error)
            | Self::PublishedButCleanupFailed(error)
            | Self::SyncDirectory(error) => Some(error),
            Self::Build(error) => Some(error),
            Self::Creator(error) => Some(error),
            Self::DigestPage(error) => Some(error),
            Self::RollingPage(error) => Some(error),
            Self::RecoveryChunk(error) | Self::VerifyRecovery(error) => Some(error),
            Self::Superblock(error) => Some(error),
            Self::RecordWrite(error) | Self::VerifyRecord(error) => Some(error),
            Self::OverlappingPaths
            | Self::SourceIsSymlink
            | Self::SourceNotRegularFile
            | Self::SourceIdentityChanged
            | Self::DestinationHasNoFileName
            | Self::TemporaryNameExhausted
            | Self::ExistingConflict
            | Self::LimitOverflow
            | Self::VerificationMismatch
            | Self::RecoveryDigestMismatch(_)
            | Self::WrittenLengthMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creator::Creator;
    use crate::geometry::{ChunkSize, MIN_CHUNK_SIZE, Redundancy};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bitrot-publish-test-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn options() -> Options {
        Options::new(
            ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap(),
            Redundancy::new(1, 2).unwrap(),
            1_024,
            Creator::new("bitrot-test", env!("CARGO_PKG_VERSION")).unwrap(),
        )
    }

    fn source_bytes() -> Vec<u8> {
        (0..usize::try_from(MIN_CHUNK_SIZE).unwrap() + 173)
            .map(|index| index.wrapping_mul(37).to_le_bytes()[0])
            .collect()
    }

    #[test]
    fn publishes_verified_sidecar_and_treats_matching_set_as_no_op() {
        let directory = TestDirectory::new();
        let source = directory.join("movie.bin");
        let destination = directory.join("movie.bin.bitrot");
        fs::write(&source, source_bytes()).unwrap();

        let first = publish(&source, &destination, &options(), ExistingSidecar::Preserve).unwrap();
        let PublishOutcome::Published(summary) = first else {
            panic!("first publication unexpectedly found a matching sidecar");
        };
        assert_eq!(
            fs::metadata(&destination).unwrap().len(),
            summary.bytes_written
        );

        let second = publish(&source, &destination, &options(), ExistingSidecar::Preserve).unwrap();
        assert_eq!(second, PublishOutcome::AlreadyCurrent);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[test]
    fn spooled_publication_matches_the_in_memory_canonical_writer() {
        let directory = TestDirectory::new();
        let source = directory.join("source.bin");
        let destination = directory.join("source.bin.bitrot");
        let bytes = source_bytes();
        fs::write(&source, &bytes).unwrap();

        let expected_sidecar = super::super::build(&mut Cursor::new(bytes), &options()).unwrap();
        let mut expected = Vec::new();
        expected_sidecar.write_canonical(&mut expected).unwrap();

        publish(&source, &destination, &options(), ExistingSidecar::Preserve).unwrap();
        assert_eq!(fs::read(destination).unwrap(), expected);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[test]
    fn removes_recovery_scratch_when_coding_fails() {
        let directory = TestDirectory::new();
        let source = directory.join("source.bin");
        let destination = directory.join("source.bin.bitrot");
        fs::write(&source, source_bytes()).unwrap();
        let mut invalid = options();
        invalid.coding_window_bytes = 3;

        assert!(matches!(
            publish(&source, &destination, &invalid, ExistingSidecar::Preserve),
            Err(PublishError::Build(BuildError::Coding(_)))
        ));
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
        assert!(!destination.exists());
    }

    #[test]
    fn preserves_conflict_by_default_and_replaces_it_explicitly() {
        let directory = TestDirectory::new();
        let source = directory.join("source.bin");
        let destination = directory.join("source.bin.bitrot");
        fs::write(&source, source_bytes()).unwrap();
        fs::write(&destination, b"existing evidence").unwrap();

        assert!(matches!(
            publish(&source, &destination, &options(), ExistingSidecar::Preserve),
            Err(PublishError::ExistingConflict)
        ));
        assert_eq!(fs::read(&destination).unwrap(), b"existing evidence");

        assert!(matches!(
            publish(&source, &destination, &options(), ExistingSidecar::Replace).unwrap(),
            PublishOutcome::Published(_)
        ));
        assert_ne!(fs::read(&destination).unwrap(), b"existing evidence");
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_replace_a_hard_link_to_the_source() {
        let directory = TestDirectory::new();
        let source = directory.join("source.bin");
        let destination = directory.join("source-alias.bitrot");
        let bytes = source_bytes();
        fs::write(&source, &bytes).unwrap();
        fs::hard_link(&source, &destination).unwrap();

        assert!(matches!(
            publish(&source, &destination, &options(), ExistingSidecar::Replace),
            Err(PublishError::OverlappingPaths)
        ));
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert_eq!(fs::read(&destination).unwrap(), bytes);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_sources() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let real_source = directory.join("real.bin");
        let source_link = directory.join("source.bin");
        let destination = directory.join("source.bin.bitrot");
        fs::write(&real_source, source_bytes()).unwrap();
        symlink(&real_source, &source_link).unwrap();

        assert!(matches!(
            publish(
                &source_link,
                &destination,
                &options(),
                ExistingSidecar::Preserve
            ),
            Err(PublishError::SourceIsSymlink)
        ));
        assert!(!destination.exists());
    }
}
