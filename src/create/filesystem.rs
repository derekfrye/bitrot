//! Crash-safe publication of newly created sidecars.

use super::spool::RecoverySpool;
use super::{Error as BuildError, Options, analyze, build_metadata, encode_and_confirm};
use crate::creator::Creator;
#[cfg(any(windows, test))]
use crate::filesystem::same_windows_file_id;
use crate::filesystem::{
    CreateTemporaryError, Directory as DestinationDirectory, FinishError, TemporaryFile,
    TemporaryKind, cleanup_stale_temporaries as cleanup_stale, destination_parent,
    finish_publication as finish_filesystem_publication, remove_file_if_same,
};
use crate::metadata::Metadata as ProtectionMetadata;
use crate::record::{self, DecodeLimits, Record};
use crate::recovery_chunk::{self, RecoveryChunk};
use crate::sidecar::{CanonicalLayout, ReadLimits, Sidecar, WriteSummary};
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::SystemTime;

/// Policy for a conflicting object already at the requested sidecar path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExistingSidecar {
    /// Keep every nonmatching existing object and report a conflict.
    #[default]
    Preserve,
    /// Atomically replace a nonmatching existing object after verification.
    ///
    /// Concurrent replacing publishers use last-writer-wins semantics.
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
    let directory = DestinationDirectory::open(parent).map_err(PublishError::OpenDirectory)?;
    let destination_name = sidecar_path
        .file_name()
        .ok_or(PublishError::DestinationHasNoFileName)?;
    let (mut source, snapshot) = open_source(source_path)?;
    let (fingerprint, geometry) = analyze(&mut source, options).map_err(PublishError::Build)?;
    cleanup_stale_temporaries(&directory, destination_name)?;
    let spool_temporary = create_temporary(&directory, destination_name, TemporaryKind::Recovery)?;
    let mut spool = RecoverySpool::new(
        spool_temporary
            .file
            .try_clone()
            .map_err(PublishError::Spool)?,
        geometry,
    )
    .map_err(PublishError::Spool)?;
    encode_and_confirm(
        &mut source,
        options,
        &fingerprint,
        geometry,
        |offset, index, bytes| spool.write_window(offset, index, bytes),
    )
    .map_err(PublishError::Build)?;
    snapshot.recheck(&source, source_path)?;
    if destination_is_source(&directory, destination_name, &snapshot)? {
        return Err(PublishError::OverlappingPaths);
    }
    let recovery_digests = spool.digests().map_err(PublishError::Spool)?;
    let generated =
        build_metadata(fingerprint, geometry, recovery_digests).map_err(PublishError::Build)?;
    let plan = CanonicalPlan::new(&generated, &options.creator)?;

    if let Some(matches) = inspect_existing(&directory, destination_name, &generated)? {
        if matches {
            return Ok(PublishOutcome::AlreadyCurrent);
        }
        if existing == ExistingSidecar::Preserve {
            return Err(PublishError::ExistingConflict);
        }
    }

    let mut temporary = create_temporary(&directory, destination_name, TemporaryKind::Sidecar)?;
    let summary = plan.write(&mut temporary.file, &mut spool)?;
    temporary.file.flush().map_err(PublishError::Flush)?;
    temporary
        .file
        .sync_all()
        .map_err(PublishError::SyncTemporary)?;
    verify_temporary(&mut temporary.file, &plan, summary)?;
    verify_temporary_path(&temporary)?;
    let published = publish_temporary(
        &mut temporary,
        &directory,
        destination_name,
        &generated,
        &plan,
        summary,
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
    #[cfg(windows)]
    volume_serial_number: Option<u32>,
    #[cfg(windows)]
    file_index: Option<u64>,
}

impl SourceSnapshot {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        #[cfg(windows)]
        use std::os::windows::fs::MetadataExt as _;

        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(windows)]
            volume_serial_number: metadata.volume_serial_number(),
            #[cfg(windows)]
            file_index: metadata.file_index(),
        }
    }

    fn same_file(&self, metadata: &Metadata) -> bool {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        #[cfg(windows)]
        use std::os::windows::fs::MetadataExt as _;

        self.len == metadata.len() && self.modified == metadata.modified().ok() && {
            #[cfg(unix)]
            {
                self.device == metadata.dev() && self.inode == metadata.ino()
            }
            #[cfg(windows)]
            {
                same_windows_file_id(
                    self.volume_serial_number,
                    self.file_index,
                    metadata.volume_serial_number(),
                    metadata.file_index(),
                )
            }
            #[cfg(not(any(unix, windows)))]
            {
                true
            }
        }
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
    directory: &DestinationDirectory,
    destination: &std::ffi::OsStr,
    snapshot: &SourceSnapshot,
) -> Result<bool, PublishError> {
    let metadata = match directory.symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(PublishError::InspectExisting(error)),
    };
    #[cfg(unix)]
    {
        Ok((snapshot.device, snapshot.inode) == metadata.unix_identity())
    }
    #[cfg(windows)]
    {
        let (volume_serial_number, file_index) = metadata.windows_identity();
        Ok(same_windows_file_id(
            snapshot.volume_serial_number,
            snapshot.file_index,
            volume_serial_number,
            file_index,
        ))
    }
    #[cfg(not(any(unix, windows)))]
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
    let source = open_read_no_follow(path).map_err(PublishError::OpenSource)?;
    let open_metadata = source.metadata().map_err(PublishError::SourceMetadata)?;
    let snapshot = SourceSnapshot::from_metadata(&open_metadata);
    if !snapshot.same_file(&path_metadata) {
        return Err(PublishError::SourceIdentityChanged);
    }
    Ok((source, snapshot))
}

fn open_read_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

struct CanonicalPlan {
    layout: CanonicalLayout<'static>,
    recovery_digests: Vec<crate::fingerprint::Digest>,
    record_limits: DecodeLimits,
}

impl CanonicalPlan {
    fn new(metadata: &ProtectionMetadata, creator: &Creator) -> Result<Self, PublishError> {
        let layout =
            CanonicalLayout::new(metadata, creator, &[]).map_err(PublishError::CanonicalLayout)?;
        let record_limits = ReadLimits::for_canonical_metadata(metadata)
            .map_err(PublishError::ReadLimits)?
            .record;
        let recovery_digests = metadata.recovery_digests.digests().copied().collect();

        Ok(Self {
            layout,
            recovery_digests,
            record_limits,
        })
    }

    fn write(
        &self,
        writer: &mut File,
        spool: &mut RecoverySpool,
    ) -> Result<WriteSummary, PublishError> {
        let mut written = 0_u64;
        self.layout
            .write_prefix(writer, &mut written)
            .map_err(PublishError::CanonicalLayout)?;
        let manifest = self.layout.manifest();
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
        self.layout
            .write_suffix(writer, &mut written)
            .map_err(PublishError::CanonicalLayout)?;
        let summary = self.layout.summary();
        if written != summary.bytes_written {
            return Err(PublishError::WrittenLengthMismatch {
                actual: written,
                expected: summary.bytes_written,
            });
        }
        Ok(summary)
    }

    fn verify(&self, reader: &mut File) -> Result<(), PublishError> {
        let limits = self.record_limits;
        expect_record(reader, limits, self.layout.superblock_record())?;
        expect_record(reader, limits, self.layout.creator_record())?;
        expect_record(reader, limits, self.layout.manifest_record())?;
        expect_records(reader, limits, self.layout.page_records())?;
        let manifest = self.layout.manifest();
        for (index, expected_digest) in self.recovery_digests.iter().enumerate() {
            let record = read_required_record(reader, limits)?;
            let index = u32::try_from(index).map_err(|_| PublishError::LimitOverflow)?;
            let chunk = RecoveryChunk::from_record(&record, manifest, *expected_digest)
                .map_err(PublishError::VerifyRecovery)?;
            if chunk.recovery_index() != index {
                return Err(PublishError::VerificationMismatch);
            }
        }
        expect_records(reader, limits, self.layout.page_records())?;
        expect_record(reader, limits, self.layout.manifest_record())?;
        expect_record(reader, limits, self.layout.creator_record())?;
        expect_record(reader, limits, self.layout.superblock_record())?;
        if record::read(reader, limits)
            .map_err(PublishError::VerifyRecord)?
            .is_some()
        {
            return Err(PublishError::VerificationMismatch);
        }
        Ok(())
    }
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
    directory: &DestinationDirectory,
    name: &std::ffi::OsStr,
    expected: &ProtectionMetadata,
) -> Result<Option<bool>, PublishError> {
    let path_metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(PublishError::InspectExisting(error)),
    };
    if path_metadata.is_symlink() || !path_metadata.is_file() {
        return Ok(Some(false));
    }
    let file = match directory.open_read_no_follow(name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(PublishError::InspectExisting(error)),
    };
    let limits = ReadLimits::for_canonical_metadata(expected).map_err(PublishError::ReadLimits)?;
    let Ok(read) = Sidecar::read(file, limits) else {
        return Ok(Some(false));
    };
    Ok(Some(
        read.damage.is_empty()
            && read.sidecar.metadata.manifest.protection_set_id()
                == expected.manifest.protection_set_id(),
    ))
}

fn create_temporary<'directory>(
    directory: &'directory DestinationDirectory,
    destination_name: &std::ffi::OsStr,
    kind: TemporaryKind,
) -> Result<TemporaryFile<'directory>, PublishError> {
    TemporaryFile::create(directory, destination_name, kind).map_err(|error| match error {
        CreateTemporaryError::NameExhausted => PublishError::TemporaryNameExhausted,
        CreateTemporaryError::LockContended => PublishError::TemporaryLockContended,
        CreateTemporaryError::Create(error) => PublishError::CreateTemporary(error),
        CreateTemporaryError::Lock(error) => PublishError::LockTemporary(error),
    })
}

fn cleanup_stale_temporaries(
    directory: &DestinationDirectory,
    destination_name: &std::ffi::OsStr,
) -> Result<(), PublishError> {
    cleanup_stale(
        directory,
        destination_name,
        &[TemporaryKind::Recovery, TemporaryKind::Sidecar],
    )
    .map_err(PublishError::CleanupTemporaries)
}

fn verify_temporary(
    file: &mut File,
    plan: &CanonicalPlan,
    summary: WriteSummary,
) -> Result<(), PublishError> {
    let metadata = file.metadata().map_err(PublishError::TemporaryMetadata)?;
    if metadata.len() != summary.bytes_written {
        return Err(PublishError::VerificationMismatch);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(PublishError::RewindTemporary)?;
    plan.verify(file)
}

fn publish_temporary(
    temporary: &mut TemporaryFile<'_>,
    directory: &DestinationDirectory,
    destination: &std::ffi::OsStr,
    expected: &ProtectionMetadata,
    plan: &CanonicalPlan,
    summary: WriteSummary,
    existing: ExistingSidecar,
) -> Result<bool, PublishError> {
    match existing {
        ExistingSidecar::Preserve => match directory.hard_link(temporary.name(), destination) {
            Ok(()) => {
                if let Err(failure) =
                    verify_published(directory, destination, &temporary.file, plan, summary)
                {
                    return Err(rollback_failed_publication(directory, destination, failure));
                }
                finish_publication(|| temporary.remove(), || directory.sync())?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if inspect_existing(directory, destination, expected)? == Some(true) {
                    return Ok(false);
                }
                return Err(PublishError::ExistingConflict);
            }
            Err(error) => return Err(PublishError::Publish(error)),
        },
        ExistingSidecar::Replace => {
            directory
                .rename(temporary.name(), destination)
                .map_err(PublishError::Publish)?;
            temporary.disarm();
            if let Err(failure) =
                verify_published(directory, destination, &temporary.file, plan, summary)
            {
                return Err(rollback_failed_publication(directory, destination, failure));
            }
            directory
                .sync()
                .map_err(PublishError::PublishedButSyncFailed)?;
        }
    }
    Ok(true)
}

struct FailedPublishedVerification {
    error: PublishedVerificationError,
    published: Option<File>,
}

fn verify_published(
    directory: &DestinationDirectory,
    destination: &std::ffi::OsStr,
    temporary: &File,
    plan: &CanonicalPlan,
    summary: WriteSummary,
) -> Result<(), FailedPublishedVerification> {
    let mut published = directory
        .open_read_no_follow(destination)
        .map_err(|error| FailedPublishedVerification {
            error: PublishedVerificationError::Open(error),
            published: None,
        })?;
    let expected = match temporary.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(FailedPublishedVerification {
                error: PublishedVerificationError::Metadata(error),
                published: Some(published),
            });
        }
    };
    let actual = match published.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(FailedPublishedVerification {
                error: PublishedVerificationError::Metadata(error),
                published: Some(published),
            });
        }
    };
    if !same_std_file_identity(&expected, &actual) {
        return Err(FailedPublishedVerification {
            error: PublishedVerificationError::IdentityChanged,
            published: Some(published),
        });
    }
    if let Err(error) = verify_temporary(&mut published, plan, summary) {
        return Err(FailedPublishedVerification {
            error: PublishedVerificationError::Content(Box::new(error)),
            published: Some(published),
        });
    }
    Ok(())
}

fn rollback_failed_publication(
    directory: &DestinationDirectory,
    destination: &std::ffi::OsStr,
    failure: FailedPublishedVerification,
) -> PublishError {
    let rollback = match failure.published {
        Some(published) => remove_published_file(directory, destination, &published),
        None => Err(io::Error::other(
            "published sidecar could not be opened for identity-safe rollback",
        )),
    };
    match rollback {
        Ok(()) => PublishError::PublishedVerificationFailed(failure.error),
        Err(rollback) => PublishError::PublishedVerificationAndRollbackFailed {
            verification: failure.error,
            rollback,
        },
    }
}

fn remove_published_file(
    directory: &DestinationDirectory,
    destination: &std::ffi::OsStr,
    published: &File,
) -> io::Result<()> {
    if remove_file_if_same(directory, destination, published, TemporaryKind::Sidecar)? {
        directory.sync()
    } else {
        Err(io::Error::other(
            "published sidecar disappeared before rollback",
        ))
    }
}

fn finish_publication(
    cleanup: impl FnOnce() -> io::Result<()>,
    sync: impl FnOnce() -> io::Result<()>,
) -> Result<(), PublishError> {
    finish_filesystem_publication(cleanup, sync).map_err(|error| match error {
        FinishError::Cleanup(error) => PublishError::PublishedButCleanupFailed(error),
        FinishError::Sync(error) => PublishError::PublishedButSyncFailed(error),
        FinishError::CleanupAndSync { cleanup, sync } => {
            PublishError::PublishedButCleanupAndSyncFailed { cleanup, sync }
        }
    })
}

fn verify_temporary_path(temporary: &TemporaryFile<'_>) -> Result<(), PublishError> {
    if temporary
        .verify_path_identity()
        .map_err(PublishError::TemporaryMetadata)?
    {
        Ok(())
    } else {
        Err(PublishError::TemporaryIdentityChanged)
    }
}

fn same_std_file_identity(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        same_windows_file_id(
            left.volume_serial_number(),
            left.file_index(),
            right.volume_serial_number(),
            right.file_index(),
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        left.len() == right.len() && left.modified().ok() == right.modified().ok()
    }
}

/// A published sidecar did not preserve the verified temporary inode and
/// content.
#[derive(Debug)]
pub enum PublishedVerificationError {
    Open(io::Error),
    Metadata(io::Error),
    IdentityChanged,
    Content(Box<PublishError>),
}

impl fmt::Display for PublishedVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(error) => write!(formatter, "cannot reopen published sidecar: {error}"),
            Self::Metadata(error) => {
                write!(formatter, "cannot inspect published sidecar: {error}")
            }
            Self::IdentityChanged => formatter
                .write_str("published pathname does not identify the verified sidecar inode"),
            Self::Content(error) => {
                write!(formatter, "published sidecar content is invalid: {error}")
            }
        }
    }
}

impl std::error::Error for PublishedVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open(error) | Self::Metadata(error) => Some(error),
            Self::Content(error) => Some(error),
            Self::IdentityChanged => None,
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
    TemporaryLockContended,
    TemporaryIdentityChanged,
    ExistingConflict,
    LimitOverflow,
    VerificationMismatch,
    RecoveryDigestMismatch(u32),
    WrittenLengthMismatch {
        actual: u64,
        expected: u64,
    },
    OpenDirectory(io::Error),
    OpenSource(io::Error),
    SourceMetadata(io::Error),
    Build(BuildError),
    Spool(io::Error),
    InspectExisting(io::Error),
    CreateTemporary(io::Error),
    LockTemporary(io::Error),
    CleanupTemporaries(io::Error),
    CanonicalLayout(crate::sidecar::WriteError),
    ReadLimits(crate::sidecar::ReadLimitError),
    RecoveryChunk(recovery_chunk::Error),
    RecordWrite(record::Error),
    Flush(io::Error),
    SyncTemporary(io::Error),
    RewindTemporary(io::Error),
    TemporaryMetadata(io::Error),
    VerifyRecord(record::Error),
    VerifyRecovery(recovery_chunk::Error),
    Publish(io::Error),
    PublishedVerificationFailed(PublishedVerificationError),
    PublishedVerificationAndRollbackFailed {
        verification: PublishedVerificationError,
        rollback: io::Error,
    },
    PublishedButCleanupFailed(io::Error),
    PublishedButSyncFailed(io::Error),
    PublishedButCleanupAndSyncFailed {
        cleanup: io::Error,
        sync: io::Error,
    },
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
            Self::TemporaryLockContended => {
                formatter.write_str("newly created temporary sidecar was unexpectedly locked")
            }
            Self::TemporaryIdentityChanged => {
                formatter.write_str("temporary sidecar path changed before publication")
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
            Self::OpenDirectory(error) => {
                write!(formatter, "cannot open destination directory: {error}")
            }
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
            Self::LockTemporary(error) => {
                write!(formatter, "cannot lock temporary sidecar: {error}")
            }
            Self::CleanupTemporaries(error) => {
                write!(formatter, "cannot clean stale temporary files: {error}")
            }
            Self::CanonicalLayout(error) => {
                write!(formatter, "canonical sidecar layout failed: {error}")
            }
            Self::ReadLimits(error) => {
                write!(formatter, "sidecar verification limits failed: {error}")
            }
            Self::RecoveryChunk(error) => {
                write!(formatter, "recovery-chunk encoding failed: {error}")
            }
            Self::RecordWrite(error) => write!(formatter, "record writing failed: {error}"),
            Self::Flush(error) => write!(formatter, "cannot flush temporary sidecar: {error}"),
            Self::SyncTemporary(error) => {
                write!(formatter, "cannot synchronize temporary sidecar: {error}")
            }
            Self::RewindTemporary(error) => {
                write!(formatter, "cannot rewind temporary sidecar: {error}")
            }
            Self::TemporaryMetadata(error) => {
                write!(formatter, "cannot inspect temporary sidecar: {error}")
            }
            Self::VerifyRecord(error) => write!(formatter, "temporary record is invalid: {error}"),
            Self::VerifyRecovery(error) => {
                write!(formatter, "temporary recovery record is invalid: {error}")
            }
            Self::Publish(error) => write!(formatter, "cannot publish sidecar: {error}"),
            Self::PublishedVerificationFailed(error) => {
                fmt_published_verification(formatter, error, None)
            }
            Self::PublishedVerificationAndRollbackFailed {
                verification,
                rollback,
            } => fmt_published_verification(formatter, verification, Some(rollback)),
            Self::PublishedButCleanupFailed(error) => write!(
                formatter,
                "sidecar was published but its temporary link could not be removed: {error}"
            ),
            Self::PublishedButSyncFailed(error) => write!(
                formatter,
                "sidecar was published but its destination directory could not be synchronized: {error}"
            ),
            Self::PublishedButCleanupAndSyncFailed { cleanup, sync } => write!(
                formatter,
                "sidecar was published but its temporary link could not be removed ({cleanup}) and its destination directory could not be synchronized ({sync})"
            ),
        }
    }
}

fn fmt_published_verification(
    formatter: &mut fmt::Formatter<'_>,
    verification: &PublishedVerificationError,
    rollback: Option<&io::Error>,
) -> fmt::Result {
    if let Some(rollback) = rollback {
        write!(
            formatter,
            "published sidecar failed verification ({verification}) and could not be rolled back: {rollback}"
        )
    } else {
        write!(
            formatter,
            "published sidecar failed verification and was rolled back: {verification}"
        )
    }
}

impl std::error::Error for PublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenDirectory(error)
            | Self::OpenSource(error)
            | Self::SourceMetadata(error)
            | Self::Spool(error)
            | Self::InspectExisting(error)
            | Self::CreateTemporary(error)
            | Self::LockTemporary(error)
            | Self::CleanupTemporaries(error)
            | Self::Flush(error)
            | Self::SyncTemporary(error)
            | Self::RewindTemporary(error)
            | Self::TemporaryMetadata(error)
            | Self::Publish(error)
            | Self::PublishedButCleanupFailed(error)
            | Self::PublishedButSyncFailed(error) => Some(error),
            Self::PublishedButCleanupAndSyncFailed { cleanup, .. } => Some(cleanup),
            Self::PublishedVerificationAndRollbackFailed { verification, .. } => Some(verification),
            Self::PublishedVerificationFailed(error) => Some(error),
            Self::Build(error) => Some(error),
            Self::CanonicalLayout(error) => Some(error),
            Self::ReadLimits(error) => Some(error),
            Self::RecoveryChunk(error) | Self::VerifyRecovery(error) => Some(error),
            Self::RecordWrite(error) | Self::VerifyRecord(error) => Some(error),
            Self::OverlappingPaths
            | Self::SourceIsSymlink
            | Self::SourceNotRegularFile
            | Self::SourceIdentityChanged
            | Self::DestinationHasNoFileName
            | Self::TemporaryNameExhausted
            | Self::TemporaryLockContended
            | Self::TemporaryIdentityChanged
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
    use std::cell::Cell;
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

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

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn rejects_a_substituted_temporary_during_publication() {
        let directory = TestDirectory::new();
        let destination = directory.join("source.bin.bitrot");
        let anchored = DestinationDirectory::open(&directory.0).unwrap();
        let mut temporary = create_temporary(
            &anchored,
            destination.file_name().unwrap(),
            TemporaryKind::Sidecar,
        )
        .unwrap();
        let opts = options();
        let sidecar = super::super::build(&mut Cursor::new(source_bytes()), &opts).unwrap();
        let plan = CanonicalPlan::new(&sidecar.metadata, &opts.creator).unwrap();
        let mut canonical = Vec::new();
        let summary = sidecar.write_canonical(&mut canonical).unwrap();
        temporary.file.write_all(&canonical).unwrap();
        temporary.file.sync_all().unwrap();

        let temporary_path = directory.0.join(temporary.name());
        let moved_temporary = directory.join("moved-verified-sidecar");
        fs::rename(&temporary_path, &moved_temporary).unwrap();
        fs::write(&temporary_path, b"substituted sidecar").unwrap();

        let result = publish_temporary(
            &mut temporary,
            &anchored,
            destination.file_name().unwrap(),
            &sidecar.metadata,
            &plan,
            summary,
            ExistingSidecar::Preserve,
        );

        assert!(matches!(
            result,
            Err(PublishError::PublishedVerificationFailed(
                PublishedVerificationError::IdentityChanged
            ))
        ));
        assert!(!destination.exists());
        drop(temporary);
        assert_eq!(fs::read(&temporary_path).unwrap(), b"substituted sidecar");
        assert_eq!(fs::read(&moved_temporary).unwrap(), canonical);
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn rolls_back_published_content_that_no_longer_verifies() {
        let directory = TestDirectory::new();
        let destination = directory.join("source.bin.bitrot");
        let anchored = DestinationDirectory::open(&directory.0).unwrap();
        let mut temporary = create_temporary(
            &anchored,
            destination.file_name().unwrap(),
            TemporaryKind::Sidecar,
        )
        .unwrap();
        let opts = options();
        let sidecar = super::super::build(&mut Cursor::new(source_bytes()), &opts).unwrap();
        let plan = CanonicalPlan::new(&sidecar.metadata, &opts.creator).unwrap();
        let mut canonical = Vec::new();
        let summary = sidecar.write_canonical(&mut canonical).unwrap();
        temporary.file.write_all(b"invalid sidecar").unwrap();
        temporary.file.sync_all().unwrap();

        let result = publish_temporary(
            &mut temporary,
            &anchored,
            destination.file_name().unwrap(),
            &sidecar.metadata,
            &plan,
            summary,
            ExistingSidecar::Preserve,
        );

        assert!(matches!(
            result,
            Err(PublishError::PublishedVerificationFailed(
                PublishedVerificationError::Content(_)
            ))
        ));
        assert!(!destination.exists());
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

    #[test]
    fn concurrent_preserving_publishers_install_exactly_once() {
        const PUBLISHERS: usize = 8;

        let directory = TestDirectory::new();
        let source = directory.join("source.bin");
        let destination = directory.join("source.bin.bitrot");
        fs::write(&source, source_bytes()).unwrap();
        let start = Arc::new(Barrier::new(PUBLISHERS));
        let mut threads = Vec::new();

        for _ in 0..PUBLISHERS {
            let source = source.clone();
            let destination = destination.clone();
            let start = Arc::clone(&start);
            threads.push(std::thread::spawn(move || {
                start.wait();
                publish(source, destination, &options(), ExistingSidecar::Preserve)
            }));
        }

        let outcomes = threads
            .into_iter()
            .map(|thread| thread.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PublishOutcome::Published(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PublishOutcome::AlreadyCurrent))
                .count(),
            PUBLISHERS - 1
        );
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[test]
    fn synchronizes_published_link_even_when_temporary_cleanup_fails() {
        let synchronized = Cell::new(false);
        let result = finish_publication(
            || Err(io::Error::other("injected cleanup failure")),
            || {
                synchronized.set(true);
                Ok(())
            },
        );

        assert!(synchronized.get());
        assert!(matches!(
            result,
            Err(PublishError::PublishedButCleanupFailed(_))
        ));
    }

    #[test]
    fn reports_both_post_publication_failures() {
        let result = finish_publication(
            || Err(io::Error::other("injected cleanup failure")),
            || Err(io::Error::other("injected synchronization failure")),
        );

        let Err(PublishError::PublishedButCleanupAndSyncFailed { cleanup, sync }) = result else {
            panic!("both failures were not retained");
        };
        assert_eq!(cleanup.to_string(), "injected cleanup failure");
        assert_eq!(sync.to_string(), "injected synchronization failure");
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn removes_old_unlocked_partials_but_preserves_locked_ones() {
        use std::fs::FileTimes;
        use std::time::UNIX_EPOCH;

        let directory = TestDirectory::new();
        let destination = directory.join("source.bin.bitrot");
        let stale = directory.join("source.bin.bitrot.bitrot-partial-999999-recovery-0-0");
        let active = directory.join("source.bin.bitrot.bitrot-partial-999999-sidecar-0-1");
        let stale_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&stale)
            .unwrap();
        let active_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&active)
            .unwrap();
        let old = FileTimes::new().set_modified(UNIX_EPOCH);
        stale_file.set_times(old).unwrap();
        active_file.set_times(old).unwrap();
        active_file.try_lock().unwrap();
        let anchored = DestinationDirectory::open(&directory.0).unwrap();

        cleanup_stale_temporaries(&anchored, destination.file_name().unwrap()).unwrap();

        assert!(!stale.exists());
        assert!(active.exists());
        drop(active_file);
        cleanup_stale_temporaries(&anchored, destination.file_name().unwrap()).unwrap();
        assert!(!active.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn stale_cleanup_restores_a_substituted_path_instead_of_deleting_it() {
        let directory = TestDirectory::new();
        let stale_name =
            std::ffi::OsStr::new("source.bin.bitrot.bitrot-partial-999999-sidecar-0-1");
        let stale_path = directory.0.join(stale_name);
        fs::write(&stale_path, b"stale partial").unwrap();
        let stale_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&stale_path)
            .unwrap();
        let moved_stale = directory.join("moved-stale-partial");
        fs::rename(&stale_path, &moved_stale).unwrap();
        fs::write(&stale_path, b"replacement that must survive").unwrap();
        let anchored = DestinationDirectory::open(&directory.0).unwrap();

        let error = remove_file_if_same(&anchored, stale_name, &stale_file, TemporaryKind::Sidecar)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            fs::read(&stale_path).unwrap(),
            b"replacement that must survive"
        );
        assert_eq!(fs::read(&moved_stale).unwrap(), b"stale partial");
    }

    #[test]
    fn guard_does_not_remove_a_replacement_at_its_temporary_path() {
        let directory = TestDirectory::new();
        let destination = directory.join("source.bin.bitrot");
        let anchored = DestinationDirectory::open(&directory.0).unwrap();
        let temporary = create_temporary(
            &anchored,
            destination.file_name().unwrap(),
            TemporaryKind::Sidecar,
        )
        .unwrap();
        let temporary_path = directory.0.join(temporary.name());
        let moved = directory.join("moved-partial");
        fs::rename(&temporary_path, &moved).unwrap();
        fs::write(&temporary_path, b"not ours").unwrap();

        assert!(matches!(
            verify_temporary_path(&temporary),
            Err(PublishError::TemporaryIdentityChanged)
        ));
        drop(temporary);
        assert_eq!(fs::read(&temporary_path).unwrap(), b"not ours");
        assert!(moved.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn explicit_cleanup_restores_a_replacement_at_the_temporary_path() {
        let directory = TestDirectory::new();
        let destination = directory.join("source.bin.bitrot");
        let anchored = DestinationDirectory::open(&directory.0).unwrap();
        let mut temporary = create_temporary(
            &anchored,
            destination.file_name().unwrap(),
            TemporaryKind::Sidecar,
        )
        .unwrap();
        let temporary_path = directory.0.join(temporary.name());
        let moved = directory.join("moved-partial");
        fs::rename(&temporary_path, &moved).unwrap();
        fs::write(&temporary_path, b"not ours").unwrap();

        assert!(temporary.remove().is_err());
        assert_eq!(fs::read(&temporary_path).unwrap(), b"not ours");
        assert!(moved.exists());
    }

    #[test]
    fn windows_file_identity_requires_matching_available_ids() {
        assert!(same_windows_file_id(Some(7), Some(11), Some(7), Some(11)));
        assert!(!same_windows_file_id(Some(7), Some(11), Some(8), Some(11)));
        assert!(!same_windows_file_id(Some(7), Some(11), Some(7), Some(12)));
        assert!(!same_windows_file_id(None, None, None, None));
        assert!(!same_windows_file_id(Some(7), None, Some(7), None));
    }

    #[test]
    fn destination_operations_remain_in_the_open_directory_after_rename() {
        let root = TestDirectory::new();
        let original = root.join("destination");
        let moved = root.join("moved-destination");
        fs::create_dir(&original).unwrap();
        let anchored = DestinationDirectory::open(&original).unwrap();
        let mut temporary = create_temporary(
            &anchored,
            std::ffi::OsStr::new("movie.bitrot"),
            TemporaryKind::Sidecar,
        )
        .unwrap();
        temporary.file.write_all(b"complete sidecar").unwrap();
        temporary.file.sync_all().unwrap();

        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        anchored
            .hard_link(temporary.name(), std::ffi::OsStr::new("movie.bitrot"))
            .unwrap();
        temporary.remove().unwrap();
        anchored.sync().unwrap();

        assert_eq!(
            fs::read(moved.join("movie.bitrot")).unwrap(),
            b"complete sidecar"
        );
        assert!(!original.join("movie.bitrot").exists());
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

    #[cfg(unix)]
    #[test]
    fn does_not_follow_an_existing_sidecar_symlink() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let source = directory.join("source.bin");
        let real_sidecar = directory.join("real.bitrot");
        let destination = directory.join("source.bin.bitrot");
        fs::write(&source, source_bytes()).unwrap();
        publish(
            &source,
            &real_sidecar,
            &options(),
            ExistingSidecar::Preserve,
        )
        .unwrap();
        symlink(&real_sidecar, &destination).unwrap();

        assert!(matches!(
            publish(&source, &destination, &options(), ExistingSidecar::Preserve),
            Err(PublishError::ExistingConflict)
        ));
        assert_eq!(fs::read_link(&destination).unwrap(), real_sidecar);
    }
}
