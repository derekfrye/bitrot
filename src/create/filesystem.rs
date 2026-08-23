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
#[cfg(windows)]
use cap_std::ambient_authority;
#[cfg(any(unix, windows))]
use cap_std::fs::{Dir, OpenOptions as DirectoryOpenOptions};
#[cfg(unix)]
use cap_std::fs::{MetadataExt as CapMetadataExt, OpenOptionsExt as CapOpenOptionsExt};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;
#[cfg(not(any(unix, windows)))]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
const STALE_TEMPORARY_AGE: Duration = Duration::from_hours(24);
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

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
    let directory = DestinationDirectory::open(parent)?;
    let destination_name = sidecar_path
        .file_name()
        .ok_or(PublishError::DestinationHasNoFileName)?;
    let (mut source, snapshot) = open_source(source_path)?;
    let (fingerprint, geometry) = analyze(&mut source, options).map_err(PublishError::Build)?;
    cleanup_stale_temporaries(&directory, destination_name)?;
    let spool_temporary =
        create_temporary(&directory, destination_name, TemporaryKind::RecoverySpool)?;
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
    temporary.verify_path_identity()?;
    let published = publish_temporary(
        &mut temporary,
        &directory,
        destination_name,
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
        Ok(snapshot.device == metadata.device && snapshot.inode == metadata.inode)
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

struct DestinationDirectory {
    #[cfg(any(unix, windows))]
    directory: Dir,
    #[cfg(unix)]
    sync_file: File,
    #[cfg(not(any(unix, windows)))]
    ambient_path: PathBuf,
}

impl DestinationDirectory {
    fn open(path: &Path) -> Result<Self, PublishError> {
        #[cfg(unix)]
        let (directory, sync_file) = {
            let sync_file = File::open(path).map_err(PublishError::OpenDirectory)?;
            let directory =
                Dir::from_std_file(sync_file.try_clone().map_err(PublishError::OpenDirectory)?);
            (directory, sync_file)
        };
        #[cfg(not(unix))]
        #[cfg(windows)]
        let directory = Dir::open_ambient_dir(path, ambient_authority())
            .map_err(PublishError::OpenDirectory)?;
        #[cfg(not(any(unix, windows)))]
        let ambient_path = path.to_owned();
        Ok(Self {
            #[cfg(any(unix, windows))]
            directory,
            #[cfg(unix)]
            sync_file,
            #[cfg(not(any(unix, windows)))]
            ambient_path,
        })
    }

    fn open_read_no_follow(&self, name: &std::ffi::OsStr) -> io::Result<File> {
        #[cfg(any(unix, windows))]
        {
            let mut options = DirectoryOpenOptions::new();
            options.read(true);
            set_no_follow(&mut options);
            self.directory
                .open_with(name, &options)
                .map(cap_std::fs::File::into_std)
        }
        #[cfg(not(any(unix, windows)))]
        {
            open_read_no_follow(&self.ambient_path.join(name))
        }
    }

    #[cfg(unix)]
    fn open_read_write_no_follow(&self, name: &std::ffi::OsStr) -> io::Result<File> {
        let mut options = DirectoryOpenOptions::new();
        options.read(true).write(true);
        set_no_follow(&mut options);
        self.directory
            .open_with(name, &options)
            .map(cap_std::fs::File::into_std)
    }

    fn create_new(&self, name: &std::ffi::OsStr) -> io::Result<File> {
        #[cfg(any(unix, windows))]
        {
            let mut options = DirectoryOpenOptions::new();
            options.read(true).write(true).create_new(true);
            set_no_follow(&mut options);
            self.directory
                .open_with(name, &options)
                .map(cap_std::fs::File::into_std)
        }
        #[cfg(not(any(unix, windows)))]
        {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(self.ambient_path.join(name))
        }
    }

    fn symlink_metadata(&self, name: &std::ffi::OsStr) -> io::Result<EntryMetadata> {
        #[cfg(any(unix, windows))]
        {
            self.directory
                .symlink_metadata(name)
                .map(|metadata| EntryMetadata::from_cap(&metadata))
        }
        #[cfg(not(any(unix, windows)))]
        {
            fs::symlink_metadata(self.ambient_path.join(name)).map(EntryMetadata::from_std)
        }
    }

    fn hard_link(&self, source: &std::ffi::OsStr, destination: &std::ffi::OsStr) -> io::Result<()> {
        #[cfg(any(unix, windows))]
        {
            self.directory
                .hard_link(source, &self.directory, destination)
        }
        #[cfg(not(any(unix, windows)))]
        {
            fs::hard_link(
                self.ambient_path.join(source),
                self.ambient_path.join(destination),
            )
        }
    }

    fn rename(&self, source: &std::ffi::OsStr, destination: &std::ffi::OsStr) -> io::Result<()> {
        #[cfg(any(unix, windows))]
        {
            self.directory.rename(source, &self.directory, destination)
        }
        #[cfg(not(any(unix, windows)))]
        {
            fs::rename(
                self.ambient_path.join(source),
                self.ambient_path.join(destination),
            )
        }
    }

    fn remove_file(&self, name: &std::ffi::OsStr) -> io::Result<()> {
        #[cfg(any(unix, windows))]
        {
            self.directory.remove_file(name)
        }
        #[cfg(not(any(unix, windows)))]
        {
            fs::remove_file(self.ambient_path.join(name))
        }
    }

    fn sync(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.sync_file.sync_all()
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
}

struct EntryMetadata {
    is_file: bool,
    is_symlink: bool,
    #[cfg(not(unix))]
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl EntryMetadata {
    #[cfg(any(unix, windows))]
    fn from_cap(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            is_file: metadata.is_file(),
            is_symlink: metadata.file_type().is_symlink(),
            #[cfg(not(unix))]
            len: metadata.len(),
            modified: metadata
                .modified()
                .ok()
                .map(cap_std::time::SystemTime::into_std),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn from_std(metadata: Metadata) -> Self {
        Self {
            is_file: metadata.is_file(),
            is_symlink: metadata.file_type().is_symlink(),
            len: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }

    const fn is_file(&self) -> bool {
        self.is_file
    }

    const fn is_symlink(&self) -> bool {
        self.is_symlink
    }
}

#[cfg(any(unix, windows))]
fn set_no_follow(options: &mut DirectoryOpenOptions) {
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    {
        let _ = options;
    }
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

fn create_temporary<'directory>(
    directory: &'directory DestinationDirectory,
    destination_name: &std::ffi::OsStr,
    kind: TemporaryKind,
) -> Result<TemporaryFile<'directory>, PublishError> {
    let epoch_nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for _ in 0_u32..128 {
        let nonce = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(destination_name);
        temporary_name.push(format!(
            ".bitrot-partial-{}-{}-{epoch_nonce:x}-{nonce:x}",
            std::process::id(),
            kind.name()
        ));
        match directory.create_new(&temporary_name) {
            Ok(file) => {
                file.try_lock().map_err(|error| match error {
                    TryLockError::Error(error) => PublishError::LockTemporary(error),
                    TryLockError::WouldBlock => PublishError::TemporaryLockContended,
                })?;
                return Ok(TemporaryFile::new(directory, temporary_name, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(PublishError::CreateTemporary(error)),
        }
    }
    Err(PublishError::TemporaryNameExhausted)
}

#[cfg(unix)]
fn cleanup_stale_temporaries(
    directory: &DestinationDirectory,
    destination_name: &std::ffi::OsStr,
) -> Result<(), PublishError> {
    use std::os::unix::ffi::OsStrExt;

    let now = SystemTime::now();
    let mut removed = false;

    for entry in directory
        .directory
        .entries()
        .map_err(PublishError::CleanupTemporaries)?
    {
        let entry = entry.map_err(PublishError::CleanupTemporaries)?;
        let name = entry.file_name();
        if !is_temporary_name_for(name.as_bytes(), destination_name.as_bytes()) {
            continue;
        }
        let metadata = directory
            .symlink_metadata(&name)
            .map_err(PublishError::CleanupTemporaries)?;
        if !metadata.is_file()
            || metadata
                .modified
                .and_then(|modified| now.duration_since(modified).ok())
                .is_none_or(|age| age < STALE_TEMPORARY_AGE)
        {
            continue;
        }
        let file = match directory.open_read_write_no_follow(&name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(PublishError::CleanupTemporaries(error)),
        };
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => continue,
            Err(TryLockError::Error(error)) => {
                return Err(PublishError::CleanupTemporaries(error));
            }
        }
        let open_metadata = file.metadata().map_err(PublishError::CleanupTemporaries)?;
        let path_metadata = match directory.symlink_metadata(&name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(PublishError::CleanupTemporaries(error)),
        };
        if !same_entry_identity(&open_metadata, &path_metadata) {
            continue;
        }
        directory
            .remove_file(&name)
            .map_err(PublishError::CleanupTemporaries)?;
        removed = true;
    }

    if removed {
        directory.sync().map_err(PublishError::CleanupTemporaries)?;
    }
    Ok(())
}

#[cfg(unix)]
fn is_temporary_name_for(candidate: &[u8], destination: &[u8]) -> bool {
    let Some(suffix) = candidate.strip_prefix(destination) else {
        return false;
    };
    let Some(fields) = suffix.strip_prefix(b".bitrot-partial-") else {
        return false;
    };
    let mut fields = fields.split(|byte| *byte == b'-');
    let Some(pid) = fields.next() else {
        return false;
    };
    let Some(kind) = fields.next() else {
        return false;
    };
    let Some(epoch) = fields.next() else {
        return false;
    };
    let Some(nonce) = fields.next() else {
        return false;
    };
    fields.next().is_none()
        && !pid.is_empty()
        && pid.iter().all(u8::is_ascii_digit)
        && matches!(kind, b"recovery" | b"sidecar")
        && is_lower_hex(epoch)
        && is_lower_hex(nonce)
}

#[cfg(unix)]
fn is_lower_hex(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(not(unix))]
fn cleanup_stale_temporaries(
    _directory: &DestinationDirectory,
    _destination_name: &std::ffi::OsStr,
) -> Result<(), PublishError> {
    Ok(())
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
    temporary: &mut TemporaryFile<'_>,
    directory: &DestinationDirectory,
    destination: &std::ffi::OsStr,
    expected: &ProtectionMetadata,
    existing: ExistingSidecar,
) -> Result<bool, PublishError> {
    match existing {
        ExistingSidecar::Preserve => match directory.hard_link(temporary.name(), destination) {
            Ok(()) => finish_publication(|| temporary.remove(), || directory.sync())?,
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
            directory
                .sync()
                .map_err(PublishError::PublishedButSyncFailed)?;
        }
    }
    Ok(true)
}

fn finish_publication(
    cleanup: impl FnOnce() -> io::Result<()>,
    sync: impl FnOnce() -> io::Result<()>,
) -> Result<(), PublishError> {
    let cleanup_error = cleanup().err();
    let sync_error = sync().err();

    match (cleanup_error, sync_error) {
        (None, None) => Ok(()),
        (Some(error), None) => Err(PublishError::PublishedButCleanupFailed(error)),
        (None, Some(error)) => Err(PublishError::PublishedButSyncFailed(error)),
        (Some(cleanup), Some(sync)) => {
            Err(PublishError::PublishedButCleanupAndSyncFailed { cleanup, sync })
        }
    }
}

struct TemporaryFile<'directory> {
    directory: &'directory DestinationDirectory,
    name: OsString,
    file: File,
    armed: bool,
}

impl<'directory> TemporaryFile<'directory> {
    fn new(directory: &'directory DestinationDirectory, name: OsString, file: File) -> Self {
        Self {
            directory,
            name,
            file,
            armed: true,
        }
    }

    fn name(&self) -> &std::ffi::OsStr {
        &self.name
    }

    fn remove(&mut self) -> io::Result<()> {
        if !self.path_still_names_file()? {
            self.armed = false;
            return Err(io::Error::other(
                "temporary path no longer names the file created by this process",
            ));
        }
        self.directory.remove_file(&self.name)?;
        self.armed = false;
        Ok(())
    }

    fn verify_path_identity(&self) -> Result<(), PublishError> {
        if !self
            .path_still_names_file()
            .map_err(PublishError::TemporaryMetadata)?
        {
            return Err(PublishError::TemporaryIdentityChanged);
        }
        Ok(())
    }

    fn path_still_names_file(&self) -> io::Result<bool> {
        let open_metadata = self.file.metadata()?;
        let path_metadata = match self.directory.symlink_metadata(&self.name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        Ok(path_metadata.is_file() && same_entry_identity(&open_metadata, &path_metadata))
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryFile<'_> {
    fn drop(&mut self) {
        if self.armed && self.path_still_names_file().unwrap_or(false) {
            let _ = self.directory.remove_file(&self.name);
        }
    }
}

fn same_entry_identity(left: &Metadata, right: &EntryMetadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        left.dev() == right.device && left.ino() == right.inode
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len && left.modified().ok() == right.modified
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
    WrittenLengthMismatch { actual: u64, expected: u64 },
    OpenDirectory(io::Error),
    OpenSource(io::Error),
    SourceMetadata(io::Error),
    Build(BuildError),
    Spool(io::Error),
    InspectExisting(io::Error),
    CreateTemporary(io::Error),
    LockTemporary(io::Error),
    CleanupTemporaries(io::Error),
    Creator(creator::Error),
    DigestPage(digest_page::Error),
    RollingPage(rolling_page::Error),
    RecoveryChunk(recovery_chunk::Error),
    Superblock(superblock::Error),
    RecordWrite(record::Error),
    Flush(io::Error),
    SyncTemporary(io::Error),
    RewindTemporary(io::Error),
    TemporaryMetadata(io::Error),
    VerifyRecord(record::Error),
    VerifyRecovery(recovery_chunk::Error),
    Publish(io::Error),
    PublishedButCleanupFailed(io::Error),
    PublishedButSyncFailed(io::Error),
    PublishedButCleanupAndSyncFailed { cleanup: io::Error, sync: io::Error },
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

    #[cfg(unix)]
    #[test]
    fn removes_old_unlocked_partials_but_preserves_locked_ones() {
        use std::fs::FileTimes;

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
            temporary.verify_path_identity(),
            Err(PublishError::TemporaryIdentityChanged)
        ));
        drop(temporary);
        assert_eq!(fs::read(&temporary_path).unwrap(), b"not ours");
        assert!(moved.exists());
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
