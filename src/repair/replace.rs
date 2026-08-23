//! Transactional replacement with retention of the damaged source.

use super::{PublishError, PublishOptions, PublishOutcome, PublishSummary, publish};
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
use crate::filesystem::FileIdentity;
use crate::sidecar::{ReadError as SidecarReadError, Sidecar};
use crate::verify::{self, SourceDigestState, SourceState};
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
use cap_std::fs::{Dir, OpenOptions as DirectoryOpenOptions, OpenOptionsExt as _};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Seek, SeekFrom};
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

const BACKUP_SUFFIX: &str = ".bitrot-damaged";
const STAGING_SUFFIX: &str = ".bitrot-replacement";

/// Work completed by a transactional source replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplaceSummary {
    /// Publication work performed by this invocation.
    ///
    /// This is `None` when a complete staged repair from an interrupted
    /// invocation was reused.
    pub publication: Option<PublishSummary>,
}

/// Successful outcome of transactional source replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaceOutcome {
    /// The damaged source was atomically replaced and retained as a backup.
    Replaced(ReplaceSummary),
    /// An interrupted exchange was completed by retaining its damaged inode.
    RecoveredInterrupted,
    /// The source already matches the authenticated sidecar.
    AlreadyCurrent,
}

/// Replaces a damaged source while retaining its original inode.
///
/// The repaired file is prepared as `<source>.bitrot-replacement`. The source
/// and prepared repair are then atomically exchanged, so the source pathname
/// always names either the damaged or repaired inode. The damaged inode is
/// finally moved without replacement to `<source>.bitrot-damaged`. Both names
/// are resolved relative to one pinned source-directory handle.
///
/// An interrupted transaction is restartable. If the source is already intact
/// and the staging name holds an unlocked damaged inode, a later invocation
/// finishes moving that inode to the backup name. Existing backup objects are
/// never overwritten.
///
/// # Errors
///
/// Returns an error when paths overlap, an input or transaction entry is
/// unsafe, the source is unrepairable, another replacement is active, a backup
/// conflicts, publication fails, atomic exchange is unsupported, verification
/// fails, or a committed namespace change cannot be durably synchronized.
pub fn replace(
    source_path: impl AsRef<Path>,
    sidecar_path: impl AsRef<Path>,
    options: PublishOptions,
) -> Result<ReplaceOutcome, ReplaceError> {
    replace_impl(source_path.as_ref(), sidecar_path.as_ref(), options)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn replace_impl(
    source_path: &Path,
    sidecar_path: &Path,
    options: PublishOptions,
) -> Result<ReplaceOutcome, ReplaceError> {
    let source_name = source_path
        .file_name()
        .ok_or(ReplaceError::SourceHasNoFileName)?;
    let staging_name = suffixed_name(source_name, STAGING_SUFFIX);
    let backup_name = suffixed_name(source_name, BACKUP_SUFFIX);
    let parent = parent_directory(source_path);
    let staging_path = parent.join(&staging_name);
    let backup_path = parent.join(&backup_name);
    if source_path == sidecar_path || sidecar_path == staging_path || sidecar_path == backup_path {
        return Err(ReplaceError::OverlappingPaths);
    }

    let directory = SourceDirectory::open(parent).map_err(ReplaceError::OpenDirectory)?;
    let mut source = directory
        .open_locked_regular(source_name, EntryRole::Source)
        .map_err(ReplaceError::Entry)?;
    let source_identity = FileIdentity::capture(&source).map_err(ReplaceError::SourceMetadata)?;
    let sidecar = read_sidecar(sidecar_path, options)?;
    let source_state = verify_state(&mut source, &sidecar).map_err(ReplaceError::VerifySource)?;

    if source_state == SourceState::Intact {
        return finish_or_recognize_interrupted(
            &directory,
            source_name,
            &staging_name,
            &backup_name,
            &mut source,
            &sidecar,
        );
    }
    if source_state == SourceState::Unrepairable {
        return Err(ReplaceError::Unrepairable);
    }
    ensure_absent(&directory, &backup_name, ReplaceError::BackupConflict)?;

    let publication = match publish(source_path, sidecar_path, &staging_path, options) {
        Ok(PublishOutcome::Published(summary)) => Some(summary),
        Ok(PublishOutcome::AlreadyCurrent) => None,
        Err(error) => return Err(ReplaceError::Prepare(error)),
    };
    let mut staged = directory
        .open_locked_regular(&staging_name, EntryRole::Staging)
        .map_err(ReplaceError::Entry)?;
    require_intact(&mut staged, &sidecar).map_err(ReplaceError::VerifyStaging)?;
    require_path_identity(&directory, source_name, &source, &source_identity)
        .map_err(ReplaceError::SourceChanged)?;
    let staged_identity = FileIdentity::capture(&staged).map_err(ReplaceError::StagingMetadata)?;
    ensure_absent(&directory, &backup_name, ReplaceError::BackupConflict)?;

    directory
        .exchange(source_name, &staging_name)
        .map_err(ReplaceError::Exchange)?;
    let mut exchanged = ExchangedFiles {
        source_name,
        staging_name: &staging_name,
        repaired: &mut staged,
        damaged: &source,
        repaired_identity: &staged_identity,
        damaged_identity: &source_identity,
    };
    if let Err(verification) = verify_exchange(&directory, &mut exchanged, &sidecar) {
        return Err(rollback_exchange(&directory, &exchanged, verification));
    }
    directory
        .sync()
        .map_err(ReplaceError::ReplacedButExchangeSyncFailed)?;

    directory
        .rename_no_replace(&staging_name, &backup_name)
        .map_err(ReplaceError::ReplacedButBackupMoveFailed)?;
    require_path_identity(&directory, &backup_name, &source, &source_identity)
        .map_err(ReplaceError::ReplacedButBackupIdentityFailed)?;
    directory
        .sync()
        .map_err(ReplaceError::ReplacedButBackupSyncFailed)?;

    Ok(ReplaceOutcome::Replaced(ReplaceSummary { publication }))
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn replace_impl(
    _source_path: &Path,
    _sidecar_path: &Path,
    _options: PublishOptions,
) -> Result<ReplaceOutcome, ReplaceError> {
    Err(ReplaceError::AtomicExchangeUnsupported)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn read_sidecar(path: &Path, options: PublishOptions) -> Result<Sidecar, ReplaceError> {
    let metadata = fs::symlink_metadata(path).map_err(ReplaceError::SidecarMetadata)?;
    if metadata.file_type().is_symlink() {
        return Err(ReplaceError::SidecarIsSymlink);
    }
    if !metadata.is_file() {
        return Err(ReplaceError::SidecarNotRegularFile);
    }
    let mut open_options = OpenOptions::new();
    open_options.read(true);
    open_options.custom_flags(libc::O_NOFOLLOW);
    let file = open_options.open(path).map_err(ReplaceError::OpenSidecar)?;
    let opened = file.metadata().map_err(ReplaceError::SidecarMetadata)?;
    if FileIdentity::from_std(&metadata) != FileIdentity::from_std(&opened) {
        return Err(ReplaceError::SidecarIdentityChanged);
    }
    Sidecar::read(file, options.sidecar_limits)
        .map(|read| read.sidecar)
        .map_err(ReplaceError::ReadSidecar)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn finish_or_recognize_interrupted(
    directory: &SourceDirectory,
    source_name: &OsStr,
    staging_name: &OsStr,
    backup_name: &OsStr,
    source: &mut File,
    sidecar: &Sidecar,
) -> Result<ReplaceOutcome, ReplaceError> {
    let staging_exists = directory
        .exists(staging_name)
        .map_err(ReplaceError::InspectStaging)?;
    let backup_exists = directory
        .exists(backup_name)
        .map_err(ReplaceError::InspectBackup)?;
    match (staging_exists, backup_exists) {
        (false, _) => Ok(ReplaceOutcome::AlreadyCurrent),
        (true, true) => Err(ReplaceError::TransactionStateConflict),
        (true, false) => {
            let mut staged = directory
                .open_locked_regular(staging_name, EntryRole::Staging)
                .map_err(ReplaceError::Entry)?;
            let staged_state = verify_state(&mut staged, sidecar)
                .map_err(IntactError::Verify)
                .map_err(ReplaceError::VerifyStaging)?;
            if staged_state == SourceState::Intact {
                return Err(ReplaceError::TransactionStateConflict);
            }
            let staged_identity =
                FileIdentity::capture(&staged).map_err(ReplaceError::StagingMetadata)?;
            require_intact(source, sidecar).map_err(ReplaceError::VerifyCurrentSource)?;
            let source_identity =
                FileIdentity::capture(source).map_err(ReplaceError::SourceMetadata)?;
            require_path_identity(directory, source_name, source, &source_identity)
                .map_err(ReplaceError::SourceChanged)?;
            directory
                .rename_no_replace(staging_name, backup_name)
                .map_err(ReplaceError::ReplacedButBackupMoveFailed)?;
            require_path_identity(directory, backup_name, &staged, &staged_identity)
                .map_err(ReplaceError::ReplacedButBackupIdentityFailed)?;
            directory
                .sync()
                .map_err(ReplaceError::ReplacedButBackupSyncFailed)?;
            Ok(ReplaceOutcome::RecoveredInterrupted)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn verify_exchange(
    directory: &SourceDirectory,
    exchanged: &mut ExchangedFiles<'_>,
    sidecar: &Sidecar,
) -> Result<(), ExchangeVerificationError> {
    require_path_identity(
        directory,
        exchanged.source_name,
        exchanged.repaired,
        exchanged.repaired_identity,
    )
    .map_err(ExchangeVerificationError::SourceIdentity)?;
    require_path_identity(
        directory,
        exchanged.staging_name,
        exchanged.damaged,
        exchanged.damaged_identity,
    )
    .map_err(ExchangeVerificationError::StagingIdentity)?;
    require_intact(exchanged.repaired, sidecar).map_err(ExchangeVerificationError::SourceContents)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
struct ExchangedFiles<'a> {
    source_name: &'a OsStr,
    staging_name: &'a OsStr,
    repaired: &'a mut File,
    damaged: &'a File,
    repaired_identity: &'a FileIdentity,
    damaged_identity: &'a FileIdentity,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn rollback_exchange(
    directory: &SourceDirectory,
    exchanged: &ExchangedFiles<'_>,
    verification: ExchangeVerificationError,
) -> ReplaceError {
    let identities_match = require_path_identity(
        directory,
        exchanged.source_name,
        exchanged.repaired,
        exchanged.repaired_identity,
    )
    .and_then(|()| {
        require_path_identity(
            directory,
            exchanged.staging_name,
            exchanged.damaged,
            exchanged.damaged_identity,
        )
    });
    let rollback_result = identities_match
        .and_then(|()| directory.exchange(exchanged.source_name, exchanged.staging_name))
        .and_then(|()| directory.sync());
    match rollback_result {
        Ok(()) => ReplaceError::ExchangeVerificationFailed(verification),
        Err(rollback) => ReplaceError::ExchangeVerificationAndRollbackFailed {
            verification,
            rollback,
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn verify_state(file: &mut File, sidecar: &Sidecar) -> Result<SourceState, verify::Error> {
    file.seek(SeekFrom::Start(0))
        .map_err(verify::Error::SourceSeek)?;
    verify::source_file(file, sidecar).map(|report| report.state)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn require_intact(file: &mut File, sidecar: &Sidecar) -> Result<(), IntactError> {
    file.seek(SeekFrom::Start(0))
        .map_err(verify::Error::SourceSeek)
        .map_err(IntactError::Verify)?;
    let report = verify::source_file(file, sidecar).map_err(IntactError::Verify)?;
    if report.state == SourceState::Intact
        && report.source_digest == SourceDigestState::Match
        && report.unavailable_data_chunks == 0
    {
        Ok(())
    } else {
        Err(IntactError::Mismatch {
            state: report.state,
            source_digest: report.source_digest,
            unavailable_data_chunks: report.unavailable_data_chunks,
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn ensure_absent(
    directory: &SourceDirectory,
    name: &OsStr,
    conflict: ReplaceError,
) -> Result<(), ReplaceError> {
    if directory
        .exists(name)
        .map_err(ReplaceError::InspectBackup)?
    {
        Err(conflict)
    } else {
        Ok(())
    }
}

fn suffixed_name(name: &OsStr, suffix: &str) -> OsString {
    let mut result = name.to_owned();
    result.push(suffix);
    result
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
struct SourceDirectory {
    directory: Dir,
    sync_file: File,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
impl SourceDirectory {
    fn open(path: &Path) -> io::Result<Self> {
        let sync_file = File::open(path)?;
        let directory = Dir::from_std_file(sync_file.try_clone()?);
        Ok(Self {
            directory,
            sync_file,
        })
    }

    fn open_locked_regular(&self, name: &OsStr, role: EntryRole) -> Result<File, EntryError> {
        let metadata = self
            .directory
            .symlink_metadata(name)
            .map_err(EntryError::Metadata)?;
        if metadata.file_type().is_symlink() {
            return Err(EntryError::Symlink(role));
        }
        if !metadata.is_file() {
            return Err(EntryError::NotRegular(role));
        }
        let mut options = DirectoryOpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let file = self
            .directory
            .open_with(name, &options)
            .map(cap_std::fs::File::into_std)
            .map_err(EntryError::Open)?;
        let identity = FileIdentity::capture(&file).map_err(EntryError::Metadata)?;
        if identity != FileIdentity::from_cap(&metadata) {
            return Err(EntryError::IdentityChanged(role));
        }
        file.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => EntryError::LockContended(role),
            TryLockError::Error(error) => EntryError::Lock(error),
        })?;
        Ok(file)
    }

    fn exists(&self, name: &OsStr) -> io::Result<bool> {
        match self.directory.symlink_metadata(name) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn exchange(&self, left: &OsStr, right: &OsStr) -> io::Result<()> {
        rustix::fs::renameat_with(
            &self.directory,
            left,
            &self.directory,
            right,
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .map_err(io::Error::from)
    }

    fn rename_no_replace(&self, source: &OsStr, destination: &OsStr) -> io::Result<()> {
        rustix::fs::renameat_with(
            &self.directory,
            source,
            &self.directory,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)
    }

    fn entry_identity(&self, name: &OsStr) -> io::Result<Option<FileIdentity>> {
        match self.directory.symlink_metadata(name) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                Ok(Some(FileIdentity::from_cap(&metadata)))
            }
            Ok(_) => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn sync(&self) -> io::Result<()> {
        self.sync_file.sync_all()
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn require_path_identity(
    directory: &SourceDirectory,
    name: &OsStr,
    file: &File,
    expected: &FileIdentity,
) -> io::Result<()> {
    let open_identity = FileIdentity::capture(file)?;
    let path_identity = directory.entry_identity(name)?;
    if open_identity == *expected && path_identity.as_ref() == Some(expected) {
        Ok(())
    } else {
        Err(io::Error::other("pathname or open-file identity changed"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryRole {
    Source,
    Staging,
}

#[derive(Debug)]
pub enum EntryError {
    Symlink(EntryRole),
    NotRegular(EntryRole),
    IdentityChanged(EntryRole),
    LockContended(EntryRole),
    Open(io::Error),
    Metadata(io::Error),
    Lock(io::Error),
}

impl fmt::Display for EntryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symlink(role) => write!(formatter, "{role:?} path is a symbolic link"),
            Self::NotRegular(role) => write!(formatter, "{role:?} path is not a regular file"),
            Self::IdentityChanged(role) => write!(formatter, "{role:?} path identity changed"),
            Self::LockContended(role) => write!(formatter, "another {role:?} operation is active"),
            Self::Open(error) => write!(formatter, "cannot open transaction entry: {error}"),
            Self::Metadata(error) => write!(formatter, "cannot inspect transaction entry: {error}"),
            Self::Lock(error) => write!(formatter, "cannot lock transaction entry: {error}"),
        }
    }
}

impl std::error::Error for EntryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open(error) | Self::Metadata(error) | Self::Lock(error) => Some(error),
            Self::Symlink(_)
            | Self::NotRegular(_)
            | Self::IdentityChanged(_)
            | Self::LockContended(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum ExchangeVerificationError {
    SourceIdentity(io::Error),
    StagingIdentity(io::Error),
    SourceContents(IntactError),
}

#[derive(Debug)]
pub enum IntactError {
    Verify(verify::Error),
    Mismatch {
        state: SourceState,
        source_digest: SourceDigestState,
        unavailable_data_chunks: u32,
    },
}

impl fmt::Display for IntactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verify(error) => write!(formatter, "complete verification failed: {error}"),
            Self::Mismatch {
                state,
                source_digest,
                unavailable_data_chunks,
            } => write!(
                formatter,
                "file is {state:?} with digest {source_digest:?} and {unavailable_data_chunks} unavailable chunks"
            ),
        }
    }
}

impl std::error::Error for IntactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Verify(error) => Some(error),
            Self::Mismatch { .. } => None,
        }
    }
}

impl fmt::Display for ExchangeVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceIdentity(error) => {
                write!(formatter, "repaired source identity is wrong: {error}")
            }
            Self::StagingIdentity(error) => {
                write!(formatter, "retained damaged identity is wrong: {error}")
            }
            Self::SourceContents(error) => {
                write!(formatter, "repaired source verification failed: {error}")
            }
        }
    }
}

impl std::error::Error for ExchangeVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SourceIdentity(error) | Self::StagingIdentity(error) => Some(error),
            Self::SourceContents(error) => Some(error),
        }
    }
}

#[derive(Debug)]
pub enum ReplaceError {
    AtomicExchangeUnsupported,
    SourceHasNoFileName,
    OverlappingPaths,
    SidecarIsSymlink,
    SidecarNotRegularFile,
    SidecarIdentityChanged,
    BackupConflict,
    TransactionStateConflict,
    Unrepairable,
    OpenDirectory(io::Error),
    Entry(EntryError),
    OpenSidecar(io::Error),
    SidecarMetadata(io::Error),
    ReadSidecar(SidecarReadError),
    SourceMetadata(io::Error),
    StagingMetadata(io::Error),
    InspectStaging(io::Error),
    InspectBackup(io::Error),
    VerifySource(verify::Error),
    VerifyCurrentSource(IntactError),
    VerifyStaging(IntactError),
    Prepare(PublishError),
    SourceChanged(io::Error),
    Exchange(io::Error),
    ExchangeVerificationFailed(ExchangeVerificationError),
    ExchangeVerificationAndRollbackFailed {
        verification: ExchangeVerificationError,
        rollback: io::Error,
    },
    ReplacedButExchangeSyncFailed(io::Error),
    ReplacedButBackupMoveFailed(io::Error),
    ReplacedButBackupIdentityFailed(io::Error),
    ReplacedButBackupSyncFailed(io::Error),
}

impl fmt::Display for ReplaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomicExchangeUnsupported => {
                formatter.write_str("atomic file exchange is unsupported on this platform")
            }
            Self::SourceHasNoFileName => formatter.write_str("source path has no file name"),
            Self::OverlappingPaths => {
                formatter.write_str("source, sidecar, staging, and backup paths must be distinct")
            }
            Self::SidecarIsSymlink => formatter.write_str("sidecar path is a symbolic link"),
            Self::SidecarNotRegularFile => formatter.write_str("sidecar is not a regular file"),
            Self::SidecarIdentityChanged => {
                formatter.write_str("sidecar path identity changed while opening")
            }
            Self::BackupConflict => {
                formatter.write_str("the deterministic damaged-source backup already exists")
            }
            Self::TransactionStateConflict => formatter.write_str(
                "staging and backup names do not describe a recoverable replacement state",
            ),
            Self::Unrepairable => {
                formatter.write_str("source damage exceeds available recovery capacity")
            }
            Self::OpenDirectory(error) => {
                write!(formatter, "cannot open source directory: {error}")
            }
            Self::Entry(error) => write!(formatter, "unsafe transaction entry: {error}"),
            Self::OpenSidecar(error) => write!(formatter, "cannot open sidecar: {error}"),
            Self::SidecarMetadata(error) => write!(formatter, "cannot inspect sidecar: {error}"),
            Self::ReadSidecar(error) => write!(formatter, "cannot authenticate sidecar: {error}"),
            Self::SourceMetadata(error) => write!(formatter, "cannot inspect source: {error}"),
            Self::StagingMetadata(error) => {
                write!(formatter, "cannot inspect staged repair: {error}")
            }
            Self::InspectStaging(error) => write!(
                formatter,
                "cannot inspect replacement staging name: {error}"
            ),
            Self::InspectBackup(error) => {
                write!(formatter, "cannot inspect damaged-source backup: {error}")
            }
            Self::VerifySource(error) => write!(formatter, "cannot verify source: {error}"),
            Self::VerifyCurrentSource(error) => {
                write!(formatter, "cannot reverify current source: {error}")
            }
            Self::VerifyStaging(error) => write!(formatter, "cannot verify staged repair: {error}"),
            Self::Prepare(error) => write!(formatter, "cannot prepare repaired source: {error}"),
            Self::SourceChanged(error) => {
                write!(formatter, "source changed before replacement: {error}")
            }
            Self::Exchange(error) => write!(
                formatter,
                "cannot atomically exchange source and repair: {error}"
            ),
            Self::ExchangeVerificationFailed(error) => write!(
                formatter,
                "atomic exchange failed verification and was rolled back: {error}"
            ),
            Self::ExchangeVerificationAndRollbackFailed {
                verification,
                rollback,
            } => write!(
                formatter,
                "atomic exchange failed verification ({verification}) and rollback failed: {rollback}"
            ),
            Self::ReplacedButExchangeSyncFailed(error) => write!(
                formatter,
                "source was replaced but exchange durability could not be confirmed: {error}"
            ),
            Self::ReplacedButBackupMoveFailed(error) => write!(
                formatter,
                "source was replaced but damaged-source backup publication failed: {error}"
            ),
            Self::ReplacedButBackupIdentityFailed(error) => write!(
                formatter,
                "source was replaced but damaged-source backup identity could not be confirmed: {error}"
            ),
            Self::ReplacedButBackupSyncFailed(error) => write!(
                formatter,
                "source and backup were published but directory durability could not be confirmed: {error}"
            ),
        }
    }
}

impl std::error::Error for ReplaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenDirectory(error)
            | Self::OpenSidecar(error)
            | Self::SidecarMetadata(error)
            | Self::SourceMetadata(error)
            | Self::StagingMetadata(error)
            | Self::InspectStaging(error)
            | Self::InspectBackup(error)
            | Self::SourceChanged(error)
            | Self::Exchange(error)
            | Self::ReplacedButExchangeSyncFailed(error)
            | Self::ReplacedButBackupMoveFailed(error)
            | Self::ReplacedButBackupIdentityFailed(error)
            | Self::ReplacedButBackupSyncFailed(error) => Some(error),
            Self::Entry(error) => Some(error),
            Self::ReadSidecar(error) => Some(error),
            Self::VerifySource(error) => Some(error),
            Self::VerifyCurrentSource(error) | Self::VerifyStaging(error) => Some(error),
            Self::Prepare(error) => Some(error),
            Self::ExchangeVerificationFailed(error)
            | Self::ExchangeVerificationAndRollbackFailed {
                verification: error,
                ..
            } => Some(error),
            Self::AtomicExchangeUnsupported
            | Self::SourceHasNoFileName
            | Self::OverlappingPaths
            | Self::SidecarIsSymlink
            | Self::SidecarNotRegularFile
            | Self::SidecarIdentityChanged
            | Self::BackupConflict
            | Self::TransactionStateConflict
            | Self::Unrepairable => None,
        }
    }
}

/// Returns the deterministic damaged-source backup path used by [`replace`].
#[must_use]
pub fn damaged_backup_path(source_path: impl AsRef<Path>) -> PathBuf {
    let source_path = source_path.as_ref();
    source_path.with_file_name(suffixed_name(
        source_path.file_name().unwrap_or_default(),
        BACKUP_SUFFIX,
    ))
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "android", target_vendor = "apple")
))]
mod tests {
    use super::*;
    use crate::create::{self, Options as CreateOptions};
    use crate::creator::Creator;
    use crate::geometry::{ChunkSize, MIN_CHUNK_SIZE, Redundancy};
    use crate::repair::Options as ReconstructionOptions;
    use crate::sidecar::ReadLimits;
    use crate::verify::LocateOptions;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const CHUNK_BYTES: usize = MIN_CHUNK_SIZE as usize;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bitrot-replace-test-{}-{serial}",
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

    fn original_bytes() -> Vec<u8> {
        [0x21, 0x76, 0xb9]
            .into_iter()
            .flat_map(|byte| vec![byte; CHUNK_BYTES])
            .collect()
    }

    fn write_sidecar(path: &Path, source: &[u8]) -> ReadLimits {
        let options = CreateOptions::new(
            ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap(),
            Redundancy::new(1, 2).unwrap(),
            1_024,
            Creator::new("bitrot-replace-test", env!("CARGO_PKG_VERSION")).unwrap(),
        );
        let sidecar = create::build(&mut Cursor::new(source), &options).unwrap();
        let limits = ReadLimits::for_canonical_metadata(&sidecar.metadata).unwrap();
        let mut encoded = Vec::new();
        sidecar.write_canonical(&mut encoded).unwrap();
        fs::write(path, encoded).unwrap();
        limits
    }

    fn options(limits: ReadLimits) -> PublishOptions {
        PublishOptions::new(
            limits,
            ReconstructionOptions::new(1_024),
            Some(LocateOptions::new(32)),
        )
    }

    fn setup() -> (
        TestDirectory,
        PathBuf,
        PathBuf,
        Vec<u8>,
        Vec<u8>,
        ReadLimits,
    ) {
        let directory = TestDirectory::new();
        let source_path = directory.join("movie.bin");
        let sidecar_path = directory.join("movie.bin.bitrot");
        let original = original_bytes();
        let mut damaged = original.clone();
        damaged[CHUNK_BYTES + 37] ^= 1;
        fs::write(&source_path, &damaged).unwrap();
        let limits = write_sidecar(&sidecar_path, &original);
        (
            directory,
            source_path,
            sidecar_path,
            original,
            damaged,
            limits,
        )
    }

    #[test]
    fn atomically_replaces_source_and_retains_damaged_inode() {
        let (_directory, source_path, sidecar_path, original, damaged, limits) = setup();
        let outcome = replace(&source_path, &sidecar_path, options(limits)).unwrap();

        let ReplaceOutcome::Replaced(summary) = outcome else {
            panic!("replacement did not complete");
        };
        assert!(summary.publication.is_some());
        assert_eq!(fs::read(&source_path).unwrap(), original);
        assert_eq!(
            fs::read(damaged_backup_path(&source_path)).unwrap(),
            damaged
        );
        assert!(
            !source_path
                .with_file_name("movie.bin.bitrot-replacement")
                .exists()
        );
    }

    #[test]
    fn refuses_to_overwrite_existing_backup() {
        let (_directory, source_path, sidecar_path, _original, damaged, limits) = setup();
        let backup_path = damaged_backup_path(&source_path);
        fs::write(&backup_path, b"older evidence").unwrap();

        assert!(matches!(
            replace(&source_path, &sidecar_path, options(limits)),
            Err(ReplaceError::BackupConflict)
        ));
        assert_eq!(fs::read(source_path).unwrap(), damaged);
        assert_eq!(fs::read(backup_path).unwrap(), b"older evidence");
    }

    #[test]
    fn reuses_a_verified_prepared_repair() {
        let (_directory, source_path, sidecar_path, original, damaged, limits) = setup();
        let staging_path = source_path.with_file_name("movie.bin.bitrot-replacement");
        publish(&source_path, &sidecar_path, &staging_path, options(limits)).unwrap();

        let outcome = replace(&source_path, &sidecar_path, options(limits)).unwrap();
        assert_eq!(
            outcome,
            ReplaceOutcome::Replaced(ReplaceSummary { publication: None })
        );
        assert_eq!(fs::read(&source_path).unwrap(), original);
        assert_eq!(
            fs::read(damaged_backup_path(&source_path)).unwrap(),
            damaged
        );
        assert!(!staging_path.exists());
    }

    #[test]
    fn finishes_an_interrupted_post_exchange_transaction() {
        let (directory, source_path, sidecar_path, original, damaged, limits) = setup();
        let source_name = source_path.file_name().unwrap();
        let staging_name = suffixed_name(source_name, STAGING_SUFFIX);
        let staging_path = directory.0.join(&staging_name);
        publish(&source_path, &sidecar_path, &staging_path, options(limits)).unwrap();
        let anchored = SourceDirectory::open(&directory.0).unwrap();
        anchored.exchange(source_name, &staging_name).unwrap();
        anchored.sync().unwrap();

        let outcome = replace(&source_path, &sidecar_path, options(limits)).unwrap();
        assert_eq!(outcome, ReplaceOutcome::RecoveredInterrupted);
        assert_eq!(fs::read(&source_path).unwrap(), original);
        assert_eq!(
            fs::read(damaged_backup_path(&source_path)).unwrap(),
            damaged
        );
        assert!(!staging_path.exists());
    }

    #[test]
    fn intact_source_is_an_idempotent_success() {
        let (_directory, source_path, sidecar_path, original, _damaged, limits) = setup();
        fs::write(&source_path, &original).unwrap();

        assert_eq!(
            replace(&source_path, &sidecar_path, options(limits)).unwrap(),
            ReplaceOutcome::AlreadyCurrent
        );
        assert_eq!(fs::read(source_path).unwrap(), original);
    }

    #[test]
    fn refuses_a_concurrent_replacer_holding_the_source_lock() {
        let (directory, source_path, sidecar_path, _original, damaged, limits) = setup();
        let anchored = SourceDirectory::open(&directory.0).unwrap();
        let locked = anchored
            .open_locked_regular(source_path.file_name().unwrap(), EntryRole::Source)
            .unwrap();

        assert!(matches!(
            replace(&source_path, &sidecar_path, options(limits)),
            Err(ReplaceError::Entry(EntryError::LockContended(
                EntryRole::Source
            )))
        ));
        assert_eq!(fs::read(source_path).unwrap(), damaged);
        drop(locked);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symbolic_link_source() {
        use std::os::unix::fs::symlink;

        let (directory, source_path, sidecar_path, _original, damaged, limits) = setup();
        let source_link = directory.join("source-link");
        symlink(&source_path, &source_link).unwrap();

        assert!(matches!(
            replace(source_link, sidecar_path, options(limits)),
            Err(ReplaceError::Entry(EntryError::Symlink(EntryRole::Source)))
        ));
        assert_eq!(fs::read(source_path).unwrap(), damaged);
    }
}
