//! Safe publication of a repaired source under a new filesystem name.

use super::{Error as ReconstructionError, Options as ReconstructionOptions, Summary};
use crate::sidecar::{ReadError as SidecarReadError, ReadLimits, Sidecar};
use crate::verify::{self, LocateOptions, LocationSummary, SourceDigestState, SourceState};
#[cfg(windows)]
use cap_std::ambient_authority;
#[cfg(any(unix, windows))]
use cap_std::fs::MetadataExt as CapMetadataExt;
#[cfg(unix)]
use cap_std::fs::OpenOptionsExt as CapOpenOptionsExt;
#[cfg(any(unix, windows))]
use cap_std::fs::{Dir, OpenOptions as DirectoryOpenOptions};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Seek, SeekFrom};
use std::path::Path;
#[cfg(not(any(unix, windows)))]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
const STALE_TEMPORARY_AGE: Duration = Duration::from_hours(24);
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

/// Resource bounds and choices for one filesystem repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishOptions {
    pub sidecar_limits: ReadLimits,
    pub reconstruction: ReconstructionOptions,
    pub locate_displaced: Option<LocateOptions>,
}

impl PublishOptions {
    #[must_use]
    pub const fn new(
        sidecar_limits: ReadLimits,
        reconstruction: ReconstructionOptions,
        locate_displaced: Option<LocateOptions>,
    ) -> Self {
        Self {
            sidecar_limits,
            reconstruction,
            locate_displaced,
        }
    }
}

/// Work completed while producing a newly published repaired file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishSummary {
    pub reconstruction: Summary,
    pub location: Option<LocationSummary>,
    pub sidecar_damage_events: u32,
}

/// Successful outcome of repair-to-new-file publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishOutcome {
    /// This invocation reconstructed and published the destination.
    Published(PublishSummary),
    /// A concurrently or previously published destination already matches.
    AlreadyCurrent,
}

/// Repairs `source_path` into a new, durably verified `destination_path`.
///
/// The source and sidecar must be regular files rather than symbolic links.
/// Reconstruction occurs in a uniquely named, locked temporary file in the
/// destination directory. The completed file is synchronized, verified again,
/// and installed using an atomic no-clobber hard link. The containing directory
/// is then synchronized. The damaged source is never modified or removed.
///
/// An existing destination is accepted only when it is a complete intact file
/// for the authenticated sidecar; any other object is preserved as a conflict.
/// This also makes concurrent publishers converge safely on one output.
///
/// # Errors
///
/// Returns an error for unsafe or overlapping paths, invalid or insufficient
/// sidecar data, an intact or unrepairable source, reconstruction failure,
/// conflicting output, temporary-file failure, or publication/durability
/// failure. An error variant explicitly states when publication happened but
/// cleanup or durability confirmation subsequently failed.
pub fn publish(
    source_path: impl AsRef<Path>,
    sidecar_path: impl AsRef<Path>,
    destination_path: impl AsRef<Path>,
    options: PublishOptions,
) -> Result<PublishOutcome, PublishError> {
    let source_path = source_path.as_ref();
    let sidecar_path = sidecar_path.as_ref();
    let destination_path = destination_path.as_ref();
    if source_path == sidecar_path
        || source_path == destination_path
        || sidecar_path == destination_path
    {
        return Err(PublishError::OverlappingPaths);
    }

    let sidecar_file = open_regular_no_follow(sidecar_path, PathRole::Sidecar)?;
    let sidecar_read =
        Sidecar::read(sidecar_file, options.sidecar_limits).map_err(PublishError::ReadSidecar)?;
    let sidecar_damage_events = u32::try_from(sidecar_read.damage.len())
        .map_err(|_| PublishError::DamageCountUnrepresentable)?;
    let sidecar = sidecar_read.sidecar;

    let mut source = open_regular_no_follow(source_path, PathRole::Source)?;
    let source_identity = FileIdentity::capture(&source).map_err(PublishError::SourceMetadata)?;
    let parent = destination_parent(destination_path);
    let directory = DestinationDirectory::open(parent).map_err(PublishError::OpenDirectory)?;
    let destination_name = destination_path
        .file_name()
        .ok_or(PublishError::DestinationHasNoFileName)?;
    cleanup_stale_temporaries(&directory, destination_name)
        .map_err(PublishError::CleanupTemporaries)?;

    match inspect_destination(&directory, destination_name, &sidecar, &source_identity)? {
        DestinationState::Absent => {}
        DestinationState::Current => return Ok(PublishOutcome::AlreadyCurrent),
        DestinationState::Conflict => return Err(PublishError::ExistingConflict),
        DestinationState::SourceAlias => return Err(PublishError::OverlappingPaths),
    }

    let mut report =
        verify::source_file(&mut source, &sidecar).map_err(PublishError::VerifySource)?;
    let location = if let Some(locate_options) = options.locate_displaced {
        if report.unavailable_data_chunks == 0 {
            None
        } else {
            Some(
                verify::locate_displaced_file(&mut source, &sidecar, &mut report, locate_options)
                    .map_err(PublishError::LocateSource)?,
            )
        }
    } else {
        None
    };
    match report.state {
        SourceState::Intact => return Err(PublishError::RepairNotNeeded),
        SourceState::Repairable => {}
        SourceState::Unrepairable => return Err(PublishError::Unrepairable),
    }

    let mut temporary = TemporaryFile::create(&directory, destination_name)?;
    let reconstruction = super::reconstruct(
        &mut source,
        &mut temporary.file,
        &sidecar,
        &report,
        options.reconstruction,
    )
    .map_err(PublishError::Reconstruct)?;
    temporary
        .file
        .sync_all()
        .map_err(PublishError::SyncTemporary)?;
    verify_intact(&mut temporary.file, &sidecar).map_err(PublishError::VerifyTemporary)?;
    temporary.verify_path_identity()?;

    match directory.hard_link(temporary.name(), destination_name) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return resolve_publication_race(
                &mut temporary,
                &directory,
                destination_name,
                &sidecar,
                &source_identity,
            );
        }
        Err(error) => return Err(PublishError::Publish(error)),
    }

    if let Err(error) = verify_published(&directory, destination_name, &temporary.file, &sidecar) {
        return Err(rollback_failed_publication(
            &directory,
            destination_name,
            &temporary.file,
            error,
        ));
    }
    finish_publication(&mut temporary, &directory)?;

    Ok(PublishOutcome::Published(PublishSummary {
        reconstruction,
        location,
        sidecar_damage_events,
    }))
}

fn verify_intact(file: &mut File, sidecar: &Sidecar) -> Result<(), OutputVerificationError> {
    file.seek(SeekFrom::Start(0))
        .map_err(verify::Error::SourceSeek)
        .map_err(OutputVerificationError::Verify)?;
    let report = verify::source_file(file, sidecar).map_err(OutputVerificationError::Verify)?;
    if report.state == SourceState::Intact
        && report.source_digest == SourceDigestState::Match
        && report.unavailable_data_chunks == 0
    {
        Ok(())
    } else {
        Err(OutputVerificationError::Mismatch {
            state: report.state,
            source_digest: report.source_digest,
            unavailable_data_chunks: report.unavailable_data_chunks,
        })
    }
}

fn verify_published(
    directory: &DestinationDirectory,
    destination: &OsStr,
    temporary: &File,
    sidecar: &Sidecar,
) -> Result<(), PublishedVerificationError> {
    let mut published = directory
        .open_read_no_follow(destination)
        .map_err(PublishedVerificationError::Open)?;
    let expected =
        FileIdentity::capture(temporary).map_err(PublishedVerificationError::Metadata)?;
    let actual = FileIdentity::capture(&published).map_err(PublishedVerificationError::Metadata)?;
    if expected != actual {
        return Err(PublishedVerificationError::IdentityChanged);
    }
    verify_intact(&mut published, sidecar).map_err(PublishedVerificationError::Verify)
}

fn rollback_failed_publication(
    directory: &DestinationDirectory,
    destination: &OsStr,
    temporary: &File,
    verification: PublishedVerificationError,
) -> PublishError {
    let rollback = path_names_file(directory, destination, temporary).and_then(|same| {
        if same {
            directory
                .remove_file(destination)
                .and_then(|()| directory.sync())
        } else {
            Err(io::Error::other(
                "published destination changed before rollback",
            ))
        }
    });
    match rollback {
        Ok(()) => PublishError::PublishedVerificationFailed(verification),
        Err(rollback) => PublishError::PublishedVerificationAndRollbackFailed {
            verification,
            rollback,
        },
    }
}

fn resolve_publication_race(
    temporary: &mut TemporaryFile<'_>,
    directory: &DestinationDirectory,
    destination: &OsStr,
    sidecar: &Sidecar,
    source_identity: &FileIdentity,
) -> Result<PublishOutcome, PublishError> {
    match inspect_destination(directory, destination, sidecar, source_identity)? {
        DestinationState::Current => {
            finish_publication(temporary, directory)?;
            Ok(PublishOutcome::AlreadyCurrent)
        }
        DestinationState::SourceAlias => Err(PublishError::OverlappingPaths),
        DestinationState::Absent | DestinationState::Conflict => {
            Err(PublishError::ExistingConflict)
        }
    }
}

fn finish_publication(
    temporary: &mut TemporaryFile<'_>,
    directory: &DestinationDirectory,
) -> Result<(), PublishError> {
    let cleanup_error = temporary.remove().err();
    let sync_error = directory.sync().err();
    match (cleanup_error, sync_error) {
        (None, None) => Ok(()),
        (Some(error), None) => Err(PublishError::PublishedButCleanupFailed(error)),
        (None, Some(error)) => Err(PublishError::PublishedButSyncFailed(error)),
        (Some(cleanup), Some(sync)) => {
            Err(PublishError::PublishedButCleanupAndSyncFailed { cleanup, sync })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationState {
    Absent,
    Current,
    Conflict,
    SourceAlias,
}

fn inspect_destination(
    directory: &DestinationDirectory,
    destination: &OsStr,
    sidecar: &Sidecar,
    source_identity: &FileIdentity,
) -> Result<DestinationState, PublishError> {
    let metadata = match directory.symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DestinationState::Absent);
        }
        Err(error) => return Err(PublishError::InspectDestination(error)),
    };
    if metadata.is_symlink() || !metadata.is_file() {
        return Ok(DestinationState::Conflict);
    }
    if source_identity.same_entry(&metadata) {
        return Ok(DestinationState::SourceAlias);
    }
    let mut file = match directory.open_read_no_follow(destination) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DestinationState::Absent);
        }
        Err(error) => return Err(PublishError::InspectDestination(error)),
    };
    let open_identity = FileIdentity::capture(&file).map_err(PublishError::InspectDestination)?;
    if !open_identity.same_entry(&metadata) {
        return Ok(DestinationState::Conflict);
    }
    match verify_intact(&mut file, sidecar) {
        Ok(()) => Ok(DestinationState::Current),
        Err(_) => Ok(DestinationState::Conflict),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
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

impl FileIdentity {
    fn capture(file: &File) -> io::Result<Self> {
        file.metadata().map(|metadata| Self::from_std(&metadata))
    }

    fn from_std(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
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

    fn same_entry(&self, metadata: &EntryMetadata) -> bool {
        #[cfg(unix)]
        {
            self.device == metadata.device && self.inode == metadata.inode
        }
        #[cfg(windows)]
        {
            same_windows_file_id(
                self.volume_serial_number,
                self.file_index,
                metadata.volume_serial_number,
                metadata.file_index,
            )
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.len == metadata.len && self.modified == metadata.modified
        }
    }
}

fn open_regular_no_follow(path: &Path, role: PathRole) -> Result<File, PublishError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| role.metadata_error(error))?;
    if path_metadata.file_type().is_symlink() {
        return Err(role.symlink_error());
    }
    if !path_metadata.is_file() {
        return Err(role.not_regular_error());
    }
    let file = open_read_no_follow(path).map_err(|error| role.open_error(error))?;
    let open_metadata = file
        .metadata()
        .map_err(|error| role.metadata_error(error))?;
    if FileIdentity::from_std(&path_metadata) != FileIdentity::from_std(&open_metadata) {
        return Err(role.identity_error());
    }
    Ok(file)
}

fn open_read_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[derive(Clone, Copy)]
enum PathRole {
    Source,
    Sidecar,
}

impl PathRole {
    const fn symlink_error(self) -> PublishError {
        match self {
            Self::Source => PublishError::SourceIsSymlink,
            Self::Sidecar => PublishError::SidecarIsSymlink,
        }
    }

    const fn not_regular_error(self) -> PublishError {
        match self {
            Self::Source => PublishError::SourceNotRegularFile,
            Self::Sidecar => PublishError::SidecarNotRegularFile,
        }
    }

    const fn identity_error(self) -> PublishError {
        match self {
            Self::Source => PublishError::SourceIdentityChanged,
            Self::Sidecar => PublishError::SidecarIdentityChanged,
        }
    }

    fn open_error(self, error: io::Error) -> PublishError {
        match self {
            Self::Source => PublishError::OpenSource(error),
            Self::Sidecar => PublishError::OpenSidecar(error),
        }
    }

    fn metadata_error(self, error: io::Error) -> PublishError {
        match self {
            Self::Source => PublishError::SourceMetadata(error),
            Self::Sidecar => PublishError::SidecarMetadata(error),
        }
    }
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
    fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        let (directory, sync_file) = {
            let sync_file = File::open(path)?;
            let directory = Dir::from_std_file(sync_file.try_clone()?);
            (directory, sync_file)
        };
        #[cfg(windows)]
        let directory = Dir::open_ambient_dir(path, ambient_authority())?;
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

    fn open_read_no_follow(&self, name: &OsStr) -> io::Result<File> {
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

    fn create_new(&self, name: &OsStr) -> io::Result<File> {
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

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    fn open_read_write_no_follow(&self, name: &OsStr) -> io::Result<File> {
        let mut options = DirectoryOpenOptions::new();
        options.read(true).write(true);
        set_no_follow(&mut options);
        self.directory
            .open_with(name, &options)
            .map(cap_std::fs::File::into_std)
    }

    fn symlink_metadata(&self, name: &OsStr) -> io::Result<EntryMetadata> {
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

    fn hard_link(&self, source: &OsStr, destination: &OsStr) -> io::Result<()> {
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

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
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

    fn remove_file(&self, name: &OsStr) -> io::Result<()> {
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
    #[cfg(not(any(unix, windows)))]
    len: u64,
    #[cfg(not(windows))]
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

impl EntryMetadata {
    #[cfg(any(unix, windows))]
    fn from_cap(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            is_file: metadata.is_file(),
            is_symlink: metadata.file_type().is_symlink(),
            #[cfg(not(unix))]
            len: metadata.len(),
            #[cfg(not(windows))]
            modified: metadata
                .modified()
                .ok()
                .map(cap_std::time::SystemTime::into_std),
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

#[cfg(any(windows, test))]
const fn same_windows_file_id(
    left_volume: Option<u32>,
    left_index: Option<u64>,
    right_volume: Option<u32>,
    right_index: Option<u64>,
) -> bool {
    matches!(
        (left_volume, left_index, right_volume, right_index),
        (Some(left_volume), Some(left_index), Some(right_volume), Some(right_index))
            if left_volume == right_volume && left_index == right_index
    )
}

#[cfg(any(unix, windows))]
fn set_no_follow(options: &mut DirectoryOpenOptions) {
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    #[cfg(not(unix))]
    let _ = options;
}

struct TemporaryFile<'directory> {
    directory: &'directory DestinationDirectory,
    name: OsString,
    file: File,
    armed: bool,
}

impl<'directory> TemporaryFile<'directory> {
    fn create(
        directory: &'directory DestinationDirectory,
        destination: &OsStr,
    ) -> Result<Self, PublishError> {
        let epoch_nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0_u32..128 {
            let nonce = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            let name = temporary_name(destination, epoch_nonce, nonce);
            match directory.create_new(&name) {
                Ok(file) => {
                    file.try_lock().map_err(|error| match error {
                        TryLockError::Error(error) => PublishError::LockTemporary(error),
                        TryLockError::WouldBlock => PublishError::TemporaryLockContended,
                    })?;
                    return Ok(Self {
                        directory,
                        name,
                        file,
                        armed: true,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(PublishError::CreateTemporary(error)),
            }
        }
        Err(PublishError::TemporaryNameExhausted)
    }

    fn name(&self) -> &OsStr {
        &self.name
    }

    fn verify_path_identity(&self) -> Result<(), PublishError> {
        if path_names_file(self.directory, &self.name, &self.file)
            .map_err(PublishError::TemporaryMetadata)?
        {
            Ok(())
        } else {
            Err(PublishError::TemporaryIdentityChanged)
        }
    }

    fn remove(&mut self) -> io::Result<()> {
        if !path_names_file(self.directory, &self.name, &self.file)? {
            self.armed = false;
            return Err(io::Error::other(
                "temporary path no longer names the file created by this process",
            ));
        }
        self.directory.remove_file(&self.name)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for TemporaryFile<'_> {
    fn drop(&mut self) {
        if self.armed && path_names_file(self.directory, &self.name, &self.file).unwrap_or(false) {
            let _ = self.directory.remove_file(&self.name);
        }
    }
}

fn temporary_name(destination: &OsStr, epoch_nonce: u128, nonce: u64) -> OsString {
    let mut name = OsString::from(destination);
    name.push(format!(
        ".bitrot-partial-{}-repair-{epoch_nonce:x}-{nonce:x}",
        std::process::id()
    ));
    name
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn cleanup_stale_temporaries(
    directory: &DestinationDirectory,
    destination: &OsStr,
) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;

    let now = SystemTime::now();
    let mut removed = false;
    for entry in directory.directory.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        if !is_repair_temporary_name_for(name.as_bytes(), destination.as_bytes()) {
            continue;
        }
        let metadata = directory.symlink_metadata(&name)?;
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
            Err(error) => return Err(error),
        };
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => continue,
            Err(TryLockError::Error(error)) => return Err(error),
        }
        removed |= quarantine_and_remove_stale(directory, destination, &name, &file)?;
    }
    if removed {
        directory.sync()?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn quarantine_and_remove_stale(
    directory: &DestinationDirectory,
    destination: &OsStr,
    original_name: &OsStr,
    opened_file: &File,
) -> io::Result<bool> {
    let epoch_nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let quarantine_name = loop {
        let nonce = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let candidate = temporary_name(destination, epoch_nonce, nonce);
        match directory.rename_no_replace(original_name, &candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    };

    if path_names_file(directory, &quarantine_name, opened_file)? {
        directory.remove_file(&quarantine_name)?;
        return Ok(true);
    }

    match directory.rename_no_replace(&quarantine_name, original_name) {
        Ok(()) => Err(io::Error::other(
            "stale repair pathname changed during cleanup; replacement was restored",
        )),
        Err(restore_error) => Err(io::Error::new(
            restore_error.kind(),
            format!(
                "stale repair pathname changed during cleanup; replacement remains at {}: {restore_error}",
                quarantine_name.display()
            ),
        )),
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn is_repair_temporary_name_for(candidate: &[u8], destination: &[u8]) -> bool {
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
        && kind == b"repair"
        && is_lower_hex(epoch)
        && is_lower_hex(nonce)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn is_lower_hex(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn cleanup_stale_temporaries(
    _directory: &DestinationDirectory,
    _destination: &OsStr,
) -> io::Result<()> {
    Ok(())
}

fn path_names_file(
    directory: &DestinationDirectory,
    name: &OsStr,
    file: &File,
) -> io::Result<bool> {
    let open_identity = FileIdentity::capture(file)?;
    let metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(metadata.is_file() && open_identity.same_entry(&metadata))
}

#[derive(Debug)]
pub enum PublishedVerificationError {
    Open(io::Error),
    Metadata(io::Error),
    IdentityChanged,
    Verify(OutputVerificationError),
}

impl fmt::Display for PublishedVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(error) => write!(formatter, "cannot reopen published repair: {error}"),
            Self::Metadata(error) => {
                write!(formatter, "cannot inspect published repair: {error}")
            }
            Self::IdentityChanged => {
                formatter.write_str("published pathname does not identify the repaired inode")
            }
            Self::Verify(error) => write!(formatter, "published repair is invalid: {error}"),
        }
    }
}

/// A repaired file could not be completely verified as the original source.
#[derive(Debug)]
pub enum OutputVerificationError {
    Verify(verify::Error),
    Mismatch {
        state: SourceState,
        source_digest: SourceDigestState,
        unavailable_data_chunks: u32,
    },
}

impl fmt::Display for OutputVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verify(error) => write!(formatter, "complete verification failed: {error}"),
            Self::Mismatch {
                state,
                source_digest,
                unavailable_data_chunks,
            } => write!(
                formatter,
                "output is {state:?} with digest {source_digest:?} and {unavailable_data_chunks} unavailable chunks"
            ),
        }
    }
}

impl std::error::Error for OutputVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Verify(error) => Some(error),
            Self::Mismatch { .. } => None,
        }
    }
}

impl std::error::Error for PublishedVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open(error) | Self::Metadata(error) => Some(error),
            Self::Verify(error) => Some(error),
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
    SidecarIsSymlink,
    SidecarNotRegularFile,
    SidecarIdentityChanged,
    DestinationHasNoFileName,
    ExistingConflict,
    RepairNotNeeded,
    Unrepairable,
    DamageCountUnrepresentable,
    TemporaryNameExhausted,
    TemporaryLockContended,
    TemporaryIdentityChanged,
    OpenSource(io::Error),
    SourceMetadata(io::Error),
    OpenSidecar(io::Error),
    SidecarMetadata(io::Error),
    ReadSidecar(SidecarReadError),
    OpenDirectory(io::Error),
    InspectDestination(io::Error),
    VerifySource(verify::Error),
    LocateSource(verify::Error),
    CreateTemporary(io::Error),
    LockTemporary(io::Error),
    CleanupTemporaries(io::Error),
    Reconstruct(ReconstructionError),
    SyncTemporary(io::Error),
    VerifyTemporary(OutputVerificationError),
    TemporaryMetadata(io::Error),
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
            Self::OverlappingPaths => {
                formatter.write_str("source, sidecar, and repaired-output paths must be distinct")
            }
            Self::SourceIsSymlink => formatter.write_str("source path is a symbolic link"),
            Self::SourceNotRegularFile => formatter.write_str("source is not a regular file"),
            Self::SourceIdentityChanged => {
                formatter.write_str("source path identity changed while opening")
            }
            Self::SidecarIsSymlink => formatter.write_str("sidecar path is a symbolic link"),
            Self::SidecarNotRegularFile => formatter.write_str("sidecar is not a regular file"),
            Self::SidecarIdentityChanged => {
                formatter.write_str("sidecar path identity changed while opening")
            }
            Self::DestinationHasNoFileName => {
                formatter.write_str("repaired output has no file name")
            }
            Self::ExistingConflict => formatter
                .write_str("a conflicting object already exists at the repaired-output path"),
            Self::RepairNotNeeded => formatter.write_str("source is intact; repair is not needed"),
            Self::Unrepairable => {
                formatter.write_str("source damage exceeds available recovery capacity")
            }
            Self::DamageCountUnrepresentable => {
                formatter.write_str("sidecar damage-event count is not representable")
            }
            Self::TemporaryNameExhausted => {
                formatter.write_str("cannot allocate a unique temporary repair name")
            }
            Self::TemporaryLockContended => {
                formatter.write_str("newly created temporary repair was unexpectedly locked")
            }
            Self::TemporaryIdentityChanged => {
                formatter.write_str("temporary repair pathname changed before publication")
            }
            Self::OpenSource(error) => write!(formatter, "cannot open source: {error}"),
            Self::SourceMetadata(error) => write!(formatter, "cannot inspect source: {error}"),
            Self::OpenSidecar(error) => write!(formatter, "cannot open sidecar: {error}"),
            Self::SidecarMetadata(error) => write!(formatter, "cannot inspect sidecar: {error}"),
            Self::ReadSidecar(error) => write!(formatter, "cannot authenticate sidecar: {error}"),
            Self::OpenDirectory(error) => {
                write!(formatter, "cannot open repaired-output directory: {error}")
            }
            Self::InspectDestination(error) => {
                write!(formatter, "cannot inspect repaired output: {error}")
            }
            Self::VerifySource(error) => write!(formatter, "cannot verify source: {error}"),
            Self::LocateSource(error) => {
                write!(formatter, "cannot locate displaced source chunks: {error}")
            }
            Self::CreateTemporary(error) => {
                write!(formatter, "cannot create temporary repair: {error}")
            }
            Self::LockTemporary(error) => {
                write!(formatter, "cannot lock temporary repair: {error}")
            }
            Self::CleanupTemporaries(error) => {
                write!(formatter, "cannot clean stale temporary repairs: {error}")
            }
            Self::Reconstruct(error) => write!(formatter, "cannot reconstruct source: {error}"),
            Self::SyncTemporary(error) => {
                write!(formatter, "cannot synchronize temporary repair: {error}")
            }
            Self::VerifyTemporary(error) => write!(
                formatter,
                "synchronized temporary repair is invalid: {error}"
            ),
            Self::TemporaryMetadata(error) => {
                write!(formatter, "cannot inspect temporary repair: {error}")
            }
            Self::Publish(error) => write!(formatter, "cannot publish repaired output: {error}"),
            Self::PublishedVerificationFailed(error) => write!(
                formatter,
                "published repair failed verification and was rolled back: {error}"
            ),
            Self::PublishedVerificationAndRollbackFailed {
                verification,
                rollback,
            } => write!(
                formatter,
                "published repair failed verification ({verification}) and could not be rolled back: {rollback}"
            ),
            Self::PublishedButCleanupFailed(error) => write!(
                formatter,
                "repair was published but its temporary link could not be removed: {error}"
            ),
            Self::PublishedButSyncFailed(error) => write!(
                formatter,
                "repair was published but its destination directory could not be synchronized: {error}"
            ),
            Self::PublishedButCleanupAndSyncFailed { cleanup, sync } => write!(
                formatter,
                "repair was published but temporary cleanup failed ({cleanup}) and destination-directory synchronization failed ({sync})"
            ),
        }
    }
}

impl std::error::Error for PublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenSource(error)
            | Self::SourceMetadata(error)
            | Self::OpenSidecar(error)
            | Self::SidecarMetadata(error)
            | Self::OpenDirectory(error)
            | Self::InspectDestination(error)
            | Self::CreateTemporary(error)
            | Self::LockTemporary(error)
            | Self::CleanupTemporaries(error)
            | Self::SyncTemporary(error)
            | Self::TemporaryMetadata(error)
            | Self::Publish(error)
            | Self::PublishedButCleanupFailed(error)
            | Self::PublishedButSyncFailed(error) => Some(error),
            Self::PublishedButCleanupAndSyncFailed { cleanup, .. } => Some(cleanup),
            Self::PublishedVerificationAndRollbackFailed { verification, .. } => Some(verification),
            Self::ReadSidecar(error) => Some(error),
            Self::VerifySource(error) | Self::LocateSource(error) => Some(error),
            Self::VerifyTemporary(error) => Some(error),
            Self::Reconstruct(error) => Some(error),
            Self::PublishedVerificationFailed(error) => Some(error),
            Self::OverlappingPaths
            | Self::SourceIsSymlink
            | Self::SourceNotRegularFile
            | Self::SourceIdentityChanged
            | Self::SidecarIsSymlink
            | Self::SidecarNotRegularFile
            | Self::SidecarIdentityChanged
            | Self::DestinationHasNoFileName
            | Self::ExistingConflict
            | Self::RepairNotNeeded
            | Self::Unrepairable
            | Self::DamageCountUnrepresentable
            | Self::TemporaryNameExhausted
            | Self::TemporaryLockContended
            | Self::TemporaryIdentityChanged => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{self, Options as CreateOptions};
    use crate::creator::Creator;
    use crate::geometry::{ChunkSize, MIN_CHUNK_SIZE, Redundancy};
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const CHUNK_BYTES: usize = MIN_CHUNK_SIZE as usize;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bitrot-repair-publish-test-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn entry_count(&self) -> usize {
            fs::read_dir(&self.0).unwrap().count()
        }

        fn has_partial(&self) -> bool {
            fs::read_dir(&self.0).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".bitrot-partial-")
            })
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn source_bytes() -> Vec<u8> {
        [0x19, 0x72, 0xc4]
            .into_iter()
            .flat_map(|value| vec![value; CHUNK_BYTES])
            .collect()
    }

    #[test]
    fn windows_identity_requires_both_available_identifiers() {
        assert!(same_windows_file_id(Some(7), Some(11), Some(7), Some(11)));
        assert!(!same_windows_file_id(None, Some(11), None, Some(11)));
        assert!(!same_windows_file_id(Some(7), None, Some(7), None));
        assert!(!same_windows_file_id(Some(7), Some(11), Some(8), Some(11)));
    }

    fn create_options() -> CreateOptions {
        CreateOptions::new(
            ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap(),
            Redundancy::new(1, 2).unwrap(),
            1_024,
            Creator::new("bitrot-test", env!("CARGO_PKG_VERSION")).unwrap(),
        )
    }

    fn write_sidecar(path: &Path, source: &[u8]) -> ReadLimits {
        let sidecar = create::build(&mut Cursor::new(source), &create_options()).unwrap();
        let limits = ReadLimits::for_canonical_metadata(&sidecar.metadata).unwrap();
        let mut encoded = Vec::new();
        sidecar.write_canonical(&mut encoded).unwrap();
        fs::write(path, encoded).unwrap();
        limits
    }

    fn publish_options(limits: ReadLimits, locate: bool) -> PublishOptions {
        PublishOptions::new(
            limits,
            ReconstructionOptions::new(1_024),
            locate.then(|| LocateOptions::new(32)),
        )
    }

    #[test]
    fn publishes_verified_repair_without_modifying_damaged_source() {
        let directory = TestDirectory::new();
        let source_path = directory.join("movie.bin");
        let sidecar_path = directory.join("movie.bin.bitrot");
        let destination_path = directory.join("movie.bin.repaired");
        let original = source_bytes();
        let mut damaged = original.clone();
        damaged[31] ^= 1;
        fs::write(&source_path, &damaged).unwrap();
        let limits = write_sidecar(&sidecar_path, &original);

        let outcome = publish(
            &source_path,
            &sidecar_path,
            &destination_path,
            publish_options(limits, false),
        )
        .unwrap();

        let PublishOutcome::Published(summary) = outcome else {
            panic!("first publisher did not publish");
        };
        assert_eq!(summary.reconstruction.bytes_written, original.len() as u64);
        assert_eq!(summary.reconstruction.reconstructed_data_chunks, 1);
        assert_eq!(summary.sidecar_damage_events, 0);
        assert_eq!(fs::read(&destination_path).unwrap(), original);
        assert_eq!(fs::read(&source_path).unwrap(), damaged);
        assert!(!directory.has_partial());
        assert_eq!(directory.entry_count(), 3);
    }

    #[test]
    fn publishes_with_bounded_recoverable_sidecar_damage() {
        let directory = TestDirectory::new();
        let source_path = directory.join("movie.bin");
        let sidecar_path = directory.join("movie.bin.bitrot");
        let destination_path = directory.join("movie.bin.repaired");
        let original = source_bytes();
        let mut damaged = original.clone();
        damaged[37] ^= 1;
        fs::write(&source_path, damaged).unwrap();
        let mut limits = write_sidecar(&sidecar_path, &original);
        let encoded = fs::read(&sidecar_path).unwrap();
        let mut prefixed = b"junk".to_vec();
        prefixed.extend_from_slice(&encoded);
        fs::write(&sidecar_path, prefixed).unwrap();
        limits.max_damage_events = 1;
        limits.max_unrecognized_bytes = 4;

        let outcome = publish(
            source_path,
            sidecar_path,
            destination_path,
            publish_options(limits, false),
        )
        .unwrap();

        let PublishOutcome::Published(summary) = outcome else {
            panic!("recoverably damaged sidecar did not produce a repair");
        };
        assert_eq!(summary.sidecar_damage_events, 1);
    }

    #[test]
    fn accepts_an_existing_intact_destination_idempotently() {
        let directory = TestDirectory::new();
        let source_path = directory.join("movie.bin");
        let sidecar_path = directory.join("movie.bin.bitrot");
        let destination_path = directory.join("movie.bin.repaired");
        let original = source_bytes();
        let mut damaged = original.clone();
        damaged[CHUNK_BYTES + 17] ^= 1;
        fs::write(&source_path, &damaged).unwrap();
        fs::write(&destination_path, &original).unwrap();
        let limits = write_sidecar(&sidecar_path, &original);

        let outcome = publish(
            source_path,
            sidecar_path,
            &destination_path,
            publish_options(limits, false),
        )
        .unwrap();

        assert_eq!(outcome, PublishOutcome::AlreadyCurrent);
        assert_eq!(fs::read(destination_path).unwrap(), original);
        assert!(!directory.has_partial());
    }

    #[test]
    fn preserves_a_conflicting_destination() {
        let directory = TestDirectory::new();
        let source_path = directory.join("movie.bin");
        let sidecar_path = directory.join("movie.bin.bitrot");
        let destination_path = directory.join("movie.bin.repaired");
        let original = source_bytes();
        let mut damaged = original.clone();
        damaged[41] ^= 1;
        fs::write(&source_path, damaged).unwrap();
        fs::write(&destination_path, b"existing evidence").unwrap();
        let limits = write_sidecar(&sidecar_path, &original);

        assert!(matches!(
            publish(
                source_path,
                sidecar_path,
                &destination_path,
                publish_options(limits, false)
            ),
            Err(PublishError::ExistingConflict)
        ));
        assert_eq!(fs::read(destination_path).unwrap(), b"existing evidence");
        assert!(!directory.has_partial());
    }

    #[test]
    fn displaced_scan_can_publish_without_spending_recovery() {
        let directory = TestDirectory::new();
        let source_path = directory.join("movie.bin");
        let sidecar_path = directory.join("movie.bin.bitrot");
        let destination_path = directory.join("movie.bin.repaired");
        let original = source_bytes();
        let mut shifted = vec![0xa5];
        shifted.extend_from_slice(&original);
        fs::write(&source_path, shifted).unwrap();
        let limits = write_sidecar(&sidecar_path, &original);

        let outcome = publish(
            source_path,
            sidecar_path,
            &destination_path,
            publish_options(limits, true),
        )
        .unwrap();

        let PublishOutcome::Published(summary) = outcome else {
            panic!("shifted source was not repaired");
        };
        let location = summary.location.unwrap();
        assert_eq!(location.located_chunks, 3);
        assert_eq!(summary.reconstruction.reconstructed_data_chunks, 0);
        assert_eq!(fs::read(destination_path).unwrap(), original);
        assert!(!directory.has_partial());
    }

    #[test]
    fn unrepairable_source_leaves_no_output_or_temporary() {
        let directory = TestDirectory::new();
        let source_path = directory.join("movie.bin");
        let sidecar_path = directory.join("movie.bin.bitrot");
        let destination_path = directory.join("movie.bin.repaired");
        let original = source_bytes();
        let mut damaged = original.clone();
        for index in 0..3 {
            damaged[index * CHUNK_BYTES + 7] ^= 1;
        }
        fs::write(&source_path, damaged).unwrap();
        let limits = write_sidecar(&sidecar_path, &original);

        assert!(matches!(
            publish(
                source_path,
                sidecar_path,
                &destination_path,
                publish_options(limits, false)
            ),
            Err(PublishError::Unrepairable)
        ));
        assert!(!destination_path.exists());
        assert!(!directory.has_partial());
        assert_eq!(directory.entry_count(), 2);
    }

    #[test]
    fn concurrent_publishers_install_exactly_one_repair() {
        const PUBLISHERS: usize = 4;

        let directory = TestDirectory::new();
        let source_path = directory.join("movie.bin");
        let sidecar_path = directory.join("movie.bin.bitrot");
        let destination_path = directory.join("movie.bin.repaired");
        let original = source_bytes();
        let mut damaged = original.clone();
        damaged[53] ^= 1;
        fs::write(&source_path, damaged).unwrap();
        let limits = write_sidecar(&sidecar_path, &original);
        let start = Arc::new(Barrier::new(PUBLISHERS));
        let mut threads = Vec::new();

        for _ in 0..PUBLISHERS {
            let source_path = source_path.clone();
            let sidecar_path = sidecar_path.clone();
            let destination_path = destination_path.clone();
            let start = Arc::clone(&start);
            threads.push(std::thread::spawn(move || {
                start.wait();
                publish(
                    source_path,
                    sidecar_path,
                    destination_path,
                    publish_options(limits, false),
                )
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
        assert_eq!(fs::read(destination_path).unwrap(), original);
        assert!(!directory.has_partial());
    }

    #[cfg(unix)]
    #[test]
    fn stale_cleanup_removes_only_unlocked_repair_partials() {
        use std::fs::FileTimes;

        let directory = TestDirectory::new();
        let destination = OsStr::new("movie.bin.repaired");
        let stale_name = temporary_name(destination, 0, 1);
        let active_name = temporary_name(destination, 0, 2);
        let stale = directory.0.join(&stale_name);
        let active = directory.0.join(&active_name);
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

        cleanup_stale_temporaries(&anchored, destination).unwrap();

        assert!(!stale.exists());
        assert!(active.exists());
        drop(active_file);
        cleanup_stale_temporaries(&anchored, destination).unwrap();
        assert!(!active.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_inputs_and_source_alias_destinations() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let source_path = directory.join("movie.bin");
        let source_link = directory.join("source-link");
        let sidecar_path = directory.join("movie.bin.bitrot");
        let sidecar_link = directory.join("sidecar-link");
        let destination_path = directory.join("movie.bin.repaired");
        let original = source_bytes();
        let mut damaged = original.clone();
        damaged[29] ^= 1;
        fs::write(&source_path, damaged).unwrap();
        let limits = write_sidecar(&sidecar_path, &original);
        symlink(&source_path, &source_link).unwrap();
        symlink(&sidecar_path, &sidecar_link).unwrap();

        assert!(matches!(
            publish(
                &source_link,
                &sidecar_path,
                &destination_path,
                publish_options(limits, false)
            ),
            Err(PublishError::SourceIsSymlink)
        ));
        assert!(matches!(
            publish(
                &source_path,
                &sidecar_link,
                &destination_path,
                publish_options(limits, false)
            ),
            Err(PublishError::SidecarIsSymlink)
        ));

        fs::hard_link(&source_path, &destination_path).unwrap();
        assert!(matches!(
            publish(
                source_path,
                sidecar_path,
                &destination_path,
                publish_options(limits, false)
            ),
            Err(PublishError::OverlappingPaths)
        ));
        assert!(!directory.has_partial());
    }
}
