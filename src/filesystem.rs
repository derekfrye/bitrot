//! Shared filesystem primitives for crash-safe publication.

#[cfg(windows)]
use cap_std::ambient_authority;
#[cfg(any(unix, windows))]
use cap_std::fs::MetadataExt as _;
#[cfg(unix)]
use cap_std::fs::OpenOptionsExt as _;
#[cfg(any(unix, windows))]
use cap_std::fs::{Dir, OpenOptions as DirectoryOpenOptions};
use std::ffi::{OsStr, OsString};
#[cfg(not(any(unix, windows)))]
use std::fs::{self, OpenOptions};
use std::fs::{File, Metadata, TryLockError};
use std::io;
use std::path::Path;
#[cfg(not(any(unix, windows)))]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple"
))]
use std::time::Duration;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple"
))]
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple"
))]
const STALE_TEMPORARY_AGE: Duration = Duration::from_hours(24);
// Advisory locks follow an open file description across `fork`. A close-on-exec
// descriptor can therefore remain locked briefly after its parent releases it.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple"
))]
const STALE_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(1);
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple"
))]
const STALE_LOCK_RETRY_TIMEOUT: Duration = Duration::from_millis(100);
const TEMPORARY_NAME_ATTEMPTS: u32 = 128;
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

pub(crate) fn destination_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(crate) struct Directory {
    #[cfg(any(unix, windows))]
    directory: Dir,
    #[cfg(unix)]
    sync_file: File,
    #[cfg(not(any(unix, windows)))]
    ambient_path: PathBuf,
}

impl Directory {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
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

    pub(crate) fn open_read_no_follow(&self, name: &OsStr) -> io::Result<File> {
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
            let mut options = OpenOptions::new();
            options.read(true).open(self.ambient_path.join(name))
        }
    }

    fn open_read_write_no_follow(&self, name: &OsStr) -> io::Result<File> {
        #[cfg(any(unix, windows))]
        {
            let mut options = DirectoryOpenOptions::new();
            options.read(true).write(true);
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
                .open(self.ambient_path.join(name))
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

    pub(crate) fn symlink_metadata(&self, name: &OsStr) -> io::Result<EntryMetadata> {
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

    pub(crate) fn hard_link(&self, source: &OsStr, destination: &OsStr) -> io::Result<()> {
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

    pub(crate) fn rename(&self, source: &OsStr, destination: &OsStr) -> io::Result<()> {
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

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_vendor = "apple"
    ))]
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

    pub(crate) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        #[cfg(any(unix, windows))]
        {
            self.directory.remove_file(name)
        }
        #[cfg(not(any(unix, windows)))]
        {
            fs::remove_file(self.ambient_path.join(name))
        }
    }

    pub(crate) fn sync(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.sync_file.sync_all()
        }
        #[cfg(not(unix))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "destination-directory durability synchronization is unsupported on this platform",
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
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
    pub(crate) fn capture(file: &File) -> io::Result<Self> {
        file.metadata().map(|metadata| Self::from_std(&metadata))
    }

    pub(crate) fn from_std(metadata: &Metadata) -> Self {
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

    #[cfg(any(unix, windows))]
    pub(crate) fn from_cap(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
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

    pub(crate) fn same_entry(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
        }
        #[cfg(windows)]
        {
            same_windows_file_id(
                self.volume_serial_number,
                self.file_index,
                other.volume_serial_number,
                other.file_index,
            )
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.len == other.len && self.modified == other.modified
        }
    }
}

pub(crate) struct EntryMetadata {
    is_file: bool,
    is_symlink: bool,
    identity: FileIdentity,
}

impl EntryMetadata {
    #[cfg(any(unix, windows))]
    fn from_cap(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            is_file: metadata.is_file(),
            is_symlink: metadata.file_type().is_symlink(),
            identity: FileIdentity::from_cap(metadata),
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn from_std(metadata: Metadata) -> Self {
        Self {
            is_file: metadata.is_file(),
            is_symlink: metadata.file_type().is_symlink(),
            identity: FileIdentity::from_std(&metadata),
        }
    }

    pub(crate) const fn is_file(&self) -> bool {
        self.is_file
    }

    pub(crate) const fn is_symlink(&self) -> bool {
        self.is_symlink
    }

    pub(crate) const fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub(crate) fn same_file(&self, metadata: &Metadata) -> bool {
        self.identity.same_entry(&FileIdentity::from_std(metadata))
    }
}

#[cfg(any(unix, windows))]
fn set_no_follow(options: &mut DirectoryOpenOptions) {
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    #[cfg(not(unix))]
    let _ = options;
}

#[derive(Clone, Copy)]
pub(crate) enum TemporaryKind {
    Recovery,
    Sidecar,
    Repair,
}

impl TemporaryKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Recovery => "recovery",
            Self::Sidecar => "sidecar",
            Self::Repair => "repair",
        }
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_vendor = "apple"
    ))]
    const fn bytes(self) -> &'static [u8] {
        self.name().as_bytes()
    }
}

#[derive(Debug)]
pub(crate) enum CreateTemporaryError {
    NameExhausted,
    LockContended,
    Create(io::Error),
    Lock(io::Error),
}

pub(crate) struct TemporaryFile<'directory> {
    directory: &'directory Directory,
    destination_name: OsString,
    kind: TemporaryKind,
    name: OsString,
    pub(crate) file: File,
    armed: bool,
}

impl<'directory> TemporaryFile<'directory> {
    pub(crate) fn create(
        directory: &'directory Directory,
        destination_name: &OsStr,
        kind: TemporaryKind,
    ) -> Result<Self, CreateTemporaryError> {
        let epoch_nonce = epoch_nonce();
        for _ in 0..TEMPORARY_NAME_ATTEMPTS {
            let name = temporary_name(destination_name, kind, epoch_nonce, next_nonce());
            match directory.create_new(&name) {
                Ok(file) => {
                    file.try_lock().map_err(|error| match error {
                        TryLockError::Error(error) => CreateTemporaryError::Lock(error),
                        TryLockError::WouldBlock => CreateTemporaryError::LockContended,
                    })?;
                    return Ok(Self {
                        directory,
                        destination_name: destination_name.to_owned(),
                        kind,
                        name,
                        file,
                        armed: true,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(CreateTemporaryError::Create(error)),
            }
        }
        Err(CreateTemporaryError::NameExhausted)
    }

    pub(crate) fn name(&self) -> &OsStr {
        &self.name
    }

    pub(crate) fn verify_path_identity(&self) -> io::Result<bool> {
        path_names_file(self.directory, &self.name, &self.file)
    }

    pub(crate) fn remove(&mut self) -> io::Result<()> {
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "redox",
            target_vendor = "apple"
        ))]
        let result = quarantine_and_remove(
            self.directory,
            &self.destination_name,
            self.kind,
            &self.name,
            &self.file,
        );
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "redox",
            target_vendor = "apple"
        )))]
        let result = Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "identity-safe temporary cleanup is unsupported on this platform",
        ));
        self.armed = false;
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err(io::Error::other(
                "temporary path no longer names the file created by this process",
            )),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryFile<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "redox",
            target_vendor = "apple"
        ))]
        let _ = quarantine_and_remove(
            self.directory,
            &self.destination_name,
            self.kind,
            &self.name,
            &self.file,
        );
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "redox",
            target_vendor = "apple"
        )))]
        let _ = self;
    }
}

pub(crate) fn cleanup_stale_temporaries(
    directory: &Directory,
    destination: &OsStr,
    kinds: &[TemporaryKind],
) -> io::Result<()> {
    cleanup_stale_temporaries_with_contention_hook(directory, destination, kinds, || {})
}

fn cleanup_stale_temporaries_with_contention_hook(
    directory: &Directory,
    destination: &OsStr,
    kinds: &[TemporaryKind],
    mut on_lock_contention: impl FnMut(),
) -> io::Result<()> {
    let Some(&quarantine_kind) = kinds.first() else {
        return Ok(());
    };
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_vendor = "apple"
    ))]
    {
        use std::os::unix::ffi::OsStrExt as _;

        let now = SystemTime::now();
        let retry_deadline = Instant::now() + STALE_LOCK_RETRY_TIMEOUT;
        let mut removed = false;
        // Share one deadline across every contended entry so a genuinely active
        // old producer cannot make cleanup wait without bound.
        loop {
            let mut contended = false;
            for entry in directory.directory.entries()? {
                let entry = entry?;
                let name = entry.file_name();
                if !is_temporary_name_for(name.as_bytes(), destination.as_bytes(), kinds) {
                    continue;
                }
                let metadata = match directory.symlink_metadata(&name) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
                if !metadata.is_file()
                    || metadata
                        .identity
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
                    Err(TryLockError::WouldBlock) => {
                        on_lock_contention();
                        contended = true;
                        continue;
                    }
                    Err(TryLockError::Error(error)) => return Err(error),
                }
                removed |=
                    quarantine_and_remove(directory, destination, quarantine_kind, &name, &file)?;
            }
            if !contended {
                break;
            }
            let instant = Instant::now();
            if instant >= retry_deadline {
                break;
            }
            std::thread::sleep(STALE_LOCK_RETRY_INTERVAL.min(retry_deadline - instant));
        }
        if removed {
            directory.sync()?;
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_vendor = "apple"
    )))]
    let _ = (directory, destination, quarantine_kind, on_lock_contention);
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple"
))]
fn quarantine_and_remove(
    directory: &Directory,
    destination: &OsStr,
    kind: TemporaryKind,
    original_name: &OsStr,
    opened_file: &File,
) -> io::Result<bool> {
    let epoch_nonce = epoch_nonce();
    let mut quarantine_name = None;
    for _ in 0..TEMPORARY_NAME_ATTEMPTS {
        let candidate = temporary_name(destination, kind, epoch_nonce, next_nonce());
        match directory.rename_no_replace(original_name, &candidate) {
            Ok(()) => {
                quarantine_name = Some(candidate);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    let Some(quarantine_name) = quarantine_name else {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot reserve a temporary-file quarantine name",
        ));
    };

    if path_names_file(directory, &quarantine_name, opened_file)? {
        directory.remove_file(&quarantine_name)?;
        return Ok(true);
    }

    match directory.rename_no_replace(&quarantine_name, original_name) {
        Ok(()) => Err(io::Error::other(
            "temporary pathname changed during cleanup; replacement was restored",
        )),
        Err(restore_error) => Err(io::Error::new(
            restore_error.kind(),
            format!(
                "temporary pathname changed during cleanup; replacement remains at {}: {restore_error}",
                quarantine_name.display()
            ),
        )),
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple"
))]
fn is_temporary_name_for(candidate: &[u8], destination: &[u8], kinds: &[TemporaryKind]) -> bool {
    let Some(fields) = candidate
        .strip_prefix(destination)
        .and_then(|suffix| suffix.strip_prefix(b".bitrot-partial-"))
    else {
        return false;
    };
    let mut fields = fields.split(|byte| *byte == b'-');
    let (Some(pid), Some(kind), Some(epoch), Some(nonce)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    fields.next().is_none()
        && !pid.is_empty()
        && pid.iter().all(u8::is_ascii_digit)
        && kinds.iter().any(|candidate| candidate.bytes() == kind)
        && is_lower_hex(epoch)
        && is_lower_hex(nonce)
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple"
))]
fn is_lower_hex(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

pub(crate) fn temporary_name(
    destination: &OsStr,
    kind: TemporaryKind,
    epoch_nonce: u128,
    nonce: u64,
) -> OsString {
    let mut name = OsString::from(destination);
    name.push(format!(
        ".bitrot-partial-{}-{}-{epoch_nonce:x}-{nonce:x}",
        std::process::id(),
        kind.name()
    ));
    name
}

fn epoch_nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn next_nonce() -> u64 {
    NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn path_names_file(
    directory: &Directory,
    name: &OsStr,
    file: &File,
) -> io::Result<bool> {
    let open_metadata = file.metadata()?;
    let path_metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(path_metadata.is_file() && path_metadata.same_file(&open_metadata))
}

pub(crate) fn remove_file_if_same(
    directory: &Directory,
    name: &OsStr,
    file: &File,
    quarantine_kind: TemporaryKind,
) -> io::Result<bool> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_vendor = "apple"
    ))]
    {
        quarantine_and_remove(directory, name, quarantine_kind, name, file)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_vendor = "apple"
    )))]
    {
        let _ = (directory, name, file, quarantine_kind);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "identity-safe file removal is unsupported on this platform",
        ))
    }
}

#[derive(Clone, Copy)]
pub(crate) enum PublishedIdentityCheck {
    SameEntry,
    ExactSnapshot,
}

#[derive(Debug)]
pub(crate) enum PublishedFileError<E> {
    Open(io::Error),
    Metadata(io::Error),
    IdentityChanged,
    Content(E),
}

pub(crate) fn verify_published_file<E>(
    directory: &Directory,
    destination: &OsStr,
    expected_file: &File,
    identity_check: PublishedIdentityCheck,
    verify_content: impl FnOnce(&mut File) -> Result<(), E>,
) -> Result<(), PublishedFileError<E>> {
    let mut published = directory
        .open_read_no_follow(destination)
        .map_err(PublishedFileError::Open)?;
    let expected = FileIdentity::capture(expected_file).map_err(PublishedFileError::Metadata)?;
    let actual = FileIdentity::capture(&published).map_err(PublishedFileError::Metadata)?;
    let identity_matches = match identity_check {
        PublishedIdentityCheck::SameEntry => expected.same_entry(&actual),
        PublishedIdentityCheck::ExactSnapshot => expected == actual,
    };
    if !identity_matches {
        return Err(PublishedFileError::IdentityChanged);
    }
    verify_content(&mut published).map_err(PublishedFileError::Content)
}

pub(crate) fn rollback_published_file(
    directory: &Directory,
    destination: &OsStr,
    published_file: &File,
    quarantine_kind: TemporaryKind,
) -> io::Result<()> {
    if remove_file_if_same(directory, destination, published_file, quarantine_kind)? {
        directory.sync()
    } else {
        Err(io::Error::other(
            "published destination changed before rollback",
        ))
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

#[derive(Debug)]
pub(crate) enum FinishError {
    Cleanup(io::Error),
    Sync(io::Error),
    CleanupAndSync { cleanup: io::Error, sync: io::Error },
}

pub(crate) fn finish_publication(
    cleanup: impl FnOnce() -> io::Result<()>,
    sync: impl FnOnce() -> io::Result<()>,
) -> Result<(), FinishError> {
    match (cleanup().err(), sync().err()) {
        (None, None) => Ok(()),
        (Some(error), None) => Err(FinishError::Cleanup(error)),
        (None, Some(error)) => Err(FinishError::Sync(error)),
        (Some(cleanup), Some(sync)) => Err(FinishError::CleanupAndSync { cleanup, sync }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_vendor = "apple"
    ))]
    const INHERITED_LOCK_CHILD: &str = "filesystem::tests::inherited_lock_process_child";

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_vendor = "apple"
    ))]
    #[test]
    #[ignore = "helper re-executed by the inherited-lock lifecycle test"]
    fn inherited_lock_process_child() {
        use std::io::Write as _;

        let mut stdout = io::stdout().lock();
        writeln!(stdout, "ready").unwrap();
        stdout.flush().unwrap();
        drop(stdout);
        std::thread::sleep(Duration::from_millis(50));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_vendor = "apple"
    ))]
    #[test]
    fn stale_cleanup_handles_a_released_lock_inherited_during_process_spawn() {
        use std::fs::{self, FileTimes, OpenOptions};
        use std::io::BufRead as _;
        use std::process::{Command, Stdio};

        struct TestDirectory(std::path::PathBuf);

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        let path = std::env::temp_dir().join(format!(
            "bitrot-inherited-lock-test-{}-{}",
            std::process::id(),
            next_nonce()
        ));
        fs::create_dir(&path).unwrap();
        let directory = TestDirectory(path);
        let anchored = Directory::open(&directory.0).unwrap();
        let destination = OsStr::new("output.bitrot");
        let old = FileTimes::new().set_modified(UNIX_EPOCH);
        let active_name = temporary_name(destination, TemporaryKind::Sidecar, 0, next_nonce());
        let active_path = directory.0.join(&active_name);
        let active_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&active_path)
            .unwrap();
        active_file.set_times(old).unwrap();
        active_file.try_lock().unwrap();

        // Passing a duplicate as standard input deterministically retains the
        // same locked open file description in the child. The readiness message
        // confirms that the parent releases its copy while the child holds one.
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(INHERITED_LOCK_CHILD)
            .arg("--ignored")
            .arg("--nocapture")
            .stdin(Stdio::from(active_file.try_clone().unwrap()))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child_stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut readiness = String::new();
        loop {
            assert_ne!(child_stdout.read_line(&mut readiness).unwrap(), 0);
            if readiness.contains("ready") {
                break;
            }
            readiness.clear();
        }

        drop(active_file);
        let mut observed_inherited_lock = false;
        cleanup_stale_temporaries_with_contention_hook(
            &anchored,
            destination,
            &[TemporaryKind::Sidecar],
            || observed_inherited_lock = true,
        )
        .unwrap();
        assert!(!active_path.exists());
        assert!(
            observed_inherited_lock,
            "child process did not retain the inherited lock"
        );
        std::io::copy(&mut child_stdout, &mut io::sink()).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[cfg(unix)]
    #[test]
    fn entry_identity_is_independent_of_mutable_metadata() {
        let original = FileIdentity {
            len: 10,
            modified: None,
            device: 7,
            inode: 11,
        };
        let changed = FileIdentity {
            len: 20,
            ..original.clone()
        };

        assert_ne!(original, changed);
        assert!(original.same_entry(&changed));
    }

    #[test]
    fn windows_identity_requires_both_available_identifiers() {
        assert!(same_windows_file_id(Some(7), Some(11), Some(7), Some(11)));
        assert!(!same_windows_file_id(None, Some(11), None, Some(11)));
        assert!(!same_windows_file_id(Some(7), None, Some(7), None));
        assert!(!same_windows_file_id(Some(7), Some(11), Some(8), Some(11)));
        assert!(!same_windows_file_id(Some(7), Some(11), Some(7), Some(12)));
    }
}
