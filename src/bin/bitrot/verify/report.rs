use bitrot::rolling::ScanSummary;
use bitrot::sidecar::{Damage, Sidecar};
use bitrot::verify::{
    ChunkReport, ChunkState, LocationSummary, Report, SourceDigestState, SourceState,
};
use serde::Serialize;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;

const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct VerificationReport {
    schema_version: u32,
    command: &'static str,
    status: Status,
    source_path: PathReport,
    sidecar_path: PathReport,
    protection_set_id: String,
    creator: CreatorReport,
    source: SourceReport,
    recovery: RecoveryReport,
    sidecar_damage: Vec<DamageReport>,
    displaced_scan: Option<DisplacedScanReport>,
}

impl VerificationReport {
    pub fn new(
        source_path: &Path,
        sidecar_path: &Path,
        sidecar: &Sidecar,
        damage: &[Damage],
        source: Report,
        location: Option<LocationSummary>,
    ) -> Self {
        let manifest = sidecar.metadata.manifest;
        let geometry = manifest.geometry();
        Self {
            schema_version: SCHEMA_VERSION,
            command: "verify",
            status: source.state.into(),
            source_path: PathReport::new(source_path),
            sidecar_path: PathReport::new(sidecar_path),
            protection_set_id: encode_hex(&source.protection_set_id),
            creator: CreatorReport {
                implementation: sidecar.creator.implementation().to_owned(),
                version: sidecar.creator.version().to_owned(),
            },
            recovery: RecoveryReport {
                expected_chunks: geometry.recovery_chunks,
                available_chunks: source.available_recovery_chunks,
                unavailable_chunks: source.unavailable_recovery_chunks,
                rejected_records: sidecar.recovery.rejected().len(),
                duplicate_records: sidecar.recovery.duplicate_records(),
            },
            sidecar_damage: damage.iter().map(DamageReport::from).collect(),
            displaced_scan: location.map(DisplacedScanReport::from),
            source: SourceReport::from(source),
        }
    }

    pub fn write_json(&self, mut writer: impl Write) -> io::Result<()> {
        serde_json::to_writer_pretty(&mut writer, self).map_err(io::Error::other)?;
        writeln!(writer)
    }

    pub fn write_human(&self, mut writer: impl Write) -> io::Result<()> {
        writeln!(writer, "status: {}", self.status)?;
        writeln!(writer, "source: {}", self.source_path.display)?;
        writeln!(writer, "sidecar: {}", self.sidecar_path.display)?;
        writeln!(writer, "protection set: {}", self.protection_set_id)?;
        writeln!(
            writer,
            "source bytes: {} expected, {} observed",
            self.source.expected_bytes, self.source.observed_bytes
        )?;
        writeln!(
            writer,
            "data chunks: {} good, {} displaced, {} corrupt, {} missing, {} unreadable",
            self.source.good_chunks,
            self.source.unexpectedly_located_chunks,
            self.source.corrupt_chunks,
            self.source.missing_chunks,
            self.source.unreadable_chunks
        )?;
        writeln!(
            writer,
            "recovery chunks: {} available, {} unavailable",
            self.recovery.available_chunks, self.recovery.unavailable_chunks
        )?;
        writeln!(
            writer,
            "sidecar damage events: {}",
            self.sidecar_damage.len()
        )?;
        if let Some(scan) = &self.displaced_scan {
            writeln!(
                writer,
                "displaced scan: {} of {} eligible chunks located across {} windows",
                scan.located_chunks, scan.eligible_chunks, scan.windows_scanned
            )?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct ErrorReport {
    schema_version: u32,
    command: &'static str,
    status: Status,
    source_path: PathReport,
    sidecar_path: PathReport,
    pub error: String,
}

impl ErrorReport {
    pub fn new(status: Status, source: &Path, sidecar: &Path, error: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command: "verify",
            status,
            source_path: PathReport::new(source),
            sidecar_path: PathReport::new(sidecar),
            error,
        }
    }

    pub fn write_json(&self, mut writer: impl Write) -> io::Result<()> {
        serde_json::to_writer_pretty(&mut writer, self).map_err(io::Error::other)?;
        writeln!(writer)
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Intact,
    Repairable,
    Unrepairable,
    InvalidSidecar,
    OperationalFailure,
}

impl From<SourceState> for Status {
    fn from(state: SourceState) -> Self {
        match state {
            SourceState::Intact => Self::Intact,
            SourceState::Repairable => Self::Repairable,
            SourceState::Unrepairable => Self::Unrepairable,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Intact => "intact",
            Self::Repairable => "repairable",
            Self::Unrepairable => "unrepairable",
            Self::InvalidSidecar => "invalid_sidecar",
            Self::OperationalFailure => "operational_failure",
        };
        formatter.write_str(name)
    }
}

#[derive(Serialize)]
struct PathReport {
    display: String,
    lossy: bool,
}

impl PathReport {
    fn new(path: &Path) -> Self {
        Self {
            display: path.to_string_lossy().into_owned(),
            lossy: path.to_str().is_none(),
        }
    }
}

#[derive(Serialize)]
struct CreatorReport {
    implementation: String,
    version: String,
}

#[derive(Serialize)]
struct SourceReport {
    expected_bytes: u64,
    observed_bytes: u64,
    digest: SourceDigestStatus,
    good_chunks: u32,
    unexpectedly_located_chunks: u32,
    corrupt_chunks: u32,
    missing_chunks: u32,
    unreadable_chunks: u32,
    required_recovery_chunks: u32,
    chunks: Vec<DataChunkReport>,
}

impl From<Report> for SourceReport {
    fn from(report: Report) -> Self {
        let mut corrupt = 0_u32;
        let mut missing = 0_u32;
        let mut unreadable = 0_u32;
        for chunk in &report.chunks {
            match chunk.state {
                ChunkState::Corrupt => corrupt += 1,
                ChunkState::Missing => missing += 1,
                ChunkState::Unreadable(_) => unreadable += 1,
                ChunkState::Good | ChunkState::UnexpectedlyLocated { .. } => {}
            }
        }
        Self {
            expected_bytes: report.expected_source_len,
            observed_bytes: report.observed_source_len,
            digest: report.source_digest.into(),
            good_chunks: report.good_data_chunks,
            unexpectedly_located_chunks: report.unexpectedly_located_data_chunks,
            corrupt_chunks: corrupt,
            missing_chunks: missing,
            unreadable_chunks: unreadable,
            required_recovery_chunks: report.required_recovery_chunks(),
            chunks: report
                .chunks
                .into_iter()
                .map(DataChunkReport::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct DataChunkReport {
    index: u32,
    expected_bytes: u32,
    bytes_read: u32,
    state: DataChunkStatus,
    located_offset: Option<u64>,
    io_error_kind: Option<IoErrorKind>,
}

impl From<ChunkReport> for DataChunkReport {
    fn from(chunk: ChunkReport) -> Self {
        let (state, located_offset, io_error_kind) = match chunk.state {
            ChunkState::Good => (DataChunkStatus::Good, None, None),
            ChunkState::Corrupt => (DataChunkStatus::Corrupt, None, None),
            ChunkState::Missing => (DataChunkStatus::Missing, None, None),
            ChunkState::Unreadable(kind) => (
                DataChunkStatus::Unreadable,
                None,
                Some(IoErrorKind::from(kind)),
            ),
            ChunkState::UnexpectedlyLocated { offset } => {
                (DataChunkStatus::UnexpectedlyLocated, Some(offset), None)
            }
        };
        Self {
            index: chunk.index,
            expected_bytes: chunk.expected_len,
            bytes_read: chunk.bytes_read,
            state,
            located_offset,
            io_error_kind,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum SourceDigestStatus {
    Match,
    Mismatch,
    Unavailable,
}

impl From<SourceDigestState> for SourceDigestStatus {
    fn from(state: SourceDigestState) -> Self {
        match state {
            SourceDigestState::Match => Self::Match,
            SourceDigestState::Mismatch => Self::Mismatch,
            SourceDigestState::Unavailable => Self::Unavailable,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum DataChunkStatus {
    Good,
    Corrupt,
    Missing,
    Unreadable,
    UnexpectedlyLocated,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum IoErrorKind {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    HostUnreachable,
    NetworkUnreachable,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    NetworkDown,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    ReadOnlyFilesystem,
    StaleNetworkFileHandle,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    StorageFull,
    NotSeekable,
    QuotaExceeded,
    FileTooLarge,
    ResourceBusy,
    ExecutableFileBusy,
    Deadlock,
    CrossesDevices,
    TooManyLinks,
    InvalidFilename,
    ArgumentListTooLong,
    Interrupted,
    Unsupported,
    UnexpectedEof,
    OutOfMemory,
    Other,
}

impl From<io::ErrorKind> for IoErrorKind {
    #[allow(clippy::too_many_lines)]
    fn from(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::ConnectionReset => Self::ConnectionReset,
            io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            io::ErrorKind::ConnectionAborted => Self::ConnectionAborted,
            io::ErrorKind::NotConnected => Self::NotConnected,
            io::ErrorKind::AddrInUse => Self::AddrInUse,
            io::ErrorKind::AddrNotAvailable => Self::AddrNotAvailable,
            io::ErrorKind::NetworkDown => Self::NetworkDown,
            io::ErrorKind::BrokenPipe => Self::BrokenPipe,
            io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            io::ErrorKind::WouldBlock => Self::WouldBlock,
            io::ErrorKind::NotADirectory => Self::NotADirectory,
            io::ErrorKind::IsADirectory => Self::IsADirectory,
            io::ErrorKind::DirectoryNotEmpty => Self::DirectoryNotEmpty,
            io::ErrorKind::ReadOnlyFilesystem => Self::ReadOnlyFilesystem,
            io::ErrorKind::StaleNetworkFileHandle => Self::StaleNetworkFileHandle,
            io::ErrorKind::InvalidInput => Self::InvalidInput,
            io::ErrorKind::InvalidData => Self::InvalidData,
            io::ErrorKind::TimedOut => Self::TimedOut,
            io::ErrorKind::WriteZero => Self::WriteZero,
            io::ErrorKind::StorageFull => Self::StorageFull,
            io::ErrorKind::NotSeekable => Self::NotSeekable,
            io::ErrorKind::QuotaExceeded => Self::QuotaExceeded,
            io::ErrorKind::FileTooLarge => Self::FileTooLarge,
            io::ErrorKind::ResourceBusy => Self::ResourceBusy,
            io::ErrorKind::ExecutableFileBusy => Self::ExecutableFileBusy,
            io::ErrorKind::Deadlock => Self::Deadlock,
            io::ErrorKind::CrossesDevices => Self::CrossesDevices,
            io::ErrorKind::TooManyLinks => Self::TooManyLinks,
            io::ErrorKind::InvalidFilename => Self::InvalidFilename,
            io::ErrorKind::ArgumentListTooLong => Self::ArgumentListTooLong,
            io::ErrorKind::Interrupted => Self::Interrupted,
            io::ErrorKind::Unsupported => Self::Unsupported,
            io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            io::ErrorKind::OutOfMemory => Self::OutOfMemory,
            _ => Self::Other,
        }
    }
}

#[derive(Serialize)]
struct RecoveryReport {
    expected_chunks: u32,
    available_chunks: u32,
    unavailable_chunks: u32,
    rejected_records: usize,
    duplicate_records: u64,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DamageReport {
    Unrecognized { offset: u64, length: u64 },
    InvalidRecord { offset: u64, error: String },
}

impl From<&Damage> for DamageReport {
    fn from(damage: &Damage) -> Self {
        match damage {
            Damage::Unrecognized { offset, length } => Self::Unrecognized {
                offset: *offset,
                length: *length,
            },
            Damage::InvalidRecord { offset, error } => Self::InvalidRecord {
                offset: *offset,
                error: error.to_string(),
            },
        }
    }
}

#[derive(Serialize)]
struct DisplacedScanReport {
    eligible_chunks: u32,
    located_chunks: u32,
    windows_scanned: u64,
    rolling_candidates: u64,
    stopped_early: bool,
}

impl From<LocationSummary> for DisplacedScanReport {
    fn from(summary: LocationSummary) -> Self {
        let ScanSummary {
            windows_scanned,
            rolling_candidates,
            stopped_early,
        } = summary.scan;
        Self {
            eligible_chunks: summary.eligible_chunks,
            located_chunks: summary.located_chunks,
            windows_scanned,
            rolling_candidates,
            stopped_early,
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_protection_ids_as_lowercase_hex() {
        assert_eq!(encode_hex(&[0, 1, 0xab, 0xff]), "0001abff");
    }

    #[test]
    fn serializes_io_error_kinds_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&IoErrorKind::from(io::ErrorKind::PermissionDenied)).unwrap(),
            r#""permission_denied""#
        );
    }
}
