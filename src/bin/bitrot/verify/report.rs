use bitrot::rolling::ScanSummary;
use bitrot::sidecar::{Damage, Sidecar};
use bitrot::verify::{
    ChunkReport, ChunkState, LocationSummary, Report, SourceDigestState, SourceState,
};
use serde::Serialize;
use std::io::{self, Write};
use std::path::Path;

const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct VerificationReport {
    schema_version: u32,
    command: &'static str,
    status: &'static str,
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
            status: source_state(source.state),
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
    status: &'static str,
    source_path: PathReport,
    sidecar_path: PathReport,
    pub error: String,
}

impl ErrorReport {
    pub fn new(status: &'static str, source: &Path, sidecar: &Path, error: String) -> Self {
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
    digest: &'static str,
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
            digest: source_digest_state(report.source_digest),
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
    state: &'static str,
    located_offset: Option<u64>,
    io_error_kind: Option<String>,
}

impl From<ChunkReport> for DataChunkReport {
    fn from(chunk: ChunkReport) -> Self {
        let (state, located_offset, io_error_kind) = match chunk.state {
            ChunkState::Good => ("good", None, None),
            ChunkState::Corrupt => ("corrupt", None, None),
            ChunkState::Missing => ("missing", None, None),
            ChunkState::Unreadable(kind) => ("unreadable", None, Some(format!("{kind:?}"))),
            ChunkState::UnexpectedlyLocated { offset } => {
                ("unexpectedly_located", Some(offset), None)
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

const fn source_state(state: SourceState) -> &'static str {
    match state {
        SourceState::Intact => "intact",
        SourceState::Repairable => "repairable",
        SourceState::Unrepairable => "unrepairable",
    }
}

const fn source_digest_state(state: SourceDigestState) -> &'static str {
    match state {
        SourceDigestState::Match => "match",
        SourceDigestState::Mismatch => "mismatch",
        SourceDigestState::Unavailable => "unavailable",
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
}
