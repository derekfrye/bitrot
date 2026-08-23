#[path = "verify/report.rs"]
mod report;

use self::report::{ErrorReport, VerificationReport};
use super::VerifyArgs;
use bitrot::digest_page;
use bitrot::geometry::{LEOPARD_FIELD_ORDER, MAX_CHUNK_SIZE};
use bitrot::metadata;
use bitrot::record::DecodeLimits;
use bitrot::recovery_chunk;
use bitrot::recovery_set;
use bitrot::rolling_page;
use bitrot::sidecar::{AssemblyLimits, ReadLimits, Sidecar};
use bitrot::verify::{self, LocateOptions, SourceState};
use std::fs::File;
use std::io;
use std::process::ExitCode;

pub const DEFAULT_MAX_SIDECAR_BYTES: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_MAX_LOCATE_TARGETS: usize = 65_535;

const EXIT_REPAIRABLE: u8 = 10;
const EXIT_UNREPAIRABLE: u8 = 11;
const EXIT_INVALID_SIDECAR: u8 = 12;
const EXIT_OPERATIONAL_FAILURE: u8 = 13;

const MAX_RECORDS: u64 = 70_000;
const MAX_UNKNOWN_OPTIONAL_RECORDS: u32 = 64;
const MAX_METADATA_RECORDS: u64 = 256;
const MAX_TABLE_PAGES: u32 = 64;
const MAX_COPIES: u32 = 8;
const MAX_DAMAGE_EVENTS: u32 = 1_024;
const MAX_UNRECOGNIZED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HEADER_LEN: u32 = 4_096;
const MAX_SHARDS: u32 = 65_535;

pub fn run(arguments: VerifyArgs) -> ExitCode {
    match verify(arguments) {
        Ok(completed) => {
            let exit = match completed.state {
                SourceState::Intact => ExitCode::SUCCESS,
                SourceState::Repairable => ExitCode::from(EXIT_REPAIRABLE),
                SourceState::Unrepairable => ExitCode::from(EXIT_UNREPAIRABLE),
            };
            if let Err(error) = completed.write() {
                eprintln!("bitrot: cannot write verification report: {error}");
                return ExitCode::from(EXIT_OPERATIONAL_FAILURE);
            }
            exit
        }
        Err(failure) => {
            let (status, exit) = match failure.kind {
                FailureKind::InvalidSidecar => ("invalid_sidecar", EXIT_INVALID_SIDECAR),
                FailureKind::Operational => ("operational_failure", EXIT_OPERATIONAL_FAILURE),
            };
            let report = ErrorReport::new(
                status,
                &failure.arguments.source,
                &failure.arguments.sidecar,
                failure.error,
            );
            if failure.arguments.json {
                if let Err(error) = report.write_json(io::stdout().lock()) {
                    eprintln!("bitrot: cannot write error report: {error}");
                    return ExitCode::from(EXIT_OPERATIONAL_FAILURE);
                }
            } else {
                eprintln!("bitrot verify: {}", report.error);
            }
            ExitCode::from(exit)
        }
    }
}

struct Completed {
    json: bool,
    state: SourceState,
    report: VerificationReport,
}

impl Completed {
    fn write(&self) -> io::Result<()> {
        if self.json {
            self.report.write_json(io::stdout().lock())
        } else {
            self.report.write_human(io::stdout().lock())
        }
    }
}

struct Failure {
    arguments: VerifyArgs,
    kind: FailureKind,
    error: String,
}

enum FailureKind {
    InvalidSidecar,
    Operational,
}

fn verify(arguments: VerifyArgs) -> Result<Completed, Failure> {
    let result = verify_inner(&arguments);
    result.map_err(|(kind, error)| Failure {
        arguments,
        kind,
        error,
    })
}

fn verify_inner(arguments: &VerifyArgs) -> Result<Completed, (FailureKind, String)> {
    let sidecar_file = File::open(&arguments.sidecar)
        .map_err(|error| operational("cannot open sidecar", error))?;
    let sidecar_len = sidecar_file
        .metadata()
        .map_err(|error| operational("cannot inspect sidecar", error))?
        .len();
    if sidecar_len > arguments.max_sidecar_bytes {
        return Err((
            FailureKind::InvalidSidecar,
            format!(
                "sidecar is {sidecar_len} bytes, exceeding the configured {}-byte limit",
                arguments.max_sidecar_bytes
            ),
        ));
    }

    let read = Sidecar::read(sidecar_file, sidecar_limits())
        .map_err(|error| (FailureKind::InvalidSidecar, error.to_string()))?;
    let mut source =
        File::open(&arguments.source).map_err(|error| operational("cannot open source", error))?;
    let mut source_report = verify::source_file(&mut source, &read.sidecar)
        .map_err(|error| operational("cannot verify source", error))?;
    let location = if arguments.locate_displaced {
        Some(
            verify::locate_displaced_file(
                &mut source,
                &read.sidecar,
                &mut source_report,
                LocateOptions::new(arguments.max_locate_targets),
            )
            .map_err(|error| operational("cannot locate displaced chunks", error))?,
        )
    } else {
        None
    };

    let state = source_report.state;
    Ok(Completed {
        json: arguments.json,
        state,
        report: VerificationReport::new(
            &arguments.source,
            &arguments.sidecar,
            &read.sidecar,
            &read.damage,
            source_report,
            location,
        ),
    })
}

fn operational(context: &str, error: impl std::fmt::Display) -> (FailureKind, String) {
    (FailureKind::Operational, format!("{context}: {error}"))
}

const fn sidecar_limits() -> ReadLimits {
    let max_payload_len = MAX_CHUNK_SIZE as u64 + recovery_chunk::PAYLOAD_HEADER_LEN as u64;
    ReadLimits {
        record: DecodeLimits::new(MAX_HEADER_LEN, max_payload_len),
        assembly: AssemblyLimits {
            max_records: MAX_RECORDS,
            max_unknown_optional_records: MAX_UNKNOWN_OPTIONAL_RECORDS,
            max_superblock_copies: MAX_COPIES,
            max_creator_copies: MAX_COPIES,
            metadata: metadata::AssemblyLimits::new(
                MAX_METADATA_RECORDS,
                digest_page::AssemblyLimits::new(LEOPARD_FIELD_ORDER - 1, MAX_TABLE_PAGES),
                rolling_page::AssemblyLimits::new(LEOPARD_FIELD_ORDER - 1, MAX_TABLE_PAGES),
            ),
            recovery: recovery_set::AssemblyLimits::new(MAX_RECORDS, MAX_SHARDS),
        },
        max_damage_events: MAX_DAMAGE_EVENTS,
        max_unrecognized_bytes: MAX_UNRECOGNIZED_BYTES,
    }
}
