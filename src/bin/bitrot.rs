#[path = "bitrot/verify.rs"]
mod verify;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Completely verify a source and its recovery sidecar.
    Verify(VerifyArgs),
}

#[derive(Debug, clap::Args)]
struct VerifyArgs {
    /// Source file to verify.
    source: PathBuf,

    /// Bitrot recovery sidecar for the source.
    sidecar: PathBuf,

    /// Emit one versioned JSON document instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Scan for strongly confirmed chunks at unexpected offsets.
    #[arg(long)]
    locate_displaced: bool,

    /// Maximum displaced chunks indexed during a scan.
    #[arg(
        long,
        default_value_t = verify::DEFAULT_MAX_LOCATE_TARGETS,
        requires = "locate_displaced"
    )]
    max_locate_targets: usize,

    /// Maximum sidecar size accepted into memory, in bytes.
    #[arg(long, default_value_t = verify::DEFAULT_MAX_SIDECAR_BYTES, value_parser = clap::value_parser!(u64).range(1..))]
    max_sidecar_bytes: u64,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Verify(arguments) => verify::run(arguments),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn requires_a_subcommand() {
        let error = Cli::try_parse_from(["bitrot"]).unwrap_err();
        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn locate_limit_requires_the_scan() {
        let error = Cli::try_parse_from([
            "bitrot",
            "verify",
            "source",
            "sidecar",
            "--max-locate-targets",
            "4",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }
}
