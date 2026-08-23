use bitrot::create::{self, Options};
use bitrot::creator::Creator;
use bitrot::geometry::{ChunkSize, MIN_CHUNK_SIZE, Redundancy};
use serde_json::Value;
use std::fs::{self, File};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bitrot-cli-verify-test-{}-{id}",
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
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Fixture {
    directory: TestDirectory,
    source: PathBuf,
    sidecar: PathBuf,
    original: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let directory = TestDirectory::new();
        let source = directory.join("movie.bin");
        let sidecar = directory.join("movie.bin.bitrot");
        let original = two_distinct_chunks();
        fs::write(&source, &original).unwrap();

        let options = Options::new(
            ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap(),
            Redundancy::new(1, 2).unwrap(),
            4_096,
            Creator::new("bitrot-test", "1").unwrap(),
        );
        let protection = create::build(&mut Cursor::new(&original), &options).unwrap();
        protection
            .write_canonical(&mut File::create(&sidecar).unwrap())
            .unwrap();

        Self {
            directory,
            source,
            sidecar,
            original,
        }
    }

    fn run(&self, arguments: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bitrot"));
        command
            .arg("verify")
            .arg(&self.source)
            .arg(&self.sidecar)
            .args(arguments)
            .output()
            .unwrap()
    }
}

#[test]
fn reports_intact_source_in_human_and_json_formats() {
    let fixture = Fixture::new();

    let human = fixture.run(&[]);
    assert_eq!(human.status.code(), Some(0));
    let stdout = String::from_utf8(human.stdout).unwrap();
    assert!(stdout.contains("status: intact"));
    assert!(stdout.contains("data chunks: 2 good"));
    assert!(human.stderr.is_empty());

    let json = fixture.run(&["--json"]);
    assert_eq!(json.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["command"], "verify");
    assert_eq!(report["status"], "intact");
    assert_eq!(report["source"]["digest"], "match");
    assert_eq!(report["source"]["good_chunks"], 2);
    assert_eq!(report["source"]["chunks"][0]["state"], "good");
    assert_eq!(report["recovery"]["available_chunks"], 1);
}

#[test]
fn exit_statuses_distinguish_repairable_and_unrepairable_damage() {
    let fixture = Fixture::new();
    let mut damaged = fixture.original.clone();
    damaged[0] ^= 1;
    fs::write(&fixture.source, &damaged).unwrap();

    let repairable = fixture.run(&["--json"]);
    assert_eq!(repairable.status.code(), Some(10));
    let report: Value = serde_json::from_slice(&repairable.stdout).unwrap();
    assert_eq!(report["status"], "repairable");
    assert_eq!(report["source"]["corrupt_chunks"], 1);
    assert_eq!(report["source"]["required_recovery_chunks"], 1);

    damaged[usize::try_from(MIN_CHUNK_SIZE).unwrap()] ^= 1;
    fs::write(&fixture.source, damaged).unwrap();
    let unrepairable = fixture.run(&["--json"]);
    assert_eq!(unrepairable.status.code(), Some(11));
    let report: Value = serde_json::from_slice(&unrepairable.stdout).unwrap();
    assert_eq!(report["status"], "unrepairable");
    assert_eq!(report["source"]["corrupt_chunks"], 2);
}

#[test]
fn displaced_scan_refines_the_report_without_trusting_the_crc() {
    let fixture = Fixture::new();
    let split = usize::try_from(MIN_CHUNK_SIZE).unwrap();
    let mut reordered = fixture.original[split..].to_vec();
    reordered.extend_from_slice(&fixture.original[..split]);
    fs::write(&fixture.source, reordered).unwrap();

    let expected_offsets = fixture.run(&["--json"]);
    assert_eq!(expected_offsets.status.code(), Some(11));

    let located = fixture.run(&["--json", "--locate-displaced"]);
    assert_eq!(located.status.code(), Some(10));
    let report: Value = serde_json::from_slice(&located.stdout).unwrap();
    assert_eq!(report["status"], "repairable");
    assert_eq!(report["source"]["unexpectedly_located_chunks"], 2);
    assert_eq!(report["source"]["required_recovery_chunks"], 0);
    assert_eq!(report["displaced_scan"]["located_chunks"], 2);
}

#[test]
fn json_errors_distinguish_invalid_sidecars_and_operational_failures() {
    let fixture = Fixture::new();
    fs::write(&fixture.sidecar, b"not a sidecar").unwrap();

    let invalid = fixture.run(&["--json"]);
    assert_eq!(invalid.status.code(), Some(12));
    let report: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(report["status"], "invalid_sidecar");
    assert!(invalid.stderr.is_empty());

    let second = Fixture::new();
    let missing = second.directory.join("missing-source");
    let operational = run_paths(&missing, &second.sidecar, &["--json"]);
    assert_eq!(operational.status.code(), Some(13));
    let report: Value = serde_json::from_slice(&operational.stdout).unwrap();
    assert_eq!(report["status"], "operational_failure");
}

#[test]
fn rejects_sidecars_above_the_configured_memory_bound() {
    let fixture = Fixture::new();
    let sidecar_len = fs::metadata(&fixture.sidecar).unwrap().len();
    let limit = (sidecar_len - 1).to_string();

    let output = fixture.run(&["--json", "--max-sidecar-bytes", &limit]);
    assert_eq!(output.status.code(), Some(12));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "invalid_sidecar");
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("exceeding the configured")
    );
}

fn run_paths(source: &Path, sidecar: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bitrot"))
        .arg("verify")
        .arg(source)
        .arg(sidecar)
        .args(arguments)
        .output()
        .unwrap()
}

fn two_distinct_chunks() -> Vec<u8> {
    let chunk_len = usize::try_from(MIN_CHUNK_SIZE).unwrap();
    let mut bytes = vec![0_u8; chunk_len * 2];
    for (index, byte) in bytes.iter_mut().take(chunk_len).enumerate() {
        *byte = u8::try_from(index % 251).unwrap();
    }
    for (index, byte) in bytes.iter_mut().skip(chunk_len).enumerate() {
        *byte = u8::try_from((index * 3 + 17) % 251).unwrap();
    }
    bytes
}
