//! Bounded-window reconstruction into a fresh seekable destination.

mod filesystem;
mod replace;

pub use filesystem::{
    OutputVerificationError, PublishError, PublishOptions, PublishOutcome, PublishSummary,
    PublishedVerificationError, publish,
};
pub use replace::{ReplaceError, ReplaceOutcome, ReplaceSummary, damaged_backup_path, replace};

use crate::coding::{self, CodingWindow, WindowDecoder};
use crate::geometry::Geometry;
use crate::sidecar::Sidecar;
use crate::verify::{self, ChunkState, Report, SourceDigestState, SourceState};
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};

/// Resource choices for reconstructing one source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options {
    pub coding_window_bytes: usize,
}

impl Options {
    #[must_use]
    pub const fn new(coding_window_bytes: usize) -> Self {
        Self {
            coding_window_bytes,
        }
    }
}

/// Successful result of reconstructing and verifying a destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub bytes_written: u64,
    pub copied_data_chunks: u32,
    pub reconstructed_data_chunks: u32,
}

/// Reconstructs a verified source into an empty seekable destination.
///
/// Good chunks are copied from their canonical offsets, unexpectedly located
/// chunks are copied from their strongly confirmed offsets, and remaining
/// chunks are restored from authenticated recovery shards. Coding proceeds in
/// bounded windows and the short final chunk is written without its coding
/// padding. The damaged source is never modified.
///
/// The destination must be empty and must not alias the source. It may contain
/// partial data after an error and should therefore be an unpublished
/// temporary object. Before success is returned, it is flushed, rewound, and
/// completely verified against the sidecar, including the whole-source digest.
///
/// # Errors
///
/// Returns an error if the report or coding options are invalid, repair is not
/// needed or possible, the source changed length, the destination is nonempty,
/// source or destination I/O fails, decoding fails, or final verification does
/// not produce an intact source.
pub fn reconstruct<S, D>(
    source: &mut S,
    destination: &mut D,
    sidecar: &Sidecar,
    report: &Report,
    options: Options,
) -> Result<Summary, Error>
where
    S: Read + Seek,
    D: Read + Write + Seek,
{
    let counts = validate_repair(sidecar, report)?;
    let geometry = sidecar.metadata.manifest.geometry();
    let source_len = source.seek(SeekFrom::End(0)).map_err(Error::SourceSeek)?;
    if source_len != report.observed_source_len {
        return Err(Error::SourceChanged {
            before: report.observed_source_len,
            after: source_len,
        });
    }
    let destination_len = destination
        .seek(SeekFrom::End(0))
        .map_err(Error::DestinationSeek)?;
    if destination_len != 0 {
        return Err(Error::DestinationNotEmpty(destination_len));
    }

    let coding = CodingWindow::new(geometry, options.coding_window_bytes).map_err(Error::Coding)?;
    let mut decoder = if counts.unavailable_data_chunks() == 0 {
        None
    } else {
        Some(coding.decoder().map_err(Error::Coding)?)
    };
    reconstruct_windows(
        source,
        destination,
        sidecar,
        report,
        coding,
        decoder.as_mut(),
    )?;

    let final_source_len = source.seek(SeekFrom::End(0)).map_err(Error::SourceSeek)?;
    if final_source_len != source_len {
        return Err(Error::SourceChanged {
            before: source_len,
            after: final_source_len,
        });
    }
    destination.flush().map_err(Error::DestinationFlush)?;
    destination
        .seek(SeekFrom::Start(0))
        .map_err(Error::DestinationSeek)?;
    let verified = verify::source(destination, sidecar).map_err(Error::OutputVerification)?;
    if !verified.is_intact() {
        return Err(Error::OutputMismatch {
            state: verified.state,
            source_digest: verified.source_digest,
            unavailable_data_chunks: verified.unavailable_data_chunks,
        });
    }

    Ok(Summary {
        bytes_written: geometry.source_len,
        copied_data_chunks: counts.available_data_chunks(),
        reconstructed_data_chunks: counts.unavailable_data_chunks(),
    })
}

fn validate_repair(sidecar: &Sidecar, report: &Report) -> Result<verify::ValidatedReport, Error> {
    let counts = verify::validate_report(sidecar, report).map_err(Error::Report)?;
    match report.state {
        SourceState::Intact => return Err(Error::SourceIntact),
        SourceState::Unrepairable => return Err(Error::Unrepairable),
        SourceState::Repairable => {}
    }
    Ok(counts)
}

fn reconstruct_windows<S, D>(
    source: &mut S,
    destination: &mut D,
    sidecar: &Sidecar,
    report: &Report,
    coding: CodingWindow,
    mut decoder: Option<&mut WindowDecoder>,
) -> Result<(), Error>
where
    S: Read + Seek,
    D: Write + Seek,
{
    let geometry = sidecar.metadata.manifest.geometry();
    let chunk_bytes =
        usize::try_from(geometry.chunk_size.bytes()).map_err(|_| Error::LengthUnrepresentable)?;
    for window_offset in (0..chunk_bytes).step_by(coding.bytes()) {
        let originals = read_available_windows(
            source,
            destination,
            report,
            geometry,
            window_offset,
            coding.bytes(),
        )?;
        if let Some(decoder) = decoder.as_deref_mut() {
            let recovery = recovery_windows(sidecar, window_offset, coding.bytes())?;
            decoder
                .restore(
                    originals
                        .iter()
                        .map(|(index, bytes)| (*index, bytes.as_slice())),
                    recovery,
                    |index, bytes| {
                        write_output_window(destination, geometry, index, window_offset, bytes)
                    },
                )
                .map_err(Error::Coding)?;
        }
    }
    Ok(())
}

fn read_available_windows<S, D>(
    source: &mut S,
    destination: &mut D,
    report: &Report,
    geometry: Geometry,
    window_offset: usize,
    window_bytes: usize,
) -> Result<Vec<(usize, Vec<u8>)>, Error>
where
    S: Read + Seek,
    D: Write + Seek,
{
    let capacity = usize::try_from(
        report
            .good_data_chunks
            .checked_add(report.unexpectedly_located_data_chunks)
            .ok_or(Error::CountUnrepresentable)?,
    )
    .map_err(|_| Error::CountUnrepresentable)?;
    let mut originals = Vec::new();
    originals
        .try_reserve_exact(capacity)
        .map_err(Error::WorkspaceAllocation)?;
    for chunk in &report.chunks {
        let layout = geometry
            .data_chunk_layout(chunk.index)
            .ok_or(Error::Report(verify::Error::ReportStructureMismatch))?;
        let base = match chunk.state {
            ChunkState::Good => layout.offset,
            ChunkState::UnexpectedlyLocated { offset } => offset,
            ChunkState::Corrupt | ChunkState::Missing | ChunkState::Unreadable(_) => continue,
        };
        let mut bytes = vec![0_u8; window_bytes];
        let available = window_available(layout.len, window_offset, window_bytes)?;
        if available != 0 {
            let offset = base
                .checked_add(u64::try_from(window_offset).map_err(|_| Error::SourceOffsetOverflow)?)
                .ok_or(Error::SourceOffsetOverflow)?;
            source
                .seek(SeekFrom::Start(offset))
                .map_err(Error::SourceSeek)?;
            source
                .read_exact(&mut bytes[..available])
                .map_err(Error::SourceRead)?;
            let index = usize::try_from(chunk.index).map_err(|_| Error::CountUnrepresentable)?;
            write_output_window(destination, geometry, index, window_offset, &bytes)
                .map_err(Error::DestinationWrite)?;
        }
        originals.push((
            usize::try_from(chunk.index).map_err(|_| Error::CountUnrepresentable)?,
            bytes,
        ));
    }
    Ok(originals)
}

fn recovery_windows(
    sidecar: &Sidecar,
    window_offset: usize,
    window_bytes: usize,
) -> Result<Vec<(usize, &[u8])>, Error> {
    let end = window_offset
        .checked_add(window_bytes)
        .ok_or(Error::RecoveryOffsetOverflow)?;
    let mut windows = Vec::new();
    windows
        .try_reserve_exact(sidecar.recovery.available_count())
        .map_err(Error::WorkspaceAllocation)?;
    for chunk in sidecar.recovery.available() {
        let bytes = chunk
            .bytes()
            .get(window_offset..end)
            .ok_or(Error::RecoveryOffsetOverflow)?;
        windows.push((
            usize::try_from(chunk.recovery_index()).map_err(|_| Error::CountUnrepresentable)?,
            bytes,
        ));
    }
    Ok(windows)
}

fn write_output_window<D: Write + Seek>(
    destination: &mut D,
    geometry: Geometry,
    data_index: usize,
    window_offset: usize,
    bytes: &[u8],
) -> io::Result<()> {
    let index = u32::try_from(data_index)
        .map_err(|_| io::Error::other("data index is not representable"))?;
    let layout = geometry.data_chunk_layout(index).ok_or_else(|| {
        io::Error::other(format!("data chunk index {index} is outside the geometry"))
    })?;
    let available = window_available(layout.len, window_offset, bytes.len())
        .map_err(|error| io::Error::other(error.to_string()))?;
    if available == 0 {
        return Ok(());
    }
    let offset = u64::try_from(window_offset)
        .map_err(|_| Error::SourceOffsetOverflow)
        .and_then(|window_offset| {
            layout
                .offset
                .checked_add(window_offset)
                .ok_or(Error::SourceOffsetOverflow)
        })
        .map_err(|error| io::Error::other(error.to_string()))?;
    destination.seek(SeekFrom::Start(offset))?;
    destination.write_all(&bytes[..available])
}

fn window_available(
    expected_len: u32,
    window_offset: usize,
    window_bytes: usize,
) -> Result<usize, Error> {
    let expected_len = usize::try_from(expected_len).map_err(|_| Error::LengthUnrepresentable)?;
    Ok(expected_len.saturating_sub(window_offset).min(window_bytes))
}

#[derive(Debug)]
pub enum Error {
    Report(verify::Error),
    SourceIntact,
    Unrepairable,
    DestinationNotEmpty(u64),
    SourceChanged {
        before: u64,
        after: u64,
    },
    SourceOffsetOverflow,
    RecoveryOffsetOverflow,
    LengthUnrepresentable,
    CountUnrepresentable,
    WorkspaceAllocation(std::collections::TryReserveError),
    Coding(coding::Error),
    SourceSeek(io::Error),
    SourceRead(io::Error),
    DestinationSeek(io::Error),
    DestinationWrite(io::Error),
    DestinationFlush(io::Error),
    OutputVerification(verify::Error),
    OutputMismatch {
        state: SourceState,
        source_digest: SourceDigestState,
        unavailable_data_chunks: u32,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Report(error) => write!(formatter, "verification report is invalid: {error}"),
            Self::SourceIntact => formatter.write_str("source is already intact"),
            Self::Unrepairable => {
                formatter.write_str("verification report does not describe a repairable source")
            }
            Self::DestinationNotEmpty(length) => {
                write!(
                    formatter,
                    "repair destination is not empty ({length} bytes)"
                )
            }
            Self::SourceChanged { before, after } => write!(
                formatter,
                "source length changed before or during repair from {before} to {after} bytes"
            ),
            Self::SourceOffsetOverflow => formatter.write_str("source offset overflows u64"),
            Self::RecoveryOffsetOverflow => {
                formatter.write_str("recovery window is outside its authenticated chunk")
            }
            Self::LengthUnrepresentable => {
                formatter.write_str("repair length is not representable")
            }
            Self::CountUnrepresentable => formatter.write_str("repair count is not representable"),
            Self::WorkspaceAllocation(error) => {
                write!(formatter, "cannot reserve repair workspace: {error}")
            }
            Self::Coding(error) => write!(formatter, "recovery decoding failed: {error}"),
            Self::SourceSeek(error) => write!(formatter, "source positioning failed: {error}"),
            Self::SourceRead(error) => write!(formatter, "source read failed: {error}"),
            Self::DestinationSeek(error) => {
                write!(formatter, "repair destination positioning failed: {error}")
            }
            Self::DestinationWrite(error) => {
                write!(formatter, "repair destination write failed: {error}")
            }
            Self::DestinationFlush(error) => {
                write!(formatter, "repair destination flush failed: {error}")
            }
            Self::OutputVerification(error) => {
                write!(formatter, "repaired output verification failed: {error}")
            }
            Self::OutputMismatch {
                state,
                source_digest,
                unavailable_data_chunks,
            } => write!(
                formatter,
                "repaired output is {state:?} with digest {source_digest:?} and {unavailable_data_chunks} unavailable chunks"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Report(error) | Self::OutputVerification(error) => Some(error),
            Self::WorkspaceAllocation(error) => Some(error),
            Self::Coding(error) => Some(error),
            Self::SourceSeek(error)
            | Self::SourceRead(error)
            | Self::DestinationSeek(error)
            | Self::DestinationWrite(error)
            | Self::DestinationFlush(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{self, Options as CreateOptions};
    use crate::creator::Creator;
    use crate::geometry::{ChunkSize, MIN_CHUNK_SIZE, Redundancy};
    use crate::recovery_set::{AssemblyLimits, RecoverySet};
    use crate::verify::{LocateOptions, locate_displaced};
    use std::io::Cursor;

    const CHUNK_BYTES: usize = MIN_CHUNK_SIZE as usize;
    const WINDOW_BYTES: usize = 1_024;

    fn original(chunk_count: usize) -> Vec<u8> {
        (0..chunk_count)
            .flat_map(|index| {
                let value = u8::try_from(index.wrapping_mul(53).wrapping_add(17)).unwrap();
                vec![value; CHUNK_BYTES]
            })
            .collect()
    }

    fn sidecar(bytes: &[u8], redundancy: Redundancy) -> Sidecar {
        let options = CreateOptions::new(
            ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap(),
            redundancy,
            WINDOW_BYTES,
            Creator::new("bitrot", "test").unwrap(),
        );
        create::build(&mut Cursor::new(bytes), &options).unwrap()
    }

    fn repair_options() -> Options {
        Options::new(WINDOW_BYTES)
    }

    #[test]
    fn repairs_every_supported_small_data_erasure_combination() {
        let original = original(4);
        let sidecar = sidecar(&original, Redundancy::new(1, 2).unwrap());

        for mask in 1_u32..16 {
            if mask.count_ones() > 2 {
                continue;
            }
            let mut damaged = original.clone();
            for index in 0..4 {
                if mask & (1 << index) != 0 {
                    damaged[index * CHUNK_BYTES + 31] ^= 1;
                }
            }
            let report = verify::source(&mut Cursor::new(&damaged), &sidecar).unwrap();
            let mut output = Cursor::new(Vec::new());
            let summary = reconstruct(
                &mut Cursor::new(damaged),
                &mut output,
                &sidecar,
                &report,
                repair_options(),
            )
            .unwrap();

            assert_eq!(summary.reconstructed_data_chunks, mask.count_ones());
            assert_eq!(output.into_inner(), original);
        }
    }

    #[test]
    fn repairs_with_mixed_data_and_recovery_loss() {
        let original = original(4);
        let mut sidecar = sidecar(&original, Redundancy::new(1, 2).unwrap());
        let manifest = sidecar.metadata.manifest;
        let records: Vec<_> = sidecar
            .recovery
            .available()
            .skip(1)
            .map(|chunk| chunk.to_record(manifest).unwrap())
            .collect();
        sidecar.recovery = RecoverySet::assemble(
            &records,
            manifest,
            sidecar.metadata.recovery_digests.digests().copied(),
            AssemblyLimits::new(2, manifest.geometry().recovery_chunks),
        )
        .unwrap();
        let mut damaged = original.clone();
        damaged[CHUNK_BYTES + 9] ^= 1;
        let report = verify::source(&mut Cursor::new(&damaged), &sidecar).unwrap();
        let mut output = Cursor::new(Vec::new());

        reconstruct(
            &mut Cursor::new(damaged),
            &mut output,
            &sidecar,
            &report,
            repair_options(),
        )
        .unwrap();

        assert_eq!(output.into_inner(), original);
    }

    #[test]
    fn copies_displaced_chunks_without_recovery() {
        let original = original(3);
        let mut sidecar = sidecar(&original, Redundancy::new(1, 3).unwrap());
        let manifest = sidecar.metadata.manifest;
        sidecar.recovery = RecoverySet::assemble(
            &[],
            manifest,
            sidecar.metadata.recovery_digests.digests().copied(),
            AssemblyLimits::new(1, manifest.geometry().recovery_chunks),
        )
        .unwrap();
        let mut reordered = original[CHUNK_BYTES..].to_vec();
        reordered.extend_from_slice(&original[..CHUNK_BYTES]);
        let mut source = Cursor::new(reordered);
        let mut report = verify::source(&mut source, &sidecar).unwrap();
        locate_displaced(&mut source, &sidecar, &mut report, LocateOptions::new(3)).unwrap();
        let mut output = Cursor::new(Vec::new());

        let summary = reconstruct(
            &mut source,
            &mut output,
            &sidecar,
            &report,
            repair_options(),
        )
        .unwrap();

        assert_eq!(summary.copied_data_chunks, 3);
        assert_eq!(summary.reconstructed_data_chunks, 0);
        assert_eq!(output.into_inner(), original);
    }

    #[test]
    fn removes_trailing_data_without_recovery() {
        let original = original(3);
        let mut sidecar = sidecar(&original, Redundancy::new(1, 3).unwrap());
        let manifest = sidecar.metadata.manifest;
        sidecar.recovery = RecoverySet::assemble(
            &[],
            manifest,
            sidecar.metadata.recovery_digests.digests().copied(),
            AssemblyLimits::new(1, manifest.geometry().recovery_chunks),
        )
        .unwrap();
        let mut extended = original.clone();
        extended.extend_from_slice(b"discard this trailer");
        let report = verify::source(&mut Cursor::new(&extended), &sidecar).unwrap();
        let mut output = Cursor::new(Vec::new());

        let summary = reconstruct(
            &mut Cursor::new(extended),
            &mut output,
            &sidecar,
            &report,
            repair_options(),
        )
        .unwrap();

        assert_eq!(summary.reconstructed_data_chunks, 0);
        assert_eq!(output.into_inner(), original);
    }

    #[test]
    fn reconstructs_a_short_final_chunk_without_padding() {
        let mut original = original(2);
        original.extend_from_slice(b"short final data");
        let sidecar = sidecar(&original, Redundancy::new(1, 3).unwrap());
        let mut damaged = original.clone();
        damaged.truncate(CHUNK_BYTES * 2);
        let report = verify::source(&mut Cursor::new(&damaged), &sidecar).unwrap();
        let mut output = Cursor::new(Vec::new());

        reconstruct(
            &mut Cursor::new(damaged),
            &mut output,
            &sidecar,
            &report,
            repair_options(),
        )
        .unwrap();

        assert_eq!(output.get_ref().len(), original.len());
        assert_eq!(output.into_inner(), original);
    }

    #[test]
    fn refuses_intact_unrepairable_and_nonempty_destinations_before_writing() {
        let original = original(3);
        let sidecar = sidecar(&original, Redundancy::new(1, 3).unwrap());
        let intact = verify::source(&mut Cursor::new(&original), &sidecar).unwrap();
        let mut empty = Cursor::new(Vec::new());
        assert!(matches!(
            reconstruct(
                &mut Cursor::new(&original),
                &mut empty,
                &sidecar,
                &intact,
                repair_options()
            ),
            Err(Error::SourceIntact)
        ));
        assert!(empty.get_ref().is_empty());

        let mut badly_damaged = original.clone();
        badly_damaged[1] ^= 1;
        badly_damaged[CHUNK_BYTES + 1] ^= 1;
        let unrepairable = verify::source(&mut Cursor::new(&badly_damaged), &sidecar).unwrap();
        assert!(matches!(
            reconstruct(
                &mut Cursor::new(badly_damaged),
                &mut empty,
                &sidecar,
                &unrepairable,
                repair_options()
            ),
            Err(Error::Unrepairable)
        ));

        let mut damaged = original.clone();
        damaged[1] ^= 1;
        let report = verify::source(&mut Cursor::new(&damaged), &sidecar).unwrap();
        let mut nonempty = Cursor::new(b"preserve me".to_vec());
        assert!(matches!(
            reconstruct(
                &mut Cursor::new(damaged),
                &mut nonempty,
                &sidecar,
                &report,
                repair_options()
            ),
            Err(Error::DestinationNotEmpty(11))
        ));
        assert_eq!(nonempty.into_inner(), b"preserve me");
    }

    struct FailingReader {
        inner: Cursor<Vec<u8>>,
        fail_at: u64,
    }

    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.inner.position() >= self.fail_at {
                return Err(io::Error::other("injected source failure"));
            }
            self.inner.read(buffer)
        }
    }

    impl Seek for FailingReader {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    struct FailingDestination {
        inner: Cursor<Vec<u8>>,
    }

    impl Read for FailingDestination {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buffer)
        }
    }

    impl Write for FailingDestination {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected destination failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Seek for FailingDestination {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn propagates_source_and_destination_failures() {
        let original = original(3);
        let sidecar = sidecar(&original, Redundancy::new(1, 3).unwrap());
        let mut damaged = original.clone();
        damaged[CHUNK_BYTES + 1] ^= 1;
        let report = verify::source(&mut Cursor::new(&damaged), &sidecar).unwrap();
        let mut failing_source = FailingReader {
            inner: Cursor::new(damaged.clone()),
            fail_at: 0,
        };
        assert!(matches!(
            reconstruct(
                &mut failing_source,
                &mut Cursor::new(Vec::new()),
                &sidecar,
                &report,
                repair_options()
            ),
            Err(Error::SourceRead(_))
        ));

        assert!(matches!(
            reconstruct(
                &mut Cursor::new(damaged),
                &mut FailingDestination {
                    inner: Cursor::new(Vec::new())
                },
                &sidecar,
                &report,
                repair_options()
            ),
            Err(Error::DestinationWrite(_))
        ));
    }

    struct CorruptingDestination {
        inner: Cursor<Vec<u8>>,
        corrupted: bool,
    }

    impl Read for CorruptingDestination {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buffer)
        }
    }

    impl Write for CorruptingDestination {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let mut bytes = buffer.to_vec();
            if !self.corrupted && !bytes.is_empty() {
                bytes[0] ^= 1;
                self.corrupted = true;
            }
            self.inner.write(&bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Seek for CorruptingDestination {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn rejects_decoder_or_storage_output_that_fails_final_verification() {
        let original = original(3);
        let sidecar = sidecar(&original, Redundancy::new(1, 3).unwrap());
        let mut damaged = original.clone();
        damaged[CHUNK_BYTES + 1] ^= 1;
        let report = verify::source(&mut Cursor::new(&damaged), &sidecar).unwrap();
        let mut output = CorruptingDestination {
            inner: Cursor::new(Vec::new()),
            corrupted: false,
        };

        assert!(matches!(
            reconstruct(
                &mut Cursor::new(damaged),
                &mut output,
                &sidecar,
                &report,
                repair_options()
            ),
            Err(Error::OutputMismatch { .. })
        ));
    }

    #[test]
    fn source_mutation_after_verification_cannot_be_accepted() {
        let original = original(3);
        let sidecar = sidecar(&original, Redundancy::new(1, 3).unwrap());
        let mut damaged = original.clone();
        damaged[1] ^= 1;
        let report = verify::source(&mut Cursor::new(&damaged), &sidecar).unwrap();
        damaged[CHUNK_BYTES + 7] ^= 1;

        assert!(matches!(
            reconstruct(
                &mut Cursor::new(damaged),
                &mut Cursor::new(Vec::new()),
                &sidecar,
                &report,
                repair_options()
            ),
            Err(Error::OutputMismatch { .. })
        ));
    }
}
