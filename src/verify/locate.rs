//! Rolling scans for intact data chunks at noncanonical source offsets.

use super::{
    ChunkState, Error, Report, increment, recompute_report, validate_report, with_stable_file,
};
use crate::rolling::{Locator, ScanSummary, Target};
use crate::sidecar::Sidecar;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::ops::ControlFlow;

/// Resource bound for an optional displaced-chunk scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocateOptions {
    pub max_targets: usize,
}

impl LocateOptions {
    #[must_use]
    pub const fn new(max_targets: usize) -> Self {
        Self { max_targets }
    }
}

/// Work performed and chunks recovered by one displaced-chunk scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocationSummary {
    pub eligible_chunks: u32,
    pub located_chunks: u32,
    pub scan: ScanSummary,
}

/// Refines an expected-offset report by finding intact full chunks elsewhere.
///
/// Only chunks previously classified as [`ChunkState::Corrupt`] or
/// [`ChunkState::Missing`] become rolling targets. Unreadable chunks remain
/// erasures because a sequential rolling scan is not able to skip their I/O
/// failures reliably. The short final data chunk has no stored rolling value
/// and is likewise ineligible.
///
/// Matches are held separately until the complete scan succeeds and the
/// source length is rechecked. The report is therefore unchanged on error.
/// Multiple expected chunks with identical content may safely reuse the same
/// strongly confirmed physical bytes.
///
/// # Errors
///
/// Returns an error if the report does not belong to this sidecar, its public
/// structure is inconsistent, the source length changed since verification,
/// the target bound is exceeded, source positioning or scanning fails, or a
/// formerly bad chunk now matches at its canonical offset.
pub fn locate_displaced<R: Read + Seek>(
    reader: &mut R,
    sidecar: &Sidecar,
    report: &mut Report,
    options: LocateOptions,
) -> Result<LocationSummary, Error> {
    validate_report(sidecar, report)?;
    let geometry = sidecar.metadata.manifest.geometry();
    let before = reader.seek(SeekFrom::End(0)).map_err(Error::SourceSeek)?;
    if before != report.observed_source_len {
        return Err(Error::SourceChanged {
            before: report.observed_source_len,
            after: before,
        });
    }

    let targets = location_targets(sidecar, report)?;
    let eligible_chunks = u32::try_from(targets.len()).map_err(|_| Error::CountUnrepresentable)?;
    let locator = Locator::new(targets, options.max_targets).map_err(Error::Rolling)?;
    let mut locations = vec![None; report.chunks.len()];
    let mut remaining = eligible_chunks;
    let mut canonical_match = false;
    reader.seek(SeekFrom::Start(0)).map_err(Error::SourceSeek)?;
    let scan = locator
        .scan(reader, geometry.chunk_size, |found| {
            for index in found.chunk_indices {
                let Ok(slot_index) = usize::try_from(index) else {
                    continue;
                };
                let Some(slot) = locations.get_mut(slot_index) else {
                    continue;
                };
                if slot.is_some() {
                    continue;
                }
                let Some(layout) = geometry.data_chunk_layout(index) else {
                    continue;
                };
                if found.offset == layout.offset {
                    canonical_match = true;
                    return ControlFlow::Break(());
                }
                *slot = Some(found.offset);
                remaining = remaining.saturating_sub(1);
            }
            if remaining == 0 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .map_err(Error::Rolling)?;
    if canonical_match {
        return Err(Error::SourceChangedDuringLocation);
    }
    let after = reader.seek(SeekFrom::End(0)).map_err(Error::SourceSeek)?;
    if after != before {
        return Err(Error::SourceChanged { before, after });
    }

    let located_chunks = apply_locations(report, locations)?;
    recompute_report(report)?;
    Ok(LocationSummary {
        eligible_chunks,
        located_chunks,
        scan,
    })
}

/// Locates displaced chunks in an open file while checking for concurrent
/// metadata-visible mutation.
///
/// This is the file-native counterpart to [`locate_displaced`] and should be
/// used when the source is a real file.
///
/// # Errors
///
/// Returns the errors documented by [`locate_displaced`], a file metadata
/// error, or [`Error::SourceMetadataChanged`] when the file changes during the
/// scan.
pub fn locate_displaced_file(
    file: &mut File,
    sidecar: &Sidecar,
    report: &mut Report,
    options: LocateOptions,
) -> Result<LocationSummary, Error> {
    with_stable_file(file, |file| {
        locate_displaced(file, sidecar, report, options)
    })
}

fn location_targets(sidecar: &Sidecar, report: &Report) -> Result<Vec<Target>, Error> {
    let geometry = sidecar.metadata.manifest.geometry();
    if sidecar.metadata.rolling_fingerprints.value_count != geometry.full_data_chunks()
        || sidecar.metadata.data_digests.digest_count != u64::from(geometry.data_chunks)
    {
        return Err(Error::FingerprintTableCountMismatch);
    }
    let full_chunks =
        usize::try_from(geometry.full_data_chunks()).map_err(|_| Error::CountUnrepresentable)?;
    let targets = sidecar
        .metadata
        .rolling_fingerprints
        .values()
        .zip(sidecar.metadata.data_digests.digests().copied())
        .zip(report.chunks.iter())
        .take(full_chunks)
        .filter(|(_, chunk)| matches!(chunk.state, ChunkState::Corrupt | ChunkState::Missing))
        .map(|((rolling, strong), chunk)| Target {
            chunk_index: chunk.index,
            rolling,
            strong,
        })
        .collect();
    Ok(targets)
}

fn apply_locations(report: &mut Report, locations: Vec<Option<u64>>) -> Result<u32, Error> {
    if locations.len() != report.chunks.len() {
        return Err(Error::ReportStructureMismatch);
    }
    let mut located = 0_u32;
    for (chunk, offset) in report.chunks.iter_mut().zip(locations) {
        if let Some(offset) = offset {
            chunk.state = ChunkState::UnexpectedlyLocated { offset };
            located = increment(located)?;
        }
    }
    Ok(located)
}
