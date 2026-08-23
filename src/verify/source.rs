//! Verification of source data at canonical chunk offsets.

use super::{ChunkCounts, ChunkReport, ChunkState, Error, Report, SourceDigestState};
use crate::digest::Digest;
use crate::fingerprint;
use crate::sidecar::Sidecar;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

/// Verifies a seekable source against an already authenticated sidecar.
///
/// Every expected chunk is read independently at its canonical offset. A read
/// failure marks that chunk unreadable and verification seeks onward, allowing
/// later chunks to be classified when the underlying reader supports it. The
/// observed source, including trailing bytes, is read completely for its
/// whole-source digest. Memory use is one data chunk plus the returned report.
///
/// Recovery records have already been physically and cryptographically
/// authenticated by [`Sidecar::read`](crate::sidecar::Sidecar::read); this
/// function incorporates their availability into repair feasibility.
///
/// # Errors
///
/// Returns an error if source positioning fails, the source length changes
/// during verification, report counts cannot be represented, or the sidecar's
/// authenticated metadata has an inconsistent data-digest count.
pub fn source<R: Read + Seek>(reader: &mut R, sidecar: &Sidecar) -> Result<Report, Error> {
    let manifest = sidecar.metadata.manifest;
    let geometry = manifest.geometry();
    let observed_source_len = reader.seek(SeekFrom::End(0)).map_err(Error::SourceSeek)?;
    let mut data = verify_data_chunks(reader, sidecar)?;

    if observed_source_len > geometry.source_len {
        reader
            .seek(SeekFrom::Start(geometry.source_len))
            .map_err(Error::SourceSeek)?;
        hash_remainder(reader, &mut data.source_hasher).map_err(Error::TrailingRead)?;
    }
    let final_source_len = reader.seek(SeekFrom::End(0)).map_err(Error::SourceSeek)?;
    if final_source_len != observed_source_len {
        return Err(Error::SourceChanged {
            before: observed_source_len,
            after: final_source_len,
        });
    }

    let source_digest = source_digest_state(&data.source_hasher, data.digest_available, sidecar);
    let available_recovery_chunks = u32::try_from(sidecar.recovery.available_count())
        .map_err(|_| Error::CountUnrepresentable)?;
    let unavailable_recovery_chunks = geometry
        .recovery_chunks
        .checked_sub(available_recovery_chunks)
        .ok_or(Error::RecoveryCountMismatch)?;
    let counts = ChunkCounts::from_chunks(&data.chunks)?;
    let state = counts.source_state(
        available_recovery_chunks,
        observed_source_len,
        geometry.source_len,
        source_digest,
    );

    Ok(Report {
        protection_set_id: manifest.protection_set_id(),
        expected_source_len: geometry.source_len,
        observed_source_len,
        source_digest,
        chunks: data.chunks,
        good_data_chunks: counts.good,
        unexpectedly_located_data_chunks: counts.unexpectedly_located,
        unavailable_data_chunks: counts.unavailable,
        available_recovery_chunks,
        unavailable_recovery_chunks,
        state,
    })
}

/// Verifies an open file and rejects metadata-visible concurrent mutation.
///
/// In addition to the length checks performed by [`source`], this snapshots
/// the file's identity, modification time, and (on Unix) status-change time
/// around the complete operation. This is the preferred entry point for real
/// files because same-length writes are otherwise invisible to a generic
/// [`Read`] + [`Seek`] interface.
///
/// The check detects ordinary concurrent filesystem writers; it is not a lock
/// and cannot provide snapshot isolation against a writer able to conceal its
/// metadata changes.
///
/// # Errors
///
/// Returns the errors documented by [`source`], a file metadata error, or
/// [`Error::SourceMetadataChanged`] when the file changed during verification.
pub fn source_file(file: &mut File, sidecar: &Sidecar) -> Result<Report, Error> {
    super::with_stable_file(file, |file| source(file, sidecar))
}

struct DataVerification {
    source_hasher: blake3::Hasher,
    digest_available: bool,
    chunks: Vec<ChunkReport>,
}

fn verify_data_chunks<R: Read + Seek>(
    reader: &mut R,
    sidecar: &Sidecar,
) -> Result<DataVerification, Error> {
    let geometry = sidecar.metadata.manifest.geometry();
    let chunk_bytes =
        usize::try_from(geometry.chunk_size.bytes()).map_err(|_| Error::LengthUnrepresentable)?;
    let mut buffer = vec![0_u8; chunk_bytes];
    let mut source_hasher = fingerprint::source_digest_hasher();
    let mut digest_available = true;
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(
            usize::try_from(geometry.data_chunks).map_err(|_| Error::CountUnrepresentable)?,
        )
        .map_err(Error::ReportAllocation)?;
    let mut expected_digests = sidecar.metadata.data_digests.digests().copied();
    for index in 0..geometry.data_chunks {
        let expected_digest = expected_digests
            .next()
            .ok_or(Error::DataDigestCountMismatch)?;
        let layout = geometry
            .data_chunk_layout(index)
            .ok_or(Error::SourceOffsetOverflow)?;
        reader
            .seek(SeekFrom::Start(layout.offset))
            .map_err(Error::SourceSeek)?;
        let expected_len_usize =
            usize::try_from(layout.len).map_err(|_| Error::LengthUnrepresentable)?;
        let read = read_chunk(
            reader,
            &mut buffer[..expected_len_usize],
            &mut source_hasher,
        );
        let (bytes_read, state) = classify_chunk(
            read,
            &buffer[..expected_len_usize],
            layout.len,
            expected_digest,
        )?;
        digest_available &= !matches!(state, ChunkState::Unreadable(_));
        chunks.push(ChunkReport {
            index,
            expected_len: layout.len,
            bytes_read,
            state,
        });
    }
    if expected_digests.next().is_some() {
        return Err(Error::DataDigestCountMismatch);
    }
    Ok(DataVerification {
        source_hasher,
        digest_available,
        chunks,
    })
}

fn classify_chunk(
    read: ChunkRead,
    bytes: &[u8],
    expected_len: u32,
    expected_digest: Digest,
) -> Result<(u32, ChunkState), Error> {
    match read {
        ChunkRead::Complete => {
            let state = if fingerprint::data_chunk_digest(bytes) == expected_digest {
                ChunkState::Good
            } else {
                ChunkState::Corrupt
            };
            Ok((expected_len, state))
        }
        ChunkRead::Eof(bytes_read) => Ok((
            u32::try_from(bytes_read).map_err(|_| Error::LengthUnrepresentable)?,
            ChunkState::Missing,
        )),
        ChunkRead::Error { bytes_read, kind } => Ok((
            u32::try_from(bytes_read).map_err(|_| Error::LengthUnrepresentable)?,
            ChunkState::Unreadable(kind),
        )),
    }
}

fn source_digest_state(
    source_hasher: &blake3::Hasher,
    available: bool,
    sidecar: &Sidecar,
) -> SourceDigestState {
    if !available {
        return SourceDigestState::Unavailable;
    }
    let actual: Digest = source_hasher.finalize().into();
    if actual == sidecar.metadata.manifest.source_digest() {
        SourceDigestState::Match
    } else {
        SourceDigestState::Mismatch
    }
}

#[derive(Clone, Copy)]
enum ChunkRead {
    Complete,
    Eof(usize),
    Error {
        bytes_read: usize,
        kind: io::ErrorKind,
    },
}

fn read_chunk<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    source_hasher: &mut blake3::Hasher,
) -> ChunkRead {
    let mut filled = 0_usize;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => return ChunkRead::Eof(filled),
            Ok(count) => {
                source_hasher.update(&buffer[filled..filled + count]);
                filled += count;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return ChunkRead::Error {
                    bytes_read: filled,
                    kind: error.kind(),
                };
            }
        }
    }
    ChunkRead::Complete
}

fn hash_remainder<R: Read>(reader: &mut R, source_hasher: &mut blake3::Hasher) -> io::Result<()> {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                source_hasher.update(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}
