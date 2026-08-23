//! Construction of a complete protection set from a seekable source.

mod filesystem;
mod spool;

pub use filesystem::{ExistingSidecar, PublishError, PublishOutcome, publish};

use crate::coding::{self, CodingWindow};
use crate::creator::Creator;
use crate::digest_page::{self, Kind};
use crate::fingerprint::{self, Digest, SourceFingerprint};
use crate::geometry::{self, ChunkSize, Geometry, Redundancy};
use crate::manifest::{self, Manifest};
use crate::metadata::Metadata;
use crate::recovery_chunk::{self, RecoveryChunk};
use crate::rolling_page;
use crate::sidecar::{self, Sidecar};
use std::collections::TryReserveError;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

/// Resource and format choices for creating one protection set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    pub chunk_size: ChunkSize,
    pub redundancy: Redundancy,
    pub coding_window_bytes: usize,
    pub creator: Creator,
}

impl Options {
    #[must_use]
    pub const fn new(
        chunk_size: ChunkSize,
        redundancy: Redundancy,
        coding_window_bytes: usize,
        creator: Creator,
    ) -> Self {
        Self {
            chunk_size,
            redundancy,
            coding_window_bytes,
            creator,
        }
    }
}

/// Builds a complete logical sidecar from a source beginning at byte zero.
///
/// The source is read once for fingerprints, once in bounded coding windows,
/// and once more to ensure it did not change during creation. Recovery chunks
/// remain resident in the returned [`Sidecar`], but the coding workspace is
/// bounded by `coding_window_bytes`.
///
/// # Errors
///
/// Returns an error if source I/O fails, options or derived geometry are
/// invalid, parity generation fails, the source changes between reads, memory
/// for the recovery set cannot be reserved, or generated format structures do
/// not validate.
pub fn build<R: Read + Seek>(source: &mut R, options: &Options) -> Result<Sidecar, Error> {
    let (fingerprint, geometry) = analyze(source, options)?;
    let mut recovery = recovery_buffers(geometry)?;
    encode_and_confirm(
        source,
        options,
        &fingerprint,
        geometry,
        |offset, index, bytes| {
            let chunk = recovery.get_mut(index).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unexpected recovery index")
            })?;
            if chunk.len() != offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "noncontiguous recovery window",
                ));
            }
            chunk.extend_from_slice(bytes);
            Ok(())
        },
    )?;
    assemble(fingerprint, geometry, recovery, options.creator.clone())
}

fn analyze<R: Read + Seek>(
    source: &mut R,
    options: &Options,
) -> Result<(SourceFingerprint, Geometry), Error> {
    source.seek(SeekFrom::Start(0)).map_err(Error::SourceSeek)?;
    let fingerprint =
        fingerprint::source(source, options.chunk_size).map_err(Error::Fingerprint)?;
    let geometry = Geometry::new(
        fingerprint.source_len,
        options.chunk_size,
        options.redundancy,
    )
    .map_err(Error::Geometry)?;
    Ok((fingerprint, geometry))
}

fn encode_and_confirm<R, F>(
    source: &mut R,
    options: &Options,
    fingerprint: &SourceFingerprint,
    geometry: Geometry,
    output: F,
) -> Result<(), Error>
where
    R: Read + Seek,
    F: FnMut(usize, usize, &[u8]) -> io::Result<()>,
{
    let coding = CodingWindow::new(geometry, options.coding_window_bytes).map_err(Error::Coding)?;
    let mut encoder = coding.encoder().map_err(Error::Coding)?;
    encoder
        .encode_source(source, output)
        .map_err(Error::Coding)?;

    source.seek(SeekFrom::Start(0)).map_err(Error::SourceSeek)?;
    let confirmed = fingerprint::source(source, options.chunk_size).map_err(Error::Fingerprint)?;
    if confirmed != *fingerprint {
        return Err(Error::SourceChanged);
    }
    Ok(())
}

fn recovery_buffers(geometry: Geometry) -> Result<Vec<Vec<u8>>, Error> {
    let count = usize::try_from(geometry.recovery_chunks).map_err(|_| Error::LengthOverflow)?;
    let chunk_bytes =
        usize::try_from(geometry.chunk_size.bytes()).map_err(|_| Error::LengthOverflow)?;
    let mut recovery = Vec::new();
    recovery
        .try_reserve_exact(count)
        .map_err(Error::RecoveryAllocation)?;
    for _ in 0..count {
        let mut chunk = Vec::new();
        chunk
            .try_reserve_exact(chunk_bytes)
            .map_err(Error::RecoveryAllocation)?;
        recovery.push(chunk);
    }
    Ok(recovery)
}

fn assemble(
    fingerprint: SourceFingerprint,
    geometry: Geometry,
    recovery: Vec<Vec<u8>>,
    creator: Creator,
) -> Result<Sidecar, Error> {
    let recovery_digest_values = recovery
        .iter()
        .map(|chunk| fingerprint::recovery_chunk_digest(chunk))
        .collect();
    let metadata = build_metadata(fingerprint, geometry, recovery_digest_values)?;
    let manifest = metadata.manifest;
    let recovery = recovery
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            let index = u32::try_from(index).map_err(|_| Error::LengthOverflow)?;
            RecoveryChunk::new(manifest, index, bytes).map_err(Error::RecoveryChunk)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Sidecar::from_generated_parts(metadata, creator, recovery).map_err(Error::Sidecar)
}

fn build_metadata(
    fingerprint: SourceFingerprint,
    geometry: Geometry,
    recovery_digest_values: Vec<Digest>,
) -> Result<Metadata, Error> {
    let data_digests = digest_page::Table::new(Kind::Data, fingerprint.data_chunk_digests)
        .map_err(Error::DigestTable)?;
    let rolling_fingerprints =
        rolling_page::Table::new(fingerprint.full_chunk_rolling).map_err(Error::RollingTable)?;
    let recovery_digests = digest_page::Table::new(Kind::Recovery, recovery_digest_values)
        .map_err(Error::DigestTable)?;
    let manifest = Manifest::new(
        geometry,
        fingerprint.source_digest,
        &data_digests,
        &recovery_digests,
        &rolling_fingerprints,
    )
    .map_err(Error::Manifest)?;
    Ok(Metadata {
        manifest,
        data_digests,
        recovery_digests,
        rolling_fingerprints,
    })
}

#[derive(Debug)]
pub enum Error {
    SourceSeek(io::Error),
    Fingerprint(fingerprint::Error),
    Geometry(geometry::GeometryError),
    Coding(coding::Error),
    RecoveryAllocation(TryReserveError),
    DigestTable(digest_page::Error),
    RollingTable(rolling_page::Error),
    Manifest(manifest::Error),
    RecoveryChunk(recovery_chunk::Error),
    Sidecar(sidecar::WriteError),
    SourceChanged,
    LengthOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceSeek(error) => write!(formatter, "source seek failed: {error}"),
            Self::Fingerprint(error) => write!(formatter, "source fingerprinting failed: {error}"),
            Self::Geometry(error) => write!(formatter, "source geometry is invalid: {error}"),
            Self::Coding(error) => write!(formatter, "recovery coding failed: {error}"),
            Self::RecoveryAllocation(error) => {
                write!(formatter, "cannot reserve recovery storage: {error}")
            }
            Self::DigestTable(error) => write!(formatter, "digest table creation failed: {error}"),
            Self::RollingTable(error) => {
                write!(formatter, "rolling table creation failed: {error}")
            }
            Self::Manifest(error) => write!(formatter, "manifest creation failed: {error}"),
            Self::RecoveryChunk(error) => {
                write!(formatter, "recovery chunk creation failed: {error}")
            }
            Self::Sidecar(error) => write!(formatter, "generated sidecar is invalid: {error}"),
            Self::SourceChanged => formatter.write_str("source changed during creation"),
            Self::LengthOverflow => formatter.write_str("generated collection length overflows"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SourceSeek(error) => Some(error),
            Self::Fingerprint(error) => Some(error),
            Self::Geometry(error) => Some(error),
            Self::Coding(error) => Some(error),
            Self::RecoveryAllocation(error) => Some(error),
            Self::DigestTable(error) => Some(error),
            Self::RollingTable(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::RecoveryChunk(error) => Some(error),
            Self::Sidecar(error) => Some(error),
            Self::SourceChanged | Self::LengthOverflow => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::MIN_CHUNK_SIZE;
    use crate::record::DecodeLimits;
    use crate::sidecar::{AssemblyLimits, ReadLimits};
    use crate::{digest_page, metadata, recovery_set, rolling_page};
    use std::io::{Cursor, SeekFrom};

    struct ChangingSource {
        inner: Cursor<Vec<u8>>,
        zero_seeks: u32,
    }

    impl Read for ChangingSource {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buffer)
        }
    }

    impl Seek for ChangingSource {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            if position == SeekFrom::Start(0) {
                self.zero_seeks += 1;
                if self.zero_seeks == 3 {
                    self.inner.get_mut()[17] ^= 1;
                }
            }
            self.inner.seek(position)
        }
    }

    fn options() -> Options {
        Options::new(
            ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap(),
            Redundancy::new(1, 2).unwrap(),
            1_024,
            Creator::new("bitrot", env!("CARGO_PKG_VERSION")).unwrap(),
        )
    }

    fn read_limits() -> ReadLimits {
        ReadLimits {
            record: DecodeLimits::new(128, u64::from(MIN_CHUNK_SIZE) + 128),
            assembly: AssemblyLimits {
                max_records: 64,
                max_unknown_optional_records: 0,
                max_superblock_copies: 2,
                max_creator_copies: 2,
                metadata: metadata::AssemblyLimits::new(
                    16,
                    digest_page::AssemblyLimits::new(8, 2),
                    rolling_page::AssemblyLimits::new(8, 2),
                ),
                recovery: recovery_set::AssemblyLimits::new(8, 8),
            },
            max_damage_events: 0,
            max_unrecognized_bytes: 0,
        }
    }

    #[test]
    fn builds_and_canonically_writes_a_complete_sidecar() {
        let chunk_bytes = usize::try_from(MIN_CHUNK_SIZE).unwrap();
        let source: Vec<_> = (0..chunk_bytes * 2 + 137)
            .map(|index| index.wrapping_mul(29).to_le_bytes()[0])
            .collect();
        let sidecar = build(&mut Cursor::new(&source), &options()).unwrap();

        assert_eq!(sidecar.metadata.manifest.geometry().data_chunks, 3);
        assert_eq!(sidecar.metadata.manifest.geometry().recovery_chunks, 2);
        assert_eq!(sidecar.recovery.available_count(), 2);
        assert!(sidecar.recovery.missing_indexes().next().is_none());

        let mut encoded = Vec::new();
        let summary = sidecar.write_canonical(&mut encoded).unwrap();
        assert_eq!(summary.bytes_written, encoded.len() as u64);
        assert_eq!(
            sidecar.superblock.first_manifest_offset(),
            summary.first_manifest_offset
        );
        assert_eq!(
            sidecar.superblock.second_manifest_offset(),
            summary.second_manifest_offset
        );
        assert_eq!(
            sidecar.superblock.observed_sidecar_len(),
            summary.bytes_written
        );
        let decoded = Sidecar::read(Cursor::new(encoded), read_limits()).unwrap();
        assert!(decoded.damage.is_empty());
        assert_eq!(decoded.sidecar.metadata, sidecar.metadata);
        assert_eq!(decoded.sidecar.recovery.available_count(), 2);
    }

    #[test]
    fn rejects_empty_sources_and_invalid_coding_windows() {
        assert!(matches!(
            build(&mut Cursor::new(Vec::<u8>::new()), &options()),
            Err(Error::Geometry(geometry::GeometryError::EmptySource))
        ));

        let mut invalid = options();
        invalid.coding_window_bytes = 3;
        assert!(matches!(
            build(
                &mut Cursor::new(vec![1_u8; MIN_CHUNK_SIZE as usize]),
                &invalid
            ),
            Err(Error::Coding(coding::Error::InvalidWindowSize { .. }))
        ));
    }

    #[test]
    fn rejects_a_source_that_changes_during_creation() {
        let mut source = ChangingSource {
            inner: Cursor::new(vec![7_u8; MIN_CHUNK_SIZE as usize]),
            zero_seeks: 0,
        };

        assert!(matches!(
            build(&mut source, &options()),
            Err(Error::SourceChanged)
        ));
    }
}
