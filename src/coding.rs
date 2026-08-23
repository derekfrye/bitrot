//! Bounded-memory Leopard GF(2^16) coding windows.

use crate::geometry::Geometry;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

/// Geometry shared by one encoder and decoder coding window.
///
/// A complete chunk is divided into equal windows at identical offsets in
/// every shard. Encoding those windows independently and concatenating their
/// outputs is identical to encoding the complete chunks at once. Smaller
/// windows bound the coding workspace without changing recovery bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodingWindow {
    source_len: u64,
    chunk_bytes: usize,
    data_chunks: usize,
    recovery_chunks: usize,
    bytes: usize,
}

impl CodingWindow {
    /// Creates a coding-window configuration for one global group.
    ///
    /// `bytes` must be positive, even, no larger than the data chunk, and an
    /// exact divisor of the data chunk size.
    ///
    /// # Errors
    ///
    /// Returns an error if the window size is invalid or the geometry is not
    /// supported by the selected coding backend.
    pub fn new(geometry: Geometry, bytes: usize) -> Result<Self, Error> {
        let chunk_bytes =
            usize::try_from(geometry.chunk_size.bytes()).map_err(|_| Error::InvalidWindowSize {
                bytes,
                chunk_bytes: usize::MAX,
            })?;
        if bytes == 0
            || !bytes.is_multiple_of(2)
            || bytes > chunk_bytes
            || !chunk_bytes.is_multiple_of(bytes)
        {
            return Err(Error::InvalidWindowSize { bytes, chunk_bytes });
        }

        let data_chunks =
            usize::try_from(geometry.data_chunks).map_err(|_| Error::UnsupportedShardCounts {
                data_chunks: u64::from(geometry.data_chunks),
                recovery_chunks: u64::from(geometry.recovery_chunks),
            })?;
        let recovery_chunks = usize::try_from(geometry.recovery_chunks).map_err(|_| {
            Error::UnsupportedShardCounts {
                data_chunks: u64::from(geometry.data_chunks),
                recovery_chunks: u64::from(geometry.recovery_chunks),
            }
        })?;
        if !ReedSolomonEncoder::supports(data_chunks, recovery_chunks) {
            return Err(Error::UnsupportedShardCounts {
                data_chunks: u64::from(geometry.data_chunks),
                recovery_chunks: u64::from(geometry.recovery_chunks),
            });
        }

        Ok(Self {
            source_len: geometry.source_len,
            chunk_bytes,
            data_chunks,
            recovery_chunks,
            bytes,
        })
    }

    #[must_use]
    pub const fn data_chunks(self) -> usize {
        self.data_chunks
    }

    #[must_use]
    pub const fn recovery_chunks(self) -> usize {
        self.recovery_chunks
    }

    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }

    /// Allocates a reusable encoder for this window geometry.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend rejects the configuration.
    pub fn encoder(self) -> Result<WindowEncoder, Error> {
        Ok(WindowEncoder {
            inner: ReedSolomonEncoder::new(self.data_chunks, self.recovery_chunks, self.bytes)?,
            config: self,
        })
    }

    /// Allocates a reusable decoder for this window geometry.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend rejects the configuration.
    pub fn decoder(self) -> Result<WindowDecoder, Error> {
        Ok(WindowDecoder {
            inner: ReedSolomonDecoder::new(self.data_chunks, self.recovery_chunks, self.bytes)?,
            config: self,
        })
    }
}

/// Reusable encoder for successive same-offset shard windows.
pub struct WindowEncoder {
    inner: ReedSolomonEncoder,
    config: CodingWindow,
}

impl WindowEncoder {
    /// Reads and encodes every window in a source, zero-padding the final data
    /// chunk to the configured chunk size.
    ///
    /// Recovery windows are emitted in window-offset order, then ascending
    /// recovery-index order. The callback receives the byte offset within the
    /// recovery chunk, its recovery index, and the borrowed recovery bytes.
    /// Input must remain unchanged and at least as long as the source length in
    /// the geometry. Bytes beyond that declared length are ignored.
    ///
    /// # Errors
    ///
    /// Returns an error if source seeking or reading fails, the backend fails,
    /// an offset overflows, or the output callback fails.
    pub fn encode_source<R, F>(&mut self, source: &mut R, mut emit: F) -> Result<(), Error>
    where
        R: Read + Seek,
        F: FnMut(usize, usize, &[u8]) -> io::Result<()>,
    {
        let mut original = vec![0_u8; self.config.bytes];
        for window_offset in (0..self.config.chunk_bytes).step_by(self.config.bytes) {
            self.inner.reset(
                self.config.data_chunks,
                self.config.recovery_chunks,
                self.config.bytes,
            )?;
            for data_index in 0..self.config.data_chunks {
                original.fill(0);
                let chunk_offset = u64::try_from(data_index)
                    .ok()
                    .and_then(|index| {
                        index.checked_mul(u64::try_from(self.config.chunk_bytes).ok()?)
                    })
                    .ok_or(Error::SourceOffsetOverflow)?;
                let absolute_offset = chunk_offset
                    .checked_add(
                        u64::try_from(window_offset).map_err(|_| Error::SourceOffsetOverflow)?,
                    )
                    .ok_or(Error::SourceOffsetOverflow)?;
                let available = self.config.source_len.saturating_sub(absolute_offset).min(
                    u64::try_from(self.config.bytes).map_err(|_| Error::SourceOffsetOverflow)?,
                );
                let available =
                    usize::try_from(available).map_err(|_| Error::SourceOffsetOverflow)?;
                if available != 0 {
                    source
                        .seek(SeekFrom::Start(absolute_offset))
                        .map_err(Error::Input)?;
                    source
                        .read_exact(&mut original[..available])
                        .map_err(Error::Input)?;
                }
                self.inner.add_original_shard(&original)?;
            }

            let result = self.inner.encode()?;
            for (recovery_index, recovery) in result.recovery_iter().enumerate() {
                emit(window_offset, recovery_index, recovery).map_err(Error::Output)?;
            }
        }
        Ok(())
    }

    /// Encodes exactly one window from every data chunk and emits recovery
    /// windows in ascending recovery-index order.
    ///
    /// The encoder resets before each call and remains reusable after input,
    /// backend, or output errors. Emitted slices are borrowed backend storage
    /// and must be consumed before the callback returns.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong shard count or size, a backend failure,
    /// or an output callback failure.
    pub fn encode<I, S, F>(&mut self, originals: I, mut emit: F) -> Result<(), Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
        F: FnMut(usize, &[u8]) -> io::Result<()>,
    {
        self.inner.reset(
            self.config.data_chunks,
            self.config.recovery_chunks,
            self.config.bytes,
        )?;
        for original in originals {
            self.inner.add_original_shard(original)?;
        }

        let result = self.inner.encode()?;
        for (index, recovery) in result.recovery_iter().enumerate() {
            emit(index, recovery).map_err(Error::Output)?;
        }
        Ok(())
    }
}

/// Reusable decoder for successive same-offset shard windows.
pub struct WindowDecoder {
    inner: ReedSolomonDecoder,
    config: CodingWindow,
}

impl WindowDecoder {
    /// Restores missing data windows from indexed, strongly verified inputs.
    ///
    /// Only missing data windows are emitted, in ascending data-index order.
    /// Callers must exclude corrupt shards rather than passing them as input.
    /// The decoder resets before every call and remains reusable after errors.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid, duplicate, incorrectly sized, or
    /// insufficient inputs, a backend failure, or an output callback failure.
    pub fn restore<O, R, OS, RS, F>(
        &mut self,
        originals: O,
        recovery: R,
        mut emit: F,
    ) -> Result<(), Error>
    where
        O: IntoIterator<Item = (usize, OS)>,
        R: IntoIterator<Item = (usize, RS)>,
        OS: AsRef<[u8]>,
        RS: AsRef<[u8]>,
        F: FnMut(usize, &[u8]) -> io::Result<()>,
    {
        self.inner.reset(
            self.config.data_chunks,
            self.config.recovery_chunks,
            self.config.bytes,
        )?;
        for (index, original) in originals {
            self.inner.add_original_shard(index, original)?;
        }
        for (index, recovery) in recovery {
            self.inner.add_recovery_shard(index, recovery)?;
        }

        let result = self.inner.decode()?;
        for (index, original) in result.restored_original_iter() {
            emit(index, original).map_err(Error::Output)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidWindowSize {
        bytes: usize,
        chunk_bytes: usize,
    },
    UnsupportedShardCounts {
        data_chunks: u64,
        recovery_chunks: u64,
    },
    SourceOffsetOverflow,
    Backend(reed_solomon_simd::Error),
    Input(io::Error),
    Output(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindowSize { bytes, chunk_bytes } => write!(
                formatter,
                "coding window size {bytes} must be positive, even, and divide chunk size {chunk_bytes}"
            ),
            Self::UnsupportedShardCounts {
                data_chunks,
                recovery_chunks,
            } => write!(
                formatter,
                "coding backend does not support {data_chunks} data and {recovery_chunks} recovery shards"
            ),
            Self::SourceOffsetOverflow => formatter.write_str("coding source offset overflows u64"),
            Self::Backend(error) => write!(formatter, "coding backend failed: {error}"),
            Self::Input(error) => write!(formatter, "coding input failed: {error}"),
            Self::Output(error) => write!(formatter, "coding output failed: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Backend(error) => Some(error),
            Self::Input(error) | Self::Output(error) => Some(error),
            _ => None,
        }
    }
}

impl From<reed_solomon_simd::Error> for Error {
    fn from(error: reed_solomon_simd::Error) -> Self {
        Self::Backend(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::Redundancy;
    use crate::geometry::{ChunkSize, MIN_CHUNK_SIZE};
    use std::io::Cursor;

    const WINDOW_BYTES: usize = 1_024;

    fn geometry(data_chunks: u64, recovery_numerator: u64) -> Geometry {
        let chunk_size = ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap();
        Geometry::new(
            data_chunks * u64::from(chunk_size.bytes()),
            chunk_size,
            Redundancy::new(recovery_numerator, data_chunks).unwrap(),
        )
        .unwrap()
    }

    fn originals(count: usize, bytes: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|shard| {
                (0..bytes)
                    .map(|offset| {
                        shard
                            .wrapping_mul(113)
                            .wrapping_add(offset.wrapping_mul(29))
                            .to_le_bytes()[0]
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn independently_encoded_windows_equal_complete_shards() {
        let geometry = geometry(3, 2);
        let config = CodingWindow::new(geometry, WINDOW_BYTES).unwrap();
        let original = originals(config.data_chunks(), WINDOW_BYTES * 3);
        let expected = reed_solomon_simd::encode(3, 2, &original).unwrap();
        let mut actual = vec![Vec::new(); config.recovery_chunks()];
        let mut encoder = config.encoder().unwrap();

        for offset in (0..WINDOW_BYTES * 3).step_by(WINDOW_BYTES) {
            encoder
                .encode(
                    original
                        .iter()
                        .map(|shard| &shard[offset..offset + WINDOW_BYTES]),
                    |index, bytes| {
                        actual[index].extend_from_slice(bytes);
                        Ok(())
                    },
                )
                .unwrap();
        }

        assert_eq!(actual, expected);
    }

    #[test]
    fn restores_arbitrary_missing_data_windows() {
        let config = CodingWindow::new(geometry(4, 2), WINDOW_BYTES).unwrap();
        let original = originals(config.data_chunks(), config.bytes());
        let mut recovery = vec![Vec::new(); config.recovery_chunks()];
        config
            .encoder()
            .unwrap()
            .encode(&original, |index, bytes| {
                recovery[index].extend_from_slice(bytes);
                Ok(())
            })
            .unwrap();

        let mut restored = Vec::new();
        config
            .decoder()
            .unwrap()
            .restore(
                [(1, &original[1]), (3, &original[3])],
                [(0, &recovery[0]), (1, &recovery[1])],
                |index, bytes| {
                    restored.push((index, bytes.to_vec()));
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(
            restored,
            vec![(0, original[0].clone()), (2, original[2].clone())]
        );
    }

    #[test]
    fn rejects_invalid_window_sizes() {
        let geometry = geometry(3, 1);
        for bytes in [0, 3, usize::try_from(MIN_CHUNK_SIZE).unwrap() + 2, 6_000] {
            assert!(matches!(
                CodingWindow::new(geometry, bytes),
                Err(Error::InvalidWindowSize { .. })
            ));
        }
    }

    #[test]
    fn reports_insufficient_and_incorrectly_sized_inputs() {
        let config = CodingWindow::new(geometry(3, 1), WINDOW_BYTES).unwrap();
        let original = originals(config.data_chunks(), config.bytes());
        let error = config
            .encoder()
            .unwrap()
            .encode(&original[..2], |_, _| Ok(()))
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Backend(reed_solomon_simd::Error::TooFewOriginalShards { .. })
        ));

        let error = config
            .encoder()
            .unwrap()
            .encode(
                [&original[0][..WINDOW_BYTES - 2], &original[1], &original[2]],
                |_, _| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Backend(reed_solomon_simd::Error::DifferentShardSize { .. })
        ));
    }

    #[test]
    fn encoder_is_reusable_after_an_output_error() {
        let config = CodingWindow::new(geometry(2, 1), WINDOW_BYTES).unwrap();
        let original = originals(config.data_chunks(), config.bytes());
        let mut encoder = config.encoder().unwrap();
        let error = encoder
            .encode(&original, |_, _| Err(io::Error::other("sink failed")))
            .unwrap_err();
        assert!(matches!(error, Error::Output(_)));

        let mut emitted = 0;
        encoder
            .encode(&original, |_, _| {
                emitted += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(emitted, 1);
    }

    #[test]
    fn source_encoding_zero_pads_the_final_data_chunk() {
        let chunk_bytes = usize::try_from(MIN_CHUNK_SIZE).unwrap();
        let source_len = chunk_bytes * 2 + 17;
        let source: Vec<u8> = (0..source_len)
            .map(|offset| offset.wrapping_mul(37).to_le_bytes()[0])
            .collect();
        let chunk_size = ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap();
        let geometry = Geometry::new(
            u64::try_from(source_len).unwrap(),
            chunk_size,
            Redundancy::new(1, 3).unwrap(),
        )
        .unwrap();
        let config = CodingWindow::new(geometry, WINDOW_BYTES).unwrap();
        let mut expected_original = vec![vec![0_u8; chunk_bytes]; 3];
        for (index, chunk) in source.chunks(chunk_bytes).enumerate() {
            expected_original[index][..chunk.len()].copy_from_slice(chunk);
        }
        let expected = reed_solomon_simd::encode(3, 1, &expected_original).unwrap();
        let mut actual = vec![Vec::new(); config.recovery_chunks()];

        config
            .encoder()
            .unwrap()
            .encode_source(&mut Cursor::new(source), |offset, index, bytes| {
                assert_eq!(offset, actual[index].len());
                actual[index].extend_from_slice(bytes);
                Ok(())
            })
            .unwrap();

        assert_eq!(actual, expected);
    }
}
