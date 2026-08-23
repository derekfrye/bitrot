//! Streaming strong fingerprints for source files and their data chunks.

pub use crate::digest::Digest;
pub use crate::geometry::{
    ChunkSize, ChunkSizeError, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
};
use std::fmt;
use std::io::{self, Read};

const SOURCE_DIGEST_CONTEXT: &str = "bitrot format v1 source file digest";
const DATA_CHUNK_DIGEST_CONTEXT: &str = "bitrot format v1 data chunk digest";
const RECOVERY_CHUNK_DIGEST_CONTEXT: &str = "bitrot format v1 recovery chunk digest";

/// Strong source identity produced by one complete read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceFingerprint {
    pub source_len: u64,
    pub chunk_size: ChunkSize,
    pub source_digest: Digest,
    pub data_chunk_digests: Vec<Digest>,
    pub full_chunk_rolling: Vec<u64>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    SourceLengthOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "source read failed: {error}"),
            Self::SourceLengthOverflow => {
                formatter.write_str("source length exceeds the format's u64 limit")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::SourceLengthOverflow => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reads a complete source once and fingerprints its unpadded bytes.
///
/// Memory use is one data chunk plus 32 bytes per completed chunk. A read that
/// returns fewer bytes than requested does not create an artificial boundary.
///
/// # Errors
///
/// Returns an error when the source cannot be read or its observed length
/// cannot be represented as `u64`.
pub fn source<R: Read>(reader: &mut R, chunk_size: ChunkSize) -> Result<SourceFingerprint, Error> {
    let mut buffer = vec![0_u8; chunk_size.bytes() as usize];
    let mut source_hasher = blake3::Hasher::new_derive_key(SOURCE_DIGEST_CONTEXT);
    let mut source_len = 0_u64;
    let mut data_chunk_digests = Vec::new();
    let mut full_chunk_rolling = Vec::new();

    loop {
        let mut filled = 0_usize;
        while filled < buffer.len() {
            match reader.read(&mut buffer[filled..]) {
                Ok(0) => break,
                Ok(count) => {
                    source_hasher.update(&buffer[filled..filled + count]);
                    filled += count;
                    source_len = source_len
                        .checked_add(u64::try_from(count).map_err(|_| Error::SourceLengthOverflow)?)
                        .ok_or(Error::SourceLengthOverflow)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(Error::Io(error)),
            }
        }

        if filled == 0 {
            break;
        }

        data_chunk_digests.push(hash(DATA_CHUNK_DIGEST_CONTEXT, &buffer[..filled]));
        if filled == buffer.len() {
            full_chunk_rolling.push(crate::rolling::crc64_iso(&buffer));
        }
        if filled < buffer.len() {
            break;
        }
    }

    Ok(SourceFingerprint {
        source_len,
        chunk_size,
        source_digest: source_hasher.finalize().into(),
        data_chunk_digests,
        full_chunk_rolling,
    })
}

fn hash(context: &str, bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Hashes one complete stored recovery chunk with the v1 recovery domain.
#[must_use]
pub fn recovery_chunk_digest(bytes: &[u8]) -> Digest {
    hash(RECOVERY_CHUNK_DIGEST_CONTEXT, bytes)
}

#[must_use]
pub(crate) fn source_digest_hasher() -> blake3::Hasher {
    blake3::Hasher::new_derive_key(SOURCE_DIGEST_CONTEXT)
}

#[must_use]
pub(crate) fn data_chunk_digest(bytes: &[u8]) -> Digest {
    hash(DATA_CHUNK_DIGEST_CONTEXT, bytes)
}

pub(crate) fn data_chunk_digest_slices(first: &[u8], second: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(DATA_CHUNK_DIGEST_CONTEXT);
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Fragmented<R> {
        inner: R,
        max_read: usize,
    }

    impl<R: Read> Read for Fragmented<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = buffer.len().min(self.max_read);
            self.inner.read(&mut buffer[..limit])
        }
    }

    fn minimum() -> ChunkSize {
        ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap()
    }

    #[test]
    fn fingerprints_empty_input_without_data_chunks() {
        let mut input = Cursor::new(Vec::<u8>::new());
        let actual = source(&mut input, minimum()).unwrap();

        assert_eq!(actual.source_len, 0);
        assert!(actual.data_chunk_digests.is_empty());
        assert!(actual.full_chunk_rolling.is_empty());
        assert_eq!(actual.source_digest, hash(SOURCE_DIGEST_CONTEXT, b""));
    }

    #[test]
    fn fills_chunks_across_short_reads() {
        let data: Vec<u8> = (0..MIN_CHUNK_SIZE * 2 + 37)
            .map(|index| index.to_le_bytes()[0])
            .collect();
        let mut input = Fragmented {
            inner: Cursor::new(&data),
            max_read: 17,
        };
        let actual = source(&mut input, minimum()).unwrap();

        assert_eq!(actual.source_len, data.len() as u64);
        assert_eq!(actual.data_chunk_digests.len(), 3);
        assert_eq!(actual.full_chunk_rolling.len(), 2);
        assert_eq!(
            actual.full_chunk_rolling[0],
            crate::rolling::crc64_iso(&data[..MIN_CHUNK_SIZE as usize])
        );
        assert_eq!(
            actual.data_chunk_digests[0],
            hash(DATA_CHUNK_DIGEST_CONTEXT, &data[..MIN_CHUNK_SIZE as usize])
        );
        assert_eq!(
            actual.data_chunk_digests[1],
            hash(
                DATA_CHUNK_DIGEST_CONTEXT,
                &data[MIN_CHUNK_SIZE as usize..(MIN_CHUNK_SIZE * 2) as usize]
            )
        );
        assert_eq!(
            actual.data_chunk_digests[2],
            hash(
                DATA_CHUNK_DIGEST_CONTEXT,
                &data[(MIN_CHUNK_SIZE * 2) as usize..]
            )
        );
    }

    #[test]
    fn exact_multiple_has_no_empty_final_chunk() {
        let data = vec![3_u8; MIN_CHUNK_SIZE as usize * 2];
        let actual = source(&mut Cursor::new(&data), minimum()).unwrap();

        assert_eq!(actual.data_chunk_digests.len(), 2);
        assert_eq!(actual.full_chunk_rolling.len(), 2);
    }

    #[test]
    fn source_and_data_chunk_domains_are_distinct() {
        let data = b"same unpadded bytes";
        let actual = source(&mut Cursor::new(data), minimum()).unwrap();

        assert_eq!(actual.data_chunk_digests.len(), 1);
        assert!(actual.full_chunk_rolling.is_empty());
        assert_ne!(actual.source_digest, actual.data_chunk_digests[0]);
    }

    #[test]
    fn final_chunk_digest_excludes_coding_padding() {
        let data = b"short final chunk";
        let actual = source(&mut Cursor::new(data), minimum()).unwrap();
        let mut padded = data.to_vec();
        padded.resize(MIN_CHUNK_SIZE as usize, 0);

        assert_eq!(
            actual.data_chunk_digests[0],
            hash(DATA_CHUNK_DIGEST_CONTEXT, data)
        );
        assert_ne!(
            actual.data_chunk_digests[0],
            hash(DATA_CHUNK_DIGEST_CONTEXT, &padded)
        );
    }

    #[test]
    fn recovery_digest_has_an_independent_domain() {
        let bytes = vec![0x5a; minimum().bytes() as usize];
        assert_ne!(
            recovery_chunk_digest(&bytes),
            hash(DATA_CHUNK_DIGEST_CONTEXT, &bytes)
        );
        assert_eq!(recovery_chunk_digest(&bytes), recovery_chunk_digest(&bytes));
    }

    #[test]
    fn changing_one_chunk_does_not_change_other_chunk_digests() {
        let mut original = vec![1_u8; MIN_CHUNK_SIZE as usize * 2];
        let before = source(&mut Cursor::new(&original), minimum()).unwrap();
        original[MIN_CHUNK_SIZE as usize + 9] ^= 1;
        let after = source(&mut Cursor::new(&original), minimum()).unwrap();

        assert_ne!(before.source_digest, after.source_digest);
        assert_eq!(before.data_chunk_digests[0], after.data_chunk_digests[0]);
        assert_ne!(before.data_chunk_digests[1], after.data_chunk_digests[1]);
    }
}
