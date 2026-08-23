//! CRC-64/GO-ISO rolling candidates with mandatory BLAKE3 confirmation.

use crate::digest::Digest;
use crate::fingerprint;
use crate::geometry::ChunkSize;
use crc::{CRC_64_GO_ISO, Crc, Table};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufReader, Read};
use std::ops::ControlFlow;

/// Reflected representation of the CRC-64/GO-ISO polynomial.
pub const CRC64_ISO_POLYNOMIAL: u64 = 0xd800_0000_0000_0000;

const CRC64_ISO: Crc<u64, Table<16>> = Crc::<u64, Table<16>>::new(&CRC_64_GO_ISO);

/// Computes CRC-64/GO-ISO with all-one initialization and final XOR.
#[must_use]
pub fn crc64_iso(bytes: &[u8]) -> u64 {
    CRC64_ISO.checksum(bytes)
}

/// Precomputed state for one fixed-size rolling window.
pub struct RollingCrc64 {
    outgoing: [u64; 256],
    window_mask: u64,
}

impl RollingCrc64 {
    #[must_use]
    pub fn new(window_size: ChunkSize) -> Self {
        let window_size = window_size.bytes();
        let zero_advance = ZeroAdvance::new(window_size);
        let mut outgoing = [0_u64; 256];
        for (byte, entry) in (1_u64..=255).zip(outgoing.iter_mut().skip(1)) {
            let value = byte << 56;
            let contribution = value ^ (value >> 1) ^ (value >> 3) ^ (value >> 4);
            *entry = zero_advance.apply(contribution);
        }
        let window_mask = zero_advance.apply(u64::MAX) ^ u64::MAX;
        Self {
            outgoing,
            window_mask,
        }
    }

    /// Advances a checksum by removing `old_byte` and appending `new_byte`.
    #[must_use]
    pub fn slide(&self, checksum: u64, old_byte: u8, new_byte: u8) -> u64 {
        let internal = self.window_mask ^ checksum;
        let advanced = update_raw(internal, new_byte) ^ self.outgoing[usize::from(old_byte)];
        self.window_mask ^ advanced
    }
}

/// One expected full-size data chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Target {
    pub chunk_index: u32,
    pub rolling: u64,
    pub strong: Digest,
}

/// Strongly confirmed expected chunks found at one byte offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Match {
    pub offset: u64,
    pub chunk_indices: Vec<u32>,
}

/// Statistics from a displaced-chunk scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanSummary {
    pub windows_scanned: u64,
    pub rolling_candidates: u64,
    pub stopped_early: bool,
}

/// Indexed expected fingerprints for candidate scanning.
pub struct Locator {
    by_rolling: HashMap<u64, Vec<Target>>,
}

impl Locator {
    /// Builds a bounded target index and collapses identical duplicate entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of supplied entries exceeds
    /// `max_targets`, or duplicate chunk indexes disagree.
    pub fn new<I>(targets: I, max_targets: usize) -> Result<Self, Error>
    where
        I: IntoIterator<Item = Target>,
    {
        let mut by_index = HashMap::<u32, Target>::new();
        let mut supplied = 0_usize;
        for target in targets {
            supplied = supplied.checked_add(1).ok_or(Error::TargetLimitExceeded {
                actual: usize::MAX,
                maximum: max_targets,
            })?;
            if supplied > max_targets {
                return Err(Error::TargetLimitExceeded {
                    actual: supplied,
                    maximum: max_targets,
                });
            }
            if let Some(existing) = by_index.get(&target.chunk_index) {
                if existing != &target {
                    return Err(Error::ConflictingTarget(target.chunk_index));
                }
            } else {
                by_index.insert(target.chunk_index, target);
            }
        }

        let mut by_rolling = HashMap::<u64, Vec<Target>>::new();
        for target in by_index.into_values() {
            by_rolling.entry(target.rolling).or_default().push(target);
        }
        for targets in by_rolling.values_mut() {
            targets.sort_unstable_by_key(|target| target.chunk_index);
        }
        Ok(Self { by_rolling })
    }

    /// Scans every full-size window and invokes `on_match` only after BLAKE3
    /// confirmation. Returning [`ControlFlow::Break`] stops the scan.
    ///
    /// Memory use is one chunk plus the bounded target index. Matches are
    /// delivered rather than accumulated, so the result size is caller-owned.
    ///
    /// # Errors
    ///
    /// Returns an error if input fails or a scan counter overflows.
    pub fn scan<R, F>(
        &self,
        reader: &mut R,
        chunk_size: ChunkSize,
        mut on_match: F,
    ) -> Result<ScanSummary, Error>
    where
        R: Read,
        F: FnMut(Match) -> ControlFlow<()>,
    {
        let mut summary = ScanSummary {
            windows_scanned: 0,
            rolling_candidates: 0,
            stopped_early: false,
        };
        if self.by_rolling.is_empty() {
            return Ok(summary);
        }

        let mut reader = BufReader::new(reader);
        let mut window = vec![0_u8; chunk_size.bytes() as usize];
        let filled = fill(&mut reader, &mut window)?;
        if filled < window.len() {
            return Ok(summary);
        }

        let roller = RollingCrc64::new(chunk_size);
        let mut checksum = crc64_iso(&window);
        let mut head = 0_usize;
        let mut offset = 0_u64;
        if self.check_candidate(&window, head, checksum, offset, &mut summary, &mut on_match)? {
            return Ok(summary);
        }

        let mut incoming = [0_u8; 1];
        loop {
            if !read_byte(&mut reader, &mut incoming)? {
                return Ok(summary);
            }
            let outgoing = window[head];
            window[head] = incoming[0];
            head += 1;
            if head == window.len() {
                head = 0;
            }
            checksum = roller.slide(checksum, outgoing, incoming[0]);
            offset = offset.checked_add(1).ok_or(Error::ScanOffsetOverflow)?;
            if self.check_candidate(&window, head, checksum, offset, &mut summary, &mut on_match)? {
                return Ok(summary);
            }
        }
    }

    fn check_candidate<F>(
        &self,
        window: &[u8],
        head: usize,
        checksum: u64,
        offset: u64,
        summary: &mut ScanSummary,
        on_match: &mut F,
    ) -> Result<bool, Error>
    where
        F: FnMut(Match) -> ControlFlow<()>,
    {
        summary.windows_scanned = summary
            .windows_scanned
            .checked_add(1)
            .ok_or(Error::WindowCountOverflow)?;
        let Some(targets) = self.by_rolling.get(&checksum) else {
            return Ok(false);
        };
        summary.rolling_candidates = summary
            .rolling_candidates
            .checked_add(1)
            .ok_or(Error::CandidateCountOverflow)?;

        let strong = fingerprint::data_chunk_digest_slices(&window[head..], &window[..head]);
        let chunk_indices: Vec<u32> = targets
            .iter()
            .filter(|target| target.strong == strong)
            .map(|target| target.chunk_index)
            .collect();
        if chunk_indices.is_empty() {
            return Ok(false);
        }
        if on_match(Match {
            offset,
            chunk_indices,
        })
        .is_break()
        {
            summary.stopped_early = true;
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    TargetLimitExceeded { actual: usize, maximum: usize },
    ConflictingTarget(u32),
    ScanOffsetOverflow,
    WindowCountOverflow,
    CandidateCountOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "rolling scan input failed: {error}"),
            Self::TargetLimitExceeded { actual, maximum } => {
                write!(formatter, "target count {actual} exceeds limit {maximum}")
            }
            Self::ConflictingTarget(index) => {
                write!(formatter, "rolling fingerprints conflict for chunk {index}")
            }
            Self::ScanOffsetOverflow => formatter.write_str("rolling scan offset overflows u64"),
            Self::WindowCountOverflow => {
                formatter.write_str("rolling scan window count overflows u64")
            }
            Self::CandidateCountOverflow => {
                formatter.write_str("rolling candidate count overflows u64")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn update_raw(state: u64, byte: u8) -> u64 {
    let index = usize::from((state ^ u64::from(byte)).to_le_bytes()[0]);
    CRC64_ISO.table()[0][index] ^ (state >> 8)
}

struct ZeroAdvance {
    transforms: Vec<[u64; 64]>,
}

impl ZeroAdvance {
    fn new(mut count: u32) -> Self {
        let mut transforms = Vec::new();
        let mut power = std::array::from_fn(|bit| update_raw(1_u64 << bit, 0));
        while count != 0 {
            if count & 1 != 0 {
                transforms.push(power);
            }
            count >>= 1;
            if count != 0 {
                power = matrix_square(&power);
            }
        }
        Self { transforms }
    }

    fn apply(&self, mut state: u64) -> u64 {
        for transform in &self.transforms {
            state = matrix_times(transform, state);
        }
        state
    }
}

fn matrix_times(matrix: &[u64; 64], mut vector: u64) -> u64 {
    let mut result = 0_u64;
    let mut bit = 0_usize;
    while vector != 0 {
        if vector & 1 != 0 {
            result ^= matrix[bit];
        }
        vector >>= 1;
        bit += 1;
    }
    result
}

fn matrix_square(matrix: &[u64; 64]) -> [u64; 64] {
    std::array::from_fn(|bit| matrix_times(matrix, matrix[bit]))
}

fn fill<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, Error> {
    let mut filled = 0_usize;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok(filled)
}

fn read_byte<R: Read>(reader: &mut R, byte: &mut [u8; 1]) -> Result<bool, Error> {
    loop {
        match reader.read(byte) {
            Ok(0) => return Ok(false),
            Ok(1) => return Ok(true),
            Ok(_) => unreachable!("one-byte buffer cannot accept more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint;
    use crate::geometry::MIN_CHUNK_SIZE;
    use std::io::Cursor;

    fn chunk_size() -> ChunkSize {
        ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap()
    }

    fn target(index: u32, bytes: &[u8]) -> Target {
        Target {
            chunk_index: index,
            rolling: crc64_iso(bytes),
            strong: fingerprint::data_chunk_digest_slices(bytes, &[]),
        }
    }

    #[test]
    fn crc_matches_go_iso_check_value() {
        assert_eq!(crc64_iso(b"123456789"), 0xb909_56c7_75a4_1001);
        assert_eq!(crc64_iso(b""), 0);
    }

    #[test]
    fn rolling_value_matches_fresh_crc_at_every_offset() {
        let size = chunk_size();
        let window_len = size.bytes() as usize;
        let data: Vec<u8> = (0..window_len + 257)
            .map(|index| index.to_le_bytes()[0])
            .collect();
        let roller = RollingCrc64::new(size);
        let mut checksum = crc64_iso(&data[..window_len]);

        for offset in 1..=257 {
            checksum = roller.slide(checksum, data[offset - 1], data[offset + window_len - 1]);
            assert_eq!(checksum, crc64_iso(&data[offset..offset + window_len]));
        }
    }

    #[test]
    fn finds_a_chunk_at_an_unexpected_offset() {
        let size = chunk_size();
        let expected = vec![0x5a; size.bytes() as usize];
        let prefix = b"inserted bytes";
        let mut source = prefix.to_vec();
        source.extend(&expected);
        source.extend(b"suffix");
        let locator = Locator::new([target(7, &expected)], 1).unwrap();
        let mut matches = Vec::new();

        let summary = locator
            .scan(&mut Cursor::new(source), size, |found| {
                matches.push(found);
                ControlFlow::Continue(())
            })
            .unwrap();

        assert_eq!(
            matches,
            vec![Match {
                offset: prefix.len() as u64,
                chunk_indices: vec![7]
            }]
        );
        assert!(!summary.stopped_early);
        assert!(summary.rolling_candidates >= 1);
    }

    #[test]
    fn rolling_match_without_strong_match_is_rejected() {
        let size = chunk_size();
        let candidate = vec![1_u8; size.bytes() as usize];
        let different = vec![2_u8; size.bytes() as usize];
        let locator = Locator::new(
            [Target {
                chunk_index: 1,
                rolling: crc64_iso(&candidate),
                strong: fingerprint::data_chunk_digest_slices(&different, &[]),
            }],
            1,
        )
        .unwrap();
        let mut matches = Vec::new();

        let summary = locator
            .scan(&mut Cursor::new(candidate), size, |found| {
                matches.push(found);
                ControlFlow::Continue(())
            })
            .unwrap();

        assert!(matches.is_empty());
        assert_eq!(summary.rolling_candidates, 1);
    }

    #[test]
    fn duplicate_content_can_satisfy_multiple_chunk_indexes() {
        let size = chunk_size();
        let bytes = vec![3_u8; size.bytes() as usize];
        let locator = Locator::new([target(9, &bytes), target(2, &bytes)], 2).unwrap();
        let mut matches = Vec::new();

        locator
            .scan(&mut Cursor::new(bytes), size, |found| {
                matches.push(found);
                ControlFlow::Continue(())
            })
            .unwrap();

        assert_eq!(matches[0].chunk_indices, vec![2, 9]);
    }

    #[test]
    fn callback_can_stop_without_accumulating_more_matches() {
        let size = chunk_size();
        let bytes = vec![0_u8; size.bytes() as usize + 100];
        let expected_window = vec![0_u8; size.bytes() as usize];
        let locator = Locator::new([target(0, &expected_window)], 1).unwrap();
        let mut calls = 0;

        let summary = locator
            .scan(&mut Cursor::new(bytes), size, |_| {
                calls += 1;
                ControlFlow::Break(())
            })
            .unwrap();

        assert_eq!(calls, 1);
        assert!(summary.stopped_early);
        assert_eq!(summary.windows_scanned, 1);
    }

    #[test]
    fn target_index_is_bounded_and_conflicts_are_rejected() {
        let bytes = vec![4_u8; chunk_size().bytes() as usize];
        let first = target(1, &bytes);
        assert!(matches!(
            Locator::new([first], 0),
            Err(Error::TargetLimitExceeded { .. })
        ));

        let mut conflicting = first;
        conflicting.rolling ^= 1;
        assert!(matches!(
            Locator::new([first, conflicting], 2),
            Err(Error::ConflictingTarget(1))
        ));

        assert!(Locator::new([first, first], 2).is_ok());
    }

    #[test]
    fn input_shorter_than_a_chunk_has_no_windows() {
        let bytes = vec![5_u8; chunk_size().bytes() as usize];
        let locator = Locator::new([target(0, &bytes)], 1).unwrap();
        let summary = locator
            .scan(
                &mut Cursor::new(&bytes[..bytes.len() - 1]),
                chunk_size(),
                |_| panic!("short input cannot match"),
            )
            .unwrap();

        assert_eq!(summary.windows_scanned, 0);
    }
}
