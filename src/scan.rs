//! Recovery-oriented scanning of a sidecar record stream.

use crate::record::{self, DecodeLimits, MAGIC, Record};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

/// One observation made while scanning a sidecar.
#[derive(Debug)]
pub enum Event {
    /// A complete record whose digest is valid.
    ValidRecord {
        offset: u64,
        encoded_len: u64,
        record: Record,
    },
    /// Bytes outside any validated record.
    Unrecognized { offset: u64, length: u64 },
    /// Magic was found, but the candidate record failed validation.
    InvalidRecord { offset: u64, error: record::Error },
}

/// Scans a seekable sidecar and resynchronizes after invalid records.
///
/// The scanner starts at byte zero. It validates every candidate containing
/// the record magic, and after a failed candidate resumes one byte beyond that
/// candidate's start. Payload bytes are never interpreted as records when the
/// enclosing record is valid.
pub struct Scanner<R> {
    reader: BufReader<R>,
    limits: DecodeLimits,
    search_from: u64,
    pending_candidate: Option<u64>,
    finished: bool,
}

impl<R: Read + Seek> Scanner<R> {
    #[must_use]
    pub fn new(reader: R, limits: DecodeLimits) -> Self {
        Self {
            reader: BufReader::new(reader),
            limits,
            search_from: 0,
            pending_candidate: None,
            finished: false,
        }
    }

    /// Returns the next valid record or damaged/unrecognized region.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying input cannot be read or seeked.
    /// Malformed record candidates are returned as [`Event::InvalidRecord`]
    /// and do not stop the scan.
    pub fn next_event(&mut self) -> Result<Option<Event>, record::Error> {
        if self.finished {
            return Ok(None);
        }

        if let Some(offset) = self.pending_candidate.take() {
            return self.validate_candidate(offset).map(Some);
        }

        let (candidate, end_offset) = self.find_magic()?;
        match candidate {
            Some(offset) if offset > self.search_from => {
                let event = Event::Unrecognized {
                    offset: self.search_from,
                    length: offset - self.search_from,
                };
                self.pending_candidate = Some(offset);
                self.search_from = offset;
                Ok(Some(event))
            }
            Some(offset) => self.validate_candidate(offset).map(Some),
            None if end_offset > self.search_from => {
                let event = Event::Unrecognized {
                    offset: self.search_from,
                    length: end_offset - self.search_from,
                };
                self.search_from = end_offset;
                self.finished = true;
                Ok(Some(event))
            }
            None => {
                self.finished = true;
                Ok(None)
            }
        }
    }

    fn validate_candidate(&mut self, offset: u64) -> Result<Event, record::Error> {
        self.reader.seek(SeekFrom::Start(offset))?;
        match record::read(&mut self.reader, self.limits) {
            Ok(Some(record)) => {
                let end = self.reader.stream_position()?;
                let encoded_len = end
                    .checked_sub(offset)
                    .ok_or(record::Error::LengthOverflow)?;
                self.search_from = end;
                Ok(Event::ValidRecord {
                    offset,
                    encoded_len,
                    record,
                })
            }
            Ok(None) => {
                self.finished = true;
                Ok(Event::InvalidRecord {
                    offset,
                    error: record::Error::Truncated,
                })
            }
            Err(record::Error::Io(error)) => Err(record::Error::Io(error)),
            Err(error) => {
                self.search_from = offset.checked_add(1).ok_or(record::Error::LengthOverflow)?;
                Ok(Event::InvalidRecord { offset, error })
            }
        }
    }

    fn find_magic(&mut self) -> Result<(Option<u64>, u64), record::Error> {
        self.reader.seek(SeekFrom::Start(self.search_from))?;
        let mut offset = self.search_from;
        let mut matched = 0_usize;

        loop {
            let buffer = self.reader.fill_buf()?;
            if buffer.is_empty() {
                return Ok((None, offset));
            }

            let mut found = None;
            for (index, byte) in buffer.iter().copied().enumerate() {
                if byte == MAGIC[matched] {
                    matched += 1;
                    if matched == MAGIC.len() {
                        let consumed = index + 1;
                        let consumed_u64 =
                            u64::try_from(consumed).map_err(|_| record::Error::LengthOverflow)?;
                        let end = offset
                            .checked_add(consumed_u64)
                            .ok_or(record::Error::LengthOverflow)?;
                        let start = end
                            .checked_sub(MAGIC.len() as u64)
                            .ok_or(record::Error::LengthOverflow)?;
                        found = Some((consumed, start, end));
                        break;
                    }
                } else if byte == MAGIC[0] {
                    matched = 1;
                } else {
                    matched = 0;
                }
            }

            if let Some((consumed, start, end)) = found {
                self.reader.consume(consumed);
                return Ok((Some(start), end));
            }

            let consumed = buffer.len();
            let consumed_u64 =
                u64::try_from(consumed).map_err(|_| record::Error::LengthOverflow)?;
            self.reader.consume(consumed);
            offset = offset
                .checked_add(consumed_u64)
                .ok_or(record::Error::LengthOverflow)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{self, BASE_HEADER_LEN};
    use std::io::Cursor;

    const LIMITS: DecodeLimits = DecodeLimits::new(4_096, 1_048_576);

    fn example(logical_id: u64, payload: &[u8]) -> Record {
        Record {
            record_type: 11,
            flags: 0,
            protection_set_id: [0x5a; 32],
            logical_id,
            header_extension: Vec::new(),
            payload: payload.to_vec(),
        }
    }

    fn encoded(record: &Record) -> Vec<u8> {
        let mut bytes = Vec::new();
        record::write(&mut bytes, record).unwrap();
        bytes
    }

    fn next(scanner: &mut Scanner<Cursor<Vec<u8>>>) -> Event {
        scanner.next_event().unwrap().unwrap()
    }

    #[test]
    fn scans_consecutive_valid_records_without_gaps() {
        let first = example(1, b"first");
        let second = example(2, b"second");
        let first_bytes = encoded(&first);
        let mut bytes = first_bytes.clone();
        bytes.extend(encoded(&second));
        let mut scanner = Scanner::new(Cursor::new(bytes), LIMITS);

        assert!(matches!(
            next(&mut scanner),
            Event::ValidRecord {
                offset: 0,
                encoded_len,
                record
            } if encoded_len == first_bytes.len() as u64 && record == first
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::ValidRecord { record, .. } if record == second
        ));
        assert!(scanner.next_event().unwrap().is_none());
    }

    #[test]
    fn reports_leading_and_trailing_unrecognized_bytes() {
        let prefix = b"damaged";
        let suffix = b"trailing bytes";
        let record = example(1, b"intact");
        let mut bytes = prefix.to_vec();
        bytes.extend(encoded(&record));
        let suffix_offset = bytes.len() as u64;
        bytes.extend(suffix);
        let mut scanner = Scanner::new(Cursor::new(bytes), LIMITS);

        assert!(matches!(
            next(&mut scanner),
            Event::Unrecognized { offset: 0, length } if length == prefix.len() as u64
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::ValidRecord { offset, .. } if offset == prefix.len() as u64
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::Unrecognized { offset, length }
                if offset == suffix_offset && length == suffix.len() as u64
        ));
        assert!(scanner.next_event().unwrap().is_none());
    }

    #[test]
    fn recovers_a_valid_record_after_a_corrupt_one() {
        let first = encoded(&example(1, b"first"));
        let mut damaged = encoded(&example(2, b"damaged"));
        damaged[BASE_HEADER_LEN as usize] ^= 0xff;
        let third = example(3, b"third");
        let third_offset = (first.len() + damaged.len()) as u64;
        let mut bytes = first;
        let damaged_offset = bytes.len() as u64;
        bytes.extend(&damaged);
        bytes.extend(encoded(&third));
        let mut scanner = Scanner::new(Cursor::new(bytes), LIMITS);

        assert!(matches!(next(&mut scanner), Event::ValidRecord { .. }));
        assert!(matches!(
            next(&mut scanner),
            Event::InvalidRecord { offset, error: record::Error::DigestMismatch }
                if offset == damaged_offset
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::Unrecognized { offset, length }
                if offset == damaged_offset + 1 && length == damaged.len() as u64 - 1
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::ValidRecord { offset, record, .. }
                if offset == third_offset && record == third
        ));
        assert!(scanner.next_event().unwrap().is_none());
    }

    #[test]
    fn rejects_false_magic_then_resynchronizes() {
        let mut false_record = MAGIC.to_vec();
        false_record.extend(99_u16.to_le_bytes());
        false_record.resize(BASE_HEADER_LEN as usize, 0);
        let valid = example(7, b"valid");
        let valid_offset = false_record.len() as u64;
        let mut bytes = false_record;
        bytes.extend(encoded(&valid));
        let mut scanner = Scanner::new(Cursor::new(bytes), LIMITS);

        assert!(matches!(
            next(&mut scanner),
            Event::InvalidRecord {
                offset: 0,
                error: record::Error::UnsupportedVersion(99)
            }
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::Unrecognized { offset: 1, .. }
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::ValidRecord { offset, record, .. }
                if offset == valid_offset && record == valid
        ));
    }

    #[test]
    fn finds_magic_split_across_scan_buffers() {
        let prefix = b"junk";
        let expected = example(8, b"valid");
        let mut bytes = prefix.to_vec();
        bytes.extend(encoded(&expected));
        let mut scanner = Scanner {
            reader: BufReader::with_capacity(MAGIC.len() - 1, Cursor::new(bytes)),
            limits: LIMITS,
            search_from: 0,
            pending_candidate: None,
            finished: false,
        };

        assert!(matches!(
            next(&mut scanner),
            Event::Unrecognized { offset: 0, length } if length == prefix.len() as u64
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::ValidRecord { record, .. } if record == expected
        ));
    }

    #[test]
    fn recovers_after_a_candidate_exceeds_decode_limits() {
        let mut oversized = encoded(&example(1, b"oversized"));
        oversized[24..32].copy_from_slice(&(LIMITS.max_payload_len + 1).to_le_bytes());
        let expected = example(2, b"valid");
        let valid_offset = oversized.len() as u64;
        let mut bytes = oversized;
        bytes.extend(encoded(&expected));
        let mut scanner = Scanner::new(Cursor::new(bytes), LIMITS);

        assert!(matches!(
            next(&mut scanner),
            Event::InvalidRecord {
                offset: 0,
                error: record::Error::PayloadTooLarge { .. }
            }
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::Unrecognized { offset: 1, .. }
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::ValidRecord { offset, record, .. }
                if offset == valid_offset && record == expected
        ));
    }

    #[test]
    fn ignores_magic_inside_a_valid_payload() {
        let mut payload = b"before".to_vec();
        payload.extend(MAGIC);
        payload.extend(b"after");
        let expected = example(1, &payload);
        let mut scanner = Scanner::new(Cursor::new(encoded(&expected)), LIMITS);

        assert!(matches!(
            next(&mut scanner),
            Event::ValidRecord { record, .. } if record == expected
        ));
        assert!(scanner.next_event().unwrap().is_none());
    }

    #[test]
    fn reports_a_truncated_final_record() {
        let mut bytes = encoded(&example(1, b"complete"));
        let truncated_offset = bytes.len() as u64;
        let mut truncated = encoded(&example(2, b"incomplete"));
        truncated.truncate(truncated.len() - 5);
        bytes.extend(&truncated);
        let mut scanner = Scanner::new(Cursor::new(bytes), LIMITS);

        assert!(matches!(next(&mut scanner), Event::ValidRecord { .. }));
        assert!(matches!(
            next(&mut scanner),
            Event::InvalidRecord { offset, error: record::Error::Truncated }
                if offset == truncated_offset
        ));
        assert!(matches!(
            next(&mut scanner),
            Event::Unrecognized { offset, length }
                if offset == truncated_offset + 1 && length == truncated.len() as u64 - 1
        ));
        assert!(scanner.next_event().unwrap().is_none());
    }
}
