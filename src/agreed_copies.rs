//! Shared reconciliation for redundantly stored logical records.

use crate::{bounded_count, record::Record};

#[derive(Clone, Copy, Debug)]
pub(crate) enum Error<E> {
    CopyLimitExceeded { actual: u64, maximum: u32 },
    Missing,
    InvalidCopy(E),
    ConflictingCopies,
}

pub(crate) fn assemble<'a, T, E, I, D>(
    records: I,
    max_copies: Option<u32>,
    mut decode: D,
) -> Result<T, Error<E>>
where
    T: Eq,
    I: IntoIterator<Item = &'a Record>,
    D: FnMut(&Record) -> Result<T, E>,
{
    let mut agreed = None;
    let mut copies = 0_u64;
    for record in records {
        copies = bounded_count::increment(copies);
        if let Some(maximum) = max_copies
            && copies > u64::from(maximum)
        {
            return Err(Error::CopyLimitExceeded {
                actual: copies,
                maximum,
            });
        }
        let candidate = decode(record).map_err(Error::InvalidCopy)?;
        if let Some(existing) = &agreed {
            if existing != &candidate {
                return Err(Error::ConflictingCopies);
            }
        } else {
            agreed = Some(candidate);
        }
    }
    agreed.ok_or(Error::Missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(logical_id: u64) -> Record {
        Record {
            record_type: 1,
            flags: 0,
            protection_set_id: [0; 32],
            logical_id,
            header_extension: Vec::new(),
            payload: Vec::new(),
        }
    }

    #[test]
    fn reconciles_identical_copies_and_rejects_conflicts() {
        let identical = [record(7), record(7)];
        assert_eq!(
            assemble(identical.iter(), None, |record| Ok::<_, ()>(
                record.logical_id
            ))
            .unwrap(),
            7
        );

        let conflicting = [record(7), record(8)];
        assert!(matches!(
            assemble(conflicting.iter(), None, |record| Ok::<_, ()>(
                record.logical_id
            )),
            Err(Error::ConflictingCopies)
        ));
    }

    #[test]
    fn reports_missing_invalid_and_over_limit_inputs() {
        let empty: [Record; 0] = [];
        assert!(matches!(
            assemble(empty.iter(), None, |_| Ok::<_, ()>(())),
            Err(Error::Missing)
        ));

        let invalid = [record(1)];
        assert!(matches!(
            assemble(invalid.iter(), None, |_| Err::<(), _>("invalid")),
            Err(Error::InvalidCopy("invalid"))
        ));

        let over_limit = [record(1), record(1)];
        assert!(matches!(
            assemble(over_limit.iter(), Some(1), |_| Ok::<_, ()>(())),
            Err(Error::CopyLimitExceeded {
                actual: 2,
                maximum: 1
            })
        ));
    }
}
