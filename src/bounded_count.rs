//! Overflow-safe arithmetic for resource-bounded item counts.

pub(crate) const fn increment(count: u64) -> u64 {
    count.saturating_add(1)
}

pub(crate) fn from_usize(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

pub(crate) fn after_push(current_len: usize) -> u64 {
    increment(from_usize(current_len))
}

pub(crate) fn items<I>(items: I) -> u64
where
    I: IntoIterator,
{
    items.into_iter().fold(0_u64, |count, _| increment(count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_items_and_saturates_arithmetic() {
        assert_eq!(items([1, 2, 3]), 3);
        assert_eq!(increment(u64::MAX), u64::MAX);
        assert_eq!(
            after_push(usize::MAX),
            u64::try_from(usize::MAX)
                .unwrap_or(u64::MAX)
                .saturating_add(1)
        );
    }
}
