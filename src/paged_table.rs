//! Shared bounded assembly for canonically paged tables.

#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) max_items: u64,
    pub(crate) max_pages: u32,
}

pub(crate) trait Page: Eq {
    fn page_index(&self) -> u32;
    fn first_item_index(&self) -> u64;
    fn item_count(&self) -> usize;
}

#[derive(Debug)]
pub(crate) struct BuiltPages<P> {
    pub(crate) item_count: u64,
    pub(crate) pages: Vec<P>,
}

#[derive(Debug)]
pub(crate) enum BuildError<E> {
    InvalidItemsPerPage,
    ItemCountUnrepresentable,
    PageCountUnrepresentable,
    ItemIndexOverflow,
    InvalidPage(E),
}

pub(crate) fn build_pages<T, P, E, F>(
    items: Vec<T>,
    items_per_page: usize,
    mut build_page: F,
) -> Result<BuiltPages<P>, BuildError<E>>
where
    F: FnMut(u32, u64, Vec<T>) -> Result<P, E>,
{
    if items_per_page == 0 {
        return Err(BuildError::InvalidItemsPerPage);
    }
    let item_count =
        u64::try_from(items.len()).map_err(|_| BuildError::ItemCountUnrepresentable)?;
    let page_capacity = items.len().div_ceil(items_per_page);
    let page_count =
        u32::try_from(page_capacity).map_err(|_| BuildError::PageCountUnrepresentable)?;

    let mut pages = Vec::with_capacity(page_capacity);
    let mut items = items.into_iter();
    let mut first_item_index = 0_u64;
    for page_index in 0..page_count {
        let page_items = items.by_ref().take(items_per_page).collect::<Vec<_>>();
        let page_item_count =
            u64::try_from(page_items.len()).map_err(|_| BuildError::ItemCountUnrepresentable)?;
        pages.push(
            build_page(page_index, first_item_index, page_items)
                .map_err(BuildError::InvalidPage)?,
        );
        first_item_index = first_item_index
            .checked_add(page_item_count)
            .ok_or(BuildError::ItemIndexOverflow)?;
    }

    Ok(BuiltPages { item_count, pages })
}

#[derive(Debug)]
pub(crate) enum Error<E> {
    ItemLimitExceeded {
        actual: u64,
        maximum: u64,
    },
    PageLimitExceeded {
        actual: u64,
        maximum: u32,
    },
    ItemCountUnrepresentable,
    PageCountUnrepresentable,
    LengthOverflow,
    InvalidPage(E),
    PageIndexOutOfRange {
        page_index: u32,
        page_count: u32,
    },
    FirstItemIndexMismatch {
        page_index: u32,
        actual: u64,
        expected: u64,
    },
    PageItemCountMismatch {
        page_index: u32,
        actual: usize,
        expected: usize,
    },
    ConflictingPage(u32),
    MissingPages(Vec<u32>),
}

pub(crate) fn assemble<P, I, E, V>(
    item_count: u64,
    items_per_page: usize,
    pages: I,
    limits: Limits,
    mut validate_page: V,
) -> Result<Vec<P>, Error<E>>
where
    P: Page,
    I: IntoIterator<Item = P>,
    V: FnMut(&P) -> Result<(), E>,
{
    if item_count > limits.max_items {
        return Err(Error::ItemLimitExceeded {
            actual: item_count,
            maximum: limits.max_items,
        });
    }
    let page_size = u64::try_from(items_per_page)
        .ok()
        .filter(|size| *size != 0)
        .ok_or(Error::LengthOverflow)?;
    let page_count = if item_count == 0 {
        0
    } else {
        ((item_count - 1) / page_size) + 1
    };
    if page_count > u64::from(limits.max_pages) {
        return Err(Error::PageLimitExceeded {
            actual: page_count,
            maximum: limits.max_pages,
        });
    }
    let page_count = usize::try_from(page_count).map_err(|_| Error::PageCountUnrepresentable)?;
    usize::try_from(item_count).map_err(|_| Error::ItemCountUnrepresentable)?;

    let mut slots = Vec::with_capacity(page_count);
    slots.resize_with(page_count, || None);
    for page in pages {
        validate_page(&page).map_err(Error::InvalidPage)?;
        let page_index = page.page_index();
        let index = usize::try_from(page_index).map_err(|_| Error::PageCountUnrepresentable)?;
        let Some(slot) = slots.get_mut(index) else {
            return Err(Error::PageIndexOutOfRange {
                page_index,
                page_count: u32::try_from(page_count)
                    .map_err(|_| Error::PageCountUnrepresentable)?,
            });
        };
        let expected_first = u64::from(page_index)
            .checked_mul(page_size)
            .ok_or(Error::LengthOverflow)?;
        if page.first_item_index() != expected_first {
            return Err(Error::FirstItemIndexMismatch {
                page_index,
                actual: page.first_item_index(),
                expected: expected_first,
            });
        }
        let remaining = item_count
            .checked_sub(expected_first)
            .ok_or(Error::LengthOverflow)?;
        let expected_count =
            usize::try_from(remaining.min(page_size)).map_err(|_| Error::LengthOverflow)?;
        if page.item_count() != expected_count {
            return Err(Error::PageItemCountMismatch {
                page_index,
                actual: page.item_count(),
                expected: expected_count,
            });
        }
        if let Some(existing) = slot {
            if existing != &page {
                return Err(Error::ConflictingPage(page_index));
            }
        } else {
            *slot = Some(page);
        }
    }

    let missing = slots
        .iter()
        .enumerate()
        .filter(|(_, page)| page.is_none())
        .map(|(index, _)| u32::try_from(index).map_err(|_| Error::PageCountUnrepresentable))
        .collect::<Result<Vec<_>, _>>()?;
    if !missing.is_empty() {
        return Err(Error::MissingPages(missing));
    }
    Ok(slots.into_iter().flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    #[test]
    fn builds_canonical_page_geometry() {
        let built = build_pages(vec![0, 1, 2, 3, 4], 2, |page, first, items| {
            Ok::<_, Infallible>((page, first, items))
        })
        .unwrap();

        assert_eq!(built.item_count, 5);
        assert_eq!(
            built.pages,
            vec![(0, 0, vec![0, 1]), (1, 2, vec![2, 3]), (2, 4, vec![4])]
        );
    }

    #[test]
    fn rejects_a_zero_page_size() {
        assert!(matches!(
            build_pages(Vec::<u8>::new(), 0, |_, _, _| Ok::<_, Infallible>(())),
            Err(BuildError::InvalidItemsPerPage)
        ));
    }
}
