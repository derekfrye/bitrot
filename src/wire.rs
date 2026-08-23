//! Checked decoding of fixed-width little-endian wire values.

pub(crate) struct Reader<'a, F> {
    bytes: &'a [u8],
    invalid: F,
}

impl<'a, F> Reader<'a, F> {
    pub(crate) const fn new(bytes: &'a [u8], invalid: F) -> Self {
        Self { bytes, invalid }
    }
}

impl<F, E> Reader<'_, F>
where
    F: Fn() -> E,
{
    pub(crate) fn array<const N: usize>(&self, offset: usize) -> Result<[u8; N], E> {
        array(self.bytes, offset).ok_or_else(&self.invalid)
    }

    pub(crate) fn u16(&self, offset: usize) -> Result<u16, E> {
        u16(self.bytes, offset).ok_or_else(&self.invalid)
    }

    pub(crate) fn u32(&self, offset: usize) -> Result<u32, E> {
        u32(self.bytes, offset).ok_or_else(&self.invalid)
    }

    pub(crate) fn u64(&self, offset: usize) -> Result<u64, E> {
        u64(self.bytes, offset).ok_or_else(&self.invalid)
    }
}

pub(crate) fn array<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    bytes.get(offset..end)?.try_into().ok()
}

pub(crate) fn u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(array(bytes, offset)?))
}

pub(crate) fn u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(array(bytes, offset)?))
}

pub(crate) fn u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_values_at_offsets() {
        let bytes = [0xff, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(u16(&bytes, 1), Some(0x1234));
        assert_eq!(u32(&bytes, 3), Some(0x1234_5678));
        assert_eq!(array::<2>(&bytes, 1), Some([0x34, 0x12]));

        let reader = Reader::new(&bytes, || "truncated");
        assert_eq!(reader.u16(1), Ok(0x1234));
        assert_eq!(reader.u32(3), Ok(0x1234_5678));
        assert_eq!(reader.array::<2>(1), Ok([0x34, 0x12]));
    }

    #[test]
    fn rejects_truncated_and_overflowing_ranges() {
        assert_eq!(u64(&[0; 7], 0), None);
        assert_eq!(u16(&[0; 2], 1), None);
        assert_eq!(u16(&[0; 2], usize::MAX), None);
        assert_eq!(array::<0>(&[], 0), Some([]));

        let reader = Reader::new(&[0; 2], || "truncated");
        assert_eq!(reader.u64(0), Err("truncated"));
        assert_eq!(reader.u16(usize::MAX), Err("truncated"));
    }
}
