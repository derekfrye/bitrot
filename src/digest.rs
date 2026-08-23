//! Strong digest values shared across the Bitrot format.

/// A full 256-bit BLAKE3 digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Digest([u8; 32]);

impl Digest {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<blake3::Hash> for Digest {
    fn from(hash: blake3::Hash) -> Self {
        Self(*hash.as_bytes())
    }
}
