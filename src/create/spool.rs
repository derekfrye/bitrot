use crate::fingerprint::{self, Digest};
use crate::geometry::Geometry;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

pub(super) struct RecoverySpool {
    file: File,
    geometry: Geometry,
}

impl RecoverySpool {
    pub(super) fn new(file: File, geometry: Geometry) -> io::Result<Self> {
        file.set_len(geometry.recovery_storage_len())?;
        Ok(Self { file, geometry })
    }

    pub(super) fn write_window(
        &mut self,
        offset: usize,
        index: usize,
        bytes: &[u8],
    ) -> io::Result<()> {
        let chunk_size = u64::from(self.geometry.chunk_size.bytes());
        let index = u64::try_from(index).map_err(|_| invalid_spool_position())?;
        let offset = u64::try_from(offset).map_err(|_| invalid_spool_position())?;
        let window_end = offset
            .checked_add(u64::try_from(bytes.len()).map_err(|_| invalid_spool_position())?)
            .ok_or_else(invalid_spool_position)?;
        let position = index
            .checked_mul(chunk_size)
            .and_then(|position| position.checked_add(offset))
            .ok_or_else(invalid_spool_position)?;
        let end = position
            .checked_add(u64::try_from(bytes.len()).map_err(|_| invalid_spool_position())?)
            .ok_or_else(invalid_spool_position)?;
        if index >= u64::from(self.geometry.recovery_chunks)
            || offset > chunk_size
            || window_end > chunk_size
            || end > self.geometry.recovery_storage_len()
        {
            return Err(invalid_spool_position());
        }
        self.file.seek(SeekFrom::Start(position))?;
        self.file.write_all(bytes)
    }

    pub(super) fn digests(&mut self) -> io::Result<Vec<Digest>> {
        let mut digests = Vec::new();
        let recovery_chunks =
            usize::try_from(self.geometry.recovery_chunks).map_err(|_| invalid_spool_position())?;
        digests
            .try_reserve_exact(recovery_chunks)
            .map_err(io::Error::other)?;
        for index in 0..self.geometry.recovery_chunks {
            let bytes = self.read_chunk(index)?;
            digests.push(fingerprint::recovery_chunk_digest(&bytes));
        }
        Ok(digests)
    }

    pub(super) fn read_chunk(&mut self, index: u32) -> io::Result<Vec<u8>> {
        if index >= self.geometry.recovery_chunks {
            return Err(invalid_spool_position());
        }
        let chunk_size = usize::try_from(self.geometry.chunk_size.bytes())
            .map_err(|_| invalid_spool_position())?;
        let position = u64::from(index)
            .checked_mul(u64::from(self.geometry.chunk_size.bytes()))
            .ok_or_else(invalid_spool_position)?;
        let mut bytes = vec![0_u8; chunk_size];
        self.file.seek(SeekFrom::Start(position))?;
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

fn invalid_spool_position() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid recovery spool position",
    )
}
