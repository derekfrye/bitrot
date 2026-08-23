use crate::digest::Digest;
use crate::digest_page::{Kind, Table};
use crate::fingerprint::recovery_chunk_digest;
use crate::geometry::{ChunkSize, Geometry, MIN_CHUNK_SIZE};
use crate::manifest::Manifest;
use crate::metadata::Metadata;
use crate::record::Record;
use crate::recovery_chunk::RecoveryChunk;
use crate::rolling_page;

pub(crate) struct RecoveryFixture {
    pub(crate) metadata: Metadata,
    pub(crate) recovery_chunks: Vec<RecoveryChunk>,
}

impl RecoveryFixture {
    pub(crate) fn metadata_records(&self) -> Vec<Record> {
        let manifest = self.metadata.manifest;
        let set_id = manifest.protection_set_id();
        let mut records = vec![manifest.to_record()];
        records.extend(
            self.metadata
                .data_digests
                .pages
                .iter()
                .map(|page| page.to_record(set_id).unwrap()),
        );
        records.extend(
            self.metadata
                .recovery_digests
                .pages
                .iter()
                .map(|page| page.to_record(set_id).unwrap()),
        );
        records.extend(
            self.metadata
                .rolling_fingerprints
                .pages
                .iter()
                .map(|page| page.to_record(set_id).unwrap()),
        );
        records
    }

    pub(crate) fn recovery_records(&self) -> Vec<Record> {
        let manifest = self.metadata.manifest;
        self.recovery_chunks
            .iter()
            .map(|chunk| chunk.to_record(manifest).unwrap())
            .collect()
    }
}

pub(crate) fn recovery_fixture() -> RecoveryFixture {
    let chunk_size = ChunkSize::new(u64::from(MIN_CHUNK_SIZE)).unwrap();
    let geometry = Geometry::from_stored(
        u64::from(chunk_size.bytes()),
        chunk_size,
        1,
        2,
        chunk_size.bytes(),
    )
    .unwrap();
    let parity = [
        vec![0xa5; chunk_size.bytes() as usize],
        vec![0x5a; chunk_size.bytes() as usize],
    ];
    let data_digests = Table::new(Kind::Data, vec![Digest::from_bytes([1; 32])]).unwrap();
    let recovery_digests = Table::new(
        Kind::Recovery,
        parity
            .iter()
            .map(|bytes| recovery_chunk_digest(bytes))
            .collect(),
    )
    .unwrap();
    let rolling_fingerprints = rolling_page::Table::new(vec![7]).unwrap();
    let manifest = Manifest::new(
        geometry,
        Digest::from_bytes([3; 32]),
        &data_digests,
        &recovery_digests,
        &rolling_fingerprints,
    )
    .unwrap();
    let recovery_chunks = parity
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            RecoveryChunk::new(manifest, u32::try_from(index).unwrap(), bytes).unwrap()
        })
        .collect();

    RecoveryFixture {
        metadata: Metadata {
            manifest,
            data_digests,
            recovery_digests,
            rolling_fingerprints,
        },
        recovery_chunks,
    }
}
