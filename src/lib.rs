//! Core primitives for the Bitrot protection format.

mod algorithm;
pub mod coding;
pub mod creator;
pub mod digest;
pub mod digest_page;
pub mod fingerprint;
pub mod geometry;
pub mod manifest;
pub mod metadata;
mod paged_table;
pub mod record;
pub mod recovery_chunk;
pub mod recovery_set;
pub mod rolling;
pub mod rolling_page;
pub mod scan;
pub mod sidecar;
pub mod superblock;
mod wire;
