//! Core primitives for the Bitrot protection format.

mod agreed_copies;
mod algorithm;
mod bounded_count;
pub mod coding;
pub mod create;
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
pub mod repair;
pub mod rolling;
pub mod rolling_page;
pub mod scan;
pub mod sidecar;
pub mod superblock;
#[cfg(test)]
mod test_support;
pub mod verify;
mod wire;
