use bitrot::rolling::crc64_iso;
use crc::{CRC_64_GO_ISO, Crc, Table};
use std::hint::black_box;
use std::time::{Duration, Instant};

const CRC_TABLE_1: Crc<u64, Table<1>> = Crc::<u64, Table<1>>::new(&CRC_64_GO_ISO);
const CRC_TABLE_16: Crc<u64, Table<16>> = Crc::<u64, Table<16>>::new(&CRC_64_GO_ISO);
const ROUNDS: usize = 5;
const CHECKSUM_BYTES_PER_ROUND: usize = 256 * 1024 * 1024;
const TRANSITIONS_PER_ROUND: usize = 10_000_000;

fn main() {
    if cfg!(debug_assertions) {
        println!("crc_compare skipped outside an optimized bench build");
        return;
    }
    println!("CRC-64/GO-ISO release benchmark; median of {ROUNDS} rounds");
    println!("checksum throughput:");
    for size in [64 * 1024, 4 * 1024 * 1024, 64 * 1024 * 1024] {
        let data = test_data(size);
        let expected = crc64_iso(&data);
        assert_eq!(CRC_TABLE_1.checksum(&data), expected);
        assert_eq!(CRC_TABLE_16.checksum(&data), expected);
        let iterations = (CHECKSUM_BYTES_PER_ROUND / size).max(1);

        println!("  {}:", display_size(size));
        measure_bytes("bitrot table<16>", &data, iterations, || crc64_iso(&data));
        measure_bytes("crc table<1>", &data, iterations, || {
            CRC_TABLE_1.checksum(&data)
        });
        measure_bytes("crc table<16>", &data, iterations, || {
            CRC_TABLE_16.checksum(&data)
        });
    }

    println!("rolling raw transition latency:");
    let arithmetic = measure_transitions("bitrot arithmetic", arithmetic_transition);
    let table = measure_transitions("crc table<16>[0]", table_transition);
    assert_eq!(arithmetic, table);
}

fn measure_bytes<F>(name: &str, data: &[u8], iterations: usize, mut checksum: F)
where
    F: FnMut() -> u64,
{
    black_box(checksum());
    let mut samples = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let start = Instant::now();
        let mut value = 0_u64;
        for _ in 0..iterations {
            value ^= black_box(checksum());
        }
        black_box(value);
        samples.push(start.elapsed());
    }
    let elapsed = median(&mut samples);
    let total_bytes = u128::try_from(data.len()).unwrap() * u128::try_from(iterations).unwrap();
    let scaled_gib_per_second =
        total_bytes * 1_000_000_000 * 1_000 / (elapsed.as_nanos() * 1024 * 1024 * 1024);
    println!(
        "    {name:20} {:4}.{:03} GiB/s",
        scaled_gib_per_second / 1_000,
        scaled_gib_per_second % 1_000
    );
}

fn measure_transitions(name: &str, transition: fn(u64, u8) -> u64) -> u64 {
    let mut samples = Vec::with_capacity(ROUNDS);
    let mut final_state = 0_u64;
    for _ in 0..ROUNDS {
        let start = Instant::now();
        let mut state = u64::MAX;
        for index in 0..TRANSITIONS_PER_ROUND {
            state = transition(state, index.to_le_bytes()[0]);
        }
        black_box(state);
        final_state = state;
        samples.push(start.elapsed());
    }
    let elapsed = median(&mut samples);
    let scaled_nanos = elapsed.as_nanos() * 1_000 / u128::try_from(TRANSITIONS_PER_ROUND).unwrap();
    println!(
        "  {name:20} {:4}.{:03} ns/byte",
        scaled_nanos / 1_000,
        scaled_nanos % 1_000
    );
    final_state
}

fn arithmetic_transition(state: u64, byte: u8) -> u64 {
    let value = (state ^ u64::from(byte)) << 56;
    (state >> 8) ^ value ^ (value >> 1) ^ (value >> 3) ^ (value >> 4)
}

fn table_transition(state: u64, byte: u8) -> u64 {
    let index = usize::from((state ^ u64::from(byte)).to_le_bytes()[0]);
    CRC_TABLE_16.table()[0][index] ^ (state >> 8)
}

fn median(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn test_data(size: usize) -> Vec<u8> {
    let pattern: Vec<u8> = (0_u32..4096)
        .map(|index| {
            index
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223)
                .to_le_bytes()[2]
        })
        .collect();
    pattern.into_iter().cycle().take(size).collect()
}

fn display_size(size: usize) -> String {
    if size >= 1024 * 1024 {
        format!("{} MiB", size / (1024 * 1024))
    } else {
        format!("{} KiB", size / 1024)
    }
}
