# Performance Cleanup

Potential performance problems and workaround-shaped designs identified by a
repository audit. These are structural findings, not benchmark-confirmed
regressions. Measure representative source sizes, chunk counts, coding-window
sizes, storage devices, and contention cases before and after changing them.

## Priorities

### Coding seek amplification

- [ ] Benchmark and reduce seek amplification in `coding::WindowEncoder::encode_source`.
  The loop processes coding-window offsets before data chunks and seeks before
  every shard-window read. This produces approximately
  `data_chunks * (chunk_size / coding_window_bytes)` seeks and repeatedly jumps
  across the source. Repair uses the same window-first access pattern.
- [ ] Investigate an I/O layout that retains bounded coding memory while using
  larger sequential reads, positional I/O, reusable shard buffers, or another
  strategy appropriate to both files and generic `Read + Seek` implementations.
- [ ] Keep short final-chunk padding, bounded workspace, and source-change
  detection semantics intact.

Relevant code:

- `src/coding.rs`, `WindowEncoder::encode_source`
- `src/repair.rs`, `reconstruct_windows` and `read_available_windows`

### Repair workspace churn

- [ ] Reuse repair workspace across coding windows. `read_available_windows`
  currently creates a new outer vector and allocates one zero-filled buffer per
  available data chunk for every window.
- [ ] Reuse the recovery-window descriptor vector where practical.
- [ ] Confirm that reuse remains bounded by `coding_window_bytes` and continues
  to clear padding and stale bytes correctly between windows.

Relevant code:

- `src/repair.rs`, `read_available_windows` and `recovery_windows`

### Recovery spool I/O

- [ ] Benchmark recovery spooling with realistic recovery counts and window
  sizes. `RecoverySpool::write_window` seeks and writes once per recovery
  shard/window, which can create highly fragmented I/O.
- [ ] Reduce redundant recovery-data passes. Publication currently reads each
  complete spooled recovery chunk to calculate digests and reads it again while
  constructing the sidecar.
- [ ] Consider incremental per-shard digest state during spooling, batched or
  positional writes, and reusable read buffers. Preserve bounded memory and
  recovery-digest authentication.

Relevant code:

- `src/create/spool.rs`
- `src/create/publish.rs`, `CanonicalPlan::write`

### Stale temporary cleanup latency

- [ ] Revisit the stale-lock retry loop. If any qualifying old temporary is
  locked, cleanup sleeps for 1 ms and rescans the entire directory until the
  lock disappears or the 100 ms deadline expires.
- [ ] Avoid making publication wait for an unrelated locked partial. Candidate
  designs include tracking and retrying only contended entries or leaving them
  for a later invocation.
- [ ] Preserve handling of locks inherited across process creation, path
  substitution protection, quarantine-before-removal, and directory syncing.

Relevant code:

- `src/filesystem.rs`, `cleanup_stale_temporaries_with_contention_hook`

## Additional opportunities

### Whole-file passes during creation and publication

- [ ] Measure the cost of the three source passes used by creation: initial
  fingerprinting, coding, and confirmation fingerprinting.
- [ ] Document which source-change guarantees require each pass and investigate
  whether any work can safely be combined without weakening those guarantees.
- [ ] Measure the complete parity/sidecar passes in publication: spool digesting,
  sidecar construction, pre-publication verification, and post-publication
  verification.
- [ ] State the fault and attacker model before removing or consolidating a
  verification pass. Several of these passes are deliberate integrity and
  TOCTOU defenses rather than accidental duplication.

Relevant code:

- `src/create.rs`, `analyze` and `encode_and_confirm`
- `src/create/publish.rs`, `publish` and `verify_published`

### Byte-at-a-time displaced-chunk scanning

- [ ] Benchmark displaced-chunk scans independently of CRC implementation
  benchmarks. The scanner consumes one byte at a time through `BufReader` and
  performs a rolling-checksum hash-table lookup for every full window.
- [ ] Investigate block-oriented ring-buffer processing that retains the same
  rolling checksum, match offsets, early stopping, and bounded memory.
- [ ] Avoid optimizing the rare strong-match allocation before measuring it;
  `chunk_indices` is allocated only for rolling-checksum candidates that also
  have strong matches.

Relevant code:

- `src/rolling.rs`, `TargetIndex::scan`, `check_candidate`, and `read_byte`

### Metadata validation cloning

- [ ] Remove the need to clone every digest and rolling page during
  `Metadata::validate`.
- [ ] Prefer making validated table internals private and immutable, then
  validating borrowed state or maintaining construction-time invariants. This
  overlaps the invalid-state cleanup in `docs/some_items_to_fix.md`.

Relevant code:

- `src/metadata.rs`, `Metadata::validate`
- `src/digest_page.rs`
- `src/rolling_page.rs`

## Audited patterns that are not current concerns

- The only production `Box` found is the `Content(Box<PublishError>)` variant of
  `PublishedVerificationError`. It breaks a recursive error-type cycle and
  allocates only on an exceptional publication failure path.
- Boxed mutation closures in `src/superblock.rs` are test-only.
- The other explicit `thread::sleep` found is test-only.
- No production `Arc<Mutex<_>>`, `Mutex`, `RwLock`, async blocking bridge, or
  application thread pool was found.
- Most conspicuous `clone` calls are test-only. Metadata page cloning during
  validation is the notable production cleanup item listed above.

## Suggested measurement order

1. Coding and repair seek counts, throughput, and CPU utilization.
2. Repair allocation counts and peak resident memory.
3. Recovery-spool write/read patterns and total bytes transferred.
4. Stale-cleanup latency under one and many contended entries.
5. Creation/publication whole-file pass costs.
6. Displaced-scan throughput.
7. Metadata-validation allocation costs.
