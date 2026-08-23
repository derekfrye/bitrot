# Bitrot protection format and Rust tool

Status: design sketch; not a frozen file-format specification.

## Summary

Replace the current PowerShell and `par2cmdline` workflow with a standalone
Rust program for detecting and repairing corruption in large, mostly immutable
media files.

The proposed format combines:

- BLAKE3 fingerprints for the complete source file and every data chunk.
- A rolling fingerprint for finding intact chunks that moved from their
  expected offsets.
- Leopard-style Reed-Solomon erasure coding for recovery chunks.
- Independently checksummed records and repeated manifests so damage to the
  sidecar does not automatically make all recovery data unusable.
- Verification before repair, repair into a new file, and complete
  verification before replacement of the damaged file.

The working sidecar extension is `.bitrot`. The name, magic bytes, and binary
encoding remain provisional until interoperability fixtures exist.

## Motivation

The observed failure mode is silent corruption in media files: files remain
present and usually retain their length, but bytes or storage sectors no longer
contain the data originally written. Whole-device failure is also possible,
but it is primarily addressed by an independent backup or redundant storage.

PAR2 already addresses this problem well. This project is intended to improve
hashing, performance, deployment, and repair safety while retaining the useful
properties of PAR2. It must not assume that a faster parity kernel alone is a
complete archival design.

## Goals

- Detect corruption with negligible probability of accepting bad data.
- Repair missing or corrupt chunks regardless of where they occur in a file,
  up to the configured recovery capacity.
- Remain usable when some recovery chunks or sidecar metadata are corrupt.
- Bound memory use while processing files much larger than RAM.
- Produce a single, portable Rust executable with no `par2cmdline` dependency.
- Make verification read-only and make repair power-loss-safe.
- Specify the on-disk format sufficiently for an independent implementation.
- Preserve unknown records when safely rewriting a sidecar, allowing future
  format extensions.

## Non-goals

- Replacing independent, preferably off-site backups.
- Repairing a lost disk when both the media and its sidecar existed only on
  that disk.
- Protecting files that are actively modified in place.
- Compression, encryption, deduplication, or general-purpose archiving in v1.
- PAR2 or PAR3 wire compatibility.
- Optimizing for network packet delivery; this is a storage format.

## Failure model

Version 1 should handle:

- Random bit flips.
- Sparse corrupt sectors distributed throughout a file.
- Contiguous overwritten or zero-filled ranges.
- Read errors and holes reported by the filesystem.
- Truncation or accidental extension.
- A limited amount of corruption in the `.bitrot` sidecar itself.
- Data appearing at a different offset because bytes were inserted, deleted,
  or copied to the wrong location.
- Interruption during create or repair.

The program cannot recover when the number of unavailable data chunks exceeds
the number of usable recovery chunks. Damage to a recovery chunk consumes the
same recovery budget as damage to a data chunk.

Hardware, RAM, controller, cabling, filesystem, and software faults can all
produce corruption. Repairs must therefore be verified from disk rather than
assuming successful writes are durable or correct.

## Coding model

### Terminology

- **Data chunk:** A fixed-size piece of the original file. The final chunk is
  logically padded with zeroes for coding.
- **Recovery chunk:** A parity shard generated from all data chunks in its
  coding group.
- **Protection set:** One source file, its metadata, and its recovery chunks.
- **Manifest:** The metadata required to identify, verify, and reconstruct a
  protection set.
- **Record:** An independently framed and checksummed unit in a sidecar.

Version 1 protects one source file per protection set. Supporting directories
or multiple files in a shared set is deferred because it complicates updates,
tail packing, and failure isolation.

### Chunk geometry

The experimental version 1 default data chunk size is 4 MiB, configurable at
creation. Values are powers of two from 64 KiB through 64 MiB, inclusive. A
1 MiB option is available when resistance to highly sparse corruption matters
more than metadata and coding overhead. These bounds remain provisional until
benchmarks and interoperability fixtures freeze version 1.

If a file has `k` data chunks and redundancy is `r`, create:

```text
m = ceil(k * r)
```

Creation represents `r` as a reduced positive integer numerator and
denominator and evaluates the ceiling with checked integer arithmetic. Binary
floating point is not used. The actual data and recovery counts, rather than
the policy ratio, are stored in the manifest.

recovery chunks. Thus 15% redundancy means 1,000 data chunks produce 150
recovery chunks. Any 150 unavailable chunks among the 1,150 total chunks can be
reconstructed by an MDS code. It does not matter whether the missing data
chunks are adjacent or scattered.

One corrupt byte invalidates its complete data chunk. Consequently, 151
single-byte corruptions in 151 different chunks exceed the example's capacity,
while a large amount of damage confined to 150 chunks remains recoverable.

The format records counts and sizes explicitly and validates them before any
allocation. Creation must reject geometries outside the selected coding
backend's supported shard limits.

### Coding groups and memory

Global coding across all chunks provides the strongest distribution-independent
guarantee. Dividing a file into small independent stripes weakens that
guarantee: one damaged stripe may exceed its local parity allowance even when
unused parity exists in other stripes.

Version 1 should therefore use one global coding group when supported. The
implementation must process subranges of each shard in bounded-memory windows
rather than loading the source file and recovery data into RAM at once.

The experimental implementation divides every chunk into equal, positive,
even-sized coding windows. The window size must divide the chunk size exactly.
Windows at the same byte offset in every data chunk are coded together, and
the short final data chunk is zero-padded by the source encoder. Concatenating
the recovery windows in offset order produces the same recovery chunks as
coding complete chunks at once; the window size is therefore an implementation
resource choice rather than a stored format parameter.

The experimental implementation targets the pure-Rust `reed-solomon-simd` 3.1
Leopard GF(2^16) construction. One global group requires positive data and
recovery counts, each below 65,536, and:

```text
min(next_power_of_two(data), next_power_of_two(recovery))
    + max(data, recovery) <= 65,536
```

Creation currently rejects geometry outside that boundary. Automatic fallback
grouping is deferred until group membership and its weaker per-group recovery
guarantee have an exact manifest representation. The dependency does not yet
define the archival format: coding details and independent fixtures still
must be frozen before interoperability is claimed.

If backend constraints require more than one coding group, groups must be as
large as practical. The manifest records each group's exact data and recovery
membership. The CLI must explain that recovery capacity then applies per group,
not globally.

### Erasure coding

Use a pure-Rust, SIMD-capable Leopard-RS implementation over GF(2^16), subject
to dependency review and compatibility fixtures. The format must record the
coding algorithm and its parameters rather than treating the current library's
behavior as an implicit specification.

The specification must eventually define:

- Field and basis.
- Evaluation points or transform construction.
- Shard ordering.
- Padding rules.
- Byte and symbol endianness.
- Recovery-index assignment.

Golden fixtures generated by an independent implementation are required before
the format is declared stable.

## Integrity and identification

### Strong hashes

Use unkeyed BLAKE3 with explicit domain separation for:

- The complete unpadded source file.
- Every unpadded data chunk, including the short final chunk.
- Every stored recovery chunk.
- Manifest identity.
- Complete record integrity.

Store full 256-bit BLAKE3 digests in v1. Truncation saves little relative to
large media files and would make the collision argument harder to audit.

The experimental version 1 implementation uses BLAKE3 derive-key mode with
the exact UTF-8 context strings `bitrot format v1 source file digest` and
`bitrot format v1 data chunk digest`. Recovery chunks use the context string
`bitrot format v1 recovery chunk digest`. The source digest covers exactly the
complete unpadded source bytes. Each data-chunk digest covers exactly that
chunk's unpadded bytes; in particular, the short final chunk's coding padding
is excluded. A recovery digest covers exactly one complete stored parity
chunk. Read boundaries are not chunk boundaries.

The protection-set identifier is derived from immutable coding parameters,
source length, full-file digest, and ordered data-chunk digests. The filename is
metadata, not identity, so a renamed intact file can still be recognized.

### Locating corruption

At expected offsets, compute each data chunk's BLAKE3 digest. A mismatch marks
the chunk as an erasure. Reed-Solomon reconstruction must never consume a chunk
that failed its strong digest.

Fixed offsets do not cope well with insertion or deletion: all later chunks
would appear damaged. To retain PAR2-like resynchronization, the manifest also
stores a rolling fingerprint for each full-size data chunk. On demand, a scan
uses rolling fingerprints to find candidates at unexpected offsets, then
confirms every candidate with BLAKE3 before accepting it.

The experimental version 1 rolling algorithm is CRC-64/GO-ISO: polynomial
`0x000000000000001B`, reflected input and output, initial value and final XOR
`0xFFFFFFFFFFFFFFFF`. Its reflected polynomial representation is
`0xD800000000000000`; the check value for ASCII `123456789` is
`0xB90956C775A41001`. These are the CRC64-ISO semantics used by PAR3's sliding
block search.

Creation stores one rolling value for every full-size data chunk, including an
exact-size final chunk, but none for a short final chunk. A resynchronization
scan advances the fixed-size window one byte at a time using PAR3's outgoing
byte table and window-mask recurrence. The rolling value only selects
candidates. Every candidate is recomputed with the full domain-separated
BLAKE3 data-chunk digest before it is accepted. Identical expected chunks may
share one confirmed candidate; no data is trusted based solely on CRC64.

The short final chunk is located using its strong digest and known length rather
than a full-size rolling window.

## Sidecar format

The sidecar is an appendable sequence of independently framed records. A
damaged record can be skipped without losing the remainder of the file.

Each record contains at least:

```text
magic
format version
record type
header length
payload length
protection-set identifier
sequence or logical identifier
payload
record digest
```

All integer widths, endianness, maximum lengths, digest coverage, and alignment
rules must be fixed before v1 is frozen. Parsers must reject overflow,
impossible lengths, duplicate logical identifiers with conflicting contents,
and resource requests inconsistent with the manifest.

The record digest covers the canonical encoded header (excluding the digest
field itself) and payload. Header corruption must not be able to redirect or
reinterpret an otherwise valid payload.

### Experimental version 1 record frame

The first implemented format primitive uses the following frame. It remains
experimental until interoperability fixtures freeze the format. All integers
are unsigned and little-endian; offsets are in bytes from the start of the
record.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | Magic: the bytes `BITROT\r\n` |
| 8 | 2 | Format version, currently 1 |
| 10 | 2 | Record type; zero is reserved |
| 12 | 4 | Flags; bit 0 means the record is required |
| 16 | 4 | Complete header length, including the base header |
| 20 | 4 | Reserved; must be zero |
| 24 | 8 | Payload length |
| 32 | 32 | Protection-set identifier |
| 64 | 8 | Record-type-specific logical identifier |
| 72 | variable | Preserved header-extension bytes |
| header length | variable | Payload |
| after payload | 32 | BLAKE3 record digest |

The minimum header length is 72 bytes. Readers reject unknown flag bits but
retain header-extension bytes and unknown optional record types. This permits
safe copying of records whose semantics are not understood. A reader must
apply caller- or operation-specific header and payload limits before
allocation.

The record digest is BLAKE3 in derive-key mode with the exact UTF-8 context
string `bitrot format v1 record digest`. Its input is the complete header from
the magic through any header extensions, followed immediately by the payload.
The trailing digest itself is excluded.

Readers resynchronize by scanning bytewise for the eight-byte magic. Each
candidate must pass structural validation, operation-specific length limits,
and its complete record digest before it is accepted. After a failed candidate,
scanning resumes one byte after that candidate's start. This also handles magic
bytes occurring in damaged payload data. Bytes between validated records are
reported as unrecognized damage; they are not silently ignored. Magic inside
the payload of a valid record is never interpreted as another record.

Required logical record types are:

- Superblock: format capabilities and locations or hints for other records.
- Core manifest: source metadata, coding geometry, algorithms, and digest-table
  roots.
- Digest-table page: a bounded portion of the ordered data or recovery digest
  table.
- Rolling-table page: a bounded portion of the ordered full-chunk CRC table.
- Recovery chunk: recovery index, logical length, and parity bytes.
- Creator: implementation name and version for diagnostics.

Optional records may include comments and original path metadata. Readers skip
unknown optional record types. Unknown required feature bits cause a clean
failure.

### Experimental core manifest

Record type 2 is the required core manifest. Its logical identifier is zero,
and version 1 has no record-header extension. Its fixed 192-byte payload is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Payload version, currently 1 |
| 2 | 2 | Required feature bits, currently zero |
| 4 | 2 | Coding algorithm: 1 = Leopard GF(2^16) |
| 6 | 2 | Strong hash: 1 = full BLAKE3 derive-key digest |
| 8 | 2 | Rolling algorithm: 1 = CRC-64/GO-ISO |
| 10 | 2 | Reserved; must be zero |
| 12 | 4 | Data chunk size |
| 16 | 8 | Unpadded source length |
| 24 | 4 | Data chunk count |
| 28 | 4 | Recovery chunk count |
| 32 | 4 | Unpadded final data chunk length |
| 36 | 4 | Reserved; must be zero |
| 40 | 32 | Full source digest |
| 72 | 8 | Data digest count; must equal data chunk count |
| 80 | 32 | Data digest-table root |
| 112 | 8 | Recovery digest count; must equal recovery chunk count |
| 120 | 32 | Recovery digest-table root |
| 152 | 8 | Rolling value count; must equal full data chunk count |
| 160 | 32 | Rolling fingerprint-table root |

The protection-set identifier uses BLAKE3 derive-key mode with context
`bitrot format v1 protection set identifier`. In order, its input is the
payload version; coding, strong-hash, and rolling algorithm identifiers; chunk
size; source length; data and recovery counts; final data-chunk length; source
digest; data digest count; and data digest-table root, all using the widths and
little-endian encoding above. The recovery and rolling roots are deliberately
excluded: the set identity describes the source and immutable coding request,
while recovery records and rolling fingerprints are committed, validated
content within that set. Readers recompute this identifier and require it to
match the record header.

### Experimental rolling-fingerprint pages

Record type 4 is a required rolling-table page. Its logical identifier is the
page index in bits 0 through 31 with all higher bits zero. Version 1 pages have
no record-header extension. Their payload is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Payload version, currently 1 |
| 2 | 2 | Reserved; must be zero |
| 4 | 4 | Zero-based page index |
| 8 | 8 | Zero-based index of the first rolling value |
| 16 | 4 | Number of rolling values in this page |
| 20 | 4 | Reserved; must be zero |
| 24 | variable | Consecutive little-endian `u64` CRC-64/GO-ISO values |

A page contains between 1 and 4,096 values. Page boundaries and redundant-copy
assembly follow the same canonical rules as digest-table pages. An empty table
has no pages, which occurs when the source is shorter than one data chunk. The
table root uses BLAKE3 derive-key mode with context
`bitrot format v1 rolling fingerprint table root`; its input is the value count
as a little-endian `u64`, followed by every rolling value as a little-endian
`u64` in data-chunk order. The short final chunk has no rolling value.

### Experimental digest-table pages

Record type 3 is a required digest-table page. Its logical identifier stores
the table kind in bits 56 through 63 (`1` for data and `2` for recovery), the
page index in bits 0 through 31, and zeroes in the remaining bits. Version 1
pages have no record-header extension. Their payload is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Payload version, currently 1 |
| 2 | 1 | Table kind: 1 data, 2 recovery |
| 3 | 1 | Reserved; must be zero |
| 4 | 4 | Zero-based page index |
| 8 | 8 | Zero-based index of the first digest |
| 16 | 4 | Number of digests in this page |
| 20 | 4 | Reserved; must be zero |
| 24 | variable | Consecutive full 32-byte digests |

A page contains between 1 and 4,096 digests, so its payload is at most 128 KiB
plus the 24-byte page header. Empty tables have no pages. Page boundaries are
canonical: all pages except the last contain 4,096 digests.

The core manifest commits to each complete ordered table with a table root.
The root uses BLAKE3 derive-key mode with the exact context string
`bitrot format v1 data digest table root` or
`bitrot format v1 recovery digest table root`. Its input is the digest count as
one little-endian `u64`, followed by every full digest in order. The root is
independent of page boundaries. Record checksums establish each physical
page's integrity; the table root detects missing, reordered, or substituted
pages once the complete table is assembled.

Table assembly applies explicit caller-selected digest and page limits before
allocating page slots. Pages may arrive in any physical order. Identical valid
copies of the same logical page are accepted and collapsed. Valid copies with
different contents are a conflict and make the table unusable. Assembly also
requires the table kind, page indexes, first-digest indexes, page sizes, and
final table root to agree with the core manifest. Every non-final page must
contain 4,096 digests; every expected page must be present. Readers never pick
one of two conflicting valid copies.

### Experimental recovery-chunk records

Record type 5 is a required recovery chunk. Its logical identifier is the
zero-based recovery index, and version 1 has no record-header extension. Its
payload is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Payload version, currently 1 |
| 2 | 2 | Coding algorithm: 1 = Leopard GF(2^16) |
| 4 | 4 | Zero-based recovery index |
| 8 | 4 | Data chunk count |
| 12 | 4 | Recovery chunk count |
| 16 | 4 | Data and recovery chunk size |
| 20 | 4 | Logical parity length; equal to chunk size in version 1 |
| 24 | 8 | Reserved; must be zero |
| 32 | variable | Complete parity chunk bytes |

The protection-set identifier in the record frame associates the shard with a
manifest. The duplicated index and coding geometry must agree with that
manifest before the parity payload is used. Record framing limits are derived
from the manifest's chunk size and applied before the generic record decoder
allocates the payload. The payload contains exactly one full-size recovery
chunk; unlike the final data chunk it is never short. Its domain-separated
BLAKE3 digest must equal the digest at the same index in the assembled recovery
digest table. Thus both the physical record checksum and the logical manifest
commitment must pass before decoding uses a recovery shard.

### Metadata redundancy

The logical manifest consists of a small core manifest plus bounded digest- and
rolling-table pages. Paging prevents one damaged byte from invalidating a
complete table.
The manifest is necessary to interpret recovery data and must not be a single
point of failure. At minimum:

- Store identical, independently checksummed copies of the core manifest and
  every digest- and rolling-table page near the beginning and end of the
  sidecar.
- Put a compact superblock at both ends.
- Include enough identity and coding metadata in every recovery record to
  associate it with the correct set and recovery index.
- Require agreement between valid manifest copies; conflicting valid copies are
  an error, not an invitation to guess.

If split recovery volumes are added, every volume contains a superblock and a
complete manifest copy. Future work may also parity-protect large digest tables,
but simple repetition is easier to validate for v1.

### Single sidecar versus volumes

Version 1 may begin with one `.bitrot` file per source file. Independent record
checksums allow damaged recovery records to be discarded. Split volumes are a
useful later feature for storing parity across devices and copying only part of
a recovery set.

The creator must write to a uniquely named temporary file in the destination
directory, flush it, verify its records, and atomically rename it into place.
It must not publish a partially created sidecar.

## Operations

### Create

Proposed interface:

```text
bitrot create --redundancy 15% --chunk-size 4MiB \
  --output-dir /jellyfin_par2 /jellyfin_data2/movie.mkv
```

Creation performs these steps:

1. Open the source without following a substituted path unexpectedly.
2. Capture file identity, length, modification time, and other useful stat data.
3. Stream the source to calculate full-file and chunk fingerprints.
4. Generate recovery chunks using bounded memory.
5. Recheck source metadata and digest; abort if the source changed.
6. Finish and flush the temporary sidecar.
7. Parse and verify the new sidecar from disk.
8. Atomically rename it and sync the containing directory where supported.

An existing valid sidecar is not overwritten unless explicitly requested. A
matching sidecar makes creation a successful no-op. A conflicting sidecar is
reported and preserved.

### Verify

```text
bitrot verify /jellyfin_data2/movie.mkv \
  /jellyfin_par2/movie.mkv.bitrot
```

Verification is read-only. It reports:

- Source and sidecar identity.
- Good, corrupt, unreadable, and unexpectedly located data chunks.
- Good and corrupt recovery chunks.
- Required versus available recovery capacity.
- Whether repair is possible.

Exit statuses distinguish intact, damaged-but-repairable, damaged-unrepairable,
invalid-sidecar, and operational failure. Machine-readable JSON output should
be supported from the first stable CLI version.

Fast verification may check metadata and a requested sample, but must be named
clearly. Plain `verify` performs a complete read of both source and required
sidecar records.

### Repair

```text
bitrot repair /jellyfin_data2/movie.mkv \
  /jellyfin_par2/movie.mkv.bitrot
```

Repair defaults to creating a new file beside the damaged source:

1. Fully verify the sidecar and classify source chunks.
2. Search for displaced chunks if doing so can reduce the erasure count.
3. Confirm sufficient valid recovery chunks exist.
4. Reconstruct into a uniquely named temporary file.
5. Verify every reconstructed chunk and the complete-file BLAKE3 digest.
6. Flush and close the repaired file.
7. Only then replace the original when the user requested replacement.

In-place block repair is deferred. It is less safe under power loss and makes
it harder to preserve evidence when storage hardware is failing. Replacement
must retain the damaged original under a deterministic backup name unless the
user explicitly opts out.

No repair is reported successful until the full source digest matches the
manifest.

### Inspect and scrub

`bitrot inspect` prints format and geometry without reading all payload bytes.

`bitrot scrub` walks a configured source directory, locates sidecars, performs
complete verification, and emits a summary suitable for scheduled operation.
It does not repair by default. Scheduling, notifications, and retention policy
are integration concerns rather than file-format features.

## Redundancy policy

The initial default should be selected from measured storage conditions rather
than treated as a universal constant. Suggested starting points are:

- 10% for data that also has a healthy independent backup.
- 15% for portable cold media where corruption repair is the primary concern.
- Higher values when independent copies are difficult, while recognizing that
  sidecar parity on the same device does not protect against device loss.

Changing 30% PAR2 redundancy to 15% directly reduces recoverable damaged data;
the newer algorithms do not create protection without storage overhead.

Whenever possible, keep source data and recovery data on different physical
devices. A checksumming filesystem with redundancy and periodic scrubs remains
the preferred first layer. This format adds portable file-level verification
and recovery; it is not a filesystem.

## Concurrency and resource limits

- Stream file I/O and use configurable bounded buffers.
- Default worker count should avoid starving media-serving workloads.
- Permit memory, thread, and I/O-rate limits.
- Hold an advisory per-set lock during create or repair.
- Refuse overlapping output and source paths.
- Avoid global current-directory changes and wildcard moves.
- Treat filenames as platform-native byte strings where possible; do not assume
  UTF-8 is available on every supported filesystem.

## Security and parser safety

Sidecars may be corrupt or malicious. Parsing must occur before large
allocations or writes and must enforce hard limits on all counts and lengths.
Arithmetic uses checked operations. Paths embedded in metadata never determine
an output location without explicit validation. Symlink and path-replacement
races require platform-appropriate handling.

Cryptographic hashes prevent accidental acceptance of corrupt chunks and make
malicious substitution difficult, but the format does not authenticate an
archive owner. Optional signatures could be added as a future record type.

## Testing strategy

### Unit and property tests

- BLAKE3 domain separation and digest coverage.
- Coding vectors and reconstruction for every allowable small geometry.
- Record encode/decode round trips.
- Parser rejection of truncation, overflow, duplicate conflicts, and random
  bytes.
- Recovery from every erasure combination for small sets.
- Property tests that repaired output always matches the original digest.

### Golden interoperability fixtures

Freeze compact fixtures containing source data, manifests, and recovery chunks.
Generate or validate them with an independent implementation of the specified
coding math. Keep fixtures permanently once the format version is released.

### Fault injection

For representative media sizes, inject:

- One-bit errors in one and many chunks.
- Random sparse errors below, at, and above recovery capacity.
- Contiguous zeroed and overwritten ranges.
- Read failures represented as missing chunks.
- Truncation and extension.
- Inserted and deleted byte ranges requiring resynchronization.
- Corrupt recovery chunks mixed with corrupt data chunks.
- Loss of either manifest copy and corruption of recovery-record headers.
- Conflicting valid-looking metadata.
- Process termination at each create and repair phase.
- Source modification during creation and repair.

Tests must establish that corruption beyond capacity is reported without
modifying the source and that no incorrectly reconstructed output is accepted.

### Operational tests

- Files larger than RAM.
- Full shard-count boundaries.
- Cross-platform filenames and filesystems.
- Low-memory operation.
- Sidecar and source on separate filesystems.
- Power-loss behavior approximated by forced termination and filesystem remount
  tests where practical.
- Benchmarks against `par2cmdline` for creation, verification, and repair.

`par2cmdline` is a development benchmark and behavior reference only; the
released program does not invoke or link it.

## Migration

Existing PAR2 recovery files should be retained. Initial deployments create the
new sidecars only for newly protected files or alongside PAR2 during a trial
period. Destructive bulk conversion is unnecessary and would discard a mature,
independently readable recovery copy.

A migration command may later verify the source against its PAR2 set, create a
`.bitrot` sidecar, verify that sidecar, and leave removal of PAR2 files as a
separate explicit operation.

## Open decisions before format freeze

1. Final format name, extension, magic, and versioning convention.
2. Exact Leopard-RS construction and Rust dependency.
3. Freeze CRC-64/GO-ISO compatibility fixtures and operational
   resynchronization limits.
4. Freeze the experimental binary record encoding using interoperability
   fixtures.
5. Freeze the experimental default and supported chunk sizes using benchmarks
   and interoperability fixtures.
6. Maximum global shard geometry and fallback grouping policy.
7. Whether v1 supports split recovery volumes.
8. Exact replacement and damaged-original retention policy.
9. Filesystem durability guarantees on Linux, Windows, and macOS.
10. Independent implementation used to generate interoperability fixtures.

These choices must be resolved in the specification and fixtures before any
created archive is described as long-term stable.
