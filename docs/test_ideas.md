# Test ideas

This document collects concrete scenarios that exercise corruption detection,
recovery correctness, hostile-input handling, and filesystem safety. The tests
should use deterministic generated data and compare repaired bytes with the
original source, not merely trust a successful return value.

The first four sections apply to the core library and on-disk format. The later
CLI and multi-file items should be added only when those features exist.

## Source corruption and recovery

### Clean verification baseline

Create a sidecar and immediately verify the unchanged source. Require a clean
report with no missing, damaged, or displaced chunks and no repair required.
This gives every corruption test a known-good control and catches disagreement
between creation and verification paths.

### Empty-source policy

Attempt creation from a zero-length source through both in-memory and
filesystem entry points. Version 1 should reject it consistently before
creating scratch data or a destination. Keep this test even if empty sources
are supported later, updating the expected canonical geometry instead of
leaving the boundary implicit.

### Single-bit corruption in contrasting data

Flip one bit near the beginning, middle, and end of separate fixtures. Include
both random data and highly repetitive data such as all-zero and all-one
chunks. Verification must reject each changed chunk and repair must reproduce
the exact original file. Repetitive inputs are important because weak rolling
fingerprints have less distinguishing context there.

### Weak-fingerprint collision with strong-hash rejection

Construct or search for two different chunk windows with the same rolling
fingerprint. Present the wrong window at an expected or candidate offset and
confirm it is never accepted without a matching strong digest. This protects
against both accidental collisions and attempts to exploit the fast scan
filter.

### Damage below, at, and above capacity

For one geometry, corrupt distinct chunks at `m - 1`, `m`, and `m + 1`, where
`m` is the number of usable recovery chunks. The first two cases must repair
exactly; the last must report that repair is impossible and leave the source
untouched. Repeat with contiguous damage and with one-byte faults spread across
many chunks, because recoverability depends on unavailable chunks rather than
the number of bad bytes.

### Total source loss at full redundancy

With a small fixture configured with enough recovery data, make every data
chunk unavailable and reconstruct the complete source. Compare every byte and
the final source digest. This exercises the decoder without accidentally
depending on any surviving source shard.

### Mixed data and recovery damage

Corrupt some source chunks and separately corrupt, truncate, or remove recovery
records. Test totals below, exactly at, and above the remaining recovery
capacity. A bad recovery record must consume capacity without hiding other
valid recovery records, and an impossible repair must not produce output that
looks successful.

### Final partial chunk

Use source lengths of one byte, one less than a chunk, exactly one chunk, one
more than a chunk, and one less than several chunks. Corrupt and repair the last
chunk in each case. Confirm coding padding is deterministic but is not written
past the original length or included in the source digest.

### Truncation boundaries

Truncate a protected source by one byte, by one complete chunk, within the
first chunk, and to zero bytes. Verification must distinguish an unexpected
length from ordinary in-place corruption, must not read beyond EOF, and must
account for unavailable chunks correctly. Repair must restore the exact
original length and contents when capacity permits.

### Extension boundaries

Append one byte, a partial chunk, and several chunks to a protected source.
Verification must report the extra data without inventing additional protected
chunks. A repair must either preserve the damaged original separately or
replace it through the documented safe workflow, and the accepted result must
have exactly the original length.

### Inserted and deleted byte ranges

Insert or delete one byte at the start, at a chunk boundary, and midway through
a chunk. Add larger shifts immediately below and above any configured scan
distance. Confirm intact displaced chunks are found at their new byte offsets,
strongly authenticated, and counted only once. This exercises
resynchronization rather than treating every later chunk as irrecoverable.

### Mixed displaced and overwritten chunks

Shift a run of intact chunks by a non-chunk-aligned offset, overwrite a
different chunk, and leave the rest in place. The scanner must find the moved
data while classifying the overwritten chunk as missing. Repair should use
both expected-position and displaced matches and reproduce the original.

### Duplicate chunk contents

Protect a file containing several identical chunks, then move or delete some
of them. One observed byte range may match more than one logical chunk digest,
but reconstruction must not double-count physical evidence in a way that
claims impossible recovery. The final output must still be unambiguous and
match the complete source digest.

### Unreadable ranges with continued verification

Use an injected reader that fails for one range but permits later reads.
Verification should mark the affected chunk unavailable, continue checking
later chunks, and report the complete damage picture. Repeat with errors on the
first read, a short final read, and intermittent short reads.

## Sidecar corruption and hostile input

### Every truncated prefix of every record type

For each physical record type, try decoding every prefix from zero bytes to one
byte short of the complete record. Decoding must return a structured error,
never panic, allocate from an untrusted declared length, or accept a partial
record. Include truncation between consecutive records and in the final record
of a sidecar.

### Header, payload, and digest bit flips

Flip bits independently in record magic, type, flags, lengths, identity,
payload, padding or extension bytes, and checksum/digest fields. Confirm the
record is rejected or reported as damaged while scanning can resynchronize to
later valid records. This demonstrates that framing corruption does not make
the rest of the sidecar unusable.

### False magic during resynchronization

Place magic-like byte strings in random garbage, inside corrupt payloads, and
across scan-buffer boundaries before a valid record. The scanner must not
accept a false candidate and must still find the later valid record. Bound the
number of candidate decodes and unrecognized bytes so crafted input cannot
cause unbounded work or diagnostics.

### Oversized and wrapping counts

Mutate source-chunk counts, recovery-chunk counts, page counts, item ranges,
record lengths, and offsets to their maximum values and to combinations whose
sums or products overflow. Reject these before allocating tables or shard
buffers. The process must return a normal error rather than panic, abort, or be
killed by memory exhaustion.

### Duplicate, reordered, and conflicting metadata

Shuffle all metadata records; repeat identical copies; remove each required
copy in turn; and provide two individually valid but conflicting copies.
Ordering and benign duplication must not matter, while missing or conflicting
required metadata must prevent repair. A corrupt duplicate must not hide an
identical valid copy.

### Foreign-record substitution

Mix well-formed records from two independently created protection sets,
including pages and recovery chunks with plausible indexes. Every component
must be bound to the same protection-set identity. Foreign records must not
fill gaps or reduce the reported number of required recovery chunks.

### Recovery-record substitution

Swap recovery payloads between indexes, replace a payload while retaining its
old digest, duplicate one authenticated index in place of another, and alter
the stored geometry. Each substitution must be detected before decoding.
Invalid parity must never be allowed to yield an accepted repaired file.

### Unknown record policy

Insert unknown optional and unknown required records at multiple positions.
Optional records should survive a read/rewrite within configured count and
size limits; required records must make the sidecar unsupported. Test unknown
records with large payload declarations to ensure policy does not bypass
resource limits.

### Damaged location hints

Corrupt each superblock location hint independently, point hints into record
interiors or past EOF, and retain valid manifests elsewhere in the sidecar.
Hints must be treated as validated accelerators rather than authority. The
reader should either recover through scanning or fail safely without reading
an arbitrary range.

### Random-input and mutation corpus

Feed arbitrary byte strings and mutations of valid sidecars through scanning,
decoding, assembly, verification, and rewrite entry points. Preserve every
input that causes a panic, excessive resource use, inconsistent classification,
or accepted corruption as a small permanent regression fixture.

## Coding, fingerprint, and encoding properties

### Exhaustive small erasure geometries

For every supported small `(data, recovery)` geometry, reconstruct every
erasure combination up to the recovery count. Exercise no erasures, all data
missing where possible, missing recovery shards, and more erasures than
capacity. Successful results must equal the original shards; over-capacity
requests must fail explicitly.

### Reference coding vectors

Freeze small, hand-inspectable vectors whose recovery bytes are produced by an
independent implementation of the specified field arithmetic. Test zero,
constant, incrementing, and random shards. Round-trip-only tests can miss a bug
shared by encoder and decoder, so fixed expected recovery bytes are required.

### Coding path equivalence

Encode the same data using whole chunks, every supported coding-window size,
and the spooled/streaming creation path. Recovery bytes and final sidecars must
be identical. Decode the same damage through reusable and freshly constructed
decoders to catch state leakage between windows.

### Failure and reuse of coding state

Inject input, output-callback, and backend errors partway through encoding and
decoding. Reuse the same encoder or decoder for a subsequent valid operation
and require the correct result. Partial state from a failed window must not
contaminate later work.

### Hash segmentation independence

Hash identical data as one buffer, one byte at a time, fixed blocks, randomly
sized blocks, and a reader that returns deliberately short reads. Source,
chunk, metadata-root, and recovery digests must be invariant to read
segmentation while remaining distinct across their domain tags.

### Independent digest known-answer values

Freeze expected digests for empty, short, exact-chunk, and partial-final-chunk
inputs using an independent implementation of the selected hash and the
documented domain framing. Test both the complete-source and per-chunk forms.
Internal round trips alone cannot detect an encoder and verifier making the
same framing mistake.

### Rolling update equivalence

For random and patterned buffers, compare the rolling update at every byte
offset with a fresh checksum of that complete window. Exercise outgoing and
incoming bytes of `0x00` and `0xff`, the minimum and maximum chunk sizes, and
enough windows to wrap the ring-buffer head repeatedly.

### Canonical integer encoding

Check known byte layouts for all multibyte fields and round-trip boundary and
random values. Include unaligned field offsets, truncated fields, and offset
plus width overflow. This catches host-endian assumptions and unsafe range
arithmetic before the format is frozen.

### Canonical ordering

Generate records and table pages in many input permutations and require one
byte-for-byte canonical output order. Include records that differ only in the
last comparison field and identical duplicates. Deterministic ordering makes
signatures, fixtures, and reproducible sidecars trustworthy.

## Filesystem and publication safety

### Never overwrite an unrelated destination by default

Pre-create the destination as an unrelated regular file, a hard link, and a
nonempty sidecar. Creation should preserve it unless replacement is explicitly
requested. Explicit replacement must still refuse any destination that is the
source itself or aliases the source.

### Symlink source and destination matrix

Test symlinks to regular files, symlinks to directories, chained symlinks,
dangling symlinks, and links changed concurrently between inspection and open.
Apply the matrix to the source, destination, temporary file, and repair output.
Default operations must not follow a link that can redirect reads or writes
outside the intended tree.

### Dangling-link repair escape

Replace the intended repair destination with a dangling symlink whose target
is outside the working directory. Repair must fail and must not create the
external target. Repeat with the link swapped in immediately before publish to
exercise time-of-check/time-of-use defenses.

### Current-directory and absolute-path independence

Place source and sidecar in nested directories, invoke operations from an
unrelated working directory, and use relative and absolute path combinations.
Creation, verification, and repair must address the same files without silently
changing the protection-set identity or deriving output under the wrong parent.

### Path traversal and platform-path forms

Where any stored or user-supplied relative path influences an output path,
exercise absolute paths, parent components, repeated separators, `.`
components, both slash styles, drive prefixes, and control characters. No
decoded or normalized path may escape the selected root. Platform-specific
rewriting must be deterministic and collision-aware rather than silently
mapping two inputs to the same destination.

### Source and sidecar on different filesystems

Exercise creation and repair when source, sidecar, scratch space, and final
output cross filesystem boundaries. Verify that unsupported atomic renames are
reported and that the fallback, if any, retains the original until a fully
written and re-read replacement is durable.

### Random-access and partial-I/O model

Write a fixture in shuffled block order and read it back through random ranges.
Use injected readers and writers that cap each operation, return interruptions,
fail after a selected byte count, or report EOF early. All loops must make
progress, preserve exact offsets, and clean up incomplete outputs.

### Existing-file race during publication

Run several creators targeting the same absent destination and require exactly
one installation. Repeat while another actor replaces the temporary path or
destination between checks. Cleanup guards must remove only the inode they
created and must never unlink a replacement belonging to another actor.

### Interrupted create and repair phases

Terminate the process after each durable-write boundary: scratch creation,
record writes, file sync, rename, directory sync, repaired-output write, and
final replacement. On restart, the original source must remain valid or be
recoverable, completed sidecars must verify, and stale partial files must be
identified without deleting active work.

### Verify is strictly read-only

Snapshot content, metadata, directory entries, and link targets before a
verification of both clean and corrupt inputs. Require no source, sidecar,
backup, or temporary-file mutation. Read-only verification is especially
important when diagnosing damage on failing storage.

## Scale, resource use, and implementation equivalence

### Files larger than available memory

Create, verify, scan, and repair a sparse or generated file substantially
larger than the configured memory limit. Measure peak resident memory and
ensure it stays near the documented chunk, coding-window, and bounded-index
budget rather than scaling with source size.

### Geometry and count limits

Test the smallest and largest supported chunk sizes, maximum supported shard
counts, one below and one above each limit, and arithmetic boundaries for
redundancy rounding. Valid boundary configurations must work; invalid ones must
fail before large allocation or I/O.

### Optimized and reference scan agreement

Run the same damaged file through a simple byte-by-byte reference scanner and
every optimized or parallel scan strategy. Require identical strongly
confirmed matches, damage classification, required recovery count, exit
status, and repaired output. Include displaced runs, duplicate chunks, and a
corrupt expected-position chunk.

### Thread-count determinism

Create, verify, and repair the same fixture with one thread and several thread
counts. Outputs and reports, excluding progress timing, must be deterministic.
Run under a race detector where available and repeat enough times to expose
nondeterministic shard or record ordering.

### Bounded diagnostics

Give the scanner a sidecar containing many tiny damage events and long garbage
runs. Confirm configured limits bound stored events, unknown records,
unrecognized bytes, and rendered diagnostic size while retaining a truthful
summary of omitted events.

## Future CLI tests

### Invalid and conflicting arguments

Table-test missing operations and paths, malformed numeric values, zero or
overflowing sizes, mutually exclusive options, unsupported options for an
operation, and extra operands. Each case should fail without creating or
modifying files and should produce a stable nonzero exit category.

### Filenames that resemble options

Exercise source and sidecar names beginning with `-`, containing spaces,
Unicode, control characters allowed by the platform, and non-UTF-8 bytes on
Unix. The end-of-options marker must make option-like names unambiguous, and
diagnostics must escape unsafe bytes rather than emitting terminal control
sequences.

### Output stream contract

For clean, damaged-but-repairable, unrepairable, malformed, and I/O-error
cases, assert exit status and which messages go to stdout or stderr. A quiet
mode should suppress informational output but retain actionable errors. This
makes the tool safe to automate without parsing progress text.

### Explicit input lists

If file lists or stdin-driven batches are added, test flat and nested paths,
mixing direct operands with list entries, blank lines, duplicates, option-like
names, malformed encodings, and paths outside an allowed base. The selected set
must be deterministic and must not escape its configured root.

### Recursive discovery

If directory protection is added, include files both at the root and in nested
directories, empty files and directories, symlink cycles, inaccessible
entries, and very large file counts. Confirm every eligible file is selected
once, excluded outputs are not recursively re-ingested, and traversal remains
bounded.

### Split recovery outputs

If recovery data can later be divided among several sidecars, test exact output
count and size policies, nonuniform final volumes, missing and damaged volumes,
duplicate shard indexes across volumes, and full recovery from every permitted
combination. Creation must never claim the requested distribution while
silently omitting recovery chunks.

## Regression-test discipline

Every fixed crash, hang, excessive-allocation bug, unsafe filesystem action,
or silent misclassification should add a minimized fixture plus assertions for
both the error category and absence of unintended writes. Periodically run the
corpus under sanitizers, a memory checker, and constrained-memory execution in
addition to the normal Rust test configuration.
