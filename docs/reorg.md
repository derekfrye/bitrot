# Repository organization review

This document records a structural review of the repository as of August 2026.
The initial review most likely described commit `4be11eb`; the document was not
tracked at the time, so that baseline is inferred from its filesystem creation
time. The recommendations were refreshed against the repository after commit
`396b20a` and are maintained as the reorganization proceeds. The review focuses
on physical file organization, module and type naming, placement of
responsibilities, and likely future split points. It is not a proposal for a
wholesale rewrite.

## Summary

The repository is logically coherent. Its main domain boundaries are sound,
and the extraction of shared crash-safe filesystem machinery into
`src/filesystem.rs` established a useful common boundary for create and repair
publication.

Several operational modules have nevertheless accumulated multiple
independently nameable responsibilities. Selectively splitting those modules
would improve navigation and make future changes easier to localize. Most of
the recommended changes can preserve the existing public API through facade
modules and re-exports.

The highest-value candidates are:

| Current file | Approximate production lines | Recommendation |
| --- | ---: | --- |
| `src/sidecar.rs` | 36 | Keep as the whole-sidecar public facade |
| `src/sidecar/assemble.rs` | 186 | Keep logical assembly and its errors together |
| `src/sidecar/read.rs` | 262 | Keep physical reading and read limits together |
| `src/sidecar/write.rs` | 346 | Keep canonical writing and layout together for now |
| `src/create/publish.rs` | 767 | Extract canonical streaming |
| `src/verify.rs` | 810 | Separate ordinary verification from displaced-chunk location |
| `src/repair/publish.rs` | 717 | Keep mostly cohesive |
| `src/repair/replace.rs` | 743 | Extract platform-specific exchange and directory machinery |
| `src/filesystem.rs` | 805 | Consider a lower-priority internal split behind a facade |

These line counts exclude inline test modules and are only a snapshot. Module
responsibilities, rather than a particular size threshold, should determine
whether a split remains worthwhile.

## Recommended structural changes

### Whole-sidecar processing is split by responsibility

Whole-sidecar processing originally owned four distinct concerns:

- assembling a logical sidecar from validated records;
- scanning and reading a possibly damaged physical stream;
- writing the canonical sidecar representation;
- calculating the canonical physical layout.

Logical reconciliation, assembly limits, and assembly errors now live in
`src/sidecar/assemble.rs`. Canonical writing and physical-layout calculation
live together in `src/sidecar/write.rs`. Physical scanning, canonical
read-limit derivation, damage diagnostics, and read errors live in
`src/sidecar/read.rs`. Each group shares its internal policy and error handling
closely enough that further splits are not currently useful.

The facade in `sidecar.rs` owns the core `Sidecar` type and re-exports the
public implementation types from this completed layout:

```text
src/sidecar.rs
src/sidecar/assemble.rs
src/sidecar/read.rs
src/sidecar/write.rs
src/sidecar/record_policy.rs
```

The existing `sidecar::*` paths have been retained without exposing the child
modules.

### Publication workflows use publication names

The operation-specific publication modules have been renamed, leaving the
shared filesystem primitives with the unqualified filesystem name:

- `src/filesystem.rs` contains shared filesystem primitives;
- `src/create/publish.rs` implements sidecar publication;
- `src/repair/publish.rs` implements repaired-file publication.

The resulting layout is:

```text
src/create/publish.rs
src/repair/publish.rs
src/filesystem.rs
```

The public `create::publish` and `repair::publish` functions remain re-exported
from their existing locations.

Create publication also contains a distinct canonical-record streaming
responsibility, centered on `CanonicalPlan` and its record sequencing and
verification helpers. That code is a good candidate for
`src/create/canonical_writer.rs` or `src/create/stream.rs`.

Repair publication is more cohesive after the shared filesystem extraction.
No further split is currently warranted unless a new responsibility develops.

### Separate verification from displaced-chunk location

`src/verify.rs` contains two related but independently understandable
workflows:

- verification of chunks at their canonical offsets;
- rolling scans that locate intact chunks at unexpected offsets and refine an
  existing report.

The second workflow has its own targeting, scanning, and report-update logic.
A possible layout is:

```text
src/verify.rs
src/verify/source.rs
src/verify/locate.rs
src/verify/file.rs
```

`file.rs` would be an optional home for file snapshot and stability checks.
If those checks remain small and tightly coupled to source verification, they
can instead stay in `source.rs`. The existing `verify::*` API should remain a
facade over these implementation modules.

### Isolate replacement platform machinery

`src/repair/replace.rs` combines the high-level replacement transaction with
platform-specific directory operations, atomic exchange, exchange
verification, and rollback. General file identity representation and
comparison now live in the shared filesystem module, but replacement-specific
identity checks remain part of this workflow.

The high-level transaction is valuable to read as one sequence. The
`SourceDirectory` implementation and its supporting entry types form a natural
lower-level boundary:

```text
src/repair/replace.rs
src/repair/replace/platform.rs
```

Transaction orchestration and public errors should remain in `replace.rs`.
Platform-specific namespace operations should move behind a narrow private
interface.

### Consider an internal split of the shared filesystem module

`src/filesystem.rs` is large, but its temporary-file lifecycle, directory
capability, identity checks, cleanup, and publication primitives all serve the
same crash-safe publication abstraction. Continued centralization has removed
more duplicated create, repair, verification, and replacement machinery, which
confirms that this is the right shared ownership boundary.

The implementation has nevertheless grown from roughly 655 to 805 production
lines since the initial review, and the anticipated internal boundaries are now
clear. A lower-priority split could retain `filesystem.rs` as a private facade
over directory/identity operations, temporary-file management and quarantine,
and publication verification and rollback. Keep the crash-safe invariants and
shared API together conceptually; perform this split after the operation-level
publication moves, when those consumers provide stable seams.

## Naming and public hierarchy

### Decide whether the public root should remain flat

`src/lib.rs` currently exposes three conceptual layers as peer modules:

- operations: `create`, `verify`, and `repair`;
- algorithms and model: `coding`, `geometry`, `fingerprint`, and `rolling`;
- wire-format pieces: `record`, `superblock`, `manifest`, `creator`, page
  modules, and recovery-record modules.

This is manageable today, especially if the crate intentionally presents
itself as a low-level format toolkit. Before stabilizing the API, decide whether
wire-format implementation should instead live under a namespace such as:

```text
bitrot::create
bitrot::verify
bitrot::repair
bitrot::geometry
bitrot::format::{record, manifest, superblock, ...}
```

This is a public API decision, unlike the internal splits above. It should be
made deliberately and separately from mechanical file moves.

### Clarify `create` versus `creator`

The neighboring root modules `create` and `creator` are easy to misread.
`creator` represents diagnostic provenance stored in a format record, rather
than creation behavior. Possible clearer names include `creator_record` and
`provenance`.

Any rename should follow the terminology chosen for the format specification.
If “creator record” remains the canonical format term, `creator_record` is the
least surprising physical and module name.

### Prefer canonical import paths

`fingerprint` re-exports `Digest`, `ChunkSize`, and related geometry items even
though those types have canonical modules of their own. Convenience
re-exports can make ownership unclear and create multiple equally plausible
import paths.

Prefer canonical paths such as `digest::Digest` and `geometry::ChunkSize`, or
establish an explicit crate-level facade/prelude if convenience imports are an
intentional API feature.

### Keep useful concept pairs

The following pairs express real distinctions and should not be collapsed only
to reduce the number of files:

- `manifest` is the small committed record, while `metadata` is the manifest
  plus the complete tables it authenticates;
- `recovery_chunk` represents one format record, while `recovery_set`
  authenticates and indexes the available collection;
- `digest` is a value type, while `fingerprint` performs source and chunk
  hashing.

### Keep the CLI layer organized by command and report

The command-line interface adds an application layer under `src/bin/bitrot`.
The current `verify.rs` command module separates report representation and
rendering into `verify/report.rs`, which is a useful boundary and does not need
another split now. As commands are added, keep command orchestration and output
schemas out of the library's core operation modules.

## Tests

Large inline test modules account for roughly 200 to 830 lines in several files.
The production portions of the main candidates are still large enough to
justify responsibility-based splits, so moving tests alone is not the main
solution.

Once a source module becomes a directory, its unit tests can move to a sibling
`tests.rs` module. This preserves access to private implementation details while
making production files easier to navigate.

The repository now has a top-level CLI integration suite in
`tests/cli_verify.rs`. Cross-module core operational contracts are still tested
primarily through inline unit tests and would fit files such as:

```text
tests/create_verify_repair.rs
tests/publication_safety.rs
tests/sidecar_damage.rs
tests/replacement_recovery.rs
```

Integration tests should complement rather than replace focused unit tests.

## Repository documentation

- Add a root `README.md` with project status, a short usage example, and a
  compact architecture map.
- Keep `docs/cli.md` current as commands, limits, output schemas, and exit
  statuses evolve.
- Rename `docs/some_items_to_fix.md` to a descriptive subject such as
  `docs/defensive-programming-audit.md`, or move its actionable items into the
  issue tracker once they are scheduled.
- Consider renaming `docs/test_ideas.md` to `docs/test-plan.md` if it is meant
  to remain a maintained testing artifact.

## Suggested order of work

1. Split `verify.rs` into source verification and displaced-location logic.
2. Extract replacement platform machinery.
3. Split the shared filesystem implementation behind its private facade if the
   operation-level moves confirm the proposed internal seams.
4. Decide the pre-1.0 public module hierarchy and `creator` terminology.
5. Organize core integration tests and repository documentation.

Each step should be a behavior-preserving change with tests kept green. Avoid
combining public API redesign with internal file movement in the same change;
separating those concerns will make review and rollback substantially easier.
