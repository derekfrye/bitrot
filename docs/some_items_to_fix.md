# Some Items to Fix

Defensive-programming follow-ups identified by comparing the current library
and working tree with [Patterns for Defensive Programming in
Rust](https://corrode.dev/blog/defensive-programming/).

## Invalid states are publicly constructible

- [ ] Make `geometry::Geometry` fields private and provide accessors.
  `Geometry::new` and `Geometry::from_stored` validate relationships between
  source length, chunk size, shard counts, and final chunk length, but public
  fields let callers bypass those checks. In particular, an invalid geometry
  with zero data chunks can underflow `manifest::expected_rolling_count`.
- [ ] Make `digest_page::Page` and `digest_page::Table` fields private and
  provide the accessors or iteration APIs callers need. A caller can currently
  mutate a validated table's count, root, pages, or page contents.
- [ ] Make `rolling_page::Page` and `rolling_page::Table` fields private and
  provide the accessors or iteration APIs callers need. These types have the
  same constructor-bypass problem as the digest-table types.
- [ ] Ensure `Manifest::new` cannot accept a table root that does not describe
  the supplied table. It currently validates table kind/count and then trusts
  the public `root` field; private, immutable table state should make that
  trust sound.

## Panic-prone indexing and slicing

- [ ] Enable or otherwise account for `clippy::indexing_slicing`. The current
  library produces 27 warnings under this lint.
- [ ] Prioritize fallible parsing boundaries. `digest_page::Page::from_record`
  directly indexes payload bytes after a separate length check, while the
  fixed-field parsers in `manifest` and `recovery_chunk` slice and `expect`.
  Keep validation coupled to access by using checked extraction helpers that
  return the module's decoding error.
- [ ] Review vector state-machine indexing in `rolling`, `scan`, `fingerprint`,
  and `coding`. Preserve genuinely type- or loop-proven fixed-array accesses
  with narrow lint allowances where checked access would only obscure the
  invariant; do not mechanically convert every warning.

## Non-exhaustive matches

- [ ] Replace `_ => None` in the `std::error::Error::source` implementations in
  `record`, `rolling`, `coding`, and `manifest` with explicit lists of the
  source-less variants. Adding a new error variant should force a decision
  about whether it carries a source.
- [ ] Enable or otherwise account for `clippy::wildcard_enum_match_arm`. The
  four `Error::source` matches currently trigger it. Keep the wildcard in
  `Kind::try_from(u8)`, where it correctly represents all unknown integer
  values rather than future enum variants.

## Runtime "impossible" branch

- [ ] Revisit `rolling::read_byte`'s `Ok(_) => unreachable!(...)`. A conforming
  `Read` implementation cannot report more bytes than the one-byte buffer can
  hold, but converting a broken implementation into a library panic is less
  defensive than returning an explicit error.

## Lint policy

- [ ] Decide whether to deny the article's relevant Clippy lints in
  `Cargo.toml`: `indexing_slicing`, `fallible_impl_from`,
  `wildcard_enum_match_arm`, `unneeded_field_pattern`,
  `fn_params_excessive_bools`, and `must_use_candidate`. If some are too noisy,
  document targeted allowances so new occurrences remain deliberate.

## Currently clean areas

No follow-up was identified for lazy `..Default::default()` construction,
fallible `From` implementations, fragile custom equality/hash implementations,
excessive boolean parameters, unclear positional `_` field placeholders, or
missing `must_use_candidate` annotations.
