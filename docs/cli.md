# Command-line interface

The experimental command-line interface currently provides complete,
read-only verification:

```text
bitrot verify [OPTIONS] <SOURCE> <SIDECAR>
```

`--locate-displaced` adds the bounded rolling-fingerprint pass after normal
expected-offset verification. `--json` emits a single JSON document with
`schema_version: 1`; paths include a `lossy` marker so automation can detect
when a platform-native path could not be represented exactly as JSON text.

The verifier applies hard limits to record sizes, record and page counts,
damage diagnostics, and rolling targets before allocating their collections.
Because the current authenticated sidecar representation retains recovery
payloads, it also rejects sidecars larger than 1 GiB by default. The
`--max-sidecar-bytes` option can deliberately raise or lower that bound. A
future streaming recovery index should remove the need to retain those payloads
during verification.

## Exit status

| Status | Meaning |
| ---: | --- |
| 0 | Source is intact. |
| 2 | Command-line usage error reported by Clap. |
| 10 | Source is damaged but repairable. |
| 11 | Source is damaged and unrepairable. |
| 12 | Sidecar is invalid or exceeds a verification limit. |
| 13 | An operational failure prevented verification or reporting. |

JSON output is produced for verification outcomes and errors occurring after
argument parsing. Argument errors use Clap's normal human-readable diagnostics.
