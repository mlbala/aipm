# ADR-0013: `srt` as the preferred sandbox, optional, failing closed under `require_sandbox`

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

Gates run agent-written code, and agents run with an API key. Both need filesystem and network isolation, ideally without containers.

## Options

- Docker-only sandboxing.
- `srt` (sandbox-runtime), with tool-native sandboxes as a fallback.

## Decision

Use `srt` where available, on macOS and Linux. With `security.require_sandbox: true`, a missing sandbox exits 8. Otherwise aipm warns on every use.

## Consequences

- OS-level isolation without containers.
- Without `srt`, isolation is reduced to environment scrubbing; the warning makes that visible.
- macOS `sandbox-exec` is deprecated by Apple (residual risk R-7).
