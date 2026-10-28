# ADR-0001: Distribute from GitHub only; package and command are both `aipm`

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

aipm needs a distribution channel and a name. The PyPI name `aipm` is taken.

## Options

- Publish to PyPI under another name, such as `aipm-cli`.
- Distribute from GitHub only, installing with `uv tool install git+https://github.com/mlbala/aipm`.

## Decision

Distribute from GitHub only. The package, the import name and the command are all `aipm`. Releases are tags; the install line pins a tag.

## Consequences

- The name stays the same everywhere, which is the owner's preference.
- Users need uv, pipx or pip with git support; `install.sh` (v0.2) covers the common case.
- Release integrity comes from tags, build provenance attestation and checksums (ARCHITECTURE §21), not from a package index.
