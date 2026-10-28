# ADR-0012: `ruamel.yaml` with deterministic output; aliases and tags rejected

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

`.pm/` files are YAML that humans review in diffs. YAML parsers can be attacked with alias bombs and custom tags.

## Options

- PyYAML.
- `ruamel.yaml` with deterministic dumping and a hardened loader.

## Decision

Use `ruamel.yaml`. Keys are written in schema order with a trailing newline. Anchors, aliases and custom tags are rejected on load, and files over 1 MiB are refused.

## Consequences

- Clean diffs and comment preservation.
- No YAML bombs and no arbitrary object construction.
