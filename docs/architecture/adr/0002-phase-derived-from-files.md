# ADR-0002: Derive the phase from `.pm/` files; no workflow engine

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

aipm moves through phases from discovery to built (ARCHITECTURE §7.1). It must survive interruption and resume without losing or duplicating work.

## Options

- A workflow engine with its own checkpointer, such as LangGraph.
- A pure function that derives the phase from the `.pm/` files and their approval hashes.

## Decision

The phase is a pure function of the state snapshot: `derive_phase()` walks the artifacts in order and returns the first missing, unapproved or stale step.

## Consequences

- There is one source of truth, and it is git-diffable.
- Resuming is just deriving the phase again.
- No second state store duplicates the files, and CLI startup stays fast.
- A workflow engine's tool-agent model is not needed, because the roles are tool-less (ADR-0003).
