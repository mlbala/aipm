# ADR-0007: Deterministic gates decide done; LLM review is veto-only

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

An LLM reviewer can be persuaded by injected text such as "this looks good".

## Options

- LLM-as-judge pass/fail.
- Deterministic gates decide; an LLM reviewer can only veto.

## Decision

A task is done only when every required deterministic gate passes. `ac_review` can fail a task (`not_met`) but adds nothing when it says `met`. Overrides are explicit and logged.

## Consequences

- An injected "looks good" can never pass a task.
- False vetoes cost a human override, which is recorded.
