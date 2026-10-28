# ADR-0004: Gates are a human-trusted menu; the LLM picks names, never commands

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

The planner decides which checks verify each task. If it could write commands, prompt injection could become command execution.

## Options

- Let the LLM write verify commands and filter them through an allowlist.
- Let the LLM choose gate names from a menu defined by trusted stack templates.

## Decision

Gate commands come only from stack templates, are shown in full at G3 and covered by the trust hash. The LLM outputs gate names; an unknown name rejects the plan.

## Consequences

- Prompt injection cannot become command execution through the plan.
- Allowlists of LLM-written commands are hard to get right and are avoided entirely.
- New kinds of check need a template change, not a prompt.
