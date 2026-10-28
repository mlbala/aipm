# ADR-0003: aipm's LLM roles are tool-less pure functions with validated output

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

aipm's roles (interviewer, PRD writer, architect, threat modeler, planner, AC reviewer) read untrusted text. A role that can call tools can be steered into using them.

## Options

- Tool-using agent roles.
- Tool-less roles whose output is parsed into strict schemas and applied by deterministic code.

## Decision

Roles have no tools. Every response is validated into a Pydantic model with `extra="forbid"`, length limits and enums, with one repair attempt; deterministic code applies the result.

## Consequences

- aipm itself has no "excessive agency": the Rule of Two holds by construction (SECURITY.md §5).
- Roles cannot run commands, fetch URLs or write files.
- Some flexibility is lost; anything a role needs must be passed in as input.
