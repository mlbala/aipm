# ADR-0010: asyncio for dispatch and gate concurrency

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

The build loop runs many subprocesses with timeouts, cancellation and process-group kills.

## Options

- Threads.
- multiprocessing.
- asyncio.

## Decision

Use asyncio, with `run_safe_async` in `aipm.execution.process` as the only way to start a process.

## Consequences

- A natural fit for subprocess-heavy, timeout-heavy work.
- One place to enforce timeouts, output caps and process-group kills.
- asyncio's self-pipe may need `--allow-unix-socket` under pytest-socket (review 01, §5).
