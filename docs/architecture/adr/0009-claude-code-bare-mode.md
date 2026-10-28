# ADR-0009: Dispatch Claude Code with `--bare` and explicit context

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

Without `--bare`, `claude -p` runs a repository's `.claude/settings.json` hooks and connects its `.mcp.json` servers without a trust prompt.

## Options

- Default `-p` mode.
- `--bare` with the context passed explicitly through `--append-system-prompt-file`.

## Decision

Claude Code is dispatched with `--bare`. Users who sign in with a subscription can set `dispatch.tools.claude.bare: false`; aipm then lists the repo's hooks and MCP servers and requires trust for them.

## Consequences

- Repository-supplied hooks and MCP servers cannot run during dispatch.
- Bare mode needs an API key or an `apiKeyHelper`.
