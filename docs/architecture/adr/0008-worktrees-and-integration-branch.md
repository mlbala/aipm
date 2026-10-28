# ADR-0008: Worktrees outside the repo, an integration branch, never push

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

Coding agents edit code. They must not reach `.pm/`, and the user's branch must not change until the user chooses.

## Options

- Let agents edit the user's branch in place.
- Give each task a worktree outside the repository and integrate into `aipm/integration`.

## Decision

Each task runs in a worktree under `<user_cache_dir>/aipm/worktrees/`. Results are integrated into `aipm/integration`. `aipm merge` fast-forwards the user's branch only after confirmation. aipm never pushes, fetches or changes remotes.

## Consequences

- Agents cannot reach the main repository's `.pm/`.
- The user's branch is untouched until they choose.
- Pushing and pull requests stay with the user. (This is about the aipm tool. The aipm repository's own development workflow is in AGENTS.md "Git".)
