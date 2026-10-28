# ADR-0005: Execution trust is stored outside the repo, per user and machine

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

aipm runs commands from a repository's configuration. A cloned repository can contain anything, including a forged approval record.

## Options

- Trust `approvals.yaml` in the repository.
- Store trust outside the repository, keyed by repo and by a hash of the exact execution surface.

## Decision

Trust lives in `<user_state_dir>/aipm/trust.json`, keyed by repo ID and surface hash, and is recorded only by an interactive confirmation or `aipm trust --confirm <hash prefix>`. `--yes` never records trust. Review 01 extends this: repo config cannot set user-only keys such as `llm.base_url`.

## Consequences

- A cloned repository cannot pre-approve its own commands.
- Any change to a command or flag requires trust again.
- Each person and machine trusts a repository once.
