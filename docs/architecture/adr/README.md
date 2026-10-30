# Architecture decision records

One file per decision, using the template below. A new ADR is proposed in a pull request before the design changes (AGENTS.md).

| ADR | Decision | Status |
|---|---|---|
| [ADR-0001](0001-distribute-from-github.md) | Distribute from GitHub only; package and command are both `aipm` | Accepted |
| [ADR-0002](0002-phase-derived-from-files.md) | Derive the phase from `.pm/` files; no workflow engine | Accepted |
| [ADR-0003](0003-tool-less-llm-roles.md) | aipm's LLM roles are tool-less pure functions with validated output | Accepted |
| [ADR-0004](0004-gate-menu-not-commands.md) | Gates are a human-trusted menu; the LLM picks names, never commands | Accepted |
| [ADR-0005](0005-trust-outside-the-repo.md) | Execution trust is stored outside the repo, per user and machine | Accepted |
| [ADR-0006](0006-thin-llm-gateway.md) | A thin LLM gateway: `anthropic` plus `openai-compatible` | Accepted |
| [ADR-0007](0007-deterministic-gates-decide-done.md) | Deterministic gates decide done; LLM review is veto-only | Accepted |
| [ADR-0008](0008-worktrees-and-integration-branch.md) | Worktrees outside the repo, an integration branch, never push | Accepted |
| [ADR-0009](0009-claude-code-bare-mode.md) | Dispatch Claude Code with `--bare` and explicit context | Accepted |
| [ADR-0010](0010-asyncio-for-concurrency.md) | asyncio for dispatch and gate concurrency | Accepted |
| [ADR-0011](0011-apache-2-license.md) | Apache-2.0 license | Accepted |
| [ADR-0012](0012-ruamel-yaml-deterministic.md) | `ruamel.yaml` with deterministic output; aliases and tags rejected | Accepted |
| [ADR-0013](0013-srt-sandbox.md) | `srt` as the preferred sandbox, optional, failing closed under `require_sandbox` | Accepted |
| [ADR-0014](0014-structured-output-without-forced-tools.md) | Structured output: native schema, then JSON mode, then prompt; no forced tool calls | Accepted |
| [ADR-0015](0015-python-3-13-or-later.md) | Python 3.13 or later; CI tests 3.13 and 3.14 | Accepted |
| [ADR-0016](0016-g3-pins-the-plan-not-progress.md) | G3 pins the plan, not task progress | Accepted |
| [ADR-0017](0017-gate-commands-as-agents-see-them.md) | Gate commands as agents see them; `sync-context --check` without trust | Accepted |
| [ADR-0018](0018-environment-cannot-set-user-only-keys.md) | `AIPM_*` variables cannot set user-only keys; `AIPM_CONFIG` stays outside the repository | Accepted |
| [ADR-0019](0019-hard-denied-programs-at-any-argv-position.md) | Hard-denied programs are refused at any argv position | Accepted |
| [ADR-0020](0020-srt-runs-commands-through-a-shell.md) | `srt` runs commands through a shell; aipm keeps argv whole and checks the outcome | Accepted |
| [ADR-0021](0021-attempt-snapshot-and-pm-write-ledger.md) | Manual-mode attempt snapshots and the `.pm/` write ledger live outside the repository | Accepted |
| [ADR-0022](0022-repository-git-config-cannot-run-programs.md) | A repository's own git config cannot make aipm's git calls run a program | Accepted |

## Template

```markdown
# ADR-NNNN: <decision>

- **Status:** Proposed | Accepted | Superseded by ADR-NNNN
- **Date:** YYYY-MM-DD

## Context

## Options

## Decision

## Consequences
```
