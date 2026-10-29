# ADR-0016: G3 pins the plan, not task progress

- **Status:** Accepted
- **Date:** 2026-10-29
- **Source:** build prompt 05; approved by the owner with the step 05 plan

## Context

G3 records the sha256 of `tasks.yaml` (ARCHITECTURE §7.2). The same file also holds task progress: `status`, `attempts`, `base_sha`, `blocked` and `done` (§6.3). `aipm prompt` is the first command that writes progress (`in_progress` and `base_sha`). With the file hash as the pin, the first `aipm prompt` would void G3, the phase would fall back to `plan_draft`, and the next `aipm prompt` would refuse to run.

## Options

1. Move task progress out of `tasks.yaml` into another file. This changes the schema in §6.3 and every reader of it.
2. Re-record G3 after each progress update. That forges an approval the user never gave.
3. Pin the plan without its progress.

## Decision

Option 3, with the exact bytes kept for a plan that has not started.

- While every task is at its defaults (`todo`, no attempts, no `base_sha`, `blocked` or `done`), the G3 hash is the file's own normalized sha256, exactly as before. A comment or a formatting change in an unstarted plan still voids G3.
- Once a task has progress, the G3 hash is the sha256 of the plan with progress reset (`TasksDoc.plan_view()`), in aipm's canonical YAML form. For a plan aipm wrote, this equals the file hash that G3 recorded, so progress never voids the approval.
- `aipm.state.store.plan_sha256` computes it, and the state snapshot uses it for `tasks.yaml`.

## Consequences

- `prompt`, and later `verify` and `build`, can record progress without a new G3.
- Any change to a task's title, description, criteria, paths, gates, dependencies or traces still voids G3, started or not.
- If a user approved a hand-edited (non-canonical) plan, the first progress write saves the canonical form, and G3 must be given again. This fails closed.
- Progress fields are not covered by G3. They never were a control: `approvals.yaml` is a record, not trust (SECURITY.md §6 rule 6), and gates decide `done` (ADR-0007).
- In manual mode the user's own agent can write `tasks.yaml` (it runs without aipm's sandbox), so it could change `base_sha` or mark a task `done` without voiding G3. Nothing in v0.1 relies on these fields for a security decision, but `verify` (v0.2) must not take them from the file alone: it should keep its own record of each task's base commit and verify results, check that `base_sha` is an ancestor of HEAD, and raise a security event on a mismatch (found in the step 05 security review).
