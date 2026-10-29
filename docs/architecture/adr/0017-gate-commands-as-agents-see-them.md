# ADR-0017: Gate commands as agents see them, and `sync-context --check` without trust

- **Status:** Accepted
- **Date:** 2026-10-29
- **Source:** build prompt 05; approved by the owner with the step 05 plan

## Context

Task prompts (`verify[]`, ARCHITECTURE §10.1) and `AGENTS.md` ("How to run checks", §10.2) show the gate argv that the agent should run itself. The argv comes from `compile_gate` (SECURITY.md §6 rule 3), which expands three placeholders (§13.1):

- `{paths}`: the task's owned paths that exist;
- `{test_paths}`: owned test paths, or the first test root;
- `{report_file}`: an absolute path aipm generates per attempt for `ac_trace`, outside the worktree.

None of these has a value when a prompt or a context file is written: the files do not exist yet, and the report path belongs to aipm's own gate run. `AGENTS.md` is committed and checked with `sync-context --check` in CI, so its content must not depend on the machine.

`sync-context --check` is meant for CI, where no trust store exists. SECURITY.md §6 rule 3 lists `sync-context` among the commands that need trust, because it writes gate argv into files agents follow.

## Options

For the placeholders:

1. Leave the placeholders in the argv. The agent cannot run the commands.
2. Expand them to machine-specific paths. `AGENTS.md` drifts between machines, and a predictable report path in a shared temp directory invites link attacks.
3. Expand them the same way everywhere, to values that never point into the worktree.

For `--check`:

1. Require trust. CI must then run `aipm trust --confirm` with a hash extracted by the script itself, which defeats the point of naming the surface.
2. Compare without trust, never showing or writing the argv.

## Decision

Placeholders, option 3. The argv an agent sees comes from `compile_gate(gate, paths=[], policy, report_file=/dev/null)`:

- `{paths}` expands to nothing, so the tool checks the whole project. This is also how `aipm trust` shows the surface.
- `{test_paths}` expands to the first test root.
- `{report_file}` is `/dev/null`. It is absolute, constant and chosen by aipm, never by task, model or config data. Only aipm's own gate run reads a report, from the fresh path it generates for that run.

The argv is otherwise identical to what `verify` runs, and still passes the command policy.

`--check`, option 2. It needs no trust, writes nothing, and reports only file names. The argv still goes through `compile_gate`, so a policy violation still exits 6. SECURITY.md §6 rule 3 records this exception.

## Consequences

- The commands in prompts and `AGENTS.md` run as shown, on every machine, and `--check` is stable.
- An agent's own run of `unit` writes its JUnit report nowhere. That is fine: `ac_trace` ignores any report except the one from aipm's run.
- A repository can be checked for context drift in CI with no trust step. Writing, approving and showing the blocks still need trust.
