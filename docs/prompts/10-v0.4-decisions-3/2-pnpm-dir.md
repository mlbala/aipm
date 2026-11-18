# Item 2: `pnpm -C <dir>` and another directory's settings

Branch: `security/v0.4-d3-2-pnpm-dir` · Severity: low · Read `docs/prompts/10-v0.4-decisions-3/README.md` "Rules for every item" first.

## Your role

You are a security engineer proving, with the real pnpm, that an open low finding is closed, and fixing it if it is not.

## Read first

- AGENTS.md, and SECURITY.md §9 and §10.
- `docs/security/reviews/v0.4-decisions-progress.md`, "Session 4".
- Code: `src/aipm/execution/package_cache.py` (`pnpm_env`), `src/aipm/gates/command_gate.py` (`refuse_pnpm_install_before_run`, `run_command_gate`), `src/aipm/state/pnpm_workspace.py`, and the placeholders and path checks in `src/aipm/security/command_policy.py`.
- `tests/security/test_real_sandbox.py`, `test_a_pnpm_gate_ignores_a_workspace_file_above_the_worktree`: the pattern to follow.

## The finding

A user-configured gate such as `pnpm -C packages/app test` (also `--dir`, `--prefix`, `-C=…`, `--dir=…`) runs pnpm in another directory. aipm checks only the worktree root's `pnpm-workspace.yaml`. If pnpm reads `packages/app/pnpm-workspace.yaml` (or one between it and the root), that file's `verifyDepsBeforeRun: install` would go unchecked. Session 4 found that `NPM_CONFIG_WORKSPACE_DIR`, which every pnpm gate gets, stops pnpm reading a `pnpm-workspace.yaml` *above* the worktree. It did not test `-C`: the pin may or may not hold. Nothing tests it yet.

## What to do

1. **Check by hand on pnpm 10.34.9**, with `NPM_CONFIG_WORKSPACE_DIR=<root>` as `pnpm_env` sets it:
   - `pnpm -C sub test`, `pnpm --dir sub test`, `pnpm --dir=sub test`, `pnpm --prefix sub test`, where `sub/pnpm-workspace.yaml` sets `verifyDepsBeforeRun: install`, and where it sets `storeDir`, `cacheDir` or `modulesDir`. Which file's settings win?
   - `-C` pointing outside the worktree: an absolute path, and `../x`. Does pnpm run there? Under srt, can it write there?
   - `pnpm --filter <pkg> test` and `pnpm -r test` in a workspace with a package that has its own `pnpm-workspace.yaml`.
2. **If the pin holds** (sub's file is ignored in every case): the fix is the tests below plus docs.
3. **If any form reads another directory's settings**: choose the smallest fail-closed fix and show it in the plan before coding. For example, run the `pnpm-workspace.yaml` check on the directory pnpm will use, or refuse (exit 6) a pnpm gate whose `-C`/`--dir`/`--prefix` leaves the worktree or names a directory with its own workspace file. A command-policy change needs the owner (rule 6).
4. A `-C` outside the worktree that works without srt is a finding of its own. Report it with what it can reach, and propose a fix. Don't widen this item without the owner's go.

## Tests

- `tests/security/test_real_sandbox_pnpm_dir.py` (real pnpm; srt and no-srt): for each spelling of the directory flag, a gate run in a sub-directory with its own `pnpm-workspace.yaml` (`verifyDepsBeforeRun: install`) does not install, and prepare with `-C` keeps the store, cache and `node_modules` where `cache_args` puts them.
- `tests/security/test_v04_d3_2_pnpm_dir.py`: unit tests for any code you change (argv parsing of every flag spelling, refusal messages, exit 6).

## Docs

The progress doc records each hand check and its result. If code changed: CHANGELOG, and the README's pnpm gate paragraph.

## Done when

All of README "Rules for every item" is met, and the report says, for each flag spelling, whether the pin holds.
