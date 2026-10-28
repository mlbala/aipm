# Prompt 06: `verify`, `scan`, `task`, gates, sandbox, post-change checks

**Milestone:** v0.2 · **Depends on:** v0.1 tagged · **Branch:** `step/06-verify`

## Your role

You are building the component that decides whether code is done. From this step on, aipm executes code written by an untrusted agent. Isolation, deterministic checks and failing closed are the whole point of this step.

## Read first

- `AGENTS.md`
- ARCHITECTURE §12.4 (steps 1, 3 and 4), §12.7, §13, §16
- SECURITY §6, §7.8, §8, §9, §10, §11, §12.2, §14.3

## Before coding

Install and read the docs for `srt` (`@anthropic-ai/sandbox-runtime`), and check its current settings format: `network.allowedDomains`, `filesystem.denyRead`/`allowWrite`/`denyWrite`. Also check the JSON output flags of semgrep, gitleaks, osv-scanner and trivy. List the versions you verified.

## Build

1. **`aipm.execution.sandbox`:**
   - `SandboxProfile` with the network profiles `none`, `registries`, `api-only:<domains>` and `open` (`open` requires a user-level config opt-in).
   - Profiles are generated from the table in SECURITY §9.1.
   - `wrap(argv, profile) -> argv` for `srt --settings <tmpfile>`; the settings file is written with mode 0600 in a per-attempt temp dir.
   - Detection. With `security.require_sandbox`, a missing sandbox exits 8. Otherwise print a warning on every use.
2. **`aipm.execution.git`:**
   - The hardened git wrapper (SECURITY §11): `-c core.hooksPath=/dev/null -c core.fsmonitor=false …`, plus `--no-ext-diff --no-textconv` on diffs.
   - Operations needed now: status (porcelain v2, `-z`), diff names and stats, file at revision, commit with trailers, and resolving HEAD.
   - `integrity_snapshot()` and `compare()` for `.git/config`, `config.worktree`, `info/attributes`, `hooks/`, and the agent's global config files.
3. **`aipm.security.diff_checks`** (post-change checks, ARCHITECTURE §12.4 step 3):
   - scope against `owns_files`;
   - protected paths (SECURITY §9.2);
   - test-tamper heuristics (§13.3: skip/xfail markers, deleted test functions, falling assertion count, test configuration changes) for each stack;
   - dependency diff against `deps_add` (parse `pyproject.toml`, `package.json` and their lockfiles);
   - symlinks escaping the workspace;
   - git integrity.

   Classify each result as `minor` or `severe`, exactly as in §12.4.
4. **`aipm.gates`:**
   - **Runner:**
     1. Run `prepare` with the `registries` network profile.
     2. Run the gates in this order: secrets, lint, format, types, unit, `ac_trace`, sast, deps, `ac_review`.
     3. Command gates run through `compile_gate` → `sandbox.wrap` → `run_safe` with the `none` network profile, a scrubbed environment and a 10-minute timeout.
     4. Produce `GateReport`. Full output goes to the run dir (redacted); summaries are capped.
   - **Built-in gates:**
     - `ac_trace`: AC IDs must appear in test files and in the executed tests (pytest `--junitxml`; jest/vitest JSON reporter).
     - `secrets`: gitleaks, with a regex fallback and a warning.
     - `sast`: semgrep with `--metrics off`.
     - `deps`: osv-scanner, plus registry existence and age checks, plus the typosquat warning. Registry lookups go through `security/supply_chain.py`, which is the only module allowed network access besides the LLM gateway; document that exception in the import-linter contract.
     - `ac_review`: the LLM AC reviewer role. Veto only. The diff is passed as `Untrusted`.
5. **`aipm.scanners`:** wrappers that normalize findings to `{tool, rule, severity, path, line, message}`. A missing scanner gives the status `skipped` with a reason. A required gate whose tool is missing makes the task fail with a clear install hint; it never passes silently.
6. **`aipm verify <T-ID>`** (manual mode, §12.7):
   - Requires trust (exit 6 otherwise).
   - Diffs `base_sha` against the working tree, runs the post-change checks and then all gates (no fail-fast).
   - Updates the task status: `done` only if every required gate passes.
   - `--commit` creates a commit with trailers through the hardened git wrapper.
   - `--override-ac ID --reason` is recorded in `approvals.yaml` and in the security events.
   - `--json` output.
7. **`aipm scan`:** all scanners over the repo, `--fail-on`.
8. **`aipm task show|reset|block|unblock|skip`:** manual state control. Every change is recorded.
9. **`install.sh`:**
   - POSIX `sh`, at most 80 lines, readable.
   - Installs `uv` from its official installer **only after asking**, unless `-y` is passed. Then runs `uv tool install git+https://github.com/mlbala/aipm@<tag>`.
   - Prints what it will do before doing it.
   - Fails on any error (`set -eu`).

## Security requirements

- Build the **malicious stub agent scenarios** from SECURITY §14.3 as integration tests. Since there is no dispatch yet, apply each scenario's diff to the working tree and then run `verify`. Each must produce the expected outcome and exit code.
- A test proving that the hook a stub writes into `.git/hooks/pre-commit` **never executes** during `verify --commit`.
- A test proving that gate processes see none of the registered fake secrets in their environment. Use a gate that dumps its environment to a file.
- A test proving that the gate network profile blocks outbound connections when `srt` is installed. Mark it to skip with a reason if `srt` is absent in CI, and document how to run it locally.
- Process-group kill test: a gate that forks a sleeper is fully killed at the timeout.

## Out of scope

Dispatching agents, worktrees, `build`.

## Definition of done

- [ ] Every scenario in SECURITY §14.3 that applies without dispatch is covered and passes.
- [ ] `aipm verify` on the clinic example task (with a hand-written implementation in a fixture) passes. A tampered variant fails with the right exit codes.
- [ ] All checks pass; the security-reviewer review is clean; then run prompt 09.
- [ ] Report written.
