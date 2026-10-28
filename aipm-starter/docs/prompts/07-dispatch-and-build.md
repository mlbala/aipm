# Prompt 07: Dispatch harness (`run`, `build`, `merge`)

**Milestone:** v0.3 · **Depends on:** v0.2 tagged · **Branch:** `step/07-build`

## Your role

You are building the loop that runs coding agents unattended. It must be safe to leave running and impossible to talk into anything outside its policy, and it must resume cleanly after a crash.

## Read first

- `AGENTS.md`
- ARCHITECTURE §11 (the Claude Code column), §12 (all of it), §16
- SECURITY §5, §6 (rule 7), §7.7, §7.8, §9, §11

## Before coding

Re-verify the Claude Code headless flags in the current docs, and record the version you verified against:

- `--bare`, `-p`
- `--output-format stream-json --verbose`
- `--permission-mode dontAsk`, `--permission-prompts none`
- `--allowedTools` syntax
- `--max-budget-usd`
- `--append-system-prompt-file`
- `--resume`
- whether `CLAUDE_CONFIG_DIR` relocates the config home
- exit codes, including 143 on SIGTERM

If any flag has changed, propose the adapter change and an ADR before coding.

## Build

1. **`ClaudeCodeAdapter.build_invocation` and `parse_result`:**
   - argv assembled from fixed fragments only. `--allowedTools` is computed as `Read,Edit,Write,Glob,Grep` plus `Bash(<gate argv prefix> *)` for each gate the task uses.
   - The prompt is passed on stdin. `AGENTS.md` content goes through `--append-system-prompt-file`.
   - The isolated config home and the API-key-only environment.
   - `check_forbidden_flags` runs on the final argv, always.
   - `detect()` confirms that every required flag appears in `claude --help`; if not, exit 8.
   - Parse the stream-json `result` event (`total_cost_usd`, `session_id`, `is_error`) and the final `AIPM-BLOCKED:` line.
   - `bare: false` path: list the repo's `.claude/settings.json` hooks and `.mcp.json` servers, include them in the execution surface, and require trust (SECURITY §6, rule 7).
2. **`aipm.execution.worktree`:**
   - Create a worktree at `<user_cache_dir>/aipm/worktrees/<repo-id>/<T-ID>` on branch `aipm/task/<T-ID>` from the integration HEAD; reset it; remove it.
   - Integration branch management (ARCHITECTURE §12.2): fast-forward, or rebase then fast-forward; a conflict blocks the task with `merge_conflict`.
   - Searching the integration branch for `Aipm-Task` / `Aipm-Attempt` trailers, for idempotency.
3. **`aipm.execution.journal`:** append-only JSONL, fsync on every write, the event types from §6.3, and replay for resume (§12.6).
4. **`aipm.domain.scheduler`:** pure. Ready set, disjoint-ownership batching, serialized resources, deterministic order.
5. **`aipm.security.budget`:** run and task USD caps and the token cap. Checked before each dispatch; exit 5 when exceeded (finish the running tasks first).
6. **`aipm.execution.build_loop`:** the asyncio orchestrator for §12.4:
   - snapshot → dispatch (sandboxed with `api-only`) → post-change checks → gates → commit and merge, or a fix prompt (with `--resume <session_id>`), or blocked;
   - `--parallel` (at most 8), `--max-retries`, `--timeout`;
   - Ctrl-C handling: the first press stops scheduling and gives running tasks a 30 s grace period, then terminates them; a second press kills immediately; exit 130;
   - the end-of-run summary.
7. **Commands:**
   - `aipm run <T-ID>`: one task.
   - `aipm build`: all ready tasks. `--only`, `--dry-run` (compiles prompts and prints the schedule and argv; dispatches nothing).
   - `aipm merge`: shows `git log --oneline <branch>..aipm/integration`, confirms, then fast-forwards only. Never pushes.
   - Every one of them requires trust, an approved plan that is not stale, a clean tree and `dispatch.enabled`.
8. **Status:** live progress in Rich (per-task line, attempts, spend), with untrusted text printed safely. `aipm status` shows the spend versus the budget.

## Security requirements

- Stub `claude` binary (`tests/fakes/bin/claude`):
  - it must **assert** at runtime that its argv contains `--bare` and `--permission-mode dontAsk` and contains no forbidden flag, that its environment contains no fake secrets except the allowed API key, and that its working directory is the worktree;
  - it then applies the scenario's diff.
- Run every scenario in SECURITY §14.3 end-to-end through `aipm build`. Expected outcomes: severe violations block immediately and are never retried; minor violations are reverted and retried with feedback.
- **Crash and resume test:** `kill -9` the aipm process during the gates of task 2 of 4, run `aipm build` again, and check that all 4 tasks end done with exactly one commit per task (check the trailers).
- **Parallel test:** 12 tasks with `--parallel 3`. Overlapping or serialized tasks never run at the same time (assert from the journal timestamps).
- **Budget test:** exit 5, no new dispatch after the cap, running tasks finish.
- **Agent persistence test:** the stub writes to its global config path. Expect a severe violation, or no effect thanks to the isolated config home.

## Out of scope

Codex, Copilot and Gemini dispatch; `auto`.

## Definition of done

- [ ] The v0.3 acceptance criteria in ARCHITECTURE §22 are met, with evidence.
- [ ] A manual run against the real Claude Code on the clinic example (`--parallel 2`, budget $3) is documented in the report: commands, outcome, cost.
- [ ] All checks pass; the security-reviewer review is clean; then run prompt 09.
- [ ] Report written.
