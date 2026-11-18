# v0.4 decisions, session 5: the last seven open items

Milestone: v0.4 · Seven independent items, one branch and one conversation each.

These are the open items left after sessions 3 and 4 (`docs/security/reviews/v0.4-decisions-progress.md`). Each prompt in this folder can be run on its own, in any order, in parallel. R-14 and N-3 are deferred to v0.5 and are not part of this session.

## Plan

| # | Item | Severity | Branch | Main files | Test file |
|---|---|---|---|---|---|
| 0 | These prompts, and CI runs every `test_real_sandbox*.py` | setup | `security/v0.4-d3-0-prompts` | `docs/prompts/10-…`, `.github/workflows/ci.yml` (the sandbox job's pytest line) | `test_v04_d3_0_real_sandbox_files.py` |
| 1 | pnpm through another launcher (`corepack pnpm`, `node …/pnpm.cjs`, an npm script) | low | `security/v0.4-d3-1-pnpm-launchers` | `gates/command_gate.py`, `execution/package_cache.py` (`pnpm_env` only) | `test_v04_d3_1_pnpm_launchers.py`, `test_real_sandbox_pnpm_launchers.py` |
| 2 | `pnpm -C <dir>` reads that directory's settings | low | `security/v0.4-d3-2-pnpm-dir` | tests; code only if the hand check finds a gap | `test_v04_d3_2_pnpm_dir.py`, `test_real_sandbox_pnpm_dir.py` |
| 3 | Cache cleanup: check-then-chmod race on Linux | low | `security/v0.4-d3-3-cleanup-race` | `execution/package_cache.py` (`_make_writable` only) | `test_v04_d3_3_cleanup_race.py` |
| 4 | Scanner temp files land beside the report | low (hygiene) | `security/v0.4-d3-4-scanner-temp` | `execution/sandbox.py` (`temp_env`, `profile_for`), `scanners/base.py` | `test_v04_d3_4_scanner_temp.py`, `test_real_sandbox_scanner_temp.py` |
| 5 | Prove `--cache-dir` beats a committed `cacheDir` | low (test gap) | `security/v0.4-d3-5-pnpm-cachedir` | tests only | `test_real_sandbox_pnpm_cachedir.py` |
| 6 | CI's Go is `1.26.x`, not an exact version | low | `security/v0.4-d3-6-go-pin` | `.github/workflows/ci.yml` (Set up Go step only) | `test_v04_d3_6_toolchain_pins.py` |
| 7 | No shellcheck for `install.sh` and the git hooks | low | `security/v0.4-d3-7-shellcheck` | `.github/workflows/security.yml` (new job), the three shell scripts if shellcheck asks | `test_v04_d3_7_shellcheck.py` |

Step 0 must be merged first: it puts these prompts on `main` and changes the sandbox job to run `tests/security/test_real_sandbox*.py tests/security/test_gates.py`, so items 1, 2, 4 and 5 add their real-tool tests in their own files. A test in step 0 fails if a module that imports `need` is not named `tests/security/test_real_sandbox_*.py` instead of all editing `test_real_sandbox.py`.

## Run order

After step 0 is merged, start each item from an up-to-date `main` in a new conversation:

| # | Paste into Claude |
|---|---|
| 1 | `Read docs/prompts/10-v0.4-decisions-3/1-pnpm-launchers.md and follow it exactly.` |
| 2 | `Read docs/prompts/10-v0.4-decisions-3/2-pnpm-dir.md and follow it exactly.` |
| 3 | `Read docs/prompts/10-v0.4-decisions-3/3-cleanup-race.md and follow it exactly.` |
| 4 | `Read docs/prompts/10-v0.4-decisions-3/4-scanner-temp.md and follow it exactly.` |
| 5 | `Read docs/prompts/10-v0.4-decisions-3/5-pnpm-cachedir.md and follow it exactly.` |
| 6 | `Read docs/prompts/10-v0.4-decisions-3/6-go-pin.md and follow it exactly.` |
| 7 | `Read docs/prompts/10-v0.4-decisions-3/7-shellcheck.md and follow it exactly.` |

Each item ends with `ship` (the `ship` skill), which merges it under the owner's name only.

## Rules for every item

These apply to every prompt in this folder, on top of AGENTS.md and CLAUDE.md.

1. **Start.** `git switch main && git pull --ff-only && git switch -c <the item's branch>`. Start in plan mode: read, check by hand, present the plan, and wait for "go" before editing files.
2. **Stay in your lane.** Change only the files the item names, plus `CHANGELOG.md`, `docs/security/reviews/v0.4-decisions-progress.md` and any docs the item names. If the fix needs another file, say so in the plan. Other items are being built at the same time; never "fix" something that belongs to another item.
3. **Your own test files.** New tests go in the item's own files (`tests/security/test_v04_d3_<n>_<slug>.py`, and `tests/security/test_real_sandbox_<slug>.py` for tests that need the real srt, pnpm or Go). A real-tool file imports `need` and the `cache` fixture from `tests/security/test_real_sandbox.py`, and calls `need(...)` for every real tool, so CI's `AIPM_REQUIRE_REAL_SRT=1` turns a missing tool into a failure.
4. **Test first.** Write the failing test, show it fail, fix, show it pass. Never change, skip, delete or weaken an existing test. If one must change, stop and ask the owner.
5. **Check real tools by hand.** Print the version first (`pnpm --version`, `srt --version`, `go version`). Locally, srt and pnpm are in `.github/sandbox/node_modules/.bin`: put that on `PATH` for the real-tool tests. Record what you checked, and on which version, in the progress doc. Never use the network in tests.
6. **Design changes need the owner.** Do not change the command policy's deny lists, the trust model or the release workflow without showing the owner first. If the fix needs a design change, propose an ADR in `docs/architecture/adr/` and stop.
7. **Docs.** One line under `## [Unreleased]` in `CHANGELOG.md` (Security or Fixed). A subsection `### Item <n>: <title>` under `## Session 5: the last open items` in the progress doc (step 0 adds the heading), with commits, hand checks and anything left open. SECURITY.md or README only where the item says.
8. **Checks.** Every command under "Commands" in AGENTS.md, and the real-tool tests with srt and pnpm on `PATH`. The `test_status_timing.py` wall-clock test can fail under `-n auto`: rerun that file alone.
9. **Review.** Ask the `security-reviewer` subagent to review `git diff main...HEAD`. Fix every high or critical finding, and every medium unless the owner says otherwise. List the rest under "Open questions".
10. **Commit, then stop.** One commit per logical change, Conventional Commits (`security:`, `fix:`, `test:`, `ci:`, `docs:`), through the `ship` skill's commit procedure. Do not push. Report: what changed, tests added, hand checks, deviations, open questions. Wait for "ship".
11. **Merging after the others.** If `main` moved while you worked, `git fetch origin && git merge origin/main` (never rebase: no history rewriting), resolve conflicts in `CHANGELOG.md` and the progress doc by keeping both sides, rerun the checks, then ship.
