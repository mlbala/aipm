# Item 5: prove `--cache-dir` beats a committed `cacheDir`

Branch: `security/v0.4-d3-5-pnpm-cachedir` · Severity: low (test gap) · Read `docs/prompts/10-v0.4-decisions-3/README.md` "Rules for every item" first.

## Your role

You are a test engineer turning a hand check into a real-tool regression test. This item changes tests and docs only, unless the test shows the flag does not win.

## Read first

- AGENTS.md, ADR-0031, and `docs/security/reviews/v0.4-decisions-progress.md` "Session 4".
- Code: `src/aipm/execution/package_cache.py` (`cache_args`, `cache_env`, `pnpm_env`).
- `tests/security/test_real_sandbox.py`: `test_a_committed_pnpm_setting_cannot_move_pnpm_files_out_of_the_worktree` and its helpers. Follow the same style.

## The gap

Prepare runs `pnpm --store-dir=… --package-import-method=copy --cache-dir=<run cache>/pnpm-cache --virtual-store-dir=node_modules/.pnpm --modules-dir=node_modules install …`. The real-pnpm test proves the flags win against a committed `virtualStoreDir` and `modulesDir`. It cannot prove it for `cacheDir`, because an offline install of a project with no dependencies never writes pnpm's metadata cache. Only the unit test pins the flag, so a pnpm upgrade that let the file win would go unnoticed.

## What to do

1. **Find an offline, read-only pnpm 10.34.9 command that shows which cache directory pnpm uses.** Check by hand, in order of preference:
   - `pnpm <cache_args> cache list` or `pnpm <cache_args> cache view <pkg>` (pnpm 10's metadata cache commands): plant a metadata entry in the flag's directory and a different one in the committed `cacheDir`, and see which one pnpm lists.
   - `pnpm <cache_args> config get cache-dir` (and `cacheDir`): which value it prints with the committed file present.
   - Any command that writes into the cache dir offline, if one exists (for example `pnpm store path` for the store, as a model).
   Use the same flags `cache_args` returns, in the same position (right after `pnpm`), and say which commands accept them there.
2. **Write the test** with the most observational command that works: one that reads or writes the cache beats one that only prints config. If only `config get` works, use it and say so in the docstring.
3. If the committed `cacheDir` wins against the flag in any case, that is a finding. Write the failing test, and stop and report before changing `cache_args`.

## Tests

`tests/security/test_real_sandbox_pnpm_cachedir.py`, using `need("pnpm")` (and `need("srt")` for the sandboxed variant), parametrized srt and no-srt like the existing pnpm tests:

- With `cacheDir: ../outside-cache` (and an absolute path under the test's `tmp_path`, never a shared location such as `/tmp`) committed in `pnpm-workspace.yaml`, pnpm run with `cache_args(...)` uses `<run cache>/pnpm-cache`, and nothing is created at the committed path.
- With no committed `cacheDir`, the flag still decides. This is the control.

Run it locally with `PATH="$PWD/.github/sandbox/node_modules/.bin:$PATH"`. Step 0 makes CI's sandbox job run every `test_real_sandbox*.py`, so the file runs on Ubuntu and macOS under `AIPM_REQUIRE_REAL_SRT=1`.

## Docs

The progress doc (the command chosen, and the hand check on pnpm 10.34.9), and the "Open questions" note from session 4 (`cacheDir`) marked as closed. CHANGELOG only if code changed.

## Done when

All of README "Rules for every item" is met, and the test fails if `--cache-dir` is removed from `cache_args`. Show that by removing it temporarily, then restore it.
