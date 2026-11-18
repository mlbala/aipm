# Item 4: a scanner's temp files land beside its report

Branch: `security/v0.4-d3-4-scanner-temp` · Severity: low (hygiene) · Read `docs/prompts/10-v0.4-decisions-3/README.md` "Rules for every item" first.

## Your role

You are a security engineer tidying a sandbox detail. You may relax one rule (the temp dir must be *an allowed write path*) to *within an allowed write path*, but only so far that the sandbox can never write anywhere it could not write before.

## Read first

- AGENTS.md, SECURITY.md §8 and §9 (sandbox profiles), and the session 3 notes on `CLAUDE_CODE_TMPDIR` in `docs/security/reviews/v0.4-decisions-progress.md`.
- Code: `src/aipm/execution/sandbox.py` (`ProfilePaths`, `SandboxProfile`, `temp_env`, `profile_for`), `src/aipm/execution/process.py` (`_check_call`, which calls `temp_env`), `src/aipm/scanners/base.py` (the function that runs a scanner, around "Run a scanner with its own `HOME` and `TMPDIR`").
- Tests: `tests/security/test_process.py` and `tests/security/test_sandbox.py` (the temp-dir tests from session 3).

## The finding

`scanners/base.py` gives a scanner `TMPDIR=<out>/tmp`, but builds its profile with `ProfilePaths(temp_dir=out_dir, output_dir=out_dir)`. `profile_for` then sets the scanner's `temp_dir` to `allow[0]`, which is `<out>`. srt sets the command's `TMPDIR` from `CLAUDE_CODE_TMPDIR`, so under srt the scanner's temp files go into `<out>` next to its report, not into `<out>/tmp`. The scanner could already write all of `<out>`, so this is not a security hole, but reports and temp files mix, and the environment's `TMPDIR` is a lie.

`temp_env` only accepts a temp dir that is *equal* to an `allow_write` entry, so passing `<out>/tmp` today raises `PolicyViolation` (exit 6).

## What to do

1. `scanners/base.py` passes `temp_dir=<out>/tmp` (already created `0700`). `profile_for(SCANNER)` keeps `allow_write = [output_dir]` and sets the profile's `temp_dir` to `paths.temp_dir`.
2. `temp_env` accepts a temp dir that is an `allow_write` entry **or inside one**, and still refuses (exit 6) one that is:
   - relative;
   - not normalised (`..` or `.` parts: compare with `os.path.normpath`);
   - inside a `deny_write` entry;
   - inside a `deny_read` entry, or matching a `deny_write_patterns` entry;
   - reached through a symlink *below* the `allow_write` entry it is inside: `os.path.realpath(temp) == os.path.join(os.path.realpath(entry), temp.relative_to(entry))`. Don't check the entry's own parents (macOS's `/var` is a link to `/private/var`, and a home folder may be a link), and keep the exact-match case as it is today, so agents, gates and prepare behave exactly as before. This is a read-only check, allowed in L1.
   Show the exact rule in the plan.
3. Check that no other kind (agent, gate, prepare) changes behaviour: their temp dir is still `paths.temp_dir`, which is an allow entry.
4. Check by hand with the real srt 0.0.81 (`.github/sandbox/node_modules/.bin`): a scanner-profile command that prints `$TMPDIR` and writes a file there gets `<out>/tmp`, and cannot write outside `<out>`.

## Tests

- `tests/security/test_v04_d3_4_scanner_temp.py`: `temp_env` accepts an entry and a sub-directory of one. It refuses a relative path, `allow/../elsewhere`, a sub-directory of a `deny_write` entry, and a path inside a `deny_read` entry, a path through a symlink below the entry, and it still accepts an entry whose own parent is a symlink. `profile_for(SCANNER)` gives `<out>/tmp`. The other kinds are unchanged.
- `tests/security/test_process.py` must stay at 100% branch coverage of `execution/process.py`. Add tests in your own file if the new branches are in `process.py`.
- `tests/security/test_real_sandbox_scanner_temp.py`: with the real srt, the scanner profile's `TMPDIR` is `<out>/tmp` and a write there succeeds.

## Docs

CHANGELOG (Fixed). The progress doc. SECURITY.md §9's sentence on the temp dir rule ("must be a path the profile may write"), updated to "or inside one, normalised, not through a link".

## Done when

All of README "Rules for every item" is met.
