# Item 3: the cache cleanup's check-then-chmod race on Linux

Branch: `security/v0.4-d3-3-cleanup-race` · Severity: low · Read `docs/prompts/10-v0.4-decisions-3/README.md` "Rules for every item" first.

## Your role

You are a security engineer removing a time-of-check to time-of-use race in a file-system routine. Make it correct on Linux and macOS, and keep the behaviour of every existing test.

## Read first

- AGENTS.md, SECURITY.md §8 (the package cache), ADR-0031.
- `docs/security/reviews/v0.4-decisions-progress.md`, "PR #22: fixes found by CI", "Open (low)", first bullet.
- Code: `src/aipm/execution/package_cache.py` (`remove_tree`, `_make_writable`), and the tests that cover them: `grep -rn "remove_tree\|_make_writable" tests/`.

## The finding

`remove_tree` makes each directory `0700` before emptying it. `_make_writable(dirfd, name)` tries, in order:

1. `os.chmod(name, 0o700, dir_fd=dirfd, follow_symlinks=False)`: works on macOS. On Linux it depends on Python and libc: CPython may raise `ValueError` or `NotImplementedError` for the pair, and glibc 2.32 and later implements the no-follow `fchmodat` itself. The progress doc says it works on ubuntu-latest's glibc 2.39. Find out which step runs on ubuntu-latest before you plan (a temporary log line in a CI run, or a test that records the call), and correct `_make_writable`'s comment if it is wrong.
2. `os.open(name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=dirfd)` then `fchmod`: works for a directory aipm can read.
3. For a directory it cannot read (mode `0000`): `os.stat(..., follow_symlinks=False)` to check it is a directory, then `os.chmod(name, 0o700, dir_fd=dirfd)` **by name, following links**. Between the check and the chmod, a process still running in the cache can swap the directory for a symlink, and aipm then chmods the link's target. That needs a leftover writer and a libc where step 1 fails for real directories, but it is a real race.

## What to do

1. On Linux, replace step 3 with a descriptor that needs no read permission: `fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=dirfd)`, check `stat.S_ISDIR(os.fstat(fd).st_mode)`, then `os.chmod(f"/proc/self/fd/{fd}", 0o700)` (`fchmod` on an `O_PATH` descriptor fails with `EBADF`), and close the descriptor. `O_PATH | O_NOFOLLOW` on a symlink gives a descriptor to the link itself. `O_DIRECTORY` then refuses it, so a swapped-in link fails instead of being followed.
2. Where `os.O_PATH` does not exist, or `/proc/self/fd` is not there: **do not chmod by name**. Skip that directory, and `shutil.rmtree(..., ignore_errors=True)` leaves it behind. Leaving a dir under aipm's cache root is safe; following a link is not. Add a log line or a returned count only if the module already logs; don't add a new dependency.
3. Keep `# nosemgrep: insecure-file-permissions` on each `0o700` call, and update `_make_writable`'s docstring (which step runs where, and why there is no by-name chmod).
4. Check by hand on Linux if you can (a Docker container or the CI run). Otherwise say so, and rely on the tests plus the Ubuntu CI jobs.

## Tests

`tests/security/test_v04_d3_3_cleanup_race.py`:

- **Force the fallback.** Step 1 may succeed on CI's Linux, so every test below forces it to fail: monkeypatch `os.chmod` to raise `NotImplementedError` when called with `follow_symlinks=False`. Then the fallback runs on every OS that has `O_PATH`, and the tests that need `O_PATH` skip elsewhere (macOS).
- **The swap.** Simulate the race: patch `os.stat`, or the new open, so the directory becomes a symlink to a file outside the cache between check and use. Assert that the outside file's mode is unchanged, before and after the fix. Show it failing on the current code first.
- **Unreadable directories.** A `0000` directory tree (with files) is fully removed on Linux. On macOS, the existing path still removes it.
- **No `O_PATH` or no `/proc`.** Monkeypatch both away. The unreadable directory is left, nothing outside is touched, and no exception escapes.
- Keep `package_cache.py` at its current branch coverage or better (`uv run pytest --cov=aipm.execution.package_cache --cov-branch`).

## Docs

CHANGELOG (Security). The progress doc. ADR-0031's cleanup paragraph, if it describes the by-name chmod.

## Done when

All of README "Rules for every item" is met, and the forced-fallback tests run (not skip) and pass on the Ubuntu "Checks" jobs.
