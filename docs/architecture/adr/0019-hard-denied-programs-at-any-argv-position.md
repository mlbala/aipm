# ADR-0019: Hard-denied programs are refused at any argv position

- **Status:** Accepted
- **Date:** 2026-10-29, revised 2026-10-30
- **Source:** the v0.1 security red-team pass (build prompt 09, finding RT01-1, [review](../../security/reviews/v0.1.md))

## Context

SECURITY.md §10 rule 3 says the hard-denied programs (shells, network tools, privilege tools, wrappers, destructive tools, fetch-and-run tools and `git`) "cannot be allowed by any configuration". The command policy rejected them as `argv[0]`, and at any position after a runner (`uv run`, `python -m`, …).

A repository config may set `allowed_executables` (a repo-ok key). With `allowed_executables: [[time]]`, the gate `time bash -c "curl … | sh"` passed the policy: `time` is not hard-denied and not a runner, so nothing looked past `argv[0]`. The same holds for `nice`, `timeout`, `command`, `caffeinate`, `arch`, `script`, `stdbuf`, `sandbox-exec`, `setsid`, `watch`, `flock`, `chroot` and `find -exec`. Each starts the program named after it. `osascript -e 'do shell script "…"'` passed too, because the policy did not know `osascript` as an interpreter.

`aipm trust` shows every argv in full, so a careful user would still see the shell. The policy exists so that this is not the only control.

## Options

1. Add the wrappers to the hard-denied list. The list is never complete, and a test pins the list to SECURITY.md.
2. Treat every argv as if it followed a runner: refuse a hard-denied program name at any position.
3. Option 2, and add more interpreters with inline-code flags.

## Decision

Option 3.

- `check_argv` refuses a hard-denied program at any argv position, for every stage. For argv with a runner the existing message ("hard-denied after a runner") stays; for the others the message says a wrapper could start it.
- `osascript -e`, `php -r` (and `-B`, `-R`, `-E`), `lua -e`, `Rscript -e` and `julia -e`/`-E` count as inline code, like `python -c` and `node -e`.

The security review of this fix (2026-10-30) found ways around it, and added:

- Programs that run a shell string or code given as an argument, and network tools that ship with macOS, are refused like the hard-denied list: `awk` and its variants, `expect`, `sqlite`, `watch`, `flock`, `script`, `nscurl`, `lwp-request`, `lwp-download`, `lwp-mirror` and `tftp` (`ALSO_DENIED`, listed in SECURITY.md §10 rule 3). The original list stays as it was, pinned by its test.
- A version suffix is folded off every program name, not only Python's, Perl's and pip's: `zsh-5.9`, `php8.3`, `node22`, `lua5.4` and `julia-1.10` are `zsh`, `php`, `node`, `lua` and `julia`.
- More inline-code flags: `perl -M`/`-m` (`-MPOSIX;system(…)`), `php --run` and `--process-*`, `julia --eval`/`--print`, `deno --eval`, `luajit -e` and `R -e`; and `python -m` with a module that runs code from an argument or serves the network (`timeit`, `code`, `pdb`, `runpy`, `cProfile`, `profile`, `trace`, `pydoc`, `webbrowser`, `http.server`, `smtpd`), also when `m` ends a flag cluster of options that take no value and the module is the next argument (`-Im timeit`, `-Pm`, `-Rm`).
- Outside a runner, an expanded `{paths}` or `{test_paths}` value that holds a `/` is not compared with the denied names: it already passed `safe_relpath`, a project may well have `cmd/env` or `scripts/sh`, and even a wrapper runs it as that file rather than looking it up on `PATH`. A bare value (`curl`, which `timeout 600 {paths}` would look up on `PATH`) and every literal argv element are still compared. After a runner every value is compared, as before (SECURITY.md §10 rule 4, pinned by `test_placeholder_values_are_rechecked`).

## Consequences

- An argv element whose basename is a denied name is refused anywhere, for example `ruff check src/git` written into a gate without a runner. With a runner this was already the case, and every gate of the shipped `python-uv` stack starts with `uv run`. The same path given through `{paths}` is allowed without a runner, and refused after one.
- Programs that run code from files (`make`, `pytest` with its `conftest.py`) are still allowed when the user trusts them: trust covers the argv, not the code it loads (R-1, R-9).
