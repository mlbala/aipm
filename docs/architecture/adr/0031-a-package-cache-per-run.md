# ADR-0031: A package cache per run

- **Status:** Accepted
- **Date:** 2026-11-15
- **Source:** red-team v0.4 §6.3, v0.2 O-2 (decided in §6.4); SECURITY.md §9.1, R-13

## Context

The prepare step runs repository code: `uv sync` runs the project's build backend, `pip install -r` can run `setup.py`. It also wrote the user's own package caches (`~/.cache/uv`, `~/.cache/pip`, `~/.npm`, pnpm's store, `~/go/pkg/mod`, `~/.cargo/registry`), and under `srt` those were the only paths outside the worktree it could write. Every other project on the machine reads those caches outside any sandbox, so a build step that poisons a cache entry reaches them (R-13).

Part 2 of the review also found that gates had no Go build cache they could write under `srt`, so `go vet` might fail under the real sandbox (observation E).

## Options

1. A cache per attempt: no sharing at all; every attempt downloads everything again.
2. A cache per run, shared by the run's tasks and deleted when the run ends.
3. Accept R-13.

## Decision

Option 2, the owner's choice.

- **Where.** `<user_cache_dir>/aipm/packages/<repo_id>/<run_id>/`, mode 0700, refused inside the repository (exit 6). `verify` gets one inside its own temp dir, which already lives for exactly one run. A gate context without a run cache never falls back to the user's caches: it uses the attempt's temp dir.
- **How.** Each package manager is pointed at its own subdirectory through its own variable, chosen by the program prepare or the gate runs:

  | Program | Variables |
  |---|---|
  | `uv` | `UV_CACHE_DIR` |
  | `python`, `pip` | `PIP_CACHE_DIR` |
  | `npm` | `npm_config_cache` |
  | `pnpm` | `npm_config_store_dir`, `npm_config_cache_dir` |
  | `go`, `gotestsum` | `GOMODCACHE`; `GOCACHE` in the attempt's temp dir |
  | `cargo` | `CARGO_HOME` |

  Gates get the same variables, so `go vet -mod=readonly`, `cargo --offline` and `uv run --offline` find what prepare fetched.
- **Who writes it.** Under `srt` only prepare may write the run's cache; it may no longer write the user's caches. Gates and agents may read it but never write it. Go's build cache is per attempt, so gates never share one.
- **Cargo.** Moving `CARGO_HOME` would make Cargo stop reading the user's `~/.cargo/config.toml` (mirrors, source replacement), so that file is copied into the run's `CARGO_HOME` when the run starts, if it is a regular file of at most 1 MiB. Credentials are never copied. Cargo runs `$CARGO_HOME/bin/cargo-<cmd>` before anything on PATH and reads `$CARGO_HOME/config.toml` as settings, so these are write-denied to every process: `config.toml`, `config`, `bin`, `credentials.toml` and `credentials`.
- **When it goes.** A build creates the cache when it starts or resumes, and deletes it when it ends, finished or interrupted. A resumed run starts with an empty cache. Go leaves its module cache read-only, so deletion first makes every directory writable, opening each without following links.

## Consequences

- The user's caches are no longer written by aipm's prepare step: R-13's cross-project path is closed.
- Within one run, tasks share the cache: one task's prepare (repository build code) can change what a later task's prepare installs. This is accepted with option 2. Option 1 would close it at the cost of downloading everything again on every attempt.
- Every run downloads its packages once. A resumed run downloads them again.
- A private registry that needs credentials in `~/.cargo/credentials.toml` no longer works for Cargo prepare steps.
- Not yet checked under the real `srt`: whether `go vet` works with a read-only `GOMODCACHE`, whether `cargo --offline` works with a read-only `CARGO_HOME` (Cargo takes a lock in `$CARGO_HOME/.package-cache`), and whether pnpm reads `npm_config_store_dir`. Checking them is part of running the real `srt` in CI (v0.3 rec 3).
- Without `srt`, the variables still steer the package managers, but nothing stops repository code from writing the user's caches anyway (as before; §9.1 "No sandbox available").
