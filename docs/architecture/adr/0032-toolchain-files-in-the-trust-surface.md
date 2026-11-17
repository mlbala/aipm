# ADR-0032: The repository's toolchain files are part of the trust surface

- **Status:** Accepted
- **Date:** 2026-11-15
- **Source:** red-team v0.4 §6.3, N-4 (decided in §6.4); SECURITY.md §6, R-9

## Context

Trust (SECURITY.md §6) pins the argv aipm runs, not the configuration those programs load from the repository. Several tools read files at the repository root that change where code, or the toolchain itself, comes from: Cargo's `.cargo/config.toml` can name a `rustc-wrapper` or a test `runner`, which is any program; `rust-toolchain.toml` picks the compiler rustup downloads; a root `go.work` can `replace` any module; `.npmrc` and `.yarnrc.yml` name the registry, and `yarnPath` runs a file as Yarn. An agent's change to any of them is already a violation (SECURITY.md §12.2). A change that arrives with `git pull` was not: the next build ran it under the old trust (R-9).

## Options

1. Hash these files into the execution surface, so a change asks for trust again.
2. Keep them a residual risk.

## Decision

Option 1. The surface gains a `toolchain_files` key, holding the SHA-256 of each file below that is committed at the repository root (in `HEAD`). The key is present only when at least one of them exists, so a repository without them keeps its hash and needs no new trust.

| File | Why it is hashed |
|---|---|
| `.cargo/config.toml`, `.cargo/config` | `build.rustc-wrapper`, `target.<triple>.runner`, `[alias]`, `[source]` replacement |
| `rust-toolchain.toml`, `rust-toolchain` | pick the toolchain, which rustup downloads and runs |
| `go.work` | `replace` for any module; used because the root has one (aipm sets `GOWORK=off` otherwise) |
| `.npmrc` | `registry`, the `git` program; pnpm reads it too |
| `.yarnrc.yml`, `.yarnrc` | `yarnPath` (`yarn-path`) runs a file as Yarn; the registry server; plugins |
| `uv.toml` | index URLs, Python downloads |
| `pyproject.toml`, the `[tool.uv]` table only | the same settings as `uv.toml`. It is hashed as sorted JSON of the parsed table, so a dependency change alone needs no new trust. A file that does not parse as TOML is pinned whole |
| `.python-version` | picks the interpreter uv installs and runs |
| `.tool-versions` | picks the toolchain version that asdf or mise shims on PATH run |
| `pnpm-workspace.yaml` | pnpm 10's settings: `storeDir`, `packageImportMethod`, `overrides`, `onlyBuiltDependencies` and more. Added in session 3 of the v0.4 decisions, when the real `srt` showed its settings win over the environment; aipm also passes the store and import method as flags (ADR-0031). Members and catalogs change with it, so a pull that touches them asks for trust again |

**Committed, not the working tree.** The files are read from `HEAD` with `git ls-tree` and `git cat-file`, which read objects only, so no repository filter or hook runs. A clone or a pull changes `HEAD`, and those changes are the ones this decision is about. An agent's change to the working tree is judged by the post-change checks as a dependency violation, and prepare does not run. Hashing the working tree would have turned an agent's change in manual mode into an "untrusted surface" error before `verify` could report the violation. That error would ask the user to trust the agent's change, and no violation would be recorded.

Names are compared casefolded, because a macOS or Windows checkout opens a committed `.NPMRC` as `.npmrc`. If two spellings are committed, the surface cannot be trusted (exit 6), because which one a tool reads then depends on the filesystem. A committed link, whether the file itself or a `.cargo` above it, also cannot be trusted, because its target could change without changing the hash. The same applies to anything that is not a regular file, and to a file over 1 MiB. A repository with no commit has no entry. `aipm trust --show` lists each file and its hash.

`.python-version` and `.tool-versions` also join the package-manager settings in the post-change checks, so an agent's change to them is a dependency change, like the other files.

**Evaluated, not hashed:**

- `pip.conf`: pip never reads one from the project directory, only the user's, the global one and the active virtualenv's.
- `go.work.sum`: checksums only; it cannot redirect anything.
- `conftest.py`: project code, like every test the gates run. Hashing it would ask for trust on most test changes (the owner's decision; R-9).
- `bunfig.toml`: aipm has no bun stack.
- Files below the root, such as `sub/.cargo/config.toml`: gates and prepare run at the worktree root, so the tools do not read them. Directories above the worktrees are refused (RT04-11) or residual (R-22).

## Consequences

- A `git pull` that changes one of these files makes the repository untrusted until the user reviews it with `aipm trust --show` and trusts it again. A repository that already holds one re-trusts once after upgrading.
- A file the user changes without committing it (or never commits, such as an untracked `.python-version`) is not hashed: it is the user's own, not something a pull brought. A build's worktrees use the committed files, and an agent's change to one is a violation.
- `conftest.py` and repository scripts the gates run stay residual (R-9).
- A repository that commits `pnpm-workspace.yaml` re-trusts once after upgrading to the version that hashes it, and after any pull that changes it, including a new workspace member or catalog entry.
- Session 4: the surface entry for `pnpm-workspace.yaml` also holds its top-level settings (not `packages` or the catalogs) as sorted JSON, and `aipm trust --show` lists each one, marking those that change what pnpm installs or runs, or where it writes; a file aipm cannot parse is named as such, and its hash still pins it. The entry changed shape, so such a repository re-trusts once more.
