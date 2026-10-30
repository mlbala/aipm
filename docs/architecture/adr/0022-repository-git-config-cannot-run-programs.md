# ADR-0022: A repository's own git config cannot make aipm's git calls run a program

- **Status:** Accepted
- **Date:** 2026-10-30
- **Source:** security red-team v0.2 (build prompt 09), finding RT02-1; SECURITY.md §11

## Context

SECURITY.md §11 hardens every git call with `-c core.hooksPath=/dev/null -c core.fsmonitor=false -c diff.external= -c core.pager=cat --no-pager`, and diffs with `--no-ext-diff --no-textconv`. In v0.1 aipm only ran `git rev-parse`. Since v0.2, `aipm prompt` (the attempt snapshot) and `aipm verify` run `git diff`, `status`, `read-tree`, `cat-file`, `add` and `commit`, and git reads the repository's own `.git/config` for each.

A `git clone` never brings a `.git/config` of the remote's choosing, but a repository copied with its `.git` directory does: a tarball, a zip of a checkout, a shared folder, a `.git` file that points elsewhere. The red-team pass showed three ways such a config makes those calls run a program, outside the sandbox and without any trust decision:

- **Filter drivers.** `filter.<name>.clean` (or `process`) runs on every file `.gitattributes` sends through it. Against a fresh index (ADR-0021) git hashes every work-tree file, so the filter runs during the snapshot, the change set, `add` and `commit`.
- **Config hooks.** git 2.5x runs hooks named in config (`hook.<name>.command` with `hook.<name>.event`). `core.hooksPath=/dev/null` and `--no-verify` do not stop them: `post-index-change` ran during `read-tree`, and `prepare-commit-msg`, `post-commit` and `reference-transaction` during `verify --commit`.
- **Lazy fetch.** In a partial clone, reading a missing object fetches it from the promisor remote; a remote URL `ext::<command>` is a command, and the repository's own `protocol.ext.allow=always` allows it. `-c protocol.allow=never` does not override the more specific key.
- **Submodules.** git starts `git status` inside each populated submodule to see whether it is dirty, and that process reads the submodule's own config (`.git/modules/<name>/config`).
- **Global filters reading repository settings.** git-lfs, installed globally, runs `lfs.extension.<name>.clean` and `smudge` commands from the repository's config.

## Options

1. Refuse every repository that has a `.git/config` aipm did not see created. Not possible: aipm cannot tell.
2. Put the programs the repository config names into the execution surface, so `aipm trust` shows them. The surface would change with every `git lfs install --local`, and each new git feature that runs a program would need adding before it could be trusted.
3. Turn off what can be turned off for every call, and refuse (exit 6) a repository config that names a program for the remaining mechanisms.

## Decision

Option 3.

- Every git call gets, through git's `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>` environment (the same precedence as `-c`), `hook.<event>.enabled=false` for every hook event in githooks(5), `gc.auto=0` and `maintenance.auto=false`. The environment is used, not more `-c` options, so the argv stays exactly the §11 set followed by the subcommand.
- Every git call also gets `GIT_NO_LAZY_FETCH=1` and `GIT_ALLOW_PROTOCOL=none`: no lazy fetch, and no transport at all whatever the repository's `protocol.*.allow` says. aipm never fetches or pushes.
- Before git compares or stages work-tree files (the snapshot and change-set listings, `diff_text`, `status`, `diff --numstat`, `hash-object`, `commit`), `check_repo_config` asks git itself (`git config --list --show-scope --show-origin --includes`) what the repository's own config files hold, includes followed as git follows them, and refuses (exit 6):
  - `filter.<name>.clean`, `smudge` or `process`, `hook.<name>.command`, `trailer.<name>.cmd` or `command`, `gpg.ssh.defaultKeyCommand`, `lfs.extension.<name>.clean` or `smudge`, `lfs.customtransfer.<name>.path`, `lfs.standaloneTransferAgent`, and a `core.worktree` that is not the repository itself;
  - a config file git reads from inside the work tree (an include such as `../shared.cfg`): a gate's child that outlives the gate (residual risk R-14) could rewrite it between this check and git's use;
  - the same, recursively, for every populated submodule git may enter (gitlinks in the index and in the base commit), a submodule whose git directory lies inside the work tree rather than under `.git/modules/` (`git submodule absorbgitdirs` moves it), and more than 64 populated submodules or nesting deeper than 4: a limit is refused, never skipped.

  Settings in the user's global config are the user's own and are not refused; their hooks are still turned off.

## Consequences

- A repository with `git-lfs` or `git-crypt` filters in `.git/config` (`git lfs install --local`, `git-crypt unlock`) is refused until the user moves the filter definition to the global config (`~/.gitconfig`); the hint says so. A global `git lfs install` keeps working.
- The check costs one `git config` process per listing or commit.
- git versions without config hooks ignore `hook.<event>.enabled`; versions without `GIT_NO_LAZY_FETCH` (before 2.44) are still covered by `GIT_ALLOW_PROTOCOL`. Config hooks arrived in git 2.54; whether 2.54 already honours the event-level `hook.<event>.enabled` was not confirmed, so on 2.54 a hook in the user's own global config may still run. A repository's hooks are refused on every version.
- A repository with an old-style submodule (its `.git` directory inside the work tree) needs `git submodule absorbgitdirs` once.
- The integrity snapshot (ADR-0021) still decides whether a config *changed* during an attempt; this decision covers a config that was hostile from the start.
