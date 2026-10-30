# ADR-0021: Manual-mode attempt snapshots and the `.pm/` write ledger live outside the repository

- **Status:** Accepted
- **Date:** 2026-10-30
- **Source:** build prompt 06; ARCHITECTURE §12.4 step 1, §12.7

## Context

In manual mode (§12.7) the user's own agent works in the user's own tree, and `aipm verify` runs the post-change checks on "the diff from `base_sha` to the working tree". The diff alone cannot tell:

- files that were already changed, untracked or ignored when the task started from the agent's changes;
- aipm's own `.pm/` writes (`prompt` sets `in_progress` in `tasks.yaml`) from an agent's;
- whether `.git/config`, hooks, attributes, included config files or the agents' global settings changed, since git does not track them; and git itself reads them, so they must be compared before git runs.

Anything kept in the repository could be rewritten by the agent being checked.

## Options

- Keep the "before" state in `.pm/` (the agent can forge it).
- Keep it in the user state directory, outside the repository.

## Decision

Two private files (mode 0600, written atomically, never through a link, refused when `HOME` or `XDG_STATE_HOME` put them inside the repository):

- **The attempt snapshot**, `<user_state_dir>/aipm/attempts/<repo-id>/<T-ID>.json`, taken by the `aipm prompt` that starts a task and removed by `aipm task reset` and `skip`. It holds the base commit, the integrity hashes (`.git/config`, `config.worktree`, `info/attributes`, `info/exclude`, `hooks/`, a linked work tree's `.git` file, files named by `include.path`, the global git config, the agents' global settings, hooks and skills) and the hash of every file that differed from the base, was untracked, or was ignored on a protected or test path.
- **The write ledger**, `<user_state_dir>/aipm/ledger/<repo-id>.json`: the sha256 of every `.pm/` file the state store wrote or removed last. Commands open the store through `runtime.open_repo_store`, which records into it.

`verify` compares the integrity hashes first, without running git; any difference is a severe violation. The change set is then every path that differs from the base and from its snapshot hash; a `.pm/` path whose bytes are aipm's last write is aipm's own. The base commit comes from the snapshot, never from `tasks.yaml`, and tampering is judged before the G3 check, so an edited plan is reported as tampering. A task without a snapshot (started under v0.1) exits 2 with the hint `aipm task reset`, then `aipm prompt`.

## Consequences

- An agent cannot whitelist its own changes or forge aipm's `.pm/` writes.
- Changes the user makes between `prompt` and `verify` count too; in manual mode aipm cannot tell the user from the agent. Answering Claude Code's "always allow" writes `.claude/settings.local.json`, a protected path, and blocks the task until `aipm task unblock`.
- The listing is made against a fresh index of the base commit, never the user's index (where `assume-unchanged` and `skip-worktree` flags could hide a file), with replace refs off (`GIT_NO_REPLACE_OBJECTS`).
- An ignored file on a protected or test path is watched, but a directory git ignores as a whole (`node_modules/`, `.venv/`, `.pm/cache/`, `.pm/runs/`) is not entered (residual risk R-11). aipm reads `.pm/cache/` and `.pm/runs/` only where the ledger shows aipm wrote those exact bytes. Python bytecode caches are left out because gates never read them from the tree (`PYTHONPYCACHEPREFIX`).
- A changed file that changes again while the gates run fails the attempt, so what is scanned is what is committed.
- At most 20,000 changed or untracked files at the start of a task; more exits 2.
