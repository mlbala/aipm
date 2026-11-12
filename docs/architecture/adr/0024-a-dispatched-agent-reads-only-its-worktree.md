# ADR-0024: A dispatched agent reads only its own worktree

- **Status:** Accepted
- **Date:** 2026-11-12
- **Source:** security red-team v0.3 (build prompt 09), findings RT03-1, RT03-2 and RT03-3; SECURITY.md §3, §9.1; SG-4

## Context

SG-4 says a dispatched coding agent works "in its own worktree only, with no credentials except its own API key". `srt` allows writes only to the paths it is given. Reads are the other way round: anything not listed in `denyRead` can be read. Until v0.3, the agent profile in SECURITY.md §9.1 denied:

- the credential directories of §3;
- the main repository's `.pm/`;
- the other worktrees that existed when the agent started.

The red-team pass found three gaps in that list:

1. **The main checkout.** The task worktree lives outside the repository, so the user's ignored `.env`, keys and local data files are not in it. They are still in the main checkout, and the agent could read them by absolute path. So could the gates and the prepare step of a build, which run agent-written code (RT03-1).
2. **Agent logins.** With its own `CLAUDE_CONFIG_DIR` (ADR-0023), a dispatched Claude Code never needs the user's agent homes. Those homes hold logins: Claude Code keeps an API key typed at `/login` in `~/.claude.json` and an OAuth token in `~/.claude/.credentials.json` (Linux); Codex and Gemini keep theirs in `~/.codex/auth.json` and `~/.gemini/oauth_creds.json`. The `api-only` network lets an agent spend any of them at `api.anthropic.com`. Shell histories and some well-known token files were readable too (RT03-2).
3. **Tasks started later.** Under `--parallel`, the deny list named only the worktrees and config homes that existed when the agent started. A task scheduled after it, and the worktree where task commits are rebased, stayed readable (RT03-3).

`srt` 0.0.81 has no "deny everything but" rule for reads. Denying the home directory would also deny the worktree, which lives in the user cache directory under it.

## Options

1. Keep the §9.1 table and document the gaps as residual risks.
2. Deny the main repository's root. This also denies `.git`, which git in the worktree must read (the objects, and the `config` that `commondir` points to). Build backends that call git during `uv run` (hatch-vcs, setuptools-scm) would then fail.
3. Deny what the process never needs, one entry at a time:
   - every top-level entry of the main repository except `.git`, and the target of each top-level link;
   - the agent homes, unless the agent's own program lives in one;
   - more credential files;
   - every other task of the plan by name, whether it exists yet or not, and the rebase directory.

## Decision

Option 3.

- **Main checkout** (`main_repo_entries`). For the agent and for a build's gates and prepare step (any process whose workspace is a task worktree), every top-level entry of the main repository except `.git` is denied, and so is the target of a top-level link. An entry that holds a path the process needs is left out, so a repository that is the home directory still runs. Paths it needs: its workspace, temp dir and config home, the agent's own program, and the `PATH` directories. A repository with more than 4,096 top-level entries is refused (exit 6). Manual-mode gates are unchanged, because their workspace is the main checkout.
- **Agent homes.** An agent with a config home of its own may not read `~/.claude`, `~/.codex`, `~/.gemini` or `~/.copilot`. If its program lives inside one of them (a Claude Code installed under `~/.claude/local`), only the token files there are denied.
- **Credential paths.** These are added to the §3 list, and so are denied to every process:
  - `~/.claude.json`, `~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.gemini/google_accounts.json`;
  - `.vault-token`, `.pgpass`, `.my.cnf`, `.terraform.d/credentials.tfrc.json`, `.config/hub`, `.m2/settings.xml`, `.gradle/gradle.properties`, `.fly`, `.config/doctl`;
  - shell and REPL histories (`.bash_history`, `.zsh_history`, `.zsh_sessions`, fish, Python, Node, psql, MySQL and SQLite histories).
- **Other tasks.** Every other task in `tasks.yaml` has its worktree path and config home denied by name, created or not. Rebases run in `<worktrees>/.integrate/<random>`, and `.integrate` is denied to every agent. A build's gates get the same list.

The `.git` directory stays readable. It holds the objects of every branch and the repository config, which may contain a token in a remote URL. Git in the worktree needs both.

## Consequences

- An injected agent can no longer read the user's `.env`, keys, agent logins or other tasks' transcripts. It can still read what it needs: its worktree, the project's history through `.git`, and its toolchain.
- The profile grows with the number of tasks (two paths per task) and with the main checkout's top-level entries. Both are bounded: 200 tasks, and 4,096 entries.
- A token in a remote URL in `.git/config` is still readable (residual risk R-16). The README recommends a git credential helper over tokens in URLs.
- None of this is enforced without `srt`. Without it, the warning on every dispatch stands, and `security.require_sandbox: true` makes a missing sandbox exit 8.
- The stub `srt` used by the tests copies every settings file it receives, so the build tests read the profile each process got (`tests/security/test_redteam_v03.py`).
