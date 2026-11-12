# ADR-0023: Claude Code dispatch reads no repository or user settings

- **Status:** Accepted
- **Date:** 2026-11-12
- **Source:** build prompt 07, "Before coding"; ARCHITECTURE.md §11; SECURITY.md §6 rule 7, §9.1, §9.3

## Context

Build prompt 07 asks for the Claude Code headless flags to be checked again before dispatch is built. They were checked against Claude Code 2.1.314 (installed) and the documentation at code.claude.com/docs (CLI reference, "Run Claude Code programmatically", settings, permissions, environment variables) on 2026-11-12.

Confirmed as ARCHITECTURE §11 assumed:

- `--bare`, `-p`, `--output-format stream-json` with `--verbose`, `--permission-mode dontAsk`, `--permission-prompts none` (2.1.259 or later), `--allowedTools` in permission-rule syntax (`Bash(cmd *)`: the space before `*` gives a word-boundary prefix match), `--max-budget-usd` (print mode only), `--append-system-prompt-file` and `--resume <session-id>`.
- Stdin is capped at 10 MB. `claude -p` exits 0 on success and non-zero on failure, and 143 when stopped with SIGTERM; a turn cut by SIGTERM records no result.
- `CLAUDE_CONFIG_DIR` relocates the configuration directory: settings, session history (which `--resume` reads) and plugins. Whether `~/.claude.json` moves with it is not documented.

Found, and not covered by the design:

1. **Repository settings still apply in bare mode.** `--bare` skips hooks, skills, plugins, subagents, `CLAUDE.md` and `.mcp.json`. The permissions page says a repository's `.claude/settings.json` `env` block and its helper commands (such as `awsAuthRefresh`) still apply, and `.claude/settings.local.json` is read from the main checkout's root, resolved through worktrees. A cloned repository could set `ANTHROPIC_BASE_URL` for the agent, or run a helper. The documented control is `--setting-sources`, which limits the settings files read to the sources named.
2. **`--append-system-prompt-file` is not its own row in `claude --help`.** It appears only inside the `--bare` description, as `--append-system-prompt[-file]`. A detector that looks for the exact option would refuse every current version.
3. **`total_cost_usd` covers the whole conversation.** After `--resume`, the result reports the session's total including earlier runs. `--max-budget-usd` counts only the current run.
4. **Background traffic.** Without settings, Claude Code checks for updates and sends telemetry and error reports. Under the `api-only` network profile those requests fail. With no sandbox they leave the machine.
5. **`bare: false`.** Bare mode never reads a subscription login. With an isolated `CLAUDE_CONFIG_DIR`, a login stored under the user's own configuration is not found either.

## Options

1. Use the flags exactly as ARCHITECTURE §11 lists them, and rely on the sandbox to stop what a repository's settings ask for.
2. Add `--setting-sources user --strict-mcp-config` to every dispatch. Run the agent with an isolated `CLAUDE_CONFIG_DIR` that aipm creates, so "user" is a directory holding nothing but what Claude Code writes itself.
3. Use `--restricted` (2.1.248 or later), which loads only managed settings and `--settings`. It also removes Bash unless `--tools` names it, and confines the file tools to the working directories.

## Decision

Option 2.

- **Fixed argv.** Every Claude Code dispatch is assembled from constant fragments: `--bare -p --output-format stream-json --verbose --permission-mode dontAsk --permission-prompts none --setting-sources user --strict-mcp-config --allowedTools <list> --max-budget-usd <task_usd> --append-system-prompt-file <file>`, then `--resume <uuid>` on a fix attempt. The prompt goes on stdin. `check_forbidden_flags` runs on the final argv in the adapter and again just before the process starts.
- **Allowed tools.** The list is `Read,Edit,Write,Glob,Grep`, then `Bash(<p>)` and `Bash(<p> *)` for each command gate the task uses. `<p>` is the gate's argv as the agent sees it (ADR-0017), up to its first placeholder. An element outside `[A-Za-z0-9._/@:+=-]` cannot be written as a rule that matches only itself, so it is refused (exit 6).
- **Isolated configuration home.** It is created per run under `<user_cache_dir>/aipm/agents/<repo-id>/<run-id>/claude` with mode 0700 and passed as `CLAUDE_CONFIG_DIR`. With `--setting-sources user`, Claude Code reads no project or local settings, and the user settings it reads are in a directory aipm created empty. The sandbox lets the agent write there, because Claude Code keeps its sessions there. The settings files it would read on the next `--resume` are protected two ways:
  - the sandbox denies writes to `settings.json`, `settings.local.json`, `CLAUDE.md`, `hooks/`, `agents/`, `skills/`, `commands/` and `plugins/` in it;
  - aipm hashes those files before and after each attempt, and any change is a severe violation.
- **Context file.** The project's `AGENTS.md` block, as aipm generates it, is written before each dispatch under a new random name, into a per-attempt directory outside the agent's writable paths. An agent cannot rewrite the system prompt of its own next attempt.
- **Environment.** The agent gets the SECURITY §8 base list, the proxy variables, `ANTHROPIC_API_KEY` (bare mode needs it; a missing key exits 8), `dispatch.tools.claude.pass_env`, `CLAUDE_CONFIG_DIR`, a `TMPDIR` in its attempt directory, `DISABLE_AUTOUPDATER=1` and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`. The `api-only` profile allows `api.anthropic.com` only.
- **Capability detection.** `detect()` runs `claude --version` and, once per executable and version, `claude --help`. Every flag above must be present; `--append-system-prompt-file` also counts when the help shows `--append-system-prompt[-file]`. The `dontAsk`, `none` and `stream-json` choices must be listed. A missing one exits 8 and suggests manual mode. The executable is resolved on `PATH` outside the repository and outside aipm's worktrees.
- **Spend.** An attempt's cost is the reported `total_cost_usd` minus the session's total after the previous attempt. An attempt with no result event (killed, crashed) is charged its full `task_usd`.
- **`bare: false`** drops `--bare` only. The isolated configuration home, `--setting-sources user` and `--strict-mcp-config` stay. The repository's `.claude/settings.json` hooks and `.mcp.json` servers are listed in the execution surface and need trust (SECURITY §6 rule 7), but they are never loaded. Users who sign in with a subscription should give agents an API key.

Option 3 was not chosen. `--restricted` is documented for evaluation harnesses on shared machines, and it changes which tools exist. It may be worth adopting once its interaction with `--bare` and `--allowedTools` has been tested.

## Consequences

- A repository's Claude Code settings, local settings, MCP servers and hooks have no effect on a dispatched agent, with or without the sandbox.
- A Claude Code older than 2.1.259 (no `--permission-prompts`) exits 8.
- Fix attempts can resume their session, because the configuration home lasts for the whole run. It is deleted when the run finishes.
- Spend under `--resume` is not counted twice. Spend that Claude Code reports late or not at all is over-counted rather than under-counted.
- `bare: false` no longer means "run the repository's trusted hooks". It is kept for compatibility, and `aipm trust` still shows what the repository declares.
- If a future Claude Code drops or renames one of these flags, detection fails closed (exit 8).
