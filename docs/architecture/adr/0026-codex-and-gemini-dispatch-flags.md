# ADR-0026: Codex and Gemini dispatch flags

- **Status:** Accepted
- **Date:** 2026-11-12
- **Source:** build prompt 08, "Before coding"; ARCHITECTURE.md §11; SECURITY.md §6, §9.1, §9.3; `docs/adapters.md`

## Context

Build prompt 08 lists starting points for the Codex CLI and Gemini CLI invocations and asks for each to be verified against the current documentation. They were checked against Codex CLI 0.167.2 and Gemini CLI 0.68.0 on 2026-11-12 (`docs/adapters.md` has the table, with sources). Neither CLI is installed on the build machine, so every cell is verified from the documentation only; detection checks the flags again in each tool's help at run time.

Found, and not covered by the design:

1. **Codex has no per-command shell allowlist.** Its least-privilege control is the sandbox (`--sandbox workspace-write`, network off by default) plus the approval policy. The approval default for `codex exec` is not documented; an approval would let a command run outside the sandbox.
2. **Codex reads project configuration only for trusted projects.** Trust lives in `$CODEX_HOME/config.toml`, so an empty `CODEX_HOME` trusts no project, and the repository's `.codex/` (hooks, rules, MCP servers) is not read.
3. **Gemini loads workspace settings unless folder trust is on, and folder trust stops headless runs.** With folder trust off (the default), Gemini reads `<project>/.gemini/settings.json` (MCP servers, hooks, tool discovery and call commands, wider tool rules) and `.env` files. With folder trust on, a headless run in an untrusted folder exits with `FatalUntrustedWorkspaceError`, and trusting the folder loads its settings.
4. **`--allowed-tools` is deprecated** in Gemini CLI in favour of the policy engine, but still listed and documented with prefix matching and chain splitting.
5. **Native sandboxes nest badly.** Codex applies Seatbelt (macOS) or bubblewrap (Linux) itself; Gemini's `--sandbox` relaunches under Seatbelt or a container. Whether either works inside `srt` is not documented.
6. **Neither reports cost.**

## Decision

- **Codex:** `codex exec --sandbox workspace-write --json --ephemeral --ignore-rules -c approval_policy=never -c analytics.enabled=false -c check_for_update_on_startup=false -`, with the prompt on stdin, `CODEX_HOME` set to the task's empty config home and `CODEX_API_KEY` passed. `command_policy` forbids every other sandbox mode and any approval policy but `never`, as well as `--full-auto`, `--approve-for-me` and `--not-so-yolo`. aipm's protected-file list for the Codex home covers `config.toml`, `AGENTS.md`, `AGENTS.override.md`, `skills/`, `rules/`, `hooks/`, `hooks.json` and `prompts/`.
- **Gemini:** `gemini --approval-mode auto_edit --output-format json --extensions none --allowed-tools run_shell_command(<gate prefix>)… [--sandbox] --prompt "Do the task above, following its rules."`, with the prompt on stdin. `GEMINI_CLI_HOME` is the task's empty config home, into which aipm writes the only `settings.json` (usage statistics and auto-update off, `context.fileName: ["AGENTS.md", "GEMINI.md"]`) before every attempt; it is protected and hashed like Claude Code's settings. **A worktree whose root holds `.gemini/` or a `.env*` file is refused (exit 6)**, because Gemini would load them; both are protected paths (SECURITY §9.2), so an agent cannot add them during a run. `--skip-trust` is forbidden.
- **Native sandboxes are the fallback** (SECURITY §9.1). Gemini gets `--sandbox` only when `srt` is not used and `dispatch.sandbox` is `auto` or `tool-native`. Codex always gets `--sandbox workspace-write`, the only allowed mode; if it cannot nest inside `srt`, its shell commands fail and the attempt fails closed.
- **Cost:** with no reported cost, each attempt is charged its task budget (`attempt_cost`), as for a Claude Code run that printed no result.
- **API domains** (`api.openai.com`; `generativelanguage.googleapis.com`) are not documented; a wrong guess makes the agent fail under the `api-only` profile, never widens it.

## Consequences

- A repository that commits `.gemini/settings.json` or a `.env` file cannot be built with Gemini; it can still be built with another tool, or by hand with `aipm prompt --tool gemini`.
- Codex's shell is bounded by its sandbox, not by an allowlist: an agent can run any program inside it, with no network and writes only to its worktree. aipm runs the gates itself in any case.
- Detection fails closed (exit 8) when a future version drops `--allowed-tools` or any other flag listed here.
- To check by hand with real installs: the API domains, and Codex and Gemini inside `srt` on macOS.
