# Coding-agent adapters: verification table

Build prompt 08 asks for every safety-relevant property of each coding agent's headless mode to be verified against the vendor's current documentation before aipm dispatches to it. This page records what was checked, where and for which version. **Any adapter with an unknown safety-relevant cell ships render-only, with dispatch disabled.**

- **Checked on:** 2026-11-12, against the official documentation only. None of the three CLIs was installed on the build machine.
- **At run time:** each adapter runs `<tool> --version` and its help once per executable, and refuses to dispatch (exit 8) when any flag below is missing.
- **Legend:** ✅ verified (source linked), ❓ unknown (not documented), ⚠ verified but with a caveat aipm works around.

Claude Code was verified for v0.3 against 2.1.314; see [ADR-0023](architecture/adr/0023-claude-code-dispatch-flags.md).

## Summary

| Tool | Tested version | Dispatch | Why |
|---|---|---|---|
| Claude Code | 2.1.314 | ✅ enabled | ADR-0023 |
| Codex CLI | 0.167.2 | ✅ enabled | Every safety cell verified; [ADR-0026](architecture/adr/0026-codex-and-gemini-dispatch-flags.md) |
| Gemini CLI | 0.68.0 | ✅ enabled, with a guard | Workspace settings load unless refused; [ADR-0026](architecture/adr/0026-codex-and-gemini-dispatch-flags.md) |
| GitHub Copilot CLI | 1.0.109 | ❌ render-only | Shell-rule matching and prompt delivery are not documented; [ADR-0025](architecture/adr/0025-copilot-ships-render-only.md) |

## Codex CLI 0.167.2

Release: [github.com/openai/codex/releases](https://github.com/openai/codex/releases) (`rust-v0.167.2`, 2026-11-11). The `developers.openai.com/codex/...` pages redirect to `learn.chatgpt.com/docs/...`.

| Cell | Status | Finding | Source |
|---|---|---|---|
| Headless invocation | ✅ | `codex exec [OPTIONS] [PROMPT]` | [Non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode) |
| Prompt delivery | ✅ | `-` as the prompt reads stdin; with no prompt argument, stdin is read | [Non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode), [CLI reference](https://learn.chatgpt.com/docs/developer-commands?surface=cli) |
| JSON output | ✅ | `--json` prints JSONL: `thread.started` (`thread_id`), `turn.started`, `item.*` (the final `agent_message` with `text`), `turn.completed` (`usage`), `turn.failed`, `error`. No cost field | [Non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode) |
| Least privilege | ⚠ | No per-command shell allowlist. `--sandbox workspace-write` plus `-c approval_policy=never` (only `on-request` and `never` remain). `--ignore-rules` skips execpolicy rules | [Approvals and security](https://learn.chatgpt.com/codex/agent-approvals-security), [Config reference](https://learn.chatgpt.com/docs/config-file/config-reference) |
| Sandbox | ✅ | `read-only`, `workspace-write`, `danger-full-access`; Seatbelt on macOS, bubblewrap on Linux; "the agent runs with network access turned off" by default | [Sandboxing](https://learn.chatgpt.com/codex/sandboxing) |
| Sandbox inside `srt` | ❓ | Not documented; aipm keeps `workspace-write`, so a failure fails closed | — |
| Context discovery | ✅ | `AGENTS.override.md`/`AGENTS.md` from `CODEX_HOME`, then from the project root down to the cwd; 32 KiB (`project_doc_max_bytes`). Skills from `.agents/skills/` up to the repository root (`SKILL.md` with `name` and `description`) | [AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md), [Skills](https://learn.chatgpt.com/docs/build-skills) |
| Config home relocation | ✅ | `CODEX_HOME` holds config, auth, logs, sessions and skills; project `.codex/` layers load only for a trusted project, and trust lives in `CODEX_HOME` | [Environment variables](https://learn.chatgpt.com/codex/config-file/environment-variables), [Config reference](https://learn.chatgpt.com/docs/config-file/config-reference) |
| Forbidden flags | ✅ | `--dangerously-bypass-approvals-and-sandbox`/`--yolo`, `danger-full-access`, `--full-auto` (retired), `--approve-for-me`/`--not-so-yolo`, any approval policy but `never` | [CLI reference](https://learn.chatgpt.com/docs/developer-commands?surface=cli) |
| Auth variable | ✅ | `CODEX_API_KEY` for a non-interactive run | [Environment variables](https://learn.chatgpt.com/codex/config-file/environment-variables) |
| Telemetry and updates | ✅ | `analytics.enabled=false`, `check_for_update_on_startup=false` | [Config reference](https://learn.chatgpt.com/docs/config-file/config-reference) |
| API domains | ❓ | Not documented; aipm assumes `api.openai.com` (a wrong guess fails closed) | — |
| Exit codes | ❓ | Not documented; aipm's gates decide | — |

**aipm's argv:** `codex exec --sandbox workspace-write --json --ephemeral --ignore-rules -c approval_policy=never -c analytics.enabled=false -c check_for_update_on_startup=false -`

## Gemini CLI 0.68.0

Release: [github.com/google-gemini/gemini-cli/releases](https://github.com/google-gemini/gemini-cli/releases) (`v0.68.0`, marked Latest).

| Cell | Status | Finding | Source |
|---|---|---|---|
| Headless invocation | ✅ | `-p`/`--prompt` forces non-interactive mode | [CLI reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/cli-reference.md), [Headless](https://github.com/google-gemini/gemini-cli/tree/main/docs/cli/headless.md) |
| Prompt delivery | ✅ | Piped stdin is the prompt; `-p` is "appended to stdin input" | [CLI reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/cli-reference.md) |
| JSON output | ✅ | `--output-format json`: one object with `response`, `stats`, optional `error`. No cost | [Headless](https://github.com/google-gemini/gemini-cli/tree/main/docs/cli/headless.md) |
| Least privilege | ⚠ | `--approval-mode auto_edit`; `--allowed-tools run_shell_command(<cmd>)` uses prefix matching and checks each part of `&&`/`\|\|`/`;` chains; in headless mode an unlisted shell call is denied. `--allowed-tools` is deprecated (policy engine) but still listed | [Shell tool](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/shell.md), [Policy engine](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md) |
| Sandbox | ✅ | `--sandbox`; on macOS Seatbelt, default profile `permissive-open` (writes confined to the project, network open) | [Sandbox](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md) |
| Sandbox inside `srt` | ❓ | Not documented; aipm passes `--sandbox` only when `srt` is not used | — |
| Context discovery | ✅ | `GEMINI.md` hierarchy; `context.fileName` accepts a list; `@./file.md` imports, ignored inside code spans | [GEMINI.md](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/gemini-md.md), [Memory import](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/memport.md) |
| Config home relocation | ✅ | `GEMINI_CLI_HOME` is the root under which `.gemini/` is created | [Configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md) |
| Workspace settings | ⚠ | With folder trust off (default), `<project>/.gemini/settings.json` and `.env` load; with it on, headless runs in an untrusted folder exit. aipm refuses a worktree whose root holds `.gemini/` or `.env*` in any case, writes an empty `.env` in the worktree's parent so the upward `.env` search stops there, and sets `GEMINI_SANDBOX` so no `.env` can change it | [Trusted folders](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md) |
| Forbidden flags | ✅ | `--yolo`/`-y`, `--approval-mode yolo`, `--skip-trust` | [CLI reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/cli-reference.md) |
| Auth variable | ✅ | `GEMINI_API_KEY` | [Configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md) |
| Telemetry and updates | ✅ | `privacy.usageStatisticsEnabled: false`, `general.enableAutoUpdate: false`; telemetry off by default | [Configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md), [Telemetry](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/telemetry.md) |
| API domains | ❓ | Not documented; aipm assumes `generativelanguage.googleapis.com` | — |
| Exit codes | ✅ | 0 success, 1 error, 42 input error, 53 turn limit | [Headless](https://github.com/google-gemini/gemini-cli/tree/main/docs/cli/headless.md) |

**aipm's argv:** `gemini --approval-mode auto_edit --output-format json --extensions none --allowed-tools 'run_shell_command(<gate prefix>)'… [--sandbox] --prompt 'Do the task above, following its rules.'`

## GitHub Copilot CLI 1.0.109 (render-only)

Release: [github.com/github/copilot-cli/releases](https://github.com/github/copilot-cli/releases) (`v1.0.109`, 2026-11-10).

| Cell | Status | Finding | Source |
|---|---|---|---|
| Headless invocation | ✅ | `copilot -p PROMPT` | [Programmatic reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference) |
| Prompt delivery | ❓ | Piped stdin is ignored with `-p`; `--attachment` takes images and PDF documents; a markdown prompt file is not documented | [Run the CLI programmatically](https://docs.github.com/en/copilot/how-tos/copilot-cli/automate-copilot-cli/run-cli-programmatically), [Use Copilot CLI](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-copilot-cli) |
| JSON output | ⚠ | `--output-format json` (JSONL); the event schema is not documented | [Programmatic reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference) |
| Least privilege | ❓ | `--allow-tool write`, `--allow-tool 'shell(<cmd>)'`, `--no-ask-user`, `--secret-env-vars` exist, and non-interactive requests that need approval are denied. Whether `shell(<prefix>)` also allows more arguments, or a chained command, is not documented | [Allowing tools](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools), [Programmatic reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference) |
| Sandbox | ✅ | No OS sandbox for the CLI process (local sandboxing restricts its tools only) | [Use Copilot CLI](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-copilot-cli) |
| Context discovery | ✅ | `AGENTS.md`, `.github/copilot-instructions.md`, `.github/instructions/**`, `CLAUDE.md`, `GEMINI.md` | [Custom instructions](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-custom-instructions) |
| Config home relocation | ✅ | `COPILOT_HOME` replaces `~/.copilot`; repository hooks and workspace MCP servers need `--trust-folder` or a trusted folder | [Config directory](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference), [Programmatic reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference) |
| Forbidden flags | ✅ | `--allow-all`/`--yolo`, `--allow-all-tools`, `--allow-all-paths`, `--allow-all-urls`, `--trust-folder`, `--assisted-approval` | [Programmatic reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference) |
| Auth variable | ✅ | `COPILOT_GITHUB_TOKEN`, then `GH_TOKEN`, then `GITHUB_TOKEN`; a fine-grained PAT with "Copilot Requests" | [Command reference](https://docs.github.com/en/copilot/reference/cli-command-reference) |
| Updates and telemetry | ✅ | `--no-auto-update`; `--disable-client-telemetry` | [Configure Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/configure-copilot-cli) |
| API domains | ❓ | Not documented | — |
| Exit codes | ❓ | Only `copilot workflow run` documents codes | [Programmatic reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference) |

`--disable-builtin-mcps` and `--no-custom-instructions` were found only in a summary of the long command reference; detection requires `--disable-builtin-mcps`, so a version without it is not dispatchable either.

## What to check by hand with real installs

1. The API domains each tool uses, under `srt`'s `api-only` profile.
2. Codex `workspace-write` and Gemini `--sandbox` inside `srt` on macOS (nested Seatbelt).
3. For Copilot, before turning dispatch on: whether `shell(uv run pytest)` allows `uv run pytest tests/x` and refuses `uv run pytest && curl …`, and how a markdown prompt file is best delivered.
