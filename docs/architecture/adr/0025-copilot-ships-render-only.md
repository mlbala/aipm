# ADR-0025: Copilot CLI ships render-only

- **Status:** Accepted
- **Date:** 2026-11-12
- **Source:** build prompt 08, "Before coding"; ARCHITECTURE.md §11; SECURITY.md §9.3; `docs/adapters.md`

## Context

Build prompt 08 says that any adapter whose safety-relevant cells are unknown ships render-only, with dispatch disabled. The GitHub Copilot CLI documentation (1.0.109, read on 2026-11-12) leaves two safety cells open:

1. **How shell permission rules match.** `--allow-tool 'shell(npm test)'` is described as allowing "the exact command `npm test`", and `shell(git:*)` as allowing every git subcommand. Nothing says whether a rule allows the same command with more arguments (a gate prefix such as `uv run --frozen --offline pytest` is always followed by test paths), or whether a chained command (`uv run pytest && curl …`) is split and checked part by part. Gemini CLI documents both; Copilot does not. A rule that matched a prefix without splitting chains would let an injected agent run any command after a gate's words.
2. **How a markdown prompt is delivered.** Piped stdin is ignored when `-p` is given, `-p` takes the prompt as an argument (which `srt`'s shell refuses when it holds quotes, ADR-0020), and `--attachment` is documented for images and PDF documents only.

The JSON event schema of `copilot -p --output-format json` is not documented either, so aipm could not read the `AIPM-BLOCKED:` line.

## Options

1. Dispatch Copilot with the flags ARCHITECTURE §11 assumed, and rely on the sandbox.
2. Ship Copilot render-only: prompts and context files work, dispatch exits 8.
3. Leave Copilot out of v0.4.

## Decision

Option 2.

- `CopilotAdapter.detect` lists `unverified: how shell permission rules match` and `unverified: markdown prompt delivery` among the missing capabilities whatever the installed version offers, so `build`/`run --tool copilot` exits 8 with the hint to use `aipm prompt`.
- `aipm prompt --tool copilot` and `aipm sync-context --tool copilot` work: `AGENTS.md` (read natively) and a thin `.github/copilot-instructions.md` that points to it, with no `@` import.
- `build_invocation` is complete and covered by the adapter contract suite and every SECURITY §14.3 scenario, with the flag turned on in tests only: a fixed `-p` naming a prompt file in the attempt's context directory (`--add-dir`), `--allow-tool write` and one `shell(<gate prefix>)` per gate, `--no-ask-user`, `--secret-env-vars COPILOT_GITHUB_TOKEN`, `--output-format json`, `--no-auto-update`, `--disable-builtin-mcps`, and `COPILOT_HOME` set to the task's empty config home, which trusts no folder, so the repository's hooks and MCP servers do not load.

## Consequences

- Turning dispatch on is one constant (`copilot.UNVERIFIED = ()`) plus an ADR that records where both cells were verified, and with which version.
- ARCHITECTURE §11's Copilot column now says "render-only (ADR-0025)" for dispatch.
- Until then, Copilot users run each task with `aipm prompt --tool copilot` and check it with `aipm verify`.
