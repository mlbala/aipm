# ADR-0020: `srt` runs commands through a shell; aipm keeps argv whole and checks the outcome

- **Status:** Accepted
- **Date:** 2026-10-30
- **Source:** build prompt 06; `@anthropic-ai/sandbox-runtime` 0.0.81 (`dist/cli.js`, `dist/sandbox/sandbox-config.js`, read from the published package)

## Context

ADR-0013 chose `srt` as the sandbox. Reading `srt` 0.0.81 showed five behaviours that matter for aipm, which runs argv lists only (AGENTS.md rule 1):

1. `srt -- <args>` does not exec an argv. It joins the arguments with a shell-quote library and runs the string through `bash -c` (`spawn(…, {shell: true})`).
2. `srt` exits 1 for its own setup errors, the same code a command uses for "failed".
3. On macOS a path in the settings is a glob pattern unless written as `{"path": …, "literal": true}`.
4. `network.allowedDomains` has no entry for "every domain" (a bare `*` is refused); `strictAllowlist` makes the list an enforced policy rather than a hint for an ask callback.
5. When the command dies of SIGTERM or SIGINT, `srt` exits 0.

## Options

- Do not use `srt` until it execs an argv.
- Use `srt`, and constrain what reaches its shell and how its exit code is read.

## Decision

Use `srt`, with these rules (`aipm.execution.sandbox`, `aipm.gates.command_gate`):

- **Strict argv.** Before wrapping, aipm refuses (exit 6) any element that holds `'`, `"`, `` ` ``, `$`, `\`, `!` or a non-printable character, is empty, or starts with `~`. Then shell-quote takes only its plain path, and each element stays one literal word.
- **Probe first.** `resolve_sandbox` runs `true` under a no-network profile before relying on `srt`. A failed probe counts as no sandbox: exit 8 under `security.require_sandbox` or `dispatch.sandbox: srt`, otherwise a warning on every use.
- **Literal paths.** Every path in the settings is written `{"path": …, "literal": true}`. The one pattern, `<workspace>/**/.env*`, is added only when the workspace path has no glob character; the protected-path check after the gates catches a change on Linux, where `srt` skips write-deny patterns.
- **Enforced allowlist; no `open` under `srt`.** `strictAllowlist` is always set. A process whose profile is `open` exits 8 under `srt` rather than running unsandboxed; turning the sandbox off (`dispatch.sandbox: none` in the user config) is the explicit way to get an open network.
- **The outcome, not only the exit code.** A gate that has a `{report_file}` passes only if it exited 0 and its report shows at least one test ran and none failed. A test that kills its own runner therefore fails even when `srt` exits 0.

## Consequences

- Gate argv with quotes, `$` or backslashes cannot run under the sandbox; the error names the element. File names with those characters in owned paths are refused the same way.
- A forged report written by test code while the gate runs is still possible; that is residual risk R-1/R-5. A gate without a report is judged on its exit code alone, so under `srt` it passes when its code kills its runner (R-12).
- **The interpreter.** `srt` 0.0.81 starts with `#!/usr/bin/env node`. aipm reads that line, resolves `node` on PATH skipping relative and repository entries, and starts `node srt …` itself, so a `node` planted in an active `.venv/bin` never runs. Any other `env` line exits 8; an absolute interpreter inside the repository exits 6.
- If a later `srt` execs argv directly or reports signals faithfully, these rules can be relaxed in a new ADR.
