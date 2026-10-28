# Prompt 08: Codex, Copilot and Gemini adapters, `auto`, plugins, release pipeline

**Milestone:** v0.4 · **Depends on:** v0.3 tagged · **Branch:** `step/08-multi-tool`

## Your role

You are extending aipm to three more coding agents without weakening any guarantee, then automating the whole flow and the release.

## Read first

- `AGENTS.md`
- ARCHITECTURE §7.3, §10.2, §11 (all columns), §17, §18, §21, §22
- SECURITY §6, §9, §12.1

## Before coding

For each of Codex CLI, GitHub Copilot CLI and Gemini CLI, read the current official docs. Produce a table of:

- the headless invocation;
- how the prompt is delivered (stdin, argument or file);
- JSON output;
- least-privilege flags;
- sandbox options;
- how the context file is discovered;
- how the config home is relocated;
- forbidden flags;
- exit codes.

Mark each cell as verified (with a source link and the tool version) or unknown. **Any adapter whose safety-relevant cells are unknown ships render-only, with dispatch disabled.**

## Build

1. **Adapters:** `codex.py`, `copilot.py`, `gemini.py`, each implementing the full `ToolAdapter`.
   - Starting points (verify every one): Codex `exec --sandbox workspace-write` (no network); Copilot `-p` + `--attachment`, `--allow-tool 'write'`, `--allow-tool 'shell(<gate>)'`, `--no-ask-user`, `--secret-env-vars`, `--output-format json`; Gemini `-p` via stdin, `--approval-mode auto_edit`, `--allowed-tools`, `--sandbox`, `--output-format json`.
   - `detect()` fails closed on any missing safety flag.
   - The forbidden-flag tables are extended in `command_policy`.
2. **Context files:** `GEMINI.md`, or `.gemini/settings.json` with `context.fileName`; `.github/copilot-instructions.md` as a thin pointer; `.agents/skills/aipm-*/SKILL.md` for Codex. All of them use managed blocks and the `sync-context` diff approval.
3. **Adapter contract tests:** one stub binary per tool that asserts its expected argv, environment and working directory, plus a shared contract suite that every adapter must pass.
4. **`aipm auto [--yes]`** (ARCHITECTURE §7.3):
   - Loops `next_command` until the phase is `built`, pausing at G1–G3 unless `--yes`.
   - Stops on exit codes 4, 5, 6 and 8 and prints the exact command to run next.
   - **Never records trust**: with an untrusted surface it stops with exit 6 and prints `aipm trust`.
5. **Plugins (`aipm.plugins.loader`):** the entry-point groups from §18, loaded only from aipm's own environment. `--no-plugins`. `doctor` lists loaded plugins.
6. **OpenTelemetry:** the `aipm[otel]` extra, with spans as in §17 and no prompt or output content in attributes. Enabled only with `--trace` plus `OTEL_EXPORTER_OTLP_ENDPOINT`.
7. **Stacks:** the `go` and `rust-cargo` templates, with golden tests.
8. **Release pipeline (`release.yml`):** on a `v*` tag: `uv build`, a CycloneDX SBOM, `actions/attest-build-provenance`, checksums, and a GitHub Release. Minimal permissions (`contents: write` and `id-token: write`, `attestations: write` only in the release job). SHA-pinned actions. A README section explaining how users verify a release (`gh attestation verify`).
9. **Docs:** a README section per tool (setup, the auth environment variable, known limits), the tested versions table, and an `auto` walkthrough.

## Security requirements

- Run the malicious-agent scenarios (SECURITY §14.3) against **every** adapter's stub.
- A test that `auto --yes` with an untrusted surface exits 6 and does not touch the trust store.
- A test that a plugin installed in the target repo's virtualenv is **not** loaded.
- zizmor passes on `release.yml`.

## Out of scope

New phases or roles, a web UI, PyPI publishing.

## Definition of done

- [ ] The v0.4 acceptance criteria in ARCHITECTURE §22 are met.
- [ ] The adapter verification table is in `docs/adapters.md` with sources and versions.
- [ ] All checks pass; the security-reviewer review is clean; then run prompt 09.
- [ ] Report written.
