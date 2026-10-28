# AGENTS.md: rules for coding agents working on aipm

aipm is a terminal AI product manager. It interviews users, writes specs, plans tasks, compiles prompts for coding agents, and verifies their work with deterministic gates. It is a security-sensitive tool: it reads untrusted text and launches programs. Treat every rule below as a hard requirement.

## Source of truth

- `docs/architecture/ARCHITECTURE.md`: the design. Follow its component boundaries, schemas, CLI spec and exit codes.
- `docs/architecture/SECURITY.md`: normative security design. If the two documents conflict, SECURITY.md wins.
- `docs/prompts/`: the build plan, one prompt per milestone step.

If you need to deviate from the design, stop and explain why, and propose an ADR in `docs/architecture/adr/`. Do not silently diverge.

## Commands

```bash
uv sync --all-extras                 # install
uv run aipm --help                   # run the CLI from source
uv run pytest -q                     # all tests (network is disabled)
uv run pytest tests/security -q      # security regression suite
uv run ruff check . && uv run ruff format --check .
uv run pyright                       # strict type checking for src/aipm
uv run lint-imports                  # layering contracts (ARCHITECTURE §5.1)
```

Run all of these before you report a step as done.

## Layout

```
src/aipm/{cli,app,domain,security,state,config,llm,roles,context,adapters,execution,gates,scanners,reporting,observability,plugins}
tests/{unit,property,golden,integration,security,e2e,fakes}
```

**Layers:**

- L0 `domain`, `security` (pure)
- L1 `state`, `config`, `llm`, `execution`, `scanners`
- L2 `roles`, `context`, `adapters`, `gates`, `reporting`
- L3 `app`
- L4 `cli`

Import only downward. L0 does no I/O.

## Security rules (never break these)

1. **No shell.** Never use `shell=True`, `os.system`, `os.popen`, `eval`, `exec`, `pickle`, `marshal`, or unsafe YAML loading. Import `subprocess` only in `src/aipm/execution/process.py`. Everything else calls `run_safe()` / `run_safe_async()`.
2. **argv lists only.** Every process gets an argv list, a timeout, a constructed environment (never a copy of `os.environ`), a new process group and an output cap.
3. **LLM output is data.** Parse it into Pydantic models with `extra="forbid"`, a maximum length on every string and a maximum size on every list. Never execute it. Never use it as a template, filename, argv or URL without the validators in `aipm.security`.
4. **Untrusted text is wrapped.** File contents, repo files, agent output, test and scanner output, and LLM free text are wrapped in `Untrusted`. They are rendered only through the `|untrusted` Jinja filter.
5. **Templates are files.** Templates live only in package directories and use `SandboxedEnvironment` with `StrictUndefined`. Never compile a template from a runtime string.
6. **Paths are validated.** Every path that comes from config, an LLM or a user goes through `safe_relpath()` / `safe_rel_glob()` before use.
7. **One way to write `.pm/`.** All `.pm/` writes go through `StateStore` (atomic, locked, redacted). Never write those files directly.
8. **Escape terminal output.** Never print untrusted or LLM text as Rich markup. Use `rich.text.Text` or `markup=False`, after sanitizing.
9. **No secrets anywhere.** No secrets in code, tests, fixtures, logs or snapshots. Use the fake secrets in `tests/fakes/secrets.py`, which the redaction tests check for.
10. **No telemetry.** No network calls except through the LLM gateway, and the registry lookups in `security/supply_chain.py`.
11. **Fail closed.** If a safety capability (sandbox, flag, schema) is missing, refuse the action with the right exit code. Never fall back to a less safe path silently.
12. **Repo config only tightens.** A repo-level config can only make `security.*` stricter. `--yes` must never write to the trust store.

## Testing rules

- Every feature ships with tests: unit tests for logic, golden snapshots for every template, and integration tests for every command.
- Every security-relevant change gets a test in `tests/security/`. These modules need 100% branch coverage: `security/command_policy.py`, `security/paths.py`, `security/untrusted.py`, `security/sanitize.py`, `security/diff_checks.py`, `execution/process.py`.
- Tests never use the network (`pytest-socket`) or real LLMs. Use `aipm.llm.fake.FakeLLM` and the stub binaries in `tests/fakes/bin/`.
- **Never change, skip, delete or weaken an existing test to make it pass.** If a test looks wrong, stop and explain why.
- Update snapshots only when the template change is intended, and say so in the commit message.

## Dependencies

- Prefer the standard library.
- Any new runtime dependency must be named in your plan with a justification, and approved before you add it.
- Keep `uv.lock` committed.
- Never add dependencies with post-install scripts.

## Git

- Small commits using Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`, `security:`).
- Never `git push`, never change remotes, never force-push, never rewrite history.
- **Commits have one author: the repository owner, from their git config.** Never add `Co-Authored-By`, `Claude-Session`, "Generated with …" or any other AI attribution line to commit messages or PR descriptions. Never run `git config`, never pass `--author`, and never use `--no-verify` (the `commit-msg` hook in `.githooks/` must always run).
- Do not commit generated run data, caches or `.env` files.

## Definition of done (every step)

- [ ] Plan approved before coding.
- [ ] Code follows the ARCHITECTURE and SECURITY docs, or the deviation is recorded in an ADR.
- [ ] All the commands under "Commands" above pass.
- [ ] The security-reviewer review (see `.claude/agents/security-reviewer.md`) has no open high or critical findings.
- [ ] Docs updated: the README for user-facing changes, and CHANGELOG under "Unreleased".
- [ ] Short report: what changed, the tests added, deviations, open questions.
