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

These rules cover how you, the coding agent, work on this repository. They do not change what aipm itself does: aipm never pushes or opens PRs (ARCHITECTURE §12.2, SECURITY §11).

- Small commits using Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`, `security:`).
- **The repository owner is the only author of everything that leaves this machine:** commits, pushes, pull requests and merges. The owner is the name and email in their git config and the account `gh auth status` shows. Never add `Co-Authored-By`, `Claude-Session`, "Generated with …", 🤖 or any other AI attribution to commit messages, PR titles, PR bodies, PR comments or merge messages.
- Never run `git config`, never pass `--author`, never set `GIT_AUTHOR_*` or `GIT_COMMITTER_*`, and never use `--no-verify`. The `commit-msg` and `pre-push` hooks in `.githooks/` must always run. If a hook refuses, stop and report it. Do not work around it.
- Never change remotes, never force-push, never rewrite history, never push tags, never push to `main` directly, and never delete remote branches.
- Do not commit generated run data, caches or `.env` files.

### Shipping a step: push, PR, merge

Ship only when the owner asks (for example "ship", or a runbook step that says so), and only after the definition of done below is met.

1. Run `gh auth status`. It must show the owner's GitHub account. If it does not, stop and ask.
2. Push the step's branch, as named in `docs/prompts/README.md` "Run order" (`step/*` or `security/*`): `git push -u origin <branch>`. The `pre-push` hook refuses any commit whose author or committer is not the owner, or that has a co-author or AI line.
3. Open the PR against `main`: `gh pr create --base main --head <branch> --title "<Conventional Commit subject>" --body-file <file outside the repo>`. The body is the step report (what changed, tests added, deviations, open questions) and nothing else.
4. Wait for the checks: `gh pr checks <number> --watch`. Never merge with a failing check, and never use `gh pr merge --admin`.
5. Merge with a merge commit, which keeps every commit exactly as the owner made it: `gh pr merge <number> --merge`. Use GitHub's default merge message. If you pass `--subject` or `--body`, the attribution rule above applies to them.
6. Update the local `main`: `git switch main && git pull --ff-only`.
7. Report the PR URL and the merge commit.

## Definition of done (every step)

- [ ] Plan approved before coding.
- [ ] Code follows the ARCHITECTURE and SECURITY docs, or the deviation is recorded in an ADR.
- [ ] All the commands under "Commands" above pass.
- [ ] The security-reviewer review (see `.claude/agents/security-reviewer.md`) has no open high or critical findings.
- [ ] Docs updated: the README for user-facing changes, and CHANGELOG under "Unreleased".
- [ ] Short report: what changed, the tests added, deviations, open questions.
