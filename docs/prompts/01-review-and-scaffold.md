# Prompt 01: Review the design and scaffold the repository

**Milestone:** v0.1 · **Depends on:** nothing · **Branch:** `step/01-scaffold`

## Your role

You are a staff engineer starting a security-sensitive open-source Python CLI. The architecture is already designed. Your job in this session is to:

1. challenge the design before any code exists, and
2. lay down a repository skeleton good enough to grow into an enterprise-grade project.

## Read first

- `AGENTS.md` (all of it)
- `docs/architecture/ARCHITECTURE.md`: all of it, since this is the review step
- `docs/architecture/SECURITY.md`: all of it

## Part A: Design review (before any files are written)

Send me a review with:

1. **Up to 10 issues**: contradictions, gaps, unbuildable parts, or security holes in the two design docs. For each one give the section, the problem, and the fix you recommend.
2. **Over-engineering:** anything that is too much for v0.1 and should move later, with the reason.
3. **Facts to verify:** any third-party detail you believe may be outdated, such as tool flags in ARCHITECTURE §11 or package APIs. Say how you would verify it.

Then **wait for my answers**. After I reply, apply the agreed doc changes in a `docs:` commit before scaffolding.

## Part B: Scaffold

Create the following. Every module gets a docstring, typed public stubs, and `NotImplementedError` with the milestone in the message where its logic belongs to a later prompt.

1. **`pyproject.toml`:**
   - `name = "aipm"`, Python `>=3.12`, `hatchling` with `hatch-vcs` for the version.
   - `[project.scripts] aipm = "aipm.cli.main:app"`.
   - Runtime dependencies exactly as in ARCHITECTURE §19, with lower bounds only. Dev dependencies go in a `dev` dependency group. Extras: `otel`, `keyring`.
   - Tool configuration:
     - `ruff`: enable the rule sets `E`, `F`, `I`, `B`, `UP`, `S` (bandit), `PTH`, `RUF`, `ASYNC`, `PL` (selected), `T20`. Ban every way to start a process listed in ARCHITECTURE §5.1, plus `pickle` and `marshal`, in `src/aipm/**` except `src/aipm/execution/process.py`, using `flake8-tidy-imports` banned-api settings (TID251). `tests/**` are exempt, because their fixtures need `git` and the CLI as subprocesses.
     - `pyright`: strict for `src/aipm`.
     - `pytest`: `--disable-socket`, strict markers, `--strict-config`.
     - `coverage`: branch coverage.
     - `importlinter` contracts:
       - a layers contract matching ARCHITECTURE §5.1;
       - a forbidden contract: `aipm.domain` and the pure `aipm.security` modules must not import `subprocess`, `socket`, `httpx`, `anthropic` or `openai`;
       - a forbidden contract: only `aipm.llm.providers` may import `anthropic` or `openai`.
2. **Package skeleton:** exactly the tree in ARCHITECTURE §19, with `__init__.py` files.
3. **CLI skeleton (`aipm.cli`):**
   - A Typer app that registers every command in ARCHITECTURE §16, with its flags and help text.
   - Global flags.
   - The JSON envelope (§16.2) in `cli/errors.py`. The exit-code enum (§16.1) and the `AipmError` hierarchy live in `domain/errors.py`; `cli/errors.py` re-exports `ExitCode`.
   - Commands for later milestones print `available in vX.Y` and exit 2.
   - `aipm --version` works.
   - Startup must be fast: no heavy imports at module level. Add a test that `aipm --help` takes less than 300 ms (skip on slow CI with a marker, but run it locally).
4. **Root files:**
   - `README.md`: what aipm is, the install line (`uv tool install git+https://github.com/mlbala/aipm`), the command table, a security model summary linking to `docs/architecture/SECURITY.md`, and a status badge placeholder.
   - `LICENSE`: the Apache-2.0 text.
   - `SECURITY.md`: the disclosure policy from SECURITY.md §16.
   - `CONTRIBUTING.md`: setup, commands, commit style, and a note that security changes need tests in `tests/security`.
   - `CODE_OF_CONDUCT.md`: Contributor Covenant 2.1.
   - `CHANGELOG.md` with an "Unreleased" section.
   - `.gitignore`, `.editorconfig`, `.python-version` (3.12).
5. **`.github/`** (every action pinned by full commit SHA, with a comment giving the version):
   - `workflows/ci.yml`:
     - matrix `ubuntu-latest` and `macos-latest` × Python 3.12 and 3.13;
     - steps: `uv sync --frozen`, ruff, `ruff format --check`, pyright, lint-imports, pytest with coverage;
     - `permissions: {}` at the top, granting `contents: read` per job.
   - `workflows/security.yml`: gitleaks, semgrep (`--metrics off`, explicit rule packs), osv-scanner on `uv.lock`, zizmor on the workflows. Runs on PRs and weekly.
   - A `commit-authorship` job in `ci.yml`. It fails if any commit in the push or PR has a message line matching `Co-Authored-By:` with an AI tool name, `Claude-Session:` or `Generated with Claude Code`, or an author other than the repository owner. Keep the existing `.githooks/commit-msg` hook as is.
   - `dependabot.yml` covering `github-actions` and `uv`.
   - `release.yml`: a stub with a TODO for prompt 08, which completes it.
6. **Test skeleton:**
   - `tests/conftest.py` with fixtures:
     - `tmp_repo`: a temporary git repo with an initial commit;
     - `fake_secrets`: registers fake secret values in the environment and exposes them so tests can assert they never leak;
     - `fake_llm`: a placeholder until prompt 03.
   - Empty directories with `README.md` files explaining each: `tests/{unit,property,golden,integration,security,e2e,fakes}`.
   - `tests/security/corpus/README.md`: describes the corpus format (one YAML file per case: `id`, `vector`, `input`, `expected`). Add the first 10 cases from SECURITY.md §14.2 as data files now. Their tests come in later prompts.
7. **`examples/clinic-booking/idea.md`:** a realistic one-page idea for a clinic appointment booking app with WhatsApp reminders, used by end-to-end tests later.
8. **`docs/architecture/adr/`:** one short file per decision in ARCHITECTURE §23 (`0001-…md` through `0013-…md`) using the template: Context, Options, Decision, Consequences.

## Security requirements for this step

- CI and security workflows MUST have minimal permissions and SHA-pinned actions. zizmor must pass.
- ruff must already ban `subprocess` outside `execution/process.py`. Add a test that the ban works: a fixture file that violates the rule, checked by running ruff on it.

## Tests

- CLI smoke tests: every command shows `--help`, `--version` works, and the JSON envelope shape is checked for one stub command.
- The import-linter contracts pass on the skeleton.
- The startup-time test.

## Out of scope

Any real logic for state, the LLM, discovery, planning or adapters.

## Definition of done

- [ ] The design review was answered and the doc fixes were committed.
- [ ] `uv sync`, ruff, pyright (strict), lint-imports and pytest all pass locally.
- [ ] `uv run aipm --help` lists every command from ARCHITECTURE §16.
- [ ] The CI and security workflows are valid (run `zizmor` locally if available; otherwise explain).
- [ ] Report written as described in `docs/prompts/README.md`.
