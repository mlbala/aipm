# Contributing to aipm

Thank you for helping. aipm is security-sensitive: it reads untrusted text and launches programs. Please read [AGENTS.md](AGENTS.md) before you change code; its rules apply to people and coding agents alike.

## Setup

You need [uv](https://docs.astral.sh/uv/) and git. uv installs Python 3.13 if you do not have it.

```bash
git clone https://github.com/mlbala/aipm && cd aipm
uv sync --all-extras
git config core.hooksPath .githooks   # once per clone: the commit-msg and pre-push hooks
uv run aipm --help
```

## Checks

Run all of these before you open a pull request; CI runs the same ones.

```bash
uv run pytest -q                      # all tests (the network is disabled)
uv run pytest tests/security -q       # the security regression suite
uv run ruff check . && uv run ruff format --check .
uv run pyright                        # strict type checking for src/aipm
uv run lint-imports                   # layering contracts (ARCHITECTURE §5.1)
uv run zizmor .github/                # if you change a workflow
```

## Commits and pull requests

- Use small commits with [Conventional Commits](https://www.conventionalcommits.org/) subjects: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`, `security:`.
- Every commit has one author: you. Do not add `Co-Authored-By`, "Generated with …" or other AI attribution lines. The `commit-msg` hook removes them, the `pre-push` hook refuses them, and the `commit-authorship` CI job fails on them.
- Never weaken, skip or delete an existing test to make a change pass. If a test looks wrong, say so in the pull request.
- Update `CHANGELOG.md` under "Unreleased" for user-facing changes.

## Security changes

Every security-relevant change needs a test in `tests/security/`. These modules need 100% branch coverage: `security/command_policy.py`, `security/paths.py`, `security/untrusted.py`, `security/sanitize.py`, `security/diff_checks.py` and `execution/process.py`.

Do not report vulnerabilities in issues or pull requests; see [SECURITY.md](SECURITY.md).

## Design changes

[ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) and [SECURITY.md](docs/architecture/SECURITY.md) are the source of truth; if they conflict, SECURITY.md wins. To deviate from them, propose an ADR in [docs/architecture/adr/](docs/architecture/adr/) first.

## Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
