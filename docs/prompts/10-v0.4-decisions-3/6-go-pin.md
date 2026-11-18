# Item 6: pin CI's Go to an exact version

Branch: `security/v0.4-d3-6-go-pin` · Severity: low · Read `docs/prompts/10-v0.4-decisions-3/README.md` "Rules for every item" first.

## Your role

You are a CI supply-chain engineer making one toolchain pin exact, and adding a test so it stays exact.

## Read first

- AGENTS.md, and SECURITY.md's CI and supply-chain section (`grep -n "CI\|pinned" docs/architecture/SECURITY.md`).
- `.github/workflows/ci.yml`, the `sandbox` job's "Set up Go" step (`go-version: "1.26.x"`), and its other toolchain inputs: uv `version: "0.13.6"`, Node `node-version: "22.15.0"`.
- `.github/dependabot.yml`, and the tests that already check the workflows: `grep -rln "workflows" tests/security/`.

## The finding

`go-version: "1.26.x"` lets every CI run pick up a new Go patch release on the day it ships, unreviewed, while every other toolchain in the workflows is pinned exactly. Session 3's CI run installed go1.26.11.

## What to do

1. Find the current exact version without the owner's GitHub credentials: the owner's credentials are for git only, so do not use `gh run view`, `gh api` or any other GitHub API call. List Go's release tags with plain git, `git ls-remote --tags https://github.com/golang/go 'refs/tags/go1.26.*'`, and take the highest `go1.26.N` (not a `beta` or `rc`). Show it to the owner in the plan. The owner may name another version, or paste the version from a CI log.
2. Set `go-version: "<exact>"` and keep `cache: false`. Add a comment saying the version is exact on purpose and is raised by hand. Dependabot does not update `go-version` inputs, which also goes in the comment.
3. Change only the Set up Go step in `ci.yml`. Item 7 is adding a job in `security.yml` at the same time.

## Tests

`tests/security/test_v04_d3_6_toolchain_pins.py`, parsing the workflows with aipm's safe YAML loader (`aipm.state.yamlio.load_yaml`), never a regex over the whole file:

- Every `go-version`, `node-version`, `python-version` (where it is a literal, not `${{ matrix.* }}`; a matrix's values must then be exact `x.y` or `x.y.z` as the existing matrix uses) and setup-uv `version` input in `.github/workflows/*.yml` is an exact version: digits and dots, with no `x`, `*`, `^`, `~`, `latest` or `stable`.
- No step sets `check-latest: true`.
- Show the test failing against `1.26.x` before the fix.

If the test finds another loose pin that is not Go, report it and stop. Fixing it is the owner's call, since it may belong to another item.

## Docs

CHANGELOG (Security: "CI pins Go to an exact version"). The progress doc. SECURITY.md's CI line, if it lists the pinned toolchains.

## Done when

All of README "Rules for every item" is met. After "ship", the owner can confirm the version in the sandbox job's "Set up Go" log.
