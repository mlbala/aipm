# Item 7: shellcheck for `install.sh` and the git hooks

Branch: `security/v0.4-d3-7-shellcheck` · Severity: low · Read `docs/prompts/10-v0.4-decisions-3/README.md` "Rules for every item" first.

## Your role

You are a CI supply-chain engineer adding a static check for the repository's shell scripts. Users pipe `install.sh` into `sh`, and the `pre-push` and `commit-msg` hooks enforce the authorship rules, so a quoting bug in either is a security bug.

## Read first

- AGENTS.md ("Git"), SECURITY.md's install and release sections (`grep -n "install.sh" docs/architecture/SECURITY.md`).
- `install.sh`, `.githooks/pre-push`, `.githooks/commit-msg`: all POSIX `sh`.
- `.github/workflows/security.yml`: how the gitleaks, semgrep, osv-scanner and zizmor jobs are written (pinned action SHAs, `permissions: contents: read`, `persist-credentials: false`).
- The tests that cover these scripts: `grep -rln "install.sh\|githooks" tests/`.

## What to do

1. **Find every shell script**: tracked files with a `sh`, `bash` or `dash` shebang, and `*.sh`. Today there are eight: `install.sh`, `.githooks/pre-push`, `.githooks/commit-msg`, and the test stubs `tests/fakes/bin/gitleaks`, `osv-scanner`, `semgrep`, `srt` and `trivy`. Check all eight. A fix in a stub must not change what it prints, its exit codes or the files it writes: the tests that use it must pass unchanged.
2. **Add a job** `shellcheck` ("Shell scripts (shellcheck)") to `.github/workflows/security.yml`, on `ubuntu-latest`, `permissions: contents: read`. Check out with the same pinned `actions/checkout` SHA and `persist-credentials: false`. Then:
   - print `shellcheck --version`;
   - fail if shellcheck is missing (`command -v shellcheck`). Do not download a binary from an unpinned URL. `sudo apt-get install -y shellcheck` from Ubuntu's signed archive is acceptable if the runner image does not include it: check the image first;
   - run `shellcheck --shell=sh --severity=style` on all eight scripts. List them explicitly in the workflow, not with a glob, so the test below can compare them.
   Only edit `security.yml` (item 6 is editing `ci.yml`). `zizmor` must stay clean.
3. **Fix what shellcheck reports** in the eight scripts, without changing their behaviour. For each warning, either fix it or disable it on that line with `# shellcheck disable=SCxxxx` and a reason. Keep the scripts POSIX `sh` (no bashisms). Any change to the hooks' refusal logic needs the owner's go.
4. Locally shellcheck is not installed. Do not install global tools. Tell the owner to run `brew install shellcheck` to check locally, and rely on the CI job until then. If the owner installs it, run it and paste the output.

## Tests

`tests/security/test_v04_d3_7_shellcheck.py`:

- `security.yml` has the shellcheck job. Parse it with `aipm.state.yamlio.load_yaml`. It uses `--shell=sh`, and the scripts it names are exactly the tracked shell scripts (found by shebang via `git ls-files` through the test helpers, or a directory walk that skips `.git`, `node_modules` and `.venv`). A new script that is not in the job fails this test.
- The job's checkout is pinned to a full SHA with `persist-credentials: false`, and the job's permissions are `contents: read` only.
- The existing tests for `install.sh` and the hooks still pass unchanged.

## Docs

CHANGELOG (Security: "CI runs shellcheck on install.sh and the git hooks"). The progress doc. SECURITY.md's list of CI checks.

## Done when

All of README "Rules for every item" is met, and the new job passes on the PR.
