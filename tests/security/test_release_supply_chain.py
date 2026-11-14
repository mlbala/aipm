"""Red-team v0.4, Part 3: the release pipeline and the installer (SECURITY.md §12.1).

The workflows are read with the safe YAML loader and checked as written; nothing here runs on
GitHub. Finding sections first (RT04-16 to RT04-19), then `test_pin_*` for the controls that
held. The checks that need GitHub itself (tag rulesets, a real release) are hand checks in
docs/security/reviews/v0.4.md §8.
"""

import fnmatch
import re
import shlex
import shutil
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

from tests.conftest import REPO_ROOT, run_program
from tests.integration.test_install_sh import SCRIPT, run, stub
from tests.integration.test_install_sh import env as env  # noqa: PLC0414 - the fixture

WORKFLOWS = REPO_ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
BUILD_CONSTRAINTS = REPO_ROOT / ".github" / "release" / "requirements-build.txt"
README = REPO_ROOT / "README.md"

PUBLISHED = ("aipm-0.4.0-py3-none-any.whl", "aipm-0.4.0.tar.gz", "aipm.cdx.json", "SHA256SUMS")
"""What the build job leaves in `dist/`: the wheel, the sdist, the SBOM and the checksums."""

WRITERS = {
    ("release.yml", "release"): {"contents", "id-token", "attestations"},
    ("scorecard.yml", "analysis"): {"security-events", "id-token"},
}
"""The only jobs that may hold a `write` permission, and which ones."""


def load(path: Path) -> dict[str, Any]:
    data = YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data  # pyright: ignore[reportUnknownVariableType]


def workflows() -> list[Path]:
    found = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    assert found
    return found


def steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return list(job.get("steps", []))


def release_jobs() -> dict[str, Any]:
    return dict(load(RELEASE)["jobs"])


# ------------------------------------------------------------------ RT04-16


def published_patterns() -> list[str]:
    """The paths `gh release create` uploads, from the release job's `run:` text."""
    for step in steps(release_jobs()["release"]):
        run = str(step.get("run", ""))
        if "gh release create" in run:
            words = shlex.split(run.replace("\\\n", " "))
            start = words.index("create") + 2  # after the tag
            return [w for w in words[start:] if not w.startswith("-") and "/" in w]
    raise AssertionError("no `gh release create` step")


def attested_patterns() -> list[str]:
    for step in steps(release_jobs()["release"]):
        if str(step.get("uses", "")).startswith("actions/attest-build-provenance@"):
            text = str(step["with"]["subject-path"])
            return [line.strip() for line in text.splitlines() if line.strip()]
    raise AssertionError("no attestation step")


def test_every_published_file_is_attested() -> None:
    """RT04-16: SHA256SUMS was published (`dist/*`) but not attested, while the README says
    every file of a release has an attestation."""
    published = published_patterns()
    attested = attested_patterns()
    for name in PUBLISHED:
        path = f"dist/{name}"
        assert any(fnmatch.fnmatch(path, p) for p in published), f"{name} is not published"
        assert any(fnmatch.fnmatch(path, p) for p in attested), f"{name} is not attested"
    # Nothing is published that is not attested: the two patterns are the same set.
    assert set(published) <= set(attested), (published, attested)


# ------------------------------------------------------------------ RT04-17


def test_the_readme_verify_command_pins_the_release_workflow_and_the_tag() -> None:
    """RT04-17: `--repo mlbala/aipm` alone accepts an attestation that any workflow run in the
    repository signed (a branch push whose edited workflow grants `id-token: write`), not only
    release.yml from the tag, which is what the README said it checks."""
    commands = [
        line.strip()
        for line in README.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("gh attestation verify")
    ]
    assert commands
    for command in commands:
        words = shlex.split(command.split("#", 1)[0])
        assert "--signer-workflow" in words, command
        assert words[words.index("--signer-workflow") + 1] == (
            "mlbala/aipm/.github/workflows/release.yml"
        )
        assert "--source-ref" in words, command
        assert re.fullmatch(r"refs/tags/v\d+\.\d+\.\d+", words[words.index("--source-ref") + 1])
        assert "--deny-self-hosted-runners" in words, command


# ------------------------------------------------------------------ pins


@pytest.mark.parametrize("path", workflows(), ids=lambda p: p.name)
def test_pin_no_privileged_pull_request_triggers(path: Path) -> None:
    """A fork's pull request never runs with this repository's write token or secrets."""
    triggers = load(path)["on"]
    names = {str(t) for t in triggers} if isinstance(triggers, (dict, list)) else {str(triggers)}
    assert not names & {"pull_request_target", "workflow_run", "issue_comment"}


@pytest.mark.parametrize("path", workflows(), ids=lambda p: p.name)
def test_pin_no_expression_inside_a_run_step(path: Path) -> None:
    """PR titles, branch names and commit messages reach shell only through `env:`, never as
    `${{ … }}` pasted into a script."""
    for name, job in load(path)["jobs"].items():
        for step in steps(job):
            assert "${{" not in str(step.get("run", "")), (path.name, name, step.get("name"))


@pytest.mark.parametrize("path", workflows(), ids=lambda p: p.name)
def test_pin_permissions_are_none_by_default_and_write_only_where_needed(path: Path) -> None:
    doc = load(path)
    assert doc["permissions"] == {}
    for name, job in doc["jobs"].items():
        perms = job.get("permissions")
        assert isinstance(perms, dict), f"{path.name}:{name} must list its permissions"
        writes = {k for k, v in perms.items() if v == "write"}
        assert writes <= WRITERS.get((path.name, name), set()), (path.name, name, writes)
        assert all(v in {"read", "write", "none"} for v in perms.values())


@pytest.mark.parametrize("path", workflows(), ids=lambda p: p.name)
def test_pin_actions_are_pinned_and_checkouts_keep_no_credentials(path: Path) -> None:
    for job in load(path)["jobs"].values():
        for step in steps(job):
            uses = str(step.get("uses", ""))
            if not uses:
                continue
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", uses), uses
            if uses.startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False
            if uses.startswith("astral-sh/setup-uv@"):
                assert step["with"]["enable-cache"] is False  # no cache to poison


def test_pin_the_release_runs_only_on_a_version_tag_on_main() -> None:
    doc = load(RELEASE)
    assert doc["on"] == {"push": {"tags": ["v*"]}}
    build = release_jobs()["build"]
    runs = "\n".join(str(s.get("run", "")) for s in steps(build))
    assert 'git merge-base --is-ancestor "${GITHUB_SHA}" origin/main' in runs


def test_pin_the_build_job_is_read_only_with_a_hash_pinned_backend() -> None:
    build = release_jobs()["build"]
    assert build["permissions"] == {"contents": "read"}
    runs = " ".join(str(s.get("run", "")) for s in steps(build))
    assert "--build-constraints .github/release/requirements-build.txt" in runs
    assert "--require-hashes" in runs
    assert "--frozen" in runs  # the SBOM is the locked set
    # Every pinned build requirement carries at least one hash.
    blocks = re.split(r"\n(?=[A-Za-z0-9])", BUILD_CONSTRAINTS.read_text(encoding="utf-8"))
    entries = [b for b in blocks if re.match(r"[A-Za-z0-9][\w.-]*==", b)]
    assert entries
    for block in entries:
        assert "--hash=sha256:" in block, block.splitlines()[0]


def test_pin_the_release_job_runs_no_project_code() -> None:
    """The job that can write (contents, id-token) checks out nothing and runs only
    sha256sum and gh on the built files."""
    release = release_jobs()["release"]
    assert release["needs"] == "build"
    for step in steps(release):
        assert not str(step.get("uses", "")).startswith("actions/checkout@")
        run = str(step.get("run", "")).replace("\\\n", " ")
        for command in re.split(r"\n|;|&&|\|\||\||`|\$\(", run):
            if command.strip():
                assert shlex.split(command)[0] in {"sha256sum", "gh"}, run


# ------------------------------------------------------------------ RT04-18 (install.sh)


def planted_uv(directory: Path, marker: Path) -> Path:
    """A `uv` a hostile repository ships: it records that it ran."""
    directory.mkdir(parents=True, exist_ok=True)
    return stub(directory / "uv", f'echo ran >> "{marker}"')


@pytest.mark.parametrize("entry", [".", "", "node_modules/.bin"])
def test_install_sh_never_runs_uv_from_a_relative_path_entry(
    env: dict[str, str], tmp_path: Path, entry: str
) -> None:
    """RT04-18: the script ran whatever `uv` came first on PATH, without asking. With `.`, an
    empty entry or another relative entry in PATH, that is the current directory's, which
    the attacker controls when the user runs it inside a cloned repository."""
    repo = tmp_path / "repo"
    marker = tmp_path / "planted.log"
    planted_uv(repo / (entry or "."), marker)
    real = tmp_path / "real.log"
    planted_uv(Path(env["PATH"].split(":")[0]), real)  # the user's uv, later on PATH
    env = {**env, "PATH": f"{entry}:{env['PATH']}"}
    code, _, err = run(env, "-t", "v0.4.0", cwd=repo)
    assert code == 2, err
    assert "relative" in err
    assert not marker.exists()
    assert not real.exists()


@pytest.mark.parametrize("path", ["{rel}:{rest}", "{rest}:", "{rest}::/usr/bin"])
def test_install_sh_refuses_any_relative_path_entry(
    env: dict[str, str], tmp_path: Path, path: str
) -> None:
    """RT04-18, after the security review: a relative or empty entry (a trailing `:` too,
    which field splitting drops) lets the repository shadow any command the script or uv's
    installer runs, not only `uv`. Refused whether or not it holds a uv."""
    repo = tmp_path / "repo"
    (repo / "bin").mkdir(parents=True)
    env = {**env, "PATH": path.format(rel="bin", rest=env["PATH"])}
    code, _, err = run(env, "-y", "-t", "v0.4.0", cwd=repo)
    assert code == 2, err
    assert "relative" in err


def test_install_sh_never_runs_uv_from_the_active_virtualenv(
    env: dict[str, str], tmp_path: Path
) -> None:
    """RT04-18: an activated virtualenv of a cloned repository puts its `bin` first on PATH."""
    repo = tmp_path / "repo"
    venv = repo / ".venv"
    marker = tmp_path / "planted.log"
    planted_uv(venv / "bin", marker)
    env = {**env, "PATH": f"{venv / 'bin'}:{env['PATH']}", "VIRTUAL_ENV": f"{venv}/"}
    code, _, err = run(env, "-t", "v0.4.0", cwd=repo)
    assert code == 2, err
    assert "virtualenv" in err
    assert not marker.exists()


# ------------------------------------------------------------------ RT04-19 (install.sh)


def ci_uv_version() -> str:
    versions = {
        str(step["with"]["version"])
        for job in load(WORKFLOWS / "ci.yml")["jobs"].values()
        for step in steps(job)
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    }
    assert len(versions) == 1, versions
    return versions.pop()


def curl_stub(env: dict[str, str], log: Path, body: str) -> None:
    """A `curl` that logs its URL and output path, writes `body` there, then runs `then`."""
    script = (
        'out=""; url=""\n'
        'while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; https://*) url="$1" ;; esac; '
        "shift; done\n"
        f'echo "$url $out" >> "{log}"\n'
        f"{body}"
    )
    stub(Path(env["PATH"].split(":")[0]) / "curl", script)


def test_install_sh_fetches_one_pinned_uv_installer(env: dict[str, str], tmp_path: Path) -> None:
    """RT04-19: the script ran whatever installer astral.sh served as "latest". It now fetches
    the installer of one uv release, the one CI uses, from that release's assets."""
    log = tmp_path / "curl.log"
    curl_stub(env, log, "exit 22")  # curl -f on an HTTP error: nothing is run
    code, _, _ = run(env, "-y", "-t", "v0.4.0", cwd=tmp_path)
    assert code != 0
    url = log.read_text(encoding="utf-8").split()[0]
    assert url == (
        f"https://github.com/astral-sh/uv/releases/download/{ci_uv_version()}/uv-installer.sh"
    )


@pytest.mark.parametrize("shell", ["sh", "dash"])
def test_install_sh_leaves_no_partial_installer_when_interrupted(
    env: dict[str, str], tmp_path: Path, shell: str
) -> None:
    """RT04-19: a download stopped by a signal leaves no temporary file and runs nothing. dash
    (`sh` on Debian and Ubuntu) runs no EXIT trap on a signal, so the file was left there."""
    path = shutil.which(shell, path="/usr/bin:/bin")
    if path is None:
        pytest.skip(f"no {shell} here")
    log = tmp_path / "curl.log"
    ran = tmp_path / "ran.log"
    partial = f'printf "echo ran >> {ran}\\n" > "$out"\nkill -TERM $PPID\nsleep 5\n'
    curl_stub(env, log, partial)
    result = run_program([path, str(SCRIPT), "-y", "-t", "v0.4.0"], env=env, cwd=tmp_path)
    assert result.returncode != 0
    installer = Path(log.read_text(encoding="utf-8").split()[1])
    assert installer.is_absolute()
    assert not installer.exists()
    assert not ran.exists()
