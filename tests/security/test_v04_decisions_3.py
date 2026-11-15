"""The owner's v0.4 decisions, session 3 (docs/security/reviews/v0.4-decisions-progress.md):
the nightly `ci-long` workflow (v0.3 rec 6) and the real `srt` in CI (v0.3 rec 3).

The workflows are read with the safe YAML loader and checked as written; nothing here runs on
GitHub. `tests/security/test_release_supply_chain.py` checks every workflow's triggers,
permissions and action pins; the tests here check what each new job is for.
"""

import json
import re
import shlex
from typing import Any

from tests.conftest import REPO_ROOT
from tests.security.test_release_supply_chain import WORKFLOWS, ci_uv_version, load, steps

CI_LONG = WORKFLOWS / "ci-long.yml"


def runs(job: dict[str, Any]) -> list[str]:
    return [str(s["run"]).replace("\\\n", " ") for s in steps(job) if "run" in s]


def uses(job: dict[str, Any], action: str) -> dict[str, Any]:
    found = [s for s in steps(job) if str(s.get("uses", "")).startswith(f"{action}@")]
    assert len(found) == 1, action
    return found[0]


# ------------------------------------------------------------------ v0.3 rec 6: ci-long


def test_ci_long_runs_nightly_and_by_hand_only() -> None:
    """v0.3 rec 6 (open since v0.1; RT03-10 was found only by ci-long): the long fuzzing run
    is too slow for every push, so it runs once a night and on demand, never on a PR."""
    triggers = load(CI_LONG)["on"]
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    crons = [entry["cron"] for entry in triggers["schedule"]]
    assert len(crons) == 1
    minute, hour, day, month, weekday = crons[0].split()
    assert minute.isdigit() and hour.isdigit()
    assert (day, month, weekday) == ("*", "*", "*")  # every night


def test_ci_long_runs_the_long_profile_over_the_properties_and_security_suite() -> None:
    jobs = load(CI_LONG)["jobs"]
    assert len(jobs) == 1
    job = next(iter(jobs.values()))
    assert job["permissions"] == {"contents": "read"}
    assert 0 < int(job["timeout-minutes"]) <= 180
    assert str(uses(job, "astral-sh/setup-uv")["with"]["version"]) == ci_uv_version()
    commands = [shlex.split(r) for r in runs(job)]
    assert ["uv", "sync", "--frozen", "--all-extras"] in commands
    assert [
        "uv", "run", "--frozen", "pytest", "--hypothesis-profile=ci-long",
        "tests/property", "tests/security",
    ] in commands  # fmt: skip


def test_the_ci_long_profile_runs_at_least_2000_examples() -> None:
    text = (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    assert 'settings.register_profile("ci-long", max_examples=2000, deadline=None)' in text


# ------------------------------------------------------------------ v0.3 rec 3: the real srt

SANDBOX_DIR = REPO_ROOT / ".github" / "sandbox"
EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+")


def sandbox_job() -> dict[str, Any]:
    return dict(load(WORKFLOWS / "ci.yml")["jobs"]["sandbox"])


def test_the_sandbox_job_runs_on_ubuntu_and_macos_with_read_only_permissions() -> None:
    job = sandbox_job()
    assert job["permissions"] == {"contents": "read"}
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "macos-latest"]
    assert job["runs-on"] == "${{ matrix.os }}"
    assert 0 < int(job["timeout-minutes"]) <= 60


def test_the_sandbox_job_installs_the_locked_packages_without_scripts() -> None:
    """v0.3 rec 3, the owner's conditions: srt at an exact version, the lockfile committed,
    `npm ci --ignore-scripts`. Nothing else in any workflow installs from npm."""
    job = sandbox_job()
    node = uses(job, "actions/setup-node")
    assert node["with"]["package-manager-cache"] is False  # no cache to poison
    assert EXACT_VERSION.fullmatch(str(node["with"]["node-version"]))
    installs = [s for s in steps(job) if "npm" in str(s.get("run", ""))]
    assert len(installs) == 1
    assert shlex.split(str(installs[0]["run"])) == [
        "npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund",
    ]  # fmt: skip
    assert installs[0]["working-directory"] == ".github/sandbox"
    for path in WORKFLOWS.glob("*.y*ml"):
        for other in load(path)["jobs"].values():
            for command in runs(other):
                words = command.split()
                if {"npm", "npx", "pnpm", "yarn"} & set(words):
                    assert command == "npm ci --ignore-scripts --no-audit --no-fund", command


def test_the_sandbox_packages_are_pinned_exactly_and_run_no_install_scripts() -> None:
    manifest = json.loads((SANDBOX_DIR / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((SANDBOX_DIR / "package-lock.json").read_text(encoding="utf-8"))
    wanted = manifest["dependencies"]
    assert set(wanted) == {"@anthropic-ai/sandbox-runtime", "pnpm"}
    assert all(EXACT_VERSION.fullmatch(v) for v in wanted.values()), wanted
    assert lock["lockfileVersion"] == 3
    packages = lock["packages"]
    assert packages[""]["dependencies"] == wanted
    for name, version in wanted.items():
        assert packages[f"node_modules/{name}"]["version"] == version
    for path, entry in packages.items():
        if not path:
            continue
        assert "hasInstallScript" not in entry, path
        assert str(entry["integrity"]).startswith("sha512-"), path
        assert str(entry["resolved"]).startswith("https://registry.npmjs.org/"), path


def test_the_sandbox_job_sets_up_linux_only_on_linux_and_requires_every_tool() -> None:
    """On Ubuntu, bubblewrap needs unprivileged user namespaces, which AppArmor restricts by
    default; the sysctl runs only there. Every real-sandbox test must run: a missing srt,
    Go, Cargo or pnpm fails the job instead of skipping."""
    job = sandbox_job()
    linux = [s for s in steps(job) if "sysctl" in str(s.get("run", ""))]
    assert len(linux) == 1
    assert linux[0]["if"] == "runner.os == 'Linux'"
    assert "kernel.apparmor_restrict_unprivileged_userns=0" in str(linux[0]["run"])
    for package in ("bubblewrap", "socat", "ripgrep"):
        assert package in str(linux[0]["run"])
    tests = [s for s in steps(job) if "pytest" in str(s.get("run", ""))]
    assert len(tests) == 1
    assert tests[0]["env"] == {"AIPM_REQUIRE_REAL_SRT": "1"}
    assert "tests/security/test_real_sandbox.py" in str(tests[0]["run"])
