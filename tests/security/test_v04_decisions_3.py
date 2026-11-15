"""The owner's v0.4 decisions, session 3 (docs/security/reviews/v0.4-decisions-progress.md):
the nightly `ci-long` workflow (v0.3 rec 6) and the real `srt` in CI (v0.3 rec 3).

The workflows are read with the safe YAML loader and checked as written; nothing here runs on
GitHub. `tests/security/test_release_supply_chain.py` checks every workflow's triggers,
permissions and action pins; the tests here check what each new job is for.
"""

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
