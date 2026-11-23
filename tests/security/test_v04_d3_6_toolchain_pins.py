"""The v0.4 decisions, session 5, item 6: every CI toolchain is pinned to an exact version.

`go-version: "1.26.x"` let each CI run take a new Go patch release on the day it shipped,
unreviewed, while uv and Node were pinned exactly. Dependabot does not update these inputs,
so a pin is raised by hand and reviewed like any other change.

The workflows are read with aipm's safe YAML loader and checked as written; nothing here runs on
GitHub. A version is exact when it is digits and dots (`1.26.11`, `22.15.0`, `0.13.6`); a
`${{ matrix.<key> }}` value is resolved in the job's own matrix, whose values must be exact
`x.y` or `x.y.z`.
"""

import re
from pathlib import Path
from typing import Any

import pytest

from aipm.state.yamlio import load_yaml
from tests.conftest import REPO_ROOT

WORKFLOWS = REPO_ROOT / ".github" / "workflows"

VERSION_INPUTS = ("go-version", "node-version", "python-version")
"""Toolchain inputs checked on every step, whatever action it uses."""

SETUP_UV = "astral-sh/setup-uv@"
"""setup-uv's `version` input is uv's own version; other actions' `version` means other things."""

VERSION_FILE_INPUTS = ("go-version-file", "node-version-file", "python-version-file")
"""Inputs that read the version from a repository file, around the pin; none may be used."""

EXACT = re.compile(r"\d+(?:\.\d+)+")
"""A literal pin: digits and dots, so no `x`, `*`, `^`, `~`, `latest` or `stable`."""

EXACT_MATRIX = re.compile(r"\d+\.\d+(?:\.\d+)?")
"""A matrix value: exact `x.y` or `x.y.z`, as the existing Python matrix uses."""

MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")

EXPECTED = {
    ("ci.yml", "checks", "version"),
    ("ci.yml", "checks", "python-version"),
    ("ci.yml", "sandbox", "version"),
    ("ci.yml", "sandbox", "python-version"),
    ("ci.yml", "sandbox", "node-version"),
    ("ci.yml", "sandbox", "go-version"),
    ("ci-long.yml", "*", "version"),
    ("release.yml", "*", "version"),
    ("security.yml", "*", "version"),
}
"""Inputs known to exist today, so a rename that hides them fails instead of passing empty."""


def workflows() -> list[Path]:
    found = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    assert found
    return found


def jobs(path: Path) -> dict[str, Any]:
    data = load_yaml(path.read_text(encoding="utf-8"), source=path.name)
    assert isinstance(data, dict)
    found = data.get("jobs")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    assert isinstance(found, dict)
    return found  # pyright: ignore[reportUnknownVariableType]


def steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    found = job.get("steps", [])
    assert isinstance(found, list)
    return [step for step in found if isinstance(step, dict)]  # pyright: ignore[reportUnknownVariableType]


def with_inputs(step: dict[str, Any]) -> dict[str, Any]:
    found = step.get("with") or {}
    assert isinstance(found, dict)
    return found  # pyright: ignore[reportUnknownVariableType]


def pinned_inputs(step: dict[str, Any]) -> list[str]:
    """The version inputs this step sets that must be exact."""
    keys = [key for key in VERSION_INPUTS if key in with_inputs(step)]
    if str(step.get("uses", "")).startswith(SETUP_UV) and "version" in with_inputs(step):
        keys.append("version")
    return keys


def loose(value: object, job: dict[str, Any]) -> str | None:
    """Why `value` is not an exact pin, or None when it is."""
    if not isinstance(value, str):
        return f"{value!r} is not a quoted string"
    if EXACT.fullmatch(value):
        return None
    ref = MATRIX_REF.fullmatch(value.strip())
    if ref is None:
        return f"{value!r} is not an exact version"
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    values = matrix.get(ref.group(1)) if isinstance(matrix, dict) else None
    if not isinstance(values, list) or not values:
        return f"{value!r} names no list in the job's matrix"
    bad = [v for v in values if not (isinstance(v, str) and EXACT_MATRIX.fullmatch(v))]  # pyright: ignore[reportUnknownVariableType]
    return f"{value!r} takes loose matrix values {bad!r}" if bad else None


def test_the_scan_sees_every_known_toolchain_input() -> None:
    seen: set[tuple[str, str, str]] = set()
    for path in workflows():
        for name, job in jobs(path).items():
            for step in steps(job):
                for key in pinned_inputs(step):
                    seen.add((path.name, name, key))
                    seen.add((path.name, "*", key))
    assert EXPECTED <= seen, sorted(EXPECTED - seen)


@pytest.mark.parametrize("path", workflows(), ids=lambda p: p.name)
def test_every_toolchain_version_is_exact(path: Path) -> None:
    problems: list[str] = []
    for name, job in jobs(path).items():
        for step in steps(job):
            for key in pinned_inputs(step):
                why = loose(with_inputs(step)[key], job)
                if why is not None:
                    problems.append(f"{name} / {step.get('name', step.get('uses'))}: {key} {why}")
    assert not problems, problems


@pytest.mark.parametrize("path", workflows(), ids=lambda p: p.name)
def test_no_step_checks_for_the_latest_release(path: Path) -> None:
    problems = [
        f"{name} / {step.get('name', step.get('uses'))}"
        for name, job in jobs(path).items()
        for step in steps(job)
        if with_inputs(step).get("check-latest") not in (None, False, "false")
    ]
    assert not problems, problems


@pytest.mark.parametrize("path", workflows(), ids=lambda p: p.name)
def test_no_step_reads_its_version_from_a_file(path: Path) -> None:
    problems = [
        f"{name} / {step.get('name', step.get('uses'))}: {key}"
        for name, job in jobs(path).items()
        for step in steps(job)
        for key in VERSION_FILE_INPUTS
        if key in with_inputs(step)
    ]
    assert not problems, problems


@pytest.mark.parametrize(
    ("value", "exact"),
    [
        ("1.26.11", True),
        ("22.15.0", True),
        ("3.13", True),
        ("1.26.x", False),
        ("1.26.*", False),
        ("^1.26", False),
        ("~1.26.0", False),
        ("latest", False),
        ("stable", False),
        ("1.26", True),
        ("1", False),
        ("1.26.11 ", False),
        ("${{ inputs.go }}", False),
        (1.26, False),
    ],
)
def test_the_exact_check_itself(value: object, exact: bool) -> None:
    assert (loose(value, {}) is None) is exact


def test_a_matrix_value_must_be_exact() -> None:
    job = {"strategy": {"matrix": {"py": ["3.13", "3.14.x"], "go": ["1.26.11"]}}}
    assert loose("${{ matrix.go }}", job) is None
    assert loose("${{ matrix.py }}", job) is not None
    assert loose("${{ matrix.missing }}", job) is not None
    assert loose("${{ matrix.go }}", {}) is not None
