"""The v0.4 decisions, session 5, item 6: every CI toolchain is pinned to an exact version.

`go-version: "1.26.x"` let each CI run take a new Go patch release on the day it shipped,
unreviewed, while uv and Node were pinned exactly. Dependabot does not update these inputs,
so a pin is raised by hand and reviewed like any other change.

The workflows (and any local composite action) are read with aipm's safe YAML loader and
checked as written; nothing here runs on GitHub. Go, Node and uv need all three parts
(`1.26.11`, `22.15.0`, `0.13.6`): their setup actions read `1.26` as a range and take the newest
patch, the same as `1.26.x`. Python may be `x.y` or `x.y.z`, as a literal or in a matrix, the
form the workflows use today; every `python-version` goes through setup-uv, whose pinned
release fixes the managed build it downloads. A `${{ matrix.<key> }}` value is resolved in the
job's own matrix, `include` entries too. Any other expression, a missing version, a
`*version-file` input, `check-latest`, or a toolchain setup action this file does not know fails.
"""

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from aipm.state.yamlio import load_yaml
from tests.conftest import REPO_ROOT

WORKFLOWS = REPO_ROOT / ".github" / "workflows"
LOCAL_ACTIONS = REPO_ROOT / ".github" / "actions"

THREE_PARTS = re.compile(r"\d+\.\d+\.\d+")
"""Go, Node and uv: `x.y.z`, so no `x`, `*`, `^`, `~`, `latest`, `stable` or two-part range."""

PYTHON = re.compile(r"\d+\.\d+(?:\.\d+)?")
"""Python: exact `x.y` or `x.y.z`."""

FORMS = {"go-version": THREE_PARTS, "node-version": THREE_PARTS, "python-version": PYTHON}
"""Toolchain inputs checked on every step, whatever action it uses."""

UV_VERSION = THREE_PARTS
"""setup-uv's `version` is uv's own version; other actions' `version` means other things."""

SETUP_ACTIONS = {
    "astral-sh/setup-uv": "version",
    "actions/setup-go": "go-version",
    "actions/setup-node": "node-version",
    "actions/setup-python": "python-version",
}
"""Toolchain setup actions this file knows, and the version input each one must set."""

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


def sources() -> list[Path]:
    found = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    found += sorted(LOCAL_ACTIONS.glob("**/action.yml")) + sorted(
        LOCAL_ACTIONS.glob("**/action.yaml")
    )
    assert found
    return found


def label(path: Path) -> str:
    return path.relative_to(REPO_ROOT / ".github").as_posix().removeprefix("workflows/")


def as_dict(value: object) -> dict[str, Any]:
    assert isinstance(value, dict), value
    return value  # pyright: ignore[reportUnknownVariableType]


def jobs(path: Path) -> Iterator[tuple[str, dict[str, Any], list[dict[str, Any]]]]:
    """Each job (or a composite action's `runs`) with its steps."""
    data = as_dict(load_yaml(path.read_text(encoding="utf-8"), source=path.name))
    if "jobs" in data:
        found = [(str(k), as_dict(v)) for k, v in as_dict(data["jobs"]).items()]
    else:
        found = [("runs", as_dict(data.get("runs")))]
    for name, job in found:
        raw = job.get("steps", [])
        assert isinstance(raw, list), (name, raw)
        yield name, job, [as_dict(step) for step in raw]  # pyright: ignore[reportUnknownVariableType]


def with_inputs(step: dict[str, Any]) -> dict[str, Any]:
    return as_dict(step.get("with") or {})


def action(step: dict[str, Any]) -> str:
    """`owner/repo` of a `uses:` step, lower-cased (GitHub matches names without case)."""
    uses = str(step.get("uses", "")).lower()
    return "/".join(uses.split("@", 1)[0].split("/")[:2])


def toolchain_like(name: str) -> bool:
    repo = name.rsplit("/", maxsplit=1)[-1]
    return repo.startswith("setup-") or "toolchain" in repo or repo == "action-setup"


def pinned_inputs(step: dict[str, Any]) -> dict[str, re.Pattern[str]]:
    """The version inputs this step sets, each with the form it must have."""
    keys = {key: form for key, form in FORMS.items() if key in with_inputs(step)}
    if action(step) == "astral-sh/setup-uv" and "version" in with_inputs(step):
        keys["version"] = UV_VERSION
    return keys


def matrix_values(job: dict[str, Any], key: str) -> list[object] | str:
    """Every value `matrix.<key>` takes, `include` entries too, or why they cannot be read."""
    matrix = (job.get("strategy") or {}).get("matrix")
    if not isinstance(matrix, dict):
        return "the job's matrix is not a mapping"
    values: list[object] = []
    if key in matrix:
        if not isinstance(matrix[key], list):
            return f"matrix.{key} is not a list"
        values += matrix[key]
    include = matrix.get("include", [])
    if not isinstance(include, list):
        return "matrix.include is not a list"
    for entry in include:  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(entry, dict):
            return "a matrix.include entry is not a mapping"
        if key in entry:
            values.append(entry[key])  # pyright: ignore[reportUnknownArgumentType]
    return values or f"matrix.{key} has no values"


def loose(value: object, job: dict[str, Any], form: re.Pattern[str] = THREE_PARTS) -> str | None:
    """Why `value` is not an exact pin of `form`, or None when it is."""
    if not isinstance(value, str):
        return f"{value!r} is not a quoted string"
    if form.fullmatch(value):
        return None
    ref = MATRIX_REF.fullmatch(value.strip())
    if ref is None:
        return f"{value!r} is not an exact version"
    values = matrix_values(job, ref.group(1))
    if isinstance(values, str):
        return f"{value!r}: {values}"
    bad = [v for v in values if not (isinstance(v, str) and form.fullmatch(v))]
    return f"{value!r} takes loose matrix values {bad!r}" if bad else None


def where(name: str, step: dict[str, Any]) -> str:
    return f"{name} / {step.get('name', step.get('uses'))}"


def test_the_scan_sees_every_known_toolchain_input() -> None:
    seen: set[tuple[str, str, str]] = set()
    for path in sources():
        for name, _job, steps in jobs(path):
            for step in steps:
                for key in pinned_inputs(step):
                    seen |= {(label(path), name, key), (label(path), "*", key)}
    assert EXPECTED <= seen, sorted(EXPECTED - seen)


@pytest.mark.parametrize("path", sources(), ids=label)
def test_every_toolchain_version_is_exact(path: Path) -> None:
    problems = [
        f"{where(name, step)}: {key} {why}"
        for name, job, steps in jobs(path)
        for step in steps
        for key, form in pinned_inputs(step).items()
        if (why := loose(with_inputs(step)[key], job, form)) is not None
    ]
    assert not problems, problems


@pytest.mark.parametrize("path", sources(), ids=label)
def test_every_toolchain_setup_step_names_its_version(path: Path) -> None:
    problems: list[str] = []
    for name, _job, steps in jobs(path):
        for step in steps:
            used = action(step)
            if used in SETUP_ACTIONS:
                if SETUP_ACTIONS[used] not in with_inputs(step):
                    problems.append(f"{where(name, step)}: no {SETUP_ACTIONS[used]}")
            elif used and toolchain_like(used):
                problems.append(
                    f"{where(name, step)}: {used} is not a toolchain action this test knows"
                )
    assert not problems, problems


@pytest.mark.parametrize("path", sources(), ids=label)
def test_no_step_checks_for_the_latest_release(path: Path) -> None:
    problems = [
        where(name, step)
        for name, _job, steps in jobs(path)
        for step in steps
        if with_inputs(step).get("check-latest") not in (None, False, "false")
    ]
    assert not problems, problems


@pytest.mark.parametrize("path", sources(), ids=label)
def test_no_step_reads_its_version_from_a_file(path: Path) -> None:
    problems = [
        f"{where(name, step)}: {key}"
        for name, _job, steps in jobs(path)
        for step in steps
        for key in with_inputs(step)
        if str(key).endswith("version-file")
    ]
    assert not problems, problems


@pytest.mark.parametrize(
    ("value", "form", "exact"),
    [
        ("1.26.11", THREE_PARTS, True),
        ("22.15.0", THREE_PARTS, True),
        ("0.13.6", THREE_PARTS, True),
        ("1.26", THREE_PARTS, False),
        ("22.15", THREE_PARTS, False),
        ("0.13", THREE_PARTS, False),
        ("1.26.x", THREE_PARTS, False),
        ("1.26.*", THREE_PARTS, False),
        ("^1.26", THREE_PARTS, False),
        ("~1.26.0", THREE_PARTS, False),
        ("latest", THREE_PARTS, False),
        ("stable", THREE_PARTS, False),
        ("1.26.11 ", THREE_PARTS, False),
        ("1.26.11.1", THREE_PARTS, False),
        ("${{ inputs.go }}", THREE_PARTS, False),
        (1.26, THREE_PARTS, False),
        ("3.13", PYTHON, True),
        ("3.13.5", PYTHON, True),
        ("3", PYTHON, False),
        ("3.x", PYTHON, False),
        ("3.13t", PYTHON, False),
    ],
)
def test_the_exact_check_itself(value: object, form: re.Pattern[str], exact: bool) -> None:
    assert (loose(value, {}, form) is None) is exact


def test_a_matrix_value_must_be_exact() -> None:
    job: dict[str, Any] = {
        "strategy": {
            "matrix": {
                "py": ["3.13", "3.14.x"],
                "go": ["1.26.11"],
                "include": [{"go": "1.25.9"}, {"node": "22.x"}, {"other": 1}],
            }
        }
    }
    assert loose("${{ matrix.go }}", job) is None
    assert loose("${{ matrix.py }}", job, PYTHON) is not None
    assert loose("${{ matrix.node }}", job) is not None
    assert loose("${{ matrix.missing }}", job) is not None
    assert loose("${{ matrix.go }}", {}) is not None
    assert loose("${{ matrix.go }}", {"strategy": {"matrix": "${{ fromJSON(x) }}"}}) is not None
    assert loose("${{ matrix.go }}", {"strategy": {"matrix": {"go": "1.26.11"}}}) is not None
    assert loose("${{ matrix.go }}", {"strategy": {"matrix": {"include": "x"}}}) is not None
    assert loose("${{ matrix.go }}", {"strategy": {"matrix": {"include": ["x"]}}}) is not None


def test_toolchain_actions_are_recognised_without_case() -> None:
    assert action({"uses": "Astral-SH/Setup-UV@68559e99"}) == "astral-sh/setup-uv"
    assert action({"uses": "actions/setup-go@b7ad1dad"}) == "actions/setup-go"
    assert action({"uses": "github/codeql-action/upload-sarif@abc"}) == "github/codeql-action"
    assert pinned_inputs({"uses": "ASTRAL-SH/setup-uv@x", "with": {"version": "0.13"}}) == {
        "version": UV_VERSION
    }
    for unknown in ("actions/setup-java", "dtolnay/rust-toolchain", "pnpm/action-setup"):
        assert toolchain_like(unknown)
    for known in ("actions/checkout", "gitleaks/gitleaks-action", "ossf/scorecard-action"):
        assert not toolchain_like(known)
