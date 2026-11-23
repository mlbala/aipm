"""The v0.4 decisions, session 5, item 7: CI runs shellcheck on every shell script.

Users pipe `install.sh` into `sh`, and the `pre-push` and `commit-msg` hooks enforce the
authorship rules, so a quoting bug in any of them is a security bug. `security.yml`'s
`shellcheck` job checks every shell script the repository holds, named one by one; a script
added without being named there fails this test.

The workflow is read with aipm's safe YAML loader and checked as written; nothing here runs on
GitHub. A shell script is a file git tracks (or would track) whose name ends in `.sh` or whose
first line is a `sh`, `bash` or `dash` shebang.
"""

import re
import shlex
from pathlib import Path
from typing import Any

from aipm.state.yamlio import load_yaml
from tests.conftest import REPO_ROOT, run_git

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yml"

SHEBANG = re.compile(rb"#!\s*(?:/usr/bin/env\s+(?:-S\s+)?)?(?:\S*/)?(?:sh|bash|dash)(?:\s|$)")

KNOWN = {
    "install.sh",
    ".githooks/pre-push",
    ".githooks/commit-msg",
    "tests/fakes/bin/gitleaks",
    "tests/fakes/bin/osv-scanner",
    "tests/fakes/bin/semgrep",
    "tests/fakes/bin/srt",
    "tests/fakes/bin/trivy",
}
"""The shell scripts known when the job was added, so a detector that finds nothing fails."""

FULL_SHA = re.compile(r"[0-9a-f]{40}")


def as_dict(value: object) -> dict[str, Any]:
    assert isinstance(value, dict), value
    return value  # pyright: ignore[reportUnknownVariableType]


def is_shell_script(path: Path) -> bool:
    if path.name.endswith(".sh"):
        return True
    with path.open("rb") as handle:
        first = handle.readline(256)
    return SHEBANG.match(first) is not None


def shell_scripts() -> set[str]:
    """Every tracked file, plus untracked files that are not ignored, that is a shell script."""
    out = run_git(REPO_ROOT, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    names = {name for name in out.split("\0") if name}
    return {
        name
        for name in names
        if (REPO_ROOT / name).is_file()
        and not (REPO_ROOT / name).is_symlink()
        and is_shell_script(REPO_ROOT / name)
    }


def job() -> dict[str, Any]:
    data = as_dict(load_yaml(WORKFLOW.read_text(encoding="utf-8"), source=WORKFLOW.name))
    jobs = as_dict(data["jobs"])
    assert "shellcheck" in jobs, sorted(jobs)
    return as_dict(jobs["shellcheck"])


def steps() -> list[dict[str, Any]]:
    raw = job().get("steps")
    assert isinstance(raw, list) and raw, raw
    return [as_dict(step) for step in raw]  # pyright: ignore[reportUnknownVariableType]


def runs() -> list[str]:
    return [str(step["run"]) for step in steps() if "run" in step]


def scan_argv() -> list[str]:
    """The argv of the one step that runs shellcheck on the scripts."""
    found = [
        shlex.split(run)
        for run in runs()
        if run.lstrip().startswith("shellcheck") and "--version" not in run
    ]
    assert len(found) == 1, runs()
    return found[0]


def checkout_shas(data: dict[str, Any]) -> set[str]:
    shas: set[str] = set()
    for name, other in as_dict(data["jobs"]).items():
        if name == "shellcheck":
            continue
        for step in as_dict(other).get("steps", []):
            uses = str(as_dict(step).get("uses", ""))
            if uses.startswith("actions/checkout@"):
                shas.add(uses.split("@", 1)[1])
    return shas


def test_the_detector_finds_the_known_scripts() -> None:
    assert KNOWN <= shell_scripts()


def test_the_detector_reads_shebangs() -> None:
    for line in (b"#!/bin/sh\n", b"#!/bin/bash -e\n", b"#!/usr/bin/env bash\n", b"#! /bin/dash"):
        assert SHEBANG.match(line), line
    for line in (b"#!/usr/bin/env python3\n", b"#!/bin/shx\n", b"# /bin/sh\n", b"sh\n"):
        assert not SHEBANG.match(line), line


def test_the_job_is_named_and_runs_on_ubuntu() -> None:
    assert job().get("name") == "Shell scripts (shellcheck)"
    assert job().get("runs-on") == "ubuntu-latest"


def test_the_job_reads_contents_only() -> None:
    assert job().get("permissions") == {"contents": "read"}


def test_the_checkout_is_pinned_and_keeps_no_credentials() -> None:
    data = as_dict(load_yaml(WORKFLOW.read_text(encoding="utf-8"), source=WORKFLOW.name))
    checkouts = [step for step in steps() if str(step.get("uses", "")).startswith("actions/")]
    assert len(checkouts) == 1, checkouts
    uses = str(checkouts[0]["uses"])
    assert uses.startswith("actions/checkout@"), uses
    sha = uses.split("@", 1)[1]
    assert FULL_SHA.fullmatch(sha), uses
    assert checkout_shas(data) == {sha}, "the same pinned checkout as the other jobs"
    assert as_dict(checkouts[0].get("with"))["persist-credentials"] is False


def test_only_the_pinned_checkout_is_used() -> None:
    uses = [str(step["uses"]) for step in steps() if "uses" in step]
    assert len(uses) == 1, uses


def test_the_job_prints_the_version_and_fails_without_shellcheck() -> None:
    text = "\n".join(runs())
    assert "shellcheck --version" in text
    assert "command -v shellcheck" in text
    for fetch in ("curl", "wget", "http://", "https://"):
        assert fetch not in text, f"no binary is downloaded ({fetch})"


def test_the_job_cannot_pass_by_skipping() -> None:
    assert "continue-on-error" not in job()
    assert "if" not in job()
    for step in steps():
        assert "continue-on-error" not in step, step
        assert "if" not in step, step


def test_the_scan_uses_posix_sh_and_style_severity() -> None:
    argv = scan_argv()
    assert argv[0] == "shellcheck"
    assert "--shell=sh" in argv
    assert "--severity=style" in argv
    options = [arg for arg in argv[1:] if arg.startswith("-")]
    assert sorted(options) == ["--severity=style", "--shell=sh"], options


def test_the_scan_names_exactly_the_shell_scripts() -> None:
    files = [arg for arg in scan_argv()[1:] if not arg.startswith("-")]
    assert len(files) == len(set(files)), files
    for name in files:
        assert not set(name) & set("*?[]{}$"), f"named, not globbed: {name}"
    assert set(files) == shell_scripts()
