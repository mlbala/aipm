"""The v0.4 decisions, session 5, item 7: CI runs shellcheck on every shell script.

Users pipe `install.sh` into `sh`, and the `pre-push` and `commit-msg` hooks enforce the
authorship rules, so a quoting bug in any of them is a security bug. `security.yml`'s
`shellcheck` job checks every shell script the repository holds, named one by one; a script
added without being named there fails this test.

The workflow is read with aipm's safe YAML loader and checked as written; nothing here runs on
GitHub. A shell script is a file git tracks (or would track) whose name ends in a shell suffix
or whose shebang starts a shell. A shebang naming an interpreter this test does not know fails,
so a shell spelled another way is never missed. The job may hold only the keys and steps it
needs, so a later `shell:`, `env:`, `.shellcheckrc` or PATH change cannot make it check nothing.
"""

import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any

from aipm.state.yamlio import load_yaml
from tests.conftest import REPO_ROOT, run_git

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yml"

SHELLS = {"sh", "bash", "dash", "ksh", "mksh", "ash", "busybox"}
"""Interpreters that make a file a shell script (shellcheck reads it as POSIX sh here)."""

OTHER_INTERPRETERS = {"python3"}
"""Interpreters known not to be shells; any other shebang fails until this test knows it."""

SUFFIXES = (".sh", ".bash", ".ksh", ".dash", ".bats")

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

JOB_KEYS = {"name", "runs-on", "permissions", "steps"}
STEP_KEYS = {"name", "uses", "with", "run"}
SCAN_OPTIONS = ["--norc", "--severity=style", "--shell=sh"]

FULL_SHA = re.compile(r"[0-9a-f]{40}")
DIRECTIVE = re.compile(r"#\s*shellcheck\s+(.*)")
DISABLE = re.compile(r"disable=(SC\d{4}(?:,SC\d{4})*)\s+#\s*\S")
"""`# shellcheck disable=SCxxxx # reason`: named checks only, each with a reason."""


def as_dict(value: object) -> dict[str, Any]:
    assert isinstance(value, dict), value
    return value  # pyright: ignore[reportUnknownVariableType]


def interpreter(line: bytes) -> str | None:
    """The interpreter a `#!` line starts, as a bare name, or None without a shebang.

    `env` is looked through, skipping its options; an `env` option that takes a value
    (`-u NAME`) leaves NAME, which is an unknown interpreter and so fails closed.
    """
    if not line.startswith(b"#!"):
        return None
    words = line[2:].decode("utf-8", errors="replace").split()
    if not words:
        return ""
    name = PurePosixPath(words[0]).name
    if name == "env":
        rest = [word for word in words[1:] if not word.startswith("-")]
        name = PurePosixPath(rest[0]).name if rest else ""
    return name


def first_line(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.readline(256)


def repository_files() -> list[str]:
    """Every tracked file, plus untracked files that are not ignored."""
    out = run_git(REPO_ROOT, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return sorted({name for name in out.split("\0") if name and (REPO_ROOT / name).is_file()})


def shell_scripts() -> set[str]:
    return {
        name
        for name in repository_files()
        if name.endswith(SUFFIXES) or interpreter(first_line(REPO_ROOT / name)) in SHELLS
    }


def workflow() -> dict[str, Any]:
    return as_dict(load_yaml(WORKFLOW.read_text(encoding="utf-8"), source=WORKFLOW.name))


def job() -> dict[str, Any]:
    jobs = as_dict(workflow()["jobs"])
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


def checkout_shas() -> set[str]:
    shas: set[str] = set()
    for name, other in as_dict(workflow()["jobs"]).items():
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
    shells = [
        b"#!/bin/sh\n",
        b"#!/bin/bash -e\n",
        b"#!/usr/bin/env bash\n",
        b"#! /bin/dash",
        b"#!/usr/bin/env -S -i bash\n",
        b"#!/bin/env sh\n",
        b"#!/usr/local/bin/env ksh\n",
        b"#!/bin/busybox sh\n",
    ]
    for line in shells:
        assert interpreter(line) in SHELLS, line
    assert interpreter(b"#!/usr/bin/env python3\n") == "python3"
    assert interpreter(b"#!/usr/bin/env -u X sh\n") not in SHELLS | OTHER_INTERPRETERS
    for line in (b"#!/bin/shx\n", b"#!\n", b"#!/usr/bin/env\n"):
        assert interpreter(line) not in SHELLS | OTHER_INTERPRETERS, line
    for line in (b"# /bin/sh\n", b"sh\n", b""):
        assert interpreter(line) is None, line


def test_every_shebang_names_a_known_interpreter() -> None:
    unknown = {
        name: found
        for name in repository_files()
        if (found := interpreter(first_line(REPO_ROOT / name))) is not None
        and found not in SHELLS | OTHER_INTERPRETERS
    }
    assert unknown == {}, "a shell script spelled another way, or a new interpreter"


def test_no_shell_script_is_a_symlink() -> None:
    links = [name for name in shell_scripts() if (REPO_ROOT / name).is_symlink()]
    assert links == [], "shellcheck the target, not a link to it"


def test_no_shellcheckrc_changes_what_is_checked() -> None:
    rc = [name for name in repository_files() if PurePosixPath(name).name == ".shellcheckrc"]
    assert rc == []


def test_every_directive_disables_named_checks_with_a_reason() -> None:
    problems: list[str] = []
    for name in sorted(shell_scripts()):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            directive = DIRECTIVE.search(line)
            if directive and not DISABLE.match(directive.group(1)):
                problems.append(f"{name}:{number}: {line.strip()}")
    assert problems == [], problems


def test_the_job_is_named_and_runs_on_ubuntu() -> None:
    assert job().get("name") == "Shell scripts (shellcheck)"
    assert job().get("runs-on") == "ubuntu-latest"


def test_the_job_reads_contents_only() -> None:
    assert job().get("permissions") == {"contents": "read"}


def test_the_job_holds_only_what_it_needs() -> None:
    assert set(job()) <= JOB_KEYS, sorted(set(job()) - JOB_KEYS)
    for step in steps():
        assert set(step) <= STEP_KEYS, (step.get("name"), sorted(set(step) - STEP_KEYS))
    assert "defaults" not in workflow()
    assert "env" not in workflow()


def test_the_checkout_is_pinned_and_keeps_no_credentials() -> None:
    uses = [str(step["uses"]) for step in steps() if "uses" in step]
    assert len(uses) == 1, uses
    assert uses[0].startswith("actions/checkout@"), uses
    sha = uses[0].split("@", 1)[1]
    assert FULL_SHA.fullmatch(sha), uses
    assert checkout_shas() == {sha}, "the same pinned checkout as the other jobs"
    checkout = next(step for step in steps() if "uses" in step)
    assert as_dict(checkout.get("with")) == {"persist-credentials": False}


def test_the_job_prints_the_version_and_fails_without_shellcheck() -> None:
    text = "\n".join(runs())
    assert "shellcheck --version" in text
    assert "command -v shellcheck" in text
    banned = ("curl", "wget", "://", "GITHUB_PATH", "GITHUB_ENV", "PATH=", "ln ", "alias")
    banned += ("add-apt-repository", "sources.list", "SHELLCHECK_OPTS", "dpkg -i", ".deb")
    for word in banned:
        assert word not in text, f"the job must not use {word!r}"


def test_the_job_cannot_pass_by_skipping() -> None:
    assert "continue-on-error" not in job()
    assert "if" not in job()
    for step in steps():
        assert "continue-on-error" not in step, step
        assert "if" not in step, step


def test_the_scan_uses_posix_sh_style_severity_and_no_rc_file() -> None:
    argv = scan_argv()
    assert argv[0] == "shellcheck"
    options = sorted(arg for arg in argv[1:] if arg.startswith("-"))
    assert options == SCAN_OPTIONS, options


def test_the_scan_names_exactly_the_shell_scripts() -> None:
    files = [arg for arg in scan_argv()[1:] if not arg.startswith("-")]
    assert len(files) == len(set(files)), files
    for name in files:
        assert not set(name) & set("*?[]{}$"), f"named, not globbed: {name}"
    assert set(files) == shell_scripts()
