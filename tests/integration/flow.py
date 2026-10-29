"""Shared steps for the design and plan tests: a repository taken through the clinic flow.

The caller routes the gateway to FakeLLM first (`fake_llm("clinic")`, or `use_responses`).
"""

import copy
import json
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from click.testing import Result
from ruamel.yaml import YAML
from typer.testing import CliRunner

from aipm.cli.main import app
from aipm.domain.models import (
    ApprovalsDoc,
    ArchitectureDoc,
    ArtifactKind,
    RoleName,
    TasksDoc,
    ThreatModelDoc,
)
from aipm.llm.fake import FakeLLM
from aipm.state.store import open_store
from tests.conftest import LLM_FIXTURES, REPO_ROOT

runner = CliRunner()


def aipm(repo: Path, *args: str, flags: Sequence[str] = (), input: str | None = None) -> Result:
    """Run aipm against `repo`; non-interactive unless `input` is given."""
    mode = [] if input is not None else ["--non-interactive"]
    return runner.invoke(app, [*mode, *flags, "-C", str(repo), *args], input=input)


def ok(result: Result) -> Result:
    assert result.exit_code == 0, result.output
    return result


def discovered(repo: Path) -> None:
    """`init`, then `discover` from the clinic idea with the clinic answers, G1 approved."""
    ok(runner.invoke(app, ["-C", str(repo), "init"]))
    shutil.copy(REPO_ROOT / "examples/clinic-booking/idea.md", repo / "idea.md")
    shutil.copy(REPO_ROOT / "tests/fakes/answers/clinic.yaml", repo / "answers.yaml")
    ok(aipm(repo, "discover", "--from", str(repo / "idea.md"), "--answers",
            str(repo / "answers.yaml"), flags=["--yes"]))  # fmt: skip


def designed(repo: Path) -> None:
    """Discovered, then `design --yes` (G2 recorded, the greenfield stack copied)."""
    discovered(repo)
    ok(aipm(repo, "design", flags=["--yes"]))


def reply(role: str, index: int = 0) -> dict[str, Any]:
    """A deep copy of one clinic fixture reply."""
    text = (LLM_FIXTURES / "clinic" / f"{role}.yaml").read_text(encoding="utf-8")
    return copy.deepcopy(YAML(typ="safe", pure=True).load(text)["responses"][index]["json"])


def use_responses(
    monkeypatch: pytest.MonkeyPatch, responses: Mapping[RoleName, Sequence[Mapping[str, Any]]]
) -> FakeLLM:
    """Route every gateway built from now on to inline responses."""
    fake = FakeLLM.from_responses(responses)
    monkeypatch.setattr("aipm.llm.gateway.make_provider", lambda llm, **_: fake)
    return fake


def pm_files(repo: Path) -> dict[str, bytes]:
    """Every file under `.pm/` except the lock and the events, by relative path."""
    pm = repo / ".pm"
    skip = {".lock", "events.jsonl"}
    return {str(p.relative_to(pm)): p.read_bytes() for p in pm.rglob("*")
            if p.is_file() and p.name not in skip}  # fmt: skip


def load[T](repo: Path, kind: ArtifactKind, model: type[T]) -> T:
    doc = open_store(repo).load(kind)
    assert isinstance(doc, model)
    return doc


def tasks(repo: Path) -> TasksDoc:
    return load(repo, ArtifactKind.TASKS, TasksDoc)


def approvals(repo: Path) -> ApprovalsDoc:
    return load(repo, ArtifactKind.APPROVALS, ApprovalsDoc)


def architecture(repo: Path) -> ArchitectureDoc:
    return load(repo, ArtifactKind.ARCHITECTURE, ArchitectureDoc)


def threat_model(repo: Path) -> ThreatModelDoc:
    return load(repo, ArtifactKind.THREAT_MODEL, ThreatModelDoc)


def trust(repo: Path) -> str:
    """Trust the repository's current execution surface, as the user would; returns the hash."""
    shown = json.loads(ok(aipm(repo, "trust", "--show", flags=["--json"])).stdout)
    surface = str(shown["data"]["surface_hash"])
    ok(aipm(repo, "trust", "--confirm", surface[:12]))
    return surface


def planned(repo: Path, *, trusted: bool = True) -> None:
    """Designed, then `plan --yes` (G3 recorded), then trusted unless `trusted=False`."""
    designed(repo)
    ok(aipm(repo, "plan", flags=["--yes"]))
    if trusted:
        trust(repo)
