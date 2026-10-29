"""The §6.3 schemas: extra keys forbidden, bounded strings and lists, ID formats, invariants."""

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from aipm.domain.ids import ID_PATTERNS, is_valid_id
from aipm.domain.models import (
    Approval,
    ApprovalsDoc,
    ArchitectureFrontMatter,
    BuiltinGate,
    DependencyAdd,
    GateDef,
    JournalEvent,
    PrepareDef,
    RepoMapFrontMatter,
    RequirementsDoc,
    SecurityEvent,
    Source,
    Task,
    ThreatModelFrontMatter,
)
from tests.fakes.secrets import FAKE_SECRETS

SHA = "b" * 64
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def task(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "T-007",
        "title": "OTP verification endpoint",
        "type": "feature",
        "size": "M",
        "acceptance": [{"id": "AC-T007-1", "text": "Wrong OTP returns 401"}],
    }
    data.update(overrides)
    return data


# ---------------------------------------------------------------- IDs


@pytest.mark.parametrize(
    ("kind", "good", "bad"),
    [
        ("feature", "F-001", "F-1"),
        ("component", "C-01", "C-001"),
        ("threat", "TM-03", "TM-3"),
        ("task", "T-007", "T-07"),
        ("acceptance", "AC-T007-1", "AC-007-1"),
        ("question", "Q-019", "Q-19"),
        ("assumption", "A-002", "A-2"),
        ("adr", "ADR-0001", "ADR-001"),
        ("event", "EV-0123456789ab", "EV-0123456789AB"),
        ("run", "r-20261028-1102-ab12", "r-2026-1102-ab12"),
    ],
)
def test_id_formats(kind: str, good: str, bad: str) -> None:
    assert is_valid_id(kind, good)
    assert not is_valid_id(kind, bad)
    assert not is_valid_id(kind, f" {good}\n")


def test_unknown_id_kind() -> None:
    assert "task" in ID_PATTERNS
    with pytest.raises(ValueError, match="unknown"):
        is_valid_id("nope", "x")


# ---------------------------------------------------------------- strictness


def test_extra_keys_are_forbidden_and_inputs_are_not_echoed() -> None:
    secret = FAKE_SECRETS["ANTHROPIC_API_KEY"]
    with pytest.raises(ValidationError) as info:
        Task.model_validate(task(extra=secret, title=secret * 10))
    text = str(info.value)
    assert "extra_forbidden" in text or "Extra inputs" in text
    assert secret not in text


@pytest.mark.parametrize(
    "overrides",
    [
        {"id": "T-7"},
        {"title": ""},
        {"title": "x" * 121},
        {"description": "x" * 4001},
        {"type": "chore"},
        {"size": "XL"},
        {"acceptance": []},
        {"acceptance": [{"id": f"AC-T007-{i}", "text": "x"} for i in range(11)]},
        {"acceptance": [{"id": "AC-T008-1", "text": "belongs elsewhere"}]},
        {"acceptance": [{"id": "AC-T007-1", "text": "a"}, {"id": "AC-T007-1", "text": "b"}]},
        {"owns_files": [f"src/m{i}.py" for i in range(41)]},
        {"owns_files": ["../outside.py"]},
        {"owns_files": [".github/workflows/ci.yml"]},
        {"reads_files": ["/etc/passwd"]},
        {"depends_on": ["T-007"]},
        {"gates": ["Lint"]},
        {"traces": ["X-001"]},
        {"status": "blocked"},
        {"blocked": {"reason": "manual"}},
        {"status": "done"},
        {"attempts": 101},
        {"base_sha": "abc"},
    ],
)
def test_task_rejects(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Task.model_validate(task(**overrides))


def test_task_accepts_and_normalizes() -> None:
    parsed = Task.model_validate(
        task(
            title="  padded  ",
            owns_files=["./src//app/otp.py", "tests/auth/**"],
            traces=["F-001", "TM-03", "NFR-01"],
            status="done",
            done={"commit": "c" * 40, "at": NOW},
        )
    )
    assert parsed.title == "padded"
    assert parsed.owns_files == ["src/app/otp.py", "tests/auth/**"]


@pytest.mark.parametrize(
    ("ecosystem", "name", "ok"),
    [
        ("pypi", "slowapi", True),
        ("pypi", "zope.interface", True),
        ("pypi", "-bad", False),
        ("npm", "@scope/pkg", True),
        ("npm", "Express", False),
        ("npm", "../evil", False),
        ("cargo", "serde", False),
    ],
)
def test_dependency_names(ecosystem: str, name: str, ok: bool) -> None:
    if ok:
        DependencyAdd.model_validate({"ecosystem": ecosystem, "name": name})
    else:
        with pytest.raises(ValidationError):
            DependencyAdd.model_validate({"ecosystem": ecosystem, "name": name})


# ---------------------------------------------------------------- other artifacts


def test_requirements_rules() -> None:
    base: dict[str, Any] = {"project": {"name": "clinic-booking"}, "mode": "greenfield"}
    RequirementsDoc.model_validate(base)
    with pytest.raises(ValidationError):
        RequirementsDoc.model_validate({**base, "project": {"name": "Clinic Booking"}})
    question = {"id": "Q-001", "dimension": "data", "question": "q"}
    answer = {**question, "answer": "a", "source": "user"}
    with pytest.raises(ValidationError, match="duplicate question"):
        RequirementsDoc.model_validate({**base, "answers": [answer], "open_questions": [question]})
    assumption = {"id": "A-001", "dimension": "data", "statement": "s"}
    with pytest.raises(ValidationError, match="duplicate assumption"):
        RequirementsDoc.model_validate({**base, "assumptions": [assumption, assumption]})
    with pytest.raises(ValidationError):
        RequirementsDoc.model_validate({**base, "coverage": {"score": 1.5}})


@pytest.mark.parametrize(
    ("data", "ok"),
    [
        ({"kind": "terminal"}, True),
        ({"kind": "file", "path": "idea.md", "sha256": SHA}, True),
        ({"kind": "file", "path": "idea.md"}, False),
        ({"kind": "terminal", "path": "idea.md", "sha256": SHA}, False),
        ({"kind": "file", "path": "../idea.md", "sha256": SHA}, False),
    ],
)
def test_sources(data: dict[str, Any], ok: bool) -> None:
    if ok:
        Source.model_validate(data)
    else:
        with pytest.raises(ValidationError):
            Source.model_validate(data)


def test_architecture_and_threat_model_rules() -> None:
    component = {"id": "C-01", "name": "api", "paths": ["src/app/api/**"]}
    arch = {"derived_from": {"prd": SHA}, "stack_template": "python-uv", "components": [component]}
    ArchitectureFrontMatter.model_validate(arch)
    with pytest.raises(ValidationError, match="duplicate component"):
        ArchitectureFrontMatter.model_validate({**arch, "components": [component, component]})
    with pytest.raises(ValidationError):
        ArchitectureFrontMatter.model_validate(
            {**arch, "components": [{**component, "paths": ["**"]}]}
        )
    threat = {
        "id": "TM-03", "stride": "I", "component": "C-01", "title": "OTP brute force",
        "severity": "high", "mitigation": "Rate-limit", "owasp_llm": "LLM01",
    }  # fmt: skip
    tm = {"derived_from": {"architecture": SHA}, "threats": [threat]}
    ThreatModelFrontMatter.model_validate(tm)
    with pytest.raises(ValidationError):
        ThreatModelFrontMatter.model_validate({**tm, "threats": [{**threat, "owasp_llm": "LLM11"}]})
    with pytest.raises(ValidationError, match="duplicate threat"):
        ThreatModelFrontMatter.model_validate({**tm, "threats": [threat, threat]})


def test_approvals_and_repo_map() -> None:
    approval = Approval(
        gate="G1", artifact="prd.md", sha256=SHA, by="Jane <j@example.invalid>", at=NOW
    )  # type: ignore[arg-type]
    assert ApprovalsDoc(approvals=[approval]).to_document()["approvals"][0]["at"] == (  # type: ignore[index]
        "2026-10-29T12:00:00Z"
    )
    with pytest.raises(ValidationError):
        Approval.model_validate({**approval.model_dump(), "at": "2026-10-29T12:00:00"})
    with pytest.raises(ValidationError):
        RepoMapFrontMatter.model_validate({"mode": "brownfield", "entries": 301})


# ---------------------------------------------------------------- gates and events


@pytest.mark.parametrize(
    ("data", "ok"),
    [
        ({"run": ["uv", "run", "ruff"]}, True),
        ({"builtin": "gitleaks", "required": True}, True),
        ({"builtin": "semgrep", "fail_on": "high"}, True),
        ({"builtin": "ac_review", "mode": "veto"}, True),
        ({}, False),
        ({"run": ["x"], "builtin": "osv"}, False),
        ({"run": ["x"], "fail_on": "high"}, False),
        ({"builtin": "osv", "mode": "veto"}, False),
        ({"run": []}, False),
        ({"run": ["x"] * 33}, False),
        ({"run": ["x" * 513]}, False),
        ({"builtin": "bash"}, False),
    ],
)
def test_gate_definitions(data: dict[str, Any], ok: bool) -> None:
    if ok:
        GateDef.model_validate(data)
    else:
        with pytest.raises(ValidationError):
            GateDef.model_validate(data)


def test_argv_whitespace_is_kept_exactly() -> None:
    assert GateDef(run=(" uv", "run ")).run == (" uv", "run ")
    assert PrepareDef(run=("uv", "sync", "--frozen")).network.value == "registries"
    assert BuiltinGate("ac_trace") is BuiltinGate.AC_TRACE


def test_journal_and_security_events() -> None:
    event = JournalEvent(
        seq=42,
        ts=NOW,
        run="r-20261028-1102-ab12",
        type="gate_result",
        task="T-007",
        attempt=2,
        data={"gate": "unit"},
    )  # type: ignore[arg-type]
    assert event.model_dump(mode="json")["v"] == 1
    with pytest.raises(ValidationError, match="data keys"):
        JournalEvent.model_validate({**event.model_dump(), "data": {str(i): i for i in range(65)}})
    with pytest.raises(ValidationError, match="larger than"):
        JournalEvent.model_validate({**event.model_dump(), "data": {"x": "y" * 20_000}})
    SecurityEvent(id="EV-0123456789ab", ts=NOW, kind="policy_violation")  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="ack_of"):
        SecurityEvent(id="EV-0123456789ab", ts=NOW, kind="ack")  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="ack_of"):
        SecurityEvent(
            id="EV-0123456789ab", ts=NOW, kind="policy_violation", ack_of="EV-0123456789ab"
        )  # type: ignore[arg-type]
