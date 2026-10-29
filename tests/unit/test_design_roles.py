"""The architect, threat modeler and planner roles, and the views built from them (prompt 04)."""

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from aipm.domain.dag import PlanRules, validate_plan
from aipm.domain.models import (
    ProposedTask,
    SecurityEvent,
    SecurityEventKind,
    TasksDerivedFrom,
    TasksDoc,
)
from aipm.reporting.plan_review import plan_facts
from aipm.reporting.status import progress_bar, unacknowledged
from aipm.reporting.worksheet import cell, render_worksheet
from aipm.roles import architect, planner, threat_modeler
from aipm.roles.architect import ArchitectureDraft
from aipm.roles.planner import PlanDraft
from aipm.roles.threat_modeler import OWASP_LLM_TOP_10, ThreatModelDraft
from aipm.security.untrusted import Untrusted
from tests.integration.flow import reply

STACKS = ("python-uv",)


def draft(**change: Any) -> ArchitectureDraft:
    return ArchitectureDraft.model_validate({**reply("architect"), **change})


def threats(**change: Any) -> ThreatModelDraft:
    return ThreatModelDraft.model_validate({**reply("threat_modeler"), **change})


# ---------------------------------------------------------------- architect


def test_the_clinic_architecture_passes() -> None:
    assert architect.problems(draft(), STACKS) == []


def test_only_built_in_templates() -> None:
    assert architect.problems(draft(stack_template="custom"), STACKS) == [
        "stack_template: must be one of the built-in templates (python-uv)"
    ]


@pytest.mark.parametrize("path", ["../x", "/etc", ".pm/**", ".github/**", "-rf", "CLAUDE.md"])
def test_component_paths_must_be_safe(path: str) -> None:
    out = draft()
    out.components[1].paths.append(path)
    (problem,) = architect.problems(out, STACKS)
    assert problem.startswith("components.1.paths.1: not a safe repository-relative glob")
    assert path not in problem


def test_component_ids_are_unique() -> None:
    data = reply("architect")
    data["components"][1]["id"] = "C-01"
    with pytest.raises(ValidationError):
        ArchitectureDraft.model_validate(data)


def test_postprocess_normalizes_paths() -> None:
    out = draft()
    out.components[0].paths[:] = ["./src//clinic/api/**", "src/clinic/api/**"]
    inp = architect.ArchitectInput(project="p", mode="greenfield",
                                   prd=Untrusted("p", source="s"), stacks=STACKS)  # fmt: skip
    assert architect.create().postprocess(out, inp).components[0].paths == ["src/clinic/api/**"]


def test_builders_number_the_decisions() -> None:
    out = draft()
    doc = architect.build_architecture(out, project="clinic", prd_sha="a" * 64)
    assert doc.meta.decisions == ["ADR-0001", "ADR-0002"]
    assert "- ADR-0002: One-time codes by WhatsApp for patients" in doc.body
    adrs = architect.build_adrs(out)
    assert [a.meta.id for a in adrs] == ["ADR-0001", "ADR-0002"]
    assert adrs[0].file_name == "0001-fastapi-and-postgres-in-one-container.md"
    assert adrs[0].body.startswith("# ADR-0001: FastAPI and Postgres in one container\n")


# ---------------------------------------------------------------- threat modeler


def components() -> tuple[str, ...]:
    return tuple(c.id for c in draft().components)


def test_the_clinic_threats_pass() -> None:
    assert threat_modeler.problems(threats(), components=components(), is_llm_app=False) == []


def test_owasp_coverage_for_llm_apps() -> None:
    covered = [{**reply("threat_modeler")["threats"][0], "id": f"TM-{n:02d}", "owasp_llm": code}
               for n, (code, _) in enumerate(OWASP_LLM_TOP_10, start=1)]  # fmt: skip
    assert threat_modeler.problems(threats(threats=covered), components=components(),
                                   is_llm_app=True) == []  # fmt: skip
    (problem,) = threat_modeler.problems(threats(threats=covered[:-1]), components=components(),
                                         is_llm_app=True)  # fmt: skip
    assert problem.endswith("missing: LLM10")
    assert threat_modeler.problems(threats(), components=components(), is_llm_app=True)


def test_postprocess_orders_by_severity() -> None:
    inp = threat_modeler.ThreatModelerInput(project="p", architecture=Untrusted("a", source="s"),
                                            components=components(), is_llm_app=False)  # fmt: skip
    out = threat_modeler.create().postprocess(threats(), inp)
    assert [t.severity.value for t in out.threats] == ["high", "high", "medium", "low"]


def test_threat_table_escapes_pipes() -> None:
    data = reply("threat_modeler")
    data["threats"][0]["title"] = "a | b\nc"
    out = threats(threats=data["threats"])
    doc = threat_modeler.build_threat_model(
        out, project="p", architecture_sha="b" * 64, is_llm_app=False
    )
    assert "| a \\| b c |" in doc.body
    assert "OWASP" not in doc.body


def test_bad_owasp_ids_fail_the_schema() -> None:
    data = reply("threat_modeler")
    data["threats"][0]["owasp_llm"] = "LLM11"
    with pytest.raises(ValidationError):
        ThreatModelDraft.model_validate(data)


# ---------------------------------------------------------------- planner


def test_the_plan_schema_caps_tasks_at_200() -> None:
    data = reply("planner")
    data["tasks"] = data["tasks"][:1] * 201
    with pytest.raises(ValidationError):
        PlanDraft.model_validate(data)


def test_the_planner_prompt_names_gates_without_commands() -> None:
    prompt = planner.create().render(planner.PlannerInput(
        project="p", prd=Untrusted("prd", source="approved:prd"),
        architecture=Untrusted("a", source="approved:architecture"),
        threat_model=Untrusted("t", source="approved:threat_model"),
        gates=(planner.MenuGate("lint", True), planner.MenuGate("types", False)),
        must_features=("F-001",), threats_to_trace=("TM-01",),
        settings=Untrusted("test_roots: [tests]\n", source="config:plan"),
        max_tasks=50))  # fmt: skip
    assert "- `lint` (required)\n- `types`\n" in prompt.user
    assert "At most 50 tasks." in prompt.user
    assert "- `.github/**`" in prompt.user
    assert "Problems with your previous reply" not in prompt.user


# ---------------------------------------------------------------- views


def plan_tasks() -> TasksDoc:
    proposed = [ProposedTask.model_validate(t) for t in reply("planner")["tasks"]]
    menu = ("lint", "format", "types", "unit", "secrets", "sast", "deps", "ac_trace", "ac_review")
    rules = PlanRules(gate_menu=menu, features=frozenset(f"F-00{n}" for n in range(1, 6)),
                      nfrs=frozenset({"NFR-01", "NFR-02"}),
                      threats=frozenset(f"TM-0{n}" for n in range(1, 5)))  # fmt: skip
    result = validate_plan(proposed, rules)
    assert result.ok, result.issues
    return TasksDoc(derived_from=TasksDerivedFrom(prd="a" * 64, architecture="b" * 64,
                                                  threat_model="c" * 64),
                    tasks=list(result.tasks))  # fmt: skip


def test_worksheet_cells() -> None:
    assert cell("a | b\n\nc") == "a \\| b c"


def test_worksheet_lists_every_task() -> None:
    text = render_worksheet(plan_tasks())
    assert text.count("\n## T-") == 7
    assert "- [ ] AC-T005-4: A webhook call with a bad signature is rejected" in text
    assert text.endswith("\n")


def test_plan_facts() -> None:
    facts = plan_facts(plan_tasks().tasks, test_roots=["tests"])
    assert (facts.depth, facts.width) == (4, 4)
    assert facts.rows[0].startswith("ID ")
    assert facts.deps_add[2] == "T-003: pypi slowapi"
    assert facts.test_or_config[0] == "T-001: pyproject.toml, tests/conftest.py"


@pytest.mark.parametrize(("done", "total", "bar"), [
    (0, 0, "[------------------------------]   0% (0/0)"),
    (1, 2, "[###############---------------]  50% (1/2)"),
    (3, 3, "[##############################] 100% (3/3)"),
])  # fmt: skip
def test_progress_bar(done: int, total: int, bar: str) -> None:
    assert progress_bar(done, total) == bar


def event(n: int, kind: SecurityEventKind, ack_of: str | None = None) -> SecurityEvent:
    return SecurityEvent(id=f"EV-{n:012x}", ts=datetime(2026, 10, 29, tzinfo=UTC), kind=kind,
                         ack_of=ack_of)  # fmt: skip


def test_unacknowledged() -> None:
    a, b = (
        event(1, SecurityEventKind.POLICY_VIOLATION),
        event(2, SecurityEventKind.ACK, "EV-ffffffffffff"),
    )
    ack = event(3, SecurityEventKind.ACK, a.id)
    c = event(4, SecurityEventKind.INJECTION_SIGNAL)
    assert unacknowledged([a, ack, c]) == [c]
    assert b not in unacknowledged([b])
