"""Phase derivation (`aipm.domain.phase`, ARCHITECTURE §7.1): every phase and staleness."""

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest

from aipm.domain.models import (
    AcceptanceCriterion,
    Approval,
    ApprovalGate,
    ApprovalsDoc,
    ArchitectureDerivedFrom,
    ArchitectureDoc,
    ArchitectureFrontMatter,
    ArtifactKind,
    Blocked,
    BlockedReason,
    Coverage,
    Dimension,
    Done,
    Mode,
    OpenQuestion,
    Phase,
    PrdDerivedFrom,
    PrdDoc,
    PrdFrontMatter,
    ProjectInfo,
    RequirementsDoc,
    StateSnapshot,
    Task,
    TasksDerivedFrom,
    TasksDoc,
    TaskSize,
    TaskStatus,
    TaskType,
    ThreatModelDerivedFrom,
    ThreatModelDoc,
    ThreatModelFrontMatter,
)
from aipm.domain.phase import (
    InputState,
    derive_phase,
    design_inputs,
    plan_inputs,
    prompt_inputs,
    ready_tasks,
)

H = {
    ArtifactKind.REQUIREMENTS: "1" * 64,
    ArtifactKind.PRD: "2" * 64,
    ArtifactKind.ARCHITECTURE: "3" * 64,
    ArtifactKind.THREAT_MODEL: "4" * 64,
    ArtifactKind.ADR: "5" * 64,
    ArtifactKind.TASKS: "6" * 64,
}
NAMES = {
    ArtifactKind.PRD: ("prd.md", ApprovalGate.G1),
    ArtifactKind.ARCHITECTURE: ("architecture.md", ApprovalGate.G2),
    ArtifactKind.THREAT_MODEL: ("threat-model.md", ApprovalGate.G2),
    ArtifactKind.ADR: ("adr", ApprovalGate.G2),
    ArtifactKind.TASKS: ("tasks.yaml", ApprovalGate.G3),
}


def approved_too(s: StateSnapshot, kind: ArtifactKind, sha: str) -> StateSnapshot:
    approvals = [*s.approvals.approvals, approval(kind, sha)]
    return replace(s, approvals=ApprovalsDoc(approvals=approvals))


def approval(kind: ArtifactKind, sha: str | None = None) -> Approval:
    name, gate = NAMES[kind]
    return Approval(gate=gate, artifact=name, sha256=sha or H[kind], by="dev",
                    at=datetime(2026, 10, 29, tzinfo=UTC))  # fmt: skip


def task(n: int, status: TaskStatus = TaskStatus.TODO, deps: tuple[int, ...] = ()) -> Task:
    extra: dict[str, Any] = {}
    if status is TaskStatus.DONE:
        extra["done"] = Done(commit="a" * 40, at=datetime(2026, 10, 29, tzinfo=UTC))
    if status is TaskStatus.BLOCKED:
        extra["blocked"] = Blocked(reason=BlockedReason.MANUAL, question="Which provider?")
    return Task(
        id=f"T-{n:03d}", title=f"Task {n}", type=TaskType.FEATURE, size=TaskSize.S,
        depends_on=[f"T-{d:03d}" for d in deps], status=status,
        acceptance=[AcceptanceCriterion(id=f"AC-T{n:03d}-1", text="works")], **extra,
    )  # fmt: skip


def requirements(score: float = 1.0, blocking: bool = False) -> RequirementsDoc:
    questions = [OpenQuestion(id="Q-009", dimension=Dimension.DATA, question="?", blocking=True)]
    return RequirementsDoc(
        project=ProjectInfo(name="clinic-booking"), mode=Mode.GREENFIELD,
        coverage=Coverage(score=score), open_questions=questions if blocking else [],
    )  # fmt: skip


def full(**change: Any) -> StateSnapshot:
    """Everything present, current, approved and trusted, with two todo tasks."""
    base: dict[str, Any] = {
        "initialized": True,
        "hashes": dict(H),
        "requirements": requirements(),
        "prd": PrdDoc(meta=PrdFrontMatter(derived_from=PrdDerivedFrom(
            requirements=H[ArtifactKind.REQUIREMENTS]))),
        "architecture": ArchitectureDoc(meta=ArchitectureFrontMatter(
            derived_from=ArchitectureDerivedFrom(prd=H[ArtifactKind.PRD]),
            stack_template="python-uv")),
        "threat_model": ThreatModelDoc(meta=ThreatModelFrontMatter(
            derived_from=ThreatModelDerivedFrom(architecture=H[ArtifactKind.ARCHITECTURE]))),
        "tasks": TasksDoc(
            derived_from=TasksDerivedFrom(prd=H[ArtifactKind.PRD],
                                          architecture=H[ArtifactKind.ARCHITECTURE],
                                          threat_model=H[ArtifactKind.THREAT_MODEL]),
            tasks=[task(1), task(2, deps=(1,))]),
        "approvals": ApprovalsDoc(approvals=[approval(k) for k in NAMES]),
        "trusted": True,
    }  # fmt: skip
    return StateSnapshot(**{**base, **change})


def without(s: StateSnapshot, *kinds: ArtifactKind) -> StateSnapshot:
    approvals = [a for a in s.approvals.approvals if all(a.artifact != NAMES[k][0] for k in kinds)]
    return replace(s, approvals=ApprovalsDoc(approvals=approvals))


def rehash(s: StateSnapshot, kind: ArtifactKind, value: str) -> StateSnapshot:
    return replace(s, hashes={**s.hashes, kind: value})


def with_tasks(s: StateSnapshot, *tasks: Task) -> StateSnapshot:
    assert s.tasks is not None
    return replace(s, tasks=s.tasks.model_copy(update={"tasks": list(tasks)}))


# ---------------------------------------------------------------- the table


@pytest.mark.parametrize(
    ("snapshot", "phase", "command"),
    [
        (StateSnapshot(), Phase.UNINITIALIZED, "aipm init"),
        (StateSnapshot(initialized=True), Phase.INITIALIZED, "aipm discover"),
        (full(requirements=requirements(0.5), prd=None), Phase.DISCOVERING, "aipm discover"),
        (full(prd=None), Phase.REQUIREMENTS_READY, "aipm discover"),
        (without(full(), ArtifactKind.PRD), Phase.PRD_DRAFT, "aipm approve prd"),
        (full(requirements=requirements(blocking=True)), Phase.PRD_DRAFT, "aipm discover"),
        (full(architecture=None, threat_model=None, tasks=None), Phase.PRD_APPROVED,
         "aipm design"),
        (full(threat_model=None, tasks=None), Phase.DESIGN_DRAFT, "aipm design --regenerate"),
        (without(full(), ArtifactKind.ADR), Phase.DESIGN_DRAFT, "aipm approve design"),
        (without(full(), ArtifactKind.THREAT_MODEL), Phase.DESIGN_DRAFT, "aipm approve design"),
        (full(tasks=None), Phase.DESIGN_APPROVED, "aipm plan"),
        (without(full(), ArtifactKind.TASKS), Phase.PLAN_DRAFT, "aipm approve plan"),
        (full(trusted=False), Phase.PLAN_DRAFT, "aipm trust"),
        (full(), Phase.PLAN_APPROVED, "aipm prompt T-001"),
        (with_tasks(full(), task(1, TaskStatus.DONE), task(2, deps=(1,))), Phase.BUILDING,
         "aipm prompt T-002"),
        (with_tasks(full(), task(1, TaskStatus.BLOCKED), task(2, deps=(1,))), Phase.BUILDING,
         "aipm status"),
        (with_tasks(full(), task(1, TaskStatus.DONE), task(2, TaskStatus.SKIPPED)), Phase.BUILT,
         None),
    ],
)  # fmt: skip
def test_phase_table(snapshot: StateSnapshot, phase: Phase, command: str | None) -> None:
    report = derive_phase(snapshot)
    assert report.phase is phase
    assert report.next_command == command


def test_blockers_name_the_reason() -> None:
    assert derive_phase(full(requirements=requirements(blocking=True))).blockers == (
        "G1 is blocked by open questions: Q-009",
    )
    assert derive_phase(full(trusted=False)).blockers == ("the execution surface is not trusted",)
    blocked = with_tasks(full(), task(1, TaskStatus.BLOCKED))
    assert derive_phase(blocked).blockers == ("no task is ready; blocked: T-001",)


def test_ready_task_is_the_first_ready_one() -> None:
    report = derive_phase(with_tasks(full(), task(1, TaskStatus.IN_PROGRESS), task(2), task(3)))
    assert report.ready_task == "T-002"
    assert [t.id for t in ready_tasks([task(2, deps=(1,)), task(1)])] == ["T-001"]


def test_an_approval_of_another_hash_does_not_count() -> None:
    s = approved_too(without(full(), ArtifactKind.PRD), ArtifactKind.PRD, "9" * 64)
    assert derive_phase(s).phase is Phase.PRD_DRAFT


# ---------------------------------------------------------------- staleness


def test_requirements_change_makes_everything_downstream_stale() -> None:
    report = derive_phase(rehash(full(), ArtifactKind.REQUIREMENTS, "9" * 64))
    assert report.phase is Phase.PRD_DRAFT
    assert report.next_command == "aipm discover"
    assert report.stale == (
        ArtifactKind.PRD, ArtifactKind.ARCHITECTURE, ArtifactKind.THREAT_MODEL, ArtifactKind.TASKS,
    )  # fmt: skip
    assert report.impacts == (
        "requirements.yaml changed after the PRD was written → the PRD, the architecture, "
        "the threat model and the plan are stale",
    )


def test_prd_change_after_design_makes_design_and_plan_stale() -> None:
    s = approved_too(rehash(full(), ArtifactKind.PRD, "9" * 64), ArtifactKind.PRD, "9" * 64)
    report = derive_phase(s)
    assert report.phase is Phase.DESIGN_DRAFT
    assert report.next_command == "aipm design --regenerate"
    assert report.stale == (ArtifactKind.ARCHITECTURE, ArtifactKind.THREAT_MODEL,
                            ArtifactKind.TASKS)  # fmt: skip
    assert report.impacts == (
        "prd.md changed after the design was written → the architecture, the threat model "
        "and the plan are stale",
    )


def test_architecture_change_makes_threat_model_and_plan_stale() -> None:
    report = derive_phase(rehash(full(), ArtifactKind.ARCHITECTURE, "9" * 64))
    assert report.phase is Phase.DESIGN_DRAFT
    assert report.stale == (ArtifactKind.THREAT_MODEL, ArtifactKind.TASKS)


def test_threat_model_change_makes_the_plan_stale() -> None:
    report = derive_phase(rehash(full(), ArtifactKind.THREAT_MODEL, "9" * 64))
    assert report.stale == (ArtifactKind.TASKS,)
    assert report.impacts == (
        "threat-model.md changed after the plan was made → the plan is stale",
    )
    assert report.phase is Phase.DESIGN_DRAFT, "the changed threat model needs G2 again"


def test_a_stale_plan_alone() -> None:
    s = full()
    assert s.tasks is not None
    tasks = s.tasks.model_copy(update={"derived_from": s.tasks.derived_from.model_copy(
        update={"architecture": "8" * 64})})  # fmt: skip
    report = derive_phase(replace(s, tasks=tasks))
    assert report.phase is Phase.PLAN_DRAFT
    assert report.next_command == "aipm plan"
    assert report.impacts == (
        "architecture.md changed after the plan was made → the plan is stale",
    )


def test_a_current_plan_is_not_stale() -> None:
    assert derive_phase(full()).stale == ()
    assert derive_phase(full()).impacts == ()


# ---------------------------------------------------------------- command inputs


def test_design_inputs() -> None:
    (prd,) = design_inputs(full())
    assert (prd.state, prd.label) == (InputState.OK, "approved:prd")
    assert prd.sha256 == H[ArtifactKind.PRD]
    (prd,) = design_inputs(without(full(), ArtifactKind.PRD))
    assert (prd.state, prd.label) == (InputState.UNAPPROVED, "unapproved:prd")
    (prd,) = design_inputs(rehash(full(), ArtifactKind.REQUIREMENTS, "9" * 64))
    assert (prd.state, prd.label) == (InputState.STALE, "stale:prd")
    (prd,) = design_inputs(full(prd=None))
    assert prd.state is InputState.MISSING
    assert "aipm discover" in prd.reason


def test_plan_inputs() -> None:
    assert [c.state for c in plan_inputs(full())] == [InputState.OK] * 4
    assert [c.label for c in plan_inputs(full())] == [
        "approved:prd", "approved:architecture", "approved:threat_model", "approved:adr",
    ]  # fmt: skip
    checks = plan_inputs(without(full(), ArtifactKind.ADR))
    assert [c.state for c in checks][3] is InputState.UNAPPROVED
    checks = plan_inputs(rehash(full(), ArtifactKind.ARCHITECTURE, "9" * 64))
    assert [c.state for c in checks] == [
        InputState.OK, InputState.UNAPPROVED, InputState.STALE, InputState.OK,
    ]  # fmt: skip
    checks = plan_inputs(full(threat_model=None))
    assert checks[2].state is InputState.MISSING


def test_a_task_in_progress_is_named_when_nothing_else_is_ready() -> None:
    """Build prompt 05: after `aipm prompt T-001`, the report says what it is waiting for."""
    report = derive_phase(with_tasks(full(), task(1, TaskStatus.IN_PROGRESS), task(2, deps=(1,))))
    assert report.phase is Phase.BUILDING
    assert report.next_command == "aipm status"
    assert report.blockers == ("no task is ready until T-001 is done (in progress)",)


def test_prompt_inputs() -> None:
    """Build prompt 05: `aipm prompt` reads what `plan` reads, plus the approved plan."""
    checks = prompt_inputs(full())
    assert [c.label for c in checks][4] == "approved:tasks"
    assert [c.state for c in checks] == [InputState.OK] * 5
    assert prompt_inputs(without(full(), ArtifactKind.TASKS))[4].state is InputState.UNAPPROVED
    stale = prompt_inputs(rehash(full(), ArtifactKind.THREAT_MODEL, "9" * 64))
    assert stale[4].state is InputState.STALE
    missing = prompt_inputs(full(tasks=None))[4]
    assert missing.state is InputState.MISSING
    assert "aipm plan" in missing.reason


def test_report_data() -> None:
    data = derive_phase(full(trusted=False)).to_data()
    assert data == {
        "phase": "plan_draft", "stale": [], "next_command": "aipm trust",
        "blockers": ["the execution surface is not trusted"], "impacts": [], "ready_task": None,
    }  # fmt: skip
