"""Golden snapshots (build prompt 04): the architect, threat modeler and planner prompts,
`architecture.md`, an ADR, `threat-model.md`, `worksheet.md` and the status output.

Nonces and hashes are fixed, so the snapshots are byte-stable. Update them only when a template
or view change is intended, and say so in the commit message (AGENTS.md).
"""

from datetime import UTC, datetime

from syrupy.assertion import SnapshotAssertion

from aipm.config.schema import BudgetConfig
from aipm.domain.dag import PlanRules, validate_plan
from aipm.domain.models import (
    Approval,
    ApprovalGate,
    ApprovalsDoc,
    ArtifactKind,
    Blocked,
    BlockedReason,
    Done,
    ProposedTask,
    SecurityEvent,
    SecurityEventKind,
    StateSnapshot,
    TasksDerivedFrom,
    TasksDoc,
    TaskStatus,
)
from aipm.domain.phase import derive_phase
from aipm.reporting.status import build_status, render_status, render_task
from aipm.reporting.worksheet import render_worksheet
from aipm.roles import architect, planner, threat_modeler
from aipm.roles.architect import ArchitectureDraft
from aipm.roles.planner import MenuGate
from aipm.roles.prd_writer import PrdDraft, build_prd
from aipm.roles.threat_modeler import ThreatModelDraft
from aipm.security.untrusted import Untrusted
from aipm.state import frontmatter
from tests.golden.test_discover_golden import requirements
from tests.integration.flow import reply

MENU = ("lint", "format", "types", "unit", "secrets", "sast", "deps", "ac_trace", "ac_review")


def nonce() -> str:
    return "u0123abcd"


def arch_draft() -> ArchitectureDraft:
    return ArchitectureDraft.model_validate(reply("architect"))


def tm_draft() -> ThreatModelDraft:
    return ThreatModelDraft.model_validate(reply("threat_modeler"))


def tasks_doc() -> TasksDoc:
    proposed = [ProposedTask.model_validate(t) for t in reply("planner")["tasks"]]
    rules = PlanRules(gate_menu=MENU, features=frozenset(f"F-00{n}" for n in range(1, 6)),
                      nfrs=frozenset({"NFR-01", "NFR-02"}),
                      threats=frozenset(f"TM-0{n}" for n in range(1, 5)))  # fmt: skip
    result = validate_plan(proposed, rules)
    assert result.ok
    return TasksDoc(derived_from=TasksDerivedFrom(prd="1" * 64, architecture="2" * 64,
                                                  threat_model="3" * 64),
                    tasks=list(result.tasks))  # fmt: skip


# ---------------------------------------------------------------- prompts


def test_architect_prompt(snapshot: SnapshotAssertion) -> None:
    prompt = architect.create(nonce=nonce).render(
        architect.ArchitectInput(
            project="clinic-booking",
            mode="brownfield",
            prd=Untrusted("---\nkind: prd\n---\n# PRD: clinic-booking\n", source="approved:prd"),
            stacks=("python-uv",),
            repo_map=Untrusted("src/\n  app.py\n", source="repo-map.md"),
            problems=Untrusted("- stack_template: must be one of the built-in templates",
                               source="aipm:validator"),
        )
    )  # fmt: skip
    assert prompt.system == snapshot(name="architect.system")
    assert prompt.user == snapshot(name="architect.user")


def test_threat_modeler_prompt(snapshot: SnapshotAssertion) -> None:
    prompt = threat_modeler.create(nonce=nonce).render(
        threat_modeler.ThreatModelerInput(
            project="clinic-booking",
            architecture=Untrusted("# Architecture: clinic-booking\n",
                                   source="unapproved:architecture"),
            components=("C-01", "C-02"),
            is_llm_app=True,
        )
    )  # fmt: skip
    assert prompt.system == snapshot(name="threat_modeler.system")
    assert prompt.user == snapshot(name="threat_modeler.user")


def test_planner_prompt(snapshot: SnapshotAssertion) -> None:
    prompt = planner.create(nonce=nonce).render(
        planner.PlannerInput(
            project="clinic-booking",
            prd=Untrusted("# PRD\n", source="approved:prd"),
            architecture=Untrusted("# Architecture\n", source="approved:architecture"),
            threat_model=Untrusted("# Threat model\n", source="stale:threat_model"),
            gates=(MenuGate("lint", True), MenuGate("unit", True), MenuGate("ac_trace", True),
                   MenuGate("types", False)),
            must_features=("F-001", "F-002"),
            threats_to_trace=("TM-01",),
            settings=Untrusted("test_roots: [tests]\n", source="config:plan"),
            max_tasks=200,
        )
    )  # fmt: skip
    assert prompt.system == snapshot(name="planner.system")
    assert prompt.user == snapshot(name="planner.user")


# ---------------------------------------------------------------- artifacts


def test_architecture_md(snapshot: SnapshotAssertion) -> None:
    doc = architect.build_architecture(arch_draft(), project="clinic-booking", prd_sha="a" * 64)
    assert frontmatter.dump(doc.front_matter(), doc.body) == snapshot(name="architecture.md")


def test_adr(snapshot: SnapshotAssertion) -> None:
    doc = architect.build_adrs(arch_draft())[1]
    assert doc.file_name == snapshot(name="adr.name")
    assert frontmatter.dump(doc.front_matter(), doc.body) == snapshot(name="adr.md")


def test_threat_model_md(snapshot: SnapshotAssertion) -> None:
    inp = threat_modeler.ThreatModelerInput(project="clinic-booking",
                                            architecture=Untrusted("a", source="s"),
                                            components=("C-01", "C-02", "C-03", "C-04"),
                                            is_llm_app=False)  # fmt: skip
    out = threat_modeler.create().postprocess(tm_draft(), inp)
    doc = threat_modeler.build_threat_model(
        out, project="clinic-booking", architecture_sha="b" * 64, is_llm_app=False
    )
    assert frontmatter.dump(doc.front_matter(), doc.body) == snapshot(name="threat-model.md")


def test_worksheet_md(snapshot: SnapshotAssertion) -> None:
    assert render_worksheet(tasks_doc()) == snapshot(name="worksheet.md")


# ---------------------------------------------------------------- status


def status_snapshot() -> StateSnapshot:
    """A plan under way: everything approved and trusted, T-001 done and T-002 blocked."""
    doc = tasks_doc()
    at = datetime(2026, 10, 29, 9, 30, tzinfo=UTC)
    doc.tasks[0] = doc.tasks[0].model_copy(update={
        "status": TaskStatus.DONE, "done": Done(commit="c" * 40, at=at)})  # fmt: skip
    doc.tasks[1] = doc.tasks[1].model_copy(update={
        "status": TaskStatus.BLOCKED,
        "blocked": Blocked(reason=BlockedReason.GATES_FAILED, detail="unit failed twice",
                           question="Should a slot be 15 or 20 minutes?")})  # fmt: skip
    hashes = {ArtifactKind.REQUIREMENTS: "d" * 64, ArtifactKind.PRD: "1" * 64,
              ArtifactKind.ARCHITECTURE: "2" * 64, ArtifactKind.THREAT_MODEL: "3" * 64,
              ArtifactKind.ADR: "4" * 64, ArtifactKind.TASKS: "5" * 64}  # fmt: skip
    prd = build_prd(PrdDraft.model_validate(reply("prd_writer")), requirements(),
                    requirements_sha="d" * 64)  # fmt: skip
    arch = architect.build_architecture(arch_draft(), project="clinic-booking", prd_sha="1" * 64)
    tm = threat_modeler.build_threat_model(tm_draft(), project="clinic-booking",
                                           architecture_sha="2" * 64, is_llm_app=False)  # fmt: skip
    approvals = ApprovalsDoc(approvals=[
        Approval(gate=gate, artifact=name, sha256=hashes[kind], by="dev", at=at)
        for gate, name, kind in (
            (ApprovalGate.G1, "prd.md", ArtifactKind.PRD),
            (ApprovalGate.G2, "architecture.md", ArtifactKind.ARCHITECTURE),
            (ApprovalGate.G2, "threat-model.md", ArtifactKind.THREAT_MODEL),
            (ApprovalGate.G2, "adr", ArtifactKind.ADR),
            (ApprovalGate.G3, "tasks.yaml", ArtifactKind.TASKS),
        )
    ])  # fmt: skip
    reqs = requirements().model_copy(update={"open_questions": []})
    return StateSnapshot(initialized=True, hashes=hashes, requirements=reqs, prd=prd,
                         architecture=arch, threat_model=tm, tasks=doc, approvals=approvals,
                         trusted=True)  # fmt: skip


def test_status_output(snapshot: SnapshotAssertion) -> None:
    s = status_snapshot()
    events = [
        SecurityEvent(id="EV-0123456789ab", ts=datetime(2026, 10, 29, 9, 0, tzinfo=UTC),
                      kind=SecurityEventKind.POLICY_VIOLATION, source="llm:planner",
                      detail="the planner proposed 1 items outside the policy"),
        SecurityEvent(id="EV-ba9876543210", ts=datetime(2026, 10, 29, 9, 5, tzinfo=UTC),
                      kind=SecurityEventKind.INJECTION_SIGNAL, source="llm:architect"),
        SecurityEvent(id="EV-ffffffffffff", ts=datetime(2026, 10, 29, 9, 6, tzinfo=UTC),
                      kind=SecurityEventKind.ACK, ack_of="EV-ba9876543210"),
    ]  # fmt: skip
    view = build_status(s, derive_phase(s), events, BudgetConfig())
    assert "\n".join(render_status(view, show_all=True)) == snapshot(name="status")
    assert "\n".join(render_task(view.tasks[1])) == snapshot(name="status.task")
