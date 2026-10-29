"""What reaches the architect, threat modeler and planner (build prompt 04; SECURITY.md §4, §7.2).

A full `discover` → `design` → `plan` run with fake secrets planted in the idea and the answers.
Every recorded request must show that:
- no fake secret is present;
- every `.pm/` artifact is inside an `untrusted` block with a source label, approved or not
  (`approved:prd`, `unapproved:architecture`, ...): approval decides the phase, never the
  wrapping;
- the planner sees gate names only, never a gate's argv;
- no request carries sampling parameters.
"""

import re
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.cli.main import app
from aipm.domain.models import RoleName
from aipm.llm.fake import FakeLLM
from aipm.llm.providers.base import ProviderRequest
from aipm.roles import architect, planner, threat_modeler
from aipm.security.untrusted import Untrusted, UntrustedRenderError
from tests.conftest import REPO_ROOT, FakeSecrets
from tests.integration.conftest import user_dirs  # noqa: F401 - isolates HOME and the trust store
from tests.integration.flow import aipm, ok, runner

BLOCK = re.compile(
    r'<untrusted source="(?P<source>[^"]*)" id="(?P<id>u[0-9a-f]{8})">\n'
    r"(?P<body>.*?)\n</untrusted id=\"(?P=id)\">",
    re.DOTALL,
)
PRD_LINE = "Sunrise Family Clinic books appointments by phone."
ARCH_LINE = "One FastAPI service with a Postgres database"
TM_LINE = "Five attempts per phone number in ten minutes"
ROLES = (RoleName.ARCHITECT, RoleName.THREAT_MODELER, RoleName.PLANNER)


@pytest.fixture
def fake(tmp_repo: Path, fake_secrets: FakeSecrets, fake_llm: Callable[[str], FakeLLM]) -> FakeLLM:
    """discover, design and plan, all approved, with secrets in the idea and the answers."""
    ok(runner.invoke(app, ["-C", str(tmp_repo), "init"]))
    idea = (REPO_ROOT / "examples/clinic-booking/idea.md").read_text(encoding="utf-8")
    secrets = " ".join(fake_secrets.values.values())
    (tmp_repo / "idea.md").write_text(f"{idea}\nOur key is {secrets}\n", encoding="utf-8")
    answers = (REPO_ROOT / "tests/fakes/answers/clinic.yaml").read_text(encoding="utf-8")
    token = fake_secrets.values["GITHUB_TOKEN"]
    answers = answers.replace("Meta WhatsApp Cloud API;", f"Meta WhatsApp Cloud API ({token});")
    (tmp_repo / "answers.yaml").write_text(answers, encoding="utf-8")
    fake = fake_llm("clinic")
    ok(aipm(tmp_repo, "discover", "--from", str(tmp_repo / "idea.md"), "--answers",
            str(tmp_repo / "answers.yaml"), flags=["--yes"]))  # fmt: skip
    ok(aipm(tmp_repo, "design", flags=["--yes"]))
    ok(aipm(tmp_repo, "plan", flags=["--yes"]))
    return fake


def requests(fake: FakeLLM) -> list[ProviderRequest]:
    return [r for role in ROLES for r in fake.requests_for(role)]


def test_one_request_per_role(fake: FakeLLM) -> None:
    assert [r.role for r in requests(fake)] == list(ROLES)


def test_fake_secrets_never_reach_a_request(fake: FakeLLM, fake_secrets: FakeSecrets) -> None:
    for request in requests(fake):
        fake_secrets.assert_absent(request.system)
        fake_secrets.assert_absent(request.user)


def test_secrets_never_reach_pm(fake: FakeLLM, fake_secrets: FakeSecrets, tmp_repo: Path) -> None:
    for path in (tmp_repo / ".pm").rglob("*"):
        if path.is_file():
            fake_secrets.assert_absent(path.read_text(encoding="utf-8", errors="replace"))


def sources(request: ProviderRequest) -> list[str]:
    return [b["source"] for b in BLOCK.finditer(request.user)]


def outside(request: ProviderRequest) -> str:
    return BLOCK.sub("", request.user)


def test_every_artifact_is_wrapped_with_its_label(fake: FakeLLM) -> None:
    (arch,) = fake.requests_for(RoleName.ARCHITECT)
    assert sources(arch) == ["approved:prd"]
    (tm,) = fake.requests_for(RoleName.THREAT_MODELER)
    assert sources(tm) == ["unapproved:architecture"]
    (plan,) = fake.requests_for(RoleName.PLANNER)
    assert sources(plan) == ["config:plan", "approved:prd", "approved:architecture",
                             "approved:threat_model"]  # fmt: skip


def test_approved_content_is_still_wrapped(fake: FakeLLM) -> None:
    """G1 and G2 were approved before the plan, yet every artifact line is inside a block."""
    (plan,) = fake.requests_for(RoleName.PLANNER)
    rest = outside(plan)
    for line in (PRD_LINE, ARCH_LINE, TM_LINE, "One-time code brute force", "stack_template",
                 "F-005", "Monthly report"):  # fmt: skip
        assert line not in rest
        assert line not in plan.system
    # Outside the blocks, only IDs that passed aipm's ID regex appear, in aipm's own rule lines.
    assert "- Trace every must feature: F-001, F-002, F-003, F-004." in rest
    assert "- Trace every threat of severity medium or higher: TM-01, TM-02, TM-03." in rest
    bodies = {b["source"]: b["body"] for b in BLOCK.finditer(plan.user)}
    assert PRD_LINE in bodies["approved:prd"]
    assert ARCH_LINE in bodies["approved:architecture"]
    assert TM_LINE in bodies["approved:threat_model"]


def test_every_block_has_a_fresh_nonce(fake: FakeLLM) -> None:
    ids = [b["id"] for r in requests(fake) for b in BLOCK.finditer(r.user)]
    assert len(ids) == len(set(ids))


def test_the_planner_sees_gate_names_only(fake: FakeLLM) -> None:
    (plan,) = fake.requests_for(RoleName.PLANNER)
    for argv_part in ("--junitxml", "{report_file}", "--frozen", "uv run", "pytest -q"):
        assert argv_part not in plan.user
        assert argv_part not in plan.system
    for name in ("`lint` (required)", "`unit` (required)", "`ac_trace` (required)", "`format`"):
        assert name in plan.user


def test_no_request_carries_sampling_parameters(fake: FakeLLM) -> None:
    for request in requests(fake):
        for name in ("temperature", "top_p", "top_k"):
            assert name not in request.schema


def test_raw_untrusted_cannot_be_rendered_by_the_new_roles() -> None:
    """The finalize hook: an Untrusted passed where no |untrusted filter applies fails closed."""
    sneaky = Untrusted("demo", source="x")
    with pytest.raises(UntrustedRenderError):
        architect.create().render(architect.ArchitectInput(
            project=sneaky, mode="greenfield", prd=Untrusted("p", source="s"),  # type: ignore[arg-type]
            stacks=("python-uv",)))  # fmt: skip
    with pytest.raises(UntrustedRenderError):
        threat_modeler.create().render(threat_modeler.ThreatModelerInput(
            project="p", architecture=Untrusted("a", source="s"),
            components=(sneaky,), is_llm_app=False))  # type: ignore[arg-type]  # fmt: skip
    with pytest.raises(UntrustedRenderError):
        planner.create().render(planner.PlannerInput(
            project="p", prd="plain text", architecture=Untrusted("a", source="s"),  # type: ignore[arg-type]
            threat_model=Untrusted("t", source="s"), gates=(), must_features=(),
            threats_to_trace=(), settings=Untrusted("x", source="s"), max_tasks=10))  # fmt: skip
