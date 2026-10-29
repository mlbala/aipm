"""`aipm approve design|plan` (build prompt 04): records pinned to hashes; `--yes` never trusts.

G3 shows every command line from the trusted config, and only an interactive G3 records trust.
"""

import json
import shlex
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.app import approve
from aipm.config.loader import load_config
from aipm.domain.models import ApprovalGate
from aipm.llm.fake import FakeLLM
from aipm.state.layout import repo_id
from aipm.state.trust_store import default_trust_store, hash_surface, render_surface
from tests.integration.conftest import UserDirs
from tests.integration.flow import aipm, approvals, discovered, ok

type UseFake = Callable[[str], FakeLLM]


@pytest.fixture
def designed_pending(tmp_repo: Path, fake_llm: UseFake) -> Path:
    """Designed with G2 pending."""
    fake_llm("clinic")
    discovered(tmp_repo)
    ok(aipm(tmp_repo, "design"))
    return tmp_repo


@pytest.fixture
def planned_pending(designed_pending: Path) -> Path:
    """G2 approved, planned with G3 pending."""
    ok(aipm(designed_pending, "approve", "design", "--yes"))
    ok(aipm(designed_pending, "plan"))
    return designed_pending


def gates(repo: Path) -> set[ApprovalGate]:
    return {a.gate for a in approvals(repo).approvals}


def trusted(user_dirs: UserDirs, repo: Path) -> bool:
    if not user_dirs.trust_file.exists():
        return False
    return repo_id(repo) in user_dirs.trust_file.read_text(encoding="utf-8")


# ---------------------------------------------------------------- G2


def test_approve_design_needs_yes_when_non_interactive(designed_pending: Path) -> None:
    result = aipm(designed_pending, "approve", "design")
    assert result.exit_code == 4
    assert "aipm approve design --yes" in result.stderr
    assert ApprovalGate.G2 not in gates(designed_pending)


def test_approve_design_shows_g2_and_records_it(designed_pending: Path) -> None:
    result = ok(aipm(designed_pending, "approve", "design", "--yes"))
    out = result.stdout
    assert "Design (G2): .pm/architecture.md, .pm/threat-model.md, .pm/adr/" in out
    assert "Stack: language: python, framework: fastapi" in out
    assert "  - C-03 notifications (src/clinic/notify/**): WhatsApp confirmations" in out
    assert "  - ADR-0002: One-time codes by WhatsApp for patients" in out
    assert "  - TM-02 (medium, C-03): Forged WhatsApp webhook calls" in out
    assert "TM-04" not in out
    assert "G2 approved." in out
    assert "Copied the python-uv stack's prepare step" in out
    assert ApprovalGate.G2 in gates(designed_pending)
    again = ok(aipm(designed_pending, "approve", "design", "--yes"))
    assert "G2 was already approved for this design." in again.stdout


def test_interactive_g2(designed_pending: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipm.cli.output.stdin_is_terminal", lambda: True)
    declined = ok(aipm(designed_pending, "approve", "design", input="n\n"))
    assert "Not approved." in declined.stdout
    assert ApprovalGate.G2 not in gates(designed_pending)
    ok(aipm(designed_pending, "approve", "design", input="y\n"))
    assert ApprovalGate.G2 in gates(designed_pending)


def test_a_stale_design_cannot_be_approved(designed_pending: Path) -> None:
    path = designed_pending / ".pm" / "architecture.md"
    path.write_text(path.read_text(encoding="utf-8") + "\nEdited.\n", encoding="utf-8")
    result = aipm(designed_pending, "approve", "design", "--yes")
    assert result.exit_code == 2
    assert "threat-model.md is stale" in result.stderr


def test_a_design_changed_after_review_is_not_approved(
    designed_pending: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = approve.review_design

    def review_then_tamper(project: Path | None) -> approve.DesignReview:
        review = real(project)
        adr = next((designed_pending / ".pm" / "adr").iterdir())
        adr.write_text(adr.read_text(encoding="utf-8") + "\nAdded later.\n", encoding="utf-8")
        return review

    monkeypatch.setattr(approve, "review_design", review_then_tamper)
    result = aipm(designed_pending, "approve", "design", "--yes")
    assert result.exit_code == 2
    assert "the design changed after it was shown" in result.stderr
    assert ApprovalGate.G2 not in gates(designed_pending)


# ---------------------------------------------------------------- G3


def test_approve_plan_yes_records_g3_and_prints_the_trust_command(
    planned_pending: Path, user_dirs: UserDirs
) -> None:
    result = ok(aipm(planned_pending, "approve", "plan", "--yes"))
    assert "G3 approved." in result.stdout
    assert "Trust is not recorded by --yes" in result.stdout
    shown = ok(aipm(planned_pending, "trust", "--show", flags=["--json"]))
    surface_hash = json.loads(shown.stdout)["data"]["surface_hash"]
    assert f"aipm trust --confirm {surface_hash[:12]}" in result.stdout
    assert ApprovalGate.G3 in gates(planned_pending)
    assert not trusted(user_dirs, planned_pending)


def test_global_yes_never_trusts_either(planned_pending: Path, user_dirs: UserDirs) -> None:
    ok(aipm(planned_pending, "approve", "plan", flags=["--yes"]))
    assert not trusted(user_dirs, planned_pending)


def test_interactive_g3_records_trust(
    planned_pending: Path, user_dirs: UserDirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aipm.cli.output.stdin_is_terminal", lambda: True)
    result = ok(aipm(planned_pending, "approve", "plan", input="y\n"))
    assert "G3 approved." in result.stdout
    assert "The execution surface is trusted." in result.stdout
    assert trusted(user_dirs, planned_pending)


def test_interactive_decline_records_nothing(
    planned_pending: Path, user_dirs: UserDirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aipm.cli.output.stdin_is_terminal", lambda: True)
    result = ok(aipm(planned_pending, "approve", "plan", input="n\n"))
    assert "Not approved." in result.stdout
    assert ApprovalGate.G3 not in gates(planned_pending)
    assert not trusted(user_dirs, planned_pending)


def test_g3_shows_the_argv_from_config_only(planned_pending: Path) -> None:
    """The command list at G3 is exactly the trust store's rendering of the trusted config."""
    out = ok(aipm(planned_pending, "approve", "plan", "--yes")).stdout
    cfg = load_config(planned_pending).config
    surface = default_trust_store().surface(cfg)
    expected = render_surface(surface, hash_surface(surface))
    shown = out.splitlines()
    start = shown.index("Execution surface")
    assert shown[start : start + len(expected)] == expected
    for name, gate in cfg.gates.items():
        if gate.run is not None:
            assert any(line.startswith(f"  {name} (") and shlex.join(gate.run) in line
                       for line in shown)  # fmt: skip
    assert "deps_add" in out
    assert "  - T-003: pypi slowapi" in out
    assert "  - T-001: pyproject.toml, tests/conftest.py" in out


def test_a_stale_plan_cannot_be_approved(planned_pending: Path) -> None:
    path = planned_pending / ".pm" / "prd.md"
    path.write_text(path.read_text(encoding="utf-8") + "\nEdited.\n", encoding="utf-8")
    result = aipm(planned_pending, "approve", "plan", "--yes")
    assert result.exit_code == 2
    assert "G3 cannot be approved" in result.stderr
    assert ApprovalGate.G3 not in gates(planned_pending)


def test_a_plan_changed_after_review_is_not_approved(
    planned_pending: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = approve.review_plan

    def review_then_tamper(project: Path | None) -> approve.PlanReview:
        review = real(project)
        path = planned_pending / ".pm" / "tasks.yaml"
        path.write_text(path.read_text(encoding="utf-8") + "# edited\n", encoding="utf-8")
        return review

    monkeypatch.setattr(approve, "review_plan", review_then_tamper)
    result = aipm(planned_pending, "approve", "plan", "--yes")
    assert result.exit_code == 2
    assert "tasks.yaml changed after it was shown" in result.stderr


def test_approve_plan_json(planned_pending: Path) -> None:
    env = json.loads(ok(aipm(planned_pending, "approve", "plan", "--yes",
                             flags=["--json"])).stdout)  # fmt: skip
    data = env["data"]
    assert (data["approved"], data["recorded"], data["trusted"]) == (True, True, False)
    assert data["depth"] == 4
    assert data["tasks"] == 7
