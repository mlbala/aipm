"""Golden snapshots (build prompt 05): `AGENTS.md`, `CLAUDE.md`, and the Claude Code task prompt,
normal and `--fix`, for the clinic plan.

Context-file nonces derive from their content, and task prompts use a fixed nonce, so the
snapshots are byte-stable. Update them only when a template change is intended, and say so in
the commit message (AGENTS.md).
"""

from syrupy.assertion import SnapshotAssertion

from aipm.adapters.claude_code import ClaudeCodeAdapter
from aipm.adapters.compiler import compile_task_spec, render_within_budget
from aipm.context.generator import agents_md, claude_md
from aipm.domain.models import GateReport
from tests.fakes.project import clinic_context, clinic_task


def nonce() -> str:
    return "u0123abcd"


def test_agents_md(snapshot: SnapshotAssertion) -> None:
    assert agents_md(clinic_context()).block == snapshot(name="AGENTS.md")


def test_claude_md(snapshot: SnapshotAssertion) -> None:
    assert claude_md(clinic_context()).block == snapshot(name="CLAUDE.md")


def test_task_prompt(snapshot: SnapshotAssertion) -> None:
    ctx = clinic_context()
    spec = compile_task_spec(clinic_task("T-002"), ctx)
    prompt = render_within_budget(ClaudeCodeAdapter(nonce=nonce), spec, ctx)
    assert prompt.text == snapshot(name="T-002.claude.md")


def test_fix_prompt(snapshot: SnapshotAssertion) -> None:
    ctx = clinic_context()
    report = GateReport.model_validate({"task": "T-003", "gates": [
        {"name": "lint", "status": "pass"},
        {"name": "unit", "status": "fail", "summary": "1 failed, 4 passed",
         "output": "FAILED tests/api/test_otp.py::test_sixth_attempt_is_limited\n"
                   "E   assert 401 == 429\n"},
    ]})  # fmt: skip
    spec = compile_task_spec(clinic_task("T-003"), ctx, previous=report)
    prompt = render_within_budget(ClaudeCodeAdapter(nonce=nonce), spec, ctx)
    assert prompt.text == snapshot(name="T-003.fix.claude.md")
