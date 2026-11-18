"""v0.4 decisions, session 5, step 0: CI's sandbox job runs every real-tool test file.

The real-tool tests skip outside the sandbox job (`need` skips without the real tool), so a
file that job does not collect would never run anywhere. The job collects
`tests/security/test_real_sandbox.py` and every `tests/security/test_real_sandbox_*.py`, and
any test module that uses `need` must be one of those.
"""

import ast
from pathlib import Path

from tests.conftest import REPO_ROOT
from tests.security.test_release_supply_chain import steps
from tests.security.test_v04_decisions_3 import sandbox_job

TESTS = REPO_ROOT / "tests"
REAL_SANDBOX = "tests.security.test_real_sandbox"


def test_the_sandbox_job_collects_every_real_sandbox_file() -> None:
    """`nullglob` drops the sibling pattern while there is none, instead of passing it on."""
    found = [s for s in steps(sandbox_job()) if "pytest" in str(s.get("run", ""))]
    assert len(found) == 1
    run = str(found[0]["run"]).replace("\\\n", " ")
    assert "shopt -s nullglob" in run
    for target in (
        "tests/security/test_real_sandbox.py",
        "tests/security/test_real_sandbox_*.py",
        "tests/security/test_gates.py",
    ):
        assert target in run.split(), target
    assert found[0]["env"] == {"AIPM_REQUIRE_REAL_SRT": "1"}


def uses_need(path: Path) -> bool:
    """Whether the module imports `need` from `test_real_sandbox`."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == REAL_SANDBOX
        and any(alias.name == "need" for alias in node.names)
        for node in ast.walk(tree)
    )


def test_every_module_that_needs_a_real_tool_runs_in_the_sandbox_job() -> None:
    misplaced = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in sorted(TESTS.rglob("*.py"))
        if uses_need(path)
        and not (path.parent == TESTS / "security" and path.name.startswith("test_real_sandbox_"))
    ]
    assert misplaced == [], "rename to tests/security/test_real_sandbox_<name>.py"
