"""Golden snapshots (build prompt 06): aipm's Claude Code subagents and skills for the clinic
project, each as the whole file aipm owns (front matter and body).

Their nonces derive from their content, so the snapshots are byte-stable. Update them only when
a template change is intended, and say so in the commit message (AGENTS.md).
"""

import pytest
from syrupy.assertion import SnapshotAssertion

from aipm.context.generator import CLAUDE_EXTRAS, claude_extras
from tests.fakes.project import clinic_context


@pytest.mark.parametrize("path", sorted(CLAUDE_EXTRAS))
def test_claude_extra(path: str, snapshot: SnapshotAssertion) -> None:
    files = {f.path: f for f in claude_extras(clinic_context())}
    assert files[path].document == snapshot(name=path)
