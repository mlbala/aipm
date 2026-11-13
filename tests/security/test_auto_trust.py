"""`aipm auto` never records trust (SECURITY.md §6 rule 4, ADR-0028).

With an untrusted execution surface, `auto` and `auto --yes` exit 6 before running any step,
print the `aipm trust` command, and leave the trust store exactly as it was: same bytes, same
modification time, and no file created when there was none.
"""

import ast
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.llm.fake import FakeLLM
from tests.conftest import FakeSecrets
from tests.integration.conftest import (
    UserDirs,
    user_dirs,  # noqa: F401 - the fixture
)
from tests.integration.flow import aipm, planned, pm_files
from tests.integration.test_verify_cli import edit_config


@pytest.fixture
def sample(tmp_repo: Path, fake_llm: Callable[[str], FakeLLM], fake_secrets: FakeSecrets) -> Path:
    del fake_secrets
    fake_llm("clinic")
    planned(tmp_repo)  # trusted, so the trust store exists
    return tmp_repo


def change_the_surface(repo: Path) -> None:
    """Add a flag to the lint gate's argv: a new surface, which nobody has trusted."""

    def change(layer: dict[str, object]) -> None:
        gates = dict(layer["gates"])  # type: ignore[call-overload]
        lint = dict(gates["lint"])
        lint["run"] = [*lint["run"], "--quiet"]
        gates["lint"] = lint
        layer["gates"] = gates

    edit_config(repo, change)


@pytest.mark.parametrize("flags", [["--yes"], []])
def test_auto_with_an_untrusted_surface_exits_6_and_leaves_the_trust_store_alone(
    sample: Path,
    user_dirs: UserDirs,  # noqa: F811 - the imported fixture
    flags: list[str],
) -> None:
    store = user_dirs.trust_file
    assert store.exists()
    change_the_surface(sample)
    before = (store.read_bytes(), store.stat().st_mtime_ns)
    pm_before = pm_files(sample)
    result = aipm(sample, "auto", flags=flags)
    assert result.exit_code == 6, result.output
    assert "aipm trust" in result.stderr and "never records trust" in result.stderr
    assert (store.read_bytes(), store.stat().st_mtime_ns) == before
    assert pm_files(sample) == pm_before, "no step ran"


def test_auto_yes_creates_no_trust_store(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    user_dirs: UserDirs,  # noqa: F811 - the imported fixture
) -> None:
    del fake_secrets
    fake_llm("clinic")
    planned(tmp_repo, trusted=False)
    assert not user_dirs.trust_file.exists()
    result = aipm(tmp_repo, "auto", "--yes")
    assert result.exit_code == 6, result.output
    assert not user_dirs.trust_file.exists()
    assert not user_dirs.trust_file.parent.exists() or not any(
        user_dirs.trust_file.parent.glob("trust*")
    )


def test_auto_cannot_reach_the_trust_store_writer() -> None:
    """`auto` imports only the read-only trust check (ADR-0028): not the trust store, and
    nothing from `aipm.app.trust` that records trust."""
    source = (Path(__file__).parents[2] / "src/aipm/app/auto.py").read_text(encoding="utf-8")
    modules: set[str] = set()
    names: dict[str, set[str]] = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
            names.setdefault(node.module, set()).update(a.name for a in node.names)
    assert not any("trust_store" in m for m in modules), modules
    assert names.get("aipm.app.trust") == {"require_trusted"}
