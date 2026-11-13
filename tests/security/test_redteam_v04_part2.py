"""The v0.4 security red-team pass, part 2: automation and extension surfaces (build prompt 09
v0.4; docs/security/reviews/v0.4-progress.md).

`aipm auto`, plugins, OpenTelemetry, the go and rust-cargo stacks and the deps gate for Go and
crates. One section per finding (RT04-n); every test in a finding section failed before its
fix. The "held" sections at the end pin controls the pass attacked without breaking them.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

from aipm.app import build as build_use_case
from aipm.cli import output as cli_output
from aipm.cli.main import app
from aipm.config import loader as config_loader
from aipm.domain.models import APPROVED_NAMES, ApprovalGate, ArtifactKind
from aipm.state.store import open_store
from tests.conftest import FakeSecrets
from tests.integration.build_flow import fake_registry, prepare_project
from tests.integration.conftest import (
    UserDirs,
    user_dirs,  # noqa: F401 - an autouse fixture
)
from tests.integration.flow import aipm, approvals, discovered, ok, runner, trust
from tests.integration.test_verify_cli import edit_config

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")
CORPUS = Path(__file__).parent / "corpus"


@pytest.fixture
def dirs(user_dirs: UserDirs) -> UserDirs:  # noqa: F811 - the imported fixture
    return user_dirs


@pytest.fixture
def project(
    tmp_repo: Path,
    fake_llm: Callable[[str], Any],
    fake_secrets: FakeSecrets,
    monkeypatch: pytest.MonkeyPatch,
    dirs: UserDirs,
) -> Path:
    del fake_secrets
    fake_registry(monkeypatch)
    fake_llm("clinic")
    return prepare_project(tmp_repo, monkeypatch, dirs.home)


def case(case_id: str) -> dict[str, Any]:
    (path,) = CORPUS.glob(f"{case_id}-*.yaml")
    data: dict[str, Any] = YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))
    return data


# ---------------------------------------------------------------- RT04-7: trust read apart


def _swap_config_between_reads(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> list[dict[str, object] | None]:
    """Each `load_config` the build makes reads a different `.pm/config.yaml`: the first an
    untrusted one (a gate with one more argument), every later one the trusted original, as a
    process left behind by an earlier attempt could alternate them (R-14)."""
    config = repo / ".pm" / "config.yaml"
    trusted = config.read_bytes()

    def tamper(layer: dict[str, object]) -> None:
        gates = dict(layer["gates"])  # type: ignore[call-overload]
        unit = dict(gates["unit"])
        unit["run"] = [*unit["run"], "-q"]
        gates["unit"] = unit
        layer["gates"] = gates

    edit_config(repo, tamper)
    untrusted = config.read_bytes()
    config.write_bytes(trusted)
    real = config_loader.load_config
    calls: list[dict[str, object] | None] = []

    def alternating(project: Path | None, **kwargs: Any) -> config_loader.LoadedConfig:
        config.write_bytes(untrusted if not calls else trusted)
        calls.append(kwargs.get("flags"))
        return real(project, **kwargs)

    monkeypatch.setattr(build_use_case, "load_config", alternating)
    return calls


@pytest.mark.parametrize("flag", [["--budget", "5"], ["--parallel", "1"], ["--max-retries", "0"]])
def test_build_checks_trust_on_the_config_it_runs(
    project: Path, monkeypatch: pytest.MonkeyPatch, flag: list[str]
) -> None:
    calls = _swap_config_between_reads(project, monkeypatch)
    result = aipm(project, "build", "--dry-run", *flag, flags=["--json"])
    assert result.exit_code == 6, result.output
    assert json.loads(result.stdout)["exit_code"] == 6
    assert len(calls) == 1, "the configuration is read once"


def test_c062_the_config_that_runs_is_the_one_trusted() -> None:
    data = case("C-062")
    assert data["expected"]["exit_code"] == 6
    assert "build --budget" in data["input"]["text"]


def test_without_flags_is_the_same_read(tmp_repo: Path, tmp_path: Path) -> None:
    from aipm.config.loader import load_config  # noqa: PLC0415

    env = {"AIPM_CONFIG": str(tmp_path / "user.yaml")}
    (tmp_path / "user.yaml").write_text("{}\n", encoding="utf-8")
    flagged = load_config(tmp_repo, env=env, flags={"budget.run_usd": 3.0})
    plain = load_config(tmp_repo, env=env)
    assert flagged.config.budget.run_usd == 3.0
    assert flagged.without_flags().config == plain.config
    assert plain.without_flags() is plain


# ---------------------------------------------------------------- RT04-8: interactive auto trusted


@pytest.fixture
def discovered_trusted(
    tmp_repo: Path,
    fake_llm: Callable[[str], Any],
    fake_secrets: FakeSecrets,
    dirs: UserDirs,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """G1 approved and the surface before G2 trusted, so `auto` passes its first trust check;
    G2 then copies the stack's gates, a surface nobody has trusted."""
    del fake_secrets, dirs
    fake_llm("clinic")
    discovered(tmp_repo)
    trust(tmp_repo)
    monkeypatch.setattr(cli_output, "stdin_is_terminal", lambda: True)
    return tmp_repo


def _surface(repo: Path) -> dict[str, Any]:
    shown: dict[str, Any] = json.loads(aipm(repo, "trust", "--show", flags=["--json"]).stdout)
    return shown["data"]


def test_interactive_auto_never_records_trust(discovered_trusted: Path, dirs: UserDirs) -> None:
    repo = discovered_trusted
    result = runner.invoke(app, ["-C", str(repo), "auto", "--dry-run"], input="y\n" * 20)
    after = _surface(repo)
    assert not after["trusted"], "auto recorded trust at G3"
    assert "trust these exact commands" not in result.output
    assert result.exit_code == 6, result.output
    assert "aipm trust" in result.output
    assert approvals(repo).has(ApprovalGate.G3, APPROVED_NAMES[ArtifactKind.TASKS],
                               open_store(repo).sha256(ArtifactKind.TASKS) or "")  # fmt: skip
    del dirs


@pytest.mark.parametrize("command", ["plan", "approve plan"])
def test_plan_and_approve_alone_still_trust_interactively(
    discovered_trusted: Path, command: str
) -> None:
    """Outside auto, an interactive yes at G3 still records trust (SECURITY.md §6 rule 3)."""
    repo = discovered_trusted
    ok(aipm(repo, "design", flags=["--yes"]))
    if command == "approve plan":
        ok(aipm(repo, "plan"))
    result = runner.invoke(app, ["-C", str(repo), *command.split()], input="y\n")
    assert result.exit_code == 0, result.output
    assert "trust these exact commands" in result.output
    assert _surface(repo)["trusted"]


def test_c063_auto_g3_records_no_trust() -> None:
    data = case("C-063")
    assert data["expected"]["exit_code"] == 6
