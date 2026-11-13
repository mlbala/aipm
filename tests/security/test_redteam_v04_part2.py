"""The v0.4 security red-team pass, part 2: automation and extension surfaces (build prompt 09
v0.4; docs/security/reviews/v0.4-progress.md).

`aipm auto`, plugins, OpenTelemetry, the go and rust-cargo stacks and the deps gate for Go and
crates. One section per finding (RT04-n); every test in a finding section failed before its
fix. The "held" sections at the end pin controls the pass attacked without breaking them.
"""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

from aipm.app import auto
from aipm.app import build as build_use_case
from aipm.cli import output as cli_output
from aipm.cli.main import app
from aipm.config import loader as config_loader
from aipm.domain.errors import HumanInputRequired, PolicyViolation
from aipm.domain.models import APPROVED_NAMES, ApprovalGate, ArtifactKind, NetworkProfile
from aipm.domain.phase import Phase, PhaseReport
from aipm.execution import git, worktree
from aipm.execution.sandbox import ProcessKind, ProfilePaths, profile_for
from aipm.gates import command_gate
from aipm.gates.command_gate import toolchain_env
from aipm.security.network import NetworkPolicy
from aipm.state import done_record
from aipm.state.private_files import write_private
from aipm.state.store import open_store
from aipm.state.trust_store import (
    execution_surface,
    hash_surface,
    render_surface,
    repo_agent_config,
)
from tests.conftest import FakeSecrets, run_git
from tests.fakes.project import clinic_config
from tests.integration.build_flow import calls, copy_t002, fake_registry, prepare_project, scenario
from tests.integration.conftest import (
    UserDirs,
    user_dirs,  # noqa: F401 - an autouse fixture
)
from tests.integration.flow import aipm, approvals, discovered, ok, runner, trust
from tests.integration.test_verify_cli import edit_config
from tests.security.test_dispatch_surface import bare_off

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


# ---------------------------------------------------------------- RT04-9: auto cycles


class _CountingSteps:
    def __init__(self) -> None:
        self.ran: list[str] = []

    def run(self, step: auto.AutoStep, *, yes: bool) -> None:
        del yes
        self.ran.append(step.command)


def _cycle(*commands: str) -> Callable[[Path | None], PhaseReport]:
    """Phase reports that go round `commands` for ever: each step "succeeds" but the state
    comes back."""
    reports = [PhaseReport(Phase.DESIGN_DRAFT, next_command=c) for c in commands]
    count = [0]

    def report(_: Path | None) -> PhaseReport:
        count[0] += 1
        return reports[(count[0] - 1) % len(reports)]

    return report


@pytest.mark.parametrize(
    "commands",
    [
        ("aipm design --regenerate", "aipm plan"),
        ("aipm plan", "aipm approve plan", "aipm design --regenerate"),
    ],
)
def test_auto_stops_when_a_state_comes_back(commands: tuple[str, ...]) -> None:
    steps = _CountingSteps()
    with pytest.raises(HumanInputRequired, match=r"changed nothing|came back"):
        auto.run(None, auto.AutoOptions(yes=True), steps, report=_cycle(*commands),
                 trust=lambda _: None)  # fmt: skip
    assert len(steps.ran) == len(commands), steps.ran


def test_auto_still_runs_a_plan_that_moves_forward() -> None:
    order = ["aipm design", "aipm approve design", "aipm plan", "aipm approve plan"]
    reports = [PhaseReport(Phase.PRD_APPROVED, next_command=c) for c in order]
    reports.append(PhaseReport(Phase.BUILT))
    steps = _CountingSteps()
    it = iter(reports)
    auto.run(None, auto.AutoOptions(yes=True), steps, report=lambda _: next(it),
             trust=lambda _: None)  # fmt: skip
    assert steps.ran == order


def test_c064_a_cycle_stops_with_exit_4() -> None:
    assert case("C-064")["expected"]["exit_code"] == int(HumanInputRequired.exit_code)


# ---------------------------------------------------------------- RT04-10: deep JSON in readers


def _deep(depth: int) -> str:
    return '{"mcpServers": ' + "[" * depth + "]" * depth + "}"


@pytest.mark.parametrize("name", [".mcp.json", ".claude/settings.json"])
@pytest.mark.parametrize("depth", [20_000, 120_000])
def test_a_deep_repository_agent_file_is_pinned_by_hash(
    tmp_path: Path, name: str, depth: int
) -> None:
    """A cloned repository's `.mcp.json` or `.claude/settings.json` nested too deeply made every
    trust check crash with a traceback when bare mode is off (Part 1 observation 8)."""
    repo = tmp_path / "repo"
    (repo / ".claude").mkdir(parents=True)
    text = _deep(depth)
    (repo / name).write_text(text, encoding="utf-8")
    agent = repo_agent_config(repo, bare_off())  # type: ignore[arg-type]
    assert agent is not None
    entry = agent[name]
    assert entry["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert "content" not in entry and entry["error"]
    surface = execution_surface(clinic_config(), repo_agent=agent)
    assert "repository hooks and MCP servers" in "\n".join(
        render_surface(surface, hash_surface(surface))
    )


def test_deep_private_records_read_as_none(tmp_path: Path, dirs: UserDirs) -> None:
    """aipm's own records outside the repository fail closed on a deep document: no done
    record, no recorded integration tip (exit 6 on merge), no cached reply, no spend."""
    del dirs
    repo = tmp_path / "repo"
    repo.mkdir()
    deep = ("[" * 20_000 + "]" * 20_000).encode()  # under the 64 KiB limits
    write_private(done_record._path(repo), deep)  # pyright: ignore[reportPrivateUsage]
    write_private(worktree._tips_path(repo), deep)  # pyright: ignore[reportPrivateUsage]
    assert done_record._load(repo) == {}  # pyright: ignore[reportPrivateUsage]
    assert worktree.recorded_tip(repo, "aipm/integration") is None
    worktree.record_tip(repo, "aipm/integration", "a" * 40)
    assert worktree.recorded_tip(repo, "aipm/integration") == "a" * 40


def test_c065_deep_agent_file_is_pinned() -> None:
    assert "mcpServers" in case("C-065")["input"]["text"]


# ---------------------------------------------------------------- RT04-11: Go and Cargo settings


TOOLCHAIN_PLANTS = ["go.work", "GO.WORK", "go.work.sum", ".cargo", ".Cargo", "rust-toolchain",
                    "rust-toolchain.toml"]  # fmt: skip
"""Go looks for `go.work`, Cargo for `.cargo/config(.toml)` and rustup for a toolchain file in
the working directory and every directory above it: the task worktrees' parents are aipm's."""


@pytest.mark.parametrize("name", TOOLCHAIN_PLANTS)
@pytest.mark.parametrize("level", [0, 1, 2])
def test_toolchain_settings_beside_the_worktrees_are_refused(
    tmp_path: Path, tmp_repo: Path, name: str, level: int
) -> None:
    manager = worktree.WorktreeManager(tmp_repo, root=tmp_path / "cache" / "worktrees")
    manager.root.mkdir(parents=True)
    where = [manager.root, manager.root.parent, manager.root.parent.parent][level]
    planted = where / name
    if name.casefold() == ".cargo":
        planted.mkdir()
        (planted / "config.toml").write_text('[build]\nrustc-wrapper = "/tmp/w"\n')
    else:
        planted.write_text("go 1.24\nuse ../T-002\n")
    with pytest.raises(PolicyViolation, match="Go, Cargo or rustup"):
        manager.check_parents()
    with pytest.raises(PolicyViolation):
        manager.create("T-002", run_git(tmp_repo, "rev-parse", "HEAD").strip())


def test_a_clean_worktree_parent_passes(tmp_path: Path, tmp_repo: Path) -> None:
    manager = worktree.WorktreeManager(tmp_repo, root=tmp_path / "cache" / "worktrees")
    manager.root.mkdir(parents=True)
    manager.check_parents()


def test_a_planted_cargo_config_beside_the_worktrees_stops_the_build(
    project: Path, dirs: UserDirs
) -> None:
    manager = worktree.WorktreeManager(project)
    manager.root.mkdir(parents=True, exist_ok=True)
    (manager.root.parent / ".cargo").mkdir(exist_ok=True)
    (manager.root.parent / ".cargo" / "config.toml").write_text('[alias]\nnextest = "run"\n')
    scenario(dirs.home, {"T-002": [{"steps": copy_t002()}]})
    result = aipm(project, "build", "--only", "T-002", flags=["--json"])
    assert result.exit_code == 6, result.output
    assert not calls(dirs.home), "no agent ran"


@pytest.mark.parametrize("has_go_work", [False, True])
def test_go_never_switches_toolchain_or_takes_an_outside_workspace(
    tmp_path: Path, has_go_work: bool
) -> None:
    root = tmp_path / "wt"
    root.mkdir()
    if has_go_work:
        (root / "go.work").write_text("go 1.24\nuse .\n")
    env = toolchain_env(root)
    assert env["GOTOOLCHAIN"] == "local"
    assert env.get("GOWORK") == (None if has_go_work else "off")


TOOLCHAIN_USER_FILES = (".cargo/config.toml", ".cargo/config", ".rustup/settings.toml",
                        "Library/Application Support/go/env", ".config/go/env")  # fmt: skip


@pytest.mark.parametrize("kind", list(ProcessKind))
def test_the_users_toolchain_settings_are_denied_to_every_process(
    tmp_path: Path, kind: ProcessKind
) -> None:
    paths = ProfilePaths(workspace=tmp_path / "wt", temp_dir=tmp_path / "t", home=tmp_path / "h")
    profile = profile_for(kind, NetworkPolicy(NetworkProfile.NONE), paths, runtime="/bin/srt")
    for rel in TOOLCHAIN_USER_FILES:
        assert paths.home / rel in profile.deny_write, (kind, rel)


def test_the_users_toolchain_settings_are_watched_in_a_build_only(
    tmp_repo: Path, tmp_path: Path
) -> None:
    labels = set(git.integrity_snapshot(tmp_repo, tmp_path))
    assert "~/.cargo/config.toml" not in labels, "the user's own go env -w must not block verify"
    wider = set(git.integrity_snapshot(tmp_repo, tmp_path, extra=git.BUILD_WATCH))
    assert {f"~/{rel}" for rel in TOOLCHAIN_USER_FILES} <= wider


@pytest.mark.parametrize("rel", [".cargo/config.toml", "Library/Application Support/go/env"])
def test_a_gate_or_agent_writing_toolchain_settings_is_severe(
    project: Path, dirs: UserDirs, rel: str
) -> None:
    write = {"home_write": rel, "text": "GOFLAGS=-toolexec=/tmp/x\n"}
    scenario(dirs.home, {"T-002": [{"steps": [*copy_t002(), write]}]})
    result = aipm(project, "build", "--only", "T-002", flags=["--json"])
    assert result.exit_code == 6, result.output
    (outcome,) = json.loads(result.stdout)["data"]["tasks"]
    assert (outcome["status"], outcome["reason"]) == ("blocked", "policy_violation")


def test_c066_every_planted_toolchain_file_is_refused_or_watched() -> None:
    text = case("C-066")["input"]["text"]
    for rel in TOOLCHAIN_USER_FILES:
        assert rel in text


# ---------------------------------------------------------------- RT04-12: borrowed Go network


GO_HOSTS = {"proxy.golang.org", "sum.golang.org", "storage.googleapis.com"}


@pytest.mark.parametrize(
    "argv",
    [
        ["go", "test", "./..."],
        ["/usr/local/go/bin/go", "build", "./..."],
        ["go", "vet", "./..."],
        ["go", "-C", "sub", "test", "./..."],
        ["go", "run", "mod", "download"],
        ["go", "mod", "verify"],
        ["gotestsum", "--junitfile", "r.xml", "--", "./..."],
        ["go", "test", "mod", "download"],
    ],
)
def test_only_go_mod_download_opens_the_go_proxy_in_prepare(argv: list[str]) -> None:
    """ADR-0029 opens the Go proxy and its storage host (anyone's bucket) to the prepare step
    because `go mod download` runs no repository code; any other go or gotestsum prepare
    command (a test run) borrowed that profile by its program name."""
    policy = command_gate._network(NetworkProfile.REGISTRIES, argv, ProcessKind.PREPARE)  # pyright: ignore[reportPrivateUsage]
    assert not GO_HOSTS & set(policy.domains), argv


@pytest.mark.parametrize(
    "argv", [["go", "mod", "download"], ["/opt/go/bin/go", "mod", "download", "-x"]]
)
def test_go_mod_download_keeps_the_go_proxy(argv: list[str]) -> None:
    policy = command_gate._network(NetworkProfile.REGISTRIES, argv, ProcessKind.PREPARE)  # pyright: ignore[reportPrivateUsage]
    assert set(policy.domains) == GO_HOSTS


def test_c067_go_test_in_prepare_gets_no_go_hosts() -> None:
    argv = case("C-067")["input"]["text"].split()
    policy = command_gate._network(NetworkProfile.REGISTRIES, argv, ProcessKind.PREPARE)  # pyright: ignore[reportPrivateUsage]
    assert not GO_HOSTS & set(policy.domains)
