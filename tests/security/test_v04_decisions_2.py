"""The owner's decisions on the v0.4 review's open items, session 2 (docs/security/reviews/v0.4.md
§6.4; docs/security/reviews/v0.4-decisions-progress.md).

One section per decision; the smaller items of session 2 are in `test_v04_decisions.py`. This
module uses the integration fixtures (a planned clinic project, the stub agent), which that
module's own `isolated` fixture would clash with. Every test in a section failed before its
change.
"""

import dataclasses
import json
import os
import signal
import stat
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import (
    BlockedReason,
    ChangeSet,
    ChangeStatus,
    Ecosystem,
    FileChange,
    GateResult,
    GateStatus,
    NetworkProfile,
    PrepareDef,
    TaskStatus,
)
from aipm.execution import package_cache
from aipm.execution.package_cache import cache_env, remove_tree, run_cache, seed_cargo
from aipm.execution.process import running_groups
from aipm.execution.sandbox import ProcessKind, ProfilePaths, profile_for
from aipm.execution.worktree import cache_root
from aipm.gates import runner as runner_module
from aipm.gates.builtin import deps
from aipm.gates.builtin.deps import PrePrepare
from aipm.gates.command_gate import CommandOutcome, sandbox_for
from aipm.gates.context import GateContext
from aipm.gates.runner import run_gates
from aipm.llm.fake import FakeLLM
from aipm.scanners import registry
from aipm.scanners.registry import (
    Fetch,
    RegistryError,
    RegistryUnavailable,
    Response,
    first_release,
    go_escape,
)
from aipm.security.network import NetworkPolicy
from aipm.state.layout import repo_id
from tests.conftest import FakeSecrets, run_git
from tests.integration.build_flow import (
    FIXTURE,
    calls,
    copy_t002,
    fake_registry,
    package_steps,
    prepare_project,
    run_aipm_process,
    scenario,
    status,
    without_ac_review,
)
from tests.integration.conftest import (
    UserDirs,
    user_dirs,  # noqa: F401 - an autouse fixture
)
from tests.integration.flow import aipm, ok, tasks, trust
from tests.integration.test_verify_cli import PY, edit_config, install, verify
from tests.security.test_gates import gate, make_ctx

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")
NONE = NetworkPolicy(NetworkProfile.NONE)


@pytest.fixture
def dirs(user_dirs: UserDirs) -> UserDirs:  # noqa: F811 - the imported fixture
    return user_dirs


@pytest.fixture(autouse=True)
def fake_registries(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_registry(monkeypatch)


# ---------------------------------------------------------------- v0.2 O-2: a per-run package cache


@pytest.mark.parametrize(
    ("program", "expected"),
    [
        ("uv", {"UV_CACHE_DIR": "uv"}),
        ("/usr/local/bin/uv", {"UV_CACHE_DIR": "uv"}),
        ("python", {"PIP_CACHE_DIR": "pip"}),
        ("python3.13", {"PIP_CACHE_DIR": "pip"}),
        ("pip3.12", {"PIP_CACHE_DIR": "pip"}),
        ("npm", {"npm_config_cache": "npm"}),
        ("pnpm", {"npm_config_store_dir": "pnpm-store", "npm_config_cache_dir": "pnpm-cache"}),
        ("go", {"GOMODCACHE": "go-mod"}),
        ("gotestsum", {"GOMODCACHE": "go-mod"}),
        ("cargo", {"CARGO_HOME": "cargo"}),
        ("node", {}),
        ("gofmt", {}),
    ],
)
def test_each_package_manager_is_pointed_at_the_run_cache(
    tmp_path: Path, program: str, expected: dict[str, str]
) -> None:
    cache, temp = tmp_path / "cache", tmp_path / "temp"
    env = cache_env(program, cache, temp)
    go_build = {"GOCACHE": str(temp / "go-build")} if "GOMODCACHE" in expected else {}
    assert env == {k: str(cache / v) for k, v in expected.items()} | go_build


ENV_RECORDER = """
import os, sys
from pathlib import Path
out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
(out / sys.argv[2]).write_text(os.environ.get("PIP_CACHE_DIR", "unset"), encoding="utf-8")
"""


def test_prepare_and_the_gates_get_the_same_cache(tmp_path: Path) -> None:
    out = tmp_path / "seen"
    unit = gate("recorder", str(out), "unit")
    ctx = make_ctx(tmp_path, modules={"recorder": ENV_RECORDER}, gates={"unit": unit})
    prepare = PrepareDef(run=(PY, "-m", "recorder", str(out), "prepare"))
    cache = tmp_path / "run-cache"
    ctx = dataclasses.replace(
        ctx, cfg=ctx.cfg.model_copy(update={"prepare": prepare}), package_cache=cache
    )
    run_gates(ctx)
    assert (out / "prepare").read_text() == str(cache / "pip")
    assert (out / "unit").read_text() == str(cache / "pip")


def test_without_a_run_cache_the_attempt_gets_its_own(tmp_path: Path) -> None:
    """Never a fall back to the user's caches: a context with no run cache (verify) uses one
    inside the attempt's temp dir."""
    ctx = make_ctx(tmp_path)
    assert ctx.package_dir == ctx.ws.temp_dir / "packages"
    assert dataclasses.replace(ctx, package_cache=tmp_path / "c").package_dir == tmp_path / "c"


def test_prepare_may_write_only_the_run_cache(tmp_path: Path) -> None:
    home, cache = tmp_path / "home", tmp_path / "cache"
    paths = ProfilePaths(workspace=tmp_path / "w", temp_dir=tmp_path / "t", home=home,
                         package_cache=cache)  # fmt: skip
    prepare = profile_for(ProcessKind.PREPARE, NONE, paths, runtime="/bin/srt")
    assert prepare.allow_write == (tmp_path / "w", tmp_path / "t", cache)
    for kind in (ProcessKind.GATE, ProcessKind.AGENT, ProcessKind.SCANNER):
        assert cache not in profile_for(kind, NONE, paths, runtime="/bin/srt").allow_write


@pytest.mark.parametrize("kind", list(ProcessKind))
def test_no_process_may_write_cargo_settings_or_programs_in_the_cache(
    tmp_path: Path, kind: ProcessKind
) -> None:
    """Cargo runs `$CARGO_HOME/bin/cargo-<cmd>` before PATH and reads `$CARGO_HOME/config.toml`
    (a `rustc-wrapper`): one task's prepare must not plant them for the next task's gates."""
    cache = tmp_path / "cache"
    paths = ProfilePaths(workspace=tmp_path / "w", temp_dir=tmp_path / "t",
                         home=tmp_path / "home", package_cache=cache)  # fmt: skip
    deny = profile_for(kind, NONE, paths, runtime="/bin/srt").deny_write
    for name in ("config.toml", "config", "bin", "credentials.toml", "credentials"):
        assert cache / "cargo" / name in deny, name


def test_the_srt_profile_of_prepare_names_the_contexts_cache(tmp_path: Path) -> None:
    ctx = dataclasses.replace(make_ctx(tmp_path), runtime="/bin/srt")
    for cache, expected in ((None, ctx.ws.temp_dir / "packages"),
                            (tmp_path / "c", tmp_path / "c")):  # fmt: skip
        profile = sandbox_for(dataclasses.replace(ctx, package_cache=cache), ProcessKind.PREPARE,
                              ctx.cfg.security.network.prepare)  # fmt: skip
        assert profile is not None
        assert expected in profile.allow_write
        assert not any(str(p).startswith(str(ctx.home)) for p in profile.allow_write)


def test_the_run_cache_is_private_and_outside_the_repository(
    tmp_repo: Path, dirs: UserDirs
) -> None:
    path = run_cache(tmp_repo, "r-20261115-1200-abcd", home=dirs.home)
    assert path == cache_root() / "packages" / repo_id(tmp_repo) / "r-20261115-1200-abcd"
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    other = run_cache(tmp_repo, "r-20261115-1200-ef01", home=dirs.home)
    assert other != path


def test_a_run_cache_inside_the_repository_is_refused(
    tmp_repo: Path, dirs: UserDirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(package_cache, "cache_root", lambda: tmp_repo / "cache")
    with pytest.raises(PolicyViolation, match="inside the repository"):
        run_cache(tmp_repo, "r-20261115-1200-abcd", home=dirs.home)
    assert not (tmp_repo / "cache").exists()


@pytest.mark.parametrize("run_id", ["../escape", "r-1/x", "", "r-20261115-1200-ABCD/.."])
def test_a_malformed_run_id_is_refused(tmp_repo: Path, dirs: UserDirs, run_id: str) -> None:
    with pytest.raises(UsageError):
        run_cache(tmp_repo, run_id, home=dirs.home)


def test_removal_clears_read_only_directories_without_following_links(tmp_path: Path) -> None:
    """Go writes its module cache read-only; a link planted in it must not be followed."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    outside.chmod(0o555)
    cache = tmp_path / "cache"
    module = cache / "go-mod" / "example.com" / "m@v1.0.0"
    module.mkdir(parents=True)
    (module / "go.mod").write_text("module example.com/m\n", encoding="utf-8")
    (module / "go.mod").chmod(0o444)
    (module / "link").symlink_to(outside, target_is_directory=True)
    for directory in (module, module.parent, module.parent.parent):
        directory.chmod(0o555)
    try:
        remove_tree(cache)
        assert not cache.exists()
        assert (outside / "keep.txt").read_text() == "keep"
        assert stat.S_IMODE(outside.stat().st_mode) == 0o555
    finally:
        outside.chmod(0o755)


def test_removing_a_missing_cache_is_fine(tmp_path: Path) -> None:
    remove_tree(tmp_path / "never-made")


def test_the_users_cargo_config_is_seeded_into_the_run_cache(tmp_path: Path) -> None:
    """With `CARGO_HOME` moved, Cargo would stop reading the user's mirrors and source
    replacements; their config is copied in (never their credentials)."""
    home, cache = tmp_path / "home", tmp_path / "cache"
    (home / ".cargo").mkdir(parents=True)
    (home / ".cargo" / "config.toml").write_text("[net]\nretry = 5\n", encoding="utf-8")
    (home / ".cargo" / "credentials.toml").write_text("token = 'x'\n", encoding="utf-8")
    seed_cargo(cache, home)
    assert (cache / "cargo" / "config.toml").read_text() == "[net]\nretry = 5\n"
    assert not (cache / "cargo" / "credentials.toml").exists()


@pytest.mark.parametrize("kind", ["directory", "fifo", "huge"])
def test_only_a_regular_cargo_config_of_bounded_size_is_seeded(tmp_path: Path, kind: str) -> None:
    home, cache = tmp_path / "home", tmp_path / "cache"
    (home / ".cargo").mkdir(parents=True)
    config = home / ".cargo" / "config.toml"
    if kind == "directory":
        config.mkdir()
    elif kind == "fifo":
        os.mkfifo(config)
    else:
        config.write_bytes(b"#" * (package_cache.MAX_CARGO_CONFIG_BYTES + 1))
    seed_cargo(cache, home)
    assert not (cache / "cargo" / "config.toml").exists()


# --- through `aipm build` and `aipm verify`

RECORD_PREPARE = '''"""Records the pip cache the prepare step was given (a test fixture)."""

import os
import uuid
from pathlib import Path

given = os.environ.get("PIP_CACHE_DIR", "unset")
out = Path.home() / ".stub-claude" / "prepare"
out.mkdir(parents=True, exist_ok=True)
seen = "exists" if Path(given).is_dir() or not Path(given).exists() else "not a directory"
(out / uuid.uuid4().hex).write_text(given + "\\n" + seen, encoding="utf-8")
'''


def with_recording_prepare(repo: Path) -> None:
    (repo / "record_prepare.py").write_text(RECORD_PREPARE, encoding="utf-8")
    run_git(repo, "add", "record_prepare.py")
    run_git(repo, "commit", "-q", "-m", "a prepare step that records its cache")

    def change(layer: dict[str, object]) -> None:
        layer["prepare"] = {"run": [PY, "-m", "record_prepare"], "network": "none"}
        allowed = list(layer["allowed_executables"])  # type: ignore[call-overload]
        layer["allowed_executables"] = [*allowed, [PY, "-m", "record_prepare"]]

    edit_config(repo, change)
    trust(repo)


def recorded(home: Path) -> list[str]:
    out = home / ".stub-claude" / "prepare"
    return sorted(p.read_text().splitlines()[0] for p in out.iterdir()) if out.is_dir() else []


@pytest.fixture
def project(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    monkeypatch: pytest.MonkeyPatch,
    dirs: UserDirs,
) -> Path:
    del fake_secrets
    fake_llm("clinic")
    repo = prepare_project(tmp_repo, monkeypatch, dirs.home)
    without_ac_review(repo)
    with_recording_prepare(repo)
    return repo


def test_a_builds_tasks_share_one_cache_that_is_gone_after_the_run(
    project: Path, dirs: UserDirs
) -> None:
    scenario(dirs.home, {
        "T-002": [{"steps": copy_t002()}],
        "T-006": [{"steps": package_steps(project, "T-006", "staff", "tests/staff/test_staff.py")}],
    })  # fmt: skip
    result = aipm(project, "build", "--only", "T-002,T-006", flags=["--json"])
    assert result.exit_code == 0, result.stdout
    run_id = json.loads(result.stdout)["data"]["run_id"]
    expected = cache_root() / "packages" / repo_id(project) / run_id / "pip"
    seen = recorded(dirs.home)
    assert len(seen) == 2, seen
    assert set(seen) == {str(expected)}
    assert not expected.parent.exists()


def test_an_interrupted_build_removes_its_cache(project: Path, dirs: UserDirs) -> None:
    scenario(dirs.home, {"T-002": [{"steps": [{"sleep": 3}, *copy_t002()]}]})
    results: list[object] = []
    thread = threading.Thread(
        target=lambda: results.append(run_aipm_process(project, "build", "--only", "T-002")),
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 60
    while not calls(dirs.home):
        assert time.monotonic() < deadline, "the agent never started"
        time.sleep(0.05)
    runs = cache_root() / "packages" / repo_id(project)
    assert runs.is_dir() and any(runs.iterdir()), "the run made no cache"
    (pid,) = running_groups()
    os.kill(pid, signal.SIGTERM)
    thread.join(timeout=120)
    assert results, "aipm did not stop"
    assert getattr(results[0], "returncode", None) == 130
    assert status(project, "T-002") is TaskStatus.DONE
    assert not any(runs.iterdir())


def test_verify_gives_its_prepare_a_cache_of_its_own(project: Path, dirs: UserDirs) -> None:
    ok(aipm(project, "prompt", "T-002"))
    install(FIXTURE / "T-002", project)
    code, envelope = verify(project)
    assert code == 0, envelope
    (seen,) = recorded(dirs.home)
    assert Path(seen).name == "pip"
    assert Path(seen).parent.name == "packages"
    assert Path(seen).parent.parent.name.startswith("aipm-verify-")
    assert not Path(seen).parent.parent.exists()


# ---------------------------------------------------------------- N-1: Go modules looked up first

GO_BEFORE = "module example.com/app\n\ngo 1.22\n"
GO_PREPARE = PrepareDef(run=("go", "mod", "download"))


def go_mod_adding(*modules: str) -> FileChange:
    requires = "".join(f"\t{m} v1.0.0\n" for m in modules)
    return FileChange(path="go.mod", status=ChangeStatus.MODIFIED, mode="100644",
                      before=GO_BEFORE, after=f"{GO_BEFORE}\nrequire (\n{requires})\n")  # fmt: skip


def go_proxy(answers: dict[str, object]) -> tuple[list[str], Fetch]:
    """A fake Go proxy: each module answers 'ok', 'new', 'missing', 'tagless', an HTTP status,
    or an exception to raise."""
    asked: list[str] = []

    def fetch(url: str, headers: Mapping[str, str]) -> Response:
        assert headers.get("Disable-Module-Fetch") == "true"
        asked.append(url)
        module = next(m for m in answers if go_escape(m) in url)
        answer = answers[module]
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, int):
            return Response(answer, b"")
        if answer == "missing":
            return Response(404, b"")
        if url.endswith("/@v/list"):
            return Response(200, b"" if answer == "tagless" else b"v1.0.0\n")
        when = datetime.now(UTC) if answer == "new" else datetime(2015, 1, 1, tzinfo=UTC)
        return Response(200, json.dumps({"Time": when.isoformat()}).encode())

    return asked, fetch


@pytest.fixture
def prepared(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stands in for the prepare step (no `go` here); records that it ran."""
    ran: list[str] = []

    def fake(ctx: object) -> CommandOutcome:
        del ctx
        ran.append("prepare")
        result = GateResult(name="prepare", status=GateStatus.PASS, required=True, summary="ok")
        return CommandOutcome(result, None, "")

    monkeypatch.setattr(runner_module, "run_prepare", fake)
    return ran


def go_ctx(tmp_path: Path, fetch: Fetch, *modules: str, prepare: PrepareDef = GO_PREPARE
           ) -> GateContext:  # fmt: skip
    ctx = make_ctx(tmp_path, modules={"unitmod": "import sys; sys.exit(0)\n"},
                   gates={"unit": gate("unitmod")})  # fmt: skip
    changes = ChangeSet("a" * 40, files=(go_mod_adding(*modules),) if modules else ())
    cfg = ctx.cfg.model_copy(update={"prepare": prepare})
    return dataclasses.replace(ctx, cfg=cfg, changes=changes, fetch=fetch)


@pytest.mark.parametrize(
    ("answer", "rule"),
    [("missing", "missing"), ("new", "too-new"), ("tagless", "unknown-age")],
)
def test_a_go_module_that_fails_the_lookup_fails_the_attempt_before_prepare(
    tmp_path: Path, prepared: list[str], answer: str, rule: str
) -> None:
    asked, fetch = go_proxy({"example.com/newmod": answer})
    run = run_gates(go_ctx(tmp_path, fetch, "example.com/newmod"))
    assert prepared == [], "prepare must not fetch a module the lookup refused"
    assert asked, "the module was looked up"
    result = {r.name: r for r in run.results}
    assert result["prepare"].status is GateStatus.FAIL
    assert [f.rule for f in result["prepare"].findings] == [rule]
    assert result["unit"].status is GateStatus.ERROR  # not run
    assert run.registry_unavailable is None
    assert not run.passed()


def test_a_lookalike_go_module_fails_the_attempt_before_prepare(
    tmp_path: Path, prepared: list[str]
) -> None:
    _, fetch = go_proxy({"github.com/stretchr-io/testify": "ok"})
    run = run_gates(go_ctx(tmp_path, fetch, "github.com/stretchr-io/testify"))
    assert prepared == []
    prepare = next(r for r in run.results if r.name == "prepare")
    assert prepare.status is GateStatus.FAIL
    assert "typosquat" in [f.rule for f in prepare.findings]


@pytest.mark.parametrize(
    "answer",
    [
        503,
        500,
        429,
        RegistryUnavailable("cannot reach the registry (URLError)"),
        RegistryUnavailable("the registry took too long to answer (over 60 s)"),
    ],
    ids=["503", "500", "429", "unreachable", "deadline"],
)
def test_a_lookup_that_cannot_be_made_holds_prepare_and_asks_to_block(
    tmp_path: Path, prepared: list[str], answer: object
) -> None:
    _, fetch = go_proxy({"example.com/ok": "ok", "example.com/newmod": answer})
    run = run_gates(go_ctx(tmp_path, fetch, "example.com/ok", "example.com/newmod"))
    assert prepared == []
    assert run.registry_unavailable is not None
    assert "example.com/newmod" in run.registry_unavailable
    prepare = next(r for r in run.results if r.name == "prepare")
    assert prepare.status is GateStatus.ERROR
    assert not run.passed()


def test_modules_that_pass_the_lookup_let_prepare_run(tmp_path: Path, prepared: list[str]) -> None:
    asked, fetch = go_proxy({"example.com/newmod": "ok"})
    run = run_gates(go_ctx(tmp_path, fetch, "example.com/newmod"))
    assert prepared == ["prepare"]
    assert len(asked) == 2  # the version list and the oldest tag's info
    assert run.registry_unavailable is None


def test_no_lookup_without_a_new_go_module(tmp_path: Path, prepared: list[str]) -> None:
    asked, fetch = go_proxy({})
    run_gates(go_ctx(tmp_path, fetch))
    assert (asked, prepared) == ([], ["prepare"])


def test_no_lookup_for_a_prepare_step_that_is_not_go_mod_download(
    tmp_path: Path, prepared: list[str]
) -> None:
    """Only `go mod download` gets the Go proxy, which fetches module paths from their origin."""
    asked, fetch = go_proxy({"example.com/newmod": "missing"})
    uv = PrepareDef(run=("uv", "sync", "--frozen"))
    run_gates(go_ctx(tmp_path, fetch, "example.com/newmod", prepare=uv))
    assert (asked, prepared) == ([], ["prepare"])


def test_no_lookup_when_the_checks_already_hold_prepare(
    tmp_path: Path, prepared: list[str]
) -> None:
    asked, fetch = go_proxy({"example.com/newmod": "ok"})
    run = run_gates(go_ctx(tmp_path, fetch, "example.com/newmod"), hold_prepare="refused")
    assert (asked, prepared, run.registry_unavailable) == ([], [], None)


@pytest.mark.parametrize("status", [500, 502, 503, 504, 429, 403, 418])
def test_a_status_that_is_no_answer_means_the_registry_is_unavailable(status: int) -> None:
    with pytest.raises(RegistryUnavailable):
        registry._status(Response(status, b""))  # pyright: ignore[reportPrivateUsage]


def test_an_unreadable_answer_means_the_registry_is_unavailable() -> None:
    with pytest.raises(RegistryUnavailable):
        registry._json_object(Response(200, b"<html>proxy login</html>"))  # pyright: ignore[reportPrivateUsage]


def test_a_tagless_module_is_an_answer_not_an_outage() -> None:
    _, fetch = go_proxy({"example.com/newmod": "tagless"})
    with pytest.raises(RegistryError) as info:
        first_release(Ecosystem.GO, "example.com/newmod", fetch=fetch)
    assert not isinstance(info.value, RegistryUnavailable)


def test_the_deadline_and_a_failed_connection_mean_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "DEADLINE_S", 0.05)

    def slow(url: str, headers: Mapping[str, str]) -> Response:
        del url, headers
        time.sleep(1)
        return Response(200, b"")

    with pytest.raises(RegistryUnavailable, match="too long"):
        registry._bounded(slow, "https://proxy.golang.org/x", {})  # pyright: ignore[reportPrivateUsage]

    class Refusing:
        def open(self, *_: object, **__: object) -> None:
            raise OSError("connection refused")

    monkeypatch.setattr(registry.urllib.request, "build_opener", lambda *_: Refusing())
    with pytest.raises(RegistryUnavailable, match="cannot reach"):
        registry._get("https://proxy.golang.org/x", {})  # pyright: ignore[reportPrivateUsage]


def test_the_deps_gate_still_reports_an_outage_as_an_error(tmp_path: Path) -> None:
    _, fetch = go_proxy({"example.com/newmod": 503})
    ctx = go_ctx(tmp_path, fetch, "example.com/newmod")
    findings, errors = deps.check_new(ctx, ctx.now)
    assert findings == []
    assert len(errors) == 1 and "example.com/newmod" in errors[0]


# --- through `aipm build` and `aipm verify`


@pytest.fixture
def proxy_down(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every attempt's lookup before prepare finds the Go proxy unreachable (the clinic project
    is Python, so the decision is replaced, not reached)."""

    def unavailable(ctx: object) -> PrePrepare:
        del ctx
        return PrePrepare(unavailable=("go example.com/newmod: cannot reach the registry",))

    monkeypatch.setattr(runner_module, "lookup_before_prepare", unavailable)


def test_a_build_blocks_the_task_when_the_proxy_cannot_be_asked(
    project: Path, dirs: UserDirs, proxy_down: None
) -> None:
    """No retry, so no budget is spent on attempts that cannot pass."""
    scenario(dirs.home, {"T-002": [{"steps": copy_t002()}, {"steps": copy_t002()}]})
    result = aipm(project, "build", "--only", "T-002", flags=["--json"])
    assert result.exit_code == 3, result.stdout
    (outcome,) = json.loads(result.stdout)["data"]["tasks"]
    assert (outcome["status"], outcome["reason"]) == ("blocked", "registry_unavailable")
    assert len(calls(dirs.home)) == 1
    assert recorded(dirs.home) == [], "prepare never ran"
    task = next(t for t in tasks(project).tasks if t.id == "T-002")
    assert task.blocked is not None
    assert task.blocked.reason is BlockedReason.REGISTRY_UNAVAILABLE
    assert task.attempts == 1


def test_verify_blocks_the_task_and_exits_8_when_the_proxy_cannot_be_asked(
    project: Path, dirs: UserDirs, proxy_down: None
) -> None:
    ok(aipm(project, "prompt", "T-002"))
    install(FIXTURE / "T-002", project)
    code, envelope = verify(project)
    assert code == 8, envelope
    assert recorded(dirs.home) == []
    task = next(t for t in tasks(project).tasks if t.id == "T-002")
    assert task.status is TaskStatus.BLOCKED
    assert task.blocked is not None
    assert task.blocked.reason is BlockedReason.REGISTRY_UNAVAILABLE
