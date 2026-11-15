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
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import NetworkProfile, PrepareDef, TaskStatus
from aipm.execution import package_cache
from aipm.execution.package_cache import cache_env, remove_tree, run_cache, seed_cargo
from aipm.execution.process import running_groups
from aipm.execution.sandbox import ProcessKind, ProfilePaths, profile_for
from aipm.execution.worktree import cache_root
from aipm.gates.command_gate import sandbox_for
from aipm.gates.runner import run_gates
from aipm.llm.fake import FakeLLM
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
from tests.integration.flow import aipm, ok, trust
from tests.integration.test_verify_cli import PY, edit_config, install, verify
from tests.security.test_gates import gate, make_ctx

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")
NONE = NetworkPolicy(NetworkProfile.NONE)


@pytest.fixture
def dirs(user_dirs: UserDirs) -> UserDirs:  # noqa: F811 - the imported fixture
    return user_dirs


@pytest.fixture(autouse=True)
def registry(monkeypatch: pytest.MonkeyPatch) -> None:
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
