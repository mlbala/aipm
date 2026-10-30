"""The v0.2 security red-team pass (build prompt 09; docs/security/reviews/v0.2.md).

One section per finding, RT02-1 to RT02-8. Every test here failed before its fix, except where a
comment says it pins a control that held. Corpus cases C-038 to C-046 run through the real code
paths: the hardened git wrapper, the post-change checks, the gate runner, the deps and AC review
gates, and `aipm prompt` and `aipm verify` on the clinic example.
"""

import json
import os
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

from aipm.config.schema import Config
from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import (
    AcceptanceCriterion,
    BuiltinGate,
    ChangeSet,
    ChangeStatus,
    DependencyAdd,
    Ecosystem,
    FileChange,
    GateDef,
    GateResult,
    GateStatus,
    GateWorkspace,
    RoleName,
    Task,
    TaskSize,
    TaskStatus,
    TaskType,
)
from aipm.execution import git
from aipm.gates import runner
from aipm.gates.builtin import ac_review, deps
from aipm.gates.context import GateContext
from aipm.gates.runner import run_gates
from aipm.llm.fake import FakeLLM, FakeResponse
from aipm.roles.ac_reviewer import ACReview, ACReviewInput, CriterionVerdict, Verdict
from aipm.scanners.registry import Response
from aipm.security.diff_checks import (
    CheckPolicy,
    Kind,
    check_changes,
    is_dependency_path,
    is_watched,
    lock_deps,
    manifest_deps,
    new_lock_packages,
    tamper_signs,
)
from aipm.security.paths import denied_for_llm
from aipm.security.redact import Redactor
from tests.conftest import run_git
from tests.integration.conftest import UserDirs, user_dirs  # noqa: F401 - an autouse fixture
from tests.integration.flow import aipm, ok, planned, tasks, trust
from tests.integration.test_verify_cli import FIXTURE, STUBS, edit_config, install, use_test_gates

CORPUS = Path(__file__).parent / "corpus"
PY = sys.executable
POLICY = CheckPolicy()


def case_text(case_id: str) -> str:
    (path,) = CORPUS.glob(f"{case_id}-*.yaml")
    data: dict[str, Any] = YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))
    return str(data["input"]["text"])


@pytest.fixture
def home(user_dirs: UserDirs) -> Path:  # noqa: F811 - the imported fixture
    """The isolated home, with a global git config that names an identity and nothing else."""
    (user_dirs.home / ".gitconfig").write_text(
        "[user]\n\tname = aipm owner\n\temail = owner@example.invalid\n", encoding="utf-8"
    )
    return user_dirs.home


def append_config(repo: Path, text: str) -> None:
    with (repo / ".git" / "config").open("a", encoding="utf-8") as handle:
        handle.write(text)


def task(**kw: object) -> Task:
    base: dict[str, object] = {
        "id": "T-002", "title": "Slots", "type": TaskType.FEATURE, "size": TaskSize.M,
        "owns_files": ["src/clinic/booking/**", "tests/booking/**", "pyproject.toml",
                       "package.json", "requirements.txt", "uv.lock", "package-lock.json"],
        "acceptance": [AcceptanceCriterion(id="AC-T002-1", text="x")],
    }  # fmt: skip
    base.update(kw)
    return Task.model_validate(base)


def change(path: str, before: str | None, after: str | None, **kw: Any) -> FileChange:
    status = ChangeStatus.ADDED if before is None else ChangeStatus.MODIFIED
    return FileChange(path=path, status=status, mode="100644", before=before, after=after, **kw)


def violations(*changes: FileChange, t: Task | None = None) -> list[tuple[Kind, str, str]]:
    found = check_changes(ChangeSet("a" * 40, files=changes), t or task(), POLICY)
    return [(v.kind, v.path, v.detail) for v in found]


# ---------------------------------------------------------------- RT02-1 repository git config


def test_every_git_call_turns_off_config_hooks_lazy_fetch_and_transports() -> None:
    """git 2.5x runs `hook.<name>.command` despite `core.hooksPath=/dev/null` and
    `--no-verify`; `hook.<event>.enabled=false` stops it. A promisor remote's `ext::` URL is a
    command; `GIT_NO_LAZY_FETCH` and `GIT_ALLOW_PROTOCOL` keep git from ever reaching it."""
    env = git.GIT_ENV
    assert env["GIT_NO_LAZY_FETCH"] == "1"
    assert env["GIT_ALLOW_PROTOCOL"] == "none"
    pairs = {
        env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
        for i in range(int(env["GIT_CONFIG_COUNT"]))
    }
    events = ("post-commit", "post-index-change", "prepare-commit-msg", "pre-commit",
              "commit-msg", "reference-transaction", "pre-auto-gc", "post-checkout")  # fmt: skip
    for event in events:
        assert pairs[f"hook.{event}.enabled"] == "false", event
    assert pairs["gc.auto"] == "0"
    assert pairs["maintenance.auto"] == "false"


def _filtered_repo(repo: Path, marker: Path) -> None:
    (repo / ".gitattributes").write_text("* filter=probe\n", encoding="utf-8")
    (repo / "a.txt").write_text("hello\n", encoding="utf-8")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "attributes")
    append_config(repo, case_text("C-038").replace("<marker>", str(marker)))


def test_a_repository_filter_driver_is_refused_and_never_runs(
    tmp_repo: Path, home: Path, tmp_path: Path
) -> None:
    marker = tmp_path / "filter-ran"
    _filtered_repo(tmp_repo, marker)
    head = git.head_sha(tmp_repo)
    (tmp_repo / "a.txt").write_text("changed\n", encoding="utf-8")
    calls: list[Callable[[], object]] = [
        lambda: git.snapshot_files(tmp_repo, head, watch_ignored=lambda _: True),
        lambda: git.diff_text(tmp_repo, head, ["a.txt"], max_bytes=4096),
        lambda: git.commit(tmp_repo, ["a.txt"], message="m", trailers=[]),
        lambda: git.status_porcelain_v2(tmp_repo),
        lambda: git.diff_stats(tmp_repo, head),
        lambda: git.staged_ids(tmp_repo, ["a.txt"]),
    ]
    for call in calls:
        with pytest.raises(PolicyViolation, match=r"filter\.probe\.clean"):
            call()
    assert not marker.exists()
    assert run_git(tmp_repo, "log", "-1", "--format=%s").strip() == "attributes"


@pytest.mark.parametrize(
    "setting",
    [
        '[hook "probe"]\n\tcommand = true\n\tevent = post-commit\n',
        '[trailer "x"]\n\tcmd = true\n',
        '[gpg "ssh"]\n\tdefaultKeyCommand = true\n',
        "[core]\n\tworktree = /\n",
        '[filter "Probe"]\n\tprocess = true\n',
    ],
)
def test_repository_settings_that_run_a_program_are_refused(
    tmp_repo: Path, home: Path, setting: str
) -> None:
    append_config(tmp_repo, setting)
    with pytest.raises(PolicyViolation) as info:
        git.check_repo_config(tmp_repo)
    assert info.value.exit_code == 6
    assert "global git config" in (info.value.hint or "")


def test_an_included_repository_setting_is_refused(tmp_repo: Path, home: Path) -> None:
    """git follows `[include]` itself (`git config --list --includes`), so a setting moved into
    an included file is still the repository's."""
    (tmp_repo / ".git" / "extra.cfg").write_text('[filter "x"]\n\tclean = cat\n', "utf-8")
    append_config(tmp_repo, "[include]\n\tPATH = extra.cfg\n")
    with pytest.raises(PolicyViolation, match=r"filter\.x\.clean"):
        git.check_repo_config(tmp_repo)


def test_settings_git_overrides_or_that_run_nothing_pass(tmp_repo: Path, home: Path) -> None:
    """Held before this pass and still allowed: the `-c` hardening outranks these."""
    append_config(tmp_repo, "[core]\n\thooksPath = .githooks\n\tfsmonitor = /x\n"
                  "[gpg]\n\tprogram = /x\n[diff \"x\"]\n\ttextconv = /x\n")  # fmt: skip
    git.check_repo_config(tmp_repo)
    run_git(tmp_repo, "config", "core.worktree", str(tmp_repo))  # a submodule checkout's own
    git.check_repo_config(tmp_repo)


def test_a_filter_in_the_global_config_is_the_user_s_own(tmp_repo: Path, home: Path) -> None:
    with (home / ".gitconfig").open("a", encoding="utf-8") as handle:
        handle.write('[filter "lfs"]\n\tclean = cat\n\tsmudge = cat\n')
    git.check_repo_config(tmp_repo)
    assert git.repo_config_entries(tmp_repo)  # local settings are listed, global ones are not
    assert all(not key.startswith("filter.") for key, _ in git.repo_config_entries(tmp_repo))


def test_config_hooks_never_run_in_snapshots_or_commits(
    tmp_repo: Path, home: Path, tmp_path: Path
) -> None:
    marker = tmp_path / "hook-ran"
    with (home / ".gitconfig").open("a", encoding="utf-8") as handle:
        handle.write(case_text("C-039").replace("<marker>", str(marker)))
    head = git.head_sha(tmp_repo)
    (tmp_repo / "b.py").write_text("x = 1\n", encoding="utf-8")
    git.snapshot_files(tmp_repo, head, watch_ignored=lambda _: True)
    git.diff_text(tmp_repo, head, ["b.py"], max_bytes=4096)
    git.commit(tmp_repo, ["b.py"], message="m", trailers=[("Aipm-Task", "T-002")])
    assert not marker.exists()
    # The same hook in the repository's own config is refused before git starts.
    append_config(tmp_repo, case_text("C-039").replace("<marker>", str(marker)))
    with pytest.raises(PolicyViolation, match=r"hook\.probe\.command"):
        git.snapshot_files(tmp_repo, head, watch_ignored=lambda _: True)
    assert not marker.exists()


def test_a_promisor_remote_is_never_fetched(tmp_repo: Path, home: Path, tmp_path: Path) -> None:
    marker = tmp_path / "fetch-ran"
    (tmp_repo / "t.txt").write_text("secret test\n", encoding="utf-8")
    run_git(tmp_repo, "add", "t.txt")
    run_git(tmp_repo, "commit", "-q", "-m", "t")
    oid = run_git(tmp_repo, "rev-parse", "HEAD:t.txt").strip()
    loose = tmp_repo / ".git" / "objects" / oid[:2] / oid[2:]
    loose.chmod(0o644)
    loose.unlink()
    append_config(tmp_repo, case_text("C-040").replace("<marker>", str(marker)))
    with pytest.raises(UsageError):
        git.read_object(tmp_repo, oid, max_bytes=1024)
    assert not marker.exists()


def test_a_filter_in_a_submodule_s_own_config_never_runs(
    tmp_repo: Path, home: Path, tmp_path: Path
) -> None:
    """git starts `git status` in each populated submodule, which reads that submodule's own
    config (C-047)."""
    lib = tmp_path / "lib"
    lib.mkdir()
    run_git(lib, "init", "-q")
    (lib / "a.txt").write_text("a\n", encoding="utf-8")
    (lib / ".gitattributes").write_text("* filter=probe\n", encoding="utf-8")
    run_git(lib, "add", "-A")
    run_git(lib, "commit", "-q", "-m", "lib")
    run_git(tmp_repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(lib), "lib")
    run_git(tmp_repo, "commit", "-q", "-m", "submodule")
    head = git.head_sha(tmp_repo)
    marker = tmp_path / "submodule-filter-ran"
    config = tmp_repo / ".git" / "modules" / "lib" / "config"
    with config.open("a", encoding="utf-8") as handle:
        handle.write(case_text("C-047").replace("<marker>", str(marker)))
    (tmp_repo / "lib" / "a.txt").write_text("changed\n", encoding="utf-8")
    with pytest.raises(PolicyViolation, match=r"lib sets filter\.probe\.clean"):
        git.listing(tmp_repo, head)
    with pytest.raises(PolicyViolation):
        git.status_porcelain_v2(tmp_repo)
    assert not marker.exists()


@pytest.mark.usefixtures("home")
def test_prompt_refuses_a_repository_with_its_own_filter(
    tmp_repo: Path, fake_llm: Callable[[str], FakeLLM], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """C-038 end to end: a repository copied with a `.git/config` that names a filter."""
    fake_llm("clinic")
    monkeypatch.setenv("PATH", f"{STUBS}{os.pathsep}{os.environ['PATH']}")
    marker = tmp_path / "filter-ran"
    planned(tmp_repo)
    use_test_gates(tmp_repo)
    install(FIXTURE / "base", tmp_repo)
    (tmp_repo / ".gitattributes").write_text("* filter=probe\n", encoding="utf-8")
    run_git(tmp_repo, "add", "-A", "--", ".", ":!.pm")
    run_git(tmp_repo, "commit", "-q", "-m", "base")
    trust(tmp_repo)
    append_config(tmp_repo, case_text("C-038").replace("<marker>", str(marker)))
    result = aipm(tmp_repo, "prompt", "T-002", "--force")
    assert result.exit_code == 6, result.stdout + result.stderr
    assert not marker.exists()


# ---------------------------------------------------------------- RT02-2 dependency sources

PYPROJECT = '[project]\nname = "x"\ndependencies = ["requests>=2"]\n'


@pytest.mark.parametrize(
    "added",
    [
        case_text("C-041"),
        '[tool.uv.sources]\nrequests = { git = "https://evil.example/requests.git" }\n',
        '[tool.uv.sources]\nrequests = { path = "vendor/requests.whl" }\n',
        '[tool.uv]\nextra-index-url = ["https://evil.example/simple"]\n',
        '[tool.uv]\nfind-links = ["https://evil.example/wheels"]\n',
        '[tool.uv.pip]\nindex-url = "https://evil.example/simple"\n',
        '[tool.poetry.dependencies]\nrequests = { git = "https://evil.example/r.git" }\n',
        '[tool.poetry.group.dev.dependencies]\nrequests = { url = "https://evil.example/r.whl" }\n',
        '[[tool.poetry.source]]\nname = "x"\nurl = "https://evil.example/simple"\n',
    ],
)
def test_a_new_source_in_pyproject_is_a_dependency_violation(added: str) -> None:
    found = violations(change("pyproject.toml", PYPROJECT, PYPROJECT + added))
    assert found and all(kind is Kind.DEPENDENCY for kind, _, _ in found), found
    assert any("source outside the registry" in detail for _, _, detail in found)


def test_a_direct_reference_replaces_a_known_dependency() -> None:
    after = PYPROJECT.replace("requests>=2", "requests @ https://evil.example/requests.whl")
    found = violations(change("pyproject.toml", PYPROJECT, after))
    assert [k for k, _, _ in found] == [Kind.DEPENDENCY]
    assert "requests @ https://evil.example/requests.whl" in found[0][2]


def test_a_new_build_requirement_needs_deps_add() -> None:
    after = PYPROJECT + '[build-system]\nrequires = ["hatchling", "evil-backend"]\n'
    before = PYPROJECT + '[build-system]\nrequires = ["hatchling"]\n'
    details = [d for _, _, d in violations(change("pyproject.toml", before, after))]
    assert details == ["pypi dependency evil-backend is not in deps_add"]


def test_a_workspace_source_is_local_and_not_flagged() -> None:
    after = PYPROJECT + "[tool.uv.sources]\nrequests = { workspace = true }\n"
    assert violations(change("pyproject.toml", PYPROJECT, after)) == []


@pytest.mark.parametrize(
    "line",
    [
        "./vendor/evil-1.0-py3-none-any.whl",
        "vendor/evil-1.0-py3-none-any.whl",
        "evil-1.0.tar.gz",
        "requests @ file:///tmp/requests.whl",
        "requests@https:evil.example/r.whl",
        "--trusted-host evil.example",
        "--no-index",
    ],
)
def test_a_path_or_unknown_option_in_requirements_is_off_registry(line: str) -> None:
    before = "requests==2.32.0\n"
    found = violations(change("requirements.txt", before, before + line + "\n"))
    assert any("source outside the registry" in d for _, _, d in found), found


def test_a_requirements_include_of_an_unchecked_file_is_flagged() -> None:
    found = violations(change("requirements.txt", "a==1\n", "a==1\n-r deps/more.txt\n"))
    assert [d for _, _, d in found] == [
        "includes a file the dependency check does not read: -r deps/more.txt"
    ]


def test_harmless_requirement_lines_pass() -> None:
    before = "requests==2.32.0\n"
    after = (
        "requests==2.32.0 \\\n    --hash=sha256:abc\n"
        'idna[all]>=3 ; python_version > "3.8"\n-r requirements-dev.txt\n--pre\n'
    )
    deps_ = manifest_deps("requirements.txt", after)
    assert deps_ is not None and deps_.off_registry == frozenset()
    found = violations(change("requirements.txt", before, after))
    assert [d for _, _, d in found] == ["pypi dependency idna is not in deps_add"]


def test_a_tarball_spec_in_package_json_is_off_registry() -> None:
    before = json.dumps({"dependencies": {"lodash": "^4.17.21"}})
    after = json.dumps({"dependencies": {"lodash": "lodash-4.17.21.tgz"}})
    found = violations(change("package.json", before, after))
    assert [d for _, _, d in found] == ["source outside the registry: lodash@lodash-4.17.21.tgz"]


# ---------------------------------------------------------------- RT02-3 lockfiles

UV_BEFORE = (
    'version = 1\n[[package]]\nname = "x"\nversion = "0.1.0"\nsource = { editable = "." }\n'
    '[[package]]\nname = "requests"\nversion = "2.32.0"\n'
    'source = { registry = "https://pypi.org/simple" }\n'
)


@pytest.mark.parametrize(
    "registry",
    ['{ url = "https://evil.example/requests.whl" }', '{ git = "https://evil.example/r.git" }',
     '{ path = "vendor/requests.whl" }', '{ registry = "https://pypi.org/simple-evil.example" }',
     '{ registry = "https://evil.example/simple" }'],
)  # fmt: skip
def test_a_changed_uv_lock_source_is_a_violation(registry: str) -> None:
    after = UV_BEFORE.replace('{ registry = "https://pypi.org/simple" }', registry)
    t = task(deps_add=[DependencyAdd(ecosystem=Ecosystem.PYPI, name="requests")])
    found = violations(change("uv.lock", UV_BEFORE, after), t=t)
    assert [k for k, _, _ in found] == [Kind.DEPENDENCY], found
    assert found[0][2].startswith("source outside the registry: requests:")


def test_a_package_only_the_lockfile_adds_is_listed_for_lookup() -> None:
    after = UV_BEFORE + (
        '[[package]]\nname = "Evil_Pkg"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    changes = ChangeSet("a" * 40, files=(change("uv.lock", UV_BEFORE, after),))
    assert new_lock_packages(changes) == [("uv.lock", Ecosystem.PYPI, "evil-pkg")]


def test_package_lock_aliases_hosts_and_new_packages() -> None:
    before = json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"}}})
    after = case_text("C-042")
    t = task(deps_add=[DependencyAdd(ecosystem=Ecosystem.NPM, name="left-pad-tools")])
    found = violations(change("package-lock.json", before, after), t=t)
    assert [d for _, _, d in found] == [
        "source outside the registry: chalk: "
        "https://registry.npmjs.org.evil.example/chalk/-/chalk-5.3.0.tgz"
    ]
    changes = ChangeSet("a" * 40, files=(change("package-lock.json", before, after),))
    names = {name for _, _, name in new_lock_packages(changes)}
    assert names == {"left-pad-tools", "lodahs", "chalk"}  # the alias by the name it installs


def test_npm_lockfile_version_1_and_git_versions() -> None:
    after = json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
              "dependencies": {"b": {"version": "git+ssh://git@evil.example/b.git#abc"}}},
        "c": {"version": "npm:evil@1.0.0"}}})  # fmt: skip
    parsed = lock_deps("package-lock.json", after)
    assert parsed is not None
    assert {n for _, n in parsed.names} == {"a", "b", "evil"}
    assert parsed.sources == frozenset({"b: git+ssh://git@evil.example/b.git#abc"})


@pytest.mark.parametrize(
    ("name", "before", "after", "source"),
    [
        ("pnpm-lock.yaml",
         "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n"
         "    resolution: {integrity: sha512-x}\n",
         "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n"
         "    resolution: {tarball: https://evil.example/lodash.tgz}\n",
         "lodash: resolution: {tarball: https://evil.example/lodash.tgz}"),
        ("yarn.lock",
         'lodash@^4.17.21:\n  version "4.17.21"\n'
         '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#a"\n',
         'lodash@^4.17.21:\n  version "4.17.21"\n'
         '  resolved "https://evil.example/lodash-4.17.21.tgz#a"\n',
         "lodash: https://evil.example/lodash-4.17.21.tgz#a"),
        ("yarn.lock",
         '"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n',
         '"lodash@npm:^4.17.21":\n  version: 4.17.21\n'
         '  resolution: "lodash@https://evil.example/l.tgz"\n',
         "lodash: lodash@https://evil.example/l.tgz"),
        ("poetry.lock",
         '[[package]]\nname = "requests"\nversion = "2.32.0"\n',
         '[[package]]\nname = "requests"\nversion = "2.32.0"\n'
         '[package.source]\ntype = "git"\nurl = "https://evil.example/r.git"\n',
         'requests: {"type": "git", "url": "https://evil.example/r.git"}'),
        ("pylock.toml",
         '[[packages]]\nname = "requests"\nindex = "https://pypi.org/simple"\n',
         '[[packages]]\nname = "requests"\n[packages.vcs]\ntype = "git"\n'
         'url = "https://evil.example/r.git"\n',
         'requests: {"vcs": {"type": "git", "url": "https://evil.example/r.git"}}'),
    ],
)  # fmt: skip
def test_other_lockfile_formats(name: str, before: str, after: str, source: str) -> None:
    eco = Ecosystem.PYPI if name in ("poetry.lock", "pylock.toml") else Ecosystem.NPM
    t = task(owns_files=[name], deps_add=[DependencyAdd(ecosystem=eco, name="lodash")])
    found = violations(change(name, before, after), t=t)
    assert [d for _, _, d in found] == [f"source outside the registry: {source}"]


def test_a_lockfile_too_large_to_read_is_a_violation() -> None:
    t = task(deps_add=[DependencyAdd(ecosystem=Ecosystem.PYPI, name="requests")])
    found = violations(change("uv.lock", UV_BEFORE, UV_BEFORE, truncated=True), t=t)
    assert [d for _, _, d in found] == ["lockfile cannot be read"]
    broken = violations(change("uv.lock", UV_BEFORE, "[[package"), t=t)
    assert [d for _, _, d in broken] == ["lockfile cannot be read"]


def _deps_ctx(tmp_path: Path, changes: ChangeSet, asked: list[str], *, created: str) -> GateContext:
    def fetch(url: str, headers: Mapping[str, str]) -> Response:
        del headers
        asked.append(url)
        body = {"files": [{"upload-time": created}], "time": {"created": created}}
        return Response(200, json.dumps(body).encode())

    temp = tmp_path / "attempt"
    temp.mkdir(mode=0o700, exist_ok=True)
    return GateContext(
        ws=GateWorkspace(root=tmp_path, temp_dir=temp, base_sha="a" * 40),
        task=task(), cfg=Config(), changes=changes, redactor=Redactor({}),
        home=tmp_path / "home", now=datetime(2026, 10, 30, tzinfo=UTC), fetch=fetch,
    )  # fmt: skip


def test_the_deps_gate_looks_up_packages_only_a_lockfile_adds(tmp_path: Path) -> None:
    after = UV_BEFORE + (
        '[[package]]\nname = "fresh-pkg"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    changes = ChangeSet("a" * 40, files=(change("uv.lock", UV_BEFORE, after),))
    asked: list[str] = []
    ctx = _deps_ctx(tmp_path, changes, asked, created="2026-10-25T00:00:00Z")
    findings, errors = deps.check_new(ctx, ctx.now)
    assert errors == []
    assert asked == ["https://pypi.org/simple/fresh-pkg/"]
    assert [(f.rule, f.message) for f in findings] == [
        ("too-new", "fresh-pkg was first released on 2026-10-25, less than 30 days ago")
    ]


def test_an_invalid_name_in_a_lockfile_is_a_finding_not_a_crash(tmp_path: Path) -> None:
    after = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/Bad Name": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                },
            },
        }
    )
    changes = ChangeSet("a" * 40, files=(change("package-lock.json", None, after),))
    asked: list[str] = []
    ctx = _deps_ctx(tmp_path, changes, asked, created="2015-01-01T00:00:00Z")
    findings, _ = deps.check_new(ctx, ctx.now)
    assert asked == []
    assert [f.rule for f in findings] == ["invalid-name"]


# ---------------------------------------------------------------- RT02-4 prepare and package config


@pytest.mark.parametrize(
    "line", case_text("C-043").splitlines(), ids=lambda line: line.split(":", 1)[0]
)
def test_package_manager_settings_are_a_dependency_change(line: str) -> None:
    path, content = line.split(": ", 1)
    found = violations(change(path, None, content), t=task(owns_files=[path]))  # even if owned
    assert [k for k, _, _ in found] == [Kind.DEPENDENCY], found
    assert "package manager configuration" in found[0][2]
    assert is_dependency_path(path) and is_dependency_path("a/uv.lock")
    assert not is_dependency_path("src/app.py")


def _prepare_ctx(tmp_path: Path) -> GateContext:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ok.py").write_text("", encoding="utf-8")
    temp = tmp_path / "attempt"
    temp.mkdir(mode=0o700)
    cfg = Config.model_validate({
        "allowed_executables": [[PY, "-m", "ok"]],
        "prepare": {"run": [PY, "-m", "ok"]},
        "gates": {"lint": {"run": [PY, "-m", "ok"], "required": True}},
    })  # fmt: skip
    return GateContext(
        ws=GateWorkspace(root=repo, temp_dir=temp, base_sha="a" * 40),
        task=task(owns_files=["ok.py"]), cfg=cfg, changes=ChangeSet("a" * 40),
        redactor=Redactor({}), home=tmp_path / "home", now=datetime.now(UTC),
    )  # fmt: skip


def test_a_held_prepare_never_runs_and_holds_the_command_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_prepare(_: GateContext) -> None:
        raise AssertionError("prepare ran although the checks refused a dependency")

    monkeypatch.setattr(runner, "run_prepare", no_prepare)
    run = run_gates(_prepare_ctx(tmp_path), hold_prepare="the checks refused it")
    assert [(r.name, r.status, r.summary) for r in run.results] == [
        ("prepare", GateStatus.ERROR, "not run: the checks refused it"),
        ("lint", GateStatus.ERROR, "not run: the prepare step did not run"),
    ]
    assert not run.passed()


# ---------------------------------------------------------------- RT02-5 the AC reviewer's diff


@pytest.mark.parametrize(
    "path",
    ["config/credentials.yml", "deploy.KEY", "src/id_rsa_backup", "SECRETS/x.py", ".npmrc",
     "a/b/server.pem.", "src/.env.local"],
)  # fmt: skip
def test_the_deny_list_matches_any_component_in_any_case(path: str) -> None:
    assert denied_for_llm(path)


@pytest.mark.parametrize("path", ["src/app.py", "docs/keys.md", "src/identity.py", "README"])
def test_ordinary_files_are_not_withheld(path: str) -> None:
    assert not denied_for_llm(path)


def test_the_reviewer_never_sees_a_withheld_file(
    tmp_repo: Path, home: Path, tmp_path: Path
) -> None:
    head = git.head_sha(tmp_repo)
    secret = "aipm-redteam-unknown-format-value-7c91"  # noqa: S105 - matches no redactor rule
    (tmp_repo / "src").mkdir()
    (tmp_repo / "src" / "aws_credentials").write_text(
        case_text("C-044").replace("<secret>", secret), encoding="utf-8"
    )
    (tmp_repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    temp = tmp_path / "attempt"
    temp.mkdir(mode=0o700)
    changes = ChangeSet(head, files=(
        FileChange(path="src/app.py", status=ChangeStatus.ADDED, mode="100644"),
        FileChange(path="src/aws_credentials", status=ChangeStatus.ADDED, mode="100644"),
    ))  # fmt: skip
    ctx = GateContext(
        ws=GateWorkspace(root=tmp_repo, temp_dir=temp, base_sha=head), task=task(),
        cfg=Config(), changes=changes, redactor=Redactor({}), home=home, now=datetime.now(UTC),
    )  # fmt: skip
    text, _ = ac_review.build_diff(ctx)
    assert secret not in text
    assert "(contents withheld: src/aws_credentials)" in text
    assert "+x = 1" in text


def test_the_reviewer_is_not_asked_after_the_secrets_gate_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[ACReviewInput] = []

    def reviewer(inp: ACReviewInput) -> ACReview:
        asked.append(inp)
        verdict = CriterionVerdict(id="AC-T002-1", verdict=Verdict.MET)
        return ACReview(criteria=[verdict], injection_suspected=[])

    def leak(ctx: GateContext, *, required: bool) -> ac_review.BuiltinOutcome:
        del ctx
        result = GateResult(name="secrets", status=GateStatus.FAIL, required=required)
        return ac_review.BuiltinOutcome(result)

    monkeypatch.setattr("aipm.gates.builtin.secrets.run", leak)
    gates = {"secrets": GateDef(builtin=BuiltinGate.GITLEAKS, required=True),
             "ac_review": GateDef(builtin=BuiltinGate.AC_REVIEW)}  # fmt: skip
    ctx = _prepare_ctx(tmp_path)
    ctx = GateContext(**{**{f: getattr(ctx, f) for f in ("ws", "task", "changes", "redactor",
                                                         "home", "now")},
                         "cfg": Config.model_validate({"gates": {
                             k: v.model_dump(mode="json", exclude_none=True)
                             for k, v in gates.items()}})})  # fmt: skip
    run = run_gates(ctx, reviewer=reviewer)
    assert asked == []
    review = next(r for r in run.results if r.name == "ac_review")
    assert review.status is GateStatus.SKIPPED
    assert "not sent to the LLM" in review.summary


# ---------------------------------------------------------------- RT02-6 hidden by .gitignore


def test_a_self_ignoring_gitignore_is_a_hidden_change(tmp_repo: Path, home: Path) -> None:
    """A `.gitignore` that ignores itself, in a directory that holds tracked files: git lists
    it (and the new file) only as ignored. A wholly new ignored directory is one entry that
    verify does not look into: residual risk R-11."""
    (tmp_repo / "docs").mkdir()
    (tmp_repo / "docs" / "guide.md").write_text("# guide\n", encoding="utf-8")
    run_git(tmp_repo, "add", "docs/guide.md")
    run_git(tmp_repo, "commit", "-q", "-m", "docs")
    head = git.head_sha(tmp_repo)
    files = git.snapshot_files(tmp_repo, head, watch_ignored=lambda p: is_watched(p, POLICY))
    integrity = git.integrity_snapshot(tmp_repo, home)
    (tmp_repo / "docs" / ".gitignore").write_text(case_text("C-045"), encoding="utf-8")
    (tmp_repo / "docs" / "evil.py").write_text("import os\n", encoding="utf-8")
    inputs = git.ChangeInputs(base_sha=head, integrity=integrity, files=files, ledger={})
    changes = git.change_set(
        tmp_repo, inputs, home=home, watch_ignored=lambda p: is_watched(p, POLICY),
        wants_content=lambda _: False,
    )  # fmt: skip
    assert changes.files == ()  # git lists neither file
    assert changes.hidden == ("docs/.gitignore",)
    found = check_changes(changes, task(), POLICY)
    assert [(v.kind, v.level.value) for v in found] == [(Kind.HIDDEN_CHANGE, "severe")]


# ---------------------------------------------------------------- RT02-7 what the snapshot watches


@pytest.mark.parametrize(
    "line",
    ["[include]\n\tPATH = {target}\n", "[include] path = {target}\n",
     '[includeIf "gitdir:/"]\n\tpath = "{target}" ; a comment\n',
     "[include]\n\tpath = \\\n{target}\n"],
)  # fmt: skip
def test_includes_in_any_spelling_are_watched(
    tmp_repo: Path, home: Path, tmp_path: Path, line: str
) -> None:
    target = tmp_path / "inc.cfg"
    target.write_text("[core]\n", encoding="utf-8")
    append_config(tmp_repo, line.format(target=target))
    before = git.integrity_snapshot(tmp_repo, home)
    target.write_text('[filter "x"]\n\tclean = cat\n', encoding="utf-8")
    assert git.compare(before, git.integrity_snapshot(tmp_repo, home)) == [f"include: {target}"]


def test_nested_includes_and_named_files_are_watched(
    tmp_repo: Path, home: Path, tmp_path: Path
) -> None:
    deep = tmp_path / "deep.cfg"
    deep.write_text("[core]\n", encoding="utf-8")
    (tmp_path / "mid.cfg").write_text(f"[include]\n\tpath = {deep}\n", encoding="utf-8")
    with (home / ".gitconfig").open("a", encoding="utf-8") as handle:
        handle.write(
            f"[include]\n\tpath = {tmp_path / 'mid.cfg'}\n"
            "[core]\n\texcludesFile = ~/my-ignore\n\tattributesFile = ~/my-attrs\n"
        )
    before = git.integrity_snapshot(tmp_repo, home)
    deep.write_text("[core]\n\tfsmonitor = /x\n", encoding="utf-8")
    (home / "my-ignore").write_text("*.py\n", encoding="utf-8")
    (home / "my-attrs").write_text("* filter=x\n", encoding="utf-8")
    assert git.compare(before, git.integrity_snapshot(tmp_repo, home)) == sorted([
        f"include: {deep}", f"core.excludesfile: {home / 'my-ignore'}",
        f"core.attributesfile: {home / 'my-attrs'}",
    ])  # fmt: skip


def test_the_git_config_git_reads_is_watched_when_xdg_points_elsewhere(
    tmp_repo: Path, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """git gets no `XDG_CONFIG_HOME` (`build_env`), so it reads `~/.config/git/config`."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "elsewhere"))
    before = git.integrity_snapshot(tmp_repo, home)
    (home / ".config" / "git").mkdir(parents=True)
    (home / ".config" / "git" / "config").write_text("[core]\n\tfsmonitor = /x\n", "utf-8")
    assert git.compare(before, git.integrity_snapshot(tmp_repo, home)) == ["~/.config/git/config"]


def test_a_fifo_include_never_blocks_the_snapshot(
    tmp_repo: Path, home: Path, tmp_path: Path
) -> None:
    fifo = tmp_path / "fifo.cfg"
    os.mkfifo(fifo)
    append_config(tmp_repo, f"[include]\n\tpath = {fifo}\n")
    assert f"include: {fifo}" in git.integrity_snapshot(tmp_repo, home)


# ---------------------------------------------------------------- RT02-8 the commit holds what ran


def test_staged_and_committed_ids_agree_for_files_links_and_deletions(
    tmp_repo: Path, home: Path
) -> None:
    (tmp_repo / "gone.txt").write_text("x\n", encoding="utf-8")
    run_git(tmp_repo, "add", "gone.txt")
    run_git(tmp_repo, "commit", "-q", "-m", "gone")
    (tmp_repo / "gone.txt").unlink()
    (tmp_repo / "a.py").write_text("x = 1\r\n", encoding="utf-8")
    (tmp_repo / "link").symlink_to("a.py")
    (tmp_repo / "new\nline.txt").write_text("odd name\n", encoding="utf-8")
    paths = ["a.py", "gone.txt", "link", "new\nline.txt"]
    expected = git.staged_ids(tmp_repo, paths)
    assert expected["gone.txt"] is None and expected["link"] is not None
    head = git.commit(tmp_repo, paths, message="m", trailers=[])
    assert git.committed_ids(tmp_repo, head, paths) == expected


def test_a_file_changed_before_the_commit_shows_as_a_mismatch(tmp_repo: Path, home: Path) -> None:
    (tmp_repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    expected = git.staged_ids(tmp_repo, ["a.py"])
    (tmp_repo / "a.py").write_text(case_text("C-046"), encoding="utf-8")
    head = git.commit(tmp_repo, ["a.py"], message="m", trailers=[])
    assert git.committed_ids(tmp_repo, head, ["a.py"]) != expected


# ---------------------------------------------------------------- end to end on the clinic example


@pytest.fixture
def clinic(
    tmp_repo: Path, fake_llm: Callable[[str], FakeLLM], monkeypatch: pytest.MonkeyPatch,
    home: Path, registry: list[str],
) -> Path:  # fmt: skip
    del home, registry
    fake_llm("clinic")
    monkeypatch.setenv("PATH", f"{STUBS}{os.pathsep}{os.environ['PATH']}")
    planned(tmp_repo)
    use_test_gates(tmp_repo)
    install(FIXTURE / "base", tmp_repo)
    run_git(tmp_repo, "add", "-A", "--", ".", ":!.pm")
    run_git(tmp_repo, "commit", "-q", "-m", "base")
    trust(tmp_repo)
    return tmp_repo


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    asked: list[str] = []

    def fetch(url: str, headers: Mapping[str, str]) -> Response:
        del headers
        asked.append(url)
        body = {"files": [{"upload-time": "2015-01-01T00:00:00Z"}],
                "time": {"created": "2015-01-01T00:00:00Z"}}  # fmt: skip
        return Response(200, json.dumps(body).encode())

    monkeypatch.setattr("aipm.scanners.registry._fetch", fetch)
    return asked


def verify(repo: Path, task_id: str, *args: str) -> tuple[int, dict[str, Any]]:
    result = aipm(repo, "verify", task_id, *args, flags=["--json"])
    return result.exit_code, json.loads(result.stdout)


def kinds(env: dict[str, Any]) -> set[str]:
    return {v["kind"] for v in env["data"]["violations"]}


def test_verify_never_runs_prepare_for_a_refused_dependency_source(
    clinic: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def add_prepare(layer: dict[str, object]) -> None:
        layer["prepare"] = {"run": [PY, "-m", "compileall", "-q", "src"], "network": "none"}

    edit_config(clinic, add_prepare)
    trust(clinic)
    ok(aipm(clinic, "prompt", "T-001"))
    ran: list[object] = []
    monkeypatch.setattr(runner, "run_prepare", ran.append)
    path = clinic / "pyproject.toml"
    path.write_text(path.read_text("utf-8") + case_text("C-041"), encoding="utf-8")
    code, env = verify(clinic, "T-001")
    assert code == 3, env
    assert kinds(env) == {"dependency"}
    assert ran == []
    gates = {g["name"]: g for g in env["data"]["gates"]}
    assert gates["prepare"]["summary"].startswith("not run: the post-change checks refused")


def test_verify_sends_no_secret_file_to_the_reviewer(
    clinic: Path, fake_llm: Callable[[str], FakeLLM]
) -> None:
    llm = fake_llm("clinic")
    llm._queues[RoleName.AC_REVIEWER] = [FakeResponse.model_validate({"json": {  # pyright: ignore[reportPrivateUsage]
        "criteria": [{"id": f"AC-T002-{i}", "verdict": "met", "evidence": "ok"} for i in (1, 2, 3)],
        "injection_suspected": []}})]  # fmt: skip
    ok(aipm(clinic, "prompt", "T-002", "--force"))
    install(FIXTURE / "T-002", clinic)
    secret = "aipm-redteam-unknown-format-value-31f4"  # noqa: S105 - matches no redactor rule
    (clinic / "src" / "clinic" / "booking" / "aws_credentials").write_text(
        case_text("C-044").replace("<secret>", secret), encoding="utf-8"
    )
    code, env = verify(clinic, "T-002")
    sent = llm.requests_for(RoleName.AC_REVIEWER)
    assert len(sent) == 1, env
    assert secret not in sent[0].user
    assert "contents withheld: src/clinic/booking/aws_credentials" in sent[0].user
    del code


def test_verify_never_asks_the_reviewer_about_a_flagged_diff(
    clinic: Path, fake_llm: Callable[[str], FakeLLM]
) -> None:
    llm = fake_llm("clinic")
    ok(aipm(clinic, "prompt", "T-002", "--force"))
    install(FIXTURE / "T-002", clinic)
    (clinic / "src" / "clinic" / "booking" / "token.py").write_text(
        'TOKEN = "FAKE-LEAK-FOR-TESTS aipm-redteam-unknown-format-value-55aa"\n', "utf-8"
    )
    code, env = verify(clinic, "T-002")
    assert code == 3, env
    assert llm.requests_for(RoleName.AC_REVIEWER) == []


def test_verify_blocks_a_self_ignoring_gitignore(clinic: Path) -> None:
    ok(aipm(clinic, "prompt", "T-002", "--force"))
    install(FIXTURE / "T-002", clinic)
    package = clinic / "src" / "clinic"  # holds tracked files; T-002 owns only booking/
    (package / ".gitignore").write_text(case_text("C-045"), encoding="utf-8")
    (package / "evil.py").write_text("import os\n", encoding="utf-8")
    code, env = verify(clinic, "T-002")
    assert code == 6, env
    assert kinds(env) == {"hidden_change"}


def test_verify_blocks_a_commit_that_differs_from_what_was_verified(
    clinic: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ok(aipm(clinic, "prompt", "T-002", "--force"))
    install(FIXTURE / "T-002", clinic)
    target = clinic / "src" / "clinic" / "booking" / "service.py"
    original = git.signing_overrides

    def swap(repo: Path) -> list[str]:
        target.write_text(case_text("C-046"), encoding="utf-8")  # a child that left its group
        return original(repo)

    monkeypatch.setattr(git, "signing_overrides", swap)
    code, env = verify(clinic, "T-002", "--commit")
    assert code == 6, env
    assert kinds(env) >= {"commit_mismatch"}
    commit = env["data"]["commit"]
    assert commit and run_git(clinic, "rev-parse", "HEAD").strip() == commit
    assert "git show" in (env["errors"][0]["hint"] or "")
    task_ = next(t for t in tasks(clinic).tasks if t.id == "T-002")
    assert task_.status is TaskStatus.BLOCKED
    assert task_.blocked is not None and "commit_mismatch" in task_.blocked.detail


def test_a_clean_commit_still_verifies(clinic: Path) -> None:
    """Pins the control that held: an honest attempt commits and is done."""
    ok(aipm(clinic, "prompt", "T-002", "--force"))
    install(FIXTURE / "T-002", clinic)
    code, env = verify(clinic, "T-002", "--commit")
    assert code == 0, env
    assert env["data"]["outcome"] == "done"


# ---------------------------------------------------------------- odd inputs never crash


def test_lockfile_readers_skip_what_they_cannot_read() -> None:
    """T2 lockfiles in shapes no tool writes: entries without names, lists where tables go,
    workspace links. Each reader skips what it cannot read and never raises."""
    uv = lock_deps("uv.lock", '[[package]]\nversion = "1"\n[[package]]\nname = "a"\n'
                   'source = { virtual = "." }\npackage = [1]\n')  # fmt: skip
    assert uv is not None and uv.names == frozenset()
    poetry = lock_deps("poetry.lock", "package = [1, {version = '1'}]\n")
    assert poetry is not None and poetry.names == frozenset()
    pylock = lock_deps("pylock.toml", "packages = [1, {version = '1'}]\n")
    assert pylock is not None and pylock.names == frozenset()
    npm = lock_deps("package-lock.json", json.dumps({
        "packages": {"": {}, "packages/ws": {}, "node_modules/x": 1,
                     "node_modules/linked": {"link": True, "resolved": "packages/ws"}},
        "dependencies": {"y": "1.0.0"}}))  # fmt: skip
    assert npm is not None and npm.names == frozenset() and npm.sources == frozenset()
    pnpm = lock_deps("pnpm-lock.yaml", "importers:\n  .:\n    tarball: file:x\npackages:\n\n")
    assert pnpm == lock_deps("pnpm-lock.yaml", "")
    yarn = lock_deps("yarn.lock", '__metadata:\n  version: 6\n  resolution: "x@file:y"\n'
                     'odd-line:\n  resolved "https://evil.example/x.tgz"\n')  # fmt: skip
    assert yarn is not None and yarn.names == frozenset() and yarn.sources == frozenset()
    assert lock_deps("uv.lock", "[[package") is None
    assert lock_deps("Gemfile.lock", "x") is None
    groups = manifest_deps("pyproject.toml", "[tool.poetry.group]\nodd = 1\n")
    assert groups is not None and groups.names == frozenset()
    lockfiles = ChangeSet("a" * 40, files=(
        FileChange(path="uv.lock", status=ChangeStatus.DELETED, mode=None, before=UV_BEFORE),
        change("package-lock.json", None, "{}", truncated=True),
        change("pnpm-lock.yaml", None, "packages:\n  x@1.0.0:\n", truncated=True),
    ))  # fmt: skip
    assert new_lock_packages(lockfiles) == []


def test_the_reviewer_is_not_asked_about_a_file_a_gate_changed(tmp_path: Path) -> None:
    """A gate runs agent-written code that can read the home directory (outside the denied
    credential paths) and write what it read into a file of the diff, which the reviewer would
    send to the LLM. RT02-5."""
    asked: list[ACReviewInput] = []

    def reviewer(inp: ACReviewInput) -> ACReview:
        asked.append(inp)
        return ACReview(criteria=[], injection_suspected=[])

    ctx = _prepare_ctx(tmp_path)
    cfg = Config.model_validate({"gates": {"ac_review": {"builtin": "ac_review"}}})
    fields = {f: getattr(ctx, f) for f in ("ws", "task", "changes", "redactor", "home", "now")}
    ctx = GateContext(**fields, cfg=cfg, changed_during_gates=lambda: ["src/clinic/x.py"])
    run = run_gates(ctx, reviewer=reviewer)
    assert asked == []
    assert "src/clinic/x.py changed while the gates ran" in run.results[0].summary


@pytest.mark.parametrize(
    "added",
    ["from pytest import mark\n@mark.skip\ndef test_a():\n    pass\n",
     "from pytest import mark as m\n@m.mark.xfail\ndef test_a():\n    pass\n",
     "from pytest import skip\ndef test_a():\n    skip('later')\n"],
)  # fmt: skip
def test_skip_markers_through_an_import_alias_are_seen(added: str) -> None:
    """Pins residual risk R-5 a little tighter: the common aliases count as markers."""
    assert tamper_signs("def test_a():\n    pass\n", added)[0].endswith("marker(s) added")


def test_a_link_a_gate_planted_in_the_temp_dir_is_skipped(tmp_path: Path) -> None:
    """A gate may write to the attempt's temp dir; a dangling link where a scanner's work dir
    goes used to crash verify (exit 1). Info, RT02-9."""
    from aipm.scanners.base import ScanContext, new_dir  # noqa: PLC0415

    (tmp_path / "semgrep").symlink_to(tmp_path / "missing")
    made = new_dir(ScanContext(repo=tmp_path, temp_dir=tmp_path), "semgrep")
    assert made == tmp_path / "semgrep-1" and made.is_dir() and not made.is_symlink()
