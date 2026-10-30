"""Post-change checks (ARCHITECTURE §12.4 step 3, §13.3; SECURITY.md §9.2, §14.3).

A pure function over a `ChangeSet`: these tests build change sets by hand. Severe: integrity,
protected paths, tests and test configuration the task does not own, escaping links, hidden
changes, an unreadable change set. Minor: scope, undeclared dependencies, tamper on owned tests.
"""

import json

import pytest

from aipm.domain.models import (
    AcceptanceCriterion,
    ChangeSet,
    ChangeStatus,
    DependencyAdd,
    Ecosystem,
    FileChange,
    Task,
    TaskSize,
    TaskType,
)
from aipm.security.diff_checks import (
    CheckPolicy,
    Kind,
    Level,
    check_changes,
    glob_match,
    is_manifest,
    is_test_path,
    is_watched,
    manifest_deps,
    needs_content,
    new_dependencies,
    normalize_pypi,
    severe,
    tamper_signs,
)

POLICY = CheckPolicy(test_roots=("tests",))


def task(**kw: object) -> Task:
    values: dict[str, object] = {
        "id": "T-002",
        "title": "Slots",
        "type": TaskType.FEATURE,
        "owns_files": ["src/clinic/booking/**", "tests/booking/**", "pyproject.toml"],
        "acceptance": [AcceptanceCriterion(id="AC-T002-1", text="Free slots are listed")],
        "size": TaskSize.M,
    }
    values.update(kw)
    return Task.model_validate(values)


def change(path: str, status: ChangeStatus = ChangeStatus.MODIFIED, **kw: object) -> FileChange:
    return FileChange(path=path, status=status, mode="100644", **kw)  # type: ignore[arg-type]


def kinds(*changes: FileChange, t: Task | None = None, policy: CheckPolicy = POLICY) -> list[Kind]:
    found = check_changes(ChangeSet("a" * 40, files=changes), t or task(), policy)
    return [v.kind for v in found]


# ---------------------------------------------------------------- scope and protected paths


def test_owned_changes_pass() -> None:
    assert kinds(change("src/clinic/booking/service.py")) == []


def test_out_of_scope_is_minor() -> None:
    found = check_changes(ChangeSet("a" * 40, files=(change("src/other.py"),)), task(), POLICY)
    assert [(v.kind, v.level) for v in found] == [(Kind.OUT_OF_SCOPE, Level.MINOR)]
    assert severe(found) == []


@pytest.mark.parametrize(
    "path",
    [".pm/tasks.yaml", ".git/hooks/pre-commit", ".github/workflows/ci.yml", "AGENTS.md",
     "CLAUDE.md", ".claude/settings.json", "deploy/.env.production", ".mcp.json", "Agents.MD"],
)  # fmt: skip
def test_protected_paths_are_severe(path: str) -> None:
    found = check_changes(ChangeSet("a" * 40, files=(change(path),)), task(), POLICY)
    assert [(v.kind, v.level) for v in found] == [(Kind.PROTECTED_PATH, Level.SEVERE)]


def test_extra_protected_paths_count() -> None:
    policy = CheckPolicy(extra_protected=("infra/**",))
    assert kinds(change("infra/main.tf"), policy=policy) == [Kind.PROTECTED_PATH]


def test_a_lockfile_is_in_scope_only_with_a_declared_dependency() -> None:
    assert kinds(change("uv.lock")) == [Kind.OUT_OF_SCOPE]
    t = task(deps_add=[DependencyAdd(ecosystem=Ecosystem.PYPI, name="fastapi")])
    assert kinds(change("uv.lock"), t=t) == []
    assert kinds(change("package-lock.json"), t=t) == [Kind.OUT_OF_SCOPE]


# ---------------------------------------------------------------- tests and test configuration


def test_a_test_the_task_does_not_own_is_severe() -> None:
    found = check_changes(
        ChangeSet("a" * 40, files=(change("tests/api/test_otp.py"),)), task(), POLICY
    )
    assert [(v.kind, v.level) for v in found] == [(Kind.TEST_NOT_OWNED, Level.SEVERE)]


@pytest.mark.parametrize(
    "path", ["src/clinic/test_x.py", "pkg/conftest.py", "web/a.spec.ts", "web/b.test.jsx"]
)
def test_test_files_are_known_by_name_anywhere(path: str) -> None:
    assert is_test_path(path, ("tests",))
    assert kinds(change(path)) == [Kind.TEST_NOT_OWNED]


@pytest.mark.parametrize(
    "name", ["pytest.ini", ".coveragerc", "jest.config.ts", "vitest.config.mjs"]
)
def test_whole_file_test_configuration_not_owned_is_severe(name: str) -> None:
    assert kinds(change(name, before="a", after="b")) == [Kind.TEST_CONFIG]


def test_pyproject_test_sections_are_test_configuration() -> None:
    t = task(owns_files=["src/clinic/booking/**"])
    before = '[project]\nname = "x"\n[tool.pytest.ini_options]\naddopts = "-q"\n'
    after = before.replace('"-q"', '"-q --deselect tests/api"')
    assert kinds(change("pyproject.toml", before=before, after=after), t=t) == [Kind.TEST_CONFIG]
    coverage = before + '[tool.coverage.run]\nomit = ["src/*"]\n'
    assert kinds(change("pyproject.toml", before=before, after=coverage), t=t) == [Kind.TEST_CONFIG]
    other = before.replace('name = "x"', 'name = "y"')
    assert kinds(change("pyproject.toml", before=before, after=other), t=t) == [Kind.OUT_OF_SCOPE]
    broken = "[tool.pytest\n"
    assert kinds(change("pyproject.toml", before=before, after=broken), t=t) == [
        Kind.TEST_CONFIG,
        Kind.DEPENDENCY,
    ]


def test_owned_test_configuration_may_change() -> None:
    before = '[project]\nname = "x"\n'
    after = before + '[tool.pytest.ini_options]\naddopts = "-q"\n'
    assert kinds(change("pyproject.toml", before=before, after=after)) == []


def test_package_json_setup_cfg_and_tox_sections() -> None:
    t = task(owns_files=["src/**"])
    pkg = json.dumps({"name": "x", "jest": {"testPathIgnorePatterns": []}})
    pkg2 = json.dumps({"name": "x", "jest": {"testPathIgnorePatterns": ["api"]}})
    assert kinds(change("package.json", before=pkg, after=pkg2), t=t) == [Kind.TEST_CONFIG]
    assert kinds(change("package.json", before=pkg, after="[1]"), t=t) == [
        Kind.TEST_CONFIG,
        Kind.DEPENDENCY,
    ]
    cfg = "[metadata]\nname = x\n[tool:pytest]\naddopts = -q\n"
    assert kinds(change("setup.cfg", before=cfg, after=cfg + "testpaths = a\n"), t=t) == [
        Kind.TEST_CONFIG
    ]
    assert kinds(change("setup.cfg", before=cfg, after=cfg.replace("x", "y")), t=t) == [
        Kind.OUT_OF_SCOPE
    ]
    tox = "[tox]\nenvlist = py\n[pytest]\naddopts = -q\n"
    assert kinds(change("tox.ini", before=tox, after=tox + "x = 1\n"), t=t) == [Kind.TEST_CONFIG]
    assert kinds(change("tox.ini", before=None, after=None), t=t) == [Kind.OUT_OF_SCOPE]


def test_a_truncated_test_configuration_counts_as_changed() -> None:
    assert kinds(change("pytest.ini", before="a", after="a", truncated=True)) == [Kind.TEST_CONFIG]


# ---------------------------------------------------------------- tamper on owned tests

OWNED = "tests/booking/test_slots.py"
BASE = (
    "import pytest\n\n"
    "def test_free_slots():\n    assert slots() == []\n    assert True\n\n"
    "def test_taken_slot():\n    with pytest.raises(Taken):\n        book()\n"
)


def test_an_owned_test_can_grow() -> None:
    after = BASE + "\ndef test_more():\n    assert 1\n"
    assert kinds(change(OWNED, before=BASE, after=after)) == []


@pytest.mark.parametrize(
    ("after", "sign"),
    [
        (BASE.replace("def test_free", "@pytest.mark.skip\ndef test_free"), "skip, xfail"),
        (BASE.replace("def test_free", "@pytest.mark.xfail\ndef test_free"), "skip, xfail"),
        (BASE.replace("    assert True\n", "    pytest.skip('later')\n"), "skip, xfail"),
        (
            BASE.split("\ndef test_taken_slot", maxsplit=1)[0] + "\n",
            "test(s) removed: test_taken_slot",
        ),
        (BASE.replace("    assert True\n", ""), "fewer assertion"),
    ],
)
def test_tamper_on_an_owned_test_is_minor(after: str, sign: str) -> None:
    found = check_changes(ChangeSet("a" * 40, files=(change(OWNED, before=BASE, after=after),)),
                          task(), POLICY)  # fmt: skip
    assert found
    assert {v.kind for v in found} == {Kind.TEST_TAMPER}
    assert all(v.level is Level.MINOR for v in found)
    assert any(sign in v.detail for v in found)


@pytest.mark.parametrize(
    "marker",
    ["it.skip('x', () => {})", "describe.only('x', () => {})", "xit('x', () => {})",
     "test.todo('x')", "fdescribe('x', () => {})", "t.Skip(\"later\")"],
)  # fmt: skip
def test_js_and_go_markers_are_seen(marker: str) -> None:
    assert tamper_signs("", marker) == ["1 skip, xfail or focus marker(s) added"]


def test_removed_js_and_go_tests_are_seen() -> None:
    before = "it('lists slots', () => { expect(1) })\nfunc TestBook(t *testing.T) {}\n"
    assert tamper_signs(before, "") == [
        "test(s) removed: TestBook, lists slots",
        "1 fewer assertion(s)",
    ]
    many = "".join(f"def test_{i}():\n    pass\n" for i in range(7))
    assert tamper_signs(many, "")[0].endswith(" …")


def test_a_deleted_owned_test_is_tamper() -> None:
    assert kinds(change(OWNED, ChangeStatus.DELETED, before=BASE, after=None)) == [
        Kind.TEST_TAMPER,
        Kind.TEST_TAMPER,
    ]


def test_a_truncated_owned_test_cannot_be_judged() -> None:
    assert kinds(change(OWNED, before="x", after="y", truncated=True)) == [Kind.TEST_TAMPER]


# ---------------------------------------------------------------- dependencies


def _pyproject(*deps: str, extra: str = "") -> str:
    listed = ", ".join(f'"{d}"' for d in deps)
    return f'[project]\nname = "x"\ndependencies = [{listed}]\n{extra}'


def test_an_undeclared_dependency_is_minor() -> None:
    c = change(
        "pyproject.toml", before=_pyproject("fastapi"), after=_pyproject("fastapi", "requests>=2")
    )
    found = check_changes(ChangeSet("a" * 40, files=(c,)), task(), POLICY)
    assert [(v.kind, v.level) for v in found] == [(Kind.DEPENDENCY, Level.MINOR)]
    assert "pypi dependency requests is not in deps_add" in found[0].detail


def test_a_declared_dependency_passes_whatever_its_spelling() -> None:
    t = task(deps_add=[DependencyAdd(ecosystem=Ecosystem.PYPI, name="Flask_SQLAlchemy")])
    c = change("pyproject.toml", before=_pyproject(), after=_pyproject("flask-sqlalchemy[async]"))
    assert kinds(c, t=t) == []


def test_allow_new_dependencies_allow_skips_the_declared_check() -> None:
    c = change("pyproject.toml", before=_pyproject(), after=_pyproject("requests"))
    assert kinds(c, policy=CheckPolicy(allow_new_dependencies="allow")) == []


def test_every_pyproject_dependency_table_is_read() -> None:
    text = _pyproject(
        "a",
        extra=(
            '[project.optional-dependencies]\nweb = ["b"]\nbad = "x"\n'
            '[dependency-groups]\ndev = ["c"]\n'
            '[tool.uv]\ndev-dependencies = ["d"]\n'
            '[tool.poetry.dependencies]\npython = "^3.12"\ne = "*"\n'
        ),
    )
    deps = manifest_deps("pyproject.toml", text)
    assert deps is not None
    assert {n for _, n in deps.names} == {"a", "b", "c", "d", "e"}
    assert manifest_deps("pyproject.toml", "[project]\ndependencies = 'x'\n") is not None
    assert manifest_deps("src/x.py", "anything") is not None


def test_requirements_files_and_index_options() -> None:
    before = "fastapi==1.0\n"
    after = (
        "fastapi==1.0\n# comment\n\n-r other.txt\nrequests>=2  # http\n"
        "--extra-index-url https://evil.example/simple\ngit+https://evil.example/x.git\n"
        "-e ./local\n"
    )
    found = check_changes(
        ChangeSet("a" * 40, files=(change("requirements-dev.txt", before=before, after=after),)),
        task(owns_files=["requirements-dev.txt"]),
        POLICY,
    )
    details = sorted(v.detail for v in found)
    assert "pypi dependency requests is not in deps_add" in details
    assert sum("source outside the registry" in d for d in details) == 3


def test_package_json_dependencies_and_non_registry_sources() -> None:
    before = json.dumps({"dependencies": {"react": "^18.0.0"}})
    after = json.dumps(
        {
            "dependencies": {"react": "^18.0.0", "lodash": "4.17.21", "evil": "github:x/y"},
            "devDependencies": {"jest": "latest"},
            "peerDependencies": "nope",
        }
    )
    t = task(owns_files=["package.json"],
             deps_add=[DependencyAdd(ecosystem=Ecosystem.NPM, name="lodash")])  # fmt: skip
    found = check_changes(
        ChangeSet("a" * 40, files=(change("package.json", before=before, after=after),)), t, POLICY
    )
    details = sorted(v.detail for v in found)
    assert details == [
        "npm dependency evil is not in deps_add",
        "npm dependency jest is not in deps_add",
        "source outside the registry: evil@github:x/y",
    ]


def test_an_unreadable_manifest_is_a_violation() -> None:
    owner = task(owns_files=["package.json"])
    assert kinds(change("package.json", before="{}", after="{nope"), t=owner) == [Kind.DEPENDENCY]
    assert kinds(change("pyproject.toml", before="", after="x", truncated=True)) == [
        Kind.DEPENDENCY
    ]


def test_new_dependencies_skip_lockfiles_and_unreadable_before() -> None:
    changes = ChangeSet(
        "a" * 40,
        files=(
            change("uv.lock", before="", after='[[package]]\nname = "x"\n'),
            change("pyproject.toml", before="[x", after=_pyproject("a")),
            change("src/x.py", before="", after="import a\n"),
        ),
    )
    assert new_dependencies(changes) == []
    assert normalize_pypi("Foo__Bar.baz") == "foo-bar-baz"


# ---------------------------------------------------------------- links, integrity, hidden


def test_links_out_of_the_workspace_are_severe() -> None:
    out = change("src/clinic/booking/key", ChangeStatus.ADDED, link_target="/x", link_escapes=True)
    onto = change("src/clinic/booking/a", ChangeStatus.ADDED, link_target="AGENTS.md",
                  link_protected=True)  # fmt: skip
    found = check_changes(ChangeSet("a" * 40, files=(out, onto)), task(), POLICY)
    assert [(v.kind, v.level) for v in found] == [(Kind.SYMLINK, Level.SEVERE)] * 2


def test_integrity_hidden_and_incomplete_are_severe() -> None:
    found = check_changes(
        ChangeSet("a" * 40, integrity=(".git/config",), complete=False), task(), POLICY
    )
    assert [v.kind for v in found] == [Kind.GIT_INTEGRITY]
    found = check_changes(ChangeSet("a" * 40, hidden=(".env",), complete=False), task(), POLICY)
    assert [v.kind for v in found] == [Kind.INCOMPLETE, Kind.HIDDEN_CHANGE]
    assert all(v.level is Level.SEVERE for v in found)


def test_severe_findings_come_first() -> None:
    found = check_changes(
        ChangeSet("a" * 40, files=(change("a.py"), change("AGENTS.md"))), task(), POLICY
    )
    assert [v.kind for v in found] == [Kind.PROTECTED_PATH, Kind.OUT_OF_SCOPE]


# ---------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    ("path", "glob", "expected"),
    [
        ("src/a.py", "src/**", True),
        ("src/a/b/c.py", "src/**", True),
        ("src", "src/**", True),
        ("src/a.py", "src/*.py", True),
        ("src/a/b.py", "src/*.py", False),
        ("tests/x.py", "src/**", False),
        ("a/b", "**/b", True),
        ("SRC/a.py", "src/**", False),
    ],
)
def test_glob_match(path: str, glob: str, expected: bool) -> None:
    assert glob_match(path, glob) is expected


def test_glob_match_can_fold_case() -> None:
    assert glob_match("SRC/a.py", "src/**", fold=True)


def test_glob_match_memoizes_repeated_globstars() -> None:
    assert glob_match("a/b/c/d", "**/**/**/d")
    assert not glob_match("a/b/c/d", "**/**/**/e")


def test_added_and_removed_manifests_and_config() -> None:
    t = task(owns_files=["src/**"])
    added = _pyproject("a", extra='[tool.pytest.ini_options]\naddopts = "-q"\n')
    found = kinds(change("pyproject.toml", ChangeStatus.ADDED, before=None, after=added), t=t)
    assert found == [Kind.TEST_CONFIG, Kind.DEPENDENCY]
    gone = json.dumps({"jest": {}})
    removed = change("package.json", ChangeStatus.DELETED, before=gone, after=None)
    assert kinds(removed, t=t) == [Kind.TEST_CONFIG]
    odd = '[project]\ndependencies = [1, "!!!", "ok"]\n'
    deps = manifest_deps("pyproject.toml", odd)
    assert deps is not None
    assert {n for _, n in deps.names} == {"ok"}


def test_needs_content_and_watched_paths() -> None:
    assert needs_content("tests/x.py", ("tests",))
    assert needs_content("pyproject.toml", ())
    assert needs_content("requirements.txt", ())
    assert not needs_content("src/a.py", ("tests",))
    assert is_manifest("web/package-lock.json")
    assert is_watched(".env", POLICY)
    assert is_watched("tests/data.json", POLICY)
    assert is_watched("pytest.ini", POLICY)
    assert not is_watched("build/out.o", POLICY)
