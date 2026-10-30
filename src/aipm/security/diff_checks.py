"""Post-change checks (C-16, ARCHITECTURE §12.4 step 3, SECURITY.md §7.8, §9.2, §13.3).

A pure function over a `ChangeSet` that `aipm.execution.git` builds: no git, no file I/O. Each
finding is a `Violation`, classified as in §12.4:

- **severe** (the task is blocked, no retry, a security event): git integrity (config, hooks,
  the agents' global config), protected paths, tests and test configuration the task does not
  own (SECURITY.md §9.2), symbolic links that leave the workspace or land on a protected path,
  watched files changed behind `.gitignore`, and a change set aipm could not read whole;
- **minor** (the attempt fails, nothing is reverted in manual mode): edits outside `owns_files`,
  dependencies not declared in `deps_add`, dependency sources outside the registry (in a
  manifest or a lockfile) and changed package-manager configuration, tamper signs on owned tests
  (skip, xfail or focus markers added, test functions removed, fewer assertions), and a changed
  file that changed again while the gates ran (`aipm.app.verify` checks that one).

A commit `verify --commit` made that does not hold what the checks and gates saw is severe too
(`commit_mismatch`, red-team v0.2 RT02-8; `aipm.app.verify` checks it).

Contents are T2: the parsers here read them as data only and never fail open. A manifest that
cannot be parsed counts as a violation.
"""

import json
import re
import tomllib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase
from functools import cache
from typing import Any, cast

from aipm.domain.dag import JS_TEST_RUNNER_CONFIG, TEST_FILE_PATTERNS
from aipm.domain.models import ChangeSet, ChangeStatus, Ecosystem, FileChange, Task
from aipm.security.paths import is_protected, protected_patterns


class Level(StrEnum):
    """How bad a violation is (ARCHITECTURE §12.4)."""

    MINOR = "minor"
    SEVERE = "severe"


class Kind(StrEnum):
    """What a violation is about."""

    GIT_INTEGRITY = "git_integrity"
    INCOMPLETE = "incomplete"
    PROTECTED_PATH = "protected_path"
    HIDDEN_CHANGE = "hidden_change"
    SYMLINK = "symlink"
    TEST_NOT_OWNED = "test_not_owned"
    TEST_CONFIG = "test_config"
    OUT_OF_SCOPE = "out_of_scope"
    TEST_TAMPER = "test_tamper"
    DEPENDENCY = "dependency"
    CHANGED_DURING_GATES = "changed_during_gates"
    COMMIT_MISMATCH = "commit_mismatch"


_SEVERE = frozenset(
    {Kind.GIT_INTEGRITY, Kind.INCOMPLETE, Kind.PROTECTED_PATH, Kind.HIDDEN_CHANGE, Kind.SYMLINK,
     Kind.TEST_NOT_OWNED, Kind.TEST_CONFIG, Kind.COMMIT_MISMATCH}
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class Violation:
    """One post-change finding. `detail` is aipm's own words; `path` is T2."""

    kind: Kind
    path: str
    detail: str

    @property
    def level(self) -> Level:
        """`severe` or `minor`, from the kind (ARCHITECTURE §12.4)."""
        return Level.SEVERE if self.kind in _SEVERE else Level.MINOR


@dataclass(frozen=True, slots=True)
class CheckPolicy:
    """The configuration the checks need: test roots, extra protected paths, the new-dependency
    policy (`security.allow_new_dependencies`)."""

    test_roots: tuple[str, ...] = ("tests",)
    extra_protected: tuple[str, ...] = ()
    allow_new_dependencies: str = "ask"

    def protected(self) -> tuple[str, ...]:
        """The protected patterns: SECURITY.md §9.2 plus the extras."""
        return protected_patterns(self.extra_protected)


# ---------------------------------------------------------------- path classes

MANIFESTS = frozenset({"pyproject.toml", "package.json"})
REQUIREMENTS = re.compile(r"requirements[\w.\-]*\.(?:txt|in)")
LOCKFILES: dict[str, Ecosystem] = {
    "uv.lock": Ecosystem.PYPI,
    "poetry.lock": Ecosystem.PYPI,
    "pylock.toml": Ecosystem.PYPI,
    "package-lock.json": Ecosystem.NPM,
    "npm-shrinkwrap.json": Ecosystem.NPM,
    "pnpm-lock.yaml": Ecosystem.NPM,
    "yarn.lock": Ecosystem.NPM,
}
MAX_LOCKFILE_BYTES = 16 * 1_048_576
"""How much of a lockfile the checks read; a larger one cannot be checked (a violation)."""
PACKAGE_CONFIG = frozenset(
    {".npmrc", ".pnpmfile.cjs", ".pnpmfile.mjs", ".yarnrc", ".yarnrc.yml", "bunfig.toml",
     "uv.toml", "pip.conf", "pip.ini"}
)  # fmt: skip
"""Package-manager settings the prepare step reads: they can name another registry, or a
program to run during install (`.pnpmfile.cjs`, `git=` in `.npmrc`, `yarnPath`). RT02-4."""
_WHOLE_FILE_TEST_CONFIG = frozenset(
    {"pytest.ini", ".coveragerc", "conftest.py", *JS_TEST_RUNNER_CONFIG}
)
_SECTIONED = frozenset({"pyproject.toml", "setup.cfg", "tox.ini", "package.json"})
_IGNORE_FILES = frozenset({".gitignore"})
"""A `.gitignore` decides what git lists, so one that ignores itself (`*`) could hide new files
from the change set (RT02-6): changing one behind `.gitignore` is a hidden change."""


def _name(path: str) -> str:
    return path.rsplit("/", 1)[-1]


@cache
def _glob_parts(glob: str) -> tuple[str, ...]:
    return tuple(glob.split("/"))


def glob_match(path: str, glob: str, *, fold: bool = False) -> bool:
    """Whether a normalized path matches an ownership glob (`*`, `?` in one component, `**` for
    any number), anchored at the repository root. Memoized per call, so it cannot backtrack."""
    parts = (path.casefold() if fold else path).split("/")
    pattern = _glob_parts(glob.casefold() if fold else glob)
    memo: dict[tuple[int, int], bool] = {}

    def at(i: int, j: int) -> bool:
        key = (i, j)
        if key not in memo:
            if j == len(pattern):
                memo[key] = i == len(parts)
            elif pattern[j] == "**":
                memo[key] = any(at(k, j + 1) for k in range(i, len(parts) + 1))
            else:
                here = i < len(parts) and fnmatchcase(parts[i], pattern[j])
                memo[key] = here and at(i + 1, j + 1)
        return memo[key]

    return at(0, 0)


def is_owned(path: str, task: Task) -> bool:
    """Whether a path matches one of the task's `owns_files` globs."""
    return any(glob_match(path, glob) for glob in task.owns_files)


def is_test_path(path: str, test_roots: Sequence[str]) -> bool:
    """A test file: under a test root, or named like one at any depth (ARCHITECTURE §13.3)."""
    folded = path.casefold()
    name = _name(folded)
    if any(folded == r.casefold() or folded.startswith(f"{r.casefold()}/") for r in test_roots):
        return True
    return any(fnmatchcase(name, pattern.casefold()) for pattern in TEST_FILE_PATTERNS)


def is_test_config_file(path: str) -> bool:
    """A file that may hold test-runner configuration (whole, or in a section)."""
    name = _name(path.casefold())
    return name in _WHOLE_FILE_TEST_CONFIG or name in _SECTIONED


def is_manifest(path: str) -> bool:
    """A dependency manifest or lockfile the dependency check reads."""
    name = _name(path)
    return name in MANIFESTS or name in LOCKFILES or bool(REQUIREMENTS.fullmatch(name))


def is_lockfile(path: str) -> bool:
    """A lockfile the dependency checks read."""
    return _name(path) in LOCKFILES


def is_package_config(path: str) -> bool:
    """Package-manager settings that the prepare step reads (`PACKAGE_CONFIG`)."""
    return _name(path.casefold()) in PACKAGE_CONFIG


def is_dependency_path(path: str) -> bool:
    """A file that changes what the prepare step installs, or how."""
    return is_manifest(path) or is_package_config(path)


def content_limit(path: str, default: int) -> int:
    """How many bytes of a changed file the checks read: lockfiles are larger than code."""
    return MAX_LOCKFILE_BYTES if is_lockfile(path) else default


def needs_content(path: str, test_roots: Sequence[str]) -> bool:
    """Whether the checks read this path's contents (for `aipm.execution.git.change_set`)."""
    return is_test_path(path, test_roots) or is_test_config_file(path) or is_manifest(path)


def is_watched(path: str, policy: CheckPolicy) -> bool:
    """Whether an ignored file on this path must not change: a protected path, a test, test
    configuration, or a `.gitignore` (one that ignores itself hides what it ignores)."""
    name = _name(path.casefold())
    return (
        is_protected(path, policy.protected())
        or is_test_path(path, policy.test_roots)
        or name in _WHOLE_FILE_TEST_CONFIG
        or name in _IGNORE_FILES
    )


# ---------------------------------------------------------------- test configuration


def _toml(text: str | None) -> dict[str, Any] | None:
    if text is None:
        return {}
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None


def _json(text: str | None) -> dict[str, Any] | None:
    if text is None:
        return {}
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return cast("dict[str, Any]", value) if isinstance(value, dict) else None


_INI_SECTION = re.compile(r"^\s*\[([^\]\n]+)\]", re.MULTILINE)


def _ini_sections(text: str | None, wanted: Iterable[str]) -> str:
    """The text of the INI sections whose names start with one of `wanted` (case-folded)."""
    if not text:
        return ""
    prefixes = tuple(w.casefold() for w in wanted)
    out: list[str] = []
    matches = list(_INI_SECTION.finditer(text))
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        if match.group(1).strip().casefold().startswith(prefixes):
            out.append(text[match.start() : end])
    return "\n".join(out)


def _test_config_view(path: str, text: str | None) -> object:
    """The test-runner part of a config file, to compare before and after; `None` if unreadable."""
    name = _name(path.casefold())
    if name == "pyproject.toml":
        doc = _toml(text)
        if doc is None:
            return None
        tool = _table(doc, "tool")
        return {k: tool.get(k) for k in ("pytest", "coverage")}
    if name == "package.json":
        doc = _json(text)
        return None if doc is None else {k: doc.get(k) for k in ("jest", "vitest", "mocha", "c8")}
    if name == "setup.cfg":
        return _ini_sections(text, ("tool:pytest", "coverage:"))
    if name == "tox.ini":
        return _ini_sections(text, ("pytest", "coverage:"))
    return text


# ---------------------------------------------------------------- tamper heuristics

_SKIP_MARKERS = re.compile(
    r"\bmark\.(?:skip|skipif|xfail)\b|pytest\.(?:skip|xfail|importorskip)\s*\(|"
    r"(?<![\w.])(?:skip|xfail|importorskip)\s*\(|"  # `from pytest import mark, skip` (RT02)
    r"unittest\.skip\w*|\bskipTest\s*\(|\bSkipTest\b|__test__\s*=\s*False|"
    r"\b(?:it|test|describe|suite|context)\.(?:skip|todo|only|fails)\b|"
    r"\b(?:xit|xdescribe|xtest|fit|fdescribe|ftest)\s*\(|\bt\.Skip\w*\s*\("
)
_TEST_FUNCS = re.compile(
    r"^\s*(?:async\s+)?def\s+(test\w*)\s*\(|^\s*func\s+(Test\w+)\s*\(|"
    r"\b(?:it|test)\s*\(\s*(['\"`])((?:(?!\3).){1,200})\3",
    re.MULTILINE,
)
_ASSERTS = re.compile(
    r"^\s*assert\b|\bself\.assert\w*\s*\(|\bpytest\.raises\s*\(|\bexpect\s*\(|"
    r"\bassert\.\w+\s*\(|\bt\.(?:Error|Errorf|Fatal|Fatalf)\s*\(|\brequire\.\w+\s*\(",
    re.MULTILINE,
)


def _test_names(text: str) -> set[str]:
    names: set[str] = set()
    for match in _TEST_FUNCS.finditer(text):
        names.add(match.group(1) or match.group(2) or match.group(4) or "")
    names.discard("")
    return names


def tamper_signs(before: str | None, after: str | None) -> list[str]:
    """Why an owned test change looks like weakening (ARCHITECTURE §13.3); empty if it does not."""
    old, new = before or "", after or ""
    signs: list[str] = []
    added = len(_SKIP_MARKERS.findall(new)) - len(_SKIP_MARKERS.findall(old))
    if added > 0:
        signs.append(f"{added} skip, xfail or focus marker(s) added")
    removed = sorted(_test_names(old) - _test_names(new))
    if removed:
        shown = ", ".join(removed[:5]) + (" …" if len(removed) > 5 else "")
        signs.append(f"test(s) removed: {shown}")
    fewer = len(_ASSERTS.findall(old)) - len(_ASSERTS.findall(new))
    if fewer > 0:
        signs.append(f"{fewer} fewer assertion(s)")
    return signs


# ---------------------------------------------------------------- dependencies

_PEP508_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?)")
_PEP508_REST = re.compile(
    r"\s*(?:\[[A-Za-z0-9,._\-\s]*\])?\s*"
    r"(?:\(?\s*[<>=!~][<>=!~\s0-9A-Za-z.*+,_\-]*\)?)?\s*(?:;.*)?",
    re.DOTALL,
)
"""What may follow a requirement's name: extras, a version, markers. Never `@` (a direct
reference to a URL or a file), nor a path."""
_ARCHIVE = re.compile(r"(?i).*\.(?:whl|zip|tgz|tar|tar\.gz|tar\.bz2|tar\.xz)")
_REQ_OPTIONS_OK = re.compile(
    r"(?:--hash|--pre|--prefer-binary|--only-binary|--no-binary|--require-hashes)(?:[\s=].*)?",
    re.DOTALL,
)
"""requirements.txt options that change nothing about where packages come from."""
_REQ_INCLUDE = re.compile(r"(?:-r|--requirement|-c|--constraint)(?:\s*=\s*|\s+)(\S+)")
_NPM_REGISTRY_SPEC = re.compile(r"^[\s~^<>=*xX0-9.\-|+a-z]*$")
_NPM_FILE_SPEC = re.compile(r"(?i).*\.(?:tgz|tar|tar\.gz)")
"""npm reads a spec ending in a tarball extension as a local file (npm-package-arg)."""

DEFAULT_REGISTRIES: dict[Ecosystem, tuple[str, ...]] = {
    Ecosystem.PYPI: ("https://pypi.org/simple", "https://files.pythonhosted.org/"),
    Ecosystem.NPM: ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/"),
}
"""Registries a lockfile may name without that being a new source."""


def normalize_pypi(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of `-`, `_` and `.` become one `-`."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True, slots=True)
class Deps:
    """Direct dependencies read from one manifest, and sources that bypass the registry."""

    names: frozenset[tuple[Ecosystem, str]]
    off_registry: frozenset[str] = frozenset()
    unchecked: frozenset[str] = frozenset()
    """`-r FILE` or `-c FILE` lines naming a file the dependency check does not read."""


def _requirement(item: str) -> tuple[str | None, str | None]:
    """A PEP 508 string as `(normalized name, None)`, or `(None, why)` for a direct reference,
    a path or anything else that does not come from the registry by name (RT02-2)."""
    line = item.strip()
    match = _PEP508_NAME.match(line)
    if match is None or _ARCHIVE.fullmatch(match.group(1)):
        return None, line[:120]
    rest = line[match.end() :]
    if not _PEP508_REST.fullmatch(rest) or "@" in rest.split(";", 1)[0] or "://" in line:
        return None, line[:120]
    return normalize_pypi(match.group(1)), None


def _pep508(items: Iterable[object], names: set[str], off: set[str], where: str) -> None:
    for item in items:
        if isinstance(item, str):
            name, why = _requirement(item)
            if name is not None:
                names.add(name)
            else:
                off.add(f"{where}: {why}")


def _table(doc: dict[str, Any], key: str) -> dict[str, Any]:
    """`doc[key]` when it is a table, else an empty one (T2 data is never trusted to fit)."""
    value = doc.get(key)
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _items(doc: dict[str, Any], key: str) -> list[object]:
    """`doc[key]` when it is a list, else an empty one."""
    value = doc.get(key)
    return cast("list[object]", value) if isinstance(value, list) else []


def _shown(value: object) -> str:
    """A source as stable, short text, so the same source before and after compares equal."""
    return json.dumps(value, sort_keys=True, default=str)[:160]


def _uv_sources(tool: dict[str, Any], off: set[str]) -> None:
    """`[tool.uv]` settings that fetch from elsewhere than the registry: sources (except
    workspace members), indexes, index URLs and find-links (RT02-2)."""
    uv = _table(tool, "uv")
    for name, source in _table(uv, "sources").items():
        entries: list[object] = (
            cast("list[object]", source) if isinstance(source, list) else [source]
        )
        for entry in entries:
            if entry != {"workspace": True}:
                off.add(f"tool.uv.sources {name}: {_shown(entry)}")
    for table in (uv, _table(uv, "pip")):
        for index in _items(table, "index"):
            off.add(f"tool.uv.index: {_shown(index)}")
        for key in ("index-url", "extra-index-url", "find-links"):
            value = table.get(key)
            for url in cast("list[object]", value) if isinstance(value, list) else [value]:
                if url is not None:
                    off.add(f"tool.uv {key}: {_shown(url)}")


_POETRY_SOURCE_KEYS = frozenset({"git", "url", "path", "source", "develop"})


def _poetry(tool: dict[str, Any], names: set[str], off: set[str]) -> None:
    """Poetry's dependency tables (including groups) and its extra sources."""
    poetry = _table(tool, "poetry")
    tables = [_table(poetry, "dependencies"), _table(poetry, "dev-dependencies")]
    for group in _table(poetry, "group").values():
        if isinstance(group, dict):
            tables.append(_table(cast("dict[str, Any]", group), "dependencies"))
    for table in tables:
        for name, spec in table.items():
            if name == "python":
                continue
            names.add(normalize_pypi(name))
            specs: list[object] = cast("list[object]", spec) if isinstance(spec, list) else [spec]
            for item in specs:
                table_spec = cast("dict[str, Any]", item) if isinstance(item, dict) else {}
                if _POETRY_SOURCE_KEYS & set(table_spec):
                    off.add(f"tool.poetry {name}: {_shown(table_spec)}")
    for source in _items(poetry, "source"):
        off.add(f"tool.poetry.source: {_shown(source)}")


def _pyproject_deps(doc: dict[str, Any]) -> Deps:
    names: set[str] = set()
    off: set[str] = set()
    project = _table(doc, "project")
    _pep508(_items(project, "dependencies"), names, off, "project.dependencies")
    for table, where in ((_table(project, "optional-dependencies"), "optional-dependencies"),
                         (_table(doc, "dependency-groups"), "dependency-groups")):  # fmt: skip
        for group in table:
            _pep508(_items(table, group), names, off, f"{where}.{group}")
    _pep508(_items(_table(doc, "build-system"), "requires"), names, off, "build-system.requires")
    tool = _table(doc, "tool")
    _pep508(_items(_table(tool, "uv"), "dev-dependencies"), names, off, "tool.uv.dev-dependencies")
    _uv_sources(tool, off)
    _poetry(tool, names, off)
    return Deps(frozenset((Ecosystem.PYPI, n) for n in names), frozenset(off))


def _requirements_deps(text: str) -> Deps:
    """A requirements file: names by PEP 508; every option that is not harmless, every URL,
    path, archive or direct reference is a source outside the registry (RT02-2)."""
    names: set[str] = set()
    off: set[str] = set()
    unchecked: set[str] = set()
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip().removesuffix("\\").strip()  # pip joins on "\\"
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            include = _REQ_INCLUDE.fullmatch(line)
            if include is not None:
                if not REQUIREMENTS.fullmatch(_name(include.group(1))):
                    unchecked.add(line[:120])  # a requirements* file is checked on its own
            elif not _REQ_OPTIONS_OK.fullmatch(line):
                off.add(line[:120])
            continue
        name, why = _requirement(line.split(" --hash", 1)[0])
        if name is not None:
            names.add(name)
        else:
            off.add(f"{why}")
    return Deps(frozenset((Ecosystem.PYPI, n) for n in names), frozenset(off), frozenset(unchecked))


def _package_json_deps(doc: dict[str, Any]) -> Deps:
    names: set[str] = set()
    off: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in _table(doc, key).items():
            names.add(name.lower())
            if (
                not isinstance(spec, str)
                or not _NPM_REGISTRY_SPEC.fullmatch(spec)
                or _NPM_FILE_SPEC.fullmatch(spec.strip())
            ):
                off.add(f"{name}@{spec!s:.80}")
    return Deps(frozenset((Ecosystem.NPM, n) for n in names), frozenset(off))


def manifest_deps(path: str, text: str | None) -> Deps | None:
    """The direct dependencies a manifest declares; `None` if it cannot be parsed."""
    name = _name(path)
    if text is None:
        return Deps(frozenset())
    if name == "pyproject.toml":
        doc = _toml(text)
        return None if doc is None else _pyproject_deps(doc)
    if name == "package.json":
        doc = _json(text)
        return None if doc is None else _package_json_deps(doc)
    if REQUIREMENTS.fullmatch(name):
        return _requirements_deps(text)
    return Deps(frozenset())


def declared(task: Task) -> frozenset[tuple[Ecosystem, str]]:
    """The task's `deps_add`, normalized."""
    return frozenset(
        (d.ecosystem, normalize_pypi(d.name) if d.ecosystem is Ecosystem.PYPI else d.name.lower())
        for d in task.deps_add
    )


def new_dependencies(changes: ChangeSet) -> list[tuple[str, Ecosystem, str]]:
    """Every direct dependency a changed manifest adds: (manifest, ecosystem, name)."""
    found: list[tuple[str, Ecosystem, str]] = []
    for change in changes.files:
        if is_lockfile(change.path) or not is_manifest(change.path):
            continue
        before = manifest_deps(change.path, change.before)
        after = manifest_deps(change.path, change.after)
        if before is None or after is None:
            continue
        found += [(change.path, eco, n) for eco, n in sorted(after.names - before.names)]
    return found


# ---------------------------------------------------------------- lockfiles (RT02-3)


@dataclass(frozen=True, slots=True)
class LockDeps:
    """The packages one lockfile pins, and every source of theirs outside the default
    registries (described, so the same source compares equal before and after)."""

    names: frozenset[tuple[Ecosystem, str]]
    sources: frozenset[str] = frozenset()


def _registry_ok(ecosystem: Ecosystem, url: str) -> bool:
    """Whether `url` is a default registry, or a file under one (never a look-alike host)."""
    clean = url.strip()
    for registry in DEFAULT_REGISTRIES[ecosystem]:
        base = registry.rstrip("/")
        if clean.rstrip("/") == base or clean.startswith(f"{base}/"):
            return True
    return False


def _uv_lock(doc: dict[str, Any]) -> LockDeps:
    names: set[tuple[Ecosystem, str]] = set()
    sources: set[str] = set()
    for item in _items(doc, "package"):
        package = cast("dict[str, Any]", item) if isinstance(item, dict) else {}
        name = package.get("name")
        if not isinstance(name, str):
            continue
        source = _table(package, "source")
        if "editable" in source or "virtual" in source:
            continue  # the project itself, or a workspace member in the repository
        names.add((Ecosystem.PYPI, normalize_pypi(name)))
        registry = source.get("registry")
        if not isinstance(registry, str) or not _registry_ok(Ecosystem.PYPI, registry):
            sources.add(f"{name}: {_shown(source)}")
    return LockDeps(frozenset(names), frozenset(sources))


def _poetry_lock(doc: dict[str, Any]) -> LockDeps:
    names: set[tuple[Ecosystem, str]] = set()
    sources: set[str] = set()
    for item in _items(doc, "package"):
        package = cast("dict[str, Any]", item) if isinstance(item, dict) else {}
        name = package.get("name")
        if not isinstance(name, str):
            continue
        names.add((Ecosystem.PYPI, normalize_pypi(name)))
        if "source" in package:
            sources.add(f"{name}: {_shown(package['source'])}")
    return LockDeps(frozenset(names), frozenset(sources))


def _pylock(doc: dict[str, Any]) -> LockDeps:
    names: set[tuple[Ecosystem, str]] = set()
    sources: set[str] = set()
    for item in _items(doc, "packages"):
        package = cast("dict[str, Any]", item) if isinstance(item, dict) else {}
        name = package.get("name")
        if not isinstance(name, str):
            continue
        names.add((Ecosystem.PYPI, normalize_pypi(name)))
        index = package.get("index")
        local = {k: package[k] for k in ("vcs", "directory", "archive") if k in package}
        if local or not isinstance(index, str) or not _registry_ok(Ecosystem.PYPI, index):
            sources.add(f"{name}: {_shown(local or {'index': index})}")
    return LockDeps(frozenset(names), frozenset(sources))


def _npm_entry(name: str, entry: dict[str, Any], names: set[tuple[Ecosystem, str]],
               sources: set[str]) -> None:  # fmt: skip
    version = entry.get("version")
    real = entry.get("name") if isinstance(entry.get("name"), str) else name
    if isinstance(version, str) and version.startswith("npm:"):
        real = version[4:].rsplit("@", 1)[0]  # an alias (`npm:other@1`) installs `other`
    names.add((Ecosystem.NPM, str(real).lower()))
    resolved = entry.get("resolved")
    if isinstance(resolved, str) and not _registry_ok(Ecosystem.NPM, resolved):
        sources.add(f"{real}: {resolved[:160]}")
    if isinstance(version, str) and re.match(r"[a-z+]+:", version) and real == name:
        sources.add(f"{real}: {version[:160]}")


def _npm_lock(doc: dict[str, Any]) -> LockDeps:
    names: set[tuple[Ecosystem, str]] = set()
    sources: set[str] = set()
    for key, value in _table(doc, "packages").items():
        if "node_modules/" not in key or not isinstance(value, dict):
            continue  # "" is the project; other keys are workspace members in the repository
        entry = cast("dict[str, Any]", value)
        if entry.get("link") is True:
            continue
        _npm_entry(key.rsplit("node_modules/", 1)[-1], entry, names, sources)
    pending = [_table(doc, "dependencies")]
    while pending:  # lockfileVersion 1 nests its dependencies
        for name, value in pending.pop().items():
            if isinstance(value, dict):
                entry = cast("dict[str, Any]", value)
                _npm_entry(name, entry, names, sources)
                pending.append(_table(entry, "dependencies"))
    return LockDeps(frozenset(names), frozenset(sources))


_PNPM_KEY = re.compile(r"  ['\"]?/?(@?[^@\s'\"/]+(?:/[^@\s'\"/]+)?)[@/](?=\d)")
_PNPM_SOURCE = re.compile(r"\b(?:tarball|repo|directory|commit)\s*:\s*['\"]?([^,}\s'\"]+)")


def _pnpm_lock(text: str) -> LockDeps:
    """pnpm-lock.yaml, read line by line (L0 has no YAML parser): package keys two spaces in
    under `packages:` or `snapshots:`, and `tarball`, `repo`, `directory` or `commit` fields."""
    names: set[tuple[Ecosystem, str]] = set()
    sources: set[str] = set()
    section = ""
    current = ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.split(":", 1)[0].strip()
            continue
        if section not in ("packages", "snapshots"):
            continue
        key = _PNPM_KEY.match(line)
        if key is not None and line.rstrip().endswith(":"):
            current = key.group(1)
            names.add((Ecosystem.NPM, current.lower()))
            continue
        source = _PNPM_SOURCE.search(line)
        if source is not None and not _registry_ok(Ecosystem.NPM, source.group(1)):
            sources.add(f"{current}: {line.strip()[:160]}")
    return LockDeps(frozenset(names), frozenset(sources))


_YARN_SPEC = re.compile(r"\s*\"?(@?[^@\s\"]+)@")
_YARN_RESOLVED = re.compile(r"\s+(?:resolved|resolution)\s*:?\s+\"?([^\"\s]+)\"?")


def _yarn_lock(text: str) -> LockDeps:
    """yarn.lock, classic and berry: entry headers name packages; `resolved` must be a default
    registry, and a berry `resolution` must use the `npm:` (or `workspace:`) protocol."""
    names: set[tuple[Ecosystem, str]] = set()
    sources: set[str] = set()
    current = ""
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            spec = _YARN_SPEC.match(line.split(",", 1)[0])
            current = spec.group(1) if spec is not None and line[:2] != "__" else ""
            if current:
                names.add((Ecosystem.NPM, current.lower()))
            continue
        found = _YARN_RESOLVED.match(line)
        if found is None or not current:
            continue
        value = found.group(1)
        protocol = value[len(current) + 1 :] if value.startswith(f"{current}@") else value
        if protocol.startswith(("npm:", "workspace:")) or "builtin<compat/" in protocol:
            continue
        if not _registry_ok(Ecosystem.NPM, value):
            sources.add(f"{current}: {value[:160]}")
    return LockDeps(frozenset(names), frozenset(sources))


_TOML_LOCKS: dict[str, Callable[[dict[str, Any]], LockDeps]] = {
    "uv.lock": _uv_lock,
    "poetry.lock": _poetry_lock,
    "pylock.toml": _pylock,
}
_TEXT_LOCKS: dict[str, Callable[[str], LockDeps]] = {
    "pnpm-lock.yaml": _pnpm_lock,
    "yarn.lock": _yarn_lock,
}


def lock_deps(path: str, text: str | None) -> LockDeps | None:
    """The packages a lockfile pins and their sources; `None` if it cannot be parsed."""
    name = _name(path)
    if text is None:
        return LockDeps(frozenset())
    if name in _TOML_LOCKS:
        doc = _toml(text)
        return None if doc is None else _TOML_LOCKS[name](doc)
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        doc = _json(text)
        return None if doc is None else _npm_lock(doc)
    reader = _TEXT_LOCKS.get(name)
    return None if reader is None else reader(text)


def new_lock_packages(changes: ChangeSet) -> list[tuple[str, Ecosystem, str]]:
    """Every package a changed lockfile pins that it did not pin before: (lockfile,
    ecosystem, name). The deps gate looks each one up like a new direct dependency."""
    found: list[tuple[str, Ecosystem, str]] = []
    for change in changes.files:
        if not is_lockfile(change.path) or change.status is ChangeStatus.DELETED:
            continue
        before = lock_deps(change.path, change.before) or LockDeps(frozenset())
        after = lock_deps(change.path, change.after)
        if after is not None and not change.truncated:
            found += [(change.path, eco, n) for eco, n in sorted(after.names - before.names)]
    return found


# ---------------------------------------------------------------- the checks


def _integrity(changes: ChangeSet) -> list[Violation]:
    found = [
        Violation(Kind.GIT_INTEGRITY, label, "changed since the task started")
        for label in changes.integrity
    ]
    if not changes.complete and not changes.integrity:
        found.append(
            Violation(
                Kind.INCOMPLETE,
                "(change set)",
                "aipm could not read every change (too many, or a name it cannot read)",
            )
        )
    found += [
        Violation(Kind.HIDDEN_CHANGE, path, "an ignored protected or test file changed")
        for path in changes.hidden
    ]
    return found


def _check_path(change: FileChange, task: Task, policy: CheckPolicy) -> list[Violation]:
    path = change.path
    patterns = policy.protected()
    if is_protected(path, patterns):
        return [Violation(Kind.PROTECTED_PATH, path, f"protected path {change.status.value}")]
    found: list[Violation] = []
    if change.link_escapes:
        found.append(Violation(Kind.SYMLINK, path, "symbolic link resolves outside the workspace"))
    elif change.link_protected:
        found.append(Violation(Kind.SYMLINK, path, "symbolic link resolves to a protected path"))
    owned = is_owned(path, task)
    if is_test_path(path, policy.test_roots):
        if not owned:
            found.append(Violation(Kind.TEST_NOT_OWNED, path, f"test not owned by {task.id}"))
            return found
        if change.truncated:
            found.append(Violation(Kind.TEST_TAMPER, path, "too large for the tamper check"))
        else:
            signs = tamper_signs(change.before, change.after)
            found += [Violation(Kind.TEST_TAMPER, path, sign) for sign in signs]
    elif is_test_config_file(path) and not owned:
        before = _test_config_view(path, change.before)
        after = _test_config_view(path, change.after)
        if change.truncated or before is None or after is None or before != after:
            detail = f"test configuration not owned by {task.id}"
            found.append(Violation(Kind.TEST_CONFIG, path, detail))
    if not owned and not found and not _lockfile_allowed(path, task):
        found.append(Violation(Kind.OUT_OF_SCOPE, path, f"outside the files {task.id} owns"))
    return found


def _lockfile_allowed(path: str, task: Task) -> bool:
    eco = LOCKFILES.get(_name(path))
    return eco is not None and any(d.ecosystem is eco for d in task.deps_add)


def _dependencies(changes: ChangeSet, task: Task, policy: CheckPolicy) -> list[Violation]:
    found: list[Violation] = []
    allowed = declared(task)
    for change in changes.files:
        if is_package_config(change.path):
            detail = "package manager configuration changed: it can redirect or run what " \
                "the prepare step installs"  # fmt: skip
            found.append(Violation(Kind.DEPENDENCY, change.path, detail))
        elif is_manifest(change.path):
            found += _new_sources(change)
    if policy.allow_new_dependencies == "allow":
        return found
    for path, eco, name in new_dependencies(changes):
        if (eco, name) not in allowed:
            detail = f"{eco.value} dependency {name} is not in deps_add"
            found.append(Violation(Kind.DEPENDENCY, path, detail))
    return found


def _new_sources(change: FileChange) -> list[Violation]:
    """Sources outside the registry that a changed manifest or lockfile adds (RT02-2, RT02-3);
    one that cannot be read whole is a violation too."""
    lock = is_lockfile(change.path)
    what = "lockfile" if lock else "manifest"
    hidden = frozenset[str]()
    if lock:
        old_lock = lock_deps(change.path, change.before) or LockDeps(frozenset())
        new_lock = None if change.truncated else lock_deps(change.path, change.after)
        added = None if new_lock is None else new_lock.sources - old_lock.sources
    else:
        old = manifest_deps(change.path, change.before) or Deps(frozenset())
        new = None if change.truncated else manifest_deps(change.path, change.after)
        added = None if new is None else new.off_registry - old.off_registry
        if new is not None:
            hidden = new.unchecked - old.unchecked
    if added is None:
        return [Violation(Kind.DEPENDENCY, change.path, f"{what} cannot be read")]
    found = [
        Violation(Kind.DEPENDENCY, change.path, f"source outside the registry: {source}")
        for source in sorted(added)
    ]
    detail = "includes a file the dependency check does not read"
    found += [
        Violation(Kind.DEPENDENCY, change.path, f"{detail}: {line}") for line in sorted(hidden)
    ]
    return found


def check_changes(changes: ChangeSet, task: Task, policy: CheckPolicy) -> list[Violation]:
    """Every post-change violation, severe ones first (ARCHITECTURE §12.4 step 3)."""
    found = _integrity(changes)
    for change in changes.files:
        found += _check_path(change, task, policy)
    found += _dependencies(changes, task, policy)
    return sorted(found, key=lambda v: (v.level is not Level.SEVERE, v.path, v.kind.value))


def severe(violations: Iterable[Violation]) -> list[Violation]:
    """The severe violations, in order."""
    return [v for v in violations if v.level is Level.SEVERE]
