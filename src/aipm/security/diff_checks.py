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
import posixpath
import re
import tomllib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
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
     "uv.toml", "pip.conf", "pip.ini", "pnpm-workspace.yaml"}
)  # fmt: skip
PACKAGE_CODE_DIRS = ("/.yarn/releases/", "/.yarn/plugins/")
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


def _fname(path: str) -> str:
    """The file name without regard to case: on macOS `UV.LOCK` is the file uv reads."""
    return _name(path).casefold()


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
    """A dependency manifest or lockfile the dependency check reads (any case)."""
    name = _fname(path)
    return name in MANIFESTS or name in LOCKFILES or bool(REQUIREMENTS.fullmatch(name))


def is_lockfile(path: str) -> bool:
    """A lockfile the dependency checks read (any case)."""
    return _fname(path) in LOCKFILES


def is_package_config(path: str) -> bool:
    """Package-manager settings that the prepare step reads (`PACKAGE_CONFIG`), and the yarn
    release and plugin files `yarnPath` and `plugins` run."""
    folded = f"/{path.casefold()}"
    return _fname(path) in PACKAGE_CONFIG or any(d in folded for d in PACKAGE_CODE_DIRS)


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
    except (tomllib.TOMLDecodeError, RecursionError):
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

MAX_LINE = 4096
"""A dependency line longer than this is not read but reported: the readers stay linear on
hostile input (security review of the v0.2 red-team fixes)."""
_PEP508_NAME = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?)")
_EXTRAS = re.compile(r"[A-Za-z0-9,._\- ]*")
_VERSION = re.compile(r"\(?\s*[<>=!~][<>=!~0-9A-Za-z.*+,_\- ]*\)?")
"""A version specifier: operators, versions, commas, spaces. Never `@`, `/` or `:`."""
_ARCHIVE = re.compile(
    r"(?i).*\.(?:whl|zip|tgz|tar|tar\.gz|tar\.bz2|tbz|tbz2|tar\.xz|txz|tlz|tar\.lz|tar\.lzma)"
)
"""pip's archive extensions: a requirement named like one is a file."""
_REQ_OPTION_OK = re.compile(
    r"--pre|--prefer-binary|--require-hashes|--hash[=\s]\s*sha(?:256|384|512):[0-9A-Fa-f]+|"
    r"--(?:only|no)-binary[=\s]\s*(?::all:|:none:|[A-Za-z0-9._,\-]+)"
)
"""One requirements option that changes nothing about where packages come from."""
_HASH_OPTION = re.compile(r"--hash[=\s]\s*sha(?:256|384|512):[0-9A-Fa-f]+")
_REQ_INCLUDE = re.compile(r"(?:-r|--requirement|-c|--constraint)(?:\s*=\s*|\s+)\S+")
_NPM_REGISTRY_SPEC = re.compile(r"[\s~^<>=*xX0-9.\-|+a-z]*")
_NPM_PATH_SPEC = re.compile(r"[.]|~/|[/\\]|[A-Za-z]:")
"""npm reads a spec starting like this as a path (npm-package-arg `isFilespec`)."""
_NPM_FILE_SPEC = re.compile(r"(?i).*\.(?:tgz|tar|tar\.gz)")
"""npm reads a spec ending in a tarball extension as a local file (npm-package-arg)."""
_NPM_REFERENCE = re.compile(r"\$[@\w./\-]+")
"""An override that names a dependency's own version (`$foo`)."""
_PACKAGE_MANAGER = re.compile(r"[a-z][a-z0-9\-]*@\d[0-9A-Za-z.+\-]*")
"""`packageManager`: a name and a version (corepack also accepts a URL, which is refused)."""

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


def _too_long(line: str) -> str:
    return f"{line[:80]}... (longer than {MAX_LINE} characters, not read)"


def _requirement(item: str) -> tuple[str | None, str | None]:
    """A PEP 508 string as `(normalized name, None)`, or `(None, why)` for a direct reference,
    a path or anything else that does not come from the registry by name (RT02-2). Read in
    linear steps: name, extras, version, markers."""
    line = item.strip()
    if len(line) > MAX_LINE:
        return None, _too_long(line)
    match = _PEP508_NAME.match(line)
    head = line.partition(";")[0].strip()
    if match is None or _ARCHIVE.fullmatch(head) or "://" in line:  # pip reads an archive name
        return None, line[:120]  # as a local file, whatever comes before it

    rest = line[match.end() :].strip()
    if rest.startswith("["):
        end = rest.find("]")
        if end < 0 or not _EXTRAS.fullmatch(rest[1:end]):
            return None, line[:120]
        rest = rest[end + 1 :].strip()
    spec = rest.partition(";")[0].strip()
    if spec and not _VERSION.fullmatch(spec):
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
    workspace members), indexes, index URLs, find-links, and direct references in overrides
    and constraints (RT02-2)."""
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
    for key in ("override-dependencies", "constraint-dependencies",
                "build-constraint-dependencies"):  # fmt: skip
        _pep508(_items(uv, key), set(), off, f"tool.uv.{key}")


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


def _requirement_line(line: str) -> tuple[str | None, str | None]:
    """One requirements line: the requirement, then only `--hash` options."""
    requirement, sep, tail = line.partition(" --")
    if sep and not all(_HASH_OPTION.fullmatch(f"--{o.strip()}") for o in tail.split(" --")):
        return None, line[:120]
    return _requirement(requirement)


def _requirements_deps(text: str) -> Deps:
    """A requirements file: names by PEP 508; every option that is not one harmless option,
    every URL, path, archive or direct reference is a source outside the registry, and every
    `-r` or `-c` names a file this check does not read (RT02-2)."""
    names: set[str] = set()
    off: set[str] = set()
    unchecked: set[str] = set()
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip().removesuffix("\\").strip()  # pip joins on "\\"
        if not line or line.startswith("#"):
            continue
        if len(line) > MAX_LINE:
            off.add(_too_long(line))
        elif line.startswith("-"):
            if _REQ_INCLUDE.fullmatch(line):
                unchecked.add(line[:120])
            elif not _REQ_OPTION_OK.fullmatch(line):
                off.add(line[:120])
        else:
            name, why = _requirement_line(line)
            if name is not None:
                names.add(name)
            else:
                off.add(f"{why}")
    return Deps(frozenset((Ecosystem.PYPI, n) for n in names), frozenset(off), frozenset(unchecked))


def _npm_spec_ok(spec: object) -> bool:
    """A registry version or tag: never a path, a URL, a git spec or a tarball."""
    if not isinstance(spec, str):
        return False
    text = spec.strip()
    return (
        _NPM_REGISTRY_SPEC.fullmatch(text) is not None
        and _NPM_PATH_SPEC.match(text) is None
        and _NPM_FILE_SPEC.fullmatch(text) is None
    )


def _npm_overrides(where: str, value: object, off: set[str], depth: int = 0) -> None:
    """Every spec in `overrides`, `resolutions` or `pnpm.overrides`, nested as npm nests them."""
    if isinstance(value, dict):
        if depth >= 8:
            off.add(f"{where}: nested deeper than aipm reads")
            return
        for key, inner in list(cast("dict[str, Any]", value).items())[:1000]:
            _npm_overrides(f"{where} {key}", inner, off, depth + 1)
        return
    text = value if isinstance(value, str) else None
    if not (_npm_spec_ok(text) or (text is not None and _NPM_REFERENCE.fullmatch(text))):
        off.add(f"{where}: {value!s:.80}")


def _package_json_deps(doc: dict[str, Any]) -> Deps:
    names: set[str] = set()
    off: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in _table(doc, key).items():
            names.add(name.lower())
            if not _npm_spec_ok(spec):
                off.add(f"{name}@{spec!s:.80}")
    for key, value in (("overrides", doc.get("overrides")),
                       ("resolutions", doc.get("resolutions")),
                       ("pnpm.overrides", _table(doc, "pnpm").get("overrides"))):  # fmt: skip
        if value is not None:
            _npm_overrides(key, value, off)
    manager = doc.get("packageManager")
    if manager is not None and not (
        isinstance(manager, str) and _PACKAGE_MANAGER.fullmatch(manager)
    ):
        off.add(f"packageManager: {manager!s:.80}")
    return Deps(frozenset((Ecosystem.NPM, n) for n in names), frozenset(off))


def manifest_deps(path: str, text: str | None) -> Deps | None:
    """The direct dependencies a manifest declares; `None` if it cannot be parsed."""
    name = _fname(path)
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


def _registry_path(ecosystem: Ecosystem, url: str) -> str | None:
    """The path of a URL on a default registry, percent-decoded, without its fragment; `None`
    for another host or a URL with a query. (`urllib` is not imported outside the registry
    lookups, ARCHITECTURE §5.1.)"""
    if not _registry_ok(ecosystem, url):
        return None
    clean = url.strip().split("#", 1)[0]
    origin = "/".join(clean.split("/", 3)[:3])
    path = clean[len(origin) :]
    if "?" in path:
        return None
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), path)


def _npm_tarball_ok(url: str, name: str, version: str | None) -> bool:
    """A registry tarball of exactly this package at exactly this version: the path must be
    `/<name>/-/<name>-<version>.tgz`, so it cannot name another package on the same host, nor
    climb out with `..` (security review of RT02-3). Without a version it fails closed."""
    path = _registry_path(Ecosystem.NPM, url)
    if path is None or not version:
        return False
    base = name.rsplit("/", 1)[-1]
    return path.casefold() == f"/{name}/-/{base}-{version}.tgz".casefold()


_SDIST = re.compile(r"(?i)(.+)\.(?:tar\.gz|zip|tar\.bz2|tar\.xz|tgz|tar)")
_PRE_RELEASE = re.compile(r"[.]?(alpha|beta|preview|pre|rc|a|b|c|post|dev)")


def _canon_version(version: str) -> str:
    """A light PEP 440 normalization, enough to compare a file name's version with a lock's."""
    text = version.casefold().removeprefix("v").replace("-", ".").replace("_", ".")
    names = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}
    return _PRE_RELEASE.sub(lambda m: names.get(m.group(1), m.group(1)), text)


def _pypi_file_ok(url: object, name: str, version: object) -> bool:
    """A wheel or sdist on PyPI's file host of exactly this project at this version."""
    path = _registry_path(Ecosystem.PYPI, url) if isinstance(url, str) else None
    if path is None or not isinstance(version, str):
        return False
    filename = path.rsplit("/", 1)[-1]
    if filename.casefold().endswith(".whl"):
        parts = filename[: -len(".whl")].split("-")
        if len(parts) not in (5, 6):
            return False
        dist, found = parts[0], parts[1]
    else:
        sdist = _SDIST.fullmatch(filename)
        if sdist is None:
            return False
        dist, _, found = sdist.group(1).rpartition("-")
    same_name = normalize_pypi(dist) == normalize_pypi(name)
    return same_name and _canon_version(found) == _canon_version(version)


def _artifact_urls(package: dict[str, Any]) -> list[object]:
    """The `sdist` and `wheels` URLs of a uv.lock or pylock.toml package."""
    urls: list[object] = [_table(package, "sdist").get("url")] if "sdist" in package else []
    for wheel in _items(package, "wheels"):
        urls.append(cast("dict[str, Any]", wheel).get("url") if isinstance(wheel, dict) else wheel)
    return [u for u in urls if u is not None]


def _inside(path: object) -> bool:
    """A relative path that stays in the repository."""
    if not isinstance(path, str) or not path or path.startswith(("/", "\\", "~")):
        return False
    return ":" not in path and ".." not in re.split(r"[/\\]", path)


def _uv_lock(doc: dict[str, Any]) -> LockDeps:
    names: set[tuple[Ecosystem, str]] = set()
    sources: set[str] = set()
    for item in _items(doc, "package"):
        package = cast("dict[str, Any]", item) if isinstance(item, dict) else {}
        name = package.get("name")
        if not isinstance(name, str):
            continue
        source = _table(package, "source")
        local = source.get("editable", source.get("virtual"))
        if "editable" in source or "virtual" in source:
            if not _inside(local):
                sources.add(f"{name}: {_shown(source)}")
            continue  # the project itself, or a workspace member in the repository
        names.add((Ecosystem.PYPI, normalize_pypi(name)))
        registry = source.get("registry")
        if not isinstance(registry, str) or not _registry_ok(Ecosystem.PYPI, registry):
            sources.add(f"{name}: {_shown(source)}")
        for url in _artifact_urls(package):
            if not _pypi_file_ok(url, name, package.get("version")):
                sources.add(f"{name}: {url!s:.160}")
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
        for url in _artifact_urls(package):
            if not _pypi_file_ok(url, name, package.get("version")):
                sources.add(f"{name}: {url!s:.160}")
    return LockDeps(frozenset(names), frozenset(sources))


def _npm_entry(name: str, entry: dict[str, Any], names: set[tuple[Ecosystem, str]],
               sources: set[str]) -> None:  # fmt: skip
    version = entry.get("version")
    real = entry.get("name") if isinstance(entry.get("name"), str) else name
    exact = version if isinstance(version, str) else None
    if exact is not None and exact.startswith("npm:"):
        real, _, exact = exact[4:].rpartition("@")  # an alias (`npm:other@1`) installs `other`
    names.add((Ecosystem.NPM, str(real).lower()))
    resolved = entry.get("resolved")
    if isinstance(resolved, str) and not _npm_tarball_ok(resolved, str(real), exact):
        sources.add(f"{real}: {resolved[:160]}")
    if exact is not None and re.match(r"[a-z+]+:", exact):
        sources.add(f"{real}: {exact[:160]}")


def _npm_lock(doc: dict[str, Any]) -> LockDeps:
    names: set[tuple[Ecosystem, str]] = set()
    sources: set[str] = set()
    for key, value in _table(doc, "packages").items():
        if "node_modules/" not in key or not isinstance(value, dict):
            continue  # "" is the project; other keys are workspace members in the repository
        entry = cast("dict[str, Any]", value)
        if entry.get("link") is True:
            if not _inside(entry.get("resolved")):
                sources.add(f"{key}: link to {entry.get('resolved')!s:.120}")
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


def _unquote_yaml(value: str) -> str:
    return value.strip().strip("'\"")


def _npm_key(key: str) -> tuple[str, str | None]:
    """`name@version(peers)` (pnpm 6+) or `/name/version` (pnpm 5) as (name, version)."""
    text = _unquote_yaml(key).removeprefix("/")
    at = text.find("@", 1)
    if at > 0:
        return text[:at], re.split(r"[(_:]", text[at + 1 :], maxsplit=1)[0] or None
    head, _, version = text.rpartition("/")
    return (head, version) if head and version[:1].isdigit() else (text, None)


_QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")
_YAML_UNSAFE = re.compile(r"(?:^\s*|:\s+|-\s+|[,{\[]\s*)[&*!|>]|<<\s*:")
"""Anchors, aliases, tags, block scalars and merge keys: YAML pnpm never writes, which a line
reader cannot follow, so a lockfile holding one is not read (fail closed)."""
_PNPM_LINE = re.compile(r"( *)((?:'[^']*'|\"[^\"]*\"|[^\s'\"#][^#]*?)):(?: +(.*))?")
_PNPM_DEP_SECTIONS = frozenset({"dependencies", "devDependencies", "optionalDependencies"})


@dataclass(slots=True)
class _PnpmState:
    """Where the pnpm reader is: the top-level section, the package or importer, and an open
    `resolution:` block (its indent) or a field whose value is on the next line."""

    section: str = ""
    name: str = ""
    version: str | None = None
    importer: str = "."
    resolution: int = -1
    pending: str = ""
    names: set[tuple[Ecosystem, str]] = field(default_factory=set[tuple[Ecosystem, str]])
    sources: set[str] = field(default_factory=set[str])

    def resolution_field(self, key: str, value: str) -> None:
        if key == "integrity" or (key == "tarball" and _npm_tarball_ok(value, self.name,
                                                                      self.version)):  # fmt: skip
            return
        self.sources.add(f"{self.name}: {key}: {value[:160]}")

    def local(self, value: str) -> None:
        """A `link:` or `file:` value: a file is a source; a link must stay in the repository,
        resolved from its importer."""
        if value.startswith("file:"):
            self.sources.add(f"{self.name or self.importer}: {value[:160]}")
        else:
            target = posixpath.normpath(posixpath.join(self.importer, value.removeprefix("link:")))
            if not _inside(target) and target != ".":
                self.sources.add(f"{self.name or self.importer}: {value[:160]}")


def _flow_pairs(text: str) -> list[tuple[str, str]] | None:
    """`{a: 1, b: x}` as pairs; `None` for anything else."""
    inner = text.strip()
    if not (inner.startswith("{") and inner.endswith("}")) or "{" in inner[1:-1]:
        return None
    pairs: list[tuple[str, str]] = []
    for item in inner[1:-1].split(","):
        if item.strip():
            key, sep, value = item.partition(":")
            if not sep:
                return None
            pairs.append((_unquote_yaml(key), _unquote_yaml(value)))
    return pairs


def _pnpm_lock(text: str) -> LockDeps | None:
    """pnpm-lock.yaml, read line by line (L0 has no YAML parser) and strictly: package keys two
    spaces in under `packages:` or `snapshots:`, the fields of each `resolution:` (flow or
    block), and `link:` or `file:` values. Anything a line reader could misread (anchors,
    aliases, tags, explicit keys, tabs, a line over `MAX_LINE`, an inline package entry other
    than `{}`) makes the file unreadable: `None`, a violation (security review of RT02-3)."""
    state = _PnpmState()
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        bare = _QUOTED.sub("''", line)
        if len(line) > MAX_LINE or "\t" in line or _YAML_UNSAFE.search(bare):
            return None
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.strip() in ("---", "...") or line.lstrip().startswith("? "):
            return None
        if not _pnpm_line(state, line):
            return None
    return LockDeps(frozenset(state.names), frozenset(state.sources))


def _pnpm_line(state: _PnpmState, line: str) -> bool:
    """Read one line into `state`; `False` when it is not a form pnpm writes."""
    indent = len(line) - len(line.lstrip(" "))
    if state.pending:
        state.resolution_field(state.pending, _unquote_yaml(line))
        state.pending = ""
        return True
    match = _PNPM_LINE.fullmatch(line)
    if match is None:
        return line.lstrip().startswith("- ")  # a list item (a setting, a checksum list)
    key, value = _unquote_yaml(match.group(2)), (match.group(3) or "").strip()
    if indent == 0:
        state.section, state.resolution = key, -1
        state.name, state.version, state.importer = "", None, "."
    elif 0 <= state.resolution < indent:
        if value:
            state.resolution_field(key, _unquote_yaml(value))
        else:
            state.pending = key
    else:
        state.resolution = -1
        return _pnpm_entry(state, indent, key, value)
    return True


def _pnpm_entry(state: _PnpmState, indent: int, key: str, value: str) -> bool:
    """A line outside an open `resolution:` block."""
    in_packages = state.section in ("packages", "snapshots")
    if indent == 2 and in_packages:
        state.name, state.version = _npm_key(key)
        state.names.add((Ecosystem.NPM, state.name.lower()))
        return value in ("", "{}")
    if indent == 2 and state.section == "importers":
        state.importer = key
    elif key == "resolution" and in_packages:
        pairs = _flow_pairs(value) if value else []
        for field_key, field_value in pairs or []:
            state.resolution_field(field_key, field_value)
        state.resolution = -1 if value else indent
        return pairs is not None
    elif _unquote_yaml(value).startswith(("link:", "file:")):
        state.local(_unquote_yaml(value))
    return True


def _yarn_spec(spec: str) -> tuple[str, str]:
    """A header spec as (the name it installs, its range): `alias@npm:real@^1` installs
    `real`."""
    text = _unquote_yaml(spec)
    at = text.find("@", 1)
    alias, spec_range = (text[:at], text[at + 1 :]) if at > 0 else (text, "")
    if spec_range.startswith("npm:"):
        real = spec_range[4:].rpartition("@")[0]
        return (real or alias), spec_range
    return alias, spec_range


_YARN_FIELD = re.compile(r"  \"?(version|resolved|resolution)\"?(?::\s*|\s+)\"?([^\"\s]+)\"?\s*")
_EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?")


def _yarn_lock(text: str) -> LockDeps | None:
    """yarn.lock, classic and berry, read entry by entry: a header names the package (an alias
    by the package it installs), then `version`, `resolved` and `resolution` are checked
    together. `resolved` must be this package's tarball at this version on a default
    registry; a berry `resolution` must be `name@npm:<version>` with no bindings, a workspace,
    or a built-in compat patch. A top-level line that is not an entry header, a comment or
    blank makes the file unreadable (`None`)."""
    names: set[tuple[Ecosystem, str]] = set()
    sources: set[str] = set()
    entries: list[tuple[str, dict[str, str]]] = []
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if len(line) > MAX_LINE:
            return None
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            if not line.rstrip().endswith(":") or "{" in line:
                return None
            entries.append((line.rstrip()[:-1], {}))
            continue
        if not entries:
            return None
        found = _YARN_FIELD.fullmatch(line)
        if found is not None:
            entries[-1][1][found.group(1)] = found.group(2)
    for header, fields in entries:
        if header.lstrip('"').startswith("__metadata"):
            continue
        real, spec_range = _yarn_spec(header.split(",", 1)[0])
        if not spec_range.startswith(("workspace:", "link:", "portal:")):
            names.add((Ecosystem.NPM, real.lower()))  # a workspace member is not on a registry
        if "resolved" in fields and not _npm_tarball_ok(
            fields["resolved"], real, fields.get("version")
        ):
            sources.add(f"{real}: {fields['resolved'][:160]}")
        if "resolution" in fields:
            sources |= _berry_resolution(real, fields["resolution"], names)
    return LockDeps(frozenset(names), frozenset(sources))


def _berry_resolution(current: str, value: str, names: set[tuple[Ecosystem, str]]) -> set[str]:
    """`name@npm:1.0.0` installs `name` 1.0.0 from the registry; a binding (`::__archiveUrl=`)
    could fetch anything, so only an exact version is accepted (security review of RT02-3)."""
    at = value.find("@", 1)
    resolved, protocol = (value[:at], value[at + 1 :]) if at > 0 else (current, value)
    if protocol.startswith("npm:") and _EXACT_VERSION.fullmatch(protocol[4:]):
        names.add((Ecosystem.NPM, resolved.lower()))
        return set()
    if protocol.startswith("workspace:") or (
        protocol.startswith("patch:") and "builtin<compat/" in protocol
    ):
        return set()
    return {f"{current}: {value[:160]}"}


_TOML_LOCKS: dict[str, Callable[[dict[str, Any]], LockDeps]] = {
    "uv.lock": _uv_lock,
    "poetry.lock": _poetry_lock,
    "pylock.toml": _pylock,
}
_TEXT_LOCKS: dict[str, Callable[[str], LockDeps | None]] = {
    "pnpm-lock.yaml": _pnpm_lock,
    "yarn.lock": _yarn_lock,
}


def lock_deps(path: str, text: str | None) -> LockDeps | None:
    """The packages a lockfile pins and their sources; `None` if it cannot be parsed."""
    name = _fname(path)
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
    eco = LOCKFILES.get(_fname(path))
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
