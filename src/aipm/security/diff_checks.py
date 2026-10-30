"""Post-change checks (C-16, ARCHITECTURE §12.4 step 3, SECURITY.md §7.8, §9.2, §13.3).

A pure function over a `ChangeSet` that `aipm.execution.git` builds: no git, no file I/O. Each
finding is a `Violation`, classified as in §12.4:

- **severe** (the task is blocked, no retry, a security event): git integrity (config, hooks,
  the agents' global config), protected paths, tests and test configuration the task does not
  own (SECURITY.md §9.2), symbolic links that leave the workspace or land on a protected path,
  watched files changed behind `.gitignore`, and a change set aipm could not read whole;
- **minor** (the attempt fails, nothing is reverted in manual mode): edits outside `owns_files`,
  dependencies not declared in `deps_add`, tamper signs on owned tests (skip, xfail or focus
  markers added, test functions removed, fewer assertions), and a changed file that changed
  again while the gates ran (`aipm.app.verify` checks that one).

Contents are T2: the parsers here read them as data only and never fail open. A manifest that
cannot be parsed counts as a violation.
"""

import json
import re
import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase
from functools import cache
from typing import Any, cast

from aipm.domain.dag import JS_TEST_RUNNER_CONFIG, TEST_FILE_PATTERNS
from aipm.domain.models import ChangeSet, Ecosystem, FileChange, Task
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


_SEVERE = frozenset(
    {Kind.GIT_INTEGRITY, Kind.INCOMPLETE, Kind.PROTECTED_PATH, Kind.HIDDEN_CHANGE, Kind.SYMLINK,
     Kind.TEST_NOT_OWNED, Kind.TEST_CONFIG}
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
_WHOLE_FILE_TEST_CONFIG = frozenset(
    {"pytest.ini", ".coveragerc", "conftest.py", *JS_TEST_RUNNER_CONFIG}
)
_SECTIONED = frozenset({"pyproject.toml", "setup.cfg", "tox.ini", "package.json"})


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


def needs_content(path: str, test_roots: Sequence[str]) -> bool:
    """Whether the checks read this path's contents (for `aipm.execution.git.change_set`)."""
    return is_test_path(path, test_roots) or is_test_config_file(path) or is_manifest(path)


def is_watched(path: str, policy: CheckPolicy) -> bool:
    """Whether an ignored file on this path must not change: a protected path or a test."""
    return (
        is_protected(path, policy.protected())
        or is_test_path(path, policy.test_roots)
        or _name(path.casefold()) in _WHOLE_FILE_TEST_CONFIG
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
    r"pytest\.mark\.(?:skip|skipif|xfail)\b|pytest\.(?:skip|xfail|importorskip)\s*\(|"
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
_INDEX_OPTIONS = re.compile(r"^\s*(?:-i|--index-url|--extra-index-url|-f|--find-links)\b")
_NPM_REGISTRY_SPEC = re.compile(r"^[\s~^<>=*xX0-9.\-|+a-z]*$")


def normalize_pypi(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of `-`, `_` and `.` become one `-`."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True, slots=True)
class Deps:
    """Direct dependencies read from one manifest, and sources that bypass the registry."""

    names: frozenset[tuple[Ecosystem, str]]
    off_registry: frozenset[str] = frozenset()


def _pep508(items: Iterable[object]) -> set[str]:
    names: set[str] = set()
    for item in items:
        if isinstance(item, str):
            match = _PEP508_NAME.match(item)
            if match is not None:
                names.add(normalize_pypi(match.group(1)))
    return names


def _table(doc: dict[str, Any], key: str) -> dict[str, Any]:
    """`doc[key]` when it is a table, else an empty one (T2 data is never trusted to fit)."""
    value = doc.get(key)
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _items(doc: dict[str, Any], key: str) -> list[object]:
    """`doc[key]` when it is a list, else an empty one."""
    value = doc.get(key)
    return cast("list[object]", value) if isinstance(value, list) else []


def _pyproject_deps(doc: dict[str, Any]) -> Deps:
    project = _table(doc, "project")
    names = _pep508(_items(project, "dependencies"))
    for table in (_table(project, "optional-dependencies"), _table(doc, "dependency-groups")):
        for group in table:
            names |= _pep508(_items(table, group))
    tool = _table(doc, "tool")
    names |= _pep508(_items(_table(tool, "uv"), "dev-dependencies"))
    poetry = _table(tool, "poetry")
    for key in ("dependencies", "dev-dependencies"):
        names |= {normalize_pypi(k) for k in _table(poetry, key) if k != "python"}
    return Deps(frozenset((Ecosystem.PYPI, n) for n in names))


def _requirements_deps(text: str) -> Deps:
    names: set[str] = set()
    off: set[str] = set()
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if _INDEX_OPTIONS.match(line) or "://" in line or line.startswith(("-e", "--editable")):
            off.add(line[:120])
            continue
        if line.startswith("-"):
            continue
        names |= _pep508([line])
    return Deps(frozenset((Ecosystem.PYPI, n) for n in names), frozenset(off))


def _package_json_deps(doc: dict[str, Any]) -> Deps:
    names: set[str] = set()
    off: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in _table(doc, key).items():
            names.add(name.lower())
            if not isinstance(spec, str) or not _NPM_REGISTRY_SPEC.fullmatch(spec):
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
        if _name(change.path) in LOCKFILES or not is_manifest(change.path):
            continue
        before = manifest_deps(change.path, change.before)
        after = manifest_deps(change.path, change.after)
        if before is None or after is None:
            continue
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
        if not is_manifest(change.path) or _name(change.path) in LOCKFILES:
            continue
        before = manifest_deps(change.path, change.before)
        after = manifest_deps(change.path, change.after)
        if change.truncated or after is None:
            found.append(Violation(Kind.DEPENDENCY, change.path, "manifest cannot be read"))
            continue
        known = before.off_registry if before is not None else frozenset[str]()
        for source in sorted(after.off_registry - known):
            detail = f"source outside the registry: {source}"
            found.append(Violation(Kind.DEPENDENCY, change.path, detail))
    if policy.allow_new_dependencies == "allow":
        return found
    for path, eco, name in new_dependencies(changes):
        if (eco, name) not in allowed:
            detail = f"{eco.value} dependency {name} is not in deps_add"
            found.append(Violation(Kind.DEPENDENCY, path, detail))
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
