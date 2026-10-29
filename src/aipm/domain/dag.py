"""Plan validation (C-8, ARCHITECTURE §9): deterministic and pure.

`validate_plan` turns the planner's proposals into `Task`s, or reports why it cannot. It runs
all eight checks of §9:

1. IDs: format, uniqueness, every `depends_on` exists, and the graph is acyclic (`graphlib`).
2. Paths: every `owns_files` and `reads_files` entry passes `safe_rel_glob`.
3. Ownership overlap: two tasks whose globs could match the same path, with no dependency path
   between them, are merged when their combined size is at most L (and the caps allow it);
   otherwise the later ID depends on the earlier one. Every change is reported.
4. Serialized resources: an overlap where both globs are serialized paths is left to the
   scheduler, which never runs such tasks together.
5. Gates: names from the trusted menu only; `unit` and `ac_trace` are added to feature,
   security and refactor tasks that lack them (a reported change: it only adds checks).
6. Traceability: every `must` feature and every threat of severity medium or higher is traced.
7. Size caps: at most 40 owned globs and 10 acceptance criteria; an L task with more than 6
   criteria must be split; at most `max_tasks` tasks.
8. Dependencies: each `deps_add` has a known ecosystem and a valid package name.

Text fields lose control characters, terminal escapes and invisible characters here, so the
validator neutralizes them whatever the prompt said; the count is reported for a security event.

Issues name their place (`T-003.owns_files[2]`) and the rule in aipm's own words. The offending
value is kept apart in `detail`, for people, and never goes back to a model (`Issue.repair`).
"""

import graphlib
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from fnmatch import fnmatchcase

from pydantic import ValidationError

from aipm.domain.errors import PolicyViolation
from aipm.domain.ids import is_valid_id
from aipm.domain.models import (
    AcceptanceCriterion,
    DependencyAdd,
    ProposedDependency,
    ProposedTask,
    Task,
    TaskSize,
    TaskType,
)
from aipm.security.paths import safe_rel_glob
from aipm.security.sanitize import sanitize_text

MAX_TASKS = 200
MAX_OWNED = 40
MAX_READ = 40
MAX_CRITERIA = 10
MAX_L_CRITERIA = 6
MAX_DEPENDS = 20
MAX_TRACES = 20
MAX_DEPS_ADD = 20
MAX_GATES = 12
MAX_TITLE = 120
MAX_DESCRIPTION = 4000
MANDATORY_GATES = ("unit", "ac_trace")
NEEDS_MANDATORY_GATES = frozenset({TaskType.FEATURE, TaskType.SECURITY, TaskType.REFACTOR})

_POINTS = {TaskSize.S: 1, TaskSize.M: 2, TaskSize.L: 3}
_SIZES = {1: TaskSize.S, 2: TaskSize.M, 3: TaskSize.L}
_TYPE_RANK = (
    TaskType.SECURITY,
    TaskType.FEATURE,
    TaskType.REFACTOR,
    TaskType.INFRA,
    TaskType.TEST,
    TaskType.DOCS,
)
_DETAIL_MAX = 80
_TEST_FILES = ("test_*.py", "*_test.py", "conftest.py", "*.test.*", "*.spec.*", "*_test.go")
_TEST_CONFIG = (
    "pyproject.toml", "setup.cfg", "setup.py", "pytest.ini", "tox.ini", "noxfile.py",
    ".coveragerc", "package.json", "jest.config.*", "vitest.config.*", "karma.conf.*",
    ".mocharc*", "playwright.config.*", "cypress.config.*",
)  # fmt: skip
"""Test-runner configuration (ARCHITECTURE §13.3): owning one is shown at G3."""


class IssueCode(StrEnum):
    """Why a plan was rejected."""

    NO_TASKS = "no_tasks"
    TOO_MANY_TASKS = "too_many_tasks"
    BAD_ID = "bad_id"
    DUPLICATE_ID = "duplicate_id"
    UNKNOWN_DEPENDENCY = "unknown_dependency"
    CYCLE = "cycle"
    TOO_MANY_DEPENDENCIES = "too_many_dependencies"
    UNSAFE_PATH = "unsafe_path"
    TOO_MANY_FILES = "too_many_files"
    UNKNOWN_GATE = "unknown_gate"
    MISSING_GATE = "missing_gate"
    BAD_TRACE = "bad_trace"
    UNTRACED_FEATURE = "untraced_feature"
    UNTRACED_THREAT = "untraced_threat"
    TOO_MANY_CRITERIA = "too_many_criteria"
    SPLIT = "split"
    EMPTY_TEXT = "empty_text"
    BAD_DEPENDENCY = "bad_dependency"


SECURITY_ISSUES = frozenset(
    {IssueCode.UNSAFE_PATH, IssueCode.UNKNOWN_GATE, IssueCode.BAD_DEPENDENCY}
)
"""Issues that mean the plan asked for more than the policy allows (exit 6 if not repaired)."""


@dataclass(frozen=True, slots=True)
class Issue:
    """One rule a plan breaks. `where` and `rule` are aipm's text; `detail` may be model text."""

    code: IssueCode
    where: str
    rule: str
    detail: str = ""

    @property
    def security(self) -> bool:
        """Whether the issue is a policy matter rather than a planning mistake."""
        return self.code in SECURITY_ISSUES

    @property
    def message(self) -> str:
        """For people: the place, the rule and the offending value."""
        suffix = f" (got {self.detail})" if self.detail else ""
        return f"{self.where}: {self.rule}{suffix}"

    @property
    def repair(self) -> str:
        """For the planner's repair attempt: the place and the rule, never the model's text."""
        return f"{self.where}: {self.rule}"


@dataclass(frozen=True, slots=True)
class PlanRules:
    """What the validator checks against; everything here comes from trusted code or config."""

    gate_menu: tuple[str, ...]
    features: frozenset[str] = frozenset()
    must_features: frozenset[str] = frozenset()
    nfrs: frozenset[str] = frozenset()
    threats: frozenset[str] = frozenset()
    threats_to_trace: frozenset[str] = frozenset()
    serialized_paths: tuple[str, ...] = ()
    extra_protected: tuple[str, ...] = ()
    max_tasks: int = MAX_TASKS


@dataclass(frozen=True, slots=True)
class PlanValidation:
    """The validated tasks, or the issues; plus every change the validator made."""

    tasks: tuple[Task, ...] = ()
    issues: tuple[Issue, ...] = ()
    changes: tuple[str, ...] = ()
    removed_characters: int = 0

    @property
    def ok(self) -> bool:
        """True when the plan passed and `tasks` holds it."""
        return not self.issues

    @property
    def security_issues(self) -> tuple[Issue, ...]:
        """The issues that are policy violations."""
        return tuple(issue for issue in self.issues if issue.security)


# ---------------------------------------------------------------- globs


def _wild(part: str) -> bool:
    return "*" in part or "?" in part


def globs_may_overlap(a: str, b: str) -> bool:
    """Whether two normalized globs could match the same path. Conservative (ARCHITECTURE §9).

    Components are compared case-insensitively from the root. The first depth where either glob
    has a wildcard counts as an overlap, and so does one glob being a prefix of the other (a
    literal path may be a directory). Only differing literal components rule an overlap out.
    """
    pa, pb = literal_prefix(a), literal_prefix(b)
    shorter = min(len(pa), len(pb))
    return pa[:shorter] == pb[:shorter]


def literal_prefix(glob: str) -> tuple[str, ...]:
    """The case-folded components of a glob before its first wildcard component."""
    out: list[str] = []
    for part in glob.casefold().split("/"):
        if _wild(part):
            break
        out.append(part)
    return tuple(out)


def _match(parts: Sequence[str], pattern: Sequence[str]) -> bool:
    if not pattern:
        return not parts
    if pattern[0] == "**":
        return any(_match(parts[k:], pattern[1:]) for k in range(len(parts) + 1))
    return bool(parts) and fnmatchcase(parts[0], pattern[0]) and _match(parts[1:], pattern[1:])


def is_serialized(glob: str, patterns: Iterable[str]) -> bool:
    """Whether a glob names a serialized resource: it equals a `plan.serialized_paths` pattern,
    or it is a literal path that one matches. Patterns are anchored at the repository root."""
    folded = glob.casefold()
    parts = folded.split("/")
    literal = not any(_wild(part) for part in parts)
    for pattern in patterns:
        pat = pattern.casefold()
        if folded == pat or (literal and _match(parts, pat.split("/"))):
            return True
    return False


def owned_test_or_config(task: Task, test_roots: Sequence[str]) -> list[str]:
    """The owned globs that may hold tests or test-runner configuration (shown at G3)."""
    hits: list[str] = []
    for glob in task.owns_files:
        base = glob.rsplit("/", 1)[-1].casefold()
        under_root = any(globs_may_overlap(glob, f"{root}/**") for root in test_roots)
        if under_root or any(fnmatchcase(base, p) for p in (*_TEST_FILES, *_TEST_CONFIG)):
            hits.append(glob)
    return hits


# ---------------------------------------------------------------- metrics


def dag_metrics(tasks: Sequence[Task]) -> tuple[int, int]:
    """(depth, width): the longest dependency chain and the widest level, in tasks."""
    ids = {t.id for t in tasks}
    graph = {t.id: [d for d in t.depends_on if d in ids] for t in tasks}
    level: dict[str, int] = {}
    for tid in graphlib.TopologicalSorter(graph).static_order():
        level[tid] = 1 + max((level[d] for d in graph[tid]), default=0)
    counts = Counter(level.values())
    return max(level.values(), default=0), max(counts.values(), default=0)


# ---------------------------------------------------------------- the working form


@dataclass(slots=True)
class _Work:
    """A task on its way from proposal to `Task`; every field already checked."""

    id: str
    title: str
    description: str
    type: TaskType
    traces: list[str]
    depends_on: list[str]
    owns: list[str]
    reads: list[str]
    deps_add: list[DependencyAdd]
    acceptance: list[str]
    gates: list[str]
    points: int


def _dedupe[T](items: Iterable[T]) -> list[T]:
    seen: set[T] = set()
    out: list[T] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _dedupe_deps(items: Iterable[DependencyAdd]) -> list[DependencyAdd]:
    seen: set[tuple[str, str]] = set()
    out: list[DependencyAdd] = []
    for item in items:
        key = (item.ecosystem.value, item.name)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _shown(value: str) -> str:
    clean = " ".join(sanitize_text(value, source="plan").text.split())
    return repr(clean if len(clean) <= _DETAIL_MAX else clean[:_DETAIL_MAX] + "…")


@dataclass
class _Checker:
    rules: PlanRules
    issues: list[Issue] = field(default_factory=list[Issue])
    changes: list[str] = field(default_factory=list[str])
    removed: int = 0

    def add(self, code: IssueCode, where: str, rule: str, detail: str = "") -> None:
        self.issues.append(Issue(code, where, rule, detail))

    def clean(self, text: str, where: str) -> str:
        result = sanitize_text(text, source="plan")
        self.removed += sum(result.removed.values())
        cleaned = result.text.strip()
        if text.strip() and not cleaned:
            self.add(IssueCode.EMPTY_TEXT, where, "empty once control characters are removed")
        return cleaned

    def globs(self, values: Sequence[str], where: str, limit: int) -> list[str]:
        out: list[str] = []
        for k, value in enumerate(values):
            try:
                out.append(safe_rel_glob(value, extra_protected=self.rules.extra_protected))
            except PolicyViolation:
                self.add(
                    IssueCode.UNSAFE_PATH,
                    f"{where}[{k}]",
                    "not a safe repository-relative glob (no absolute path, '..', leading "
                    "'-', '@' or '+', protected path or .pm/)",
                    _shown(value),
                )
        out = _dedupe(out)
        if len(out) > limit:
            self.add(IssueCode.TOO_MANY_FILES, where, f"at most {limit} globs")
        return out

    def gates(self, task_type: TaskType, values: Sequence[str], where: str) -> list[str]:
        menu = self.rules.gate_menu
        kept: set[str] = set()
        for k, value in enumerate(values):
            if value in menu:
                kept.add(value)
            else:
                self.add(
                    IssueCode.UNKNOWN_GATE,
                    f"{where}.gates[{k}]",
                    f"not in the gate menu ({', '.join(menu) or 'empty'})",
                    _shown(value),
                )
        if task_type in NEEDS_MANDATORY_GATES:
            for gate in MANDATORY_GATES:
                if gate in kept:
                    continue
                if gate in menu:
                    kept.add(gate)
                    self.changes.append(f"{where}: added the mandatory {gate} gate")
                else:
                    self.add(
                        IssueCode.MISSING_GATE,
                        f"{where}.gates",
                        f"{task_type.value} tasks need the {gate} gate, which the menu lacks",
                    )
        return [gate for gate in menu if gate in kept]

    def traces(self, values: Sequence[str], where: str) -> list[str]:
        known = self.rules.features | self.rules.threats | self.rules.nfrs
        out: list[str] = []
        for k, value in enumerate(values):
            if value in known:
                out.append(value)
            else:
                self.add(
                    IssueCode.BAD_TRACE,
                    f"{where}.traces[{k}]",
                    "not a feature, threat or NFR ID from the PRD or threat model",
                    _shown(value),
                )
        return _dedupe(out)

    def deps_add(self, values: Sequence[ProposedDependency], where: str) -> list[DependencyAdd]:
        out: list[DependencyAdd] = []
        for k, value in enumerate(values):
            try:
                out.append(DependencyAdd.model_validate(value.model_dump()))
            except ValidationError:
                self.add(
                    IssueCode.BAD_DEPENDENCY,
                    f"{where}.deps_add[{k}]",
                    "needs ecosystem pypi or npm and a valid package name",
                    _shown(f"{value.ecosystem}:{value.name}"),
                )
        return _dedupe_deps(out)

    def task(self, index: int, p: ProposedTask) -> _Work:
        valid_id = is_valid_id("task", p.id)
        where = p.id if valid_id else f"tasks[{index}]"
        if not valid_id:
            self.add(IssueCode.BAD_ID, f"{where}.id", "not a task ID like T-001", _shown(p.id))
        depends: list[str] = []
        for k, dep in enumerate(p.depends_on):
            if not is_valid_id("task", dep):
                self.add(IssueCode.BAD_ID, f"{where}.depends_on[{k}]", "not a task ID", _shown(dep))
            elif dep == p.id:
                self.add(
                    IssueCode.CYCLE, f"{where}.depends_on[{k}]", "a task cannot depend on itself"
                )
            else:
                depends.append(dep)
        acceptance = [self.clean(c, f"{where}.acceptance[{k}]") for k, c in enumerate(p.acceptance)]
        if len(acceptance) > MAX_CRITERIA:
            self.add(IssueCode.TOO_MANY_CRITERIA, f"{where}.acceptance", f"at most {MAX_CRITERIA}")
        elif p.size is TaskSize.L and len(acceptance) > MAX_L_CRITERIA:
            self.add(
                IssueCode.SPLIT,
                f"{where}.acceptance",
                f"split: an L task has at most {MAX_L_CRITERIA} acceptance criteria",
            )
        return _Work(
            id=p.id,
            title=self.clean(p.title, f"{where}.title"),
            description=self.clean(p.description, f"{where}.description"),
            type=p.type,
            traces=self.traces(p.traces, where),
            depends_on=_dedupe(depends),
            owns=self.globs(p.owns_files, f"{where}.owns_files", MAX_OWNED),
            reads=self.globs(p.reads_files, f"{where}.reads_files", MAX_READ),
            deps_add=self.deps_add(p.deps_add, where),
            acceptance=acceptance,
            gates=self.gates(p.type, p.gates, where),
            points=_POINTS[p.size],
        )

    def graph(self, works: Sequence[_Work]) -> None:
        ids = Counter(w.id for w in works if is_valid_id("task", w.id))
        for tid, count in sorted(ids.items()):
            if count > 1:
                self.add(IssueCode.DUPLICATE_ID, tid, f"{count} tasks share this ID")
        for w in works:
            for k, dep in enumerate(w.depends_on):
                if dep not in ids:
                    self.add(
                        IssueCode.UNKNOWN_DEPENDENCY,
                        f"{w.id}.depends_on[{k}]",
                        "no task in the plan has this ID",
                        _shown(dep),
                    )
        if self.issues:
            return
        try:
            graphlib.TopologicalSorter({w.id: w.depends_on for w in works}).prepare()
        except graphlib.CycleError as exc:
            cycle: list[str] = list(exc.args[1])
            self.add(IssueCode.CYCLE, "plan", "dependency cycle: " + " -> ".join(cycle))

    def traceability(self, works: Sequence[_Work]) -> None:
        traced = {t for w in works for t in w.traces}
        for fid in sorted(self.rules.must_features - traced):
            self.add(IssueCode.UNTRACED_FEATURE, "plan", f"must feature {fid} is traced by no task")
        for tid in sorted(self.rules.threats_to_trace - traced):
            self.add(IssueCode.UNTRACED_THREAT, "plan", f"threat {tid} is traced by no task")


# ---------------------------------------------------------------- overlap resolution


def _merge(a: _Work, b: _Work, menu: Sequence[str]) -> _Work | None:
    """`b` folded into `a`, or None when the result would break a size cap."""
    points = a.points + b.points
    acceptance = a.acceptance + b.acceptance
    owns = _dedupe(a.owns + b.owns)
    reads = _dedupe(a.reads + b.reads)
    traces = _dedupe(a.traces + b.traces)
    depends = [d for d in _dedupe(a.depends_on + b.depends_on) if d not in (a.id, b.id)]
    deps_add = _dedupe_deps(a.deps_add + b.deps_add)
    gates = [g for g in menu if g in set(a.gates) | set(b.gates)]
    description = f"{a.description}\n\nMerged from {b.id} ({b.title}):\n{b.description}".strip()
    if (
        points > _POINTS[TaskSize.L]
        or len(acceptance) > MAX_CRITERIA
        or (points == _POINTS[TaskSize.L] and len(acceptance) > MAX_L_CRITERIA)
        or len(owns) > MAX_OWNED
        or len(reads) > MAX_READ
        or len(traces) > MAX_TRACES
        or len(depends) > MAX_DEPENDS
        or len(deps_add) > MAX_DEPS_ADD
        or len(gates) > MAX_GATES
        or len(description) > MAX_DESCRIPTION
    ):
        return None
    title = f"{a.title}; {b.title}"
    if len(title) > MAX_TITLE:
        title = title[: MAX_TITLE - 1].rstrip() + "…"
    return _Work(
        id=a.id,
        title=title,
        description=description,
        type=min(a.type, b.type, key=_TYPE_RANK.index),
        traces=traces,
        depends_on=depends,
        owns=owns,
        reads=reads,
        deps_add=deps_add,
        acceptance=acceptance,
        gates=gates,
        points=points,
    )


def _first_overlap(a: _Work, b: _Work, serialized: Sequence[str]) -> tuple[str, str] | None:
    for ga in a.owns:
        for gb in b.owns:
            if not globs_may_overlap(ga, gb):
                continue
            if is_serialized(ga, serialized) and is_serialized(gb, serialized):
                continue
            return ga, gb
    return None


@dataclass(slots=True)
class _Node:
    children: dict[str, "_Node"] = field(default_factory=dict[str, "_Node"])
    here: int = 0
    """Tasks (as bits) with a glob whose literal prefix ends at this node."""
    below: int = 0
    """Tasks with a glob whose literal prefix ends here or deeper."""


def _insert(root: _Node, prefix: tuple[str, ...], bit: int) -> None:
    node = root
    node.below |= bit
    for part in prefix:
        node = node.children.setdefault(part, _Node())
        node.below |= bit
    node.here |= bit


def _partners(root: _Node, prefix: tuple[str, ...]) -> int:
    """Tasks owning a glob that may overlap one with this prefix: one prefix extends the other."""
    found = 0
    node = root
    for part in prefix:
        found |= node.here
        child = node.children.get(part)
        if child is None:
            return found
        node = child
    return found | node.below


def _overlapping_pairs(works: Sequence[_Work], serialized: Sequence[str]) -> list[tuple[int, int]]:
    """Every pair (i < j) of tasks with globs that may overlap, serialized pairs excepted.

    A trie of literal prefixes finds the candidates without comparing every pair of globs, so
    a large hostile plan stays cheap. Two serialized globs never count as an overlap.
    """
    every, plain = _Node(), _Node()
    marked: list[list[tuple[tuple[str, ...], bool]]] = []
    for i, w in enumerate(works):
        entries = [(literal_prefix(g), is_serialized(g, serialized)) for g in w.owns]
        marked.append(entries)
        for prefix, is_ser in entries:
            _insert(every, prefix, 1 << i)
            if not is_ser:
                _insert(plain, prefix, 1 << i)
    pairs: list[tuple[int, int]] = []
    for i, entries in enumerate(marked):
        mask = 0
        for prefix, is_ser in entries:
            mask |= _partners(plain if is_ser else every, prefix)
        mask >>= i + 1
        j = i + 1
        while mask:
            if mask & 1:
                pairs.append((i, j))
            mask >>= 1
            j += 1
    # Each task meets its nearest earlier partner first, so a run of tasks sharing one file
    # becomes a chain of single edges rather than every task depending on every earlier one.
    pairs.sort(key=lambda pair: (pair[1], -pair[0]))
    return pairs


def _reach(works: Sequence[_Work]) -> list[int]:
    """`reach[i]`: the tasks (as bits) that task `i` depends on, directly or not."""
    index = {w.id: i for i, w in enumerate(works)}
    graph = {w.id: w.depends_on for w in works}
    reach = [0] * len(works)
    for tid in graphlib.TopologicalSorter(graph).static_order():
        i = index[tid]
        for dep in graph[tid]:
            j = index[dep]
            reach[i] |= reach[j] | (1 << j)
    return reach


@dataclass(slots=True)
class _Resolver:
    """Merges and orders overlapping tasks. Indices follow the tasks sorted by ID."""

    works: list[_Work]
    menu: Sequence[str]
    changes: list[str]
    reach: list[int] = field(default_factory=list[int])
    parent: list[int] = field(default_factory=list[int])
    alive: list[bool] = field(default_factory=list[bool])

    def __post_init__(self) -> None:
        self.reach = _reach(self.works)
        self.parent = list(range(len(self.works)))
        self.alive = [True] * len(self.works)

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            i = self.parent[i]
        return i

    def connected(self, lo: int, hi: int) -> bool:
        return bool((self.reach[hi] >> lo) & 1 or (self.reach[lo] >> hi) & 1)

    def settle(self, lo: int, hi: int, why: str) -> None:
        """Merge `hi` into `lo` if the caps allow; otherwise `hi` depends on `lo`."""
        low, high = self.works[lo], self.works[hi]
        merged = _merge(low, high, self.menu)
        if merged is None:
            high.depends_on.append(low.id)
            gained = self.reach[lo] | (1 << lo)
            for u, alive in enumerate(self.alive):
                if alive and (u == hi or (self.reach[u] >> hi) & 1):
                    self.reach[u] |= gained
            self.changes.append(f"{high.id} now depends on {low.id}: {why}")
            return
        self.works[lo] = merged
        self.parent[hi] = lo
        self.alive[hi] = False
        both = (1 << lo) | (1 << hi)
        self.reach[lo] = (self.reach[lo] | self.reach[hi]) & ~both
        for u, alive in enumerate(self.alive):
            if alive and u != lo and self.reach[u] & both:
                self.reach[u] = (self.reach[u] & ~(1 << hi)) | (1 << lo) | self.reach[lo]
        self.changes.append(f"merged {high.id} into {low.id}: {why}")

    def survivors(self) -> list[_Work]:
        index = {w.id: i for i, w in enumerate(self.works)}
        out = [w for w, alive in zip(self.works, self.alive, strict=True) if alive]
        for w in out:
            mapped = (self.works[self.find(index[d])].id for d in w.depends_on)
            w.depends_on = [d for d in _dedupe(mapped) if d != w.id]
        return out


def _resolve(works: list[_Work], rules: PlanRules, changes: list[str]) -> list[_Work]:
    """Merge or order every pair of overlapping tasks that could otherwise run together.

    Paths are never removed (an added edge only adds paths, and merging keeps every path), so a
    pair settled once stays settled, and one pass over the overlapping pairs in ID order is
    enough. An edge always points from the later ID to the earlier one, and only between tasks
    with no path between them, so no cycle can appear.
    """
    works.sort(key=lambda w: w.id)
    original = list(works)
    resolver = _Resolver(works, rules.gate_menu, changes)
    for i, j in _overlapping_pairs(original, rules.serialized_paths):
        lo, hi = sorted((resolver.find(i), resolver.find(j)))
        if lo == hi or resolver.connected(lo, hi):
            continue
        ga, gb = _first_overlap(original[i], original[j], rules.serialized_paths) or ("?", "?")
        resolver.settle(lo, hi, f"both own {ga} and {gb}")
    return resolver.survivors()


def _build(w: _Work) -> Task:
    number = w.id.removeprefix("T-")
    return Task(
        id=w.id,
        title=w.title,
        description=w.description,
        type=w.type,
        traces=w.traces,
        depends_on=w.depends_on,
        owns_files=w.owns,
        reads_files=w.reads,
        deps_add=w.deps_add,
        acceptance=[
            AcceptanceCriterion(id=f"AC-T{number}-{k}", text=text)
            for k, text in enumerate(w.acceptance, start=1)
        ],
        gates=w.gates,
        size=_SIZES[w.points],
    )


# ---------------------------------------------------------------- the validator


def validate_plan(proposed: Sequence[ProposedTask], rules: PlanRules) -> PlanValidation:
    """Check a proposed plan against every rule of ARCHITECTURE §9 and resolve overlaps."""
    if not proposed:
        return PlanValidation(issues=(Issue(IssueCode.NO_TASKS, "plan", "the plan has no tasks"),))
    if len(proposed) > rules.max_tasks:
        issue = Issue(
            IssueCode.TOO_MANY_TASKS, "plan", f"at most {rules.max_tasks} tasks", str(len(proposed))
        )
        return PlanValidation(issues=(issue,))
    checker = _Checker(rules)
    works = [checker.task(i, p) for i, p in enumerate(proposed)]
    checker.graph(works)
    checker.traceability(works)
    if checker.issues:
        return PlanValidation(
            issues=tuple(checker.issues),
            changes=tuple(checker.changes),
            removed_characters=checker.removed,
        )
    resolved = _resolve(works, rules, checker.changes)
    for w in resolved:
        if len(w.depends_on) > MAX_DEPENDS:
            checker.add(
                IssueCode.TOO_MANY_DEPENDENCIES,
                f"{w.id}.depends_on",
                f"after ordering overlapping tasks it would depend on more than {MAX_DEPENDS} "
                "tasks; give tasks narrower owns_files",
            )
    if checker.issues:
        return PlanValidation(
            issues=tuple(checker.issues),
            changes=tuple(checker.changes),
            removed_characters=checker.removed,
        )
    return PlanValidation(
        tasks=tuple(_build(w) for w in resolved),
        changes=tuple(checker.changes),
        removed_characters=checker.removed,
    )
