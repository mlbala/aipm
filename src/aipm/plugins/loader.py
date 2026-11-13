"""Entry-point plugins from aipm's own environment only (ARCHITECTURE §18, v0.4).

Plugins are Python code, trusted like aipm itself, so where they come from is the whole control:

- Distributions are read only from the running interpreter's own `purelib` and `platlib`
  directories (`sysconfig`), never from `sys.path`, which holds the current directory under
  `python -m` and whatever `PYTHONPATH` names. A plugin installed in the target repository's
  virtualenv, or dropped into the current directory, is never seen.
- If those directories lie inside the repository aipm works on (aipm installed into the target
  repo's own `.venv`), nothing is loaded and a warning says why.
- Each entry point must name a module and attribute in plain dotted identifiers. While it is
  imported, `sys.path` holds only those directories and the standard library (never the
  current directory, `PYTHONPATH` or anything inside the repository), and a module that still
  comes from anywhere else is refused.
  The import is the one `importlib.import_module` call allowed in `src/aipm` besides
  `execution/process.py`, exempted from TID251 on its own line only (ARCHITECTURE §5.1).
- A plugin whose name is a built-in name of its group is refused; a plugin that fails to load
  is skipped with a warning. `--no-plugins` turns loading off.

Loading is lazy: `configure` records whether plugins are on (the CLI's `--no-plugins`), and the
first `loaded()` call imports them, so `aipm --help` imports none.
"""

import importlib
import importlib.metadata
import os
import re
import sys
import sysconfig
from collections.abc import Generator, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

GROUPS: tuple[str, ...] = (
    "aipm.adapters",
    "aipm.gates",
    "aipm.scanners",
    "aipm.llm_providers",
    "aipm.stacks",
)
"""The entry-point groups of ARCHITECTURE §18."""
BUILTIN_NAMES: Mapping[str, frozenset[str]] = {
    "aipm.adapters": frozenset({"claude", "codex", "copilot", "gemini"}),
    "aipm.gates": frozenset({"gitleaks", "semgrep", "osv", "ac_trace", "ac_review"}),
    "aipm.scanners": frozenset({"gitleaks", "semgrep", "osv", "trivy"}),
    "aipm.llm_providers": frozenset({"anthropic", "openai", "fake"}),
    "aipm.stacks": frozenset(),
}
"""Names a plugin may not take: a plugin adds, it never replaces (stacks are checked against
the shipped templates when they are listed)."""
MAX_PLUGINS = 64
_NAME = re.compile(r"[a-z][a-z0-9_\-]{0,39}")
_DOTTED = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")


@dataclass(frozen=True, slots=True)
class Plugin:
    """One loaded plugin: its group and name, where it came from, and the object it names."""

    group: str
    name: str
    target: str
    distribution: str
    version: str
    obj: object

    def to_data(self) -> dict[str, str]:
        """For `doctor`: never the object itself."""
        return {
            "group": self.group,
            "name": self.name,
            "target": self.target,
            "distribution": self.distribution,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class Loaded:
    """What `load_plugins` found: the plugins, why others were skipped, and whether loading
    was on."""

    enabled: bool
    plugins: tuple[Plugin, ...] = ()
    warnings: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()

    def of(self, group: str) -> tuple[Plugin, ...]:
        """The plugins of one group."""
        return tuple(p for p in self.plugins if p.group == group)


def own_paths() -> tuple[Path, ...]:
    """The running interpreter's own site-packages directories."""
    found: list[Path] = []
    for key in ("purelib", "platlib"):
        value = sysconfig.get_paths().get(key)
        if value and Path(value).is_dir():
            path = Path(os.path.realpath(value))
            if path not in found:
                found.append(path)
    return tuple(found)


def _inside(path: Path, root: Path) -> bool:
    try:
        Path(os.path.realpath(path)).relative_to(os.path.realpath(root))
    except ValueError:
        return False
    return True


def _stdlib() -> tuple[Path, ...]:
    paths = sysconfig.get_paths()
    return tuple(Path(os.path.realpath(paths[k])) for k in ("stdlib", "platstdlib") if k in paths)


@contextmanager
def _only(paths: Sequence[Path]) -> Generator[None]:
    """`sys.path` set to `paths` and the standard library while a plugin is imported."""
    stdlib = _stdlib()
    saved = list(sys.path)
    keep = [e for e in saved if e and any(_inside(Path(e), root) for root in stdlib)]
    sys.path[:] = [*(str(p) for p in paths), *keep]
    try:
        yield
    finally:
        sys.path[:] = saved


def _from(module: object, paths: Sequence[Path]) -> bool:
    """Whether an imported module's file lies in `paths` (aipm's own modules count too)."""
    where = getattr(module, "__file__", None)
    if not isinstance(where, str):
        return False
    own = Path(os.path.realpath(__file__)).parents[1]  # the aipm package itself
    return any(_inside(Path(where), root) for root in (*paths, own))


def _resolve(target: str, paths: Sequence[Path]) -> object:
    module, _, attr = target.partition(":")
    if not _DOTTED.fullmatch(module) or (attr and not _DOTTED.fullmatch(attr)):
        raise ValueError(f"the entry point {target[:120]!r} is not a plain module:attribute")
    with _only(paths):
        obj: object = importlib.import_module(module)  # noqa: TID251 - the plugin import (§5.1)
    if not _from(obj, paths):
        raise ValueError(f"the module {module!r} is not installed in aipm's own environment")
    for part in attr.split(".") if attr else ():
        obj = getattr(obj, part)
    return obj


def _entries(paths: Sequence[Path]) -> Iterable[tuple[str, str, str, str, str]]:
    """(group, name, target, distribution, version) for every entry point in `paths`."""
    for dist in importlib.metadata.distributions(path=[str(p) for p in paths]):
        name = str(dist.metadata["Name"] or "?")[:100]
        version = str(dist.version or "?")[:40]
        for entry in dist.entry_points:
            if entry.group in GROUPS:
                yield entry.group, entry.name, entry.value, name, version


def load_plugins(
    *, enabled: bool, repo: Path | None = None, paths: Sequence[Path] | None = None
) -> Loaded:
    """Load every plugin installed in aipm's own environment (nothing when not `enabled`).

    `repo` is the repository aipm works on: an environment inside it is never read. `paths` is a
    seam for tests; it defaults to `own_paths()`.
    """
    if not enabled:
        return Loaded(enabled=False)
    where = tuple(paths) if paths is not None else own_paths()
    shown = tuple(str(p) for p in where)
    if repo is not None and any(_inside(p, repo) for p in where):
        return Loaded(
            enabled=True,
            warnings=(
                "plugins are off: aipm's own environment is inside the repository it works on",
            ),
            paths=shown,
        )
    plugins: list[Plugin] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    for group, name, target, dist, version in sorted(set(_entries(where))):
        label = f"plugin {name[:40]!r} ({group}, from {dist} {version})"
        if not _NAME.fullmatch(name):
            warnings.append(f"{label} skipped: the name is not plain lower-case words")
            continue
        if name in BUILTIN_NAMES[group] or (group, name) in seen:
            warnings.append(f"{label} skipped: the name is taken")
            continue
        if len(plugins) >= MAX_PLUGINS:
            warnings.append(f"{label} skipped: more than {MAX_PLUGINS} plugins")
            continue
        try:
            obj = _resolve(target, where)
        except Exception as exc:  # a plugin is third-party code: any failure skips it
            warnings.append(f"{label} skipped: {type(exc).__name__}: {str(exc)[:200]}")
            continue
        seen.add((group, name))
        plugins.append(Plugin(group, name, target, dist, version, obj))
    return Loaded(enabled=True, plugins=tuple(plugins), warnings=tuple(warnings), paths=shown)


_settings: dict[str, object] = {"enabled": True, "repo": None}
_cache: list[Loaded] = []


def configure(*, enabled: bool, repo: Path | None = None) -> None:
    """Record `--no-plugins` and the repository for this process; loads nothing yet."""
    _settings["enabled"] = enabled
    _settings["repo"] = repo
    _cache.clear()


def loaded() -> Loaded:
    """The plugins of this process, loaded on first use."""
    if not _cache:
        repo = _settings["repo"]
        _cache.append(
            load_plugins(
                enabled=bool(_settings["enabled"]),
                repo=repo if isinstance(repo, Path) else None,
            )
        )
    return _cache[0]
