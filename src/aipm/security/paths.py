"""Path validation: `safe_relpath` and `safe_rel_glob` (SECURITY.md §7.4, §9.2, §10 rule 5).

The only L0 module allowed read-only filesystem calls (`realpath`), to detect symlinks that
escape the workspace or land on a protected path (ARCHITECTURE §5.1).

Protected patterns are matched case-insensitively (macOS file systems are), at any depth, and
after trailing dots and spaces are dropped from each component. A glob is rejected when it
could match a protected path at the repository root (`**`, `*.md`, `.*/**`), or when its own
text names a protected path at any depth (`src/**/.env*`). Glob wildcards are `*` and `?`
within one component and `**` as a whole component; every other character is literal.
"""

import os
import unicodedata
from collections.abc import Iterable, Sequence
from functools import cache
from pathlib import Path
from typing import NewType

from aipm.domain.errors import PolicyViolation

SafeRelPath = NewType("SafeRelPath", str)
"""A relative path inside the workspace: no `..`, no leading `-`, no NUL, no escaping link."""

SafeRelGlob = NewType("SafeRelGlob", str)
"""A relative glob with the same rules, outside protected paths and `.pm/`."""

MAX_PATH_LENGTH = 512
MAX_COMPONENTS = 64
MAX_GLOBSTARS = 4

PROTECTED_PATHS: tuple[str, ...] = (
    ".pm/**", ".git/**", ".github/**", ".gitlab-ci.yml",
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", ".claude/**",
    ".gemini/**", ".codex/**", ".agents/**", ".mcp.json",
    ".gitattributes", ".gitmodules", ".aipmignore", "**/.env*",
)  # fmt: skip
"""SECURITY.md §9.2. `security.extra_protected_paths` adds to these, never replaces them."""

# Glob tokens. A literal token is always one character, so these never collide with one.
_ONE = "<?>"
_STAR = "<*>"
_GLOBSTAR = "<**>"
_WILD = frozenset({_ONE, _STAR, _GLOBSTAR})

type _Tokens = tuple[str, ...]


def _reject(value: str, reason: str) -> PolicyViolation:
    shown = value if len(value) <= 80 else value[:80] + "…"
    return PolicyViolation(f"path {shown!r} rejected: {reason}")


def _bad_char(ch: str) -> bool:
    category = unicodedata.category(ch)
    if category[0] == "C" or category in ("Zl", "Zp"):
        return True
    return category == "Zs" and ch != " "


def _check_text(value: object) -> str:
    if not isinstance(value, str):
        raise PolicyViolation(f"path must be a string, not {type(value).__name__}")
    if not value:
        raise _reject(value, "empty")
    if len(value) > MAX_PATH_LENGTH:
        raise _reject(value, f"longer than {MAX_PATH_LENGTH} characters")
    if any(_bad_char(ch) for ch in value):
        raise _reject(value, "control, format or unusual space character")
    if "\\" in value or ":" in value:
        raise _reject(value, "backslash or colon")
    if value.startswith(("/", "~")):
        raise _reject(value, "absolute or home-relative")
    return value


def _parts(raw: object, *, glob: bool) -> list[str]:
    """Check the syntax shared by paths and globs, and return the normalized components."""
    value = _check_text(raw)
    parts = [part for part in value.split("/") if part not in ("", ".")]
    if not parts:
        raise _reject(value, "refers to the workspace root")
    if len(parts) > MAX_COMPONENTS:
        raise _reject(value, f"more than {MAX_COMPONENTS} components")
    if ".." in parts:
        raise _reject(value, "contains '..'")
    if parts[0].startswith("-"):
        raise _reject(value, "starts with '-'")
    if glob:
        if any("**" in part and part != "**" for part in parts):
            raise _reject(value, "'**' must be a whole component")
        if parts.count("**") > MAX_GLOBSTARS:
            raise _reject(value, f"more than {MAX_GLOBSTARS} '**' components")
    elif any(ch in "*?" for ch in value):
        raise _reject(value, "wildcard in a literal path")
    return parts


def _tokens(pattern: str, *, literal: bool) -> _Tokens:
    if literal:
        return tuple(pattern)
    out: list[str] = []
    for index, part in enumerate(pattern.split("/")):
        if index:
            out.append("/")
        if part == "**":
            out.append(_GLOBSTAR)
            continue
        out.extend(_STAR if ch == "*" else _ONE if ch == "?" else ch for ch in part)
    return tuple(out)


def _expand_globstars(parts: Sequence[str]) -> list[list[str]]:
    """Expand each non-final `**` into "no component" or "one or more components"."""
    variants: list[list[str]] = [[]]
    last = len(parts) - 1
    for index, part in enumerate(parts):
        if part == "**" and index != last:
            variants = [v for prefix in variants for v in (prefix, [*prefix, part])]
        else:
            variants = [[*prefix, part] for prefix in variants]
    return variants


@cache
def _pattern_variants(pattern: str, *, any_depth: bool) -> tuple[_Tokens, ...]:
    """Token sequences whose union is the set of paths `pattern` protects."""
    folded = pattern.casefold()
    stems = [folded]
    if folded.endswith("/**"):
        stems.append(folded[:-3])  # the directory itself
    variants: list[_Tokens] = []
    for stem in stems:
        parts = stem.split("/")
        if parts[0] == "**" and len(parts) > 1:
            parts = parts[1:]  # "**/x" is "x" at any depth, which any_depth adds below
        prefixes: list[list[str]] = [[], ["**"]] if any_depth else [[]]
        for prefix in prefixes:
            for expanded in _expand_globstars([*prefix, *parts]):
                variants.append(_tokens("/".join(expanded), literal=False))
    return tuple(variants)


def _chars_meet(a: str, b: str) -> bool:
    """Whether one character exists that both single-character tokens accept."""
    if a in _WILD and b in _WILD:
        return True
    if a in _WILD:
        a, b = b, a
    if b in _WILD:
        return b == _GLOBSTAR or a != "/"
    return a == b


def _intersects(a: _Tokens, b: _Tokens) -> bool:
    """Whether some path matches both token sequences. `**` here is any string.

    A search over (position in a, position in b): a star may match nothing, and two tokens may
    consume one character together when some character satisfies both. Iterative, because two
    512-character inputs would exceed the recursion limit.
    """
    stars = (_STAR, _GLOBSTAR)
    seen: set[tuple[int, int]] = set()
    stack = [(0, 0)]
    while stack:
        state = stack.pop()
        if state in seen:
            continue
        seen.add(state)
        i, j = state
        if i == len(a) and j == len(b):
            return True
        if i < len(a) and a[i] in stars:
            stack.append((i + 1, j))
        if j < len(b) and b[j] in stars:
            stack.append((i, j + 1))
        if i < len(a) and j < len(b) and _chars_meet(a[i], b[j]):
            # A star that consumes a character stays where it is. When both stay, the state
            # does not change, and the star-matches-nothing moves above already cover it.
            stack.append((i if a[i] in stars else i + 1, j if b[j] in stars else j + 1))
    return False


def normalize_relpath(path: str) -> str:
    """Check a relative path's syntax and normalize it, without resolving or protection checks.

    For recorded metadata only, such as where a requirements source came from. Anything that
    opens, writes or passes a path to a process uses `safe_relpath`.
    """
    return "/".join(_parts(path, glob=False))


def protected_patterns(extra: Iterable[str] = ()) -> tuple[str, ...]:
    """Return `PROTECTED_PATHS` plus validated extra patterns (`security.extra_protected_paths`)."""
    added = tuple("/".join(_parts(pattern, glob=True)) for pattern in extra)
    return PROTECTED_PATHS + added


def is_protected(relpath: str, patterns: Sequence[str] = PROTECTED_PATHS) -> bool:
    """Whether a normalized relative path matches a protected pattern, at any depth."""
    canonical = "/".join(part.rstrip(" .") for part in relpath.casefold().split("/"))
    path = _tokens(canonical, literal=True)
    return any(
        _intersects(path, variant)
        for pattern in patterns
        for variant in _pattern_variants(pattern, any_depth=True)
    )


def safe_relpath(root: Path, path: str, *, extra_protected: Iterable[str] = ()) -> SafeRelPath:
    """Validate `path` against `root`, or raise `PolicyViolation`.

    Returns the normalized path (`./a//b` becomes `a/b`). Symlinks are resolved: the target must
    stay inside `root`, must not be `root` itself, and must not be protected either.
    """
    parts = _parts(path, glob=False)
    rel = "/".join(parts)
    patterns = protected_patterns(extra_protected)
    if is_protected(rel, patterns):
        raise _reject(path, "protected path")
    root_real = os.path.realpath(root)
    target = os.path.realpath(Path(root_real, *parts))
    if target == root_real:
        raise _reject(path, "resolves to the workspace root")
    if not target.startswith(root_real.rstrip(os.sep) + os.sep):
        raise _reject(path, "resolves outside the workspace")
    resolved = os.path.relpath(target, root_real).replace(os.sep, "/")
    if is_protected(resolved, patterns):
        raise _reject(path, "resolves to a protected path")
    return SafeRelPath(rel)


def safe_rel_glob(glob: str, *, extra_protected: Iterable[str] = ()) -> SafeRelGlob:
    """Validate an ownership glob from a plan, or raise `PolicyViolation`.

    Pure: nothing is resolved. Returns the normalized glob.
    """
    parts = _parts(glob, glob=True)
    rel = "/".join(parts)
    patterns = protected_patterns(extra_protected)
    tokens = _tokens(rel.casefold(), literal=False)
    for pattern in patterns:
        if any(_intersects(tokens, v) for v in _pattern_variants(pattern, any_depth=False)):
            raise _reject(glob, f"could match the protected path {pattern!r}")
    if is_protected(rel, patterns):
        raise _reject(glob, "names a protected path")
    return SafeRelGlob(rel)
