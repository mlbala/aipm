"""`repo-map.md`: a sanitized summary of an existing repository (written by `aipm init`).

At most `MAX_ENTRIES` files and directories, in sorted depth-first order, plus the manifests
found at the root and the README's first heading. `.gitignore`, `.aipmignore` and the built-in
deny list (SECURITY.md §7.1) are respected; symbolic links are listed but never followed. A
name that sanitizing would change (control, invisible or bidi characters) is skipped and
counted. The result is untrusted text (T2) whenever a role reads it back.
"""

import os
import re
import stat
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from pathspec import GitIgnoreSpec

from aipm.domain.errors import InputRejected
from aipm.domain.models import Mode, RepoMapDoc, RepoMapFrontMatter
from aipm.security.paths import LLM_DENY_PATTERNS
from aipm.security.sanitize import decode_untrusted, sanitize_text

MAX_ENTRIES = 300
MAX_IGNORE_BYTES = 262_144
MAX_IGNORE_LINES = 2000
MAX_NAME_LENGTH = 200
DENY_PATTERNS = LLM_DENY_PATTERNS
MANIFESTS = (
    "pyproject.toml", "uv.lock", "setup.py", "setup.cfg", "requirements.txt", "package.json",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "go.mod", "Cargo.toml", "pom.xml",
)  # fmt: skip
_REQUIREMENTS = re.compile(r"requirements[\w.\-]*\.txt")
_HEADING = re.compile(r"#{1,6}[ \t]+(.+)")
_TRIVIAL = frozenset({"readme", "license", "licence", "changelog", ".gitignore", ".gitattributes"})


@dataclass(frozen=True, slots=True)
class RepoScan:
    """What the walk found."""

    entries: tuple[str, ...]
    truncated: bool
    skipped: int
    manifests: tuple[str, ...]
    readme_heading: str | None
    mode: Mode


def _read_ignore(path: Path) -> list[str]:
    """Read an ignore file: never through a link, never from a FIFO or device."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return []
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return []
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_IGNORE_BYTES)
    return data.decode("utf-8", errors="replace").splitlines()[:MAX_IGNORE_LINES]


def _usable(name: str) -> bool:
    clean = sanitize_text(name, source="file name").text
    return clean == name and name.strip() == name and len(name) <= MAX_NAME_LENGTH


def manifests_in(root: Path) -> tuple[str, ...]:
    """The manifest files at the repository root."""
    try:
        names = [entry.name for entry in root.iterdir()]
    except OSError:
        return ()
    found = {name for name in names if name in MANIFESTS or _REQUIREMENTS.fullmatch(name)}
    return tuple(sorted(name for name in found if (root / name).is_file()))


def _readme_heading(root: Path, max_bytes: int) -> str | None:
    candidates = sorted(
        name
        for name in (entry.name for entry in root.iterdir())
        if name.casefold() in ("readme.md", "readme", "readme.rst")
    )
    for name in candidates:
        path = root / name
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        try:
            text = decode_untrusted(data, source=name, max_bytes=max_bytes, truncate=True).text
        except InputRejected:  # binary or undecodable: no heading
            return None
        for line in text.splitlines():
            match = _HEADING.fullmatch(line.strip())
            if match:
                return match.group(1).strip()[:MAX_NAME_LENGTH]
        return None
    return None


def _children(directory: Path) -> Iterator[os.DirEntry[str]]:
    try:
        with os.scandir(directory) as found:
            entries = sorted(found, key=lambda entry: entry.name)
    except OSError:
        entries = []
    return iter(entries)


_DENY_SPEC = GitIgnoreSpec.from_lines(DENY_PATTERNS)


@dataclass(frozen=True, slots=True)
class IgnoreRules:
    """Files never read for LLM context (SECURITY.md §7.1).

    `.gitignore` and `.aipmignore` are matched as git matches them. The built-in deny list is
    matched without regard to case: on a case-insensitive file system `Secrets.yaml`,
    `server.PEM` or `.NETRC` name the same kinds of file (red-team v0.1, RT01-6).
    """

    ignored: GitIgnoreSpec

    def match_file(self, path: str) -> bool:
        """Whether `path` (relative, `/`-separated, a trailing `/` for a directory) is excluded."""
        return self.ignored.match_file(path) or _DENY_SPEC.match_file(path.casefold())


def ignore_spec(root: Path, *, also: Iterable[str] = ()) -> IgnoreRules:
    """Files never read for LLM context: `.gitignore`, `.aipmignore` and the §7.1 deny list.
    `also` adds more ignore lines (the base commit's, so an agent that edits `.gitignore`
    cannot un-ignore a file for the AC reviewer)."""
    ignore_files = [*_read_ignore(root / ".gitignore"), *_read_ignore(root / ".aipmignore")]
    return IgnoreRules(GitIgnoreSpec.from_lines([*ignore_files, *list(also)[:MAX_IGNORE_LINES]]))


def scan_repo(root: Path, *, max_input_bytes: int) -> RepoScan:
    """Walk the repository and summarize it."""
    spec = ignore_spec(root)
    entries: list[str] = []
    skipped = 0
    truncated = False
    substantive = False
    # Depth-first, sorted: each stack frame is a directory prefix and its remaining children.
    stack: list[tuple[str, Iterator[os.DirEntry[str]]]] = [("", _children(root))]
    while stack:
        prefix, children = stack[-1]
        child = next(children, None)
        if child is None:
            stack.pop()
            continue
        if not _usable(child.name):
            skipped += 1
            continue
        rel = f"{prefix}{child.name}"
        is_dir = child.is_dir(follow_symlinks=False)
        if spec.match_file(f"{rel}/" if is_dir else rel):
            continue
        if len(entries) >= MAX_ENTRIES:
            truncated = True
            break
        if child.is_symlink():
            entries.append(f"{rel} (link)")
        elif is_dir:
            entries.append(f"{rel}/")
            stack.append((f"{rel}/", _children(root / rel)))
        else:
            entries.append(rel)
            top = rel.split("/", 1)[0].casefold()
            substantive = substantive or top.split(".", 1)[0] not in _TRIVIAL
    manifests = manifests_in(root)
    mode = Mode.BROWNFIELD if substantive or manifests else Mode.GREENFIELD
    return RepoScan(
        entries=tuple(entries),
        truncated=truncated,
        skipped=skipped,
        manifests=manifests,
        readme_heading=_readme_heading(root, max_input_bytes),
        mode=mode,
    )


def repo_map_doc(scan: RepoScan, *, stack_template: str | None) -> RepoMapDoc:
    """Render the scan as `repo-map.md`."""
    lines = [
        "# Repository map",
        "",
        "Generated by `aipm init` from the files in this repository. File names and the README",
        "heading are untrusted text.",
        "",
        f"- Mode: {scan.mode.value}",
        f"- Stack template: {stack_template or 'none'}",
        f"- Manifests: {', '.join(scan.manifests) or 'none'}",
        f"- README heading: {scan.readme_heading or 'none'}",
        "",
        "## Files",
        "",
    ]
    lines.extend(f"- {entry}" for entry in scan.entries)
    if not scan.entries:
        lines.append("- (no files)")
    if scan.truncated:
        lines.extend(["", f"Listing stopped after {MAX_ENTRIES} entries."])
    if scan.skipped:
        lines.extend(["", f"{scan.skipped} entries with unusual names were left out."])
    meta = RepoMapFrontMatter(
        mode=scan.mode,
        stack_template=stack_template,
        entries=len(scan.entries),
        truncated=scan.truncated,
        manifests=list(scan.manifests),
    )
    return RepoMapDoc(meta=meta, body="\n".join(lines) + "\n")
