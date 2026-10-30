"""The only way to write `.pm/` (AGENTS.md rule 7): atomic, locked, redacted (ARCHITECTURE §5.3).

Every write sanitizes and redacts each string of the artifact, refuses the write if the result
still holds a secret (exit 6), validates the exact text it is about to write, then replaces the
file atomically (temp file, fsync, `os.replace`, directory fsync). `.pm/` itself must be a real
directory inside the repository, and no file in it is read or written through a symlink, so a
cloned repo cannot point aipm's reads or writes elsewhere.

Security events are appended to `.pm/events.jsonl` through the store as well (§6.1).

A store opened with a `WriteLedger` records the sha256 of everything it writes or removes, so
`verify` can tell aipm's own `.pm/` writes from anyone else's (ADR-0021).
"""

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Generator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

from filelock import FileLock, Timeout
from pydantic import JsonValue, ValidationError
from ruamel.yaml import YAML

from aipm.domain.errors import LockHeld, PolicyViolation, SchemaError, UsageError
from aipm.domain.ids import is_valid_id
from aipm.domain.models import (
    ADR_DIR,
    SCHEMA_VERSION,
    AdrDoc,
    ApprovalsDoc,
    ArchitectureDoc,
    Artifact,
    ArtifactKind,
    MarkdownArtifact,
    PrdDoc,
    RepoMapDoc,
    RequirementsDoc,
    SecurityEvent,
    SecurityEventKind,
    TasksDoc,
    ThreatModelDoc,
    YamlArtifact,
)
from aipm.domain.models.artifacts import is_adr_file_name
from aipm.observability.redaction import process_redactor
from aipm.security.agent_text import agent_text_problems
from aipm.security.redact import Redactor
from aipm.security.sanitize import sanitize_text
from aipm.state import frontmatter
from aipm.state.layout import (
    EVENTS_FILE,
    GITIGNORE_FILE,
    GITIGNORE_TEXT,
    LOCK_FILE,
    PROMPTS_DIR,
    artifact_name,
    pm_root,
)
from aipm.state.yamlio import MAX_YAML_BYTES, dump_yaml, load_yaml

if TYPE_CHECKING:
    from aipm.state.attempts import WriteLedger

MAX_EVENTS_BYTES = 16 * 1_048_576
MAX_ADR_FILES = 100
MAX_PROMPT_BYTES = 1_048_576
_HOLDER = re.compile(r"(\d{1,10}) (\S{1,40})")
_TOOL = re.compile(r"[a-z]{1,16}")
_RUN_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,99}")
RUNS_DIR = "runs"
CACHE_DIR = "cache/llm"
MAX_CACHE_BYTES = 1_048_576
_CACHE_KEY = re.compile(r"[0-9a-f]{64}")

_MODELS: Mapping[ArtifactKind, type[YamlArtifact] | type[MarkdownArtifact[Any]]] = {
    ArtifactKind.REQUIREMENTS: RequirementsDoc,
    ArtifactKind.PRD: PrdDoc,
    ArtifactKind.ARCHITECTURE: ArchitectureDoc,
    ArtifactKind.THREAT_MODEL: ThreatModelDoc,
    ArtifactKind.TASKS: TasksDoc,
    ArtifactKind.APPROVALS: ApprovalsDoc,
    ArtifactKind.REPO_MAP: RepoMapDoc,
}


class StateStore(Protocol):
    """Load and save `.pm/` artifacts."""

    root: Path

    def load(self, kind: ArtifactKind) -> Artifact:
        """Load and validate an artifact; a newer schema_version exits 2."""
        ...

    def save(self, artifact: Artifact) -> str:
        """Write atomically after redaction and return the sha256."""
        ...

    def exists(self, kind: ArtifactKind) -> bool:
        """Return whether the artifact exists."""
        ...

    def sha256(self, kind: ArtifactKind) -> str | None:
        """Return the normalized hash, or None if missing."""
        ...

    def lock(self) -> AbstractContextManager[None]:
        """Hold the `.pm/` lock; raises `LockHeld` (exit 7) if another process has it."""
        ...


def normalized_sha256(data: bytes) -> str:
    """sha256 of the normalized bytes: LF line endings, trailing whitespace stripped (§6.2)."""
    text = data.decode("utf-8", errors="surrogateescape").replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip(" \t") for line in text.split("\n")]
    normalized = "\n".join(lines).rstrip("\n") + "\n"
    return hashlib.sha256(normalized.encode("utf-8", errors="surrogateescape")).hexdigest()


def plan_sha256(doc: TasksDoc, file_sha256: str) -> str:
    """The hash G3 approves (ADR-0016).

    A plan that no task has started is pinned to its exact file bytes (`file_sha256`), as
    before. Once work starts, `tasks.yaml` also records progress (`status`, `base_sha`, ...), so
    the pin becomes the plan without progress in aipm's canonical form, which is the hash of the
    file aipm wrote for the unstarted plan. Progress never voids G3; a change to the plan does.
    """
    view = doc.plan_view()
    if view == doc:
        return file_sha256
    return normalized_sha256(dump_yaml(view.to_document()).encode("utf-8"))


def _check_version(raw: Mapping[str, object], source: str) -> None:
    version = raw.get("schema_version")
    if isinstance(version, int) and not isinstance(version, bool) and version > SCHEMA_VERSION:
        raise SchemaError(
            f"{source} has schema_version {version}; this aipm reads up to {SCHEMA_VERSION}",
            hint="Upgrade aipm to read this file.",
        )


def _line_of(text: str, loc: tuple[int | str, ...]) -> int | None:
    """Best-effort 1-based line of a validation error, from a round-trip parse."""
    try:
        parser: Any = YAML(typ="rt", pure=True)
        node: Any = parser.load(text)
        line: int | None = None
        for key in loc:
            line = node.lc.key(key)[0] if isinstance(key, str) else node.lc.item(key)[0]
            node = node[key]
    except Exception:  # only a hint for the error message
        return None
    return None if line is None else line + 1


def _describe(exc: ValidationError, source: str, text: str, *, offset: int) -> str:
    parts: list[str] = []
    for error in exc.errors()[:5]:
        loc = tuple(error["loc"])
        field = ".".join(str(part) for part in loc) or "(document)"
        line = _line_of(text, loc[1:] if offset else loc)
        where = f" (line {line + offset})" if line is not None else ""
        parts.append(f"{field}{where}: {error['msg']}")
    more = len(exc.errors()) - len(parts)
    suffix = f"; and {more} more" if more > 0 else ""
    return f"{source} is not valid: " + "; ".join(parts) + suffix


class FileStateStore:
    """`StateStore` over the files in `<repo>/.pm`."""

    def __init__(
        self,
        repo_root: Path,
        *,
        redactor: Redactor | None = None,
        ledger: "WriteLedger | None" = None,
    ) -> None:
        self.repo_root = Path(os.path.realpath(repo_root))
        self.root = pm_root(self.repo_root)
        self.redactor = redactor if redactor is not None else process_redactor()
        self.ledger = ledger

    def _record(self, name: str, data: bytes | None) -> None:
        if self.ledger is not None:
            digest = None if data is None else hashlib.sha256(data).hexdigest()
            self.ledger.record(f".pm/{name}", digest)

    # ------------------------------------------------------------ directory and file safety

    def _check_root(self, *, create: bool) -> None:
        try:
            info = os.lstat(self.root)
        except FileNotFoundError:
            if not create:
                raise UsageError(
                    f"{self.root} does not exist", hint="Run `aipm init` first."
                ) from None
            self.root.mkdir(mode=0o755)
            info = os.lstat(self.root)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PolicyViolation(f"{self.root} must be a real directory, not a link or a file")

    def _read(self, name: str, *, limit: int) -> bytes | None:
        """Read a `.pm/` file without following links; None if it does not exist."""
        self._check_root(create=False)
        try:
            # O_NONBLOCK: a FIFO planted in place of a file cannot hang the read.
            fd = os.open(self.root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise PolicyViolation(f".pm/{name} cannot be read safely ({exc.strerror})") from None
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise PolicyViolation(f".pm/{name} is not a regular file")
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise SchemaError(f".pm/{name} is larger than {limit} bytes")
        return data

    def _atomic_write(self, name: str, data: bytes) -> None:
        self._check_root(create=True)
        target = self.root / name
        if target.is_symlink():
            raise PolicyViolation(f".pm/{name} is a symlink; refusing to write through it")
        tmp = self.root / f"{name}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            tmp.replace(target)
        except BaseException:
            with suppress(FileNotFoundError):
                tmp.unlink()
            raise
        dir_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        self._record(name, data)

    # ------------------------------------------------------------ cleaning

    def _clean_text(self, text: str, source: str, signals: list[int]) -> str:
        result = sanitize_text(text, source=source)
        signals.append(result.invisible_removed)
        return self.redactor.redact(result.text)

    def _clean(self, value: object, source: str, signals: list[int]) -> object:
        if isinstance(value, str):
            return self._clean_text(value, source, signals)
        if isinstance(value, Mapping):
            items: Mapping[object, object] = value  # pyright: ignore[reportUnknownVariableType]
            return {
                self._clean(key, source, signals): self._clean(item, source, signals)
                for key, item in items.items()
            }
        if isinstance(value, list):
            seq: list[object] = value  # pyright: ignore[reportUnknownVariableType]
            return [self._clean(item, source, signals) for item in seq]
        return value

    def _refuse_secrets(self, text: str, source: str) -> None:
        if self.redactor.contains_secret(text):
            raise PolicyViolation(
                f"refusing to write {source}: it still contains a secret after redaction",
                hint="Remove the secret from the input and try again.",
            )

    # ------------------------------------------------------------ parsing

    def _parse(
        self,
        model: type[YamlArtifact] | type[MarkdownArtifact[Any]],
        text: str,
        source: str,
    ) -> Artifact:
        offset = 0
        if issubclass(model, MarkdownArtifact):
            meta, body = frontmatter.parse(text, source=source)
            _check_version(meta, source)
            document: Mapping[object, object] = {"meta": meta, "body": body}
            yaml_text = text.replace("\r\n", "\n").split("\n---\n", 1)[0].removeprefix("---\n")
            offset = 1
        else:
            raw = load_yaml(text, source=source)
            if not isinstance(raw, dict):
                raise SchemaError(f"{source} must be a YAML mapping")
            mapping: dict[object, object] = raw  # pyright: ignore[reportUnknownVariableType]
            document = mapping
            _check_version({str(k): v for k, v in mapping.items()}, source)
            yaml_text = text
        try:
            return model.model_validate(document)
        except ValidationError as exc:
            raise SchemaError(
                _describe(exc, source, yaml_text, offset=offset),
                hint=f"Fix the field in {source}, or regenerate the file with aipm.",
            ) from None

    # ------------------------------------------------------------ the StateStore protocol

    def load(self, kind: ArtifactKind) -> Artifact:
        """Load and validate an artifact; a newer schema_version exits 2."""
        model = _MODELS.get(kind)
        if model is None:
            raise UsageError(f"the store does not load {kind.value} files")
        name = artifact_name(kind)
        data = self._read(name, limit=MAX_YAML_BYTES)
        if data is None:
            raise UsageError(f".pm/{name} does not exist")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SchemaError(f".pm/{name} is not valid UTF-8 (byte {exc.start})") from None
        return self._parse(model, text, f".pm/{name}")

    def _render(self, artifact: Artifact, source: str) -> tuple[bytes, int]:
        """The cleaned, checked bytes to write, and how many invisible characters were removed."""
        signals: list[int] = []
        if isinstance(artifact, MarkdownArtifact):
            meta = self._clean(artifact.front_matter(), source, signals)
            body = self._clean_text(artifact.body, source, signals)
            text = frontmatter.dump(meta, body)  # type: ignore[arg-type]
        else:
            text = dump_yaml(self._clean(artifact.to_document(), source, signals))
        self._refuse_secrets(text, source)
        self._parse(type(artifact), text, source)
        return text.encode("utf-8"), sum(signals)

    def _signal(self, source: str, removed: int) -> None:
        if removed:
            self.append_event(
                SecurityEventKind.INJECTION_SIGNAL,
                source=source,
                detail=f"{removed} invisible characters removed before writing",
            )

    def preview(self, artifact: Artifact) -> tuple[str, str]:
        """The exact text `save` would write, and its sha256, without writing anything."""
        name = artifact_name(artifact.artifact_kind)
        data, _ = self._render(artifact, f".pm/{name}")
        return data.decode("utf-8"), normalized_sha256(data)

    def save(self, artifact: Artifact) -> str:
        """Sanitize, redact and write atomically; return the sha256 of the written bytes."""
        name = artifact_name(artifact.artifact_kind)
        source = f".pm/{name}"
        data, removed = self._render(artifact, source)
        self._atomic_write(name, data)
        self._signal(source, removed)
        return normalized_sha256(data)

    def load_with_hash(self, kind: ArtifactKind) -> tuple[Artifact, str]:
        """Load an artifact and hash the very bytes that were parsed (a consistent read)."""
        model = _MODELS.get(kind)
        if model is None:
            raise UsageError(f"the store does not load {kind.value} files")
        name = artifact_name(kind)
        data = self._read(name, limit=MAX_YAML_BYTES)
        if data is None:
            raise UsageError(f".pm/{name} does not exist")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SchemaError(f".pm/{name} is not valid UTF-8 (byte {exc.start})") from None
        return self._parse(model, text, f".pm/{name}"), normalized_sha256(data)

    # ------------------------------------------------------------ the ADR directory

    def _adr_dir(self, *, create: bool) -> bool:
        """Check `.pm/adr` is a real directory (made if `create`); False if it is missing."""
        self._check_root(create=create)
        path = self.root / ADR_DIR
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            if not create:
                return False
            path.mkdir(mode=0o755)
            info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PolicyViolation(f".pm/{ADR_DIR} must be a real directory, not a link or a file")
        return True

    def adr_names(self) -> list[str]:
        """The ADR file names aipm reads, in order; other entries in `.pm/adr/` are ignored."""
        if not os.path.lexists(self.root) or not self._adr_dir(create=False):
            return []
        entries = (entry.name for entry in (self.root / ADR_DIR).iterdir())
        names = sorted(name for name in entries if is_adr_file_name(name))
        if len(names) > MAX_ADR_FILES:
            raise SchemaError(f".pm/{ADR_DIR} holds more than {MAX_ADR_FILES} ADR files")
        return names

    def _check_adr_entries(self) -> None:
        """Every ADR-named entry must be a regular file, so a replace cannot fail half way."""
        for name in self.adr_names():
            info = os.lstat(self.root / ADR_DIR / name)
            if not stat.S_ISREG(info.st_mode):
                raise PolicyViolation(f".pm/{ADR_DIR}/{name} is not a regular file")

    def _adr_bytes(self) -> list[tuple[str, bytes]]:
        found: list[tuple[str, bytes]] = []
        for name in self.adr_names():
            data = self._read(f"{ADR_DIR}/{name}", limit=MAX_YAML_BYTES)
            if data is not None:
                found.append((name, data))
        return found

    @staticmethod
    def _listing_sha256(files: list[tuple[str, bytes]]) -> str:
        listing = "".join(f"{name} {normalized_sha256(data)}\n" for name, data in files)
        return hashlib.sha256(listing.encode("ascii")).hexdigest()

    def adr_sha256(self) -> str:
        """The hash G2 pins for `adr/`: sha256 of each file name and normalized file hash."""
        return self._listing_sha256(self._adr_bytes())

    def load_adrs(self) -> tuple[list[AdrDoc], str]:
        """Every ADR, in file-name order, and the hash of exactly the bytes that were parsed."""
        files = self._adr_bytes()
        docs: list[AdrDoc] = []
        for name, data in files:
            source = f".pm/{ADR_DIR}/{name}"
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SchemaError(f"{source} is not valid UTF-8 (byte {exc.start})") from None
            doc = self._parse(AdrDoc, text, source)
            if isinstance(doc, AdrDoc):
                docs.append(doc)
        return docs, self._listing_sha256(files)

    def save_adrs(self, docs: list[AdrDoc]) -> str:
        """Replace the ADR set: write each file atomically, then remove ADRs not in `docs`."""
        names = [doc.file_name for doc in docs]
        if len(set(names)) != len(names) or len({d.meta.id for d in docs}) != len(docs):
            raise UsageError("ADR IDs and file names must be unique")
        rendered = [(name, *self._render(doc, f".pm/{ADR_DIR}/{name}")) for name, doc in
                    zip(names, docs, strict=True)]  # fmt: skip
        self._adr_dir(create=True)
        self._check_adr_entries()
        for name, data, removed in rendered:
            self._atomic_write(f"{ADR_DIR}/{name}", data)
            self._signal(f".pm/{ADR_DIR}/{name}", removed)
        for old in sorted(set(self.adr_names()) - set(names)):
            target = self.root / ADR_DIR / old
            try:
                target.unlink(missing_ok=True)
            except OSError as exc:
                message = f".pm/{ADR_DIR}/{old} cannot be removed ({exc.strerror})"
                raise PolicyViolation(message) from None
            self._record(f"{ADR_DIR}/{old}", None)
        return self.adr_sha256()

    def read_text(self, kind: ArtifactKind) -> str | None:
        """Read an artifact's text with the store's safety checks, or None if it is missing.

        For readers that validate on their own, such as the layered config loader.
        """
        name = artifact_name(kind)
        if not os.path.lexists(self.root):
            return None
        data = self._read(name, limit=MAX_YAML_BYTES)
        if data is None:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SchemaError(f".pm/{name} is not valid UTF-8 (byte {exc.start})") from None

    def exists(self, kind: ArtifactKind) -> bool:
        """Return whether the artifact exists."""
        return os.path.lexists(self.root / artifact_name(kind))

    def sha256(self, kind: ArtifactKind) -> str | None:
        """Return the normalized hash, or None if missing."""
        if not os.path.lexists(self.root):
            return None
        data = self._read(artifact_name(kind), limit=MAX_YAML_BYTES)
        return None if data is None else normalized_sha256(data)

    @contextmanager
    def _locked(self) -> Generator[None]:
        self._check_root(create=True)
        path = self.root / LOCK_FILE
        if path.is_symlink():
            raise PolicyViolation(f"{path} is a symlink; refusing to lock through it")
        lock = FileLock(
            path,
            timeout=0,
            mode=0o600,
            thread_local=False,
            fallback_to_soft=False,
            preserve_lock_file=True,
            on_acquired=_record_holder,
        )
        try:
            lock.acquire()
        except Timeout:
            raise LockHeld(
                f"another aipm process holds the .pm/ lock ({_holder(path)})",
                hint="Wait for it to finish. A crashed process releases the lock by itself.",
            ) from None
        try:
            yield
        finally:
            lock.release()

    def lock(self) -> AbstractContextManager[None]:
        """Hold the `.pm/` lock; raises `LockHeld` (exit 7) if another process has it."""
        return self._locked()

    # ------------------------------------------------------------ other .pm/ files

    def write_gitignore(self) -> None:
        """Write `.pm/.gitignore` (runs, cache, events and the lock stay local)."""
        self._atomic_write(GITIGNORE_FILE, GITIGNORE_TEXT.encode("utf-8"))

    def write_text(self, name: str, text: str) -> str:
        """Write a generated, schema-less `.pm/` file (sanitized, redacted, atomic)."""
        if "/" in name or name.startswith(".") or not name:
            raise UsageError(f"not a plain .pm/ file name: {name!r}")
        source = f".pm/{name}"
        cleaned = self._clean_text(text, source, [])
        self._refuse_secrets(cleaned, source)
        data = cleaned.encode("utf-8")
        self._atomic_write(name, data)
        return normalized_sha256(data)

    def _real_subdir(self, name: str) -> None:
        """Make sure `.pm/<name>` is a real directory (created if missing), never a link."""
        self._check_root(create=True)
        path = self.root / name
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            path.mkdir(mode=0o755)
            info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PolicyViolation(f".pm/{name} must be a real directory, not a link or a file")

    def _real_dirs(self, parts: Sequence[str]) -> None:
        """Make `.pm/<parts…>` real directories (created if missing), never links."""
        self._check_root(create=True)
        path = self.root
        for part in parts:
            path = path / part
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                path.mkdir(mode=0o755)
                info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise PolicyViolation(f"{path} must be a real directory, not a link or a file")

    def save_run_text(self, run_id: str, parts: Sequence[str], text: str) -> str:
        """Write `.pm/runs/<run-id>/<parts…>` (sanitized, redacted, atomic); returns its path
        relative to the repository. Gate output is T2, so it is cleaned like any other text."""
        if not is_valid_id("run", run_id) or not parts:
            raise UsageError(f"not a run ID and file: {run_id!r}")
        for part in parts:
            if not _RUN_PART.fullmatch(part) or part in (".", ".."):
                raise UsageError(f"not a run file name: {part!r}")
        name = "/".join((RUNS_DIR, run_id, *parts))
        source = f".pm/{name}"
        cleaned = self._clean_text(text, source, [])
        self._refuse_secrets(cleaned, source)
        self._real_dirs([RUNS_DIR, run_id, *parts[:-1]])
        self._atomic_write(name, cleaned.encode("utf-8"))
        return source

    def _cache_name(self, key: str) -> str:
        if not _CACHE_KEY.fullmatch(key):
            raise UsageError("not a cache key")
        return f"{CACHE_DIR}/{key}.json"

    def cache_get(self, key: str) -> str | None:
        """A cached LLM reply (T2: the caller validates it again), or `None` (ARCHITECTURE §14)."""
        name = self._cache_name(key)
        try:
            data = self._read(name, limit=MAX_CACHE_BYTES)
        except (PolicyViolation, UsageError):
            return None
        if data is None:
            return None
        try:
            entry: object = json.loads(data)
        except ValueError:
            return None
        if not isinstance(entry, dict):
            return None
        text = cast("dict[str, object]", entry).get("text")
        return text if isinstance(text, str) else None

    def cache_put(self, key: str, text: str) -> None:
        """Store an LLM reply that passed validation (sanitized, redacted, atomic)."""
        name = self._cache_name(key)
        cleaned = self._clean_text(text, f".pm/{name}", [])
        if self.redactor.contains_secret(cleaned):
            return
        data = json.dumps({"v": 1, "text": cleaned}, ensure_ascii=True).encode("ascii")
        if len(data) > MAX_CACHE_BYTES:
            return
        self._real_dirs(CACHE_DIR.split("/"))
        self._atomic_write(name, data)

    def cache_drop(self, key: str) -> None:
        """Delete a cached reply that failed validation."""
        name = self._cache_name(key)
        try:
            (self.root / name).unlink()
        except FileNotFoundError:
            return
        self._record(name, None)

    def latest_report(self, task_id: str) -> str | None:
        """The text of the newest `verify` gate report of a task, or `None` (`prompt --fix`).

        Reports live in `.pm/runs/<run-id>/gates/<T-ID>/<attempt>/report.yaml`; links and
        anything but real directories and files are skipped.
        """
        if not is_valid_id("task", task_id):
            raise UsageError(f"not a task ID: {task_id!r}")
        runs = self.root / RUNS_DIR
        best: tuple[str, int, str] | None = None
        for run_id in _real_children(runs):
            if not is_valid_id("run", run_id):
                continue
            task_dir = runs / run_id / "gates" / task_id
            for attempt in _real_children(task_dir):
                if attempt.isdigit() and (best is None or (run_id, int(attempt)) > best[:2]):
                    best = (run_id, int(attempt), f"{RUNS_DIR}/{run_id}/gates/{task_id}/{attempt}")
        if best is None:
            return None
        data = self._read(f"{best[2]}/report.yaml", limit=MAX_YAML_BYTES)
        return None if data is None else data.decode("utf-8", errors="replace")

    def save_prompt(
        self, task_id: str, tool: str, text: str, *, allowed_url_domains: Sequence[str] = ()
    ) -> tuple[str, str]:
        """Write `.pm/prompts/<T-ID>.<tool>.md`; return the text written and its sha256.

        The prompt holds `untrusted` blocks (gate output, model text), so it is redacted between
        the block tags, never across one (SECURITY.md §7.2, §8), and refused if a secret is left.
        Redaction can cut a code span short, so the redacted text is checked against invariant
        I-3 again and refused (exit 6) if it fails. Callers print or copy the returned text,
        never their own copy.
        """
        if not is_valid_id("task", task_id) or not _TOOL.fullmatch(tool):
            raise UsageError(f"not a task ID and tool name: {task_id!r}, {tool!r}")
        # Imported here: the template module loads Jinja, which read-only commands do not need.
        from aipm.security.untrusted import map_between_tags  # noqa: PLC0415

        name = f"{PROMPTS_DIR}/{task_id}.{tool}.md"
        source = f".pm/{name}"
        cleaned = sanitize_text(text, source=source)
        redacted = map_between_tags(cleaned.text, self.redactor.redact)
        self._refuse_secrets(redacted, source)
        problems = agent_text_problems(redacted, allowed_url_domains=allowed_url_domains)
        if problems:
            raise PolicyViolation(
                f"refusing to write {source}: after redaction it fails invariant I-3 "
                f"({'; '.join(problems)})",
                hint="A secret-looking value sits in a path or command of this task; remove it.",
            )
        data = redacted.encode("utf-8")
        if len(data) > MAX_PROMPT_BYTES:
            raise UsageError(f"{source} would be larger than {MAX_PROMPT_BYTES} bytes")
        self._real_subdir(PROMPTS_DIR)
        self._atomic_write(name, data)
        self._signal(source, cleaned.invisible_removed)
        return redacted, normalized_sha256(data)

    def append_event(
        self,
        kind: SecurityEventKind,
        *,
        source: str = "",
        detail: str = "",
        data: Mapping[str, JsonValue] | None = None,
        ack_of: str | None = None,
    ) -> SecurityEvent:
        """Append a security event with a fresh random ID to `.pm/events.jsonl`."""
        signals: list[int] = []
        draft = SecurityEvent(
            id=f"EV-{secrets.token_hex(6)}",
            ts=datetime.now(UTC),
            kind=kind,
            source=source[:200],
            detail=detail[:1000],
            ack_of=ack_of,
            data=dict(data or {}),
        )
        event = SecurityEvent.model_validate(
            self._clean(draft.model_dump(mode="json"), EVENTS_FILE, signals)
        )
        line = json.dumps(event.model_dump(mode="json"), ensure_ascii=True, separators=(",", ":"))
        self._refuse_secrets(line, EVENTS_FILE)
        self._check_root(create=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
        try:
            fd = os.open(self.root / EVENTS_FILE, flags, 0o600)
        except OSError as exc:
            message = f".pm/{EVENTS_FILE} cannot be appended safely ({exc.strerror})"
            raise PolicyViolation(message) from None
        try:
            os.write(fd, (line + "\n").encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
        if self.ledger is not None:
            self._record(EVENTS_FILE, self._read(EVENTS_FILE, limit=MAX_EVENTS_BYTES))
        return event

    def read_events(self) -> list[SecurityEvent]:
        """Return the valid events in `.pm/events.jsonl`; malformed lines are skipped."""
        if not os.path.lexists(self.root):
            return []
        data = self._read(EVENTS_FILE, limit=MAX_EVENTS_BYTES)
        events: list[SecurityEvent] = []
        for line in (data or b"").decode("utf-8", errors="replace").splitlines():
            with suppress(ValidationError, ValueError):
                events.append(SecurityEvent.model_validate_json(line))
        return events


def _real_children(path: Path) -> list[str]:
    """The names of the real directories in `path` (links skipped); empty if it is not one."""
    try:
        info = os.lstat(path)
    except OSError:
        return []
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return []
    return sorted(
        entry.name
        for entry in os.scandir(path)
        if entry.is_dir(follow_symlinks=False) and not entry.is_symlink()
    )


def _record_holder(fd: int) -> None:
    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    os.write(fd, f"{os.getpid()} {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}\n".encode())


def _holder(path: Path) -> str:
    """Describe the lock holder from the lock file, which is untrusted: only digits and a time."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read(64).decode("ascii", errors="replace").strip()
    except OSError:
        raw = ""
    match = _HOLDER.fullmatch(raw)
    if match is None:
        return "holder unknown"
    return f"PID {match.group(1)}, since {match.group(2)}"


def open_store(
    repo_root: Path, *, redactor: Redactor | None = None, ledger: "WriteLedger | None" = None
) -> FileStateStore:
    """Return the store for `<repo_root>/.pm`, with a redactor built from the full environment.

    Commands pass the repository's `WriteLedger` (`aipm.app.runtime.open_repo_store`).
    """
    return FileStateStore(repo_root, redactor=redactor, ledger=ledger)
