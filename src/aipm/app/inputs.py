"""Reading user-named input files (`--from`, `--answers`) safely.

A path given on the command line is a user path (AGENTS.md rule 6): it must resolve inside the
repository and pass `safe_relpath`, so a symlink cannot smuggle in `.env` or a file outside the
repo, and the recorded `sources[].path` is a clean repo-relative path. Files that are never read
for LLM context (SECURITY.md §7.1: `.gitignore`, `.aipmignore` and the deny list) are refused.
The file is opened without following a final symlink, must be the same inode that was checked,
must be a regular file, and is size-capped before it is decoded.
"""

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, ValidationError, field_validator, model_validator

from aipm.app.repo_map import ignore_spec
from aipm.domain.errors import InputRejected, PolicyViolation, SchemaError, UsageError
from aipm.domain.ids import is_valid_id
from aipm.domain.models import Dimension, Source, SourceKind, StrictModel
from aipm.security.paths import safe_relpath
from aipm.state.store import normalized_sha256
from aipm.state.yamlio import load_yaml


@dataclass(frozen=True, slots=True)
class RepoFile:
    """A file read from inside the repository."""

    relpath: str
    data: bytes
    sha256: str


def read_repo_file(root: Path, given: Path, *, max_bytes: int, what: str) -> RepoFile:
    """Read a user-named file that must live inside the repository at `root`."""
    absolute = Path(os.path.realpath(given if given.is_absolute() else Path.cwd() / given))
    try:
        rel = absolute.relative_to(root)
    except ValueError:
        raise UsageError(
            f"{what} {given} is outside the repository",
            hint="Copy the file into the repository and pass its path.",
        ) from None
    relpath = safe_relpath(root, rel.as_posix())
    if ignore_spec(root).match_file(relpath):
        raise PolicyViolation(
            f"{what} {relpath} is a file aipm never reads for LLM context "
            "(.gitignore, .aipmignore, or a secrets name such as .env, *.key or .netrc)",
            hint="Copy the text you want to use into a plain file inside the repository.",
        )
    try:
        checked = absolute.stat()
        fd = os.open(root / relpath, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise UsageError(f"{what} {given} does not exist") from None
    except OSError as exc:
        raise UsageError(f"{what} {given} cannot be read ({exc.strerror})") from None
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode):
        os.close(fd)
        raise UsageError(f"{what} {given} is not a regular file")
    if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
        os.close(fd)
        raise PolicyViolation(f"{what} {relpath} changed while it was being opened")
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise InputRejected(
            f"{what} {relpath} is larger than {max_bytes} bytes",
            hint="Shorten the file, or raise security.max_input_kib in your user config.",
        )
    return RepoFile(relpath=relpath, data=data, sha256=normalized_sha256(data))


# ---------------------------------------------------------------- the answers file

AnswerItem = Annotated[str, StringConstraints(min_length=1, max_length=500)]
AnswerValue = Annotated[str, StringConstraints(max_length=4000)] | list[AnswerItem] | bool


class AnswersFile(StrictModel):
    """`--answers FILE`: answers keyed by question ID (Q-001), assumption ID (A-001) or dimension.

    A value is text, a list of options, or a boolean (for confirm questions, and to confirm an
    assumption). `confirm_extracted: true` confirms every answer extracted from `--from`.
    """

    schema_version: Literal[1] = 1
    description: Annotated[str, StringConstraints(max_length=4000)] = ""
    confirm_extracted: bool = False
    answers: dict[str, AnswerValue] = Field(default_factory=dict[str, AnswerValue], max_length=300)

    @field_validator("answers", mode="before")
    @classmethod
    def _numbers_as_text(cls, value: object) -> object:
        if isinstance(value, dict):
            items: dict[object, object] = value  # pyright: ignore[reportUnknownVariableType]
            return {
                k: str(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else v
                for k, v in items.items()
            }
        return value

    @model_validator(mode="after")
    def _keys(self) -> Self:
        dimensions = {d.value for d in Dimension}
        for key in self.answers:
            if not (
                key in dimensions or is_valid_id("question", key) or is_valid_id("assumption", key)
            ):
                raise ValueError(
                    f"answers keys are question IDs, assumption IDs or dimension names, not {key!r}"
                )
        return self


def answer_text(value: str | list[str] | bool) -> str:
    """The stored text of an answers-file value."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return "; ".join(value)
    return value.strip()


def load_answers(root: Path, given: Path, *, max_bytes: int) -> tuple[AnswersFile, Source]:
    """Read and validate an answers file; returns it with its `sources` entry."""
    file = read_repo_file(root, given, max_bytes=max_bytes, what="--answers")
    try:
        text = file.data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputRejected(f"--answers {file.relpath} is not valid UTF-8") from None
    raw = load_yaml(text, source=file.relpath)
    try:
        parsed = AnswersFile.model_validate(raw if raw is not None else {})
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"]) or "(file)"
        raise SchemaError(
            f"{file.relpath} is not a valid answers file: {where}: {first['msg']}",
            hint="See `aipm discover --help` and the README for the answers file format.",
        ) from None
    source = Source(kind=SourceKind.ANSWERS, path=file.relpath, sha256=file.sha256)
    return parsed, source
