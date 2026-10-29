"""Markdown helpers for text that coding agents read: context files and task prompts.

- `code_span` and `fence` pick a backtick run longer than any in the text, so no value can close
  its span or fence early (CommonMark). Claude Code does not expand `@path` imports inside code
  spans or fenced blocks, which is why free text and gate argv are always put in one.
- `ContentNonces` gives untrusted blocks in context files ids derived from the rendered data, so
  an unchanged project renders the same bytes and `sync-context --check` sees no drift. The block
  boundary never depended on the id being secret: `|untrusted` neutralizes every `untrusted` tag
  inside the content (SECURITY.md §7.2).
- `agent_text_problems` (invariant I-3 as a run-time check) lives in `aipm.security.agent_text`,
  so the state store can apply it too; it is re-exported here.
"""

import hashlib
import re
from collections.abc import Iterable

from aipm.security.agent_text import agent_text_problems, outside_code

_BACKTICKS = re.compile(r"`+")


def _longest_run(text: str) -> int:
    return max((len(m) for m in _BACKTICKS.findall(text)), default=0)


def code_span(text: str) -> str:
    """`text` as one inline code span."""
    ticks = "`" * (_longest_run(text) + 1)
    pad = " " if text.startswith(("`", " ")) or text.endswith(("`", " ")) else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def fence(text: str, info: str = "text") -> str:
    """`text` as one fenced code block."""
    ticks = "`" * max(3, _longest_run(text) + 1)
    return f"{ticks}{info}\n{text.rstrip(chr(10))}\n{ticks}"


class ContentNonces:
    """Untrusted-block ids derived from `seed`, the same for the same rendered data."""

    def __init__(self, seed: str) -> None:
        self._seed = seed
        self._count = 0

    def __call__(self) -> str:
        self._count += 1
        digest = hashlib.sha256(f"{self._seed}:{self._count}".encode()).hexdigest()
        return f"u{digest[:8]}"


def seed_of(parts: Iterable[str]) -> str:
    """A seed for `ContentNonces` from the texts a file is rendered from."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\x00")
    return digest.hexdigest()


__all__ = ["ContentNonces", "agent_text_problems", "code_span", "fence", "outside_code", "seed_of"]
