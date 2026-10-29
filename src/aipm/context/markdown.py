"""Markdown helpers for text that coding agents read: context files and task prompts.

- `code_span` and `fence` pick a backtick run longer than any in the text, so no value can close
  its span or fence early (CommonMark). Claude Code does not expand `@path` imports inside code
  spans or fenced blocks, which is why free text and gate argv are always put in one.
- `ContentNonces` gives untrusted blocks in context files ids derived from the rendered data, so
  an unchanged project renders the same bytes and `sync-context --check` sees no drift. The block
  boundary never depended on the id being secret: `|untrusted` neutralizes every `untrusted` tag
  inside the content (SECURITY.md §7.2).
- `agent_text_problems` is invariant I-3 as a runtime check (SECURITY.md §14.1).
"""

import hashlib
import re
from collections.abc import Iterable

from aipm.security.sanitize import has_mention, sanitize_for_context, sanitize_text

_BACKTICKS = re.compile(r"`+")
_FENCED = re.compile(r"^(`{3,})[^`\n]*\n.*?^\1[ \t]*$", re.MULTILINE | re.DOTALL)
_SPAN = re.compile(r"(?<!`)(`+)(?!`).*?(?<!`)\1(?!`)")


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


def outside_code(text: str) -> str:
    """`text` without its fenced code blocks and code spans, where no import is read."""
    return _SPAN.sub(" ", _FENCED.sub("", text))


def agent_text_problems(
    text: str, *, allowed_url_domains: Iterable[str], imports: Iterable[str] = ()
) -> list[str]:
    """What breaks invariant I-3 in `text`: URLs outside the allowlist, HTML comments, invisible
    or control characters, and, outside code, `@` mentions other than the exact `imports`
    lines."""
    problems: list[str] = []
    if "<!--" in text:
        problems.append("an HTML comment")
    removed = sanitize_text(text, source="check").removed
    if removed:
        problems.append("invisible or control characters: " + ", ".join(sorted(removed)))
    if sanitize_for_context(text, allowed_url_domains=allowed_url_domains).removed["url"]:
        problems.append("a URL outside context.allowed_url_domains")
    allowed_lines = set(imports)
    rest = "\n".join(line for line in text.split("\n") if line not in allowed_lines)
    if has_mention(outside_code(rest)):
        problems.append("an @ mention that Claude Code could read as a file import")
    return problems
