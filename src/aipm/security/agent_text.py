"""Invariant I-3 as a run-time check, for text coding agents read (SECURITY.md §14.1).

Context files and task prompts must hold no URL outside `context.allowed_url_domains`, no HTML
comment, no invisible or control character, and, outside code, no `@` mention that Claude Code
could expand as a file import. Code spans and fenced blocks are skipped for the mention check,
because Claude Code reads no import there. Paths shown to agents must also be plain: only
ASCII letters, digits and `. _ / * ? + -`, so a glob or a protected path can never carry prose
or a mention. Pure and standard-library only (layer L0): the state store re-checks a prompt
after redaction with it.
"""

import re
from collections.abc import Iterable

from aipm.security.sanitize import has_mention, sanitize_for_context, sanitize_text

_FENCED = re.compile(r"^(`{3,})[^`\n]*\n.*?^\1[ \t]*$", re.MULTILINE | re.DOTALL)
_SPAN = re.compile(r"(?<!`)(`+)(?!`).*?(?<!`)\1(?!`)")
PLAIN_PATH = re.compile(r"[A-Za-z0-9._/*?+\-]{1,512}")


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


def is_plain_path(value: str) -> bool:
    """Whether a path or glob uses only the characters an agent may be shown."""
    return PLAIN_PATH.fullmatch(value) is not None
