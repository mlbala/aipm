"""L1 input hygiene (SECURITY.md §7.1): Unicode clean-up, control and escape removal.

Standard library only, because `aipm.cli` imports this module to clean text before printing it
(ARCHITECTURE §5.1). The removal order is: terminal escape sequences, then single characters,
then NFC. NFKC is never used, because it changes code.
"""

import re
import unicodedata
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from aipm.domain.errors import InputRejected

INVISIBLE_CLASSES = ("tag", "zero_width", "bidi", "variation_selector", "format")
"""Removal classes that raise an `injection_signal` event when non-zero (§7.9)."""

URL_MARKER = "«URL removed»"

# Terminated OSC, DCS/SOS/PM/APC strings, CSI, and the remaining two-character escapes, in both
# 7-bit (ESC ...) and C1 forms. An unterminated string matches nothing here; its introducer is
# then removed as a control character and the rest stays visible as plain text.
_ESCAPE_SEQUENCE = re.compile(
    r"(?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)"
    r"|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f])[^\x1b\x9c]*(?:\x1b\\|\x9c)"
    r"|(?:\x1b\[|\x9b)[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"
    r"|\x1b[\x20-\x2f]*[\x30-\x7e]"
)

_ZERO_WIDTH = frozenset({*range(0x200B, 0x2010), *range(0x2060, 0x2065), 0xFEFF})
# Unicode default-ignorable code points that are not format characters: letters and marks that
# render as nothing (Hangul fillers, Khmer inherent vowels, Mongolian free variation selectors,
# the combining grapheme joiner), and unassigned code points reserved as default-ignorable
# (red-team v0.1, RT01-5). They are counted as zero-width.
_IGNORABLE_LETTERS = frozenset(
    {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180F, 0x3164, 0xFFA0}
)
_IGNORABLE = frozenset(
    {*_IGNORABLE_LETTERS, 0x2065, *range(0xFFF0, 0xFFF9), *range(0xE0080, 0xE0100),
     *range(0xE01F0, 0xE1000)}
)  # fmt: skip
_BIDI = frozenset({*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x061C})
_KEYCAP_BASES = frozenset("#*0123456789")

_HTML_COMMENT = re.compile(r"<!--(?:.*?-->|.*)", re.DOTALL)
_URL_STOP = r"[^\s<>\"'`()\[\]{}]"
# No word boundaries: "0https://…" and "xwww.…" are caught too. Over-matching is safe, because
# any scheme other than http(s) is always removed. Browsers and Markdown viewers read
# "https:host" without slashes as "https://host", so that form is always removed as well
# (red-team v0.1, RT01-3).
_URL = re.compile(
    rf"(?P<scheme>[a-z][a-z0-9+.\-]{{1,31}}):(?P<slashes>[/\\]+){_URL_STOP}*"
    rf"|(?:javascript|data|vbscript|file|mailto|https?):{_URL_STOP}*"
    rf"|www\.{_URL_STOP}*"
    rf"|(?<![\w:/\\])//[a-z0-9\-]+(?:\.[a-z0-9\-]+)+{_URL_STOP}*",
    re.IGNORECASE,
)
_HOST = re.compile(r"[a-z0-9.\-]+")
# A Claude Code `@path` import (in CLAUDE.md and AGENTS.md) or file mention (in a prompt): an `@`
# that does not follow a word character, an email-local character or a dot, directly followed by
# text. It becomes `@ ` so no tool reads a path after it; `name@example.com` stays as it is.
_MENTION = re.compile(r"(?<![\w.%+\-])@(?=\S)")
MENTION_SPACER = "@ "


@dataclass(frozen=True, slots=True)
class SanitizeResult:
    """Clean text, plus how many characters or sequences of each class were removed."""

    text: str
    removed: Counter[str] = field(default_factory=Counter[str])
    source: str = ""

    @property
    def invisible_removed(self) -> int:
        """The number of removed invisible characters (Tags, zero-width, bidi, selectors)."""
        return sum(self.removed[name] for name in INVISIBLE_CLASSES)


def is_ignorable(ch: str) -> bool:
    """Whether `ch` is a default-ignorable code point that is not a format character.

    Paths and argv refuse these as they refuse format characters: they render as nothing.
    """
    return ord(ch) in _IGNORABLE


def _is_emoji_base(ch: str) -> bool:
    cp = ord(ch)
    if ch in _KEYCAP_BASES or cp in (0xA9, 0xAE) or 0x1F000 <= cp <= 0x1FAFF:
        return True
    return 0x2000 <= cp <= 0x3299 and unicodedata.category(ch) in ("So", "Sm")


def _char_class(ch: str, previous: str | None) -> str | None:
    """Return the removal class of `ch`, or None to keep it."""
    cp = ord(ch)
    category = unicodedata.category(ch)
    kind: str | None
    if category == "Cc":
        kind = None if ch in "\n\t" else "control"
    elif 0xE0000 <= cp <= 0xE007F:
        kind = "tag"
    elif cp in _ZERO_WIDTH or cp in _IGNORABLE:
        kind = "zero_width"
    elif cp in _BIDI:
        kind = "bidi"
    elif 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        keep = cp in (0xFE0E, 0xFE0F) and previous is not None and _is_emoji_base(previous)
        kind = None if keep else "variation_selector"
    else:
        kind = {"Cf": "format", "Cs": "surrogate"}.get(category)
    return kind


def _strip_escapes(text: str, removed: Counter[str]) -> str:
    stripped, count = _ESCAPE_SEQUENCE.subn("", text)
    if count:
        removed["escape_sequence"] += count
    return stripped


def sanitize_text(s: str, *, source: str) -> SanitizeResult:
    """Normalize Unicode and remove invisible and control characters. Idempotent."""
    removed: Counter[str] = Counter()
    text = _strip_escapes(s, removed)
    kept: list[str] = []
    previous: str | None = None
    for ch in text:
        kind = _char_class(ch, previous)
        if kind is None:
            kept.append(ch)
            previous = ch
        else:
            removed[kind] += 1
    return SanitizeResult(unicodedata.normalize("NFC", "".join(kept)), removed, source)


def strip_terminal_escapes(s: str) -> str:
    """Remove ANSI CSI, OSC and other escape sequences and C0/C1 controls (I-6).

    Newlines and tabs stay. Use this on aipm's own text before it reaches a terminal; use
    `sanitize_text` for anything from an untrusted source.
    """
    text = _strip_escapes(s, Counter())
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cc" or ch in "\n\t")


def _host_allowed(host: str, allowed: Iterable[str]) -> bool:
    host = host.rsplit("@", 1)[-1].split(":", 1)[0].lower().rstrip(".")
    if not _HOST.fullmatch(host):
        return False
    return any(host == domain or host.endswith(f".{domain}") for domain in allowed)


def _url_allowed(match: re.Match[str], allowed: tuple[str, ...]) -> bool:
    url = match.group(0)
    scheme = match.group("scheme")
    if scheme is not None:
        if scheme.lower() not in ("http", "https"):
            return False
        rest = url[len(scheme) + 1 + len(match.group("slashes")) :]
    elif url.lower().startswith("www."):
        rest = url
    else:
        return False
    authority = re.split(r"[/\\?#]", rest, maxsplit=1)[0]
    return _host_allowed(authority, allowed)


def sanitize_for_context(s: str, *, allowed_url_domains: Iterable[str]) -> SanitizeResult:
    """Clean a field for a context file or task prompt: L1, HTML comments and non-allowlisted
    URLs removed, `@path` mentions neutralized.

    Only `http` and `https` URLs whose host is an allowlisted domain (or a subdomain of one)
    survive (SECURITY.md §7.10, invariant I-3). Every other URL becomes `«URL removed»`. An `@`
    that would start a Claude Code import or file mention (`@.env`, `@~/.ssh/id_rsa`) gets a
    space after it, counted as `mention`.
    """
    base = sanitize_text(s, source="context")
    removed = base.removed
    text = base.text
    while True:
        text, count = _HTML_COMMENT.subn("", text)
        if not count:
            break
        removed["html_comment"] += count
    allowed = tuple(d.strip().lower().rstrip(".") for d in allowed_url_domains if d.strip())

    def replace(match: re.Match[str]) -> str:
        if _url_allowed(match, allowed):
            return match.group(0)
        removed["url"] += 1
        return URL_MARKER

    text, mentions = _MENTION.subn(MENTION_SPACER, _URL.sub(replace, text))
    if mentions:
        removed["mention"] += mentions
    return SanitizeResult(text, removed, base.source)


def has_mention(s: str) -> bool:
    """Whether `s` holds an `@` that `sanitize_for_context` would neutralize."""
    return _MENTION.search(s) is not None


def _cut_bytes(data: bytes, limit: int, *, from_end: bool = False) -> str:
    part = data[-limit:] if from_end else data[:limit]
    return part.decode("utf-8", errors="ignore")


def cap_text(s: str, max_bytes: int) -> tuple[str, bool]:
    """Cap `s` at `max_bytes` of UTF-8, with a visible marker. Returns (text, truncated)."""
    data = s.encode("utf-8", errors="surrogatepass")
    if len(data) <= max_bytes:
        return s, False
    marker = f"\n«truncated: {len(data) - max_bytes} bytes removed»\n"
    return _cut_bytes(data, max_bytes) + marker, True


def head_tail(s: str, head: int = 4096, tail: int = 4096) -> str:
    """Keep the first `head` and last `tail` bytes, for gate output in prompts (§7.1)."""
    data = s.encode("utf-8", errors="surrogatepass")
    if len(data) <= head + tail:
        return s
    omitted = len(data) - head - tail
    middle = f"\n«{omitted} bytes omitted»\n"
    return _cut_bytes(data, head) + middle + _cut_bytes(data, tail, from_end=True)


def is_binary(data: bytes, *, sample: int = 8192) -> bool:
    """NUL/ratio heuristic: a NUL byte, or more than 30% control bytes in the sample."""
    chunk = data[:sample]
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    controls = sum(1 for b in chunk if b < 0x20 and b not in (0x09, 0x0A, 0x0C, 0x0D))
    return controls / len(chunk) > 0.30


def decode_untrusted(
    data: bytes, *, source: str, max_bytes: int, truncate: bool = False
) -> SanitizeResult:
    """Decode and sanitize T2 bytes, or raise `InputRejected` (exit 2).

    Input larger than `max_bytes` is rejected, or truncated with a visible marker when
    `truncate` is set. Binary content and invalid UTF-8 are always rejected.
    """
    marker = ""
    if len(data) > max_bytes:
        if not truncate:
            raise InputRejected(
                f"{source} is larger than {max_bytes} bytes",
                hint="Raise security.max_input_kib in your user config, or shorten the input.",
            )
        marker = f"\n«truncated: {len(data) - max_bytes} bytes removed»\n"
        data = data[:max_bytes]
    if is_binary(data):
        raise InputRejected(f"{source} looks binary, not text")
    try:
        text = data.decode("utf-8-sig", errors="ignore" if marker else "strict")
    except UnicodeDecodeError as exc:
        raise InputRejected(f"{source} is not valid UTF-8 (byte {exc.start})") from None
    return sanitize_text(text + marker, source=source)
