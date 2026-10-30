"""Secret redaction (SECURITY.md §8).

The redactor takes an environment snapshot instead of reading `os.environ`, which keeps this
module pure. The gateway, `StateStore` and logging build it from the full environment through
`aipm.observability.redaction.process_redactor`.

`redact` replaces secrets with `«REDACTED:<kind>»`. `contains_secret` is the pre-write scan: it
also looks for base64 and percent-encoded forms of the environment secrets, which `redact`
leaves alone, so a write that still carries one is aborted (exit 6) instead of written.
"""

import base64
import logging
import re
from collections.abc import Iterable, Mapping

from aipm.domain.errors import UsageError

MIN_SECRET_LENGTH = 8
MAX_EXTRA_PATTERNS = 20
MAX_PATTERN_LENGTH = 200

_SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL", re.IGNORECASE)
_PLAIN_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_EDGE = r"(?<![A-Za-z0-9_\-])"
_PEM_HEADER = r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"

# Well-known token formats, most specific first (`sk-ant-` before `sk-`).
_TOKENS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "pem_private_key",
        re.compile(_PEM_HEADER + r"(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY-----|.*)", re.DOTALL),
    ),
    ("anthropic_key", re.compile(_EDGE + r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("openai_key", re.compile(_EDGE + r"sk-[A-Za-z0-9_\-]{16,}")),
    ("github_token", re.compile(_EDGE + r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("github_pat", re.compile(_EDGE + r"github_pat_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(_EDGE + r"xox[abpr]-[A-Za-z0-9\-]{10,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(_EDGE + r"AIza[0-9A-Za-z_\-]{35}")),
    (
        "jwt",
        re.compile(_EDGE + r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    ),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}=*")),
)
_GENERIC = re.compile(
    r"(?i)(?P<lead>(?:api[_-]?key|secret|token|passw(?:or)?d)\s*[:=]\s*['\"]?)"
    r"(?!«REDACTED)(?P<value>[^\s'\"]{8,})"
)
_LONE_PEM_HEADER = re.compile(_PEM_HEADER)


def _marker(kind: str) -> str:
    return f"«REDACTED:{kind}»"


def _percent_encode(value: str) -> str:
    safe = "-._~"
    return "".join(
        ch if (ch.isascii() and ch.isalnum()) or ch in safe else f"%{ord(ch):02X}" for ch in value
    )


def _encodings(value: str) -> set[str]:
    raw = value.encode("utf-8", errors="surrogatepass")
    forms = {
        base64.b64encode(raw).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        _percent_encode(value),
    }
    forms.discard(value)
    return forms


def _compile_extra(patterns: Iterable[str]) -> tuple[re.Pattern[str], ...]:
    items = list(patterns)
    if len(items) > MAX_EXTRA_PATTERNS:
        raise UsageError(f"security.extra_redact_patterns: at most {MAX_EXTRA_PATTERNS} patterns")
    compiled: list[re.Pattern[str]] = []
    for pattern in items:
        if len(pattern) > MAX_PATTERN_LENGTH:
            raise UsageError(
                f"security.extra_redact_patterns: a pattern is longer than {MAX_PATTERN_LENGTH}"
            )
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise UsageError(
                f"security.extra_redact_patterns: {pattern!r} is not a valid regular expression"
                f" ({exc})"
            ) from None
        if regex.fullmatch(""):
            raise UsageError(
                f"security.extra_redact_patterns: {pattern!r} matches the empty string"
            )
        compiled.append(regex)
    return tuple(compiled)


class Redactor:
    """Replace secret values and known token formats with «REDACTED:<kind>»."""

    def __init__(self, env: Mapping[str, str], *, extra_patterns: Iterable[str] = ()) -> None:
        self.env_names = frozenset(env)
        secrets: dict[str, str] = {}
        for name, value in env.items():
            if not _SECRET_NAME.search(name):
                continue
            # A value from a CRLF `.env` ends in "\r", which logging strips before its second
            # pass, so the trimmed form must match too (red-team v0.1 review).
            for form in (value, value.strip()):
                if len(form) >= MIN_SECRET_LENGTH:
                    secrets.setdefault(form, name)
        self._secrets = secrets
        ordered = sorted(secrets, key=len, reverse=True)
        self._env_regex = re.compile("|".join(map(re.escape, ordered))) if ordered else None
        self._encoded = tuple({form for value in ordered for form in _encodings(value)})
        self._extra = _compile_extra(extra_patterns)

    def _env_kind(self, value: str) -> str:
        name = self._secrets[value]
        return f"env:{name}" if _PLAIN_NAME.fullmatch(name) else "env"

    def redact(self, text: str) -> str:
        """Return `text` with every secret replaced."""
        if self._env_regex is not None:
            text = self._env_regex.sub(lambda m: _marker(self._env_kind(m.group(0))), text)
        for kind, regex in _TOKENS:
            text = regex.sub(_marker(kind), text)
        text = _GENERIC.sub(lambda m: m.group("lead") + _marker("generic"), text)
        for regex in self._extra:
            text = regex.sub(_marker("custom"), text)
        return text

    def contains_secret(self, text: str) -> bool:
        """Return whether `text` still matches a high-confidence secret pattern."""
        if any(value in text for value in self._secrets):
            return True
        if any(form in text for form in self._encoded):
            return True
        if _LONE_PEM_HEADER.search(text):
            return True
        return any(regex.search(text) for _, regex in _TOKENS)

    def logging_filter(self) -> logging.Filter:
        """A filter that redacts every record: message, arguments, traceback and stack."""
        return _RedactingFilter(self)


class _RedactingFilter(logging.Filter):
    def __init__(self, redactor: Redactor) -> None:
        super().__init__()
        self._redactor = redactor

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        record.msg = self._redactor.redact(message)
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = self._redactor.redact(record.exc_text)
        if record.stack_info:
            record.stack_info = self._redactor.redact(record.stack_info)
        return True
