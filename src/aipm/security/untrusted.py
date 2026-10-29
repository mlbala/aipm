"""Typed untrusted content, its Jinja filter and the template environment (SECURITY.md §7.2).

`Untrusted` text reaches template output only through the `|untrusted` filter, which sanitizes
it, neutralizes `untrusted` tags inside it and wraps it in a block with a fresh random nonce. The
environment's `finalize` hook fails closed on a raw `Untrusted`, and `Untrusted` refuses every
conversion to `str`, so filters and string concatenation cannot leak it either.

Templates are loaded only from package files (`PackageTemplateLoader`); no template is ever
compiled from a string. Loading reads package resources and writes nothing.
"""

import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from types import ModuleType
from typing import Any, NoReturn, cast

from jinja2 import BaseLoader, Environment, StrictUndefined, TemplateNotFound
from jinja2.sandbox import ImmutableSandboxedEnvironment

from aipm.domain.errors import AipmError
from aipm.security.sanitize import sanitize_text

type NonceFactory = Callable[[], str]

_TAG = re.compile(r"<(?=\s*/?\s*untrusted)", re.IGNORECASE)
_NONCE = re.compile(r"u[0-9a-f]{8}")
# Components of letters, digits, `_` and `-`, with single dots inside a name
# (`interviewer.system.j2`), so `.` and `..` can never be a component.
_NAME_PART = r"[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*"
_TEMPLATE_NAME = re.compile(rf"(?:[A-Za-z0-9_\-]+/)*{_NAME_PART}\.j2")
_SOURCE_MAX = 200
_MAX_DEPTH = 8


class UntrustedRenderError(AipmError):
    """An `Untrusted` value was rendered without the `|untrusted` filter (a template bug)."""

    code = "UNTRUSTED_RENDER"


@dataclass(frozen=True, slots=True, repr=False)
class Untrusted:
    """Text from a T2 source, or any `.pm/` artifact rendered into a prompt.

    `source` is a label such as `idea.md`, `repo-file:src/app.py` or `approved:prd`. Read the
    text with `.text` in code; templates can only pass the value to `|untrusted`.
    """

    text: str
    source: str

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("Untrusted.text must be a str")
        if not isinstance(self.source, str) or not self.source:  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("Untrusted.source must be a non-empty str")

    def __str__(self) -> NoReturn:
        raise UntrustedRenderError(f"Untrusted text from {self.source!r} converted to str")

    def __format__(self, format_spec: str) -> NoReturn:
        raise UntrustedRenderError(f"Untrusted text from {self.source!r} formatted")

    def __repr__(self) -> str:
        return f"Untrusted(source={self.source!r}, chars={len(self.text)})"


def _new_nonce() -> str:
    return f"u{secrets.token_hex(4)}"


def _attribute(value: str) -> str:
    text = sanitize_text(value, source="label").text.replace("\n", " ").replace("\t", " ")
    text = text[:_SOURCE_MAX]
    for raw, escaped in (("&", "&amp;"), ('"', "&quot;"), ("<", "&lt;"), (">", "&gt;")):
        text = text.replace(raw, escaped)
    return text[:_SOURCE_MAX]


def untrusted_filter(value: object, *, nonce: NonceFactory = _new_nonce) -> str:
    """Sanitize, neutralize `untrusted` tags and wrap in a nonce-delimited block."""
    if not isinstance(value, Untrusted):
        raise UntrustedRenderError("the untrusted filter takes an Untrusted value")
    block_id = nonce()
    if not _NONCE.fullmatch(block_id):
        raise UntrustedRenderError("nonce must look like uXXXXXXXX")
    body = _TAG.sub("&lt;", sanitize_text(value.text, source=value.source).text)
    source = _attribute(value.source)
    return f'<untrusted source="{source}" id="{block_id}">\n{body}\n</untrusted id="{block_id}">'


def _check_no_untrusted(value: object, depth: int = 0) -> None:
    if isinstance(value, Untrusted):
        raise UntrustedRenderError(
            f"Untrusted text from {value.source!r} rendered without |untrusted"
        )
    if isinstance(value, (list, tuple, set, frozenset, Mapping)):
        if depth >= _MAX_DEPTH:
            raise UntrustedRenderError("value nested too deeply to check for Untrusted")
        items: list[object] = []
        if isinstance(value, Mapping):
            mapping: Mapping[object, object] = value  # pyright: ignore[reportUnknownVariableType]
            for key, item in mapping.items():
                items.extend((key, item))
        else:
            items.extend(value)  # pyright: ignore[reportUnknownArgumentType]
        for item in items:
            _check_no_untrusted(item, depth + 1)


def _finalize(value: object) -> object:
    _check_no_untrusted(value)
    return value


class _AipmSandbox(ImmutableSandboxedEnvironment):
    """The sandbox, with `Untrusted` attributes hidden and string templates refused."""

    def is_safe_attribute(self, obj: Any, attr: str, value: Any) -> bool:
        if isinstance(obj, Untrusted):
            return False
        return super().is_safe_attribute(obj, attr, value)

    def from_string(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise UntrustedRenderError("templates are loaded from package files only")


class PackageTemplateLoader(BaseLoader):
    """Load `.j2` templates from a package's own files, never from the repo or a string.

    It takes the package module itself, not its name, so loading never imports anything.
    """

    def __init__(self, package: ModuleType, subdir: str = "") -> None:
        if not isinstance(package, ModuleType) or not hasattr(package, "__path__"):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("PackageTemplateLoader needs an imported package module")
        root = files(package)
        for part in subdir.split("/") if subdir else ():
            root = root / part
        self._root: Traversable = root

    def get_source(
        self, environment: Environment, template: str
    ) -> tuple[str, str | None, Callable[[], bool] | None]:
        if not _TEMPLATE_NAME.fullmatch(template):
            raise TemplateNotFound(template)
        node = self._root
        for part in template.split("/"):
            node = node / part
        if not node.is_file():
            raise TemplateNotFound(template)
        return node.read_text(encoding="utf-8"), None, lambda: True


def make_env(loader: PackageTemplateLoader, *, nonce: NonceFactory = _new_nonce) -> Environment:
    """Return the only template environment aipm uses (SECURITY.md §7.2).

    Sandboxed and immutable, `StrictUndefined`, autoescape off (the output is Markdown), and a
    `finalize` hook that raises `UntrustedRenderError` for a raw `Untrusted` value.
    """
    if not isinstance(loader, PackageTemplateLoader):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("make_env needs a PackageTemplateLoader")
    env = _AipmSandbox(
        loader=loader,
        undefined=StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
        finalize=_finalize,
    )

    def untrusted(value: object) -> str:
        return untrusted_filter(value, nonce=nonce)

    filters = cast("dict[str, Callable[..., object]]", env.filters)  # pyright: ignore[reportUnknownMemberType]
    filters["untrusted"] = untrusted
    return env
