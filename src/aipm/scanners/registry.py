"""Package-registry lookups for the deps gate: existence and first-release age.

The only network access in aipm besides the LLM gateway (ARCHITECTURE §5.1, AGENTS.md rule 10;
the import-linter contract names this module as the exception). It sends one HTTPS GET per new
dependency to a fixed host, follows no redirect, reads at most `MAX_RESPONSE_BYTES`, and treats
the reply as untrusted JSON. Anything unexpected raises `RegistryError`, which the deps gate
reports as an error: a lookup that fails never passes a package.

- PyPI: the JSON simple API (PEP 691) for the normalized name; the first release is the oldest
  file's `upload-time` (PEP 700).
- npm: the package document; the first release is `time.created`.
- Go: the module proxy's version list (`@v/list`, plain text), then the `.info` of the oldest
  tagged version for its time; a module with no tagged version is an error (v0.4).
- crates.io: the crate document; the first release is `crate.created_at`. crates.io refuses
  requests without a User-Agent, so a fixed one naming aipm (never the user) is sent (v0.4).
"""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from aipm.domain.models import Ecosystem
from aipm.security.supply_chain import check_package_name, normalize_name

TIMEOUT_S = 15.0
MAX_RESPONSE_BYTES = 32 * 1_048_576
PYPI_SIMPLE = "https://pypi.org/simple/{name}/"
NPM_DOC = "https://registry.npmjs.org/{name}"
GO_PROXY = "https://proxy.golang.org/{module}/@v/{what}"
CRATES_DOC = "https://crates.io/api/v1/crates/{name}"
USER_AGENT = "aipm-deps-gate (+https://github.com/mlbala/aipm)"
MAX_GO_VERSIONS = 10_000
_ACCEPT = {
    Ecosystem.PYPI: "application/vnd.pypi.simple.v1+json",
    Ecosystem.NPM: "application/json",
    Ecosystem.GO: "application/json",
    Ecosystem.CRATES: "application/json",
}
_GO_VERSION = re.compile(
    r"v(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:-([0-9A-Za-z.\-]{1,100}))?(?:\+[0-9A-Za-z.\-]{1,100})?"
)


class RegistryError(Exception):
    """The registry could not be asked, or answered something aipm cannot read."""


@dataclass(frozen=True, slots=True)
class PackageInfo:
    """Whether a package exists in its registry, and when its first release was published."""

    exists: bool
    first_release: datetime | None = None


@dataclass(frozen=True, slots=True)
class Response:
    """One HTTP response: the status and at most `MAX_RESPONSE_BYTES` of the body."""

    status: int
    body: bytes


type Fetch = Callable[[str, Mapping[str, str]], Response]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: object, **__: object) -> None:
        return None


def _fetch(url: str, headers: Mapping[str, str]) -> Response:
    """GET over HTTPS with no redirects; 404 is an answer, anything else but 200 an error."""
    if not url.startswith("https://"):
        raise RegistryError("registry lookups use HTTPS only")
    opener = urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(url, headers=dict(headers), method="GET")  # noqa: S310
    try:
        with opener.open(request, timeout=TIMEOUT_S) as reply:
            body = reply.read(MAX_RESPONSE_BYTES + 1)
            status = reply.status
    except urllib.error.HTTPError as exc:
        return Response(exc.code, b"")
    except Exception as exc:  # any failure to ask fails closed
        raise RegistryError(f"cannot reach the registry ({type(exc).__name__})") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise RegistryError("the registry's answer is larger than aipm reads")
    return Response(status, body)


def _url(ecosystem: Ecosystem, name: str) -> str:
    if ecosystem is Ecosystem.PYPI:
        return PYPI_SIMPLE.format(name=urllib.parse.quote(normalize_name(ecosystem, name), safe=""))
    if ecosystem is Ecosystem.CRATES:
        return CRATES_DOC.format(name=urllib.parse.quote(name, safe=""))
    return NPM_DOC.format(name=urllib.parse.quote(name, safe="@"))


def go_escape(module: str) -> str:
    """A module path as the proxy protocol spells it: each capital letter becomes `!` and its
    lower-case form (go.dev/ref/mod#goproxy-protocol), then percent-encoded but for `/`."""
    escaped = "".join(f"!{c.lower()}" if c.isupper() else c for c in module)
    return urllib.parse.quote(escaped, safe="/!")


def oldest_tag(listing: str) -> str | None:
    """The oldest tagged version in a proxy `@v/list` reply (a release sorts after its
    pre-releases); `None` when it lists none."""
    best: tuple[int, int, int, int, str] | None = None
    found: str | None = None
    for line in listing.splitlines()[:MAX_GO_VERSIONS]:
        match = _GO_VERSION.fullmatch(line.strip())
        if match is None:
            continue
        major, minor, patch, pre = match.groups()
        key = (int(major), int(minor), int(patch), 0 if pre else 1, pre or "")
        if best is None or key < best:
            best, found = key, line.strip()
    return found


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _pypi_first(doc: dict[str, Any]) -> datetime | None:
    files = doc.get("files")
    if not isinstance(files, list):
        raise RegistryError("PyPI answered without a file list")
    times = [
        _parse_time(cast("dict[str, Any]", item).get("upload-time"))
        for item in cast("list[object]", files)
        if isinstance(item, dict)
    ]
    found = [t for t in times if t is not None]
    return min(found) if found else None


def _npm_first(doc: dict[str, Any]) -> datetime | None:
    times = doc.get("time")
    if not isinstance(times, dict):
        return None
    return _parse_time(cast("dict[str, Any]", times).get("created"))


def _crates_first(doc: dict[str, Any]) -> datetime | None:
    crate = doc.get("crate")
    if not isinstance(crate, dict):
        return None
    return _parse_time(cast("dict[str, Any]", crate).get("created_at"))


def _json_object(response: Response) -> dict[str, Any]:
    try:
        doc = json.loads(response.body)
    except (ValueError, RecursionError):
        raise RegistryError("the registry's answer is not JSON") from None
    if not isinstance(doc, dict):
        raise RegistryError("the registry's answer is not a JSON object")
    return cast("dict[str, Any]", doc)


def _status(response: Response, *, gone: tuple[int, ...] = (404,)) -> bool:
    """True for 200, False for "no such package"; an error otherwise."""
    if response.status in gone:
        return False
    if response.status != 200:
        raise RegistryError(f"the registry answered HTTP {response.status}")
    return True


def _go_first(name: str, ask: Fetch) -> PackageInfo:
    module = go_escape(name)
    listing = ask(GO_PROXY.format(module=module, what="list"), {"Accept": "text/plain"})
    if not _status(listing, gone=(404, 410)):
        return PackageInfo(exists=False)
    tag = oldest_tag(listing.body.decode("utf-8", errors="replace"))
    if tag is None:
        raise RegistryError("the module has no tagged version, so its age is unknown")
    info = ask(GO_PROXY.format(module=module, what=f"{urllib.parse.quote(tag)}.info"),
               {"Accept": _ACCEPT[Ecosystem.GO]})  # fmt: skip
    if not _status(info, gone=(404, 410)):
        raise RegistryError(f"the proxy lists {tag} but has no information on it")
    first = _parse_time(_json_object(info).get("Time"))
    if first is None:
        raise RegistryError("the registry gave no first-release time")
    return PackageInfo(exists=True, first_release=first)


def first_release(ecosystem: Ecosystem, name: str, *, fetch: Fetch | None = None) -> PackageInfo:
    """Look a package up in its registry. Raises `RegistryError` on any doubt."""
    check_package_name(ecosystem.value, name)
    ask = fetch if fetch is not None else _fetch
    if ecosystem is Ecosystem.GO:
        return _go_first(name, ask)
    headers = {"Accept": _ACCEPT[ecosystem]}
    if ecosystem is Ecosystem.CRATES:
        headers["User-Agent"] = USER_AGENT
    response = ask(_url(ecosystem, name), headers)
    if not _status(response):
        return PackageInfo(exists=False)
    data = _json_object(response)
    readers = {Ecosystem.PYPI: _pypi_first, Ecosystem.NPM: _npm_first,
               Ecosystem.CRATES: _crates_first}  # fmt: skip
    first = readers[ecosystem](data)
    if first is None:
        raise RegistryError("the registry gave no first-release time")
    return PackageInfo(exists=True, first_release=first)
