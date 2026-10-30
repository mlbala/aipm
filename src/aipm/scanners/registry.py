"""Package-registry lookups for the deps gate: existence and first-release age.

The only network access in aipm besides the LLM gateway (ARCHITECTURE §5.1, AGENTS.md rule 10;
the import-linter contract names this module as the exception). It sends one HTTPS GET per new
dependency to a fixed host, follows no redirect, reads at most `MAX_RESPONSE_BYTES`, and treats
the reply as untrusted JSON. Anything unexpected raises `RegistryError`, which the deps gate
reports as an error: a lookup that fails never passes a package.

- PyPI: the JSON simple API (PEP 691) for the normalized name; the first release is the oldest
  file's `upload-time` (PEP 700).
- npm: the package document; the first release is `time.created`.
"""

import json
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
_ACCEPT = {
    Ecosystem.PYPI: "application/vnd.pypi.simple.v1+json",
    Ecosystem.NPM: "application/json",
}


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
    return NPM_DOC.format(name=urllib.parse.quote(name, safe="@"))


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


def first_release(ecosystem: Ecosystem, name: str, *, fetch: Fetch | None = None) -> PackageInfo:
    """Look a package up in its registry. Raises `RegistryError` on any doubt."""
    check_package_name(ecosystem.value, name)
    ask = fetch if fetch is not None else _fetch
    response = ask(_url(ecosystem, name), {"Accept": _ACCEPT[ecosystem]})
    if response.status == 404:
        return PackageInfo(exists=False)
    if response.status != 200:
        raise RegistryError(f"the registry answered HTTP {response.status}")
    try:
        doc = json.loads(response.body)
    except (ValueError, RecursionError):
        raise RegistryError("the registry's answer is not JSON") from None
    if not isinstance(doc, dict):
        raise RegistryError("the registry's answer is not a JSON object")
    data = cast("dict[str, Any]", doc)
    first = _pypi_first(data) if ecosystem is Ecosystem.PYPI else _npm_first(data)
    if first is None:
        raise RegistryError("the registry gave no first-release time")
    return PackageInfo(exists=True, first_release=first)
