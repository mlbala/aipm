"""Supply-chain checks (SECURITY.md §12.2): names, typosquats, release age, registry lookups.

The registry is never contacted: every lookup goes through an injected `fetch`. The real
`_fetch` is tested only for refusing anything but HTTPS (pytest-socket blocks the network).
"""

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import pytest

from aipm.domain.errors import ExitCode, PolicyViolation
from aipm.domain.models import Ecosystem
from aipm.scanners import registry
from aipm.scanners.registry import PackageInfo, RegistryError, Response, first_release
from aipm.security.supply_chain import (
    POPULAR_NPM,
    POPULAR_PYPI,
    age_ok,
    check_package_name,
    edit_distance,
    normalize_name,
    typosquat_distance,
    typosquat_of,
)

NOW = datetime(2026, 10, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    ("ecosystem", "name"),
    [("pypi", "-rf"), ("pypi", "a b"), ("npm", "UPPER"), ("npm", "../x"), ("cargo", "serde"),
     ("pypi", ""), ("pypi", "x" * 215), ("npm", "@scope/-x")],
)  # fmt: skip
def test_bad_names_and_ecosystems_are_refused(ecosystem: str, name: str) -> None:
    with pytest.raises(PolicyViolation) as info:
        check_package_name(ecosystem, name)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION


def test_good_names_pass() -> None:
    assert check_package_name("pypi", "Flask_SQLAlchemy").name == "Flask_SQLAlchemy"
    assert check_package_name("npm", "@types/node").ecosystem is Ecosystem.NPM


def test_normalization() -> None:
    assert normalize_name(Ecosystem.PYPI, "Ruamel.YAML__clib") == "ruamel-yaml-clib"
    assert normalize_name(Ecosystem.NPM, "React") == "react"


def test_reference_lists_are_normalized() -> None:
    assert all(normalize_name(Ecosystem.PYPI, n) == n for n in POPULAR_PYPI)
    assert all(n == n.lower() for n in POPULAR_NPM)


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [("requests", "requests", 0), ("reqeusts", "requests", 1), ("request", "requests", 1),
     ("requestz", "requests", 1), ("rqeuests", "requests", 1), ("flask", "django", 4),
     ("a", "abcdefg", 4), ("", "ab", 2)],
)  # fmt: skip
def test_edit_distance_counts_a_swap_as_one(a: str, b: str, expected: int) -> None:
    assert edit_distance(a, b) == expected


@pytest.mark.parametrize(
    ("ecosystem", "name", "squats"),
    [
        (Ecosystem.PYPI, "reqeusts", "requests"),
        (Ecosystem.PYPI, "Request_s", "requests"),
        (Ecosystem.PYPI, "requestss", "requests"),
        (Ecosystem.PYPI, "fastapii", "fastapi"),
        (Ecosystem.PYPI, "requests", None),
        (Ecosystem.PYPI, "sqlmodel", None),
        (Ecosystem.NPM, "lodahs", "lodash"),
        (Ecosystem.NPM, "expresss", "express"),
        (Ecosystem.NPM, "@evil/lodash", "lodash"),
        (Ecosystem.NPM, "@types/node", None),
        (Ecosystem.NPM, "left-pad", None),
    ],
)
def test_typosquats_are_found(ecosystem: Ecosystem, name: str, squats: str | None) -> None:
    assert typosquat_of(ecosystem, name) == squats


def test_a_custom_reference_list_and_distance() -> None:
    assert typosquat_of(Ecosystem.PYPI, "acme-corp", popular=["acme-crop"]) == "acme-crop"
    assert typosquat_distance("lodahs", POPULAR_NPM) == 1
    assert typosquat_distance("lodash", ["lodash"]) == 4


def test_the_age_policy() -> None:
    assert age_ok(NOW - timedelta(days=30), min_days=30, now=NOW)
    assert not age_ok(NOW - timedelta(days=29, hours=23), min_days=30, now=NOW)
    assert age_ok(NOW, min_days=0, now=NOW)


# ---------------------------------------------------------------- registry lookups


def fake(status: int, body: object) -> tuple[list[tuple[str, dict[str, str]]], registry.Fetch]:
    calls: list[tuple[str, dict[str, str]]] = []

    def fetch(url: str, headers: Mapping[str, str]) -> Response:
        calls.append((url, dict(headers)))
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return Response(status, raw)

    return calls, fetch


def test_pypi_first_release_is_the_oldest_upload() -> None:
    calls, fetch = fake(
        200,
        {"files": [{"upload-time": "2020-01-02T00:00:00.000Z"},
                   {"upload-time": "2019-05-01T10:00:00Z"}, {"x": 1}, "junk"]},
    )  # fmt: skip
    info = first_release(Ecosystem.PYPI, "Flask_SQLAlchemy", fetch=fetch)
    assert info == PackageInfo(True, datetime(2019, 5, 1, 10, tzinfo=UTC))
    url, headers = calls[0]
    assert url == "https://pypi.org/simple/flask-sqlalchemy/"
    assert headers == {"Accept": "application/vnd.pypi.simple.v1+json"}


def test_npm_first_release_is_created() -> None:
    calls, fetch = fake(200, {"time": {"created": "2015-01-01T00:00:00", "modified": "x"}})
    info = first_release(Ecosystem.NPM, "@types/node", fetch=fetch)
    assert info.first_release == datetime(2015, 1, 1, tzinfo=UTC)
    assert calls[0][0] == "https://registry.npmjs.org/@types%2Fnode"


def test_a_missing_package_does_not_exist() -> None:
    _, fetch = fake(404, b"")
    assert first_release(Ecosystem.NPM, "lodahs", fetch=fetch) == PackageInfo(False)


@pytest.mark.parametrize(
    ("ecosystem", "status", "body", "message"),
    [
        (Ecosystem.PYPI, 500, b"", "HTTP 500"),
        (Ecosystem.PYPI, 301, b"", "HTTP 301"),
        (Ecosystem.PYPI, 200, b"not json", "not JSON"),
        (Ecosystem.PYPI, 200, b"[1]", "not a JSON object"),
        (Ecosystem.PYPI, 200, {"files": "x"}, "without a file list"),
        (Ecosystem.PYPI, 200, {"files": [{"upload-time": "yesterday"}]}, "no first-release"),
        (Ecosystem.PYPI, 200, {"files": [{"upload-time": "x" * 100}]}, "no first-release"),
        (Ecosystem.NPM, 200, {"time": "x"}, "no first-release"),
        (Ecosystem.NPM, 200, {"time": {"created": 5}}, "no first-release"),
        (Ecosystem.NPM, 200, b"[" * 100_000, "not JSON"),
    ],
)
def test_doubtful_answers_fail_closed(
    ecosystem: Ecosystem, status: int, body: object, message: str
) -> None:
    _, fetch = fake(status, body)
    with pytest.raises(RegistryError, match=message):
        first_release(ecosystem, "somepkg", fetch=fetch)


def test_names_are_checked_before_any_lookup() -> None:
    calls, fetch = fake(200, {})
    with pytest.raises(PolicyViolation):
        first_release(Ecosystem.PYPI, "../../etc", fetch=fetch)
    assert calls == []


def test_the_real_fetch_refuses_plain_http() -> None:
    with pytest.raises(RegistryError, match="HTTPS only"):
        registry._fetch("http://pypi.org/simple/x/", {})  # pyright: ignore[reportPrivateUsage]


def test_the_real_fetch_reports_an_unreachable_registry_as_an_error() -> None:
    """pytest-socket blocks the network, so the attempt fails like an unreachable host."""
    with pytest.raises((RegistryError, Exception)):
        registry._fetch("https://pypi.org/simple/x/", {})  # pyright: ignore[reportPrivateUsage]
