"""The go and rust-cargo stacks' supply chain and test tracing (build prompt 08, ADR-0029):
registry lookups through the Go module proxy and crates.io, the registries a prepare step may
reach, typosquats, and `ac_trace` for Go packages."""

import json
from collections.abc import Mapping
from datetime import UTC, datetime

import pytest

from aipm.domain.errors import PolicyViolation
from aipm.domain.models import Ecosystem, NetworkProfile
from aipm.gates.builtin import ac_trace
from aipm.gates.command_gate import ecosystems_for
from aipm.gates.reports import CaseStatus, TestCase, TestReport
from aipm.scanners import registry
from aipm.scanners.registry import RegistryError, Response, go_escape, oldest_tag
from aipm.security.network import REGISTRY_DOMAINS, allowed_domains
from aipm.security.supply_chain import (
    POPULAR_CRATES,
    POPULAR_GO,
    normalize_name,
    typosquat_of,
)


def answers(
    replies: Mapping[str, Response],
) -> tuple[list[tuple[str, dict[str, str]]], registry.Fetch]:
    asked: list[tuple[str, dict[str, str]]] = []

    def fetch(url: str, headers: Mapping[str, str]) -> Response:
        asked.append((url, dict(headers)))
        return replies.get(url, Response(500, b""))

    return asked, fetch


PROXY = "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/"


def test_go_module_paths_are_escaped_for_the_proxy() -> None:
    assert go_escape("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"
    assert go_escape("example.com/a b") == "example.com/a%20b"


def test_the_oldest_tag_ignores_pseudo_versions_and_ranks_prereleases_first() -> None:
    listing = "v1.2.0\nv1.0.0\nv1.0.0-rc.1\nv0.0.0-20200101000000-abcdefabcdef\nnot-a-version\n"
    assert oldest_tag(listing) == "v0.0.0-20200101000000-abcdefabcdef"
    assert oldest_tag("v1.2.0\nv1.0.0\nv1.0.0-rc.1\n") == "v1.0.0-rc.1"
    assert oldest_tag("v2.0.0+incompatible\n") == "v2.0.0+incompatible"
    assert oldest_tag("\nmaster\n") is None


def test_a_go_module_first_release_is_its_oldest_tag() -> None:
    asked, fetch = answers({
        PROXY + "list": Response(200, b"v1.4.0\nv0.3.0\n"),
        PROXY + "v0.3.0.info": Response(200, json.dumps(
            {"Version": "v0.3.0", "Time": "2013-03-20T17:03:02Z"}).encode()),
    })  # fmt: skip
    info = registry.first_release(Ecosystem.GO, "github.com/BurntSushi/toml", fetch=fetch)
    assert info.exists and info.first_release == datetime(2013, 3, 20, 17, 3, 2, tzinfo=UTC)
    assert [url for url, _ in asked] == [PROXY + "list", PROXY + "v0.3.0.info"]


@pytest.mark.parametrize("status", [404, 410])
def test_a_go_module_the_proxy_does_not_know_does_not_exist(status: int) -> None:
    _, fetch = answers({PROXY + "list": Response(status, b"")})
    assert not registry.first_release(
        Ecosystem.GO, "github.com/BurntSushi/toml", fetch=fetch
    ).exists


@pytest.mark.parametrize(
    ("replies", "message"),
    [
        ({PROXY + "list": Response(200, b"")}, "no tagged version"),
        ({PROXY + "list": Response(503, b"")}, "HTTP 503"),
        ({PROXY + "list": Response(200, b"v1.0.0\n"),
          PROXY + "v1.0.0.info": Response(404, b"")}, "no information"),
        ({PROXY + "list": Response(200, b"v1.0.0\n"),
          PROXY + "v1.0.0.info": Response(200, b'{"Time": "soon"}')}, "no first-release time"),
        ({PROXY + "list": Response(200, b"v1.0.0\n"),
          PROXY + "v1.0.0.info": Response(200, b"[]")}, "not a JSON object"),
    ],
)  # fmt: skip
def test_doubtful_go_answers_fail_closed(replies: Mapping[str, Response], message: str) -> None:
    _, fetch = answers(replies)
    with pytest.raises(RegistryError, match=message):
        registry.first_release(Ecosystem.GO, "github.com/BurntSushi/toml", fetch=fetch)


CRATE = "https://crates.io/api/v1/crates/serde_json"


def test_a_crate_first_release_is_created_at_and_aipm_names_itself() -> None:
    body = json.dumps({"crate": {"created_at": "2015-08-04T02:03:04.000000+00:00"}}).encode()
    asked, fetch = answers({CRATE: Response(200, body)})
    info = registry.first_release(Ecosystem.CRATES, "serde_json", fetch=fetch)
    assert info.first_release == datetime(2015, 8, 4, 2, 3, 4, tzinfo=UTC)
    ((_, headers),) = asked
    assert headers["User-Agent"] == registry.USER_AGENT
    assert "@" not in headers["User-Agent"]  # names aipm, never the user


def test_crate_answers_fail_closed() -> None:
    _, fetch = answers({CRATE: Response(200, b'{"crate": "x"}')})
    with pytest.raises(RegistryError):
        registry.first_release(Ecosystem.CRATES, "serde_json", fetch=fetch)
    _, missing = answers({CRATE: Response(404, b"")})
    assert not registry.first_release(Ecosystem.CRATES, "serde_json", fetch=missing).exists


@pytest.mark.parametrize(
    ("ecosystem", "name"), [(Ecosystem.GO, "../../etc"), (Ecosystem.CRATES, "-rf")]
)
def test_names_are_checked_before_any_lookup(ecosystem: Ecosystem, name: str) -> None:
    asked, fetch = answers({})
    with pytest.raises(PolicyViolation):
        registry.first_release(ecosystem, name, fetch=fetch)
    assert asked == []


def test_typosquats_and_normalization() -> None:
    assert normalize_name(Ecosystem.CRATES, "Serde_JSON") == "serde-json"
    assert (
        normalize_name(Ecosystem.GO, "github.com/BurntSushi/toml") == "github.com/burntsushi/toml"
    )
    assert typosquat_of(Ecosystem.CRATES, "serde_jsom") == "serde-json"
    assert typosquat_of(Ecosystem.CRATES, "serde_json") is None
    assert typosquat_of(Ecosystem.GO, "github.com/stretchr/testfy") == "github.com/stretchr/testify"
    assert all(normalize_name(Ecosystem.CRATES, n) == n for n in POPULAR_CRATES)
    assert all(n == n.lower() for n in POPULAR_GO)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (("/usr/bin/go", "mod", "download"), (Ecosystem.GO,)),
        (("cargo", "fetch"), (Ecosystem.CRATES,)),
        (("uv", "sync"), (Ecosystem.PYPI,)),
        (("pnpm", "install"), (Ecosystem.NPM,)),
        (("make",), (Ecosystem.PYPI, Ecosystem.NPM)),
    ],
)
def test_a_prepare_step_reaches_only_its_own_registries(
    argv: tuple[str, ...], expected: tuple[Ecosystem, ...]
) -> None:
    assert ecosystems_for(argv) == expected
    domains = allowed_domains(NetworkProfile.REGISTRIES, ecosystems=expected)
    assert set(domains) == {d for e in expected for d in REGISTRY_DOMAINS[e]}


def test_a_python_prepare_never_reaches_the_go_storage_host() -> None:
    domains = allowed_domains(NetworkProfile.REGISTRIES, ecosystems=ecosystems_for(("uv",)))
    assert "storage.googleapis.com" not in domains


def report(*locations: str, status: CaseStatus = CaseStatus.PASSED) -> TestReport:
    return TestReport(tuple(TestCase(loc, "TestX", status) for loc in locations))


GO_TEST = 'package booking\n\nimport "testing"\n\nfunc TestSlots(t *testing.T) {}\n'


def test_a_go_test_file_ran_when_one_of_its_own_tests_ran() -> None:
    module = "example.com/clinic"
    ran = TestReport((
        TestCase("example.com/clinic/internal/booking", "TestSlots/free", CaseStatus.PASSED),
        TestCase("example.com/clinic", "TestSlots", CaseStatus.PASSED),
    ))  # fmt: skip
    assert ac_trace.ran("internal/booking/slots_test.go", ran, go_module=module, text=GO_TEST)
    assert ac_trace.ran("main_test.go", ran, go_module=module, text=GO_TEST)
    assert not ac_trace.ran("internal/other/x_test.go", ran, go_module=module, text=GO_TEST)
    assert not ac_trace.ran("internal/booking/slots_test.go", ran, go_module=None, text=GO_TEST)


def test_another_test_of_the_same_package_does_not_count() -> None:
    """A file with only an AC comment and no test of its own does not trace (step 08 review)."""
    module = "example.com/clinic"
    ran = report("example.com/clinic/internal/booking")  # a case named TestX
    marker_only = "package booking\n\n// AC-T002-1\n"
    assert not ac_trace.ran("internal/booking/ac_test.go", ran, go_module=module,
                            text=marker_only)  # fmt: skip
    skipped = TestReport((TestCase("example.com/clinic/internal/booking", "TestSlots",
                                   CaseStatus.SKIPPED),))  # fmt: skip
    assert not ac_trace.ran("internal/booking/slots_test.go", skipped, go_module=module,
                            text=GO_TEST)  # fmt: skip


@pytest.mark.parametrize(
    ("text", "module"),
    [
        ("module example.com/clinic\n\ngo 1.24\n", "example.com/clinic"),
        ('module "example.com/q" // quoted\n', "example.com/q"),
        ("go 1.24\n", None),
        ("module two words\n", None),
    ],
)
def test_the_go_module_line(text: str, module: str | None) -> None:
    assert ac_trace.go_module(text) == module


# ---------------------------------------------------------------- step 08 security review


def test_every_go_proxy_request_forbids_fetching_from_the_origin() -> None:
    """Without the header the proxy fetches an uncached, agent-chosen module path from its own
    server: a channel out for whatever the path encodes."""
    asked, fetch = answers({
        PROXY + "list": Response(200, b"v0.3.0\n"),
        PROXY + "v0.3.0.info": Response(200, b'{"Time": "2013-03-20T17:03:02Z"}'),
    })  # fmt: skip
    registry.first_release(Ecosystem.GO, "github.com/BurntSushi/toml", fetch=fetch)
    assert len(asked) == 2
    assert all(headers.get("Disable-Module-Fetch") == "true" for _, headers in asked)


def test_gates_never_get_the_go_registries() -> None:
    from aipm.execution.sandbox import ProcessKind  # noqa: PLC0415
    from aipm.gates.command_gate import _network  # pyright: ignore[reportPrivateUsage]  # noqa: PLC0415

    argv = ("go", "test")
    gate = _network(NetworkProfile.REGISTRIES, argv, ProcessKind.GATE)
    prepare = _network(NetworkProfile.REGISTRIES, ("go", "mod", "download"), ProcessKind.PREPARE)
    assert "proxy.golang.org" not in gate.domains and "storage.googleapis.com" not in gate.domains
    assert "proxy.golang.org" in prepare.domains


def test_agents_may_not_read_a_dotenv_in_home() -> None:
    from aipm.execution.sandbox import CREDENTIAL_PATHS  # noqa: PLC0415

    assert ".env" in CREDENTIAL_PATHS
