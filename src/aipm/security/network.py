"""Network profiles for agents, gates, the prepare step and scanners (SECURITY.md §9.1).

Pure: a profile becomes a list of allowed domains here, and `aipm.execution.sandbox` writes that
list into the sandbox settings. `none` allows nothing. `api-only:<domains>` is built in code for
a tool's API or a scanner's rule registry, never read from a repository. `open` needs an opt-in
in the user config file (`aipm.config.loader`), and `srt` cannot run it (ADR-0020).
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from aipm.domain.errors import PolicyViolation
from aipm.domain.models import Ecosystem, NetworkProfile

__all__ = [
    "REGISTRY_DOMAINS",
    "NetworkPolicy",
    "NetworkProfile",
    "allowed_domains",
    "parse_network",
]

REGISTRY_DOMAINS: dict[Ecosystem, tuple[str, ...]] = {
    Ecosystem.PYPI: ("pypi.org", "files.pythonhosted.org"),
    Ecosystem.NPM: ("registry.npmjs.org",),
}
MAX_DOMAINS = 32
_DOMAIN = re.compile(
    r"(?:\*\.)?[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+"
)


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """A network profile and the domains it allows."""

    profile: NetworkProfile
    domains: tuple[str, ...] = ()


def _check_domains(domains: Iterable[str]) -> tuple[str, ...]:
    checked = tuple(domains)
    if not checked or len(checked) > MAX_DOMAINS:
        raise PolicyViolation(f"an api-only profile names 1 to {MAX_DOMAINS} domains")
    for domain in checked:
        if not _DOMAIN.fullmatch(domain):
            raise PolicyViolation(f"not a plain domain name: {domain!r}")
    return checked


def allowed_domains(
    profile: NetworkProfile,
    *,
    ecosystems: Iterable[Ecosystem] = (),
    api_domains: Iterable[str] = (),
) -> tuple[str, ...]:
    """The domains a profile allows. `none` is empty, which `srt` reads as no network at all.

    `open` names no domain either: it is no list at all, and `aipm.execution.sandbox` refuses to
    write it into `srt` settings, where an empty list would mean the opposite.
    """
    if profile is NetworkProfile.NONE:
        return ()
    if profile is NetworkProfile.REGISTRIES:
        return tuple(d for eco in ecosystems for d in REGISTRY_DOMAINS[eco])
    if profile is NetworkProfile.API_ONLY:
        return _check_domains(api_domains)
    return ()


def parse_network(spec: str, *, ecosystems: Iterable[Ecosystem] = ()) -> NetworkPolicy:
    """Read `none`, `registries`, `api-only:<a.com,b.com>` or `open` into a policy.

    An unknown profile, or `api-only` without valid domains, raises `PolicyViolation` (exit 6).
    """
    name, separator, rest = spec.partition(":")
    try:
        profile = NetworkProfile(name)
    except ValueError:
        raise PolicyViolation(f"unknown network profile {name!r}") from None
    if separator and profile is not NetworkProfile.API_ONLY:
        raise PolicyViolation(f"the {name} network profile takes no domains")
    api = tuple(rest.split(",")) if profile is NetworkProfile.API_ONLY else ()
    domains = allowed_domains(profile, ecosystems=ecosystems, api_domains=api)
    return NetworkPolicy(profile=profile, domains=domains)
