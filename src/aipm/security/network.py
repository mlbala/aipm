"""Network profiles for agents, gates and the prepare step (SECURITY.md §9)."""

from enum import StrEnum


class NetworkProfile(StrEnum):
    """The network profiles a sandboxed process can get."""

    NONE = "none"
    REGISTRIES = "registries"
    API_ONLY = "api-only"
    OPEN = "open"


def allowed_domains(profile: NetworkProfile) -> tuple[str, ...]:
    """Return the domains a profile allows."""
    raise NotImplementedError("v0.2: build prompt 06")
