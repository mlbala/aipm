"""Pure supply-chain checks: package names, typosquat distance, release-age policy.

The registry HTTP lookups live in `aipm.scanners.registry` (ARCHITECTURE §5.1).
"""

from collections.abc import Sequence


def check_package_name(ecosystem: str, name: str) -> None:
    """Validate the ecosystem and the name format, or raise `PolicyViolation`."""
    raise NotImplementedError("v0.2: build prompt 06")


def typosquat_distance(name: str, popular: Sequence[str]) -> int:
    """Return the smallest edit distance from `name` to a popular package name."""
    raise NotImplementedError("v0.2: build prompt 06")
