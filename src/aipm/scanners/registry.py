"""Package-registry lookups for the deps gate: existence and first-release age.

The only network access in aipm besides the LLM gateway (ARCHITECTURE §5.1, AGENTS.md rule 10).
"""


def first_release_age_days(ecosystem: str, name: str) -> int | None:
    """Return the age of the first release, or None if the package does not exist."""
    raise NotImplementedError("v0.2: build prompt 06")
