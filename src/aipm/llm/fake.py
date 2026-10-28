"""FakeLLM: deterministic role outputs for tests; records every request (build prompt 03)."""

from pathlib import Path


class FakeLLM:
    """Return fixture responses keyed by (role, fixture) and record every request."""

    def __init__(self, fixtures_dir: Path) -> None:
        raise NotImplementedError("v0.1: build prompt 03")
