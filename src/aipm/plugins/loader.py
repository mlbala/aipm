"""Entry-point plugins from aipm's own environment only (ARCHITECTURE §18, v0.4)."""


def load_plugins(*, enabled: bool) -> list[str]:
    """Load plugins and return their names."""
    raise NotImplementedError("v0.4: build prompt 08")
