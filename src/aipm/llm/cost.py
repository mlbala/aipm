"""Token accounting; USD only when `llm.pricing` defines the model (§14)."""

from collections.abc import Mapping


def usd_cost(
    model: str, *, input_tokens: int, output_tokens: int, pricing: Mapping[str, Mapping[str, float]]
) -> float | None:
    """Return the USD cost, or None when the model has no configured price."""
    raise NotImplementedError("v0.1: build prompt 03")
