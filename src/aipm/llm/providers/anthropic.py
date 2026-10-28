"""The Anthropic provider (ARCHITECTURE §14).

Uses the official `anthropic` SDK (>=2.0.0, which sends API version 2026-10-21), imported
lazily at call time. Never sends `temperature`, `top_p` or `top_k`.
"""


class AnthropicProvider:
    """Call the Messages API with structured output."""

    def complete(self, *, model: str, system: str, user: str, max_output_tokens: int) -> str:
        """Return the raw response text."""
        raise NotImplementedError("v0.1: build prompt 03")
