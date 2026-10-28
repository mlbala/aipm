"""The openai-compatible provider: the official `openai` SDK with `base_url` (ARCHITECTURE §14).

Covers OpenAI, Azure OpenAI, OpenRouter, Ollama, vLLM and LM Studio. The SDK is imported
lazily. Never sends `temperature`, `top_p` or `top_k`.
"""


class OpenAICompatProvider:
    """Call a Chat Completions-compatible endpoint with structured output."""

    def complete(self, *, model: str, system: str, user: str, max_output_tokens: int) -> str:
        """Return the raw response text."""
        raise NotImplementedError("v0.1: build prompt 03")
