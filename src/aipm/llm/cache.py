"""The LLM response cache under `.pm/cache/llm/` (v0.2; review 01, D-4)."""


def cache_key(
    *,
    provider: str,
    model: str,
    role: str,
    template_version: str,
    rendered_prompt: str,
    schema_json: str,
) -> str:
    """Return the cache key from ARCHITECTURE §14."""
    raise NotImplementedError("v0.2: build prompt 06")
