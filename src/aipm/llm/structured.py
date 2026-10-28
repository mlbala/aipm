"""Structured output: native JSON schema, forced tool output, or validated JSON (§14)."""

from pydantic import BaseModel


def parse_response[T: BaseModel](raw: str, schema: type[T]) -> T:
    """Validate a provider response into `schema`, or raise."""
    raise NotImplementedError("v0.1: build prompt 03")
