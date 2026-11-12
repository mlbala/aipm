"""Optional OpenTelemetry spans with no prompt or output content (ARCHITECTURE §17, ADR-0027).

Off unless the user passes `--trace` and sets `OTEL_EXPORTER_OTLP_ENDPOINT`, with the `otel`
extra installed (`uv tool install 'aipm[otel] @ git+…'`). The OpenTelemetry packages are imported
only here, and only then, so a normal run imports none of them.

Spans: the CLI command (`aipm.command`), each role call through the LLM gateway (`aipm.llm`),
each agent dispatch (`aipm.dispatch`) and each gate (`aipm.gate`). Attributes pass an allowlist:
known keys only, and values that are numbers, booleans or short identifiers (no spaces), so no
prompt, model reply, file content, path or agent output can be attached, even by mistake.
"""

import atexit
import math
import os
import re
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from typing import Any, Protocol

from aipm import __version__

ENDPOINT_ENV = "OTEL_EXPORTER_OTLP_ENDPOINT"
SPAN_NAMES = frozenset({"aipm.command", "aipm.llm", "aipm.dispatch", "aipm.gate"})
ATTRIBUTES = frozenset(
    {
        "command", "role", "model", "task_id", "attempt", "tool", "gate", "status",
        "exit_code", "timed_out", "duration_ms", "input_tokens", "output_tokens", "cost_usd",
        "required", "cached", "saw_result", "is_error",
    }
)  # fmt: skip
"""The attribute keys a span may carry, each sent as `aipm.<key>`."""
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\-]{0,79}")


class _Span(Protocol):
    def set_attribute(self, key: str, value: Any) -> None: ...


class _Tracer(Protocol):
    def start_as_current_span(self, name: str, *, attributes: Any = None) -> Any: ...


_state: dict[str, Any] = {}


def clean_attributes(attrs: Mapping[str, object]) -> dict[str, bool | int | float | str]:
    """The allowed attributes, as `aipm.<key>`; anything else is dropped, never sent."""
    out: dict[str, bool | int | float | str] = {}
    for key, value in attrs.items():
        if key not in ATTRIBUTES or value is None:
            continue
        if isinstance(value, bool | int):
            out[f"aipm.{key}"] = value
        elif isinstance(value, float) and math.isfinite(value):
            out[f"aipm.{key}"] = value
        elif isinstance(value, str) and _IDENT.fullmatch(value):
            out[f"aipm.{key}"] = value
    return out


def configure_tracing(
    *, enabled: bool, environ: Mapping[str, str] | None = None, exporter: object | None = None
) -> str | None:
    """Turn spans on when `enabled` (`--trace`) and the endpoint is set; returns a warning when
    `--trace` cannot take effect. `exporter` is a seam for tests (an in-memory exporter)."""
    _state.clear()
    if not enabled:
        return None
    env = os.environ if environ is None else environ
    if exporter is None and not env.get(ENDPOINT_ENV):
        return f"--trace needs {ENDPOINT_ENV}; no spans are sent"
    try:
        from opentelemetry.sdk.resources import Resource  # noqa: PLC0415
        from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415
        from opentelemetry.sdk.trace.export import (  # noqa: PLC0415
            BatchSpanProcessor,
            SimpleSpanProcessor,
        )
    except ImportError:
        return "--trace needs the otel extra (aipm[otel]); no spans are sent"
    resource = Resource.create({"service.name": "aipm", "service.version": __version__})
    provider = TracerProvider(resource=resource)
    if exporter is None:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
                OTLPSpanExporter,
            )
        except ImportError:
            return "--trace needs the otel extra (aipm[otel]); no spans are sent"
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        atexit.register(provider.shutdown)
    else:
        provider.add_span_processor(SimpleSpanProcessor(exporter))  # type: ignore[arg-type]
    _state["provider"] = provider
    _state["tracer"] = provider.get_tracer("aipm", __version__)
    return None


def enabled() -> bool:
    """Whether spans are being recorded."""
    return "tracer" in _state


@contextmanager
def span(name: str, **attrs: object) -> Generator["SpanHandle"]:
    """A span named `name` (one of `SPAN_NAMES`), or nothing when tracing is off."""
    tracer: _Tracer | None = _state.get("tracer")
    if tracer is None or name not in SPAN_NAMES:
        yield SpanHandle(None)
        return
    with tracer.start_as_current_span(name, attributes=clean_attributes(attrs)) as current:
        yield SpanHandle(current)


class SpanHandle:
    """Adds allowed attributes to a running span; does nothing when tracing is off."""

    def __init__(self, current: _Span | None) -> None:
        self._span = current

    def set(self, **attrs: object) -> None:
        """Set more attributes, through the same allowlist."""
        if self._span is None:
            return
        for key, value in clean_attributes(attrs).items():
            self._span.set_attribute(key, value)


def shutdown() -> None:
    """Flush and stop the exporter (tests; the CLI relies on `atexit`)."""
    provider = _state.pop("provider", None)
    _state.clear()
    if provider is not None:
        provider.shutdown()
