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
TRACES_ENDPOINT_ENV = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
_NO_HOST = "(no host)"
_ENDPOINT = re.compile(
    r"(?P<scheme>https?)://(?:[^@/?#\[\]]*@)?"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}[A-Za-z0-9])?)"
    r"(?::(?P<port>[0-9]{1,5}))?(?:[/?#][!-~]*)?"
)
"""The only endpoint form aipm sends spans to: plain ASCII, no spaces, backslashes or second `@`,
so the host aipm prints is the host `requests` connects to whatever parser reads it (urllib3
ends the host at a backslash, Python's `urlsplit` does not; security review of N-5)."""
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
    def start_as_current_span(
        self,
        name: str,
        *,
        attributes: Any = None,
        record_exception: bool = True,
        set_status_on_exception: bool = True,
    ) -> Any: ...


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


def traces_endpoint(environ: Mapping[str, str]) -> str:
    """The URL spans are sent to, by the OTLP/HTTP rules: the traces endpoint when set, else the
    base endpoint plus `/v1/traces`. aipm hands this URL to the exporter itself, so the host it
    prints is the host that receives the spans (N-5)."""
    traces = environ.get(TRACES_ENDPOINT_ENV)
    if traces:
        return traces
    return f"{environ.get(ENDPOINT_ENV, '').removesuffix('/')}/v1/traces"


def endpoint_host(url: str) -> str:
    """`host[:port]` of `url`, never a user name or password; `(no host)` when `url` is not of
    the one unambiguous form aipm sends to (`_ENDPOINT`)."""
    printable = url.isascii() and all("!" <= ch <= "~" for ch in url)
    match = _ENDPOINT.fullmatch(url) if printable and "\\" not in url else None
    if match is None:
        return _NO_HOST
    port = match["port"]
    if port is not None and not 0 < int(port) < 65536:
        return _NO_HOST
    host = match["host"].lower()
    return host if port is None else f"{host}:{port}"


def _proxies(environ: Mapping[str, str]) -> list[str]:
    """Every proxy variable set in the environment, as `host (NAME)`.

    `requests` takes any variable whose name ends in `_proxy`, in any letter case, and keys it by
    scheme or by `scheme://host` (`Http_Proxy`, `http://collector_proxy`), so every such name is
    named rather than guessing which one applies. `NO_PROXY` is not consulted: this may name a
    proxy the spans bypass, never miss one they take (re-review of N-5).
    """
    found: list[str] = []
    for name, value in sorted(environ.items()):
        folded = name.lower()
        if not value or not folded.endswith("_proxy") or folded == "no_proxy":
            continue
        shown = endpoint_host(value if "://" in value else f"http://{value}")
        found.append(f"{shown} ({name[:60]})")
    return found


def destination() -> str | None:
    """Where spans go, while tracing sends them to an OTLP endpoint: the host, and every proxy
    variable set in the environment; else `None`."""
    return _state.get("host")


def _endpoint_problem(env: Mapping[str, str]) -> str | None:
    """What the endpoint lacks for spans to be sent, or `None`."""
    if not (env.get(ENDPOINT_ENV) or env.get(TRACES_ENDPOINT_ENV)):
        return ENDPOINT_ENV
    if endpoint_host(traces_endpoint(env)) == _NO_HOST:
        return (
            "a plain http(s)://host[:port]/path endpoint (ASCII, no spaces, backslashes or "
            "second @)"
        )
    return None


def configure_tracing(
    *, enabled: bool, environ: Mapping[str, str] | None = None, exporter: object | None = None
) -> str | None:
    """Turn spans on when `enabled` (`--trace`) and the endpoint is set; returns a warning when
    `--trace` cannot take effect. `exporter` is a seam for tests (an in-memory exporter)."""
    _state.clear()
    if not enabled:
        return None
    env = os.environ if environ is None else environ
    problem = None if exporter is not None else _endpoint_problem(env)
    if problem is not None:
        return f"--trace needs {problem}; no spans are sent"
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
        endpoint = traces_endpoint(env)
        try:
            otlp = OTLPSpanExporter(endpoint=endpoint)
        except (RuntimeError, ValueError, OSError) as exc:  # e.g. an unknown credential provider
            return f"--trace cannot set up the exporter ({type(exc).__name__}); no spans are sent"
        provider.add_span_processor(BatchSpanProcessor(otlp))
        atexit.register(provider.shutdown)
        proxies = _proxies(env)
        host = endpoint_host(endpoint)
        _state["host"] = host if not proxies else f"{host}, through a proxy: {', '.join(proxies)}"
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
    # An exception's message, stack trace and chained causes are free text (task text, paths,
    # provider error bodies) that would skip the allowlist and the redactor, so the SDK never
    # records one: status and exit code are set only through `SpanHandle.set` (step 08 review).
    with tracer.start_as_current_span(
        name,
        attributes=clean_attributes(attrs),
        record_exception=False,
        set_status_on_exception=False,
    ) as current:
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
