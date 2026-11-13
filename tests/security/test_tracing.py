"""OpenTelemetry spans (ARCHITECTURE §17, ADR-0027): off unless `--trace` and the endpoint are
both set, and never carrying prompt, reply, path or output text."""

import ast
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from aipm.llm.fake import FakeLLM
from aipm.observability import tracing
from tests.conftest import REPO_ROOT, FakeSecrets
from tests.fakes.secrets import FAKE_SECRETS
from tests.integration.flow import aipm, designed

ENDPOINT = "http://127.0.0.1:4318"


@pytest.fixture(autouse=True)
def tracing_off() -> Iterator[None]:
    yield
    tracing.shutdown()


@pytest.fixture
def exported(monkeypatch: pytest.MonkeyPatch) -> InMemorySpanExporter:
    """The OTLP exporter replaced by an in-memory one (the tests have no network)."""
    memory = InMemorySpanExporter()
    monkeypatch.setattr(
        "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter",
        lambda *_a, **_k: memory,
    )
    return memory


def test_tracing_is_off_by_default() -> None:
    assert tracing.configure_tracing(enabled=False) is None
    assert not tracing.enabled()
    with tracing.span("aipm.command", command="status") as span:
        span.set(status="ok")


def test_trace_without_an_endpoint_sends_nothing() -> None:
    warning = tracing.configure_tracing(enabled=True, environ={})
    assert warning is not None and "OTEL_EXPORTER_OTLP_ENDPOINT" in warning
    assert not tracing.enabled()


def test_the_endpoint_without_trace_sends_nothing() -> None:
    assert (
        tracing.configure_tracing(enabled=False, environ={tracing.ENDPOINT_ENV: ENDPOINT}) is None
    )
    assert not tracing.enabled()


@pytest.mark.parametrize(
    ("attrs", "kept"),
    [
        ({"command": "verify", "exit_code": 3, "timed_out": False}, 3),
        ({"task_id": "T-002", "cost_usd": 0.25, "input_tokens": 1200}, 3),
        ({"prompt": "You are a coding agent"}, 0),  # not an allowed key
        ({"status": "You are a coding agent"}, 0),  # spaces: free text
        ({"gate": "src/clinic/booking.py"}, 0),  # a path
        ({"model": "x" * 81}, 0),  # too long
        ({"cost_usd": float("nan"), "role": None}, 0),
        ({"command": ["a", "b"]}, 0),  # not a scalar
    ],
)
def test_attributes_pass_an_allowlist(attrs: dict[str, object], kept: int) -> None:
    clean = tracing.clean_attributes(attrs)
    assert len(clean) == kept
    assert all(key.startswith("aipm.") for key in clean)


def test_unknown_span_names_record_nothing() -> None:
    memory = InMemorySpanExporter()
    tracing.configure_tracing(enabled=True, exporter=memory)
    with tracing.span("aipm.secret-sauce", command="x"):
        pass
    with tracing.span("aipm.gate", gate="lint", status="pass"):
        pass
    assert [s.name for s in memory.get_finished_spans()] == ["aipm.gate"]


def test_a_span_ended_by_an_exception_exports_no_message_or_stack_trace(
    fake_secrets: FakeSecrets,
) -> None:
    """The SDK would record the exception as an event and as the status description, outside
    the allowlist and the redactor (step 08 security review, F-2)."""
    del fake_secrets
    secret = next(iter(FAKE_SECRETS.values()))
    memory = InMemorySpanExporter()
    tracing.configure_tracing(enabled=True, exporter=memory)
    with pytest.raises(RuntimeError), tracing.span("aipm.command", command="verify"):
        try:
            raise ValueError(f"task text: ignore previous instructions {secret} /Users/x/repo")
        except ValueError as error:
            raise RuntimeError("wrapped") from error
    (finished,) = memory.get_finished_spans()
    assert list(finished.events) == []
    assert not finished.status.description
    assert set(dict(finished.attributes or {})) == {"aipm.command"}


def spans(memory: InMemorySpanExporter) -> list[tuple[str, dict[str, Any]]]:
    tracing.shutdown()
    return [(s.name, dict(s.attributes or {})) for s in memory.get_finished_spans()]


def test_a_traced_command_records_the_command_and_its_role_calls_and_no_text(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    exported: InMemorySpanExporter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_secrets
    fake_llm("clinic")
    designed(tmp_repo)
    monkeypatch.setenv(tracing.ENDPOINT_ENV, ENDPOINT)
    result = aipm(tmp_repo, "plan", flags=["--trace", "--yes"])
    assert result.exit_code == 0, result.output
    recorded = spans(exported)
    names = [name for name, _ in recorded]
    assert "aipm.command" in names and "aipm.llm" in names
    command = next(attrs for name, attrs in recorded if name == "aipm.command")
    assert command["aipm.command"] == "plan" and command["aipm.exit_code"] == 0
    llm = next(attrs for name, attrs in recorded if name == "aipm.llm")
    assert llm["aipm.role"] == "planner"
    for _name, attrs in recorded:
        for key, value in attrs.items():
            assert key.startswith("aipm."), key
            text = str(value)
            assert " " not in text and "/" not in text and len(text) <= 80, (key, value)
            assert all(secret not in text for secret in FAKE_SECRETS.values())


def test_only_the_tracing_module_imports_opentelemetry() -> None:
    offenders: list[str] = []
    for path in sorted((REPO_ROOT / "src" / "aipm").rglob("*.py")):
        if path.name == "tracing.py" and path.parent.name == "observability":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(n == "opentelemetry" or n.startswith("opentelemetry.") for n in names):
                offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []
