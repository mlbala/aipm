"""Optional OpenTelemetry spans with no prompt or output content (v0.4, ARCHITECTURE §17)."""


def configure_tracing(*, enabled: bool) -> None:
    """Enable spans when `--trace` and OTEL_EXPORTER_OTLP_ENDPOINT are both set."""
    raise NotImplementedError("v0.4: build prompt 08")
