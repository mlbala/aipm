# ADR-0027: OpenTelemetry export is an opt-in third network path

- **Status:** Accepted
- **Date:** 2026-11-12
- **Source:** build prompt 08, step 6; ARCHITECTURE.md §5.1, §17; AGENTS.md security rule 10

## Context

ARCHITECTURE §17 adds optional OpenTelemetry spans in v0.4: "Disabled unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set and `--trace` is passed", with IDs, durations, token counts and statuses as attributes, never prompt or output content. Sending spans is a network call. AGENTS.md rule 10 says "No telemetry. No network calls except through the LLM gateway, and the registry lookups", and ARCHITECTURE §5.1 names the same two places.

The two rules aim at different things: rule 10 forbids aipm phoning home, and spans go only to an endpoint the user names, only when they ask.

## Options

1. Leave tracing out.
2. Allow OTLP export as a third network path, under conditions that keep rule 10's intent.

## Decision

Option 2, with these conditions:

- **Both switches.** Spans are recorded only with `--trace` and `OTEL_EXPORTER_OTLP_ENDPOINT` set, and the `otel` extra installed. A missing one prints a warning and sends nothing. There is no default endpoint.
- **One module.** `opentelemetry` is imported only in `aipm/observability/tracing.py`, lazily, after both switches are seen; a test enforces this.
- **No content.** Span names are fixed (`aipm.command`, `aipm.llm`, `aipm.dispatch`, `aipm.gate`). Attributes pass an allowlist of keys, and of values: numbers, booleans and identifiers of at most 80 characters with no spaces or slashes. A prompt, a model reply, a path or agent output cannot pass, even by a coding mistake.
- **Not in the trust surface.** The endpoint is the user's own; a repository's `.env` loaded by another tool could set the variable, but not `--trace`.

ARCHITECTURE §5.1 and AGENTS.md rule 10 are read with this exception: no network calls except the LLM gateway, the registry lookups, and OTLP export that the user turned on.

## Consequences

- `aipm[otel]` users get spans for every command, role call, dispatch and gate.
- Everyone else imports none of OpenTelemetry, and `aipm --help` stays fast.
