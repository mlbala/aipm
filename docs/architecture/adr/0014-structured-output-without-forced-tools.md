# ADR-0014: Structured output without forced tool calls

- **Status:** Accepted
- **Date:** 2026-10-29
- **Source:** build prompt 03 (LLM gateway)

## Context

ARCHITECTURE §14 orders the gateway's structured-output mechanisms as native JSON-schema output, then forced tool-call output, then JSON with validation. Checked on 2026-10-29 for build prompt 03:

- **Anthropic.** The Messages API takes `output_config: {format: {type: "json_schema", schema}}` on every current model (`anthropic` 2.3.0, API version `2026-10-21`). Claude Opus 5.5 and Claude Sonnet 5.5, two of the three models in aipm's default config, return 400 for a forced `tool_choice` (`any` or `tool`). The schema keywords the API does not support (string lengths, numeric bounds, most array limits) must be left out and checked by the client.
- **OpenAI-compatible.** Chat Completions takes `response_format: {type: "json_schema", json_schema: {name, schema, strict: true}}`; strict mode needs every property in `required` and `additionalProperties: false`, and does not support `minLength`/`maxLength`. Ollama documents `response_format` on its compatible endpoint; `json_object` is the older, wider-supported JSON mode.
- A forced tool call gives a tool-less role (ADR-0003) a tool, even if one with no side effects.

## Options

1. Keep the §14 order and use forced tool calls as the second mechanism.
2. Native schema output first, then the provider's plain JSON mode where it has one, then JSON requested in the prompt; no forced tool calls.

## Decision

Option 2. The gateway sends one provider-neutral wire schema built from the role's Pydantic model: every property required, `additionalProperties: false`, only the keywords both strict modes accept, and length, size and pattern limits written into the descriptions. The order is:

| Provider | 1st | 2nd | 3rd |
|---|---|---|---|
| `anthropic` | `output_config.format` json_schema | JSON requested in the system prompt | — |
| `openai-compatible` | `response_format` json_schema, `strict: true` | `response_format` json_object | JSON requested in the system prompt |

The gateway moves to the next mechanism only when the provider rejects the mechanism itself (a 400 or 422 that names the structured-output parameters), and remembers that for the rest of the process. Every mechanism ends in the same strict Pydantic validation (`extra="forbid"`, every limit, strict types) and the same single repair attempt, so a fallback never weakens validation.

## Consequences

- Roles stay tool-less in every request (SECURITY.md §7.3): no request carries `tools` or `tool_choice`.
- Current Claude models work with the default config; forced `tool_choice` would fail on two of them.
- The provider does not enforce lengths and sizes; Pydantic does, after parsing, which it had to do anyway.
- A provider with neither schema nor JSON mode still works through the prompt, at the cost of more repair attempts.
