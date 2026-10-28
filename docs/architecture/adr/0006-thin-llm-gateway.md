# ADR-0006: A thin LLM gateway: `anthropic` plus `openai-compatible`

- **Status:** Accepted
- **Date:** 2026-10-28
- **Source:** ARCHITECTURE.md §23

## Context

aipm must work with hosted and local models while keeping its dependency surface small and its startup fast.

## Options

- LiteLLM as a core dependency.
- A thin gateway over the official `anthropic` and `openai` SDKs, with `base_url` for compatible servers.

## Decision

The gateway supports `anthropic` and `openai-compatible` (OpenAI, Azure, OpenRouter, Ollama, vLLM, LM Studio). SDKs are imported lazily. Other providers come through the `aipm.llm_providers` entry point; LiteLLM can be a plugin. The gateway never sends sampling parameters (review 01, §2).

## Consequences

- Fewer dependencies and a faster import.
- Local and hosted models are covered.
- Provider-specific features beyond structured output need gateway code.
