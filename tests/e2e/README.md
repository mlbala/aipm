# End-to-end tests

The `examples/clinic-booking` flow: `init` → `discover --answers` → `design` → `plan` → `trust` → `prompt` → `sync-context` with the fake LLM for v0.1, then verify and build with stub agents (ARCHITECTURE §20). They arrive with build prompt 05.

## Live smoke test

`test_live_smoke.py` makes one real interviewer call with the provider in your user config. It is skipped unless `AIPM_LIVE=1`, and never runs in CI:

```bash
AIPM_LIVE=1 uv run pytest tests/e2e/test_live_smoke.py -q
```

Against a local Ollama server (no key is needed on localhost):

```bash
ollama pull llama3.3
cat > /tmp/aipm-ollama.yaml <<'YAML'
llm:
  provider: openai-compatible
  base_url: http://localhost:11434/v1
  api_key_env: OLLAMA_API_KEY
  models: {default: llama3.3}
YAML
AIPM_CONFIG=/tmp/aipm-ollama.yaml AIPM_LIVE=1 uv run pytest tests/e2e/test_live_smoke.py -q
```
