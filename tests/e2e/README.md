# End-to-end tests

The `examples/clinic-booking` flow with the fake LLM (ARCHITECTURE §20). `test_clinic_flow.py` runs `init` → `discover --answers` → `design` → `approve design` → `plan` → `approve plan` → `trust --confirm` → `status` (build prompt 04). `prompt` and `sync-context` join it with build prompt 05, then verify and build with stub agents.

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
