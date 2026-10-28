# Fakes

Test doubles. Tests never use the network or a real LLM.

- `secrets.py`: fake secret values that the redaction tests check for (AGENTS.md rule 9). They avoid real token formats, and `.gitleaks.toml` allowlists this one file.
- `llm_fixtures/` (build prompt 03): canned responses for `aipm.llm.fake.FakeLLM`.
- `bin/` (build prompts 05–08): stub `claude`, `codex`, `copilot`, `gemini` and scanner binaries.
