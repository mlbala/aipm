# Fakes

Test doubles. Tests never use the network or a real LLM.

- `secrets.py`: fake secret values that the redaction tests check for (AGENTS.md rule 9). They avoid real token formats, and `.gitleaks.toml` allowlists this one file.
- `templates/`: small `.j2` files (including a dotted name, like the role templates) that `tests/security/test_untrusted.py` loads through `PackageTemplateLoader`, plus a `.txt` file the loader must refuse.
- `llm_fixtures/<fixture>/<role>.yaml`: canned responses for `aipm.llm.fake.FakeLLM`, consumed in order (`json:`, `raw:` for invalid output, `error:` for provider failures). The `fake_llm` fixture in `tests/conftest.py` routes the real gateway to one of them. Fixtures: `clinic` (the example idea), `pending` (questions without answers), `interactive` (one question of each kind), `injection` (corpus C-001) and `invalid` (two invalid replies).
- `answers/clinic.yaml`: the `--answers` file for the clinic interview.
- `bin/` (build prompts 05–08): stub `claude`, `codex`, `copilot`, `gemini` and scanner binaries.
