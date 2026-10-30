# Fakes

Test doubles. Tests never use the network or a real LLM.

- `secrets.py`: fake secret values that the redaction tests check for (AGENTS.md rule 9). They avoid real token formats, and `.gitleaks.toml` allowlists this one file.
- `templates/`: small `.j2` files (including a dotted name, like the role templates) that `tests/security/test_untrusted.py` loads through `PackageTemplateLoader`, plus a `.txt` file the loader must refuse.
- `llm_fixtures/<fixture>/<role>.yaml`: canned responses for `aipm.llm.fake.FakeLLM`, consumed in order (`json:`, `raw:` for invalid output, `error:` for provider failures). The `fake_llm` fixture in `tests/conftest.py` routes the real gateway to one of them. Fixtures: `clinic` (the example idea, plus AC reviewer replies for T-002), `pending` (questions without answers), `interactive` (one question of each kind), `injection` (corpus C-001) and `invalid` (two invalid replies).
- `answers/clinic.yaml`: the `--answers` file for the clinic interview.
- `bin/`: stub binaries that imitate a tool's flags and output. `claude` (build prompt 05) answers `--version` like Claude Code. From build prompt 06: `srt` checks its settings file and runs the command unsandboxed (only the network test runs under the real one); `gitleaks`, `semgrep`, `osv-scanner` and `trivy` write a report in the tool's JSON format, with a finding for each staged file holding `FAKE-LEAK-FOR-TESTS` (gitleaks, trivy) or `eval(` (semgrep), or a lockfile naming `vulnerable-pkg` (osv). `codex`, `copilot` and `gemini` follow in prompts 07–08.
- `clinic/`: a hand-written implementation of clinic task T-002 for `aipm verify` (see its README).
- `project.py`: the clinic project as a `ProjectContext` (built with `build_context` from an approved snapshot and the python-uv config), plus helpers that put hostile text into every model-written field of the context or a task.
