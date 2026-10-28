# Security tests

The security regression suite (SECURITY.md §14). Every security-relevant change adds a test here (AGENTS.md).

- `corpus/`: hostile inputs, one YAML file per case; see its README.
- `fixtures/`: deliberately violating code, excluded from the normal lint and never imported.
- `test_banned_api.py`: ruff bans every way to start a process outside `execution/process.py`.
- `test_layers.py`: the import-linter contracts hold, and they catch violations.
- `test_no_hidden_characters.py`: no tracked text hides bidi, zero-width, tag or control characters.
- `test_corpus_format.py`: the corpus is well formed.
