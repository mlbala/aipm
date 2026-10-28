# Violating fixtures

Code that breaks a rule on purpose, so a test can prove the rule is enforced. These files are excluded from the normal `ruff` run (`extend-exclude` in `pyproject.toml`), are not packages, and are never imported.

- `banned_apis.py`: every banned way to start a process or import dynamically. `test_banned_api.py` lints it as if it lived under `src/aipm/`.
