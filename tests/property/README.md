# Property tests

Hypothesis tests for invariants that must hold for every input (ARCHITECTURE §20, SECURITY.md §14.4): no path escapes the repo, `compile_gate` never emits a denied argv, `sanitize_text` is idempotent, and the redactor never outputs a registered fake secret. The first ones arrive with build prompt 02.

`test_redteam_v01_props.py` holds the fuzzing of the v0.1 red-team pass. Its properties take their example count from the active profile: `uv run pytest tests/property --hypothesis-profile=ci-long` runs each at least 2,000 times (the profile is registered in `tests/conftest.py`).
