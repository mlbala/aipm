# Property tests

Hypothesis tests for invariants that must hold for every input (ARCHITECTURE §20, SECURITY.md §14.4): no path escapes the repo, `compile_gate` never emits a denied argv, `sanitize_text` is idempotent, and the redactor never outputs a registered fake secret. The first ones arrive with build prompt 02.
