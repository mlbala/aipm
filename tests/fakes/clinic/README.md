# Clinic verify fixture (build prompt 06)

A hand-written implementation of clinic task T-002 ("Slots and appointments without double
booking"), for `tests/integration/test_verify_cli.py`. Files end in `.txt` so this repository's
own ruff, pyright and pytest never read them; the tests copy them without the suffix.

- `base/`: the project before the task (committed before `aipm prompt T-002`): `pyproject.toml`
  with `pythonpath = ["src"]`, the `clinic` package, and a test T-002 does not own.
- `T-002/`: what a well-behaved agent writes: `src/clinic/booking/` and `tests/booking/`, with
  one test per acceptance criterion, each naming its AC ID.
