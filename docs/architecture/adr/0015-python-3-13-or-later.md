# ADR-0015: Python 3.13 or later

- **Status:** Accepted
- **Date:** 2026-10-29
- **Source:** the owner's request after build prompt 04

## Context

ARCHITECTURE §4 required Python 3.12+, and CI tested 3.12 and 3.13. The owner asked for aipm to target Python 3.13 and later. aipm is installed with `uv tool install`, and uv downloads a managed Python when the machine has none of the right version, so a higher floor costs users nothing.

## Options

1. Keep 3.12 as the floor and add 3.14 to CI.
2. Require 3.13 or later, and test 3.13 and 3.14.

## Decision

Option 2. `requires-python = ">=3.13"`, `.python-version` is 3.13, ruff targets `py313`, pyright checks against 3.13, and CI runs `ubuntu-latest` and `macos-latest` with Python 3.13 and 3.14.

## Consequences

- Python 3.12 can no longer install aipm; `uv tool install` picks a managed 3.13 or later instead.
- Code may use 3.13 language and standard-library features; ruff's `py313` target applies the matching rewrites.
- Each new Python release is added to the CI matrix once its dependencies ship wheels for it.
