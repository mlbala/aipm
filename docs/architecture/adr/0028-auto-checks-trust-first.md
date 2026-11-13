# ADR-0028: `aipm auto` checks trust before its first step

- **Status:** Accepted
- **Date:** 2026-11-12
- **Source:** build prompt 08, step 4; ARCHITECTURE.md §7.3, §22; SECURITY.md §6 rules 3 and 4

## Context

ARCHITECTURE §7.3 describes `aipm auto` as a loop over the phase engine's `next_command`, and §22 asks that `aipm auto --yes` on the sample "stops correctly at the trust gate". The phase engine puts the trust gate after G3: `aipm plan` and `aipm approve plan` run before it. SECURITY.md §6 rule 3 lists `auto` among the commands that "MUST check trust first and exit 6 if the surface is untrusted", and rule 4 says `auto --yes` never grants trust. Read one way, `auto` may run discover, design and plan before it meets the trust gate; read the other, it checks trust before anything.

SECURITY.md wins when the two documents differ (AGENTS.md).

## Options

1. Check trust only when the phase engine reaches the trust gate.
2. Check trust before the first step, and again wherever the phase engine stops at the trust gate.

## Decision

Option 2. `aipm auto` first checks that the repository is initialized and that its current execution surface is trusted, through the same read-only `require_trusted` the other commands use, and exits 6 with `aipm trust --show` and `aipm trust` as the next commands otherwise. It never writes the trust store. When G2 copies the stack template's gates into `.pm/config.yaml`, the surface changes, the phase engine stops at `aipm trust` after G3, and `auto` exits 6 again.

The loop then runs only what its table names: `discover`, `design` (`--regenerate`), `plan`, `approve prd|design|plan` (G1-G3: a pause without `--yes`, exit 4 when nobody can answer), and `build` for ready tasks. `aipm trust`, a blocked plan and an unknown next command stop it. A step that fails stops it with that step's exit code and the command to run next; a step that changes nothing stops it with exit 4; so do 50 steps.

## Consequences

- On a fresh project a user runs `aipm trust` before `aipm auto`, and again after G2 when the stack's gates arrive: each time they see the exact argv they trust.
- `auto --yes` with an untrusted surface exits 6 and leaves the trust store's bytes and timestamps unchanged (`tests/security/test_auto_trust.py`).
