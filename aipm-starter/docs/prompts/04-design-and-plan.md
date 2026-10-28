# Prompt 04: `design`, `plan`, phase engine, `status`, `approve`

**Milestone:** v0.1 · **Depends on:** 03 merged · **Branch:** `step/04-design-plan`

## Your role

You are building the architect and planner, and the deterministic validators that keep their output safe and buildable. The planner's output decides what will execute later, so the validator matters more than the prompt.

## Read first

- `AGENTS.md`
- ARCHITECTURE §6.3 (architecture, threat model, tasks), §7, §9, §13.1, §14.1, §16, §17
- SECURITY §6, §7.4, §7.5

## Build

1. **Roles:** `architect`, `threat_modeler` and `planner` (ARCHITECTURE §14.1).
   - The architect may choose only a built-in `stack_template`.
   - The threat modeler includes the OWASP LLM Top 10 items when `is_llm_app` is true.
   - The planner receives the gate menu by name and must output gate names only.
2. **`aipm design`:**
   - Writes `architecture.md`, `adr/NNNN-*.md` (from the architect's `adrs[]`) and `threat-model.md`.
   - For greenfield projects, after G2, copies the chosen stack template's `prepare`, `gates` and `allowed_executables` into `.pm/config.yaml`. This changes the execution surface, so trust becomes required again.
   - G2 shows the stack, the components, the ADR titles, and the threats with severity medium or higher.
   - `--regenerate` rebuilds from the current PRD.
3. **`aipm.domain.dag`, the plan validator** (ARCHITECTURE §9, all eight checks). It is deterministic and pure:
   - **Overlap:** conservative glob-overlap detection. Overlapping tasks with no dependency path between them are auto-merged when their combined size is at most L; otherwise a dependency edge is added. Every change goes into a validation report.
   - **Traceability:** missing traces for features or threats give the planner one repair attempt (pass the errors back). If that still fails, exit 1 and show the errors.
4. **`aipm plan`:**
   - Runs the planner, then the validator, then writes `tasks.yaml` and `worksheet.md`.
   - **G3:** shows the task table, DAG depth and maximum parallel width, the full argv of the `prepare` step and every gate (from the trusted config, not from the LLM), all `deps_add` entries, and any tasks that own test or config paths.
   - Approving G3 interactively also records trust (SECURITY §6).
5. **`aipm.domain.phase`:** `derive_phase()` (§7.1) with staleness detection through the `derived_from` hashes. Downstream commands refuse stale input with exit 2 unless `--accept-stale`, which is recorded in `approvals.yaml`.
6. **Bare `aipm`:** prints the phase report. In an interactive terminal it then offers to run the next command.
7. **`aipm status`:**
   - Built with `reporting/worksheet.py` and `reporting/status.py`.
   - Shows counts by status, a progress bar, blocked tasks with their reasons and questions, security events, the features and threats not yet covered by done tasks, and the spend-versus-budget placeholder.
   - Supports `--json`, `--all`, `--task`, and `--ack EVENT-ID` (acknowledges a security event; the acknowledgement is recorded).
   - Works without an LLM, and in under 300 ms with 500 tasks (add a benchmark test with a generated `tasks.yaml`).
8. **`aipm approve design|plan`:** non-interactive approvals. `approve plan --yes` records approval but **not** trust; print the `aipm trust` command to run.

## Security requirements

- Corpus cases for the planner. Each must be rejected or neutralized by the validator, never by the prompt:
  - an unknown gate name such as `shell`;
  - a gate argument smuggled in a task description;
  - `owns_files` containing `.github/workflows/ci.yml`, `.pm/tasks.yaml`, `../x`, `/etc/passwd` or `--output=x`;
  - a dependency cycle;
  - 500 tasks (over the cap);
  - an acceptance criterion containing an OSC 52 escape;
  - a `deps_add` name with shell metacharacters.
- G3 output must display argv from config only. Add a test showing that LLM text never appears in the command list.
- Taint: architecture and threat-model content counts as untrusted until G2. The planner may read them only after approval, and through `Untrusted` wrapping if unapproved content is ever passed with `--accept-stale`.

## Tests (other)

- Unit tests for every validator rule. Property test: the validator's output DAG is always acyclic and ownership-disjoint for any batch the scheduler could build.
- Phase derivation table tests, covering every phase and the staleness transitions.
- Golden snapshots of `worksheet.md` and the status output.
- E2E: the clinic-booking example runs `init` → `discover` → `design` → `plan` with `FakeLLM` fixtures.

## Out of scope

Prompts, adapters, context files, gate execution.

## Definition of done

- [ ] The E2E flow passes, and the report includes `aipm status` output for the sample.
- [ ] All checks pass; the security-reviewer review is clean for high and critical.
- [ ] Report written.
