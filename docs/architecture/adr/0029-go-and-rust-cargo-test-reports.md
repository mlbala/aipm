# ADR-0029: Test reports for the go and rust-cargo stacks

- **Status:** Accepted
- **Date:** 2026-11-12
- **Source:** build prompt 08, step 7; ARCHITECTURE.md §13.1, §13.3; SECURITY.md §10 rule 5

## Context

The `ac_trace` gate reads the test report that the `unit` gate wrote to `{report_file}`, an aipm-generated path outside the worktree (SECURITY §10 rule 5), and counts a test file as run when a case in the report came from it. The Python stacks write JUnit XML (`pytest --junitxml`), and the Node stacks jest JSON.

- **Go.** `go test` has no option to write a report to a file. `gotestsum --junitfile <file>` runs `go test` and writes JUnit XML whose `classname` is the package's import path, not a file.
- **Rust.** `cargo test` writes no report. `cargo nextest` writes JUnit only to a path set in its configuration file, inside the target directory, and libtest's JSON output is unstable (nightly only).

## Options

1. Read the report from the worktree. This breaks rule 5: an agent could plant one.
2. Use gotestsum for Go, and map each test file's directory to its package's import path through `go.mod`'s `module` line. For Rust, run `cargo test` with no report and make `ac_trace` advisory in the template.
3. Leave the two stacks out.

## Decision

Option 2.

- **go:** the unit gate is `gotestsum --junitfile {report_file} -- -mod=readonly ./...` (gotestsum is an allowed executable of the template). `ac_trace` counts `pkg/x/y_test.go` as run when a passed or failed case has the classname `<module>/pkg/x` (`<module>` for a file at the root), with `<module>` read from the worktree's `go.mod`. Without a readable `module` line, no Go file counts as run, so the gate fails closed.
- **rust-cargo:** the unit gate is `cargo test --locked --offline`, with no report, and the template marks `ac_trace` `required: false`. The gate still runs and still reports which criteria it could not trace; `ac_review` (the reviewer veto) still applies.
- The command policy refuses the routes that run another program: `go run|generate|tool|env|install`, `-exec`, `-toolexec`, `-vettool`, gotestsum's `--raw-command`, `--post-run-command` and `--watch`, and `cargo run|install`, `--config`, `-Z` and `+toolchain`.

## Consequences

- A Rust task's acceptance criteria are traced to tests by the reviewer only, until cargo can write a report to a path aipm chooses. The README and the template say so.
- Go projects need gotestsum installed alongside Go.
