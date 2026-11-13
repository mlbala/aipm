# ADR-0030: The rust-cargo unit gate runs cargo-nextest with a configuration aipm writes

- **Status:** Accepted
- **Date:** 2026-11-13
- **Source:** step 08 security review, finding F-1 (high); ARCHITECTURE.md §13.1, §13.2; SECURITY.md §10 rule 5, §15 R-12; supersedes the rust-cargo part of [ADR-0029](0029-go-and-rust-cargo-test-reports.md)

## Context

ADR-0029 shipped the rust-cargo `unit` gate as `cargo test --locked --offline`, with no report. A gate without `{report_file}` is judged on its exit code alone (R-12), and ADR-0020's protection, that a test which kills its own runner must not pass, did not apply. The step 08 security review showed that the exit code is in the agent's hands. A test in a file the task owns can call `std::process::exit(0)`, and the libtest binary exits 0 before the failing tests run. Under `srt`, a `build.rs` that sends SIGTERM to its parent cargo makes `srt` exit 0. Nothing required checks that tests ran: `ac_trace` and `ac_review` are both advisory in the template. A task could be marked `done` while its tests failed.

`cargo test` writes no report. libtest's JSON output is nightly-only, and `-Z` is refused. cargo-nextest writes JUnit, but only to a path set in its configuration file: `[profile.<name>.junit] path`, relative to `store.dir/<profile>`.

## Options

1. Keep `cargo test` and make `ac_review` required. An LLM veto is not a check that tests ran.
2. Parse libtest's `test result:` lines from stdout. Test code writes to the same stdout, so it can print a passing line and exit 0.
3. Run `cargo nextest run --config-file <file aipm writes>`, and judge the gate on the JUnit report that file sends to `{report_file}`.

## Decision

Option 3.

- **A fourth placeholder, `{nextest_config}`.** ARCHITECTURE §13.1 listed exactly three. `{nextest_config}` expands to `<report_file>.nextest.toml`, an absolute path beside `{report_file}` in the attempt's private temp dir, outside the worktree, never derived from task, LLM or config data. A gate that uses it gets a `{report_file}` even if it never names one, and is judged on that report as every report gate is (ADR-0020): exit 0, a report, at least one test that ran, and none failed.
- **The configuration** is written fresh for each run, mode 0600, `O_EXCL|O_NOFOLLOW`. Anything already at the path is removed first, never read. It sets the default profile's JUnit path to `{report_file}` (absolute), `retries = 0` and `fail-fast = false`, keeps captured output out of the report, and puts nextest's store in the temp dir. `--config-file` replaces the repository's `.config/nextest.toml` for this run, so a repository cannot set a `default-filter` that leaves failing tests out.
- **The template:** `unit: cargo nextest run --locked --offline --config-file {nextest_config}`. The allowed prefix includes `--config-file`, so the gate cannot drop it.
- **Manual mode (ADR-0017):** an agent's copy renders `{nextest_config}` as `/dev/null`, an empty configuration: nextest's defaults and no report.
- **The command policy** allows `run` after `cargo nextest` only (`cargo nextest run`). Any other `run` is still `cargo run` and refused. It also refuses nextest's `--archive-file`, `--binaries-metadata` and `--cargo-metadata`, which run test binaries named in a file instead of the ones it builds from source, and `--tool-config-file`, whose setup and wrapper scripts start any program. `cargo --config`, `-Z` and `+toolchain` stay refused.
- **ac_trace stays advisory for rust-cargo.** nextest's JUnit names test binaries (`crate`, `crate::integration`), not files, so it cannot say which `tests/*.rs` file ran.

## Consequences

- Each test runs in its own process, so `exit(0)` in one test passes only that test, and the other tests still run and are reported. A runner that dies writes no report, and the gate fails. A report forged by test code during the run is still possible, as with pytest (R-1, R-5).
- **Weaker than pytest in one way.** nextest counts a test as passed when its process exits 0. Agent-written library code that a test calls can exit 0 inside that test (for example, only when `NEXTEST` is set), and that one test is reported as passed. pytest's runner would die and write no report. This is the R-1/R-5 class: code the agent wrote runs inside the gate. Requiring libtest's `ok` line in each case's output would not help, because test code can print it too. Review the library code a Rust task changes, and keep `ac_review` on.
- Rust projects need cargo-nextest installed alongside cargo (`cargo install cargo-nextest --locked`). Without it, the unit gate fails.
- **Checked by hand, not by the tests:** whether nextest accepts an absolute `store.dir` and an absolute JUnit `path`. The nextest docs say only that they are relative to the workspace root and `store.dir/<profile>`. If nextest rejects them, it writes no report and the gate fails closed, never open. Check with a real install before v0.4 is tagged (docs/adapters.md "check by hand").
