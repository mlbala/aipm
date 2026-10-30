# Changelog

All notable changes to aipm are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `aipm verify <T-ID>` (v0.2): post-change checks and every gate for one task, in manual mode. It needs trust (exit 6) and the attempt snapshot `aipm prompt` takes outside the repository (ADR-0021); compares git's configuration, hooks and the agents' global settings before git runs; blocks the task on a severe violation (exit 6); otherwise runs the gates without stopping at the first failure and marks the task `done` only when every required gate passed and the AC reviewer vetoed nothing. `--commit` commits the task's files with `Aipm-*` trailers and no hooks; `--gate`, `--base`, `--override-ac ID --reason` (recorded), `--accept-risk`, `--accept-stale` and `--json`. Reports, gate logs and a journal go to `.pm/runs/<run-id>/`; `aipm prompt --fix` reads the newest report.
- `aipm scan` (v0.2): gitleaks, semgrep, osv-scanner and trivy over a staged copy of the repository, plus trusted `scanners.extra`; `--scanner`, `--fail-on`.
- `aipm task show|reset|block|unblock|skip` (v0.2): manual task state control, each change recorded in `approvals.yaml`.
- The gate runner and the built-in gates `secrets`, `sast`, `deps`, `ac_trace` and `ac_review` (the new AC reviewer role, veto only), the scanner wrappers, the registry lookups for the deps gate, and the stack templates `python-pip`, `node-npm` and `node-pnpm`.
- The sandbox: `srt` profiles from SECURITY.md §9.1, the network profiles `none`, `registries`, `api-only:<domains>` and `open` (user config only), and detection that exits 8 under `security.require_sandbox` (ADR-0020).
- The hardened git wrapper: status, diffs, files at a revision, commits with trailers and signing from your global config, and integrity snapshots.
- The LLM response cache in `.pm/cache/llm/` for the AC reviewer, and `--no-cache` (ARCHITECTURE §14).
- Claude Code subagents and skills from `aipm sync-context`.
- `install.sh`.
- ADR-0020 (`srt` runs commands through a shell) and ADR-0021 (attempt snapshots and the `.pm/` write ledger); residual risk R-10.

### Fixed

- A directory where aipm expected a file (a `.gitignore` directory in a cloned repository, a trust store path) is refused instead of crashing.

### Security

The v0.1 red-team pass ([docs/security/reviews/v0.1.md](docs/security/reviews/v0.1.md)) found seven problems, all fixed, and two security reviews of the fixes found ways around four of them, also fixed:

- The command policy refuses a hard-denied program (a shell, `curl`, `rm`, `git`, …) at any argv position, so a wrapper such as `time`, `nice`, `timeout`, `caffeinate` or `find -exec` can no longer start one (ADR-0019). It also refuses programs that run a shell string or code given as an argument (`awk`, `watch`, `flock`, `script`, `expect`, `sqlite3`) and `nscurl`, `lwp-*` and `tftp`, and it folds version suffixes from every name (`zsh-5.9`, `php8.3`). `osascript -e`, `php -r`/`--run`, `perl -M`, `lua -e`, `luajit -e`, `R -e`, `Rscript -e`, `julia -e`/`--eval`, `deno --eval` and `python -m timeit`, `-m code` or `-m http.server` count as inline code, also when `m` ends a flag cluster (`python3 -Im timeit`, `-Pm`). Without a runner, a `{paths}` value such as `cmd/env` is no longer mistaken for a program; a bare value such as `curl` still is.
- An `AIPM_*` environment variable that sets a user-only key such as `llm.base_url` or `llm.api_key_env` makes aipm exit 6, and every `AIPM_*` relaxation of a security setting is printed as a warning. Your user config and the trust store must be outside the repository, wherever `AIPM_CONFIG`, `HOME`, `XDG_CONFIG_HOME` or `XDG_STATE_HOME` put them (compared by inode, so links, firmlinks and case variants count), and the user config must be a regular file (exit 6); no log file is written inside the repository, or through a repository link that leads out of it. The repository is the one the command works on, `-C` included. `security.extra_redact_patterns` is read from your user config file only. A repository `.env` loaded by pipenv or a similar tool could otherwise redirect your API key or ship its own trust decision (ADR-0018).
- `http` and `https` URLs written without slashes (`https:evil.example`) are removed from context files and prompts.
- Logging redacts, removes escape sequences, then redacts again, so neither a secret split by an escape sequence nor one that ends in a control character (or both) reaches a log line.
- Default-ignorable characters that render as nothing (Hangul fillers, Khmer and Mongolian marks) are removed from text and refused in paths and gate argv.
- The secrets deny list matches file names without regard to case (`Secrets.yaml`, `server.PEM`).
- aipm reads YAML 1.2 only. A `.pm/` YAML file with another `%YAML` version, a collection as a mapping key, a date or time out of range, or an integer longer than 100 characters is a schema error (exit 2) instead of an internal error.

### Added

- Corpus cases C-028 to C-037, `tests/security/test_redteam_v01.py`, red-team fuzzing in `tests/property/test_redteam_v01_props.py`, and the `ci-long` Hypothesis profile: `uv run pytest --hypothesis-profile=ci-long` runs each new property 2,000 times.
- SECURITY.md: threat T-7 (repository content as configuration through the environment) and residual risks R-8 and R-9.

## [0.1.0] - not yet tagged

v0.1, the PM core. The owner tags it after the v0.1 security red-team pass (build prompt 09) and sets the date here.

### Changed

- aipm needs Python 3.13 or later (ADR-0015). CI tests Python 3.13 and 3.14 on Linux and macOS.
- G3 pins the plan without task progress once work has started (ADR-0016): `prompt` can mark a task `in_progress` without voiding the approval, while an unstarted plan is still pinned to its exact bytes.
- `aipm status` names the task it is waiting for when nothing else is ready.

### Added

- `aipm prompt <T-ID>`: the Claude Code prompt for one task, compiled without a model from the approved plan and the trusted config. It needs trust (exit 6), prints the prompt (or `--out FILE`, inside the repository), saves `.pm/prompts/<T-ID>.claude.md`, marks the task `in_progress` with `base_sha` set to HEAD, and copies it with `--copy` (`pbcopy`, `wl-copy` or `xclip`). Unfinished dependencies need `--force`; a stale plan needs `--accept-stale`, which is recorded. `--fix --report FILE` adds the failing output of a saved gate report, cut to head and tail. The prompt stays within 24 KiB, trimming read-only files, then upstream titles, then older output, and refuses otherwise.
- `aipm sync-context`: managed blocks in `AGENTS.md` (overview, stack, how to run checks, architecture map, conventions, boundaries, task protocol) and `CLAUDE.md` (`@AGENTS.md` plus Claude Code notes). It shows a diff, writes after an interactive yes or an `aipm approve context` approval, and records each block's hash; text outside the markers is kept byte for byte, and broken markers exit 2. `--check` exits 3 on drift and needs no trust (ADR-0017). `--tool` is repeatable; only `claude` exists in v0.1.
- `aipm approve context [--yes]`: approves the reviewed managed blocks without writing them.
- The prompt compiler (`TaskSpec`), the Claude Code adapter (`render_prompt`, `context_files`, and `detect` with `claude --version`), the adapter registry and the context generator, with package templates. Gate commands appear as agents run them: `{paths}` empty, `{test_paths}` the first test root, `{report_file}` `/dev/null` (ADR-0017).
- README: the full v0.1 quickstart, a recorded session, the tested tool versions and the manual offline check with Ollama.
- Tests: managed-block fuzzing with hypothesis, invariant I-3 over every generated file and prompt (fuzzed), corpus cases C-022 to C-027 through PRD and architecture fields and bodies, task fields and gate output, golden snapshots of `AGENTS.md`, `CLAUDE.md` and the task prompt (normal and `--fix`), integration tests for `prompt`, `sync-context` and `approve context`, and the clinic flow end to end through `prompt` and `sync-context`, including exit 6 before trust. The smoke test's stub checks for `prompt` and `sync-context` became "every v0.1 command is built".

- `aipm design`: the architect and threat modeler write `.pm/architecture.md`, `.pm/adr/NNNN-<slug>.md` and `.pm/threat-model.md`, then G2 shows the stack, components, ADR titles and threats of medium or higher. Only built-in stack templates; an LLM app must cover the OWASP Top 10 for LLM Applications. After G2, a greenfield project gets the stack's prepare step, gates and allowed commands in `.pm/config.yaml` (trust is needed again). `--regenerate` rebuilds from the current PRD.
- `aipm plan`: the planner proposes a task graph and the plan validator (`aipm.domain.dag`) checks all eight rules of ARCHITECTURE §9, merging or ordering tasks that own the same files and listing every change, with one repair attempt for the planner. Writes `.pm/tasks.yaml` and `.pm/worksheet.md`, then G3 shows the task table, DAG depth and width, every command line from the config, every `deps_add` and the tasks that own test or config files. An interactive G3 also records trust.
- `aipm approve design` and `aipm approve plan`; `--yes` records the approval but never trust and prints the `aipm trust --confirm` command.
- Phase derivation (`aipm.domain.phase`) with transitive staleness through the `derived_from` hashes. `design` and `plan` refuse stale or unapproved input (exit 2) unless `--accept-stale`, which is recorded in `approvals.yaml` under `overrides`.
- `aipm` with no command prints the phase report and offers to run the next step in a terminal.
- `aipm status`, with `--json`, `--all`, `--task` and `--ack EVENT-ID`: counts, a progress bar, blocked tasks, security events, features and threats not yet covered by done tasks, and the budget. No LLM calls.
- Tests: validator rules and a property test (accepted plans are acyclic and tasks that may run together own no common file), the phase table, golden snapshots of the new prompts, `architecture.md`, an ADR, `threat-model.md`, `worksheet.md` and the status output, integration tests for every new command, and the clinic-booking flow end to end with FakeLLM.
- `aipm discover`: the requirements interview. Starts from `--from FILE` (extracted answers are shown for confirmation; unconfirmed ones do not count) or a one-paragraph description, then asks a few questions per round (single, multi, text and confirm, with defaults, "use defaults for the rest of this round" and "I'm done"), shows the coverage score after each round, and stops at the threshold, the round limit or when you are done. Accepted defaults become assumptions. Writes `requirements.yaml`, `requirements.md` and `prd.md`, then offers G1. Re-runs start from open questions and unconfirmed assumptions; `--edit Q-ID` changes one answer. Non-interactive runs take `--answers FILE` (keyed by question ID, assumption ID or dimension) and `--defaults`, and exit 4 with the pending questions as JSON, keeping the progress so far.
- `aipm approve prd`: records G1 in `approvals.yaml` for the exact PRD hash shown; refuses a stale PRD or one with blocking open questions; never writes trust. `design`, `plan` and `context` follow in build prompts 04 and 05.
- The LLM gateway: role-to-model routing, redaction of every prompt (and refusal to send one that still holds a secret), retries for 429, 5xx and timeouts with exponential backoff, jitter and `retry-after` (5 tries), strict schema validation with one repair attempt, the token budget (exit 5) and usage and cost accounting. Providers: `anthropic` (SDK 2.x, API version `2026-10-21`) and `openai-compatible` (OpenAI, Ollama, vLLM and others). No request ever carries `temperature`, `top_p` or `top_k`.
- The interviewer and PRD writer roles, with sandboxed templates that spotlight every input as untrusted, and the coverage engine with the mandatory clamp: no dimension scores above 0.5 without an answer from the user or a confirmed file answer.
- `FakeLLM` for tests: fixture responses per role, recorded requests, invalid output and injection reports. An opt-in live smoke test (`AIPM_LIVE=1`).
- ADR-0014: structured output uses native schemas, then JSON mode, then the prompt; never forced tool calls.
- `aipm init`: refuses outside a git repository (exit 2), detects the stack and greenfield or brownfield, writes `.pm/config.yaml` (with the `python-uv` gate menu when detected), `.pm/.gitignore` and a sanitized `.pm/repo-map.md`, then shows the execution surface and offers to trust it. `--force` keeps existing artifacts.
- `aipm trust`: prints every argv in full with the surface hash, records trust only after an interactive yes or `--confirm <hash12>`, and supports `--show` and `--revoke`. Trust lives in `trust.json` in the user state directory (mode 0600).
- `aipm doctor`, with `--json`: tool versions, whether API key variables are set (never their values), `.pm/` schema validity, lock and trust status.
- The core: the state store (atomic, locked, redacted writes; deterministic YAML; front matter; security events), Pydantic models for every `.pm/` schema, the layered config with key classes, the `python-uv` stack template, the trust store and structured logging.
- Repository skeleton: the `aipm` package laid out by layer (ARCHITECTURE §19), with typed stubs that name the build step that implements them.
- The `aipm` command line with every command and flag from ARCHITECTURE §16, the JSON envelope and the exit codes. Commands exit 2 until their build step lands, saying which one.
- Tests: CLI smoke tests, a startup-time test (`aipm --help` under 300 ms), the ruff process ban, the import-linter layer contracts, a hidden-character check, and the first 10 cases of the injection corpus.
- CI on Linux and macOS with Python 3.13 and 3.14, a commit-authorship check, and a weekly security workflow (gitleaks, semgrep, osv-scanner, zizmor). Every action is pinned by commit SHA.
- `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, ADRs 0001–0013 and the `clinic-booking` example idea.

### Security

- Context files and task prompts render model-written text only inside fenced `untrusted` blocks, and every field passes `sanitize_for_context`, which now also neutralizes `@path` mentions that Claude Code would read as file imports (`@.env` becomes `@ .env`). Each generated block and prompt is checked against invariant I-3 before it is written, and protected paths appear only as "MUST NOT modify" rules.
- Context files and `--out` files are never read or written through a symbolic link, only regular files are accepted, and a write is refused if the file changed after it was shown. Prompts are redacted between untrusted-block tags before they are saved, printed or copied.
- aipm's one git call (`rev-parse` for the base commit) runs through `run_safe` with the full SECURITY §11 hardening (hooks, fsmonitor and external diff off, no pager) and a constructed environment; a `git` or clipboard tool found on PATH inside the repository is never run.
- From the step 05 security review: paths and globs shown to agents must be plain (letters, digits and `. _ / * ? + -`) or the command exits 6; a prompt is checked against I-3 again after redaction; a context block that would contain a secret is refused before it is shown; `--out` never follows a link and never keeps execute bits; `--check` names a refused gate without its argv; and a prompt run with `--accept-stale` labels its text `stale` or `unapproved`, not approved.
- The plan validator, not the prompt, is the control: unknown gate names, unsafe or protected owned paths, cycles, oversized plans and bad package names are rejected deterministically, and terminal escapes and invisible characters are removed from task text (recorded as a security event). Repair notes never carry the model's text. Corpus cases C-015 to C-021 run through `aipm plan`.
- G3 command lines come from the trusted config through the trust store's surface; a test shows that no task text reaches them. The planner sees gate names only, never argv.
- Every `.pm/` artifact a role reads is wrapped as `Untrusted` with a source label (`approved:prd`, `unapproved:architecture`, `stale:threat_model`), including approved ones.
- `.pm/adr/` must be a real directory; ADR files are read without following links, only names aipm would write are read, and file names are built by aipm.
- Fixes from the step 04 security review: owned globs must be clean NFC text, so two spellings of one file cannot run in parallel; G3 lists every glob that could hold tests or test, gate or scanner configuration; G3 re-checks `tasks.yaml` from disk with every plan rule, and a hand-edited cycle is a schema error; repair notes never name a task by its text; ADR replacement checks every entry before writing; serialized-path matching cannot backtrack; npm names cannot start with `-` or `~`; config warnings appear before G3 asks for trust.
- Model output is data: every reply is parsed strictly (no duplicate keys, no NaN, size-capped, `extra="forbid"`, every limit, strict types); the repair prompt names fields and rules only, never the rejected text or keys the model invented. Question IDs are allocated by aipm. Nothing a model writes can add a gate, change config, approve an artifact or touch trust.
- `injection_suspected` from any role is recorded as a security event and shown with the excerpts; non-interactive runs exit 4 unless `--accept-risk`. Invisible characters removed from an idea file raise a security event too.
- `--from` and `--answers` files must resolve inside the repository and pass `safe_relpath` (no protected paths, no escaping symlinks), must not be ignored or secret-named (SECURITY.md §7.1), and must be the inode that was checked; oversized files are rejected (exit 2).
- Fixes from the step 03 security review: the gateway redacts only between untrusted block tags and refuses a prompt whose block structure is broken, so a redaction pattern can no longer remove a closing tag and aipm's own instructions; a server that reports no usage is charged an estimate; IDs accept ASCII digits only, and running out of IDs exits 2; a dimension-wide or yes/no answer never answers a confirm question; the interactive extraction review defaults to one by one.
- Providers get their key, base URL and timeout explicitly, so `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` or a credential profile cannot redirect them; SDK retries and the Anthropic SDK's OpenTelemetry instrumentation are off. The openai-compatible provider refuses to send an `ANTHROPIC_*` key.
- The import contracts now cover `httpx2`, which the LLM SDKs use.
- Corpus case C-014 (oversized idea file); C-001, C-002, C-004, C-008 and C-010 now run through `aipm discover`.
- Path validation (`safe_relpath`, `safe_rel_glob`): no absolute paths, `..`, leading `-`, control or invisible characters, protected paths (case-insensitive, at any depth) or symlinks that escape the workspace.
- The command policy: argv-prefix allow-list, hard-denied executables (also after a runner), inline-code flags, install patterns outside the prepare step, whole-element placeholders, and the forbidden coding-agent flags.
- The process runner: argv only, constructed environment, new session, SIGTERM then SIGKILL to the whole process group, output caps; a sandbox profile is refused until v0.2.
- Repo config is limited by key class: user-only keys are ignored and tighten-only keys can only get stricter, with a warning each time. A shell gate in a repo config can never be trusted (exit 6).
- YAML loading rejects aliases, anchors, tags, deep nesting and files over 1 MiB before constructing anything.
- The import-linter contracts for SDKs, `subprocess` and network modules now cover the whole package, and the CLI's imports are checked against an allow-list.
- Corpus cases C-011 (YAML alias bomb), C-012 (config redirection) and C-013 (config relaxation).
- Fixes from the step 02 security review: an allowed argv prefix must name its program (no bare `uv`, `npm`, `python` or `uv run`); `uv tool run/uvx`, `npm exec/x`, `pnpm dlx`, `yarn dlx` and `bun x` are refused in every stage; attached `-mpip` and more interpreter inline-code flags are caught; argv elements reject invisible characters. Paths and globs may not start with `@` or `+` (option files), and globs reject brackets, braces and a leading `!`. An interactive trust confirms the full surface hash. YAML errors never echo values. The user's `security.extra_redact_patterns` apply to `.pm/` writes and logs.
- The `pre-push` hook refuses any push that is not a fast-forward of a `step/*` or `security/*` branch: no `main`, no deletions, no force pushes, and no tags unless the owner sets `AIPM_RELEASE_TAG=1`.
- More process and dynamic-import routes are banned (ctypes, ProcessPoolExecutor, webbrowser, pydoc, runpy, importlib loaders, event-loop `subprocess_exec`, `sys.modules[...]`, `getattr` lookups). `execution/process.py` no longer has a file-wide lint exemption.
- The commit-authorship check also verifies the committer, and fails if it reads fewer commits than the comparison holds.
- The hidden-character check covers every file in the repository and fails on files that are not valid UTF-8.

### Changed

- Design review 01 applied to the architecture and security design: config keys are user-only, tighten-only or repo-ok; the command policy checks argv prefixes and runners; approved artifacts stay wrapped as untrusted; `prompt` and `sync-context` need trust; the LLM gateway never sends sampling parameters.
