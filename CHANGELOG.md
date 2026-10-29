# Changelog

All notable changes to aipm are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
- CI on Linux and macOS with Python 3.12 and 3.13, a commit-authorship check, and a weekly security workflow (gitleaks, semgrep, osv-scanner, zizmor). Every action is pinned by commit SHA.
- `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, ADRs 0001–0013 and the `clinic-booking` example idea.

### Security

- Model output is data: every reply is parsed strictly (no duplicate keys, no NaN, size-capped, `extra="forbid"`, every limit, strict types); the repair prompt names fields and rules only, never the rejected text or keys the model invented. Question IDs are allocated by aipm. Nothing a model writes can add a gate, change config, approve an artifact or touch trust.
- `injection_suspected` from any role is recorded as a security event and shown with the excerpts; non-interactive runs exit 4 unless `--accept-risk`. Invisible characters removed from an idea file raise a security event too.
- `--from` and `--answers` files must resolve inside the repository and pass `safe_relpath` (no protected paths, no escaping symlinks); oversized files are rejected (exit 2).
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
