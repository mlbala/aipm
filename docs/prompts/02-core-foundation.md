# Prompt 02: Core foundation (state, config, security primitives, `init`, `doctor`, `trust`)

**Milestone:** v0.1 · **Depends on:** 01 merged · **Branch:** `step/02-core`

## Your role

You are building the parts every later feature trusts. Correctness and security matter more than speed here. Write the security modules test-first.

## Read first

- `AGENTS.md`
- ARCHITECTURE §3, §5, §6, §13.1, §15, §16, §19
- SECURITY §4, §6, §7.1, §7.2, §7.10, §8, §10

## Build, in this order

1. **`aipm.security.sanitize`** (L1, SECURITY §7.1):
   - `sanitize_text(s, *, source) -> SanitizeResult(text, removed: Counter[str])` performs NFC normalization and removes control characters, ANSI/OSC sequences, Unicode Tags, zero-width characters, bidi controls and stray variation selectors.
   - `sanitize_for_context(s)` additionally removes HTML comments and URLs whose domain is not in the allowlist.
   - `strip_terminal_escapes(s)`.
   - Size caps.
   - Binary detection.
2. **`aipm.security.untrusted`** (L2, SECURITY §7.2):
   - The `Untrusted` dataclass (text and source).
   - The `untrusted` Jinja filter, using a random nonce per render and neutralizing closing tags.
   - `make_env()`, which returns a `SandboxedEnvironment` with `StrictUndefined` and a `finalize` hook that raises `UntrustedRenderError` when `Untrusted` is rendered without the filter.
   - A template loader that reads only from package resources.
3. **`aipm.security.redact`** (SECURITY §8):
   - `Redactor`, built from an environment snapshot passed to its constructor (it never reads `os.environ` itself), built-in patterns and config patterns. It provides `redact(str) -> str`, `contains_secret(str) -> bool` and a logging filter.
   - A test asserts that the redactors used by the LLM gateway, `StateStore` and logging are built from the full `os.environ`.
4. **`aipm.security.paths`:**
   - `safe_relpath(root, p) -> SafeRelPath` and `safe_rel_glob(g) -> SafeRelGlob`. These reject absolute paths, `..`, a leading `-`, NUL, protected paths and `.pm/`, and resolve symlinks to confirm containment.
   - `PROTECTED_PATHS` from SECURITY §9.2, combined with config.
5. **`aipm.security.command_policy`** (SECURITY §10):
   - `CommandPolicy`.
   - `compile_gate(gate, paths, policy, report_file=None) -> Argv`, which stays pure: argv-prefix matching against `allowed_executables` (SECURITY §10 rule 2), the hard-deny list (also at any position after a runner), inline-code and argument-pattern denials, and placeholder expansion for `{paths}`, `{test_paths}` and `{report_file}` (rule 5).
   - `check_forbidden_flags(tool, argv)`, using the forbidden table in ARCHITECTURE §11.
6. **`aipm.execution.process`** (the only module that imports `subprocess`). There is no file-wide lint exemption: put `# noqa: TID251` on each `subprocess` and `asyncio.create_subprocess_*` line only; `tests/security/test_banned_api.py` allows that comment nowhere else.
   - `run_safe` and `run_safe_async`: argv only, timeout, new session, process-group kill (SIGTERM, then SIGKILL after 10 s), output cap, constructed environment.
   - `build_env(base_allowlist, extra)`.
   - Sandbox support is only a parameter for now; `None` is the only option until prompt 06.
7. **`aipm.state`:**
   - `yamlio`: `ruamel.yaml` with deterministic dumping. Loading rejects aliases, anchors and tags, and files over 1 MiB.
   - `frontmatter`: parse and dump.
   - `layout`: the `.pm/` paths.
   - `store.StateStore`: atomic writes (temp file + fsync + replace + directory fsync), the `filelock` lock (exit 7, with the holder's PID), redaction before every write, a pre-write secret scan, sha256 normalization (§6.2), and schema validation on load.
   - The schema-version check: a file with a newer `schema_version` than aipm knows exits 2. The migration framework is deferred to the first v2 schema (review 01, D-2).
   - Security events: append to `.pm/events.jsonl` (gitignored, append-only) with random IDs (ARCHITECTURE §6.1).
8. **`aipm.domain.models`:** Pydantic v2 models for every schema in ARCHITECTURE §6.3. All of them use `extra="forbid"`, length limits, ID regexes and enums. Include the run-journal event model.
9. **`aipm.config`:**
   - The schema (§15).
   - The layered loader: defaults < user < repo < env < flags.
   - **Key classes** (ARCHITECTURE §15, SECURITY §6 rule 5), stored as field metadata in the schema. A user-only key from the repo is ignored with a warning. A tighten-only key from the repo can only make the setting stricter (`budget.*`: the minimum wins; `context.allowed_url_domains`: the intersection). Relaxations are reported as warnings.
   - `defaults.yaml`.
   - The stack template `python-uv` (ARCHITECTURE §13.1), with `allowed_executables` (argv prefixes), `prepare`, `gates` and `test_roots`. `python-pip`, `node-npm` and `node-pnpm` come in prompt 06 (review 01, D-1).
10. **`aipm.state.trust_store`:**
    - Resolves each `argv[0]` with `shutil.which` at trust time; the resolved absolute paths are part of the surface hash.
    - The canonical execution surface and its hash (SECURITY §6, rule 1).
    - `trust.json` in `platformdirs.user_state_dir("aipm")`, mode 0600, written atomically.
    - `is_trusted`, `trust`, `revoke`.
11. **Commands:**
    - **`aipm init`:**
      1. Detect git; refuse with exit 2 when not in a git repo, and suggest `git init`.
      2. Detect the stack from manifests (`pyproject.toml`, `uv.lock`, `requirements*.txt`, `package.json` plus its lockfile).
      3. Detect greenfield versus brownfield.
      4. Write `.pm/config.yaml` (gates copied from the stack template, if known), `.pm/.gitignore` and `repo-map.md`.
         - The repo map is a file tree limited to 300 entries, plus the manifest names and the README's first heading. It respects `.gitignore`, `.aipmignore` and the deny list, and is sanitized.
      5. Show the execution surface and offer to trust it.
      6. `--force` re-initializes and keeps existing artifacts.
    - **`aipm doctor`:**
      - Versions of git, uv, claude, codex, copilot, gemini, srt, semgrep, gitleaks, osv-scanner and trivy (missing tools are listed, not errors).
      - Whether the API key environment variables are present (never their values).
      - `.pm/` schema validity.
      - Lock status and trust status.
      - Supports `--json`.
    - **`aipm trust`:** `--show` prints every argv in full together with the surface hash. Trust is recorded by interactive confirmation, or non-interactively only with `--confirm <first 12 hex characters of the surface hash>`, so that a blanket "yes" can never grant trust. `--revoke` removes it.
12. **Logging (`aipm.observability.logging`):** human output to stderr, the redaction filter on every handler, and a JSON-lines file handler in the user state dir.
13. **CLI output helpers:** `output.print_untrusted(text)` always sanitizes and uses `Text`, never markup.

## Security requirements

- Write `tests/security` and `tests/property` for modules 1–6 **first**, then implement them until the tests pass.
- Tighten the import-linter contracts (step 01 security review, finding 7):
  - give the SDK and `subprocess` contracts `source_modules = ["aipm"]`, with `ignore_imports` for the real exceptions (`aipm.llm.providers.*` → the SDKs, `aipm.execution.process` → `subprocess`), so new modules are covered by default;
  - add a contract that keeps network modules (`socket`, `ssl`, `http`, `httpx`, `ftplib`, `smtplib`, `xmlrpc`, and `urllib` where it fetches) out of every package except `aipm.llm` and `aipm.scanners.registry`. import-linter does not follow imports inside the standard library, so name the modules themselves;
  - turn the `cli` contract into an allow-list (a test of `cli`'s imports), so a new `domain` or `security` module is not allowed by default.
- These modules need 100% branch coverage: `sanitize`, `untrusted`, `paths`, `command_policy`, `process`.
- Property tests (hypothesis):
  - the path validators never accept an escaping path;
  - `compile_gate` never emits an argv outside the allowed prefixes, a hard-denied executable, a denied pattern, or an unvalidated placeholder value, and no hard-denied name or inline-code flag appears after a runner in any argv it returns;
  - `sanitize_text` is idempotent and never outputs the removed character classes;
  - the redactor never outputs a registered fake secret.
- Corpus cases: path traversal, argument injection, a YAML alias bomb, Unicode smuggling, a fake closing tag, ANSI/OSC in text.
- Integration tests:
  - a repo `.pm/config.yaml` that tries to set `security.require_sandbox: false` or add `bash` to the gates is ignored or rejected, as specified;
  - a repo `.pm/config.yaml` that sets `llm.base_url` and `llm.api_key_env` (the config-redirection corpus case) is ignored with a warning (invariant I-8);
  - the global `--yes` flag never writes trust: `aipm --yes trust` without `--confirm` exits 4 in non-interactive mode; `--confirm` with a wrong or stale hash exits 6.

## Tests (other)

- State store: atomic-write crash simulation (an exception mid-write leaves the old file intact); a second process gets lock contention and exit 7; deterministic dumps produce identical bytes for identical models; schema-version rejection.
- `init` golden output for each stack template. `doctor --json` shape.

## Out of scope

LLM calls, discover, design, plan, gates execution, the sandbox implementation.

## Definition of done

- [ ] Every check in AGENTS.md passes; the coverage targets are met.
- [ ] `aipm init` in an empty git repo and in a sample Python repo produces valid `.pm/` files, shown in the report.
- [ ] security-reviewer has no open high or critical findings.
- [ ] Report written.
