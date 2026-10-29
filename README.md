# aipm

<!-- Status badges arrive with the first green CI run on main:
[![CI](https://github.com/mlbala/aipm/actions/workflows/ci.yml/badge.svg)](https://github.com/mlbala/aipm/actions/workflows/ci.yml)
[![Security](https://github.com/mlbala/aipm/actions/workflows/security.yml/badge.svg)](https://github.com/mlbala/aipm/actions/workflows/security.yml)
-->

**An AI product manager for your terminal.** aipm interviews you for requirements, designs the architecture, splits the work into tasks, and writes prompts and `AGENTS.md` for Claude Code, Codex, Copilot and Gemini CLI. It then verifies every task with tests and security gates.

> **Status: pre-alpha, v0.1 feature-complete.** The commands are built step by step from the prompts in [`docs/prompts/`](docs/prompts/README.md). Every v0.1 command works: `aipm`, `init`, `doctor`, `trust`, `discover`, `design`, `plan`, `approve`, `status`, `prompt` and `sync-context`. The later commands (`verify`, `scan`, `task`, `run`, `build`, `merge`, `auto`) are registered and exit with code 2, naming the milestone that brings them.

## Install

```bash
uv tool install git+https://github.com/mlbala/aipm
```

aipm needs Python 3.13 or later. It is distributed from GitHub only ([ADR-0001](docs/architecture/adr/0001-distribute-from-github.md)).

## Use

The v0.1 flow, in any git repository:

```bash
aipm init                       # .pm/, stack detection, repo map
aipm discover --from idea.md    # requirements interview, then the PRD (approve it: G1)
aipm design                     # architecture, ADRs, threat model (approve it: G2)
aipm plan                       # task graph and worksheet (approve it, and trust its commands: G3)
aipm sync-context               # AGENTS.md and CLAUDE.md for your coding agent
aipm prompt T-001 --copy        # the first task's prompt; paste it into Claude Code
aipm status                     # where you are, and what to run next
```

`aipm` on its own always prints the phase and the next command. In a terminal each step asks before it records an approval; in a script, use `--yes` for G1–G3, `aipm trust --confirm <hash>` for trust, and `aipm approve context --yes` for the context files.

## Commands

| Command | What it does | Milestone |
|---|---|---|
| `aipm` | Phase report and the next step | v0.1 |
| `aipm init` | Create `.pm/`, detect the stack, write the repo map, run the trust flow | v0.1 |
| `aipm doctor` | Tool versions, capabilities, sandbox, which API keys are set (never their values) | v0.1 |
| `aipm trust` | Show the exact commands aipm may run, then record your trust | v0.1 |
| `aipm discover` | Requirements interview, then `requirements.yaml` and the PRD | v0.1 |
| `aipm approve <prd\|design\|plan\|context>` | Non-interactive approval | v0.1 |
| `aipm design` | Architecture, ADRs and threat model | v0.1 |
| `aipm plan` | Task graph with acceptance criteria and gates | v0.1 |
| `aipm status` | Task status and security events, without an LLM | v0.1 |
| `aipm prompt <T-ID>` | The prompt for one task, for your own coding agent | v0.1 |
| `aipm sync-context` | Managed blocks in `AGENTS.md` and `CLAUDE.md` | v0.1 |
| `aipm verify <T-ID>` | Post-change checks and gates for one task | v0.2 |
| `aipm scan` | Every scanner over the repository | v0.2 |
| `aipm task …` | Show, reset, block, unblock or skip a task | v0.2 |
| `aipm run <T-ID>` | Dispatch one task to a coding agent and verify it | v0.3 |
| `aipm build` | Build every ready task, in parallel where safe | v0.3 |
| `aipm merge` | Fast-forward your branch to the integration branch | v0.3 |
| `aipm auto` | Run every step in order, pausing at the review gates | v0.4 |

Every command accepts `--json`, which prints exactly one result object to stdout. Exit codes are listed in [ARCHITECTURE.md §16.1](docs/architecture/ARCHITECTURE.md#161-exit-codes).

### Getting started: `init`, `trust` and `doctor`

`aipm init` must run inside a git repository. It detects the stack from the manifests at the repository root (`python-uv` ships today; `python-pip`, `node-npm` and `node-pnpm` arrive in v0.2), copies that stack's gate menu into `.pm/config.yaml`, writes `.pm/.gitignore` and `.pm/repo-map.md`, and shows the execution surface: every command aipm may run, in full, with the executable it resolves to on your `PATH`. `--force` re-initializes and keeps your other `.pm/` files. `--provider` is a user-level setting, so aipm tells you where to put it instead of writing it into the repository.

`aipm trust` records your approval of that exact surface, for you and this machine only, in your user state directory. It asks interactively, or takes `--confirm` with the first 12 characters of the surface hash, so a script has to name the surface it trusts. `--yes` never grants trust. Any change to a gate, the prepare step, a dispatch flag, a security setting or the resolved path of an executable changes the hash and needs trust again. `aipm trust --show` prints the surface without recording anything, and `--revoke` removes your trust.

`aipm doctor` lists the versions of git, uv, the coding agents and the scanners (missing tools are listed, not errors), whether your API key variables are set (never their values), whether the `.pm/` files are valid, and the lock and trust status.

### Requirements: `discover` and `approve prd`

`aipm discover` interviews you a few questions at a time, aimed at whatever the coverage checklist (problem, users, features, data, integrations, scale, security, deployment, constraints, success metrics) still lacks. Start from a file with `--from idea.md`, or describe the project in one paragraph. Answers the model finds in the file are shown for you to confirm; unconfirmed ones do not count. Each question takes Enter for its default, and offers "use defaults for the rest of this round" and "I'm done". Accepted defaults become written assumptions. The coverage score is computed by aipm, not by the model, and a topic cannot score above 0.5 until you (not a default, not the file alone) have answered it. The interview stops at `discover.coverage_threshold` (0.85), after `discover.max_rounds` (6), or when you are done; `--threshold` and `--max-rounds` override them for one run.

It writes `.pm/requirements.yaml` (the source of truth), a readable `.pm/requirements.md` and `.pm/prd.md`, then shows the PRD for approval (G1). Run `aipm discover` again to answer open questions and confirm assumptions, or `aipm discover --edit Q-004` to change one answer; the PRD is rewritten and needs approval again. `aipm approve prd` approves the current PRD (with `--yes`, without the review prompt); it refuses a PRD written from older requirements, or while a blocking question is open. Approvals are a record in `.pm/approvals.yaml`; they never grant trust.

Without a terminal (`--non-interactive`, `--json`, or piped stdin), answers come from `--answers FILE` and `--defaults`. Anything still unanswered saves your progress and exits 4, printing the pending questions as JSON, so a script can answer them and run again:

```yaml
# answers.yaml: keys are question IDs, assumption IDs or checklist dimensions
schema_version: 1
description: "A booking app for a small clinic, with WhatsApp reminders."   # when there is no --from
confirm_extracted: true          # confirm every answer found in the --from file, unreviewed
answers:
  Q-004: "India only, no payments yet"
  integrations: "none"
  security_compliance: [GDPR, EU data residency]
  A-002: true                    # confirm an assumption (or give text to replace it)
```

A dimension key answers that dimension's text and choice questions; a yes/no question is answered only by its ID, so a file never says "yes" to a question it has not seen. `--from` and `--answers` files must be inside the repository, and aipm refuses files it never reads for model context: anything in `.gitignore` or `.aipmignore`, and secret-looking names such as `.env*`, `*.key`, `*.pem`, `id_*`, `*secret*`, `*credentials*` and `.netrc`. If a model reports instructions hidden in its input (`injection_suspected`), aipm shows them and asks before it continues; a non-interactive run exits 4 unless you pass `--accept-risk`.

### Design and plan: `design`, `plan`, `approve design|plan` and `status`

`aipm design` turns the approved PRD into `.pm/architecture.md`, one `.pm/adr/NNNN-<slug>.md` per decision and `.pm/threat-model.md`, then shows G2: the stack, the components, the ADR titles and every threat of severity medium or higher. The architect may only pick a built-in stack template, and an LLM app's threat model must cover all ten OWASP Top 10 for LLM Applications items; a reply that breaks a rule gets one repair attempt, and nothing is written from one that fails twice. For a greenfield project, approving G2 copies the chosen template's prepare step, gates and allowed commands into `.pm/config.yaml`; that changes the commands aipm may run, so trust is needed again. A current design is not regenerated without `--regenerate`, and a stale one (the PRD changed) asks for it.

`aipm plan` asks the planner for a task graph, then checks it with a deterministic validator: task IDs and dependencies (no cycles), safe owned and read paths (never `.pm/`, `.github/` or another protected path), gate names from the menu only, `unit` and `ac_trace` on feature, security and refactor tasks, every must feature and every threat of medium or higher traced, at most 40 owned paths and 10 acceptance criteria per task (an L task with more than 6 must be split), and valid package names in `deps_add`. Tasks that could change the same files at the same time are merged when small enough, or ordered otherwise, and every change is listed. A plan that still breaks a rule after one repair attempt is not written: a policy problem (an unknown gate, an unsafe path, a bad package name) exits 6, anything else exits 1. `--max-tasks N` lowers the cap of 200.

It writes `.pm/tasks.yaml` and a readable `.pm/worksheet.md`, then shows G3: the task table, the DAG depth and parallel width, the full command line of the prepare step and every gate (from your config, never from the plan), every new dependency, and the tasks that own test or test-config files. Approving G3 in a terminal also trusts those exact commands. `aipm approve design` and `aipm approve plan` approve without running a model; `--yes` records the approval but never trust, and prints the `aipm trust --confirm` command to run instead.

Every command checks that its input is approved and current. When the PRD or the design changed after it was approved, `design` and `plan` exit 2 and say what to run first; `--accept-stale` runs anyway and records that in `.pm/approvals.yaml`. Every `.pm/` file a model reads is wrapped as untrusted text with a label such as `approved:prd`, whether it is approved or not.

`aipm` on its own prints the phase (for example `design_approved`), anything stale with its downstream impact, and the next command; in a terminal it offers to run it. `aipm status` shows task counts and a progress bar, blocked tasks with their reasons and questions, unacknowledged security events, the features and threats no done task covers yet, and the budget. `--all` lists every task, `--task T-007` shows one in full, and `--ack EVENT-ID` acknowledges a security event recorded on this machine. It never calls a model.

### Prompts and context files: `prompt`, `sync-context` and `approve context`

Both commands hand your gate commands to a coding agent that runs outside aipm's sandbox, so both exit 6 until you have trusted the repository's commands with `aipm trust`. Neither calls a model.

`aipm prompt T-001` prints the prompt for one task, saves it to `.pm/prompts/T-001.claude.md`, marks the task `in_progress` and records `HEAD` as its base commit. The prompt holds the rules (each protected path as a "MUST NOT modify" rule, the dependency and network limits), the task's text and acceptance criteria, the files it may change and read, and the exact check commands to run, which come from your trusted config through the command policy. Text a model wrote is shown inside `untrusted` blocks that the agent is told to treat as data. The prompt goes to stdout alone, so `aipm prompt T-001 > prompt.md` works; `--out FILE` writes it to a file inside the repository and `--copy` also copies it with `pbcopy`, `wl-copy` or `xclip`. A task whose dependencies are not done is refused unless you pass `--force`, and a stale plan unless `--accept-stale`. `--fix --report FILE` adds the failing output of a saved gate report, cut to its first and last 4 KiB (from v0.2, `aipm verify` saves the reports). Prompts stay under 24 KiB: aipm drops the read-only file list, then upstream titles, then older check output, and refuses a prompt that still does not fit.

`aipm sync-context` writes a managed block, between `<!-- aipm:begin … -->` and `<!-- aipm:end -->`, into `AGENTS.md` (overview, stack, how to run checks, architecture map, conventions, boundaries and the task protocol) and `CLAUDE.md` (an `@AGENTS.md` import and notes for Claude Code). Everything outside the markers stays exactly as you wrote it, and a file whose markers are broken or repeated is left alone (exit 2). It shows a diff of each block that changes and writes after you confirm; without a terminal it writes only blocks you approved with `aipm approve context --yes`, and otherwise exits 4. `--check` exits 3 when a block is out of date, for CI, and needs no trust because it writes nothing and prints only file names. Fields from the PRD and design are cleaned (no URLs outside `context.allowed_url_domains`, no HTML comments, no invisible characters, no `@path` imports) and shown only inside fenced `untrusted` blocks. Paths shown to an agent (owned and read files, component paths, protected paths, test roots) may use only letters, digits and `. _ / * ? + -`; a plan or config with any other character in a path stops `prompt` and `sync-context` with exit 6. A block that would contain a secret is never shown or written.

### Models and providers

aipm talks to a model through one gateway, with the official `anthropic` SDK or any OpenAI-compatible server (OpenAI, Azure OpenAI, OpenRouter, Ollama, vLLM, LM Studio). It asks for JSON that matches a strict schema, validates every reply, and gives a model one chance to repair an invalid reply; nothing is written from a reply that fails twice. It never sends `temperature`, `top_p` or `top_k`. Set the provider in your user config:

```yaml
# Anthropic (the default): the key is read from ANTHROPIC_API_KEY
llm:
  models: {default: claude-sonnet-5-5, interviewer: claude-haiku-5-5}

# A local Ollama server: no key needed on localhost
llm:
  provider: openai-compatible
  base_url: http://localhost:11434/v1
  api_key_env: OLLAMA_API_KEY
  models: {default: llama3.3}
```

**Offline with Ollama (manual check, v0.1 acceptance criterion 3).** With the network off except `localhost`:

1. Install [Ollama](https://ollama.com), run `ollama pull llama3.3`, and start it (`ollama serve`).
2. Put the `openai-compatible` block above in your user config, and unset `ANTHROPIC_API_KEY`.
3. Turn off Wi-Fi (or block outbound traffic except `127.0.0.1`).
4. In a new git repository, run `aipm init`, `aipm discover --from idea.md`, `aipm design`, `aipm plan`, `aipm trust`, `aipm prompt T-001` and `aipm sync-context`.
5. Expected: every command succeeds and no connection leaves the machine (check with `lsof -i -n -P | grep -v 127.0.0.1` while it runs). A small local model may need a repair attempt more often; `discover`, `design` and `plan` say so when it happens.

`budget.run_tokens` caps the tokens one command may spend (exit 5 when reached); token usage is shown after each run, and cost too when you set prices in `llm.pricing`.

### Configuration

Settings come in layers, later ones winning: built-in defaults, your user config (`$AIPM_CONFIG`, or `config.yaml` in your platform's user config directory), the repository's `.pm/config.yaml`, `AIPM_*` environment variables (`AIPM_LLM__MODELS__DEFAULT` sets `llm.models.default`), then command-line flags. A repository cannot set user-only keys such as `llm.base_url` or `llm.api_key_env`, and it can only make security settings and budgets stricter; aipm prints a warning for every repository setting it ignores and every relaxation you make ([ARCHITECTURE.md §15](docs/architecture/ARCHITECTURE.md#15-configuration)).

## A recorded session

The clinic-booking example ([`examples/clinic-booking/idea.md`](examples/clinic-booking/idea.md)) through the whole v0.1 flow, non-interactively. It was recorded with aipm's test model (`FakeLLM`, the same fixtures the end-to-end test uses), so a real model's text differs. Long outputs are cut where marked `…`, and paths are shortened; the paths, the commit and the surface hash depend on your machine.

```console
$ aipm init
Initialized .pm/ in /tmp/clinic-booking (greenfield)
Stack template: none
Wrote: .gitignore, config.yaml, repo-map.md
…
Not trusted yet. After reviewing it, run: aipm trust --confirm 1d34dab0a0ee
$ aipm --yes discover --from idea.md --answers answers.yaml
Coverage 1.00 (target 0.85) after 1 rounds; 10 answers, 0 assumptions, 0 open questions.
Wrote: .pm/requirements.yaml, .pm/requirements.md, .pm/prd.md, .pm/approvals.yaml
G1 (PRD approval): approved
$ aipm design
Wrote: .pm/architecture.md, .pm/adr/, .pm/threat-model.md
Design: python-uv, 4 components, 2 ADRs, 3 threats of medium or higher
G2 (design approval): pending
note: review .pm/architecture.md, .pm/threat-model.md and .pm/adr/, then run `aipm approve design`
$ aipm approve design --yes
…
G2 approved.
Copied the python-uv stack's prepare step, gates and allowed commands into .pm/config.yaml. The execution surface changed: review it with `aipm trust --show` before `aipm plan`.
$ aipm plan
Wrote: .pm/tasks.yaml, .pm/worksheet.md
Plan: 7 tasks, DAG depth 4, widest level 4; 1 change by the plan validator
G3 (plan approval): pending
Execution surface trusted: no
note: review .pm/worksheet.md, then run `aipm approve plan`
$ aipm approve plan --yes
…
  unit (required): uv run --frozen --offline pytest -q --junitxml '{report_file}' '{test_paths}'    [/usr/local/bin/uv]
…
G3 approved.
Trust is not recorded by --yes. Review `aipm trust --show`, then run `aipm trust --confirm de02099206ea`.
$ aipm prompt T-001
aipm prompt: aipm prompt hands this repository's gate commands to your coding agent, and you have not trusted them
hint: Review them with `aipm trust --show`, then run `aipm trust`.
$ aipm trust --confirm de02099206ea
…
This surface is trusted.
$ aipm prompt T-001
# Task T-001 for `clinic-booking`
…
## Checks to run before you finish

Run these from the repository root, exactly as written:

- `lint` (required): `uv run --frozen --offline ruff check`
- `unit` (required): `uv run --frozen --offline pytest -q --junitxml /dev/null tests`
…
Saved .pm/prompts/T-001.claude.md; T-001 is in progress from 83239b1b007b.
$ aipm sync-context
AGENTS.md: new file (not approved yet)
--- a/AGENTS.md (managed block)
+++ b/AGENTS.md (managed block)
@@ -0,0 +1,108 @@
+# Instructions for coding agents: `clinic-booking`
…
aipm sync-context: the managed blocks changed and need your approval
hint: Review the diff, then run `aipm approve context --yes` and `aipm sync-context` again, or run it in a terminal.
$ aipm approve context --yes
…
Context approved.
Run `aipm sync-context` to write them.
$ aipm sync-context
…
Wrote: AGENTS.md, CLAUDE.md
$ aipm sync-context --check
Up to date: AGENTS.md, CLAUDE.md
$ aipm status
Phase: building
blocked: no task is ready until T-001 is done (in progress)
Next: aipm status

Tasks: 7 (todo 6, in progress 1, blocked 0, done 0, skipped 0)
…
```

## Tested tool versions

aipm v0.1 renders prompts and context files for Claude Code; it starts no coding agent yet (dispatch arrives in v0.3). These are the versions this release was tested with, on macOS 27 (arm64), on 2026-10-29.

| Tool | Version | What was checked |
|---|---|---|
| Python | 3.13.5 (CI: 3.13 and 3.14) | the whole test suite |
| uv | 0.13.6 | install, `uv run`, the python-uv gate commands |
| git | 2.55.0 | `init` and the base commit (`rev-parse`, hooks and fsmonitor off) |
| Claude Code | 1.0.80 installed; formats checked against the Claude Code docs of 2026-10-29 | `claude --version` parsing (`detect`); `CLAUDE.md` with an `@AGENTS.md` import (imports are not read inside code spans or fenced blocks); subagent and skill front matter, for v0.2 |

## Security model

aipm reads untrusted text (your repository, LLM output, agent output) and launches programs, so it is built to fail closed. In short ([SECURITY.md](docs/architecture/SECURITY.md) has the full design):

- **The LLM never chooses commands.** It picks gate *names* from a menu that you review; the commands themselves come from trusted stack templates.
- **Trust lives outside the repository.** A cloned repo cannot pre-approve its own commands or redirect your API key: `aipm trust` records your approval of the exact commands per user and machine, and repo config can only make security settings stricter.
- **Untrusted text is always wrapped and sanitized** before it reaches a model, a file or your terminal.
- **Deterministic gates decide when a task is done.** An LLM reviewer can veto, never pass.
- **Coding agents run sandboxed**, with a scrubbed environment and limited network, when `srt` is installed.

Give coding agents a dedicated API key with a spend limit. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Documentation

- Design: [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md)
- Security model: [docs/architecture/SECURITY.md](docs/architecture/SECURITY.md)
- Decisions: [docs/architecture/adr/](docs/architecture/adr/)
- Build plan: [docs/prompts/](docs/prompts/README.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

[Apache-2.0](LICENSE)
