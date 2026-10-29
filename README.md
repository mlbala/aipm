# aipm

<!-- Status badges arrive with the first green CI run on main:
[![CI](https://github.com/mlbala/aipm/actions/workflows/ci.yml/badge.svg)](https://github.com/mlbala/aipm/actions/workflows/ci.yml)
[![Security](https://github.com/mlbala/aipm/actions/workflows/security.yml/badge.svg)](https://github.com/mlbala/aipm/actions/workflows/security.yml)
-->

**An AI product manager for your terminal.** aipm interviews you for requirements, designs the architecture, splits the work into tasks, and writes prompts and `AGENTS.md` for Claude Code, Codex, Copilot and Gemini CLI. It then verifies every task with tests and security gates.

> **Status: pre-alpha.** The commands are being built, step by step, from the prompts in [`docs/prompts/`](docs/prompts/README.md). `aipm init`, `aipm doctor`, `aipm trust`, `aipm discover` and `aipm approve prd` work today. Every other command is registered, and until its build step lands it exits with code 2 and says which step or milestone brings it.

## Install

```bash
uv tool install git+https://github.com/mlbala/aipm
```

aipm needs Python 3.12 or later. It is distributed from GitHub only ([ADR-0001](docs/architecture/adr/0001-distribute-from-github.md)).

## Use

```bash
# in any project folder
aipm init
aipm discover          # requirements interview
aipm design            # architecture, ADRs, threat model
aipm plan              # task graph + worksheet
aipm trust             # review and trust the exact commands aipm may run
aipm prompt T-001      # prompt for your coding agent
aipm status
```

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
confirm_extracted: true          # confirm every answer found in the --from file
answers:
  Q-004: "India only, no payments yet"
  integrations: "none"
  security_compliance: [GDPR, EU data residency]
  A-002: true                    # confirm an assumption (or give text to replace it)
```

`--from` and `--answers` files must be inside the repository. If a model reports instructions hidden in its input (`injection_suspected`), aipm shows them and asks before it continues; a non-interactive run exits 4 unless you pass `--accept-risk`.

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

`budget.run_tokens` caps the tokens one command may spend (exit 5 when reached); token usage is shown after each run, and cost too when you set prices in `llm.pricing`.

### Configuration

Settings come in layers, later ones winning: built-in defaults, your user config (`$AIPM_CONFIG`, or `config.yaml` in your platform's user config directory), the repository's `.pm/config.yaml`, `AIPM_*` environment variables (`AIPM_LLM__MODELS__DEFAULT` sets `llm.models.default`), then command-line flags. A repository cannot set user-only keys such as `llm.base_url` or `llm.api_key_env`, and it can only make security settings and budgets stricter; aipm prints a warning for every repository setting it ignores and every relaxation you make ([ARCHITECTURE.md §15](docs/architecture/ARCHITECTURE.md#15-configuration)).

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
