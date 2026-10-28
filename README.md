# aipm

<!-- Status badges arrive with the first green CI run on main:
[![CI](https://github.com/mlbala/aipm/actions/workflows/ci.yml/badge.svg)](https://github.com/mlbala/aipm/actions/workflows/ci.yml)
[![Security](https://github.com/mlbala/aipm/actions/workflows/security.yml/badge.svg)](https://github.com/mlbala/aipm/actions/workflows/security.yml)
-->

**An AI product manager for your terminal.** aipm interviews you for requirements, designs the architecture, splits the work into tasks, and writes prompts and `AGENTS.md` for Claude Code, Codex, Copilot and Gemini CLI. It then verifies every task with tests and security gates.

> **Status: pre-alpha.** The repository skeleton is in place; the commands are being built, step by step, from the prompts in [`docs/prompts/`](docs/prompts/README.md). Every command below is registered, and until its build step lands it exits with code 2 and says which step or milestone brings it.

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
