# aipm

**An AI product manager for your terminal.** aipm interviews you for requirements, designs the architecture, splits the work into tasks, and writes prompts and `AGENTS.md` for Claude Code, Codex, Copilot and Gemini CLI. It then verifies every task with tests and security gates.

> Status: in design. The first release (v0.1) is being built from the prompts in [`docs/prompts/`](docs/prompts/README.md).

```bash
# install (once v0.1 is tagged)
uv tool install git+https://github.com/mlbala/aipm

# in any project folder
aipm init
aipm discover          # requirements interview
aipm design            # architecture, ADRs, threat model
aipm plan              # task graph + worksheet
aipm prompt T-001      # prompt for your coding agent
aipm status
```

- Design: [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md)
- Security model: [docs/architecture/SECURITY.md](docs/architecture/SECURITY.md)

License: Apache-2.0
