# Build prompts for Claude Code

These prompts build aipm step by step, following [ARCHITECTURE.md](../architecture/ARCHITECTURE.md) and [SECURITY.md](../architecture/SECURITY.md). Each prompt is a single Claude Code session.

| # | Prompt | Milestone | Rough effort |
|---|---|---|---|
| 01 | [Review the design and scaffold the repo](01-review-and-scaffold.md) | v0.1 | 1 day |
| 02 | [Core: state, config, security primitives, `init`, `doctor`, `trust`](02-core-foundation.md) | v0.1 | 3 days |
| 03 | [LLM gateway, interviewer, `discover`, PRD](03-llm-gateway-and-discover.md) | v0.1 | 3 days |
| 04 | [`design`, `plan`, phase engine, `status`, `approve`](04-design-and-plan.md) | v0.1 | 3 days |
| 05 | [Prompt compiler, Claude Code adapter, `prompt`, `sync-context`; v0.1 release](05-prompts-and-context.md) | v0.1 | 2–3 days |
| 06 | [`verify`, `scan`, gates, sandbox, post-change checks](06-verify-and-scan.md) | v0.2 | 4 days |
| 07 | [`run`, `build`, `merge`: the dispatch harness](07-dispatch-and-build.md) | v0.3 | 5 days |
| 08 | [Codex, Copilot and Gemini adapters, `auto`, plugins, release pipeline](08-multi-tool-and-auto.md) | v0.4 | 4 days |
| 09 | [Security red-team pass (run after 05, 06, 07 and 08)](09-security-red-team.md) | each | 1 day |

## How to run a prompt

```bash
cd aipm
git switch main && git pull --ff-only     # if the repo has a remote
git switch -c step/02-core                # one branch per prompt
claude                                    # start Claude Code in the repo
```

In Claude Code:

1. Run `/clear` so each prompt starts with a fresh context.
2. Switch to plan mode with Shift+Tab, then type:

   ```
   Read docs/prompts/02-core-foundation.md and follow it exactly.
   ```
3. Review the plan Claude produces. Answer its questions, then reply `go`.
4. When it reports done, review the diff yourself, run `uv run pytest -q`, then merge the branch: `git switch main && git merge --ff-only step/02-core`.

## Working method (every prompt follows this)

1. **Read** `AGENTS.md`, plus the ARCHITECTURE and SECURITY sections the prompt names.
2. **Plan, then wait.** Write a plan with:
   - the files to create or change;
   - the public interfaces;
   - any new dependencies, with justification;
   - the tests you will write, including security tests;
   - any conflicts or gaps you found in the design docs.

   Then **wait for "go"**.
3. **Implement in small commits**, using Conventional Commits. Write tests first for security modules.
4. **Run all checks** from AGENTS.md. Fix every failure. Never weaken an existing test.
5. **Security review.** Ask the `security-reviewer` subagent to review the diff. Fix the high and critical findings and list the rest.
6. **Report:**
   - what was built;
   - the tests added (with counts);
   - coverage for the security modules;
   - deviations from the design, with the ADRs written for them;
   - open questions;
   - what I should verify by hand.

   Then **stop**. Do not start the next prompt.

## Rules that apply to every prompt

- `AGENTS.md` security rules 1–12 are non-negotiable.
- If the design is ambiguous, pick the safer option and note it in the report.
- If the design seems wrong, stop and ask. Do not improvise around it.
- Anything in a prompt's "Out of scope" list stays out, even when it is easy to add.
