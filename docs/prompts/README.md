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

## Run order

Run the steps in this order, one branch each. Every step ends with `ship`, which pushes the branch, opens a PR and merges it under the owner's name only (the `ship` skill).

| # | Prompt | Branch | Paste into Claude |
|---|---|---|---|
| 1 | 01 | `step/01-scaffold` | `Read docs/prompts/01-review-and-scaffold.md and docs/architecture/reviews/01-design-review.md. Part A is done and decided. Apply decisions 1, 2 and 4 from the review file, then do Part B.` |
| 2 | 02 | `step/02-core` | `Read docs/prompts/02-core-foundation.md and follow it exactly.` |
| 3 | 03 | `step/03-discover` | `Read docs/prompts/03-llm-gateway-and-discover.md and follow it exactly.` |
| 4 | 04 | `step/04-design-plan` | `Read docs/prompts/04-design-and-plan.md and follow it exactly.` |
| 5 | 05 | `step/05-prompts-context` | `Read docs/prompts/05-prompts-and-context.md and follow it exactly.` |
| 6 | 09 | `security/redteam-v0.1` | `Read docs/prompts/09-security-red-team.md and follow it. Milestone: v0.1.` |
| | tag | `main` | The owner tags `v0.1.0`. |
| 7 | 06 | `step/06-verify` | `Read docs/prompts/06-verify-and-scan.md and follow it exactly.` |
| 8 | 09 | `security/redteam-v0.2` | `Read docs/prompts/09-security-red-team.md and follow it. Milestone: v0.2.` |
| | tag | `main` | The owner tags `v0.2.0`. |
| 9 | 07 | `step/07-build` | `Read docs/prompts/07-dispatch-and-build.md and follow it exactly.` |
| 10 | 09 | `security/redteam-v0.3` | `Read docs/prompts/09-security-red-team.md and follow it. Milestone: v0.3.` |
| | tag | `main` | The owner tags `v0.3.0`. |
| 11 | 08 | `step/08-multi-tool` | `Read docs/prompts/08-multi-tool-and-auto.md and follow it exactly.` |
| 12 | 09 | `security/redteam-v0.4` | `Read docs/prompts/09-security-red-team.md and follow it. Milestone: v0.4.` |

The owner runs the tag commands (the `ship` skill, "Tags"). Claude never tags or pushes tags.

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
4. When it reports done, review the diff yourself and run `uv run pytest -q`.
5. Reply `ship` (or run `/ship`). Claude pushes the branch, opens a PR against `main`, waits for the checks and merges it, as described in AGENTS.md "Shipping a step". Every commit, the PR and the merge carry only your name. The `pre-push` hook refuses any commit with another author or committer, or with a co-author or AI line.

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
