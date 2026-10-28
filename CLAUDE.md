@AGENTS.md

## Claude Code specifics

- Start every build prompt in plan mode. Present the plan and wait for "go" before editing files.
- When a step is finished, ask the `security-reviewer` subagent to review the diff (`git diff main...HEAD`, or the staged changes). Fix the high and critical findings before reporting.
- Use the commands in AGENTS.md. Do not install global tools. If a tool such as `srt`, `semgrep` or `gitleaks` is missing, write the code so it degrades as specified, and tell me what to install.
- Commit messages contain only the Conventional Commit subject and body. PR titles, PR bodies and merge messages contain only the owner's content. Add no co-author, session, 🤖 or "Generated with Claude Code" lines anywhere. The owner is the only author.
- `.claude/settings.json` turns off all Claude attribution (`attribution.commit` and `attribution.pr` are empty, `attribution.sessionUrl` is false). Never change those values.
- Use the `ship` skill (`.claude/skills/ship/SKILL.md`) for every commit, push, PR and merge. Push, open PRs and merge only when I say "ship" or run `/ship`.
- Keep context small: read the ARCHITECTURE and SECURITY sections the prompt names, not the whole documents, unless you need more.
