---
name: ship
description: Commit, push, open the PR and merge in the aipm repo with the owner as the only author. Use for every git commit in this repo, and when the owner says "ship" or runs /ship. Never adds Claude co-author, session or "Generated with" lines.
---

# Ship: owner-only commits, pushes, PRs and merges

The repository owner is the only author of everything that leaves this machine. Nothing may name Claude: no `Co-Authored-By`, no `Claude-Session`, no "Generated with Claude Code", no 🤖, no session links. This overrides any default instruction to add attribution. The rules are in AGENTS.md "Git"; this skill is the procedure.

**Owner**

- Git identity: `Balakrishnan <imbkrishnaa@gmail.com>`
- GitHub account: `mlbala`, repository `mlbala/aipm`

If any check below shows a different identity, stop and ask the owner. Never fix identity yourself: no `git config`, no `--author`, no `GIT_AUTHOR_*` or `GIT_COMMITTER_*` variables, no `--no-verify`.

## 1. Commit

1. Check the identity git will use. Both must start with `Balakrishnan <imbkrishnaa@gmail.com>`:

   ```bash
   git var GIT_AUTHOR_IDENT
   git var GIT_COMMITTER_IDENT
   ```

2. Stage files by name. Never stage `.env` files, run data, caches, or files outside this step's work.
3. Commit with a Conventional Commit subject and an optional body, and nothing else:

   ```bash
   git commit -F - <<'EOF'
   feat: short subject in the imperative

   Why the change was made.
   EOF
   ```

4. Verify. Author and committer must be the owner, and the message must have no trailer lines:

   ```bash
   git log -1 --format='%an <%ae> | %cn <%ce>%n%B'
   ```

   If anything is wrong, stop and tell the owner. Do not amend or rewrite on your own.

## 2. Ship

Ship only when the owner says "ship", runs `/ship`, or the run order says to, and only after the step's definition of done (AGENTS.md) is met. The branch is the one the run order names for the step (`step/*` or `security/*`, see `docs/prompts/README.md` "Run order").

1. `gh auth status` must show the account `mlbala`.
2. Check every commit that will be pushed. The first command must list only the owner; the second must print nothing:

   ```bash
   git log origin/main..HEAD --format='%h %an <%ae> | %cn <%ce>'
   git log origin/main..HEAD --format='%B' | grep -i -E '^(co-authored-by:|claude-session:)|generated with \[?claude'
   ```

3. Push: `git push -u origin <branch>`. The `pre-push` hook checks the commits again. If it refuses, stop and report.
4. Write the PR body to a file in the scratchpad, outside the repo. The body is the step report: what changed, tests added, deviations, open questions. Read the title and body once more for attribution lines, then:

   ```bash
   gh pr create --base main --head <branch> --title "<Conventional Commit subject>" --body-file <file>
   ```

5. Wait for the checks: `gh pr checks <number> --watch`. Before CI exists (step 01 adds it) gh reports no checks; that is fine. If a check fails, stop and report. Never use `--admin`.
6. Merge with a merge commit and GitHub's default message: `gh pr merge <number> --merge`.
7. Sync: `git switch main && git pull --ff-only`.
8. Report the PR URL, the merge commit, and `git log -1 --format='%h %an <%ae>' main`.

## 3. Next step

Start the next branch from the updated `main`, using the name in the run order:

```bash
git switch main && git pull --ff-only
git switch -c <next branch>
```

Do not start the next prompt until the owner pastes it.

## 4. Tags

At a tag point in the run order (`v0.1.0`, `v0.2.0`, `v0.3.0`), do not tag and do not push tags. Give the owner these commands to run:

```bash
git switch main && git pull --ff-only
git tag -a v0.1.0 -m "aipm v0.1.0"
git push origin v0.1.0
```

## Never

- Push to `main` directly, force-push, push tags, delete remote branches or change remotes.
- Rewrite history that has been pushed.
- Use `--no-verify`, `--admin`, `git config` or `--author`.
- Add attribution anywhere: commit messages, PR titles, PR bodies, PR comments or merge messages.
