# Prompt 09: Security red-team pass

**Run after:** prompts 05, 06, 07 and 08 (once per milestone) · **Branch:** `security/redteam-<milestone>`

## Your role

You are an offensive security engineer. Your goal is to make aipm do something its security design says it must never do. Assume the attacker controls any combination of:

- `idea.md`;
- any file in the target repository, including a cloned repo's `.pm/` directory;
- every LLM response;
- coding-agent output and diffs;
- test and scanner output;
- package registry metadata.

The attacker does **not** control the user's terminal input, the user-level config, or aipm's installed code.

## Read first

- `docs/architecture/SECURITY.md` (all of it)
- ARCHITECTURE §5.1, §6, §11, §12, §13
- The code under `src/aipm/security`, `execution`, `gates`, `adapters`, `llm`, `roles`, `context`, `state`, `app/trust.py`

## Do

1. **Map the attack surface for this milestone.** List every place T2 data enters, and every place aipm executes, writes, prints or decides. Compare that list against SECURITY §13.1 and add any threat that is missing.
2. **Attack each invariant I-1 to I-7** (SECURITY §14.1). For each one, try at least three distinct techniques. Ideas:
   - **Encoding tricks:** Unicode confusables, mixed normalization, overlong UTF-8, CRLF, NUL bytes.
   - **Template and boundary attacks:** breaking the untrusted block (guessing or reusing the nonce), Jinja syntax inside data, Markdown fences.
   - **Path tricks:** symlinks created between check and use (TOCTOU), case-insensitive filesystem collisions on macOS, `.PM/` versus `.pm/`, Unicode lookalike paths, hard links.
   - **Config tricks:** relaxing security through environment variables or flags injected by repo content, YAML merge keys, duplicate keys.
   - **Git tricks:** `.gitattributes` filters, `core.*` settings in `config.worktree`, `includeIf` directives, submodules.
   - **Process tricks:** a child that changes its process group, a process that ignores SIGTERM, output floods on stderr, slow-drip output that keeps a pipe open.
   - **Agent tricks:** context-file poisoning that survives `sync-context`, `AIPM-BLOCKED` abuse, `--resume` session poisoning between attempts.
   - **Scheduler tricks:** ownership globs that look disjoint but overlap (`src/a*` versus `src/ab/**`), case variants.
   - **Budget tricks:** many cheap retries, parallel overspend between checks.
3. **For every successful or plausible attack:**
   - write a failing test in `tests/security/`;
   - fix the code;
   - confirm the test passes;
   - add the case to the corpus.
4. **Fuzz:** extend the hypothesis strategies for the path validators, the command policy, the sanitizer, managed blocks and the schema loaders. Run with `--hypothesis-profile=ci-long` (define it: at least 2,000 examples).
5. **Write `docs/security/reviews/<milestone>.md`** with:
   - the scope;
   - the attacks tried, in a table with the result for each;
   - the findings, with severity and fix commits;
   - residual risks: update SECURITY §15 if one changed;
   - recommendations for the next milestone.

## Rules

- Do not weaken any control to make a test pass. If a control is wrong by design, stop and propose a design change.
- Use only local fake secrets and stub binaries. Never use the network or real credentials.

## Definition of done

- [ ] Every invariant was attacked with at least three techniques, and the results are recorded.
- [ ] All findings are fixed and tested, or explicitly accepted by me as residual risk.
- [ ] All checks pass.
- [ ] The review document is committed.
