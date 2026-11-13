Prompt 09 (v0.4): Final security red-team pass before v0.4.0

Milestone: v0.4 · Branch: security/redteam-v0.4 · Run as three parts, each in a new conversation tab on the same branch.

This file narrows docs/prompts/09-security-red-team.md to v0.4. That base prompt's method, rules and definition of done still apply. Where the two differ, this file wins.

Your role

You are an offensive security engineer doing the last pass before v0.4.0. This is the first release that ships:

all four coding agents;
aipm auto;
plugins;
OpenTelemetry;
the go and rust-cargo stacks;
a release pipeline that publishes signed artifacts.

Your goal is to make aipm break an invariant in SECURITY.md §14.1 (I-1 to I-8), or a promise in §2 (SG-1 to SG-7).

The attacker controls everything in the base prompt, plus:

the output of codex, gemini and copilot: JSON events, final messages, exit codes, timing;
anything an agent writes into its own config home (CLAUDE_CONFIG_DIR, CODEX_HOME, GEMINI_CLI_HOME) during an attempt;
go.mod, go.work, Cargo.toml, .cargo/config*, build.rs, toolchain files, and registry metadata from the Go module proxy and crates.io;
pull requests from forks to mlbala/aipm: titles, branch names, commit messages, changed files;
a target repository's own virtualenv, .pth files and PATH entries.

The attacker does not control:

the user's terminal input;
the user-level config;
aipm's installed code and its site-packages (where plugins live);
the OTEL_* variables the user sets.
Read first (every part)
AGENTS.md.
docs/prompts/09-security-red-team.md: the method and rules.
docs/architecture/SECURITY.md §2, §6, §9, §10, §13, §14 and §15.
docs/security/reviews/v0.3.md: what was already attacked, and §7, its recommendations for v0.4.
docs/adapters.md and ADR-0023 to ADR-0030.
If it exists, docs/security/reviews/v0.4-progress.md: what earlier parts found.

Read code only for the part you are on.

Rules for this pass
Test first: for every finding, write a failing test in tests/security/, fix the code, check that the test passes, and add the case to the corpus.
One commit per finding: security: <what was fixed>.
No weakening: never weaken a control or a test to make something pass. If a control is wrong by design, stop and propose a design change with an ADR.
No unasked changes: do not change the release workflow, the trust model or the command policy's hard-deny list without showing me the change first.
Real tools need permission. Use real codex, gemini, copilot, srt or scanners only if they are installed. Print their versions first. Ask me before any real agent dispatch: each one spends money on my accounts. If I agree, use a throwaway repository and --budget 1.
End of each part: append your findings to docs/security/reviews/v0.4-progress.md, commit, and stop.
Part 1: the new coding-agent surfaces

Code to read: src/aipm/adapters/ (all of it), execution/sandbox.py, context/, and the stub binaries and contract suite in tests/fakes/bin/.

1. Flag drift. For each of Codex, Gemini and Copilot:

If the tool is installed, compare its real --help with docs/adapters.md and the adapter's detect().
Any safety flag that is missing, renamed or has new semantics is a finding.
Also check flag aliases, --flag=value forms, repeated flags, and whether the CLI accepts abbreviated flag prefixes. check_forbidden_flags must catch every form that reaches the same behaviour.

2. Environment equivalents. Find environment variables and config keys that change approval mode, the sandbox, network access, extensions, rules or the config home: CODEX_*, GEMINI_*, COPILOT_*, GH_*, NODE_OPTIONS and similar. Prove that the scrubbed environment and the aipm-written settings block every one of them.

3. Output parsing. Attack parse_result for Codex and Gemini with:

forged or duplicate final events;
events after the final one;
lines over 10 MB and no trailing newline;
invalid UTF-8;
ANSI/OSC escapes in messages;
a fake AIPM-BLOCKED line in the middle of the output;
negative or huge token counts.

Neither tool reports cost, so each attempt is charged its task budget. Show that no output can lower that charge.

4. Config homes and persistence. An agent writes into its config home a file that its next attempt, or another tool, would load: Codex rules or execpolicy files, config.toml, AGENTS.md or skills; Gemini settings.json, extensions, GEMINI.md, commands or hooks.

Prove that each attempt starts from a clean, aipm-written home.
Prove that token files outside it stay unreadable (.codex/auth.json, .gemini/oauth_creds.json and the others in sandbox.py).
Also check v0.3 recommendation 2: every adapter must get the ADR-0024 read rules.

5. Workspace tricks:

.gemini/ or .env* in a subdirectory instead of the worktree root;
a nested AGENTS.md or GEMINI.md deeper in the tree;
.agents/skills created by the agent mid-attempt;
symlinks to any of these;
case variants on macOS.

6. Memory-file import injection. CLAUDE.md and GEMINI.md import files with @path lines. Try to get an @ import into a generated managed block through T1 or T2 text, for example a component name or an acceptance criterion containing @~/.ssh/id_rsa or @../../.env. If you succeed, the agent loads a secret into its context on every session. Do the same for skill front matter (allowed-tools, scripts) and .github/copilot-instructions.md.

7. Copilot render-only. Prove there is no path to dispatch: not --tool copilot through build, run or auto, not a plugin adapter named copilot, not config.

8. Malicious-agent scenarios. Run every SECURITY.md §14.3 scenario against each stub. Add tool-specific scenarios for anything above that the suite lacks.

Write the progress note and stop.

Part 2: automation and extension surfaces

Code to read: app/auto.py, plugins/loader.py, observability/, config/stacks/{go,rust-cargo}.yaml, security/command_policy.py, security/supply_chain.py, security/network.py.

1. aipm auto:

Trust is checked first, but the execution surface changes in the middle of a run (greenfield design copies the stack template after G2). Prove that build re-checks trust after that change, with no time-of-check/time-of-use gap.
Try --yes, --accept-risk, --accept-stale and --non-interactive in every combination.
Try a step that loops without progress, a step that changes .pm/ behind auto's back, Ctrl-C in each phase, and exit-code mapping for every exit code (2–8 and 130).
auto must never write trust.

2. Plugins. The loader reads only aipm's own site-packages. Try to load attacker code through:

PYTHONPATH, PYTHONUSERBASE, PYTHONSTARTUP or PYTHONHOME;
a .pth file or sitecustomize/usercustomize;
a dist-info with entry points in the user site or in the target repo's .venv;
a target-repo .venv/bin that comes first on PATH;
importlib metadata caches.

Also check:

a plugin that shadows a built-in adapter, gate or stack name must be refused or loudly reported, never silently preferred;
a plugin stack YAML must still pass the full command policy, with no hard-denied program and no new placeholder;
--no-plugins must hold everywhere, including in auto and in doctor.

3. OpenTelemetry:

Try to get T2 text or secrets into spans through span names, resource attributes (OTEL_RESOURCE_ATTRIBUTES, OTEL_SERVICE_NAME), events, links or baggage.
Check that exporter headers (OTEL_EXPORTER_OTLP_HEADERS, which often hold tokens) never appear in logs or doctor output.
No repo config may set the endpoint or turn tracing on.
Re-test the exception-recording fix from step 08.

4. Go and Rust stacks:

Flags through the environment: GOFLAGS (-toolexec, -exec, -modfile), GOENV, GOPROXY, GONOSUMCHECK/GONOSUMDB/GOFLAGS=-mod=mod, GOTOOLCHAIN (toolchain download), go.work replace directives.
Cargo config pickup: .cargo/config.toml in a subdirectory or a parent directory (cargo reads config upward from the working directory, and from CARGO_HOME); [alias], [target.*.runner], [build] rustc-wrapper; rust-toolchain.toml that triggers a rustup download.
The nextest config: the {nextest_config} placeholder's path validation; NEXTEST_* variables; a test that writes a fake JUnit report where aipm reads it.
Borrowed network profiles: a gate or prepare command whose program borrows another program's network profile (ADR-0019, registries per program).

5. The deps gate for Go and crates:

module-path lookalikes, such as github.com/stretchr/testify against a homoglyph or a different owner;
replace directives to local paths or other modules;
[patch] sections;
git = and path = dependencies, including paths outside the worktree;
go.sum and Cargo.lock edits without manifest edits;
registry responses that are slow, huge, malformed or that redirect.

Write the progress note and stop.

Part 3: release, supply chain, whole system and the report

1. Workflows (.github/workflows/*.yml, .github/dependabot.yml, .github/release/):

Run zizmor.
Look for pull_request_target or workflow_run misuse, and for untrusted expressions (PR title, branch name, commit message) inside run: steps.
Look for cache or artifact poisoning between jobs and workflows.
Check per-job permissions: is id-token: write granted only where it is needed?
Check that the release can run only from a v* tag in mlbala/aipm, not from a fork, and that the build job has no write permissions.
Check that the hash-pinned build constraints are actually enforced.
Check that the attestation subjects cover every published file, including SHA256SUMS and the SBOM.
Check that the scorecard workflow's permissions are minimal.
Recommend GitHub settings I should turn on, such as tag rulesets and required reviews for workflow changes, as a list for me. You cannot change GitHub settings.

2. install.sh:

how the tag is pinned and checksummed;
what runs before the user confirms;
set -eu failure paths;
what happens on an interrupted download;
behaviour when uv already exists at an unexpected path.

3. Hostile-world end-to-end test. Add one test that runs aipm auto --yes (after a correct manual aipm trust --confirm) over the clinic example with:

a hostile idea.md;
a hostile repository (planted .cargo/config.toml, .gemini/, a conftest.py that phones home);
FakeLLM fixtures with injection attempts and injection_suspected entries;
a hostile stub agent for each dispatchable tool.

It must assert I-1 to I-8 and stop with the documented exit codes. If it is too slow for every CI run, mark it for the nightly ci-long run.

4. Open items. For each v0.3 recommendation (1–7) and each open decision (v0.2 O-1 and O-2; v0.1 O-1 to O-4), state whether it is done, not done, or needs a decision. For each one that needs a decision, give me the options with their trade-offs and wait for my choice. Do not implement decisions yourself.

5. Residual risks. Re-check that R-1 to R-17 in SECURITY.md §15 are still accurate after v0.4. Update the wording and add new risks. Each new risk needs an ID, why it remains, and a recommendation.

6. Fuzzing. Run uv run pytest --hypothesis-profile=ci-long tests/property tests/security. Record the duration and results in the review.

7. Real enforcement. For each of srt, gitleaks, semgrep, osv-scanner, trivy, codex, gemini and copilot, record whether it was installed and its version. Say which tests ran against the real tool and which only checked the profile as written.

8. Write docs/security/reviews/v0.4.md. Use the same structure as v0.3.md, sections 1–7. Fold in the progress note, then delete the progress note. Add a section 8. Release readiness, which contains:

a go or no-go verdict for v0.4.0;
the blocking items, if any;
the exact checks I should run by hand after tagging.

9. Update CHANGELOG.md. Add the fixes under "Unreleased → Security", in the style already used there.

Then run every check in AGENTS.md, ask the security-reviewer subagent to review the branch diff and fix its high and critical findings, and stop. Do not tag.

Definition of done
 Parts 1–3 are done. Every invariant was attacked against every dispatchable adapter, and the results are in the review.
 Every finding is fixed and tested, or explicitly accepted by me as a residual risk.
 The hostile-world E2E test exists and passes.
 Open decisions are presented to me, not decided for me.
 All checks pass; ci-long ran; the security-reviewer review is clean.
 docs/security/reviews/v0.4.md has a release-readiness verdict.