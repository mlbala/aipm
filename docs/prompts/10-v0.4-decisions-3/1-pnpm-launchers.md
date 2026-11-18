# Item 1: pnpm reached through another launcher

Branch: `security/v0.4-d3-1-pnpm-launchers` · Severity: low · Read `docs/prompts/10-v0.4-decisions-3/README.md` "Rules for every item" first.

## Your role

You are a security engineer closing one open low finding in aipm. Keep the change small and fail closed.

## Read first

- AGENTS.md, and SECURITY.md §9 (gates, prepare) and §10 (command policy).
- `docs/security/reviews/v0.4-decisions-progress.md`, "Session 4" (what pnpm 10.34.9 does with each setting).
- ADR-0031 and ADR-0032.
- Code: `src/aipm/gates/command_gate.py` (`refuse_pnpm_install_before_run`, `run_command_gate`, `run_prepare`), `src/aipm/execution/package_cache.py` (`pnpm_env`, `cache_args`), `src/aipm/security/command_policy.py` (`program_name`, `HARD_DENIED`, `RUNNERS`, `FETCH_AND_RUN`), `src/aipm/state/pnpm_workspace.py`.

## The finding

Session 4 gives a gate whose `argv[0]` is `pnpm` two protections: `pnpm_env` (`NPM_CONFIG_WORKSPACE_DIR=<worktree>`, `npm_config_` and `pnpm_config_verify_deps_before_run=error`), and `refuse_pnpm_install_before_run`, which refuses (exit 6) a repository whose `pnpm-workspace.yaml` asks pnpm to install before a script. Both key on `program_name(argv[0]) == "pnpm"`. A user-configured gate that reaches pnpm another way gets neither:

- `corepack pnpm test` (corepack is not denied);
- `node <path>/pnpm.cjs test`, or `node` running pnpm's `bin/pnpm.cjs` from `node_modules`;
- `npm test` or `npm run x`, where the repository's `package.json` script calls `pnpm`.

`npx` and `pnpx` are already hard-denied. A committed `pnpm-workspace.yaml` with `verifyDepsBeforeRun: install` would then make pnpm install, with the gate's network, during a gate.

## What to do

1. **Check by hand first, on pnpm 10.34.9** (`.github/sandbox/node_modules/.bin`) and the local npm. Record each result:
   - Is `NPM_CONFIG_WORKSPACE_DIR` or `pnpm_config_verify_deps_before_run` visible to pnpm when it starts through `corepack pnpm`, `node …/pnpm.cjs` and an npm script? (Expected: yes, the environment is inherited.)
   - Does npm warn or fail on `npm_config_verify_deps_before_run`, `pnpm_config_verify_deps_before_run` or `NPM_CONFIG_WORKSPACE_DIR` in its environment (for example "Unknown env config")? Check `npm test`, `npm run`, and `npm ci` in prepare.
   - Do uv, go and cargo gates mind these variables? (Expected: they ignore them.)
2. **Give the variables to every gate and every prepare**, whatever `argv[0]` is, if step 1 shows no tool warns or behaves differently. If npm warns, give them to every gate except `npm`-led ones and record the gap for npm scripts as a residual risk. Keep `cache_args` (the flags) for `pnpm` only.
3. **Refuse what aipm can recognise.** Extend the `pnpm-workspace.yaml` check (`refuse_pnpm_install_before_run`) to run for a gate whose argv reaches pnpm through `corepack` or a `node` script whose file name is `pnpm.cjs`, `pnpm.js` or `pnpm.mjs`. Simplest correct option: run the check for every gate when the worktree has a `pnpm-workspace.yaml`, since `read_settings` is cheap and fails closed. Choose in the plan and say why.
4. **corepack and the command policy.** Check whether `corepack pnpm dlx …`, `corepack npx …`, `corepack pnpm@<version> …` or `corepack install` pass `check_command`. Also check plain `corepack pnpm test` when the repository's `package.json` `packageManager` names a pnpm version that is not installed, and when it uses the URL form: corepack downloads and runs that pnpm before pnpm sees any of aipm's variables. Record what `COREPACK_ENABLE_NETWORK=0` and `COREPACK_ENABLE_DOWNLOAD_PROMPT` change. Any that let a gate fetch and run code is a separate finding: write the failing test, then stop and show the owner the policy change you propose (rule 6: deny lists need the owner).
5. Update `pnpm_env`'s and `refuse_pnpm_install_before_run`'s docstrings, the README's pnpm gate paragraph, and SECURITY.md §9 if the rule changes. Add a residual-risk line for anything left (npm scripts, if npm warns).

## Tests

- `tests/security/test_v04_d3_1_pnpm_launchers.py`: the environment of a gate led by `corepack`, `node`, `npm`, `uv` and `go` (stub binaries in `tests/fakes/bin/`); the refusal for `corepack pnpm test` and `node …/pnpm.cjs test` with `verifyDepsBeforeRun: install`, with a `${…}` key, and with an unreadable file; no refusal with `verifyDepsBeforeRun: error`; prepare's environment.
- `tests/security/test_real_sandbox_pnpm_launchers.py`: with real pnpm and srt, a gate `node <pnpm.cjs> test` in a worktree whose `pnpm-workspace.yaml` sets `verifyDepsBeforeRun: install` is refused, and with `error` it runs without installing (no `node_modules` appears). Parametrize srt and no-srt as `test_real_sandbox.py` does.

## Done when

All of README "Rules for every item" is met, and the report states which launchers are covered by the environment, which by the refusal, and what is left.
