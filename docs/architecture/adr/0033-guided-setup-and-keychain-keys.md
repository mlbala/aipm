# ADR-0033: Guided setup, one user config path, and keys from the OS keychain

- **Status:** Accepted
- **Date:** 2026-11-24
- **Source:** owner feedback on first-run setup; ARCHITECTURE.md §15, §16; SECURITY.md §6 rule 5, §8; security review of `step/docs-provider-keys`

## Context

A new user has to do three things by hand before the first `aipm discover`: find the user config path for their OS (`~/Library/Application Support/aipm/config.yaml` on macOS, `~/.config/aipm/config.yaml` on Linux), write YAML into it for any provider but Anthropic, and export the key in their shell profile. Users who clone the repository also try to keep a `.env` in the clone and run aipm from its root, where aipm works on its own source.

Comparable tools are easier because they read the provider, URL and key from a `.env` in the working directory. aipm must not do that: SECURITY.md §6 rule 5 and invariant I-8 exist because a cloned repository could otherwise send the user's key and code to its own server. This ADR keeps that rule and every user-only key unchanged, and removes the manual steps instead.

SECURITY.md §8 allowed keys "from the OS keychain through the optional `keyring` extra", and `pyproject.toml` declares the extra, but no code read it.

## Options

1. Documentation only (the README quick start and CONTRIBUTING "Try your changes", already on `step/docs-provider-keys`).
2. Option 1, plus a guided `aipm setup`, one user config path on every OS, and keys read from the OS keychain.
3. Option 2, plus a user config file kept at the root of a source checkout (`<checkout>/aipm.config.yaml`). Rejected: the file would hold user-only keys inside a work tree that coding agents edit, and being gitignored it shows in no `git status` or diff a reviewer reads. A prompt-injected agent working in the aipm checkout could write `llm.base_url` there, and git overwrites ignored files on checkout and merge, so a branch that tracks the file replaces it silently. Contributors use `AIPM_CONFIG=~/.config/aipm/dev.yaml` instead.
4. Read the provider, URL and key from the project's `.env` or `.pm/config.yaml`. Rejected: it reverses I-8 and reopens the config-redirection attack that SECURITY.md §14 tests for.

## Decision

Option 2, in three parts. Nothing here changes a key class, what a repository's `.pm/config.yaml` may set, what `AIPM_*` variables may set, or the rule that the user config lies outside the repository aipm works on (by inode). The trust store's location does not change.

### 1. One user config path

The default user config becomes `~/.config/aipm/config.yaml` on macOS. `XDG_CONFIG_HOME` is not read there: today only `AIPM_CONFIG` and `HOME` can move the macOS path, and this must not add a variable a repository `.env` can set. (An earlier draft built the path from the password database; the implementation keeps `HOME`, which already moved the old path and already warns when it is not the account's home, so the exposure is unchanged and tests can still isolate the user config.) Linux keeps `$XDG_CONFIG_HOME/aipm/config.yaml`, else `~/.config/aipm/config.yaml`. `AIPM_CONFIG` still wins, with its warning.

On macOS, if only the old `~/Library/Application Support/aipm/config.yaml` exists, aipm reads it and prints a one-line note to move it; if both exist, the new one is read and aipm warns that the old one is ignored. Every existing check on the user config (absolute, regular file, outside the repository by inode, R-25) applies to whichever file is read.

### 2. `aipm setup`

A new interactive command (questionary, already a dependency):

1. Asks for the provider: Anthropic, OpenAI, another OpenAI-compatible service, or a local Ollama server. A base URL must be `https` (or `http` to a loopback address only) and carry no user info and no query string, so a key pasted into the URL prompt is refused.
2. Asks for the models, with the current values as defaults, and the key-variable name, with the provider's usual name as the default; the name must pass the existing `EnvName` check.
3. Asks for the API key with hidden input, and offers to store it in the OS keychain (part 3). Leaving it blank keeps the key in the environment, as today. aipm never writes a key to a file.
4. Shows the target path, the environment variable that chose it (if any), and the resulting `llm:` block, and writes only after an interactive yes. `--yes` never skips this confirmation, as with trust (SECURITY.md §6 rule 4).
5. Ends by telling the user to run `aipm doctor`, which shows the config, the provider, the models and where each key comes from.

The write path:

- An existing file is first read with `load_yaml` (aliases and tags rejected, 1 MiB cap) and validated. Setup changes only `llm.provider`, `llm.base_url`, `llm.api_key_env` and `llm.models`, and validates the whole result again before writing.
- The result passes the pre-write secret scan; a match refuses the write.
- The directory is created with mode 0700. Each path component is opened without following symbolic links, and the parent must be owned by the user and not group- or world-writable.
- The file is written atomically with mode 0600.
- The target is refused (exit 6) when it lies inside the current repository or inside any git work tree. This is stricter than the read path, which refuses only a config inside the target repository: a user whose home directory is a dotfiles repository has to write the file by hand, or point `AIPM_CONFIG` outside the work tree. That fails closed.

Without a terminal, `aipm setup` exits 2 and names the README section.

`aipm doctor` also prints the user config path in use (or "not found: defaults in use"), the provider, the models, and for the provider's key variable whether it is set in the environment, in the keychain, or nowhere. Values are never shown.

### 3. Keys from the OS keychain

**Which names.** The keychain entry is `service="aipm", username=<variable name>`. Only two kinds of name are ever looked up: the user config's `llm.api_key_env`, and the built-in `required_env` names of the shipped adapters. `pass_env` names and any name from a repository are never looked up.

**Lookup order.** The environment comes first; an empty value counts as unset. The keychain comes next. aipm warns when the environment and the keychain both hold a value and the two differ, since a repository `.env` loaded into the shell can override the key.

**Where the value goes.**

- The LLM gateway uses it.
- Dispatch puts it into the constructed environment of a coding agent, only under the names that agent's adapter declares.
- It is never written into aipm's own `os.environ`.
- It is never resolved for gate, scanner or prepare processes, which keep getting no API keys (SECURITY.md §8).

**Redaction.** Every value resolved from the keychain is added to the exact-value set of every redactor: the gateway, `StateStore`, logging, run artifacts and the pre-write secret scan. Pattern rules alone would miss keys such as Azure's 32-hex keys or custom gateway tokens. The test that checks redactors are built from the full environment is extended to keychain values.

**No backend discovery.** keyring's own selection (`keyring.get_password`, `PYTHON_KEYRING_BACKEND`, `KEYRING_PROPERTY_*`, a `keyringrc.cfg` under a `HOME` or `XDG_CONFIG_HOME` a repository `.env` can set, and `keyring.backends` entry points) would choose which code runs inside aipm, past `--no-plugins`. aipm does not use keyring at all. On macOS it runs `/usr/bin/security` through `run_safe` (no `ctypes`, which aipm bans), with a timeout and a constructed environment holding only `PATH=/usr/bin:/bin`, `LANG=C` and a `HOME` from the password database, so a `HOME` set by a repository `.env` cannot point it at another keychain. The key reaches `security -i` on stdin, never in argv, and must match `[A-Za-z0-9._~+/=:-]{8,4096}`, so it never needs quoting. Security tests check that no aipm module imports keyring, that keyring's variables and a planted `keyringrc.cfg` change nothing, and what argv, stdin and environment `security` gets.

**No prompts, fail closed.**

- A lookup runs with a timeout.
- On macOS it never shows the authorization dialog: aipm stores keys with `security` itself, so the item's access list trusts `security`, and the lookup runs `security` too. A lookup that fails for any reason counts as unset.
- On Linux it never unlocks a locked collection; only `aipm setup` may ask to unlock.
- A missing, locked or failing backend counts as unset, and the command fails closed with the existing missing-key error.
- Note (2026-11-26): whether a lookup on a **locked** macOS Keychain shows the unlock prompt or fails is not yet tested. Since then, only the commands that may call the model or start a coding agent, and `doctor`, read keys (SECURITY §8), so other commands never trigger a lookup.

**Residual risk.** On macOS, an item aipm stores trusts `/usr/bin/security`, so any program running as the user can read it through `security` without a prompt. On Linux, Secret Service is reached over the D-Bus session bus. So repository code that runs **outside** a sandbox, as the same user, can read an `aipm` keychain item without a prompt. This is no worse than today's alternative: an exported key in a shell profile is equally readable by such code. Inside `srt`, `Library/Keychains` and `.local/share/keyrings` are already denied (`execution/sandbox.py`). Security tests are to check that a sandboxed gate cannot read an `aipm` item (not yet built: `srt` is not available where this was implemented; see owner decision 2 below):

- macOS: `security find-generic-password -s aipm`
- Linux: `secret-tool lookup service aipm`

On Linux, keychain keys are refused (exit 8) unless gates are shown unable to reach the D-Bus session bus. That is shown either by a sandbox probe at start-up or by the security test above, run against the `srt` version in use. With no sandbox at all, Linux keychain keys are always refused, and the environment remains the way to supply a key. This risk is added to SECURITY.md §15.

The Linux probe is not built yet, so in this implementation Linux uses no keychain at all: `aipm setup` skips the keychain step and prints how to set the key, and lookups use the environment only. Whether `srt` keeps a gate's `security` away from the keychain daemon on macOS is not yet tested either (SECURITY.md R-27).

## Consequences

- An Anthropic user still needs only an exported `ANTHROPIC_API_KEY`, or now `aipm setup` once. Other providers need `aipm setup` once instead of hand-written YAML.
- macOS users with a config at the old path keep working, with a note to move it.
- The README's shell-function setup keeps working unchanged: it puts the key in aipm's environment, which is looked up first, and `doctor` reports it as set in the environment. Its keychain items (`service=anthropic-api-key`) are not the ones aipm reads (`service=aipm`). The README now recommends `aipm setup` and keeps the function as the alternative on Linux.
- A contributor keeps their settings in `~/.config/aipm/config.yaml` (or `AIPM_CONFIG`) and runs `uv run aipm -C <project> …` from the clone.
- There is one new write path outside `.pm/`: the user config, written only by `aipm setup` after an interactive confirmation. Security tests cover:
  - every write-path rule in part 2;
  - the keychain rules in part 3: names, redaction, backend pinning, no prompts, and the sandbox;
  - that a repository `.pm/config.yaml` or an `AIPM_*` variable still cannot set any user-only key.
- The implementation updates:
  - ARCHITECTURE §15: the macOS path.
  - ARCHITECTURE §16: `setup` and the new `doctor` lines.
  - SECURITY.md §8: the keychain lookup order, the allowed names and redaction.
  - SECURITY.md §13 and §15: the new threats and the residual risk.

## Owner decisions (2026-11-24)

1. `keyring` (pure Python wheels, no install scripts; on Linux it pulls in `SecretStorage` and `jeepney`) was approved as a runtime dependency. The implementation turned out not to need it: macOS uses `/usr/bin/security`, and Linux uses no keychain yet. No dependency was added; the existing optional `keyring` extra is unchanged and unused.
2. The checkout config file (option 3) is dropped, as the security review recommended.

## Owner decisions on the implementation (2026-11-25)

1. Approved: part 1 builds the macOS path from `HOME`, not from the password database as first accepted. `HOME` already moved the old path and already warns when it is not the account's home, so the exposure is unchanged, and tests can still isolate the user config. `XDG_CONFIG_HOME` is not read on macOS, for the new path or the old one (the old one is built without platformdirs, which reads it).
2. Approved: the macOS Keychain is used by default although the sandbox test above does not exist yet. Without `srt`, gates and prepare steps can read an `aipm` item through `security`, as they could read a key kept in a shell profile; under `srt`, whether `security` can still reach the keychain daemon is untested (SECURITY.md R-27). The owner chose to keep the macOS Keychain on by default, with `aipm setup` the same command on every platform (the Keychain on macOS, an environment variable elsewhere), and the risk recorded as R-27. The alternative, the Keychain only under `srt` or `security.require_sandbox: true`, was declined.
3. Approved: `tests/security/test_redteam_v01.py::test_review_xdg_config_home_cannot_put_the_user_config_in_the_repo` checks each platform. On Linux, `XDG_CONFIG_HOME` still chooses the user config and a planted one in the repository is refused (exit 6), as before. On macOS, where it is no longer read, the test checks that the planted file is never read and its URL never used.
