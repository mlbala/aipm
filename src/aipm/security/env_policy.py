"""Environment variable names `dispatch.tools.<tool>.pass_env` may never hand an agent (N-2).

`pass_env` is a user-only key, but some names would undo what aipm sets up around an agent: a
loader or interpreter option that runs code before the agent does, the shell options of the
sandbox's shell (ADR-0020), a git, Go, Cargo, npm, pip or uv setting that changes where code
comes from, the variables aipm sets for the agent itself, a file or prefix the agent runs, or a
switch that turns the agent's own approvals off. They are refused when the config loads
(exit 6), as forbidden agent flags are refused even from the user config (red-team v0.4, N-2;
SECURITY.md §8).
"""

DENIED_NAMES: frozenset[str] = frozenset(
    {
        # Process basics aipm sets or copies itself.
        "PATH", "HOME", "TMPDIR",
        # Code loaded before the program runs.
        "NODE_OPTIONS", "NODE_PATH",
        "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE",
        "PERL5OPT", "PERL5LIB", "PERLLIB", "PERL5DB", "RUBYOPT", "RUBYLIB",
        "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
        # Shell start-up files and options (srt runs commands through a shell, ADR-0020), and
        # the shell an agent runs its commands with.
        "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "IFS", "PS4", "PROMPT_COMMAND", "ZDOTDIR",
        "SHELL",
        # Where git (and other tools) read their user configuration: `$XDG_CONFIG_HOME/git/config`.
        "XDG_CONFIG_HOME",
        # Go and Rust settings that change the toolchain, the module source or the compiler.
        "GOFLAGS", "GOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOINSECURE", "GOTOOLCHAIN",
        "GOENV", "GOSUMDB", "GOPRIVATE", "GONOPROXY", "GOWORK", "GOROOT", "GOMODCACHE",
        "CC", "CXX",
        "RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC", "RUSTC_WORKSPACE_WRAPPER", "RUSTDOC", "RUSTDOCFLAGS",
        # The agents' homes and the settings aipm gives them (adapters/*.py).
        "CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "GEMINI_CLI_HOME", "GEMINI_SANDBOX",
        "DISABLE_AUTOUPDATER", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        # Files and prefixes the agents run or read as settings before aipm's.
        "CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_ENV_FILE",
        # srt makes the dir these name writable, as the command's TMPDIR (execution/sandbox.py).
        "CLAUDE_CODE_TMPDIR", "CLAUDE_TMPDIR",
        "GEMINI_CLI_SYSTEM_SETTINGS_PATH", "GEMINI_CLI_SYSTEM_DEFAULTS_PATH",
        # An agent's own switch that approves every tool call.
        "COPILOT_ALLOW_ALL",
    }
)  # fmt: skip
"""Refused as written (environment names are case-sensitive)."""

DENIED_PREFIXES: tuple[str, ...] = (
    "DYLD_", "LD_", "GIT_", "CARGO_", "PIP_", "UV_", "CGO_", "RUSTUP_",
)  # fmt: skip
"""Families: the dynamic loaders, git, Cargo, pip, uv, cgo (compiler and linker flags) and rustup
(the toolchain and its home) read every name that starts so."""

DENIED_PREFIXES_ANY_CASE: tuple[str, ...] = ("npm_config_", "yarn_")
"""npm reads its `npm_config_*` settings, and Yarn its `YARN_*` settings (`YARN_YARN_PATH` runs
a file as Yarn), in any letter case."""


def denied_pass_env(name: str) -> bool:
    """Whether `name` may never be passed through to an agent."""
    folded = name.casefold()
    return (
        name in DENIED_NAMES
        or name.startswith(DENIED_PREFIXES)
        or folded.startswith(DENIED_PREFIXES_ANY_CASE)
    )
