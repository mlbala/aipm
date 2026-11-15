"""Environment variable names `dispatch.tools.<tool>.pass_env` may never hand an agent (N-2).

`pass_env` is a user-only key, but some names would undo what aipm sets up around an agent: a
loader or interpreter option that runs code before the agent does, the shell options of the
sandbox's shell (ADR-0020), a git, Go, Cargo, npm, pip or uv setting that changes where code
comes from, the variables aipm sets for the agent itself, or a switch that turns the agent's own
approvals off. They are refused when the config loads (exit 6), as forbidden agent flags are
refused even from the user config (red-team v0.4, N-2; SECURITY.md §8).
"""

DENIED_NAMES: frozenset[str] = frozenset(
    {
        # Process basics aipm sets or copies itself.
        "PATH", "HOME", "TMPDIR",
        # Code loaded before the program runs.
        "NODE_OPTIONS", "NODE_PATH",
        "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
        "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB",
        "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
        # Shell start-up files and options (srt runs commands through a shell, ADR-0020).
        "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "IFS", "PS4", "PROMPT_COMMAND", "ZDOTDIR",
        # Go and Rust settings that change the toolchain, the module source or the compiler.
        "GOFLAGS", "GOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOINSECURE", "GOTOOLCHAIN",
        "RUSTFLAGS", "RUSTC_WRAPPER",
        # The agents' homes and the settings aipm gives them (adapters/*.py).
        "CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "GEMINI_CLI_HOME", "GEMINI_SANDBOX",
        "DISABLE_AUTOUPDATER", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        # An agent's own switch that approves every tool call.
        "COPILOT_ALLOW_ALL",
    }
)  # fmt: skip
"""Refused as written (environment names are case-sensitive)."""

DENIED_PREFIXES: tuple[str, ...] = ("DYLD_", "LD_", "GIT_", "CARGO_", "PIP_", "UV_")
"""Families: the dynamic loaders, git, Cargo, pip and uv read every name that starts so."""

DENIED_PREFIXES_ANY_CASE: tuple[str, ...] = ("npm_config_",)
"""npm reads its `npm_config_*` settings in any letter case."""


def denied_pass_env(name: str) -> bool:
    """Whether `name` may never be passed through to an agent."""
    folded = name.casefold()
    return (
        name in DENIED_NAMES
        or name.startswith(DENIED_PREFIXES)
        or folded.startswith(DENIED_PREFIXES_ANY_CASE)
    )
