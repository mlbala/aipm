"""The command policy (SECURITY.md §10). Pure: no executable resolution happens here.

`compile_gate` turns a trusted gate definition into an argv; `compile_prepare` does the same for
the prepare step. Both expand placeholders first and then check the finished argv, so a
placeholder value can never smuggle in what the template could not. The trust store resolves
executables with `shutil.which` at trust time.

Program names are compared by basename, case-insensitively (macOS file systems are). After a
runner, a short-option cluster that contains an inline-code letter counts as that flag
(`-Bc` is `-B -c`), and so does a short flag with its value attached (`-cprint(1)`).
"""

import posixpath
import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Literal

from aipm.domain.errors import PolicyViolation
from aipm.domain.models import GateDef, PrepareDef, ToolName
from aipm.security.paths import SafeRelPath, is_protected, normalize_relpath, protected_patterns
from aipm.security.sanitize import is_ignorable

type Argv = tuple[str, ...]
type Stage = Literal["gate", "prepare"]

MAX_ARGV = 32
MAX_ARG_LENGTH = 512
MAX_EXPANDED_VALUES = 256
"""Placeholder values per argv; the 32-element limit applies to the configured template."""

PLACEHOLDERS = frozenset({"{paths}", "{test_paths}", "{report_file}", "{nextest_config}"})

HARD_DENIED: frozenset[str] = frozenset(
    {
        "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "pwsh", "cmd",
        "curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "sftp", "rsync", "ftp", "telnet",
        "sudo", "su", "doas",
        "env", "xargs", "nohup", "eval", "exec",
        "rm", "dd", "mkfs",
        "npx", "pnpx", "bunx", "uvx", "pipx",
        "git",
    }
)  # fmt: skip
"""SECURITY.md §10 rule 3: never allowed, at any argv position. A wrapper such as `time`, `nice`,
`timeout`, `caffeinate` or `find -exec` starts the program named after it, so checking only
`argv[0]` and the elements after a runner is not enough (red-team v0.1, RT01-1)."""

ALSO_DENIED: frozenset[str] = frozenset(
    {
        "awk", "gawk", "nawk", "mawk", "expect", "sqlite", "watch", "flock", "script",
        "nscurl", "lwp-request", "lwp-download", "lwp-mirror", "tftp",
    }
)  # fmt: skip
"""Refused like `HARD_DENIED` (SECURITY.md §10 rule 3): programs that run a shell string or code
given as an argument (`awk 'system(…)'`, `watch '…'`, `flock f -c`, `script -c`, `expect -c`,
`sqlite3 '.shell …'`), and network tools that ship with macOS (red-team v0.1 review)."""

DENIED_PROGRAMS: frozenset[str] = HARD_DENIED | ALSO_DENIED
"""Every program name the policy refuses, at any argv position."""

RUNNERS: tuple[Argv, ...] = (
    ("uv", "run"),
    ("uv", "tool", "run"),
    ("uv", "tool", "uvx"),
    ("npm", "exec"),
    ("npm", "x"),
    ("pnpm", "dlx"),
    ("pnpm", "exec"),
    ("yarn", "dlx"),
    ("yarn", "exec"),
    ("bun", "x"),
    ("bun", "run"),
    ("python", "-m"),
)
"""SECURITY.md §10 rule 4: argv prefixes that start another program."""

FETCH_AND_RUN: tuple[Argv, ...] = (
    ("uv", "tool", "run"),
    ("uv", "tool", "uvx"),
    ("npm", "exec"),
    ("npm", "x"),
    ("pnpm", "dlx"),
    ("yarn", "dlx"),
    ("bun", "x"),
)
"""Spellings of the hard-denied `uvx`, `npx`, `pnpx` and `bunx`: refused in every stage."""

_NEEDS_PROGRAM = frozenset(
    {"uv", "npm", "pnpm", "yarn", "bun", "pip", "python", "node", "nodejs", "deno", "ruby", "perl",
     "go", "cargo", "corepack"}
)  # fmt: skip
"""Package managers and interpreters: an allowed prefix starting with one must also name the
program or subcommand it runs, so `[uv]` or `[uv, run]` can never allow everything."""
_RUNNER_WORDS = frozenset({"run", "tool", "exec", "dlx", "x", "uvx"})

PNPM_SCRIPTS = frozenset({"pnpm.cjs", "pnpm.js", "pnpm.mjs"})
"""The file names of pnpm's own entry points, which `node` can run directly."""
PNPX_SCRIPTS = frozenset({"pnpx.cjs", "pnpx.js", "pnpx.mjs"})
"""pnpm's `pnpx` entry points: `pnpx` is hard-denied, and so is running its script."""
COREPACK_MANAGERS = frozenset({"pnpm", "yarn", "npm"})
"""What `corepack <manager> …` may start. Every other corepack command (`install`, `use`, `up`,
`enable`, `prepare`, `pack`, `cache`, …) installs or changes a package manager, and a version
(`corepack pnpm@10.0.0`) makes corepack download it (v0.4 decisions, session 5, item 1)."""
_SCRIPT_RUNNERS = frozenset({"node", "nodejs", "bun"})
"""Programs that run a JavaScript file given as their first argument."""

_PYTHON = re.compile(r"(?:python|pypy)(?:\d+(?:\.\d+)*t?)?")
_PERL = re.compile(r"perl\d+(?:\.\d+)*")
_PIP = re.compile(r"pip\d*(?:\.\d+)*")
# A version after a name: `php8.3`, `node22`, `zsh-5.9`, `julia-1.10`, `lua5.4`.
_VERSION_SUFFIX = re.compile(r"(?<=[a-z])[\-_]?\d+(?:\.\d+)*t?$")
# A Python flag cluster up to its first `m`: any letters but those that take a value (`-c`,
# `-W`, `-X`), so `-Im`, `-Pm` and `-Rm` count (the module follows, or is attached).
_ATTACHED_MODULE = re.compile(r"-(?:(?![cWX])[A-Za-z?])*?m(.*)")
_RUNNER_LETTERS = frozenset("ce")
_RUNNER_LONG = ("--eval",)
_NODE_LETTERS = frozenset("pr")
_NODE_LONG = ("--print", "--import", "--require", "--loader", "--experimental-loader")

# Interpreter -> (inline-code short letters, long flags, subcommands).
_INTERPRETERS: dict[str, tuple[frozenset[str], tuple[str, ...], frozenset[str]]] = {
    "python": (frozenset("c"), (), frozenset()),
    "node": (frozenset("epr"), ("--eval", *_NODE_LONG), frozenset()),
    "nodejs": (frozenset("epr"), ("--eval", *_NODE_LONG), frozenset()),
    "bun": (frozenset("ep"), ("--eval", "--print"), frozenset()),
    "ruby": (frozenset("e"), (), frozenset()),
    "perl": (frozenset("eEMm"), (), frozenset()),  # -M'POSIX;system(…)' runs code too
    "deno": (frozenset(), ("--eval",), frozenset({"eval"})),
    # macOS ships osascript, whose AppleScript can `do shell script` (red-team v0.1, RT01-1).
    "osascript": (frozenset("e"), (), frozenset()),
    "php": (
        frozenset("rBRE"),
        ("--run", "--process-begin", "--process-code", "--process-end"),
        frozenset(),
    ),
    "lua": (frozenset("e"), (), frozenset()),
    "luajit": (frozenset("e"), (), frozenset()),
    "rscript": (frozenset("e"), (), frozenset()),
    "r": (frozenset("e"), (), frozenset()),
    "julia": (frozenset("eE"), ("--eval", "--print"), frozenset()),
}

_NPM_INSTALL = frozenset(
    {
        "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
        "isntall", "add", "ci", "clean-install", "exec", "x", "update", "up", "upgrade", "it",
        "cit", "install-test", "install-ci-test", "rebuild",
    }
)  # fmt: skip
_INSTALL_WORDS: dict[str, frozenset[str]] = {
    "pip": frozenset({"install", "download"}),
    "npm": _NPM_INSTALL,
    "pnpm": frozenset({"dlx", "install", "i", "add", "update", "up"}),
    "yarn": frozenset({"dlx", "add", "install", "up", "upgrade"}),
    "uv": frozenset({"add", "sync"}),
    "go": frozenset({"get", "download"}),
    "cargo": frozenset({"fetch", "update", "add", "generate-lockfile"}),
}

# Go, gotestsum and cargo (the v0.4 stacks): routes that start a program other than the
# repository's own code, or that read settings that do, refused at every stage.
_GO_DENIED_WORDS = frozenset({"run", "generate", "tool", "env", "install"})
"""`go run` builds and runs anything, `generate` runs the `//go:generate` lines, `tool` runs any
tool, `env -w` rewrites the toolchain's settings and `install` puts programs on PATH."""
_GO_EXEC_FLAGS = ("-exec", "-toolexec", "-vettool")
"""Each names a program `go` starts in place of, or around, its own."""
_GO_FILE_FLAGS = ("-modfile", "-overlay")
"""`-modfile` reads another `go.mod` (and its `go.sum`), which the dependency checks do not know;
`-overlay` builds files named in a JSON file in place of the ones the diff shows (N-6)."""
_GOTESTSUM_FLAGS = ("--raw-command", "--post-run-command", "--watch")
_CARGO_DENIED_WORDS = frozenset({"run", "install"})
_CARGO_FLAGS = ("--config",)
"""`--config` can set `target.<triple>.runner` or `build.rustc-wrapper`: any program."""
_NEXTEST_FLAGS = ("--archive-file", "--binaries-metadata", "--cargo-metadata", "--tool-config-file")
"""The first three make `cargo nextest` run test binaries named in a file instead of the ones it
builds from the repository's source; a tool configuration can add setup and wrapper scripts,
which start any program (ADR-0030)."""
_PIP_MODULES = frozenset({"pip", "pip3", "ensurepip"})
# `python -m` modules that run code given as an argument, or serve the network.
_CODE_MODULES = frozenset(
    {"timeit", "code", "pdb", "runpy", "cprofile", "profile", "trace", "pydoc", "webbrowser",
     "http.server", "smtpd"}
)  # fmt: skip

_FORBIDDEN_FLAGS: dict[ToolName, tuple[str, ...]] = {
    ToolName.CLAUDE: ("--dangerously-skip-permissions", "--allow-dangerously-skip-permissions"),
    ToolName.CODEX: (
        "--yolo",
        "--dangerously-bypass-approvals-and-sandbox",
        "--full-auto",
        "--approve-for-me",
        "--not-so-yolo",
    ),
    ToolName.COPILOT: (
        "--allow-all",
        "--yolo",
        "--allow-all-tools",
        "--allow-all-paths",
        "--allow-all-urls",
        "--trust-folder",
        "--assisted-approval",
    ),
    ToolName.GEMINI: ("--yolo", "-y", "--skip-trust"),
}
_FORBIDDEN_VALUES: dict[ToolName, tuple[tuple[str, frozenset[str]], ...]] = {
    ToolName.CLAUDE: (("--permission-mode", frozenset({"bypasspermissions", "auto"})),),
    ToolName.GEMINI: (("--approval-mode", frozenset({"yolo"})),),
}
_CODEX_APPROVAL = re.compile(r"approval_policy\s*=\s*(.*)", re.IGNORECASE)
"""A Codex `-c approval_policy=<v>` override: only `never` keeps every command in the sandbox."""
_CODEX_CONFIG: dict[str, str] = {
    "approval_policy": "never",
    "analytics.enabled": "false",
    "check_for_update_on_startup": "false",
}
"""The only `-c`/`--config` overrides a Codex argv may hold, with their one allowed value
(red-team v0.4, RT04-5). Any other key could widen the sandbox (`sandbox_workspace_write.*`),
pick a profile with its own policy (`profiles.*`), pass the environment through
(`shell_environment_policy.*`) or start an MCP server outside the sandbox (`mcp_servers.*`)."""
_CODEX_OPTIONS = ("--add-dir", "--search", "--profile")
"""Codex options that widen what the agent may write or reach, or load a profile."""
_CODEX_FLAGS = frozenset({"--json", "--ephemeral", "--ignore-rules", "-"})
_CODEX_VALUED = frozenset({"--sandbox", "-s", "--ask-for-approval", "-a", "--config", "-c"})
"""The only options a Codex argv may hold after `exec` (their values are checked above): the
argv aipm builds is fixed, so anything else is refused (security review of part 1)."""
_GEMINI_FLAGS = frozenset({"--sandbox"})
_GEMINI_VALUED: dict[str, str | None] = {
    "--approval-mode": "auto_edit",
    "--output-format": "json",
    "--extensions": "none",
    "--allowed-tools": None,
    "--prompt": None,
}
"""The only options a Gemini argv may hold, with their one allowed value (`None`: any value,
`--allowed-tools` must be one shell rule)."""
_GEMINI_RULE = re.compile(r"run_shell_command\([^()]+\)")
_CAMEL = re.compile(r"[A-Z]")
_SHORT_GROUP = re.compile(r"-([A-Za-z]{2,})(=.*)?")


def _deny(message: str) -> PolicyViolation:
    return PolicyViolation(message, hint="See SECURITY.md §10 for what a gate may run.")


def program_name(arg: str) -> str:
    """The basename of an argv element, casefolded, with any version folded off: `python3.13t`,
    `pypy3`, `perl5.36` and `pip3.12` name their family, and `php8.3`, `node22` or `zsh-5.9`
    name `php`, `node` and `zsh`."""
    name = arg.rsplit("/", 1)[-1].casefold()
    for pattern, family in ((_PYTHON, "python"), (_PERL, "perl"), (_PIP, "pip")):
        if pattern.fullmatch(name):
            return family
    return _VERSION_SUFFIX.sub("", name)


_program = program_name


def _entry_name(arg: str) -> str:
    """`program_name` of `arg` after normalising its path: `node_modules/pnpm/` and
    `node_modules/pnpm/.` name pnpm's package directory, which `node` runs as its `main`."""
    return program_name(posixpath.normpath(arg))


def reaches_pnpm(argv: Sequence[str]) -> bool:
    """Whether `argv` names pnpm anywhere the policy can see it: as the program, after a launcher
    or wrapper (`corepack pnpm`, `corepack pnpm@10.34.9`, `time pnpm`), or as a script or
    package directory a JavaScript runtime runs (`node …/pnpm.cjs`, `node …/pnpm/`). A
    `package.json` script, a Makefile or a link under another name that runs pnpm is not
    visible here; the environment every gate gets covers those."""
    for arg in argv:
        name = _entry_name(arg)
        if name.split("@", 1)[0] == "pnpm" or name in PNPM_SCRIPTS:
            return True
    return False


def _invisible(ch: str) -> bool:
    category = unicodedata.category(ch)
    if category[0] == "C" or category in ("Zl", "Zp") or is_ignorable(ch):
        return True
    return category == "Zs" and ch != " "


def _check_element(arg: object) -> str:
    if not isinstance(arg, str):
        raise _deny("argv elements must be strings")
    if not arg or len(arg) > MAX_ARG_LENGTH:
        raise _deny(f"argv elements must have 1-{MAX_ARG_LENGTH} characters")
    if any(_invisible(ch) for ch in arg):
        # Control characters, and invisible ones the trust display would not show.
        raise _deny("argv elements must not contain control, format or invisible characters")
    return arg


def _check_shape(argv: object, *, max_len: int) -> Argv:
    if isinstance(argv, str) or not isinstance(argv, Sequence):
        raise _deny("argv must be a list of strings")
    items: Sequence[object] = argv  # pyright: ignore[reportUnknownVariableType]
    if not 1 <= len(items) <= max_len:
        raise _deny(f"argv must have 1-{max_len} elements")
    return tuple(_check_element(arg) for arg in items)


def _check_prefix(prefix: object) -> Argv:
    checked = _check_shape(prefix, max_len=MAX_ARGV)
    if any("{" in arg or "}" in arg for arg in checked):
        raise _deny("an allowed argv prefix must not contain placeholders")
    if _program(checked[0]) in DENIED_PROGRAMS:
        raise _deny(f"{checked[0]!r} is hard-denied and cannot be allowed by any configuration")
    if _program(checked[0]) in _NEEDS_PROGRAM and not any(
        not arg.startswith("-") and arg.casefold() not in _RUNNER_WORDS for arg in checked[1:]
    ):
        raise _deny(
            f"the allowed prefix {list(checked)} must also name the program or subcommand it runs"
        )
    return checked


@dataclass(frozen=True, slots=True)
class CommandPolicy:
    """The allowed argv prefixes (stack template plus user-level extras) and gate context.

    `test_roots` feed `{test_paths}`; `extra_protected` adds to the protected paths that no
    placeholder value may name.
    """

    allowed_prefixes: tuple[Argv, ...]
    test_roots: tuple[str, ...] = ()
    extra_protected: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.allowed_prefixes:
            raise _deny("no allowed argv prefixes are configured")
        for prefix in self.allowed_prefixes:
            _check_prefix(prefix)
        for root in self.test_roots:
            normalize_relpath(root)
        protected_patterns(self.extra_protected)


def _subsequence(needle: Sequence[str], hay: Sequence[str]) -> bool:
    it = iter(hay)
    return all(any(item == want for item in it) for want in needle)


def _normalized(argv: Argv) -> list[str]:
    """argv casefolded; after a Python program, a flag cluster ending in `m` is `-m`, and an
    attached module (`-mpip`, `-Impip`) is split off: `-Im timeit` and `-Imtimeit` are both
    `-m timeit`."""
    out: list[str] = []
    python = False
    for arg in argv:
        match = _ATTACHED_MODULE.fullmatch(arg) if python else None
        if match is None:
            out.append(arg.casefold())
        else:
            out.extend(("-m", match.group(1).casefold()) if match.group(1) else ("-m",))
        python = python or _program(arg) == "python"
    return out


def _matches(sequences: Sequence[Argv], argv: Argv) -> Argv | None:
    head = _program(argv[0])
    rest = _normalized(argv)[1:]
    return next((seq for seq in sequences if head == seq[0] and _subsequence(seq[1:], rest)), None)


def _runner_present(argv: Argv) -> bool:
    return _matches(RUNNERS, argv) is not None


def _flag_hit(arg: str, letters: frozenset[str], long_flags: Iterable[str]) -> bool:
    """Whether `arg` is one of the long flags, or a short flag or cluster holding a letter."""
    if arg.startswith("--"):
        return any(arg == flag or arg.startswith(f"{flag}=") for flag in long_flags)
    return arg.startswith("-") and any(ch in letters for ch in arg[1:])


def _names(argv: Argv, values: frozenset[int]) -> list[str]:
    """The program name of each argv element, or "" for an expanded placeholder value with a `/`.

    Such a value passed `safe_relpath` and names a file in the workspace: even a wrapper would
    run that file, never the program of the same name on `PATH`, so `cmd/env` is not `env`. A
    bare value (`curl`) is still a program name. After a runner every value is still compared
    (`_check_runner`, SECURITY.md §10 rule 4).
    """
    return ["" if i in values and "/" in arg else _program(arg) for i, arg in enumerate(argv)]


def _check_runner(argv: Argv) -> None:
    programs = [_program(arg) for arg in argv]
    for arg, program in zip(argv[1:], programs[1:], strict=True):
        if program in DENIED_PROGRAMS:
            raise _deny(f"{arg!r} is hard-denied after a runner")
    node = any(program in ("node", "nodejs") for program in programs)
    letters = _RUNNER_LETTERS | _NODE_LETTERS if node else _RUNNER_LETTERS
    long_flags = _RUNNER_LONG + (_NODE_LONG if node else ())
    for arg in argv[1:]:
        if _flag_hit(arg, letters, long_flags):
            raise _deny(f"inline-code flag {arg!r} after a runner")


def _check_denied_anywhere(argv: Argv, values: frozenset[int]) -> None:
    """No hard-denied program at any position: a wrapper (`time bash -c …`) would start it.

    `values` are the positions of expanded placeholder values: paths that `compile_gate` has
    already validated, which may well be named `cmd/env` or `scripts/sh` (`_names`).
    """
    for arg, program in zip(argv[1:], _names(argv, values)[1:], strict=True):
        if program in DENIED_PROGRAMS:
            raise _deny(f"{arg!r} is hard-denied at any argv position; a wrapper could start it")


def _check_code_modules(argv: Argv) -> None:
    """`python -m timeit '…'`, `-m code` and the like run code from an argument."""
    normalized = _normalized(argv)
    python = False
    for current, following in pairwise(normalized):
        python = python or _program(current) == "python"
        if python and current == "-m" and following in _CODE_MODULES:
            raise _deny(f"inline code for python: -m {following}")


def _check_interpreters(argv: Argv) -> None:
    for index, arg in enumerate(argv):
        spec = _INTERPRETERS.get(_program(arg))
        if spec is None:
            continue
        letters, long_flags, subcommands = spec
        for later in argv[index + 1 :]:
            if _flag_hit(later, letters, long_flags) or later in subcommands:
                raise _deny(f"inline code for {arg!r}: {later!r}")


def _flag_named(arg: str, flags: Iterable[str]) -> str | None:
    """The flag in `flags` that `arg` is, as `-f`, `--f`, `-f=v` or `--f=v`."""
    bare = arg.lstrip("-")
    if bare == arg:
        return None
    return next(
        (f for f in flags if bare == f.lstrip("-") or bare.startswith(f"{f.lstrip('-')}=")), None
    )


def _check_toolchains(argv: Argv) -> None:
    """Go, gotestsum and cargo may build and test the repository's code, and nothing else."""
    for index, arg in enumerate(argv):
        program = _program(arg)
        rest = argv[index + 1 :]
        if program in ("go", "gotestsum"):
            for later in rest:
                flag = _flag_named(later, _GO_EXEC_FLAGS)
                if flag is not None:
                    raise _deny(f"{flag} starts another program; it is refused")
                flag = _flag_named(later, _GO_FILE_FLAGS)
                if flag is not None:
                    raise _deny(f"{flag} reads files the checks do not see; it is refused")
        if program == "go":
            for later in rest:
                if later.casefold() in _GO_DENIED_WORDS:
                    raise _deny(f"`go {later}` runs code other than the tests; it is refused")
        if program == "gotestsum":
            for later in rest:
                flag = _flag_named(later, _GOTESTSUM_FLAGS)
                if flag is not None:
                    raise _deny(f"gotestsum {flag} runs another command; it is refused")
        if program == "cargo":
            _check_cargo(rest)


def _check_cargo(rest: Argv) -> None:
    # `cargo nextest run` runs the tests, like `cargo test`; any other `run` is `cargo run`.
    nextest = len(rest) >= 2 and rest[0] == "nextest" and rest[1] == "run"
    for index, later in enumerate(rest):
        if nextest and index == 1:
            continue
        if nextest and _flag_named(later, _NEXTEST_FLAGS) is not None:
            raise _deny(f"cargo nextest {later} runs other programs; it is refused")
        if later.casefold() in _CARGO_DENIED_WORDS:
            raise _deny(f"`cargo {later}` runs or installs a program; it is refused")
        if _flag_named(later, _CARGO_FLAGS) is not None:
            raise _deny("cargo --config can name any program as a runner; it is refused")
        if later.startswith("-Z"):
            raise _deny("cargo -Z enables unstable features; it is refused")
        if later.startswith("+"):
            raise _deny(f"cargo {later} picks another toolchain; it is refused")


def _check_install(argv: Argv) -> None:
    """Package installation is allowed only in the prepare step."""
    normalized = _normalized(argv)
    for index, item in enumerate(normalized):
        program = _program(item)
        rest = normalized[index + 1 :]
        hit = any(word in _INSTALL_WORDS.get(program, frozenset()) for word in rest)
        if program == "uv":
            hit = hit or any(word.startswith("--with") for word in rest)
            hit = hit or ("pip" in rest and ("install" in rest or "sync" in rest))
            hit = hit or ("tool" in rest and "install" in rest)
        if program == "python":
            hit = hit or any(a == "-m" and b in _PIP_MODULES for a, b in pairwise(rest))
        if hit:
            raise _deny(f"package installation is allowed only in the prepare step: {item!r}")


def _launched(argv: Argv) -> list[Argv]:
    """The package-manager argv each launcher in `argv` starts, read the way the policy reads
    `argv[0]`: `corepack pnpm dlx x` is `pnpm dlx x`, `node …/pnpm.cjs install` is `pnpm
    install`. A launcher shape the policy cannot read with certainty is refused (the owner's
    decision on session 5, item 1)."""
    found: list[Argv] = []
    for index, arg in enumerate(argv):
        program = _program(arg)
        rest = argv[index + 1 :]
        if program == "corepack":
            manager = rest[0].casefold() if rest else ""
            if "@" in manager:
                raise _deny(
                    f"corepack {rest[0]!r} names a package manager version, which corepack "
                    "downloads and runs; it is refused"
                )
            if manager not in COREPACK_MANAGERS:
                raise _deny(
                    "corepack may only start pnpm, yarn or npm (`corepack pnpm …`); its other "
                    "commands install or change package managers, and are refused"
                )
            found.append((manager, *rest[1:]))
        elif program in _SCRIPT_RUNNERS:
            for position, later in enumerate(rest):
                name = _entry_name(later)
                if name == "pnpx" or name in PNPX_SCRIPTS:
                    raise _deny(f"{later!r} is pnpx, which fetches and runs a package; refused")
                if name != "pnpm" and name not in PNPM_SCRIPTS:
                    continue
                if position != 0:
                    raise _deny(
                        f"{arg!r} must run pnpm's script as its first argument, with nothing "
                        "before it, so the policy can read the pnpm command; it is refused"
                    )
                found.append(("pnpm", *rest[1:]))
                break
    return found


def _check_launchers(argv: Argv, stage: Stage) -> None:
    """What a launcher starts gets the checks `argv[0]` gets: fetch-and-run and, in a gate,
    installation. The other runners of pnpm, yarn and npm are `exec`, which is denied at any
    position (`_check_denied_anywhere`)."""
    for launched in _launched(argv):
        fetch = _matches(FETCH_AND_RUN, launched)
        if fetch is not None:
            raise _deny(f"{' '.join(fetch)} fetches and runs a package; it is hard-denied")
        if stage == "gate":
            _check_install(launched)


def check_argv(
    argv: Sequence[str],
    policy: CommandPolicy,
    *,
    stage: Stage,
    max_len: int = MAX_ARGV,
    values: frozenset[int] = frozenset(),
) -> Argv:
    """Check a concrete argv (no placeholders) against SECURITY.md §10 rules 1-4.

    `values` holds the positions of expanded placeholder values (`compile_gate`).
    """
    checked = _check_shape(argv, max_len=max_len)
    if any("{" in arg or "}" in arg for arg in checked):
        raise _deny("unexpanded or partial placeholder in argv")
    if _program(checked[0]) in DENIED_PROGRAMS:
        raise _deny(f"{checked[0]!r} is hard-denied")
    fetch = _matches(FETCH_AND_RUN, checked)
    if fetch is not None:
        raise _deny(f"{' '.join(fetch)} fetches and runs a package; it is hard-denied")
    if not any(checked[: len(prefix)] == prefix for prefix in policy.allowed_prefixes):
        raise _deny(f"argv does not start with an allowed prefix: {list(checked[:6])}")
    if _runner_present(checked):
        _check_runner(checked)
    _check_interpreters(checked)
    _check_code_modules(checked)
    _check_toolchains(checked)
    _check_denied_anywhere(checked, values)
    _check_launchers(checked, stage)
    if stage == "gate":
        _check_install(checked)
    return checked


def _path_value(value: str, patterns: Sequence[str]) -> str:
    rel = normalize_relpath(value)
    if is_protected(rel, patterns):
        raise _deny(f"placeholder value {rel!r} is a protected path")
    return rel


def _test_paths(paths: Sequence[str], test_roots: Sequence[str]) -> list[str]:
    roots = [normalize_relpath(root) for root in test_roots]
    owned = [p for p in paths if any(p == root or p.startswith(f"{root}/") for root in roots)]
    return owned or roots[:1]


def nextest_config_path(report_file: Path) -> Path:
    """Where aipm writes the nextest configuration for the gate whose report is `report_file`."""
    return report_file.with_name(f"{report_file.name}.nextest.toml")


def _report_value(path: Path | None, placeholder: str) -> str:
    if path is None:
        raise _deny(f"the gate uses {placeholder}, but no report file was given for it")
    value = str(path)
    if not path.is_absolute():
        raise _deny(f"{placeholder} must be an absolute path that aipm generated")
    return _check_element(value)


def compile_gate(
    gate: GateDef,
    *,
    paths: Sequence[SafeRelPath],
    policy: CommandPolicy,
    report_file: Path | None = None,
    nextest_config: Path | None = None,
) -> Argv:
    """Expand placeholders and check the result, or raise `PolicyViolation` (exit 6).

    `{paths}` and `{test_paths}` become one argv element per value, each re-checked here;
    `{report_file}` is the absolute path aipm generated outside the workspace (§13.1), and
    `{nextest_config}` the nextest configuration aipm writes beside it, which sends nextest's
    JUnit report to `{report_file}`: `nextest_config_path(report_file)` unless the caller names
    another (ADR-0030).
    """
    if nextest_config is None and report_file is not None:
        nextest_config = nextest_config_path(report_file)
    if gate.run is None:
        raise _deny("a built-in gate has no argv to compile")
    template = _check_shape(gate.run, max_len=MAX_ARGV)
    patterns = protected_patterns(policy.extra_protected)
    values = [_path_value(p, patterns) for p in paths]
    if len(values) > MAX_EXPANDED_VALUES:
        raise _deny(f"more than {MAX_EXPANDED_VALUES} paths for one gate")
    expanded: list[str] = []
    positions: set[int] = set()
    for arg in template:
        if arg in ("{paths}", "{test_paths}"):
            found = values if arg == "{paths}" else _test_paths(values, policy.test_roots)
            positions.update(range(len(expanded), len(expanded) + len(found)))
            expanded.extend(found)
        elif arg == "{report_file}":
            expanded.append(_report_value(report_file, arg))
        elif arg == "{nextest_config}":
            expanded.append(_report_value(nextest_config, arg))
        elif "{" in arg or "}" in arg:
            raise _deny(f"{arg!r}: a placeholder must be a whole argv element")
        else:
            expanded.append(arg)
    return check_argv(
        expanded,
        policy,
        stage="gate",
        max_len=MAX_ARGV + 2 * MAX_EXPANDED_VALUES,
        values=frozenset(positions),
    )


def compile_prepare(prepare: PrepareDef, *, policy: CommandPolicy) -> Argv:
    """Check the prepare step. It takes no placeholders, and may install packages. A prepare
    that starts pnpm through anything but `pnpm` itself (`corepack pnpm`, `node …/pnpm.cjs`, a
    wrapper) is refused: aipm's store, copy and directory flags go right after `pnpm`, and the
    environment does not beat a committed `pnpm-workspace.yaml` or `.npmrc` (the owner's
    decision on session 5, item 1; checked by hand on pnpm 10.34.9)."""
    checked = check_argv(prepare.run, policy, stage="prepare")
    if reaches_pnpm(checked) and _program(checked[0]) != "pnpm":
        raise PolicyViolation(
            f"the prepare step starts pnpm through {checked[0]!r}, so aipm cannot pass the store "
            "and copy flags that beat the repository's pnpm settings",
            hint="Run pnpm directly (`pnpm install --frozen-lockfile`).",
        )
    return checked


def _option_values(argv: Argv, long: str, short: str) -> list[str | None]:
    """Every value given to an option, in each spelling clap accepts: `--long v`, `--long=v`,
    `-s v` and `-sv`; `None` for one that ends the argv without a value."""
    found: list[str | None] = []
    for index, arg in enumerate(argv):
        if arg in (long, short):
            found.append(argv[index + 1] if index + 1 < len(argv) else None)
        elif arg.startswith(f"{long}="):
            found.append(arg.split("=", 1)[1])
        elif arg.startswith(short) and not arg.startswith("--"):
            found.append(arg[len(short) :])
    return found


def _plain(value: str) -> str:
    return value.strip().strip("'\"").strip().casefold()


def _check_codex_options(argv: Argv) -> None:
    """Every spelling of `--sandbox`, `--ask-for-approval` and `--config`, and the options that
    widen Codex's reach (red-team v0.4, RT04-5)."""
    for value in _option_values(argv, "--sandbox", "-s"):
        if value is not None and _plain(value) != "workspace-write":
            raise PolicyViolation(f"codex: sandbox mode {value[:40]!r} is forbidden")
    for value in _option_values(argv, "--ask-for-approval", "-a"):
        if value is not None and _plain(value) != "never":
            raise PolicyViolation(f"codex: approval policy {value[:40]!r} is forbidden")
    for value in _option_values(argv, "--config", "-c"):
        if value is None:
            continue
        key, _, setting = value.partition("=")
        key = "".join(ch for ch in key if ch not in " '\"").casefold()
        if key == "approval_policy" and _plain(setting) != "never":
            raise PolicyViolation(f"codex: approval policy {setting[:40]!r} is forbidden")
        if _CODEX_CONFIG.get(key) != _plain(setting):
            raise PolicyViolation(f"codex: the config override {key[:60]!r} is forbidden")
    for arg in argv:
        name = arg.split("=", 1)[0]
        attached = arg.startswith("-p") and not arg.startswith("--")
        if name in _CODEX_OPTIONS or attached:
            raise PolicyViolation(f"codex: option {name[:40]} is forbidden")


def _yargs_argv(argv: Argv) -> Argv:
    """`argv` as yargs reads its option names: `--approvalMode` is `--approval-mode`, `--y` is
    `-y`, and a short group `-sy` or `-dy=true` is `-s -y` or `-d -y=true` (red-team v0.4,
    RT04-5, and its security review)."""
    out: list[str] = []
    for arg in argv:
        group = _SHORT_GROUP.fullmatch(arg)
        if arg.startswith("--"):
            name, sep, value = arg.partition("=")
            kebab = _CAMEL.sub(lambda m: "-" + m.group(0).lower(), name[2:])
            prefix = "-" if len(kebab) == 1 else "--"
            out.append(f"{prefix}{kebab}{sep}{value}")
        elif group is not None:
            letters, tail = group.group(1), group.group(2) or ""
            out.extend(f"-{ch}" for ch in letters[:-1])
            out.append(f"-{letters[-1]}{tail}")
        else:
            out.append(arg)
    return tuple(out)


def _check_codex_exact(argv: Argv) -> None:
    """Nothing but `exec` and the options aipm passes: no global option before `exec`, no
    positional prompt but `-` (security review of part 1)."""
    if "exec" not in argv:
        raise PolicyViolation("codex: anything but `codex exec` is forbidden")
    start = argv.index("exec")
    for arg in argv[:start]:
        if arg.startswith("-"):
            raise PolicyViolation(f"codex: option {arg[:40]!r} before exec is forbidden")
    index = start + 1
    while index < len(argv):
        arg = argv[index]
        attached = arg[:2] in ("-s", "-a", "-c") and len(arg) > 2 and not arg.startswith("--")
        if arg in _CODEX_VALUED:
            index += 2
            continue
        if arg in _CODEX_FLAGS or attached or arg.split("=", 1)[0] in _CODEX_VALUED:
            index += 1
            continue
        raise PolicyViolation(f"codex: {arg[:40]!r} is forbidden: aipm passes only its own options")


def _check_gemini_exact(argv: Argv) -> None:
    """Nothing but the options aipm passes, each with its one value (security review of part
    1). The launcher comes first: the program, then any absolute path (its script)."""
    index = 1
    while index < len(argv) and argv[index].startswith("/"):
        index += 1
    while index < len(argv):
        name, sep, value = argv[index].partition("=")
        index += 1
        if name in _GEMINI_FLAGS and not sep:
            continue
        if name not in _GEMINI_VALUED:
            raise PolicyViolation(
                f"gemini: {argv[index - 1][:40]!r} is forbidden: aipm passes only its own options"
            )
        if not sep:
            value = argv[index] if index < len(argv) else ""
            index += 1
        wanted = _GEMINI_VALUED[name]
        if name == "--allowed-tools":
            allowed = _GEMINI_RULE.fullmatch(value) is not None
        else:
            allowed = wanted is None or value == wanted
        if not allowed:
            raise PolicyViolation(f"gemini: {name} {value[:40]!r} is forbidden")


def _check_codex(argv: Argv) -> None:
    """No full access, and no approval policy but `never`: an approval would let a command run
    outside the sandbox, and nobody is there to answer one."""
    if any("danger-full-access" in arg for arg in argv):
        raise PolicyViolation("codex: danger-full-access is forbidden")
    for index, arg in enumerate(argv):
        value = None
        if arg in ("--ask-for-approval", "-a") and index + 1 < len(argv):
            value = argv[index + 1]
        elif arg.startswith("--ask-for-approval="):
            value = arg.split("=", 1)[1]
        else:
            match = _CODEX_APPROVAL.fullmatch(arg)
            value = match.group(1) if match else None
        if value is not None and value.strip(" '\"").casefold() != "never":
            raise PolicyViolation(f"codex: approval policy {value[:40]!r} is forbidden")
    _check_codex_options(argv)
    _check_codex_exact(argv)


def check_forbidden_flags(tool: ToolName, argv: Argv, *, allow_auto_mode: bool = False) -> None:
    """Raise `PolicyViolation` if `argv` holds a forbidden flag (ARCHITECTURE §11).

    `allow_auto_mode` is `dispatch.tools.claude.allow_auto_mode` from the user-level config.
    Gemini's argv is read as yargs reads it (camelCase names, short groups).
    """
    if tool is ToolName.GEMINI:
        argv = _yargs_argv(argv)
    for arg in argv:
        for flag in _FORBIDDEN_FLAGS[tool]:
            if arg == flag or arg.startswith(f"{flag}="):
                raise PolicyViolation(f"{tool.value}: flag {flag} is forbidden")
    if tool is ToolName.CODEX:
        _check_codex(argv)
    for option, values in _FORBIDDEN_VALUES.get(tool, ()):
        for index, arg in enumerate(argv):
            if arg == option and index + 1 < len(argv):
                value = argv[index + 1]
            elif arg.startswith(f"{option}="):
                value = arg.split("=", 1)[1]
            else:
                continue
            folded = value.casefold()
            if folded in values and not (folded == "auto" and allow_auto_mode):
                raise PolicyViolation(f"{tool.value}: {option} {value} is forbidden")
    if tool is ToolName.GEMINI:
        _check_gemini_exact(argv)
