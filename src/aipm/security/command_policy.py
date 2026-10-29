"""The command policy (SECURITY.md §10). Pure: no executable resolution happens here.

`compile_gate` turns a trusted gate definition into an argv; `compile_prepare` does the same for
the prepare step. Both expand placeholders first and then check the finished argv, so a
placeholder value can never smuggle in what the template could not. The trust store resolves
executables with `shutil.which` at trust time.

Program names are compared by basename, case-insensitively (macOS file systems are). After a
runner, a short-option cluster that contains an inline-code letter counts as that flag
(`-Bc` is `-B -c`), and so does a short flag with its value attached (`-cprint(1)`).
"""

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

type Argv = tuple[str, ...]
type Stage = Literal["gate", "prepare"]

MAX_ARGV = 32
MAX_ARG_LENGTH = 512
MAX_EXPANDED_VALUES = 256
"""Placeholder values per argv; the 32-element limit applies to the configured template."""

PLACEHOLDERS = frozenset({"{paths}", "{test_paths}", "{report_file}"})

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
"""SECURITY.md §10 rule 3: never allowed, as `argv[0]` or anywhere after a runner."""

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
    {"uv", "npm", "pnpm", "yarn", "bun", "pip", "python", "node", "nodejs", "deno", "ruby", "perl"}
)
"""Package managers and interpreters: an allowed prefix starting with one must also name the
program or subcommand it runs, so `[uv]` or `[uv, run]` can never allow everything."""
_RUNNER_WORDS = frozenset({"run", "tool", "exec", "dlx", "x", "uvx"})

_PYTHON = re.compile(r"(?:python|pypy)(?:\d+(?:\.\d+)*t?)?")
_PERL = re.compile(r"perl\d+(?:\.\d+)*")
_PIP = re.compile(r"pip\d*(?:\.\d+)*")
_ATTACHED_MODULE = re.compile(r"-[bBdEiIOqsSuvx]*m(.+)")
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
    "perl": (frozenset("eE"), (), frozenset()),
    "deno": (frozenset(), (), frozenset({"eval"})),
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
}
_PIP_MODULES = frozenset({"pip", "pip3", "ensurepip"})

_FORBIDDEN_FLAGS: dict[ToolName, tuple[str, ...]] = {
    ToolName.CLAUDE: ("--dangerously-skip-permissions", "--allow-dangerously-skip-permissions"),
    ToolName.CODEX: ("--yolo", "--dangerously-bypass-approvals-and-sandbox"),
    ToolName.COPILOT: (
        "--allow-all",
        "--yolo",
        "--allow-all-tools",
        "--allow-all-paths",
        "--allow-all-urls",
        "--trust-folder",
    ),
    ToolName.GEMINI: ("--yolo", "-y"),
}
_FORBIDDEN_VALUES: dict[ToolName, tuple[tuple[str, frozenset[str]], ...]] = {
    ToolName.CLAUDE: (("--permission-mode", frozenset({"bypasspermissions", "auto"})),),
    ToolName.GEMINI: (("--approval-mode", frozenset({"yolo"})),),
}


def _deny(message: str) -> PolicyViolation:
    return PolicyViolation(message, hint="See SECURITY.md §10 for what a gate may run.")


def program_name(arg: str) -> str:
    """The basename of an argv element, casefolded; versioned Python, pip and perl are folded."""
    name = arg.rsplit("/", 1)[-1].casefold()
    for pattern, family in ((_PYTHON, "python"), (_PERL, "perl"), (_PIP, "pip")):
        if pattern.fullmatch(name):
            return family
    return name


_program = program_name


def _invisible(ch: str) -> bool:
    category = unicodedata.category(ch)
    return category[0] == "C" or category in ("Zl", "Zp") or (category == "Zs" and ch != " ")


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
    if _program(checked[0]) in HARD_DENIED:
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
    """argv casefolded; after a Python program, an attached `-m<module>` (`-mpip`, `-Impip`) is
    split into `-m` and the module."""
    out: list[str] = []
    python = False
    for arg in argv:
        match = _ATTACHED_MODULE.fullmatch(arg) if python else None
        out.extend(("-m", match.group(1).casefold()) if match else (arg.casefold(),))
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


def _check_runner(argv: Argv) -> None:
    programs = [_program(arg) for arg in argv]
    for arg, program in zip(argv[1:], programs[1:], strict=True):
        if program in HARD_DENIED:
            raise _deny(f"{arg!r} is hard-denied after a runner")
    node = any(program in ("node", "nodejs") for program in programs)
    letters = _RUNNER_LETTERS | _NODE_LETTERS if node else _RUNNER_LETTERS
    long_flags = _RUNNER_LONG + (_NODE_LONG if node else ())
    for arg in argv[1:]:
        if _flag_hit(arg, letters, long_flags):
            raise _deny(f"inline-code flag {arg!r} after a runner")


def _check_interpreters(argv: Argv) -> None:
    for index, arg in enumerate(argv):
        spec = _INTERPRETERS.get(_program(arg))
        if spec is None:
            continue
        letters, long_flags, subcommands = spec
        for later in argv[index + 1 :]:
            if _flag_hit(later, letters, long_flags) or later in subcommands:
                raise _deny(f"inline code for {arg!r}: {later!r}")


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


def check_argv(
    argv: Sequence[str], policy: CommandPolicy, *, stage: Stage, max_len: int = MAX_ARGV
) -> Argv:
    """Check a concrete argv (no placeholders) against SECURITY.md §10 rules 1-4."""
    checked = _check_shape(argv, max_len=max_len)
    if any("{" in arg or "}" in arg for arg in checked):
        raise _deny("unexpanded or partial placeholder in argv")
    if _program(checked[0]) in HARD_DENIED:
        raise _deny(f"{checked[0]!r} is hard-denied")
    fetch = _matches(FETCH_AND_RUN, checked)
    if fetch is not None:
        raise _deny(f"{' '.join(fetch)} fetches and runs a package; it is hard-denied")
    if not any(checked[: len(prefix)] == prefix for prefix in policy.allowed_prefixes):
        raise _deny(f"argv does not start with an allowed prefix: {list(checked[:6])}")
    if _runner_present(checked):
        _check_runner(checked)
    _check_interpreters(checked)
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


def _report_value(report_file: Path | None) -> str:
    if report_file is None:
        raise _deny("the gate uses {report_file}, but no report file was given")
    value = str(report_file)
    if not report_file.is_absolute():
        raise _deny("{report_file} must be an absolute path that aipm generated")
    return _check_element(value)


def compile_gate(
    gate: GateDef,
    *,
    paths: Sequence[SafeRelPath],
    policy: CommandPolicy,
    report_file: Path | None = None,
) -> Argv:
    """Expand placeholders and check the result, or raise `PolicyViolation` (exit 6).

    `{paths}` and `{test_paths}` become one argv element per value, each re-checked here;
    `{report_file}` is the absolute path aipm generated outside the workspace (§13.1).
    """
    if gate.run is None:
        raise _deny("a built-in gate has no argv to compile")
    template = _check_shape(gate.run, max_len=MAX_ARGV)
    patterns = protected_patterns(policy.extra_protected)
    values = [_path_value(p, patterns) for p in paths]
    if len(values) > MAX_EXPANDED_VALUES:
        raise _deny(f"more than {MAX_EXPANDED_VALUES} paths for one gate")
    expanded: list[str] = []
    for arg in template:
        if arg == "{paths}":
            expanded.extend(values)
        elif arg == "{test_paths}":
            expanded.extend(_test_paths(values, policy.test_roots))
        elif arg == "{report_file}":
            expanded.append(_report_value(report_file))
        elif "{" in arg or "}" in arg:
            raise _deny(f"{arg!r}: a placeholder must be a whole argv element")
        else:
            expanded.append(arg)
    return check_argv(expanded, policy, stage="gate", max_len=MAX_ARGV + 2 * MAX_EXPANDED_VALUES)


def compile_prepare(prepare: PrepareDef, *, policy: CommandPolicy) -> Argv:
    """Check the prepare step. It takes no placeholders, and may install packages."""
    return check_argv(prepare.run, policy, stage="prepare")


def check_forbidden_flags(tool: ToolName, argv: Argv, *, allow_auto_mode: bool = False) -> None:
    """Raise `PolicyViolation` if `argv` holds a forbidden flag (ARCHITECTURE §11).

    `allow_auto_mode` is `dispatch.tools.claude.allow_auto_mode` from the user-level config.
    """
    for arg in argv:
        for flag in _FORBIDDEN_FLAGS[tool]:
            if arg == flag or arg.startswith(f"{flag}="):
                raise PolicyViolation(f"{tool.value}: flag {flag} is forbidden")
    if tool is ToolName.CODEX and any("danger-full-access" in arg for arg in argv):
        raise PolicyViolation("codex: danger-full-access is forbidden")
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
