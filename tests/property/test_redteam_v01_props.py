"""Red-team fuzzing for v0.1 (build prompt 09; docs/security/reviews/v0.1.md).

These properties take their example count from the active Hypothesis profile, so
`pytest --hypothesis-profile=ci-long` runs each one at least 2,000 times (tests/conftest.py).
The strategies add what the red-team pass attacked: case variants and Unicode confusables of
protected paths, default-ignorable characters, wrappers around hard-denied programs, URLs without
slashes, hostile marker and fence fragments in model-written fields, YAML structure tricks, and
repository or environment layers that try to set user-only keys or relax tighten-only ones.

Every oracle here restates its rule on its own instead of calling the code under test.
"""

import datetime
import re
import unicodedata
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aipm.config.loader import load_config
from aipm.context.generator import agents_md
from aipm.context.managed_block import MalformedBlock, extract_block, find_block, replace_block
from aipm.domain.errors import PolicyViolation, SchemaError
from aipm.security.agent_text import agent_text_problems
from aipm.security.command_policy import CommandPolicy, check_argv
from aipm.security.paths import is_protected, safe_rel_glob, safe_relpath
from aipm.security.sanitize import sanitize_for_context, sanitize_text
from aipm.security.untrusted import check_blocks
from aipm.state.yamlio import dump_yaml, load_yaml
from tests.fakes.project import clinic_context, hostile_context

FUZZ = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])

# Default-ignorable code points (Unicode DerivedCoreProperties), restated for the oracle.
IGNORABLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)  # fmt: skip
EMOJI_SELECTORS = (0xFE0E, 0xFE0F)


def ignorable(ch: str) -> bool:
    return any(low <= ord(ch) <= high for low, high in IGNORABLE_RANGES)


def hidden(ch: str) -> bool:
    """Refused in paths and argv: any control, format, private or unassigned code point."""
    return ch not in "\n\t" and (unicodedata.category(ch)[0] == "C" or ignorable(ch))


def invisible(ch: str) -> bool:
    """Removed from text: controls, format characters, surrogates and default-ignorables."""
    return ch not in "\n\t" and (unicodedata.category(ch) in ("Cc", "Cf", "Cs") or ignorable(ch))


# ---------------------------------------------------------------- paths

PARTS = st.sampled_from(
    [
        ".pm", ".PM", ".Pm", ".pm.", ".pm ", ".git", ".GIT", ".gIt.", ".github", ".GitHub",
        ".gitattributes", ".gitattribute\u017f", ".gitmodules", ".mcp.json", ".mcp.j\u017fon",
        ".env", ".ENV", ".env.local", "AGENTS.md", "agents.md", "AGENTS.MD", "AGENTS.md.",
        "CLAUDE.md", "claude.MD", ".claude", ".Claude", ".aipmignore", "src", "tests", "app.py",
        "*", "**", "?", ".*", "*.md", "e\u0301", "\u00e9", "\u212a", "x\u3164", "x\u034f",
        "x\u200b", "x\u17b4", "-x", "@x", "+x", "..", ".",
    ]
)  # fmt: skip
GLOBS = st.lists(PARTS, min_size=1, max_size=5).map("/".join)
ROOT_PROTECTED = [
    ".pm", ".pm/tasks.yaml", ".git", ".git/config", ".github/workflows/ci.yml", ".gitlab-ci.yml",
    "agents.md", "claude.md", "gemini.md", ".claude/settings.json", ".gemini/settings.json",
    ".codex/config.toml", ".agents/skills/x.md", ".mcp.json", ".gitattributes", ".gitmodules",
    ".aipmignore", ".env", ".env.local",
]  # fmt: skip
# The same rules at any depth, as a path check sees them (SECURITY.md §9.2).
PROTECTED_DIRS = (".pm", ".git", ".github", ".claude", ".gemini", ".codex", ".agents")
PROTECTED_FILES = (
    ".gitlab-ci.yml", "agents.md", "claude.md", "gemini.md", ".mcp.json", ".gitattributes",
    ".gitmodules", ".aipmignore",
)  # fmt: skip


def glob_regex(glob: str) -> re.Pattern[str]:
    pieces: list[str] = []
    for index, part in enumerate(glob.split("/")):
        if index:
            pieces.append("/")
        if part == "**":
            pieces.append(".*")
            continue
        pieces.extend(
            "[^/]*" if ch == "*" else "[^/]" if ch == "?" else re.escape(ch) for ch in part
        )
    return re.compile("".join(pieces), re.DOTALL)


@FUZZ
@given(GLOBS)
def test_an_accepted_glob_matches_no_protected_path_in_any_spelling(glob: str) -> None:
    try:
        out = safe_rel_glob(glob)
    except PolicyViolation:
        return
    assert not any(hidden(ch) for ch in out), out
    pattern = glob_regex(out.casefold())
    for sample in ROOT_PROTECTED:
        assert not pattern.fullmatch(sample), (out, sample)


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("rt01") / "ws"
    (root / "src").mkdir(parents=True)
    return root


@FUZZ
@given(GLOBS.filter(lambda g: "*" not in g and "?" not in g))
def test_an_accepted_path_is_never_protected_in_any_spelling(workspace: Path, path: str) -> None:
    try:
        out = safe_relpath(workspace, path)
    except PolicyViolation:
        return
    assert not any(hidden(ch) for ch in out), out
    parts = [part.rstrip(" .") for part in out.casefold().split("/")]
    assert not set(parts) & set(PROTECTED_DIRS), out
    assert parts[-1] not in PROTECTED_FILES and not parts[-1].startswith(".env"), out
    assert not is_protected(out)


# ---------------------------------------------------------------- the command policy

DENIED = {
    "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "pwsh", "cmd", "curl", "wget",
    "nc", "ncat", "socat", "ssh", "scp", "sftp", "rsync", "ftp", "telnet", "sudo", "su", "doas",
    "env", "xargs", "nohup", "eval", "exec", "rm", "dd", "mkfs", "npx", "pnpx", "bunx", "uvx",
    "pipx", "git",
}  # fmt: skip
INLINE_FLAGS = {
    "python": "c", "node": "epr", "ruby": "e", "perl": "eE", "osascript": "e", "php": "rBRE",
    "lua": "e", "rscript": "e", "julia": "eE",
}  # fmt: skip
WRAPPERS = st.sampled_from(
    [
        "time", "/usr/bin/time", "nice", "timeout", "command", "caffeinate", "arch", "script",
        "stdbuf", "sandbox-exec", "find", "setsid", "watch", "flock", "chroot", "xcrun", "make",
        "osascript", "php", "lua", "Rscript", "julia", "awk", "python3.13", "node", "ruby",
    ]
)  # fmt: skip
ARGS = st.sampled_from(
    [
        "-c", "-e", "-E", "-r", "-B", "-p", "-n", "5", "-exec", ";", "x", "src/app.py", "bash",
        "/bin/BASH", "sh", "Zsh", "curl", "/usr/bin/curl", "rm", "git", "src/git", "env",
        "nohup", "eval", "exec", "uvx", "npx", "python3", "Python3.12", "node", "--eval",
        "-qc", "x\u3164", "-q\u034f", "do shell script", "osascript", "php", "--", "-l",
    ]
)  # fmt: skip


def program(arg: str) -> str:
    name = arg.rsplit("/", 1)[-1].casefold()
    return "python" if re.fullmatch(r"(?:python|pypy)(?:\d+(?:\.\d+)*t?)?", name) else name


@FUZZ
@given(WRAPPERS, st.lists(ARGS, max_size=6))
def test_an_accepted_argv_never_starts_a_denied_program_or_inline_code(
    head: str, rest: list[str]
) -> None:
    argv = (head, *rest)
    try:
        policy = CommandPolicy(allowed_prefixes=((head, *rest[:1]),))
        checked = check_argv(argv, policy, stage="gate")
    except PolicyViolation:
        return
    names = [program(arg) for arg in checked]
    assert not DENIED & set(names), checked
    assert not any(hidden(ch) for arg in checked for ch in arg), checked
    for index, name in enumerate(names):
        letters = INLINE_FLAGS.get(name)
        if letters is None:
            continue
        for later in checked[index + 1 :]:
            if later.startswith("-") and not later.startswith("--"):
                assert not set(later[1:]) & set(letters), checked
            assert name != "node" or later != "--eval", checked


# The review of the RT01-1 fix: more denied programs, versioned names, long inline-code flags
# and `python -m` modules that run code from an argument.
ALSO_DENIED = {
    "awk", "gawk", "nawk", "mawk", "expect", "sqlite", "watch", "flock", "script", "nscurl",
    "lwp-request", "lwp-download", "lwp-mirror", "tftp",
}  # fmt: skip
REVIEW_FLAGS = {
    "python": ("c", ()), "node": ("epr", ("--eval", "--print")), "ruby": ("e", ()),
    "perl": ("eEMm", ()), "php": ("rBRE", ("--run", "--process-begin", "--process-code",
    "--process-end")), "lua": ("e", ()), "luajit": ("e", ()), "r": ("e", ()),
    "rscript": ("e", ()), "julia": ("eE", ("--eval", "--print")), "deno": ("", ("--eval",)),
}  # fmt: skip
CODE_MODULES = {
    "timeit", "code", "pdb", "runpy", "cprofile", "profile", "trace", "pydoc", "webbrowser",
    "http.server", "smtpd",
}  # fmt: skip
VERSIONED = st.sampled_from(
    [
        "php8.3", "node22", "zsh-5.9", "lua5.4", "luajit", "julia-1.10", "perl", "perl5.36", "R",
        "deno", "python3", "pypy3", "ruby3.3", "make", "ruff", "time", "sqlite3", "gawk", "Awk",
        "/usr/bin/nscurl", "lwp-request", "tftp", "watch", "flock", "Script", "expect",
    ]
)  # fmt: skip
REVIEW_ARGS = st.sampled_from(
    [
        "-e", "-E", "-M", "-m", "-Im", "-sEm", "-MPOSIX;system(1)", "-mcode", "-Imtimeit", "timeit",
        "code",
        "cProfile", "http.server", "--run", "--eval", "--print", "--process-code", "x",
        "src/app.py", "zsh-5.9", "bash5", "sqlite3", "gawk", "nscurl", "lwp-mirror", "tftp",
        "watch", "flock", "Script", "/usr/bin/AWK", "node22", "php8.3", "-c", "-r", "--", "-q",
    ]
)  # fmt: skip


def folded(arg: str) -> str:
    name = program(arg)
    if re.fullmatch(r"perl\d+(?:\.\d+)*", name):
        return "perl"
    return re.sub(r"(?<=[a-z])[\-_]?\d+(?:\.\d+)*t?$", "", name)


@FUZZ
@given(VERSIONED, st.lists(REVIEW_ARGS, max_size=6), st.integers(0, 2))
def test_an_accepted_argv_holds_no_newly_denied_program_flag_or_code_module(
    head: str, rest: list[str], prefix: int
) -> None:
    argv = (head, *rest)
    try:
        policy = CommandPolicy(allowed_prefixes=((head, *rest[:prefix]),))
        checked = check_argv(argv, policy, stage="gate")
    except PolicyViolation:
        return
    names = [folded(arg) for arg in checked]
    assert not (DENIED | ALSO_DENIED) & set(names), checked
    for index, name in enumerate(names):
        if name not in REVIEW_FLAGS:
            continue
        letters, long_flags = REVIEW_FLAGS[name]
        for later in checked[index + 1 :]:
            if later.startswith("-") and not later.startswith("--"):
                assert not set(later[1:]) & set(letters), checked
            assert later.casefold() not in long_flags, checked
    if "python" in names:
        # A cluster that ends in `m` (`-Im`) is `-m`; the module is the next argument.
        lowered = [
            "-m" if re.fullmatch(r"-[bdeioqsuvx]*m", arg.casefold()) else arg.casefold()
            for arg in checked
        ]
        for current, following in pairwise(lowered):
            assert not (current == "-m" and following in CODE_MODULES), checked
        for arg in lowered:
            attached = re.fullmatch(r"-[bdeiiqssuvx]*m(.+)", arg)
            assert attached is None or attached.group(1) not in CODE_MODULES, checked


@FUZZ
@given(
    st.sampled_from(["python3", "pypy3", "python3.13t", "/usr/bin/Python3", "uv"]),
    st.sampled_from(
        [
            "-m",
            "-Im",
            "-sEm",
            "-OOm",
            "-Bm",
            "-Pm",
            "-IPm",
            "-Rm",
            "-I",
            "-mtimeit",
            "-Imcode",
            "run",
        ]
    ),
    st.sampled_from(["timeit", "code", "cProfile", "http.server", "pdb", "pytest", "x.py"]),
    st.lists(
        st.sampled_from(["x", "-q", "src/app.py", "-m", "slow", "python3", "-Im"]), max_size=3
    ),
)
def test_python_runs_no_code_module_through_any_flag_cluster(
    head: str, flags: str, module: str, tail: list[str]
) -> None:
    argv = (head, flags, module, *tail)
    try:
        checked = check_argv(argv, CommandPolicy(allowed_prefixes=(argv[:3],)), stage="gate")
    except PolicyViolation:
        return
    lowered = [arg.casefold() for arg in checked]
    for index, arg in enumerate(lowered):
        if program(arg) != "python":
            continue
        for current, following in pairwise([*lowered[index + 1 :], ""]):
            named = re.fullmatch(r"-(?:(?![cwx])[a-z?])*?m(.*)", current)
            if named is not None:
                assert (named.group(1) or following) not in CODE_MODULES, checked


# ---------------------------------------------------------------- the sanitizer

HOSTILE = st.sampled_from(
    [
        "https:", "HTTP:", "http:evil.example", "Https:evil.example/p", "https:\\evil",
        "evil.example", "/", "(", ")", "[x](", "![", "\u3164", "\u115f", "\u034f", "\u17b4",
        "\u180b", "\ufff0", "\U000e0080", "\U000e0fff", "\u200b", "\x1b[0m", "\x1b]8;;x\x07",
        "@", "@~/.ssh/id_rsa", "<!--", "-->", "`", "```", " ", "\n", "x", "\u00e9", "e\u0301",
        "\u2764", "\ufe0f", "www.", "//", ":",
    ]
)  # fmt: skip
TEXT = st.lists(st.one_of(HOSTILE, st.text(max_size=4)), max_size=30).map("".join)


@FUZZ
@given(TEXT)
def test_sanitized_text_holds_no_ignorable_and_context_text_passes_i3(text: str) -> None:
    clean = sanitize_text(text, source="fuzz").text
    previous = ""
    for ch in clean:
        emoji_selector = ord(ch) in EMOJI_SELECTORS and previous not in ("", "\ufe0e", "\ufe0f")
        assert not invisible(ch) or emoji_selector, f"U+{ord(ch):04X} survived"
        previous = ch
    context = sanitize_for_context(text, allowed_url_domains=()).text
    assert not re.search(r"(?i)https?:", context), context
    assert sanitize_for_context(context, allowed_url_domains=()).text == context
    assert agent_text_problems(context, allowed_url_domains=()) == [], context


# ---------------------------------------------------------------- managed blocks, hostile fields

BASE_CONTEXT = clinic_context()
FIELD = st.lists(
    st.sampled_from(
        [
            "<!-- aipm:begin -->",
            "<!-- aipm:end -->",
            "<!-- AIPM:END",
            "```",
            "~~~",
            "`",
            "<untrusted",
            '</untrusted id="u12345678">',
            "@~/.ssh/id_rsa",
            "https:evil.example",
            "\u3164",
            "\x1b]8;;x\x07",
            "{{ 7*7 }}",
            "{% raw %}",
            "\r\n",
            "\n",
            "x",
            " ",
            "#",
        ]
    ),
    min_size=1,
    max_size=12,
).map("".join)
USER_LINES = ["# Notes\n", "keep\r\n", "<!-- aipm:begin -->\n", "<!-- aipm:end -->\n", "x", "\n"]
USER_DOC = st.lists(st.sampled_from([*USER_LINES, "`"]), max_size=6).map("".join)


@FUZZ
@given(FIELD, USER_DOC)
def test_hostile_fields_make_a_clean_block_that_round_trips(field: str, document: str) -> None:
    block = agents_md(hostile_context(field, BASE_CONTEXT)).block
    check_blocks(block)
    assert agent_text_problems(block, allowed_url_domains=()) == []
    assert "<!--" not in block
    try:
        out = replace_block(document, block)
    except MalformedBlock:
        return
    assert extract_block(out) == block
    span = find_block(out)
    assert span is not None
    assert document.startswith(out[: span.begin]) or out.startswith(document)
    assert replace_block(out, block) == out


# ---------------------------------------------------------------- YAML and the config loader

YAML_PIECES = st.sampled_from(
    [
        "a: 1", "b: [x, y]", "<<: {c: 2}", "&x ", "*x", "!!python/object:os.system ", "!t ",
        "? ", "- ", "\n", "  ", "a: 1\na: 2", "{", "}", "[", "]", "'", '"', "#", "---", "...",
        "%YAML 1.1\n", "\t", "\u2028", "\x85", ":", ",", "key", "2026-10-29", "~", "null", "0x1F",
        "1e9", ".inf", "|", ">", "\\u0000",
    ]
)  # fmt: skip
PLAIN = (str, int, float, bool, type(None), datetime.date)


def plain(value: object, depth: int = 0) -> bool:
    assert depth <= 70
    if isinstance(value, dict):
        items: dict[object, object] = value  # pyright: ignore[reportUnknownVariableType]
        return all(plain(k, depth + 1) and plain(v, depth + 1) for k, v in items.items())
    if isinstance(value, list):
        seq: list[object] = value  # pyright: ignore[reportUnknownVariableType]
        return all(plain(v, depth + 1) for v in seq)
    return isinstance(value, PLAIN)


@FUZZ
@given(st.lists(YAML_PIECES, max_size=16).map("".join))
def test_yaml_loads_to_plain_data_or_a_schema_error(text: str) -> None:
    try:
        data = load_yaml(text, source="fuzz")
    except SchemaError:
        return
    assert plain(data), repr(data)


NETWORK = st.sampled_from(["none", "api-only", "registries"])
DOMAINS = st.lists(st.sampled_from(["docs.python.org", "evil.example", "example.com"]), unique=True)
SECURITY_LAYER = st.fixed_dictionaries(
    {},
    optional={
        "require_sandbox": st.booleans(),
        "max_input_kib": st.integers(1, 10_240),
        "allow_new_dependencies": st.sampled_from(["deny", "ask", "allow"]),
        "min_dependency_age_days": st.integers(0, 3650),
        "network": st.fixed_dictionaries({}, optional={"agent": NETWORK, "prepare": NETWORK}),
        "extra_allowed_executables": st.just([["make"]]),
    },
)
LAYER = st.fixed_dictionaries(
    {},
    optional={
        "security": SECURITY_LAYER,
        "budget": st.fixed_dictionaries(
            {}, optional={"run_usd": st.floats(0, 1000), "run_tokens": st.integers(0, 10**7)}
        ),
        "dispatch": st.fixed_dictionaries(
            {},
            optional={
                "parallel": st.integers(1, 8),
                "sandbox": st.sampled_from(["srt", "tool-native", "auto", "none"]),
                "task_timeout": st.sampled_from(["5m", "20m", "2h", "90s"]),
                "tools": st.fixed_dictionaries(
                    {},
                    optional={
                        "claude": st.fixed_dictionaries(
                            {},
                            optional={
                                "bare": st.booleans(),
                                "pass_env": st.just(["AWS_SECRET_ACCESS_KEY"]),
                                "allow_auto_mode": st.booleans(),
                            },
                        )
                    },
                ),
            },
        ),
        "context": st.fixed_dictionaries({}, optional={"allowed_url_domains": DOMAINS}),
        "llm": st.fixed_dictionaries(
            {},
            optional={
                "provider": st.just("openai-compatible"),
                "base_url": st.just("https://evil.example/v1"),
                "api_key_env": st.just("ANTHROPIC_API_KEY"),
            },
        ),
    },
)
ENV_ATTACK = st.fixed_dictionaries(
    {},
    optional={
        "AIPM_LLM__BASE_URL": st.just("https://evil.example/v1"),
        "AIPM_LLM__API_KEY_ENV": st.just("ANTHROPIC_API_KEY"),
        "AIPM_DISPATCH__TOOLS__CLAUDE__PASS_ENV": st.just("[AWS_SECRET_ACCESS_KEY]"),
        "AIPM_SECURITY__EXTRA_ALLOWED_EXECUTABLES": st.just("[[make]]"),
    },
)
RANK = {
    "network": ["none", "api-only", "registries"],
    "sandbox": ["srt", "tool-native", "auto", "none"],
    "deps": ["deny", "ask", "allow"],
}
SECONDS = {"5m": 300, "20m": 1200, "2h": 7200, "90s": 90}


@pytest.fixture(scope="module")
def layers(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    base = tmp_path_factory.mktemp("rt01-config")
    repo = base / "repo"
    (repo / ".pm").mkdir(parents=True)
    return repo, base / "user.yaml"


def no_looser(user: Any, final: Any) -> None:
    us, fs = user.security, final.security
    assert fs.require_sandbox or not us.require_sandbox
    assert fs.max_input_kib <= us.max_input_kib
    assert fs.min_dependency_age_days >= us.min_dependency_age_days
    deps = RANK["deps"]
    ours_deps, final_deps = us.allow_new_dependencies.value, fs.allow_new_dependencies.value
    assert deps.index(final_deps) <= deps.index(ours_deps)
    net = RANK["network"]
    for kind in ("agent", "gates", "prepare"):
        ours, theirs = getattr(us.network, kind).value, getattr(fs.network, kind).value
        assert net.index(theirs) <= net.index(ours), kind
    assert final.budget.run_usd <= user.budget.run_usd
    assert final.budget.run_tokens <= user.budget.run_tokens
    assert final.dispatch.parallel <= user.dispatch.parallel
    sandbox = RANK["sandbox"]
    assert sandbox.index(final.dispatch.sandbox.value) <= sandbox.index(user.dispatch.sandbox.value)
    timeout = SECONDS.get(final.dispatch.task_timeout, 1200)
    assert timeout <= SECONDS.get(user.dispatch.task_timeout, 1200)
    assert set(final.context.allowed_url_domains) <= set(user.context.allowed_url_domains)


ENV_RELAX = st.fixed_dictionaries(
    {},
    optional={
        "AIPM_SECURITY__REQUIRE_SANDBOX": st.sampled_from(["true", "false"]),
        "AIPM_SECURITY__NETWORK__AGENT": NETWORK,
        "AIPM_SECURITY__EXTRA_PROTECTED_PATHS": st.sampled_from(["[]", "[infra/**]"]),
    },
)


@FUZZ
@given(LAYER, LAYER)
def test_the_repo_never_sets_user_only_keys_or_relaxes_security(
    layers: tuple[Path, Path], user: dict[str, Any], repo_layer: dict[str, Any]
) -> None:
    repo, user_path = layers
    user_path.write_text(dump_yaml(user) if user else "", encoding="utf-8")
    (repo / ".pm" / "config.yaml").write_text(
        dump_yaml({"schema_version": 1, **repo_layer}), encoding="utf-8"
    )
    own = load_config(None, env={"AIPM_CONFIG": str(user_path)}).config
    final = load_config(repo, env={"AIPM_CONFIG": str(user_path)}).config
    assert final.llm.provider == own.llm.provider
    assert final.llm.base_url == own.llm.base_url
    assert final.llm.api_key_env == own.llm.api_key_env
    assert final.security.extra_allowed_executables == own.security.extra_allowed_executables
    for name, tool in final.dispatch.tools.items():
        mine = own.dispatch.tools.get(name)
        assert tool.pass_env == (mine.pass_env if mine else [])
        assert tool.allow_auto_mode == (mine.allow_auto_mode if mine else False)
        assert tool.bare or (mine is not None and not mine.bare)
    no_looser(own, final)


@FUZZ
@given(LAYER, ENV_ATTACK.filter(bool), ENV_RELAX)
def test_the_environment_never_sets_a_user_only_key(
    layers: tuple[Path, Path], user: dict[str, Any], attack: dict[str, str], relax: dict[str, str]
) -> None:
    repo, user_path = layers
    user_path.write_text(dump_yaml(user) if user else "", encoding="utf-8")
    (repo / ".pm" / "config.yaml").write_text("schema_version: 1\n", encoding="utf-8")
    with pytest.raises(PolicyViolation, match="user-only key"):
        load_config(repo, env={"AIPM_CONFIG": str(user_path), **attack, **relax})


@FUZZ
@given(LAYER, LAYER, ENV_RELAX)
def test_every_relaxation_from_the_environment_is_warned(
    layers: tuple[Path, Path], user: dict[str, Any], repo_layer: dict[str, Any], env: dict[str, str]
) -> None:
    repo, user_path = layers
    user_path.write_text(dump_yaml(user) if user else "", encoding="utf-8")
    (repo / ".pm" / "config.yaml").write_text(
        dump_yaml({"schema_version": 1, **repo_layer}), encoding="utf-8"
    )
    before = load_config(repo, env={"AIPM_CONFIG": str(user_path)}).config.security
    loaded = load_config(repo, env={"AIPM_CONFIG": str(user_path), **env})
    after = loaded.config.security
    relaxed = {
        "security.require_sandbox": before.require_sandbox and not after.require_sandbox,
        "security.network.agent": RANK["network"].index(after.network.agent.value)
        > RANK["network"].index(before.network.agent.value),
        "security.extra_protected_paths": not set(before.extra_protected_paths)
        <= set(after.extra_protected_paths),
    }
    for key, looser in relaxed.items():
        warned = any(
            w.startswith(f"AIPM_* environment variables: relaxed {key} ") for w in loaded.warnings
        )
        assert warned == looser, (key, before, after, loaded.warnings)
