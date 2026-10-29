"""Property tests for `compile_gate` (§20): whatever the template and paths, the argv it returns
starts with an allowed prefix, holds no hard-denied program, no inline-code flag after a runner,
no denied install pattern, and no placeholder value that was not validated.

The oracle restates the rules on its own instead of calling the policy's helpers.
"""

from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from aipm.domain.errors import PolicyViolation
from aipm.domain.models import GateDef
from aipm.security.command_policy import CommandPolicy, compile_gate
from aipm.security.paths import SafeRelPath

UV_RUN = ("uv", "run", "--frozen", "--offline")
PREFIXES = ((*UV_RUN, "ruff"), (*UV_RUN, "pytest"), ("python", "-m", "pytest"), ("node", "x.js"))
POLICY = CommandPolicy(allowed_prefixes=PREFIXES, test_roots=("tests",))

DENIED = {
    "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "pwsh", "cmd", "curl", "wget",
    "nc", "ncat", "socat", "ssh", "scp", "sftp", "rsync", "ftp", "telnet", "sudo", "su", "doas",
    "env", "xargs", "nohup", "eval", "exec", "rm", "dd", "mkfs", "npx", "pnpx", "bunx", "uvx",
    "pipx", "git",
}  # fmt: skip

ELEMENTS = st.sampled_from(
    [
        "check", "-q", "-x", "tests", "src", "{paths}", "{test_paths}", "{report_file}", "{bad}",
        "x{paths}", "bash", "/bin/sh", "BASH", "git", "curl", "env", "-c", "-e", "--eval",
        "--eval=1", "-p", "-Bc", "-cprint(1)", "node", "python", "-m", "pip", "install", "add",
        "--with", "--with=x", "sync", "eval", "a\nb", "ok", "--junitxml", "uv", "run",
    ]
)  # fmt: skip
PATH_VALUES = st.sampled_from(
    [
        "src/app.py", "tests/test_app.py", "bash", "src/rm", "-rf", "../x", ".pm/tasks.yaml",
        "src/.env", "/etc/passwd", "add", "tests", "docs/a b.md", "node", "src/-x",
    ]
)  # fmt: skip
TEMPLATES = st.tuples(st.sampled_from(PREFIXES), st.lists(ELEMENTS, max_size=6)).map(
    lambda t: (*t[0], *t[1])
)
REPORT = "/aipm-attempt/report.xml"


def basename(arg: str) -> str:
    return arg.rsplit("/", 1)[-1].lower()


@settings(max_examples=1500, deadline=None)
@given(TEMPLATES, st.lists(PATH_VALUES, max_size=4))
def test_compile_gate_output_obeys_the_policy(template: tuple[str, ...], values: list[str]) -> None:
    try:
        argv = compile_gate(
            GateDef(run=template),
            paths=[SafeRelPath(v) for v in values],
            policy=POLICY,
            report_file=Path(REPORT),
        )
    except PolicyViolation:
        return
    assert any(argv[: len(p)] == p for p in PREFIXES)
    assert basename(argv[0]) not in DENIED
    assert not any("{" in a or "}" in a or "\n" in a or "\x00" in a for a in argv)
    runner = (argv[0] == "uv" and "run" in argv) or (argv[0] == "python" and "-m" in argv)
    if runner:
        assert not any(basename(a) in DENIED for a in argv[1:]), argv
        for arg in argv[1:]:
            assert arg not in ("-c", "-e", "--eval"), argv
            assert not arg.startswith("--eval"), argv
            if arg.startswith("-") and not arg.startswith("--"):
                assert "c" not in arg[1:] and "e" not in arg[1:], argv
    lowered = [a.lower() for a in argv]
    if argv[0] == "uv":
        assert not {"add", "sync"} & set(lowered[1:]), argv
        assert not any(a.startswith("--with") for a in argv), argv
    for index, arg in enumerate(lowered):
        if basename(arg) == "pip":
            assert "install" not in lowered[index + 1 :], argv
        after_python = any(basename(a).startswith("python") for a in lowered[:index])
        if arg == "-m" and after_python and index + 1 < len(lowered):
            assert lowered[index + 1] != "pip", argv
    if "node" in argv:
        assert not any(a.startswith("-") and "p" in a.lstrip("-")[:1] for a in argv[1:]), argv
    template_args = set(template)
    for arg in argv:
        if arg in template_args or arg == REPORT:
            continue
        # Any other element came from {paths} or {test_paths}: it must be a validated value.
        assert not arg.startswith(("-", "/")), argv
        assert ".." not in arg.split("/"), argv
        assert not arg.startswith(".pm") and "/.env" not in f"/{arg}", argv
