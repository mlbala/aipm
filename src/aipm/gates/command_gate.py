"""Command gates: `compile_gate`, then `sandbox.wrap`, then `run_safe` (ARCHITECTURE §13.2).

The argv comes only from the trusted menu through `compile_gate`; `argv[0]` is resolved on PATH
as the trust store resolved it. The gate runs in the work tree with the `gates` network
profile (none by default), a constructed environment without API keys, a 10-minute timeout,
its own process group and an output cap. Python writes no bytecode into the tree, and reads none
from it: `PYTHONPYCACHEPREFIX` points into the attempt's temp dir.

`{report_file}` is a fresh name in the attempt's private temp dir, deleted immediately before the
gate runs (SECURITY.md §10 rule 5). A gate that has one passes only if it exited 0 *and* its
report shows tests ran and none failed: `srt` exits 0 when the command dies of SIGTERM, and a
test that kills its own runner must not pass (ADR-0020).
"""

import secrets
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from aipm.domain.errors import PolicyViolation
from aipm.domain.models import Ecosystem, GateDef, GateResult, GateStatus, NetworkProfile
from aipm.execution.process import BASE_ENV_ALLOWLIST, ProcessResult, build_env, run_safe
from aipm.execution.sandbox import ProcessKind, ProfilePaths, SandboxProfile, profile_for
from aipm.gates.context import GateContext
from aipm.gates.reports import ReportError, TestReport, load_report
from aipm.security.command_policy import compile_gate, compile_prepare
from aipm.security.network import NetworkPolicy, parse_network
from aipm.security.paths import SafeRelPath
from aipm.security.sanitize import head_tail, sanitize_text, strip_terminal_escapes

GATE_TIMEOUT_S = 600.0
MAX_OUTPUT_BYTES = 2_000_000
_OUTPUT_HEAD = 32_768


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    """A command gate's result, its test report if it has one, and its full (redacted) output."""

    result: GateResult
    report: TestReport | None
    full_output: str


def resolve_program(name: str, repo: Path) -> str:
    """`argv[0]` as an absolute path from PATH, as the trust store resolved it for the surface
    hash (SECURITY.md §10 rule 2). A project's own interpreter or tool may live in the
    repository (`.venv/bin/python`); that is residual risk R-9, shown in full by `aipm trust`.
    """
    del repo
    found = shutil.which(name)
    return name if found is None else found


def gate_env(ctx: GateContext) -> dict[str, str]:
    """The base allowlist (SECURITY.md §8), with the temp dir and no in-tree bytecode."""
    temp = ctx.ws.temp_dir
    return build_env(
        extra={
            "TMPDIR": str(temp),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": str(temp / "pycache"),
        }
    )


def _network(profile: NetworkProfile) -> NetworkPolicy:
    if profile is NetworkProfile.API_ONLY:
        raise PolicyViolation(
            "api-only needs named domains, which only aipm's own tools have",
            hint="Use none (the default), registries or open for gates and the prepare step.",
        )
    return parse_network(profile.value, ecosystems=(Ecosystem.PYPI, Ecosystem.NPM))


def sandbox_for(
    ctx: GateContext, kind: ProcessKind, profile: NetworkProfile
) -> SandboxProfile | None:
    """The `srt` profile for a gate or the prepare step, or `None` without a sandbox."""
    if ctx.runtime is None:
        return None
    paths = ProfilePaths(workspace=ctx.root, temp_dir=ctx.ws.temp_dir, home=ctx.home)
    return profile_for(kind, _network(profile), paths, runtime=ctx.runtime)


def _output(result: ProcessResult, ctx: GateContext) -> str:
    """Decoded, cleaned, then redacted, so a secret split by an escape or an invisible character
    is whole when the redactor sees it (SECURITY.md §8)."""
    raw = (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="replace")
    return ctx.redactor.redact(sanitize_text(raw, source="gate output").text)


def _last_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        clean = strip_terminal_escapes(line).strip()
        if clean:
            return clean[:200]
    return ""


def _judge(
    result: ProcessResult, report_file: Path | None
) -> tuple[GateStatus, str, TestReport | None]:
    if result.timed_out or result.returncode != 0 or report_file is None:
        if result.timed_out:
            return GateStatus.ERROR, f"timed out after {int(GATE_TIMEOUT_S // 60)} minutes", None
        ok = result.returncode == 0
        return (GateStatus.PASS if ok else GateStatus.FAIL), f"exit {result.returncode}", None
    try:
        report = load_report(report_file)
    except ReportError as exc:
        return GateStatus.FAIL, f"exit 0, but {exc}", None
    if not report.ran:
        return GateStatus.FAIL, f"no tests ran ({report.summary()})", report
    if report.failed:
        return GateStatus.FAIL, f"the report shows failures ({report.summary()})", report
    return GateStatus.PASS, report.summary(), report


def run_command_gate(
    name: str, gate: GateDef, ctx: GateContext, *, paths: list[SafeRelPath], required: bool
) -> CommandOutcome:
    """Compile, wrap and run one command gate, and judge it."""
    assert gate.run is not None  # noqa: S101 - the runner sends only command gates here
    report_file = None
    if "{report_file}" in gate.run:
        report_file = ctx.ws.temp_dir / f"report-{name}-{secrets.token_hex(8)}"
    argv = list(
        compile_gate(gate, paths=paths, policy=ctx.cfg.command_policy(), report_file=report_file)
    )
    argv[0] = resolve_program(argv[0], ctx.root)
    profile = sandbox_for(ctx, ProcessKind.GATE, ctx.cfg.security.network.gates)
    if report_file is not None:
        report_file.unlink(missing_ok=True)
    started = time.monotonic()
    result = run_safe(
        argv,
        cwd=ctx.root,
        env=gate_env(ctx),
        timeout_s=GATE_TIMEOUT_S,
        max_output_bytes=MAX_OUTPUT_BYTES,
        sandbox=profile,
    )
    output = _output(result, ctx)
    status, summary, report = _judge(result, report_file)
    if status is not GateStatus.PASS and (last := _last_line(output)):
        summary = f"{summary}: {last}"
    if result.truncated:
        summary += f" (output cut at {MAX_OUTPUT_BYTES} bytes)"
    gate_result = GateResult(
        name=name,
        status=status,
        required=required,
        duration_ms=int((time.monotonic() - started) * 1000),
        summary=summary[:1000],
        output=head_tail(output, _OUTPUT_HEAD, _OUTPUT_HEAD),
    )
    return CommandOutcome(gate_result, report, output)


def run_prepare(ctx: GateContext) -> CommandOutcome | None:
    """The prepare step, with the `prepare` network profile (registries by default)."""
    prepare = ctx.cfg.prepare
    if prepare is None:
        return None
    argv = list(compile_prepare(prepare, policy=ctx.cfg.command_policy()))
    argv[0] = resolve_program(argv[0], ctx.root)
    profile = sandbox_for(ctx, ProcessKind.PREPARE, min_network(prepare.network, ctx))
    started = time.monotonic()
    env = build_env(
        extra={"TMPDIR": str(ctx.ws.temp_dir)},
        base_allowlist=(*BASE_ENV_ALLOWLIST, *PREPARE_ENV),
    )
    result = run_safe(
        argv, cwd=ctx.root, env=env, timeout_s=GATE_TIMEOUT_S,
        max_output_bytes=MAX_OUTPUT_BYTES, sandbox=profile,
    )  # fmt: skip
    output = _output(result, ctx)
    status, summary, _ = _judge(result, None)
    if status is not GateStatus.PASS and (last := _last_line(output)):
        summary = f"{summary}: {last}"
    gate_result = GateResult(
        name="prepare",
        status=status,
        required=True,
        duration_ms=int((time.monotonic() - started) * 1000),
        summary=summary[:1000],
        output=head_tail(output, _OUTPUT_HEAD, _OUTPUT_HEAD),
    )
    return CommandOutcome(gate_result, None, output)


_RANK = ("none", "api-only", "registries", "open")
PREPARE_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE")
"""The prepare step also gets the proxy settings (SECURITY.md §8)."""


def min_network(template: NetworkProfile, ctx: GateContext) -> NetworkProfile:
    """The stricter of the template's prepare network and `security.network.prepare`."""
    configured = ctx.cfg.security.network.prepare
    return min(template, configured, key=lambda p: _RANK.index(p.value))
