"""What every stub coding agent in this directory shares (SECURITY.md §14.3, build prompt 08).

Each stub (`claude`, `codex`, `copilot`, `gemini`) answers `--version` and its help like the
real tool, and treats any other call as a dispatch: it first ASSERTS what aipm must guarantee
(argv, environment, working directory), exiting 97 with `STUB-ASSERTION-FAILED: ...` on stderr
when one does not hold, then plays its scenario and prints output in its tool's format.

The stubs share one state directory, `$HOME/.stub-claude` (named for the first stub): the
scenario, `{"tasks": {"T-001": [attempt, ...], "*": [...]}, "help_drop": [flags]}`, is read
from `scenario.json`, and every call is logged to `calls.jsonl`. An attempt is `{"steps": [...],
"cost": 0.1, "text": "...", "exit": 0, "result": true, "error": false, "subtype": "success"}`;
the steps are listed in `STEPS`. `config_home_write` writes into the stub's own config home
(the variable `Stub.home_var` names). Python 3.8 syntax on purpose: the `python3` on PATH may
be an old system one.
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SECRET_MARK = "not-a-real-secret"


class Stub:
    """One stub agent: `tool` names it, `home_var` is its config-home variable and `key_var`
    the one variable that may hold a fake secret (its own API key)."""

    def __init__(self, tool, home_var, key_var):
        self.tool = tool
        self.home_var = home_var
        self.key_var = key_var

    # ------------------------------------------------------------ state

    def dir(self):
        path = Path(os.environ.get("HOME", "/nonexistent")) / ".stub-claude"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def scenario(self):
        path = self.dir() / "scenario.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def calls_for(self, task):
        log = self.dir() / "calls.jsonl"
        if not log.exists():
            return 0
        lines = log.read_text(encoding="utf-8").splitlines()
        return sum(1 for line in lines if json.loads(line).get("task") == task)

    # ------------------------------------------------------------ assertions

    def check_env(self, real_home_dir):
        """No fake secret but the stub's own key, which must be there; the config home is an
        existing directory that is not the user's own (`real_home_dir`, relative to HOME)."""
        for name, value in os.environ.items():
            if SECRET_MARK in value and name != self.key_var:
                fail("the environment holds a fake secret in " + name)
        if SECRET_MARK not in os.environ.get(self.key_var, ""):
            fail(self.key_var + " is missing")
        home = os.environ.get(self.home_var)
        if not home or not Path(home).is_dir():
            fail(self.home_var + " is not an existing directory")
        user_home = Path(os.environ.get("HOME", "/"))
        real = user_home / real_home_dir if real_home_dir else user_home
        if Path(home).resolve() == real.resolve():
            fail(self.home_var + " is the user's own " + str(real))

    def check_prompt(self, prompt):
        if SECRET_MARK in prompt:
            fail("the prompt holds a fake secret")

    # ------------------------------------------------------------ scenario

    def attempt_for(self, prompt):
        """(task, call index, attempt) for the task the prompt names."""
        found = re.search(r"\bT-[0-9]{3}\b", prompt)
        task = found.group(0) if found else "T-???"
        index = self.calls_for(task)
        plan = self.scenario().get("tasks", {})
        attempts = plan.get(task, plan.get("*", [{}]))
        attempt = attempts[min(index, len(attempts) - 1)] if attempts else {}
        return task, index, attempt

    def log_call(self, task, index, args, prompt, **extra):
        home = os.environ.get(self.home_var, "")
        record = {
            "tool": self.tool,
            "task": task,
            "call": index + 1,
            "argv": args,
            "cwd": os.getcwd(),
            "config_home": home,
            "settings_seen": os.path.exists(os.path.join(home, "settings.json")),
            "config_home_files": config_home_files(home),
            "prompt_has_escape": "\x1b" in prompt or "\x9b" in prompt,
            "prompt_has_evil_url": "evil.example" in prompt,
            "prompt_closing_tags": prompt.count("</untrusted"),
            "prompt_opening_tags": prompt.count("<untrusted "),
        }
        record.update(extra)
        with (self.dir() / "calls.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def play(self, attempt):
        for step in attempt.get("steps", []):
            run_step(step, self.home_var)

    def help(self, usage, flags):
        drop = set(self.scenario().get("help_drop", []))
        print(usage + "\n\nOptions:")
        for flag, text in flags:
            if not any(d in flag or d in text for d in drop):
                print("  %-40s %s" % (flag, text))


def fail(message):
    sys.stderr.write("STUB-ASSERTION-FAILED: " + message + "\n")
    sys.stderr.flush()
    sys.exit(97)


def value_of(args, flag):
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith(flag + "="):
            return arg.split("=", 1)[1]
    return None


def values_of(args, flag):
    return [args[i + 1] for i, arg in enumerate(args) if arg == flag and i + 1 < len(args)]


def check_forbidden(args, flags):
    for flag in flags:
        if any(a == flag or a.startswith(flag + "=") for a in args):
            fail("forbidden flag " + flag)


def check_cwd():
    cwd = Path.cwd()
    if not (cwd / ".git").is_file():
        fail("the working directory is not a linked worktree: " + str(cwd))
    if "aipm/worktrees/" not in cwd.as_posix() + "/":
        fail("the working directory is not under aipm/worktrees/: " + str(cwd))


def emit(event):
    sys.stdout.write(json.dumps(event) + "\n")
    sys.stdout.flush()


def config_home_files(home):
    """Every file in the agent's config home when the call starts, relative to it."""
    found = []
    if home and Path(home).is_dir():
        for current, dirs, files in os.walk(home):
            dirs.sort()
            for name in sorted(files):
                found.append(os.path.relpath(os.path.join(current, name), home))
    return found[:200]


def common_git_dir():
    text = (Path.cwd() / ".git").read_text(encoding="utf-8").strip()
    git_dir = Path(text.split(":", 1)[1].strip())
    common = git_dir / "commondir"
    if common.exists():
        return (git_dir / common.read_text(encoding="utf-8").strip()).resolve()
    return git_dir


def target(rel):
    path = Path.cwd() / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


STEPS = (
    "write",
    "append",
    "copy",
    "delete",
    "symlink",
    "write_abs",
    "git_config",
    "git_hook",
    "home_write",
    "config_home_write",
    "sleep",
    "daemon",
    "flood_mb",
    "nested_repo",
    "raw_stdout",
    "daemon_write",
)


def run_step(step, home_var):
    """One scenario step. Paths are relative to the worktree unless the step says otherwise."""
    if "write" in step:
        target(step["write"]).write_text(step["text"], encoding="utf-8")
    elif "append" in step:
        with target(step["append"]).open("a", encoding="utf-8") as handle:
            handle.write(step["text"])
    elif "copy" in step:
        target(step["copy"]).write_bytes(Path(step["from"]).read_bytes())
    elif "delete" in step:
        Path.cwd().joinpath(step["delete"]).unlink()
    elif "symlink" in step:
        target(step["symlink"]).symlink_to(step["to"])
    elif "write_abs" in step:
        Path(step["write_abs"]).write_text(step["text"], encoding="utf-8")
    elif "git_config" in step:
        with (common_git_dir() / "config").open("a", encoding="utf-8") as handle:
            handle.write(step["git_config"])
    elif "git_hook" in step:
        hook = common_git_dir() / "hooks" / step["git_hook"]
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text(step["text"], encoding="utf-8")
        hook.chmod(0o755)
    elif "home_write" in step:
        path = Path(os.environ["HOME"]) / step["home_write"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(step["text"], encoding="utf-8")
    elif "config_home_write" in step:
        path = Path(os.environ[home_var]) / step["config_home_write"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(step["text"], encoding="utf-8")
    elif "sleep" in step:
        time.sleep(float(step["sleep"]))
    elif "daemon" in step:
        pid = os.fork()
        if pid == 0:  # the child stays in the process group, as a careless daemon would
            Path(step["daemon"]).write_text(str(os.getpid()), encoding="utf-8")
            time.sleep(300)
            os._exit(0)
    elif "flood_mb" in step:
        chunk = b"x" * 1_048_576
        for _ in range(int(step["flood_mb"])):
            sys.stdout.buffer.write(chunk + b"\n")
        sys.stdout.flush()
    elif "nested_repo" in step:
        # A repository inside the worktree with one commit, as gate code the agent runs could
        # make; `config` is appended to its own .git/config (red-team v0.3).
        path = target(step["nested_repo"])
        path.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1")
        ident = ["-c", "user.name=agent", "-c", "user.email=agent@example.invalid"]
        subprocess.run(["git", "init", "-q", str(path)], check=True, env=env)
        (path / "lib.py").write_text(step.get("text", "VALUE = 1\n"), encoding="utf-8")
        subprocess.run(["git", "-C", str(path), "add", "lib.py"], check=True, env=env)
        subprocess.run(
            ["git", "-C", str(path)] + ident + ["commit", "-q", "-m", "x"], check=True, env=env
        )
        if "config" in step:
            with (path / ".git" / "config").open("a", encoding="utf-8") as handle:
                handle.write(step["config"])
    elif "raw_stdout" in step:
        sys.stdout.write(step["raw_stdout"] + "\n")
        sys.stdout.flush()
    elif "daemon_write" in step:
        # A child in its own session, so the process-group kill misses it on macOS: it keeps
        # rewriting a file of the worktree for `seconds` after the agent exits (R-14).
        # With `wait_for`, it starts only once that file exists (a test writes it from inside
        # the gates), and deletes `release` after its first write.
        path = Path.cwd() / step["daemon_write"]
        pid = os.fork()
        if pid == 0:
            os.setsid()
            devnull = os.open(os.devnull, os.O_RDWR)
            for fd in (0, 1, 2):
                os.dup2(devnull, fd)
            deadline = time.monotonic() + float(step.get("seconds", 20))
            wait_for = step.get("wait_for")
            while wait_for and not Path(wait_for).exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            released = False
            while time.monotonic() < deadline:
                try:
                    path.write_text(step["text"], encoding="utf-8")
                except OSError:
                    pass
                if step.get("release") and not released:
                    released = True
                    try:
                        os.unlink(step["release"])
                    except OSError:
                        pass
                time.sleep(0.05)
            os._exit(0)
    else:
        fail("unknown scenario step " + json.dumps(step))
