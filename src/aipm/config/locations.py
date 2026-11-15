"""Where the user config, trust store, logs and caches live, and warnings when that moved.

aipm keeps following `HOME`, `XDG_*` and `AIPM_CONFIG`, which Linux users set on purpose. A
repository `.env` loaded by a tool such as pipenv can set them too, and the setting stays in the
shell after `cd` to another repository, so each run warns when they point somewhere unusual
(v0.1 O-1, decision B; SECURITY.md §15 R-24). Standard library only: the CLI callback calls this
on every run.
"""

import os
import pwd
from collections.abc import Mapping
from pathlib import Path

USER_CONFIG_ENV = "AIPM_CONFIG"
WATCHED_DIRS: tuple[str, ...] = (
    USER_CONFIG_ENV, "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME",
)  # fmt: skip
"""The variables that move the user config, the trust store and logs, or aipm's caches."""
_SHOWN = 200


def account_home() -> str | None:
    """The home directory of the account running aipm, from the password database; `None` when
    there is no entry. Tests replace this function in-process; no environment variable can."""
    try:
        return pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        return None


def git_root(start: Path) -> Path | None:
    """The nearest directory from `start` upwards that holds `.git`, like `find_repo_root`."""
    current = Path(os.path.realpath(start))
    for candidate in (current, *current.parents):
        if os.path.lexists(candidate / ".git"):
            return candidate
    return None


def _show(value: str) -> str:
    """At most 200 characters, cut in the middle: the end of a path says where it leads."""
    if len(value) <= _SHOWN:
        return value
    return f"{value[:60]}…{value[-(_SHOWN - 61) :]}"


def _real(value: str) -> str:
    """`value` with `~` expanded and links and `..` resolved; as given when it cannot be."""
    try:
        return os.path.realpath(Path(value).expanduser())
    except (RuntimeError, OSError, ValueError):  # `~nosuchuser`, a NUL byte
        return value


def location_warnings(env: Mapping[str, str] | None = None) -> list[str]:
    """The warnings to print on every run (empty when nothing is moved).

    - `AIPM_CONFIG` is set: the user config, which can set `llm.base_url`, comes from that file;
    - `HOME` is not the account's home: the config, trust store and logs follow `HOME`;
    - `AIPM_CONFIG` or `XDG_CONFIG_HOME`/`XDG_STATE_HOME`/`XDG_CACHE_HOME` is inside a git work
      tree, where a repository's files would act as the user's own.
    """
    environ = os.environ if env is None else env
    found: list[str] = []
    config = environ.get(USER_CONFIG_ENV)
    if config:
        found.append(
            f"{USER_CONFIG_ENV} is set, so your user config is read from "
            f"{_show(_real(config))}; a repository .env loaded by a tool such as pipenv can set "
            "it. Unset it unless you set it yourself."
        )
    home = environ.get("HOME")
    if home:
        account = account_home()
        if account is None:
            found.append(
                "aipm cannot look up your account's home directory to check HOME "
                f"({_show(home)}); your config, trust store and logs follow HOME."
            )
        elif _real(home) != os.path.realpath(account):
            found.append(
                f"HOME is {_show(_real(home))}, not your account's home {_show(account)}; your "
                "config, trust store and logs follow HOME, which a repository .env loaded by a "
                "tool such as pipenv can set."
            )
    for name in WATCHED_DIRS:
        value = environ.get(name)
        if not value:
            continue
        root = git_root(Path(_real(value)))
        if root is not None:
            found.append(
                f"{name} points inside the git work tree {_show(str(root))} "
                f"({_show(_real(value))}); a repository's files there would act as your own."
            )
    return found
