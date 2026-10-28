"""`aipm --help` starts in under 300 ms (ARCHITECTURE §20, v0.1 acceptance criterion 4).

Measured on the installed console script, not through `uv run`. Skipped on CI runners, whose
timing is too noisy; run it locally, or set AIPM_RUN_TIMING=1.
"""

import subprocess
import sys
import time
from pathlib import Path

import pytest

BUDGET_S = 0.300
AIPM = Path(sys.executable).with_name("aipm")


def elapsed(argv: list[str]) -> float:
    start = time.perf_counter()
    subprocess.run(argv, capture_output=True, check=True, timeout=30)
    return time.perf_counter() - start


@pytest.mark.timing
def test_help_is_fast() -> None:
    elapsed([str(AIPM), "--help"])  # warm the bytecode cache
    best = min(elapsed([str(AIPM), "--help"]) for _ in range(5))
    assert best < BUDGET_S, f"aipm --help took {best * 1000:.0f} ms"


def test_help_imports_no_heavy_modules() -> None:
    """The CLI must not import the LLM SDKs, pydantic or Rich just to show help."""
    code = (
        "import sys\n"
        "from aipm.cli.main import app\n"
        "heavy = ('anthropic', 'openai', 'httpx', 'pydantic', 'rich', 'ruamel', 'jinja2')\n"
        "print(sorted(m for m in sys.modules if m.split('.')[0] in heavy))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=30
    )
    assert proc.stdout.strip() == "[]", proc.stdout
