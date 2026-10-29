"""Retry timing for provider calls: exponential backoff with jitter, honouring `retry-after`.

The clock and the random source are injected, so tests run the full retry path instantly and
deterministically.
"""

import random
import time
from typing import Protocol

MAX_TRIES = 5
"""Tries per call for 429, 5xx, timeouts and connection errors (ARCHITECTURE §5.4)."""
BASE_DELAY_S = 1.0
MAX_BACKOFF_S = 30.0
MAX_RETRY_AFTER_S = 120.0


class Clock(Protocol):
    """Something that can wait."""

    def sleep(self, seconds: float) -> None:
        """Block for `seconds`."""
        ...


class SystemClock:
    """The real clock."""

    def sleep(self, seconds: float) -> None:
        """Block for `seconds`."""
        time.sleep(seconds)


def backoff_delay(failures: int, *, retry_after: float | None, rng: random.Random) -> float:
    """Seconds to wait after `failures` failed tries (1 after the first failure).

    A provider's `retry-after` wins, capped at two minutes. Otherwise the delay doubles from one
    second up to 30, and half of it is random (equal jitter), so parallel callers spread out.
    """
    if retry_after is not None:
        return min(max(retry_after, 0.0), MAX_RETRY_AFTER_S)
    ceiling = min(MAX_BACKOFF_S, BASE_DELAY_S * 2 ** max(failures - 1, 0))
    return ceiling / 2 + rng.uniform(0.0, ceiling / 2)
