"""The process-wide redactor factory (SECURITY.md §8).

The LLM gateway, `StateStore` and logging build their redactor only here, from the full
`os.environ`, so no secret in the environment can be missed by a narrower snapshot.
"""

import os
from collections.abc import Iterable

from aipm.security.redact import Redactor


def process_redactor(extra_patterns: Iterable[str] = ()) -> Redactor:
    """Return a redactor built from the whole current environment."""
    return Redactor(dict(os.environ), extra_patterns=extra_patterns)
