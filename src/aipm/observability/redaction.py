"""The process-wide redactor factory (SECURITY.md §8).

The LLM gateway, `StateStore` and logging build their redactor only here, from the full
`os.environ` plus every key read from the OS keychain (ADR-0033), so no secret aipm holds can be
missed by a narrower snapshot. Keychain values never enter `os.environ`, so they are added here.
"""

import os
from collections.abc import Iterable

from aipm.config import keychain
from aipm.security.redact import Redactor

_KEYCHAIN_PREFIX = "AIPM_KEYCHAIN_SECRET_"
"""Keychain values are added under this prefix plus the variable name, so the redactor treats
every one as a secret whatever the variable is called."""


def process_redactor(extra_patterns: Iterable[str] = ()) -> Redactor:
    """Return a redactor built from the whole current environment and the keychain's keys."""
    secrets = dict(os.environ)
    for name, value in keychain.resolved_values().items():
        secrets[f"{_KEYCHAIN_PREFIX}{name}"] = value
    return Redactor(secrets, extra_patterns=extra_patterns)
