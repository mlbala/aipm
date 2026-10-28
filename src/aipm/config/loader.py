"""Layered config: defaults < user < repo < env < flags, with key classes enforced (§15)."""

from pathlib import Path

from aipm.config.schema import Config


def load_config(project: Path) -> Config:
    """Merge every layer; ignore user-only repo keys and repo relaxations, with warnings."""
    raise NotImplementedError("v0.1: build prompt 02")
