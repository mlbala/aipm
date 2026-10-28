"""aipm: an AI product manager for your terminal.

The design is in docs/architecture/ARCHITECTURE.md and the security design in
docs/architecture/SECURITY.md.
"""

__all__ = ["__version__"]

try:
    from aipm._version import __version__
except ImportError:  # pragma: no cover - only before the hatch-vcs build hook has run
    __version__ = "0.0.0+unknown"
