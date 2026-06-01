"""Non-tulpa INK protocol reference client."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ink-interop")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = ["__version__"]
