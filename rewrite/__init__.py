"""Implementation package for the sole Sylanne 3 root plugin entry point."""

# Make the implementation package self-sufficient when imported directly: the
# cold-load package probe (and any embedder that imports `rewrite` without
# executing main.py's runtime bootstrap) must be able to import sylanne3.
import sys as _sys
from pathlib import Path as _Path

_IMPL_ROOT = str(_Path(__file__).resolve().parent)
if _IMPL_ROOT not in _sys.path:
    _sys.path.insert(0, _IMPL_ROOT)
