"""
pytest setup for the NVGT half of the suite.

These tests came from nvgt-source-recovery, where every module sat at the top
level and was imported flat (`import extract`, `from decompile import ...`).
The modules still support that -- each one tries its package-relative import
first and falls back to the flat one -- so putting tools/nvgt on sys.path runs
the tests unchanged against the merged code.

Fixtures live in fixtures/: owned AngelScript sources, and optionally
fixtures/build/bcdump.exe (extra/nvgt/build_bcdump.bat builds it). Tests that
need the host, a real NVGT compiler or a local game skip when those are absent;
see tests/nvgt/README.md for the environment variables that enable them.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS_NVGT = HERE.parents[1] / "tools" / "nvgt"

for path in (str(TOOLS_NVGT), str(HERE)):
    if path not in sys.path:
        sys.path.insert(0, path)
