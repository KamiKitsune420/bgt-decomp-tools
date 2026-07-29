"""
bgtdecomp -- tooling for games built with BGT (BlastBay Gaming Toolkit).

Every module here works two ways on purpose:

    python tools/bgt_unpack.py game.exe -o out      # straight from a checkout
    from bgtdecomp import bgtlib                    # after `pip install -e .`

Running a file directly puts its own directory on `sys.path`, so the plain sibling
imports resolve; installed, the package-relative imports resolve instead. That is why
the modules try the relative import first and fall back -- neither form needs a
`sys.path` fixup at call sites, which used to break under test runners.
"""

__version__ = "0.2.0"
