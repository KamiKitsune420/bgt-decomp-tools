"""Where NVGT is -- one answer, for every tool here that needs the compiler.

Three places used to answer this, and they disagreed. `bgt tonvgt` searched the
checkout's `release/` first, `bgt nvgt libcheck` searched `C:\\nvgt` and never
the checkout at all, and `bgt nvgt recover --check-with` made the caller name a
path. So a toolkit that had just found NVGT for the converter would check a
*different* NVGT for the library score, and on a machine with both a built
checkout and an installed copy the two answers were different engines.

That is the failure this file keeps recording in other guises -- two places
answering one question, with one of them stricter or staler -- so it is one
function and the callers differ only in what they wrap it in.

**`NVGT_COMPILER` wins**, because somebody who set it meant it. Then the usual
places, then `PATH`. **A miss returns None rather than a guess**: a compile
check that silently ran the wrong compiler would report a verdict about the
wrong engine, which is worse than reporting that it could not run.
"""

from __future__ import annotations

import os
import shutil
from typing import Optional, Sequence, Tuple

#: Where NVGT usually is. A checkout's `release/` holds the compiler, its
#: `include/` and `bgt_compat.nvgt`; an installed copy has the same shape, which
#: is why one list serves both and why the checkout comes first -- a person with
#: a checkout built it on purpose.
ROOTS: Tuple[str, ...] = (
    os.path.join(os.path.expanduser("~"), "Documents", "GitHub", "nvgt",
                 "release"),
    r"C:\nvgt",
    r"C:\Program Files\nvgt",
)

#: What the executable is called, so a caller never spells it.
EXE_NAME = "nvgt.exe"


def candidate_roots(explicit: Optional[str] = None) -> Sequence[str]:
    """Every place to look, in the order they are looked at."""
    roots = []
    if explicit:
        roots.append(explicit)
    env = os.environ.get("NVGT_COMPILER")
    if env:
        roots.append(env)
    roots.extend(ROOTS)
    found = shutil.which("nvgt")
    if found:
        roots.append(found)
    return roots


def find_exe(explicit: Optional[str] = None) -> Optional[str]:
    """`nvgt.exe`'s path, or None with nothing guessed.

    `explicit` may be the executable or the folder holding it, because callers
    are handed both: `--compiler D:/nvgt/nvgt.exe` and `--nvgt D:/nvgt` are the
    same intent spelled two ways, and making the caller normalise it is how the
    two spellings drift apart.
    """
    for root in candidate_roots(explicit):
        if not root:
            continue
        exe = root if os.path.isfile(root) else os.path.join(root, EXE_NAME)
        if os.path.isfile(exe):
            return exe
    return None
