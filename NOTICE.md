# Notices

This project is MIT-licensed (see [LICENSE.md](LICENSE.md)). Part of it is adapted
from a third-party MIT project; this file records which part, and carries that
project's license notice as its terms require.

## BGT decompilation toolkit

Copyright (c) 2026 KamiKitsune420 (Adel Spence).

Everything under `tools/` except `tools/nvgt/`, plus `tests/test_toolkit.py`,
`docs/ghidra_workflow.md` and `CLAUDE.md`. Earlier releases of this part were
published under the PolyForm Noncommercial License 1.0.0; from this release on
it is MIT.

## NVGT source recovery

Copyright (c) 2026 beyond sight tech. MIT License.
Upstream: <https://github.com/beyondsighttech/nvgt-source-recovery>

Incorporated, with changes, as:

| here | upstream |
|---|---|
| `tools/nvgt/*.py` (except `nvgt_pack.py` and `__init__.py`) | the top-level `*.py` modules |
| `tools/nvgt/gen_opcodes.py`, `tools/nvgt/refine_source_archive.py` | `tools/` |
| `tests/nvgt/test_*.py`, `tests/nvgt/fixtures/` | the top-level tests and `.as` / `.nvgt` fixtures |
| `extra/nvgt/bcdump.cpp`, `extra/nvgt/build_bcdump.bat` | `tools/` |
| `docs/nvgt.md` | condensed from `README.md`, `USAGE.md` and `REVIEW.md` |

Changes made while merging are listed in `docs/nvgt.md` under "Changes in the
merged toolkit".

## New in the merged toolkit

`tools/engine.py`, `tools/nvgt/nvgt_pack.py`, `tests/test_integration.py` and
`tests/nvgt/conftest.py`, by the maintainers of this repository, MIT.

## Formats read, not code copied

Readers here are transcriptions of file-format logic read out of other
software: AngelScript's `asCReader` (zlib license) as linked into BGT and NVGT
binaries, and NVGT's own `src/pack.cpp`, `src/crypto.cpp` and
`src/nvgt_angelscript.cpp` (zlib license, Copyright (c) 2022-2026 Sam Tupy).
No source from those projects is included.

This repository ships no game files, engine binaries or keys.

## Third-party license: nvgt-source-recovery

The code listed under "NVGT source recovery" above is used under the following
license, which requires this notice to accompany it:

    MIT License

    Copyright (c) 2026 beyond sight tech

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
