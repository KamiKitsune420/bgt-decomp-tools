# NVGT tests

Run with the rest of the suite:

```bash
python -m pytest tests/ -q
```

The portable tests use synthetic PE stubs and owned fixtures only. The rest
skip unless their optional inputs are present. Nothing here is committed that
is not owned source.

| enables | how |
|---|---|
| owned compile / decompile / recompile / run round trips (`test_behavior`, much of `test_regressions`, `test_project`, `test_source_evidence`, `test_signatures`) | build `fixtures/build/bcdump.exe` with `extra/nvgt/build_bcdump.bat` (needs `NVGT_SOURCE` pointing at an NVGT checkout with its AngelScript SDK built, and MinGW `g++`) |
| compiler-backed library reuse, project compilation | `NVGT_COMPILER` = path to `nvgt.exe`, `NVGT_INCLUDE` = its `include/` folder |
| game-specific regressions | `NVGT_BOPIT_EXE`, `NVGT_BOPIT_SOURCE`, `NVGT_NUMBER_EXE`, `NVGT_LIBRARY_PROBE` |
| key-schedule scan across chunk boundaries | NumPy installed (`pip install -e .[scan]`) |

`conftest.py` puts `tools/nvgt` on `sys.path`, so these tests import the modules
flat (`import extract`), exactly as they did in the upstream project.
