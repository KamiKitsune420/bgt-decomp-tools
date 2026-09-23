"""
libcheck -- decompile NVGT's own library and require it to compile again.

NVGT ships its standard library as source (`include/*.nvgt`), so, as with BGT's
`bgt libcheck`, it is the one body of code whose original is known and which
nobody here wrote. This builds a corpus out of it, in both forms a game can
ship, and holds the decompiler to it:

    bgt nvgt libcheck                                  # nvgt.exe from NVGT_COMPILER or C:\\nvgt
    bgt nvgt libcheck --compiler D:/nvgt/nvgt.exe sound_pool menu -v
    python tools/nvgt/libcheck.py --keep work/libcheck --json results.json

For every include it:

1. writes a harness that `#include`s the file and, run by nvgt.exe, exports its
   own module twice -- `get_bytecode(false)` with debug information and
   `get_bytecode(true)` stripped, as a release build ships it;
2. decompiles each into a full project (`recover.generate_project`);
3. compiles that project with the same nvgt.exe.

A module passes when the recovered project compiles. The stripped build is the
harder case and the one that matters: no local names, no declaration positions,
so one frame slot can hold a `bool` in one scope and a `float` in the next and
nothing says where the switch happens.

An include that does not compile *as shipped* -- this build lacks the `sqlite3`
or `pack` type it uses, say -- is reported as `include-broken` and left out of
the score: there is no bytecode to decompile, so it measures NVGT, not this.

Compiling proves the output is valid AngelScript, not that it means the same
thing. `tests/nvgt/test_roundtrip_behavior.py` covers that half: it RUNS a
decompiled program and compares what it computes.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

try:                      # installed as a package
    from . import asreader, decompile, recover
except ImportError:       # run directly from a checkout
    import asreader
    import decompile
    import recover

DEFAULT_COMPILERS = (r"C:\nvgt\nvgt.exe", r"C:\Program Files\nvgt\nvgt.exe")
KINDS = ("debug", "strip")

HARNESS = """#include "{include}"
void main() {{
\tfile_put_contents("debug.bin", script_get_module("nvgt_game", 0).get_bytecode(false));
\tfile_put_contents("strip.bin", script_get_module("nvgt_game", 0).get_bytecode(true));
}}
"""


def find_compiler(explicit: Optional[str]) -> Optional[Path]:
    candidates = [explicit, os.environ.get("NVGT_COMPILER"), *DEFAULT_COMPILERS,
                  shutil.which("nvgt")]
    for c in candidates:
        if c and Path(c).is_file():
            return Path(c)
    return None


def first_error(text: str) -> str:
    """The first compiler ERROR line, or the first line when there is none."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return next((l for l in lines if "ERROR" in l), lines[0] if lines else "")


def export_bytecode(compiler: Path, include: Path, folder: Path,
                    timeout: int = 90) -> Optional[str]:
    """Build `include` into debug.bin / strip.bin in `folder`; None on success."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "harness.nvgt").write_text(
        HARNESS.format(include=include.resolve().as_posix()), encoding="utf-8")
    try:
        result = subprocess.run([str(compiler), "harness.nvgt"], cwd=folder,
                                capture_output=True, text=True, errors="replace",
                                timeout=timeout)
    except subprocess.TimeoutExpired:
        return "harness did not finish (a script exception shows a modal dialog)"
    if all((folder / f"{kind}.bin").is_file() for kind in KINDS):
        return None
    return first_error(result.stdout + result.stderr) or f"exit {result.returncode}"


def check_module(compiler: Path, path: Path, out: Path) -> Dict[str, object]:
    """Decompile one bytecode file, recompile the project, report the numbers."""
    row: Dict[str, object] = {}
    module = asreader.read_module(path.read_bytes())
    text = decompile.decompile_module(module)
    row["functions"] = len(module.script_functions)
    row["decompiler_errors"] = text.count("[decompiler error:")
    row["unhandled_opcodes"] = text.count("(unhandled)")
    row["gotos"] = len(re.findall(r"\bgoto\s+L", text))
    manifest = recover.generate_project(str(path), out, compiler=str(compiler))
    row["compile"] = manifest["source_compilation"]
    if row["compile"] != "passed":
        report = out / "compile-report.txt"
        row["first_error"] = first_error(report.read_text(encoding="utf-8", errors="replace")
                                         if report.exists() else "")
    return row


def run(compiler: Path, include_dir: Path, work: Path, only=(),
        progress=print) -> List[Dict[str, object]]:
    rows = []
    for include in sorted(include_dir.glob("*.nvgt")):
        name = include.stem
        if only and name not in only:
            continue
        folder = work / name
        problem = export_bytecode(compiler, include, folder)
        if problem:
            rows.append({"name": name, "kind": "-", "compile": "include-broken",
                         "first_error": problem})
            progress("%-28s include-broken  %s" % (name, problem[:90]))
            continue
        for kind in KINDS:
            row = {"name": name, "kind": kind}
            try:
                row.update(check_module(compiler, folder / f"{kind}.bin",
                                        folder / f"project_{kind}"))
            except Exception as exc:                  # noqa: BLE001 -- reported, not hidden
                row["compile"] = "exception"
                row["first_error"] = "%s: %s" % (type(exc).__name__, exc)
            rows.append(row)
            progress("%-28s %-5s %-8s %s" % (name, kind, row["compile"],
                                            str(row.get("first_error", ""))[:90]))
    return rows


def summary(rows: List[Dict[str, object]]) -> str:
    scored = [r for r in rows if r["compile"] != "include-broken"]
    passed = [r for r in scored if r["compile"] == "passed"]
    broken = sorted({r["name"] for r in rows if r["compile"] == "include-broken"})
    lines = ["%d / %d library modules recompile after decompilation" % (len(passed), len(scored))]
    for kind in KINDS:
        of_kind = [r for r in scored if r["kind"] == kind]
        lines.append("  %-6s %d / %d" % (kind, sum(r["compile"] == "passed" for r in of_kind),
                                         len(of_kind)))
    lines.append("  decompiler errors %d, unhandled opcodes %d, gotos %d" % tuple(
        sum(int(r.get(k, 0)) for r in scored)
        for k in ("decompiler_errors", "unhandled_opcodes", "gotos")))
    if broken:
        lines.append("  not scored (include does not compile as shipped): " + ", ".join(broken))
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="bgt nvgt libcheck", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", help="only these includes (file stems)")
    ap.add_argument("--compiler", help="nvgt.exe (default: NVGT_COMPILER, then C:\\nvgt)")
    ap.add_argument("--include", help="include folder (default: beside the compiler)")
    ap.add_argument("--keep", metavar="DIR",
                    help="work here and keep the bytecode and projects (default: a temp dir)")
    ap.add_argument("--json", metavar="FILE", help="also write every row as JSON")
    ap.add_argument("-v", "--verbose", action="store_true", help="a line per module")
    args = ap.parse_args(argv)

    compiler = find_compiler(args.compiler)
    if compiler is None:
        print("libcheck: no nvgt.exe -- pass --compiler or set NVGT_COMPILER", file=sys.stderr)
        return 2
    include_dir = Path(args.include) if args.include else compiler.parent / "include"
    if not include_dir.is_dir():
        print("libcheck: no include folder at %s -- pass --include" % include_dir,
              file=sys.stderr)
        return 2

    work = Path(args.keep) if args.keep else Path(tempfile.mkdtemp(prefix="nvgt_libcheck_"))
    try:
        rows = run(compiler, include_dir, work, set(args.names),
                   progress=print if args.verbose else (lambda _line: None))
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
    if not rows:
        print("libcheck: no includes matched in %s" % include_dir, file=sys.stderr)
        return 2
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(summary(rows))
    failed = [r for r in rows if r["compile"] not in ("passed", "include-broken")]
    for r in failed if not args.verbose else ():
        print("  FAIL %-26s %-5s %s" % (r["name"], r["kind"], str(r.get("first_error", ""))[:100]))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
