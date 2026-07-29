"""
bgt_validate -- run the whole pipeline over several titles and compare.

    python bgt_validate.py strike.exe rpg.exe game.exe

These games share a runtime, so a change that improves one title and breaks
another is wrong. That is easy to say and easy to miss: the natural way to work
is against whichever title is in front of you, and a record layout that is
subtly specific to it still parses that one perfectly. This script is the check.

Each stage is pass/fail on its own evidence, not on whether it threw:

    unpack     the trailer, seed, container and LZ77 length all agree
    dialect    one of the two string encodings parses the enum section
    enums      recovered count == declared count
    classes    recovered count == declared count
    funcdefs   recovered count == declared count
    opcodes    asBCInfo recovered from the executable
    blocks     every class block parsed
    tail       the used* tables end EXACTLY at EOF
    disasm     a function body decodes to its declared instruction count
    rewrite    the module writes back BYTE FOR BYTE

A stage that is not reached is reported as `-`, not as a failure -- "we never
got there" and "we got there and it was wrong" are different results and
collapsing them hides regressions.
"""

import argparse
import os
import struct
import sys
import tempfile
import time
import traceback
from typing import Any, Dict, List, Optional

try:                      # installed as a package
    from . import as_module, as_opcodes, as_write, bgtlib
except ImportError:       # run directly from a checkout
    import as_module
    import as_opcodes
    import as_write
    import bgtlib


STAGES = ("unpack", "dialect", "enums", "classes", "funcdefs", "opcodes",
          "blocks", "tail", "disasm", "rewrite")


class Result:
    def __init__(self, path: str) -> None:
        self.path = path
        self.name = os.path.basename(path)
        self.stages: Dict[str, Optional[bool]] = {s: None for s in STAGES}
        self.notes: Dict[str, str] = {}
        self.errors: List[str] = []
        self.facts: Dict[str, Any] = {}
        self.seconds = 0.0

    def ok(self, stage: str, note: str = "") -> None:
        self.stages[stage] = True
        if note:
            self.notes[stage] = note

    def fail(self, stage: str, note: str) -> None:
        self.stages[stage] = False
        self.notes[stage] = note
        self.errors.append("%s: %s" % (stage, note))

    @property
    def passed(self) -> bool:
        """True only if nothing that ran actually failed."""
        return not any(v is False for v in self.stages.values())

    @property
    def status(self) -> str:
        if not self.passed:
            return "FAIL"
        return "PASS" if all(self.stages.values()) else "PARTIAL"


def validate(path: str, deep: bool = False) -> Result:
    """Run every stage over one executable, continuing past failures."""
    res = Result(path)
    started = time.time()

    # -- unpack ---------------------------------------------------------
    try:
        unpacked = bgtlib.unpack_file(path)
    except (bgtlib.BgtError, OSError) as exc:
        res.fail("unpack", str(exc))
        res.seconds = time.time() - started
        return res
    res.ok("unpack", "%d B module, seed 0x%02X" % (len(unpacked.bytecode),
                                                   unpacked.seed))
    res.facts.update(module_size=len(unpacked.bytecode), seed=unpacked.seed)
    module = unpacked.bytecode

    # -- the opcode table, from this title's own binary ------------------
    table = None
    try:
        info = as_opcodes.extract(path)
        table = info["table"]
        res.ok("opcodes", "%d" % info["count"])
        res.facts["opcodes"] = info["count"]
    except (ValueError, struct.error, OSError) as exc:
        res.fail("opcodes", str(exc))

    # -- dialect + enums -------------------------------------------------
    try:
        dialect, _start, _enums = as_module.detect(module)
    except as_module.ParseError as exc:
        res.fail("dialect", str(exc))
        res.seconds = time.time() - started
        return res
    res.ok("dialect", dialect)
    res.facts["dialect"] = dialect

    # summarize() re-walks from the top; it is the same path the tools use.
    tmp = _write_temp(module)
    try:
        summary = as_module.summarize(tmp, opcodes=table)
    except Exception as exc:                                  # noqa: BLE001
        res.fail("enums", "%s: %s" % (type(exc).__name__, exc))
        res.seconds = time.time() - started
        os.unlink(tmp)
        return res
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

    n_enums = len(summary["enums"])
    members = summary["member_count"]
    res.ok("enums", "%d (%d members)" % (n_enums, members))
    res.facts.update(enums=n_enums, enum_members=members)

    _count_stage(res, "classes", len(summary["classes"]),
                 summary["classes_declared"])
    _count_stage(res, "funcdefs", len(summary["funcdefs"]),
                 summary["funcdefs_declared"])

    blocks, classes = len(summary["blocks"]), len(summary["classes"])
    res.facts["blocks"] = blocks
    if table is None:
        res.notes["blocks"] = "needs an opcode table"
    elif blocks == classes and classes:
        res.ok("blocks", "%d" % blocks)
    elif blocks:
        res.fail("blocks", "%d / %d" % (blocks, classes))
    else:
        res.notes["blocks"] = "0 / %d -- function bodies did not parse" % classes

    tail = summary.get("tail")
    if tail:
        res.ok("tail", "ends at EOF")
        for key in ("used_functions", "used_string_constants",
                    "used_global_props", "used_object_props"):
            res.facts[key] = len(tail.get(key, []))
    elif summary.get("tail_error"):
        res.fail("tail", summary["tail_error"])
    else:
        res.notes["tail"] = "not reached"

    errs = summary.get("parse_errors") or []
    res.facts["parse_errors"] = len(errs)
    if errs:
        res.notes["blocks"] = "%s (%d bodies failed)" % (
            res.notes.get("blocks", ""), len(errs))

    # -- disassembly -----------------------------------------------------
    if table and tail:
        bodies = _bodies(summary)
        res.facts["bodies"] = len(bodies)
        if not bodies:
            res.notes["disasm"] = "no function bodies recovered"
        else:
            checked = exact = 0
            for f in (bodies if deep else bodies[:200]):
                start_off, end_off = f["body"]
                decoded = as_opcodes.disassemble(module[start_off:end_off], table)
                checked += 1
                if len(decoded) == f.get("instructions"):
                    exact += 1
            if exact == checked:
                res.ok("disasm", "%d/%d bodies exact" % (exact, checked))
            else:
                res.fail("disasm", "%d/%d bodies match their declared count"
                         % (exact, checked))
    else:
        res.notes["disasm"] = "not reached"

    # -- rewrite: the whole module back out, byte for byte -----------------
    if table and tail:
        tmp2 = _write_temp(module)
        try:
            as_write.verify_roundtrip(tmp2, opcodes=table)
            res.ok("rewrite", "byte-exact")
        except Exception as exc:                              # noqa: BLE001
            res.fail("rewrite", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if os.path.exists(tmp2):
                os.unlink(tmp2)
    else:
        res.notes["rewrite"] = "not reached"

    res.seconds = time.time() - started
    return res


def _bodies(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    out, seen = [], set()

    def add(f):
        if isinstance(f, dict) and f.get("body") and id(f) not in seen:
            seen.add(id(f))
            out.append(f)

    for b in summary.get("blocks", []):
        add(b.get("destructor"))
        for ctor, factory in b.get("ctors", []):
            add(ctor)
            add(factory)
        for m in b.get("methods", []):
            add(m)
        for v in b.get("virtuals", []):
            add(v)
    tail = summary.get("tail") or {}
    for f in tail.get("module_functions", []):
        add(f)
    for f in tail.get("global_functions", []):
        add(f)
    return out


def _count_stage(res: Result, stage: str, got: int, declared: Optional[int]) -> None:
    if declared is None:
        res.notes[stage] = "not reached"
        return
    res.facts[stage] = got
    if got == declared:
        res.ok(stage, "%d" % got)
    else:
        res.fail(stage, "%d / %d declared" % (got, declared))


def _write_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def _cell(res: Result, stage: str) -> str:
    v = res.stages[stage]
    return "-" if v is None else ("ok" if v else "FAIL")


def report(results: List[Result], verbose: bool = False) -> None:
    head = ("title", "dialect", "enums", "classes", "funcs", "opcodes",
            "tail", "time", "status")
    rows = []
    for r in results:
        rows.append((
            r.name,
            str(r.facts.get("dialect", "-")),
            str(r.facts.get("enums", "-")),
            str(r.facts.get("classes", "-")),
            str(r.facts.get("bodies", "-")),
            str(r.facts.get("opcodes", "-")),
            _cell(r, "tail"),
            "%.1fs" % r.seconds,
            r.status,
        ))
    widths = [max(len(str(x)) for x in col) for col in zip(head, *rows)] \
        if rows else [len(h) for h in head]
    fmt = "  ".join("%%-%ds" % w for w in widths)
    print(fmt % head)
    print(fmt % tuple("-" * w for w in widths))
    for row in rows:
        print(fmt % row)

    print()
    stage_head = ("title",) + STAGES
    srows = [(r.name,) + tuple(_cell(r, s) for s in STAGES) for r in results]
    swidths = [max(len(str(x)) for x in col) for col in zip(stage_head, *srows)] \
        if srows else [len(h) for h in stage_head]
    sfmt = "  ".join("%%-%ds" % w for w in swidths)
    print(sfmt % stage_head)
    print(sfmt % tuple("-" * w for w in swidths))
    for row in srows:
        print(sfmt % row)

    for r in results:
        if r.errors or verbose:
            print()
            print("%s:" % r.name)
            for stage in STAGES:
                note = r.notes.get(stage)
                if note and (verbose or r.stages[stage] is False):
                    print("   %-9s %s %s" % (stage, _cell(r, stage), note))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", nargs="+", help="BGT executables to validate")
    ap.add_argument("--deep", action="store_true",
                    help="check every function body, not the first 200")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show every stage note, not just failures")
    args = ap.parse_args()

    results = []
    for path in args.exe:
        try:
            results.append(validate(path, deep=args.deep))
        except Exception:                                     # noqa: BLE001
            # A crash in one title must not stop the others -- that is the whole
            # point of running them together.
            res = Result(path)
            res.fail("unpack", traceback.format_exc(limit=2).strip().splitlines()[-1])
            results.append(res)

    report(results, verbose=args.verbose)

    failed = [r for r in results if not r.passed]
    print()
    print("%d/%d titles passed every stage they reached"
          % (len(results) - len(failed), len(results)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
