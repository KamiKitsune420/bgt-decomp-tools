#!/usr/bin/env python3
"""`bgt roundtrip`: the original bytecode against the RECOMPILED bytecode.

Every other check in this toolkit compares a recovery against something
*smaller* than the program. `bgt audit` compares a body's callees, literals
and constants as multisets, so it cannot see a statement that moved, a
comparison whose operator changed, or a conditional that lost its guard.
`bgt libcheck` compares against BGT's own library source, which covers 149 of
a title's 926 bodies. `bgt apicheck` asks only whether a call could resolve.
None of them answers the question the whole project is pointed at: **does the
recovered source mean what the original meant?**

The compiler answers it. Recover a title, build it, unpack what the engine
wrote, and compare the two modules instruction for instruction:

    bgt recover game.exe -o out/
    bgt compile out/game.bgt --build release
    bgt roundtrip game.exe out/game.exe

What is compared, and what is deliberately not:

* the opcode sequence, which is the whole point;
* every operand that NAMES something -- a callee, a literal, a global, a
  member, a type -- taken as the name, because a rebuild reorders the tables
  and an index means nothing across two modules;
* every operand that is a constant, taken as its value;
* a jump, taken as its relative distance in instructions, which is
  comparable between two bodies of the same shape where a label number is
  not;
* a frame slot, renumbered first-seen for the strict score and dropped for
  the loose one. The compiler allocates slots in its own order and a
  recovered body with one local more shifts every later offset, so comparing
  raw offsets would report every body as differing and mean nothing by it.

So the loose score answers "does this body do the same things in the same
order?" and the strict one "...out of the same slots?".

**The headline is the edit distance, not the exact-match count.** A body
usually differs for several independent reasons at once, so closing one of
them leaves it differing: the first real fix measured against this halved
Super Egg Hunt's distance (20,036 instructions to 15,124) while the
exact-match count did not move at all. An exact-match count is the coarse
summary; the edit distance is the measurement.

**It is calibrated against a known answer, which is what makes it
trustworthy.** `bgt recover` substitutes BGT's own shipped source for a
library file that matches, so those bodies are compiled from source this
project did not write -- and all four of Super Egg Hunt's
`position_sound_*` bodies, one of them 110 instructions, come back
**instruction for instruction identical**, as do `number_speaker::speak`,
`speak_next` and `speak_wait`. So the compiler is deterministic, equal source
really does give equal bytecode, and every differing body is a difference
between the recovered source and the original's -- not noise.
"""
from __future__ import annotations

import argparse
import collections
import difflib
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

if __package__:
    from . import as_disasm, bgtlib
else:  # run directly
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import as_disasm
    import bgtlib

#: Which of an opcode's operands are frame slots, by `asBCInfo[].type`.
#:
#: This is AngelScript's own `asBCType` enum, and it is not guessed: every
#: entry's operand count is checked against the count the build's own opcode
#: table declares, and a disagreement raises rather than being worked around
#: -- a wrong mapping here would make every slot-versus-constant decision
#: wrong quietly, which is the failure this whole document is organised
#: against.
#:
#:   W = a plain word operand (a count, a size, a stack offset)
#:   V = a word operand naming a FRAME SLOT
#:   C = a dword or qword constant
OPERAND_KINDS: Dict[int, Tuple[str, ...]] = {
    0:  (),                 # INFO
    1:  (),                 # NO_ARG
    2:  ("W",),             # W_ARG
    3:  ("V",),             # wW_ARG
    4:  ("C",),             # DW_ARG
    5:  ("V", "C"),         # rW_DW_ARG
    6:  ("C",),             # QW_ARG
    7:  ("C", "C"),         # DW_DW_ARG
    8:  ("V", "V", "V"),    # wW_rW_rW_ARG
    9:  ("V", "C"),         # wW_QW_ARG
    10: ("V", "V"),         # wW_rW_ARG
    11: ("V",),             # rW_ARG
    12: ("V", "C"),         # wW_DW_ARG
    13: ("V", "V", "C"),    # wW_rW_DW_ARG
    14: ("V", "V"),         # rW_rW_ARG
    15: ("V", "W"),         # wW_W_ARG
    16: ("C", "C"),         # QW_DW_ARG
    17: ("V", "C"),         # rW_QW_ARG
    18: ("W", "C"),         # W_DW_ARG
    19: ("V", "W", "C"),    # rW_W_DW_ARG
    20: ("V", "C", "C"),    # rW_DW_DW_ARG
}


def operand_kinds(opcodes: Dict[int, Dict[str, Any]]) -> Dict[str, Tuple[str, ...]]:
    """Per opcode name, the kind of each operand -- from this build's table."""
    kinds: Dict[str, Tuple[str, ...]] = {}
    for op, entry in sorted(opcodes.items()):
        shape = OPERAND_KINDS.get(entry.get("type"))
        if shape is None:
            raise ValueError(
                "opcode %d (%s) has asBCType %r, which the operand-kind "
                "table does not describe" % (op, entry.get("name"),
                                             entry.get("type")))
        if len(shape) != entry["operands"]:
            raise ValueError(
                "opcode %s: the build's table says %d operand(s), asBCType "
                "%d says %d -- the enum mapping is wrong"
                % (entry["name"], entry["operands"], entry["type"],
                   len(shape)))
        kinds[entry["name"]] = shape
    return kinds


def canonical(dis: Dict[str, Any], kinds: Dict[str, Tuple[str, ...]],
              slots: bool = True) -> List[str]:
    """One body as the lines two modules can be compared in."""
    out: List[str] = []
    renumbered: Dict[int, int] = {}
    for ins in dis["instructions"]:
        shape = kinds.get(ins["name"], ())
        parts = [ins["name"]]
        for j, item in enumerate(ins["args"]):
            role = item.get("role")
            if role == "jump":
                parts.append("@%+d" % item["value"])
            elif role:
                text = item.get("text")
                parts.append(text if text is not None
                             else "%s#%d" % (role, item["value"]))
            elif j < len(shape) and shape[j] == "V":
                if not slots:
                    continue
                parts.append("v%d" % renumbered.setdefault(
                    item["value"], len(renumbered)))
            else:
                parts.append(str(item["value"]))
        out.append(" ".join(parts))
    return out


def _module_of(path: str, scratch: Optional[str] = None,
               role: str = "") -> Tuple[str, str]:
    """`(module path, executable path)` for a module file or an executable.

    The scratch name carries `role` and a digest of the source path, because
    the two sides of a round trip are USUALLY NAMED THE SAME: the engine
    writes `superegghunt.exe` beside the recovered script, and the original
    is `superegghunt.exe` too. Unpacking both to one name made the second
    overwrite the first, so the comparison was the rebuild against itself
    and reported 143 of 143 bodies identical with an edit distance of zero.
    A check that cannot fail is the trap this toolkit is organised against,
    and this one reported a perfect score.
    """
    with open(path, "rb") as fh:
        head = fh.read(2)
    if head != b"MZ":
        return path, path
    unpacked = bgtlib.unpack_file(path)
    stem = os.path.splitext(os.path.basename(path))[0]
    tag = hashlib.sha256(os.path.abspath(path).encode("utf-8")).hexdigest()[:8]
    out = os.path.join(scratch or os.path.dirname(os.path.abspath(path)),
                       "%s_%s_%s_bytecode.bin" % (stem, role or "side", tag))
    with open(out, "wb") as fh:
        fh.write(unpacked.bytecode)
    return out, path


def _two_sides(original: str, rebuilt: str, scratch: Optional[str]
               ) -> Tuple[Tuple[str, str], Tuple[str, str]]:
    """Both sides, refusing to compare a module against itself."""
    if os.path.abspath(original) == os.path.abspath(rebuilt):
        raise ValueError("the two sides are the same file: %s" % original)
    a = _module_of(original, scratch, "original")
    b = _module_of(rebuilt, scratch, "rebuilt")
    if os.path.abspath(a[0]) == os.path.abspath(b[0]):
        raise ValueError("both sides resolved to one module, %s" % a[0])
    return a, b


def bodies(module_path: str, exe: str) -> Tuple[Any, Dict[str, Tuple[str, ...]],
                                                Dict[str, List[Any]]]:
    mod = as_disasm.load(module_path, exe)
    kinds = operand_kinds(mod.opcodes)
    by_label: Dict[str, List[Any]] = collections.defaultdict(list)
    for f in mod.functions:
        if not f.get("body"):
            continue
        dis = as_disasm.disassemble_function(mod, f)
        by_label[dis["label"]].append(dis)
    return mod, kinds, by_label


def compare(original: str, rebuilt: str, limit: int = 25,
            scratch: Optional[str] = None) -> Dict[str, Any]:
    """Every body of two modules, paired by `owner::name` and diffed."""
    (a_mod_path, a_exe), (b_mod_path, b_exe) = _two_sides(
        original, rebuilt, scratch)
    a_mod, kinds, a = bodies(a_mod_path, a_exe)
    b_mod, _, b = bodies(b_mod_path, b_exe)

    both = set(a) & set(b)
    ambiguous = sorted(l for l in both if len(a[l]) != 1 or len(b[l]) != 1)
    pairs = sorted(l for l in both if l not in set(ambiguous))

    same_loose = same_strict = edits = total = 0
    rows: List[Dict[str, Any]] = []
    for label in pairs:
        da, db = a[label][0], b[label][0]
        la = canonical(da, kinds, slots=False)
        lb = canonical(db, kinds, slots=False)
        total += len(la)
        if la == lb:
            same_loose += 1
            if canonical(da, kinds) == canonical(db, kinds):
                same_strict += 1
            continue
        matcher = difflib.SequenceMatcher(None, la, lb)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag != "equal":
                edits += (i2 - i1) + (j2 - j1)
        rows.append({"label": label, "ratio": matcher.ratio(),
                     "original": len(la), "rebuilt": len(lb),
                     "delta": len(lb) - len(la)})
    rows.sort(key=lambda r: (r["ratio"], -abs(r["delta"])))
    return {
        "module_bodies": [len(a_mod.functions), len(b_mod.functions)],
        "paired": len(pairs), "ambiguous": len(ambiguous),
        "only_original": sorted(set(a) - set(b)),
        "only_rebuilt": sorted(set(b) - set(a)),
        "identical": same_loose, "identical_with_slots": same_strict,
        "differing": len(rows),
        "edits": edits, "original_instructions": total,
        "rows": rows if limit == 0 else rows[:limit],
    }


def report(res: Dict[str, Any]) -> str:
    a, b = res["module_bodies"]
    paired = res["paired"] or 1
    total = res["original_instructions"] or 1
    lines = [
        "bodies            %d original, %d rebuilt" % (a, b),
        "paired            %d  (%d declined as ambiguous)"
        % (res["paired"], res["ambiguous"]),
        "same, slot-blind  %d / %d  (%.1f%%)"
        % (res["identical"], res["paired"], 100.0 * res["identical"] / paired),
        "same, with slots  %d / %d  (%.1f%%)"
        % (res["identical_with_slots"], res["paired"],
           100.0 * res["identical_with_slots"] / paired),
        "differing         %d" % res["differing"],
        "EDIT DISTANCE     %d instructions added or lost, over %d  (%.1f%%)"
        % (res["edits"], res["original_instructions"],
           100.0 * res["edits"] / total),
    ]
    for key, caption in (("only_original", "only in original"),
                         ("only_rebuilt", "only in rebuilt")):
        if res[key]:
            lines.append("%-17s %d: %s"
                         % (caption, len(res[key]), ", ".join(res[key][:6])))
    if res["rows"]:
        lines += ["", "%-46s %6s %7s %7s %6s"
                  % ("body", "ratio", "orig", "rebuilt", "d")]
        for r in res["rows"]:
            lines.append("%-46s %6.3f %7d %7d %+6d"
                         % (r["label"][:46], r["ratio"], r["original"],
                            r["rebuilt"], r["delta"]))
    return "\n".join(lines)


def detail(original: str, rebuilt: str, label: str,
           scratch: Optional[str] = None, context: int = 3) -> str:
    """One body's two canonical forms, as a unified diff."""
    (a_mod_path, a_exe), (b_mod_path, b_exe) = _two_sides(
        original, rebuilt, scratch)
    _, kinds, a = bodies(a_mod_path, a_exe)
    _, _, b = bodies(b_mod_path, b_exe)
    if label not in a or label not in b:
        where = "original" if label not in a else "rebuilt"
        return "no body %s in the %s module" % (label, where)
    la = canonical(a[label][0], kinds)
    lb = canonical(b[label][0], kinds)
    out = ["%s   %d -> %d instructions" % (label, len(la), len(lb))]
    out += list(difflib.unified_diff(la, lb, "original", "rebuilt",
                                     n=context, lineterm=""))
    return "\n".join(out)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Compare a recovered project's RECOMPILED bytecode "
                    "against the original's, body by body.")
    ap.add_argument("original", help="the original executable or its module")
    ap.add_argument("rebuilt", help="the rebuilt executable or its module")
    ap.add_argument("--detail", metavar="OWNER::NAME",
                    help="one body's instruction diff instead of the summary")
    ap.add_argument("--limit", type=int, default=25,
                    help="worst bodies to list (0 for all)")
    ap.add_argument("--context", type=int, default=3,
                    help="context lines for --detail")
    ap.add_argument("--json", metavar="PATH", help="write the full result")
    ap.add_argument("--scratch", metavar="DIR",
                    help="where to write a module unpacked from an exe")
    args = ap.parse_args(argv)

    # A refusal is an outcome, not a crash: the two sides being one file is
    # the mistake a round trip invites, because the engine writes the rebuilt
    # executable under the game's own name.
    try:
        if args.detail:
            text = detail(args.original, args.rebuilt, args.detail,
                          args.scratch, args.context)
            print(text)
            return 1 if text.startswith("no body ") else 0
        res = compare(args.original, args.rebuilt, args.limit, args.scratch)
    except ValueError as exc:
        print("bgt roundtrip: %s" % exc, file=sys.stderr)
        return 2
    print(report(res))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1)
        print("\nwritten to %s" % args.json)
    # A comparison that paired NOTHING must not read like one that found no
    # difference, which is the shape `bgt audit` already guards against.
    return 0 if res["paired"] else 1


if __name__ == "__main__":
    sys.exit(main())
