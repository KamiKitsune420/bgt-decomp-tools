"""
bgt_signatures -- the text as the oracle: does the recovery say something a
programmer never would?

`bgt audit` asks the bytecode whether the recovery LOST a value. This asks the
other half, of the text alone: a recovered line can be valid BGT, compile
cleanly, run, and still be an expression that no author would write. Every
signature below is here because a real, reported bug left it behind:

| signature | the bug that left it |
|---|---|
| `self_identical` | a collapsed snapshot -- `this.damage = this.damage;` |
| `tautology` | the same collapse inside a condition -- `if (a == a)` |
| `empty_arm` | "an `if` with an empty arm is a condition that has lost its value" |
| `two_empty_arms` | the stronger form, which found the folded `\\|\\|` chain |
| `double_assign` | a name assigned twice in a row and then read several times in one expression -- `get_percent_of_range` |
| `identity_cast` | `double(int(x))`: a value converted twice and changed by neither |
| `bare_read` | a statement that only reads -- the borrowed handle hoisted out of its guard |
| `duplicated_call` | the same call text three or more times in one statement |

**A hit is a lead, not a verdict**, and the discipline is the same as for
`bgt audit`: the original wrote some of these itself. Paladin's `battle`
really does compare `player.strikes[i].name` with itself -- the bytecode
copy-constructs the left operand and compares it against the live member, so
the author's typo is in the shipped game -- and `breakfast_time` really does
write `speech = speech += "..."`. Both survive the sweep and neither is ours.

What the sweep is FOR is the difference between two recovery trees, and the
difference between titles. A count that moves is a change in the decompiler,
and a count sitting in a title nobody has read is the cross-validation this
project runs on: the four fold-safety rules took Manamon 1 from 9
self-identical lines to 1 and 12 tautologies to 4, in a title where nothing
was looking for either.

    bgt signatures recovered/
    bgt signatures recovered/ --against ../previous_recovery/
    bgt signatures recovered/ --detail tautology
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Tuple

#: A string literal, so a name inside one is never read as code. Replaced by
#: spaces rather than removed, because a line's columns are reported.
_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
_IDENT = r"[A-Za-z_]\w*"
#: An expression with no call in it: a name, a member path, an index. A call
#: cannot appear, because two textually identical CALLS are not a tautology --
#: `rand() == rand()` is two different values and the original's own business.
_PATH = r"@?" + _IDENT + r"(?:\s*\.\s*" + _IDENT + r"|\s*\[[^\[\]]*\])*"

_SELF = re.compile(r"^\s*(" + _PATH + r")\s*=\s*(" + _PATH + r")\s*;\s*$")
_TAUTOLOGY = re.compile(r"\(\s*(" + _PATH + r")\s*(?:==|!=)\s*("
                        + _PATH + r")\s*\)")
_ASSIGN = re.compile(r"^\s*(" + _IDENT + r")\s*=\s*[^=].*;\s*$")
#: Two numeric conversions in a row. `int(double(x))` truncates and
#: `double(int(x))` loses the fraction, so the pair is either the original's
#: own or a snapshot that collapsed into the value it was taken from.
_NUMERIC = r"(?:int|uint|float|double|int8|uint8|int16|uint16|int64|uint64)"
_IDENTITY_CAST = re.compile(r"\b" + _NUMERIC + r"\s*\(\s*" + _NUMERIC + r"\s*\(")
_BARE = re.compile(r"^\s*(" + _PATH + r")\s*;\s*$")
_CALL_TEXT = re.compile(_IDENT + r"\s*\([^()]*\)")
_IF_EMPTY = re.compile(r"\bif\s*\(.*\)\s*\{\s*\}\s*$")
_IF_OPEN = re.compile(r"\bif\s*\(.*\)\s*\{\s*$")
_ELSE_EMPTY = re.compile(r"^\s*(?:\}\s*)?else\s*\{\s*\}\s*$")

#: What `bgt recover` writes at the top of a file it replaced with BGT's own
#: source. Such a file's text is the engine's, not the recovery's, so its
#: shapes say nothing about this decompiler.
_STOCK_MARKER = "BGT's own copy of this file"

KINDS = ("self_identical", "tautology", "empty_arm", "two_empty_arms",
         "double_assign", "identity_cast", "bare_read", "duplicated_call")

#: How many times one call text has to appear in a single statement before it
#: is worth reporting. Two is the ordinary cost of a short-circuit rendered
#: without a temporary; three is what `file_menu` and `play_extended_1d`
#: looked like, and what this file records as a correctness number.
DUPLICATION_LIMIT = 3


def mask(line: str) -> str:
    """Blank every string literal and drop a trailing line comment.

    Columns are preserved so a reported line still matches the file.
    """
    line = _STRING.sub(lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', line)
    cut = line.find("//")
    return line[:cut] if cut >= 0 else line


def _empty_else(lines: List[str], j: int) -> bool:
    """Whether an empty `else` arm starts at line `j`, written either way."""
    if j >= len(lines):
        return False
    here = lines[j].strip()
    if _ELSE_EMPTY.match(here):
        return True
    return (bool(re.match(r"^(?:\}\s*)?else\s*\{\s*$", here))
            and j + 1 < len(lines) and lines[j + 1].strip() == "}")


def _norm(text: str) -> str:
    """Two spellings of one expression, compared. Drops whitespace and a
    leading handle marker: `@x` and `x` name the same thing."""
    return re.sub(r"\s+", "", text).lstrip("@")


def scan(text: str) -> List[Tuple[str, int, str]]:
    """Every signature hit in one file's text, as (kind, line number, line)."""
    raw = text.splitlines()
    lines = [mask(x) for x in raw]
    hits: List[Tuple[str, int, str]] = []

    def hit(kind: str, i: int) -> None:
        hits.append((kind, i + 1, raw[i].strip()))

    for i, line in enumerate(lines):
        stripped = line.strip()
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""

        m = _SELF.match(line)
        if m and _norm(m.group(1)) == _norm(m.group(2)):
            hit("self_identical", i)

        for m in _TAUTOLOGY.finditer(line):
            if _norm(m.group(1)) == _norm(m.group(2)):
                hit("tautology", i)

        if _IDENTITY_CAST.search(line):
            hit("identity_cast", i)

        #: A statement that reads something and does nothing with it. A bare
        #: name is excluded: it is more often a label-ish artifact than a
        #: read, and a member or an index is what the borrowed-handle bug
        #: left behind.
        if (_BARE.match(line) and "=" not in stripped
                and not stripped.startswith(("return", "break", "continue"))
                and re.search(r"[.\[]", stripped)):
            hit("bare_read", i)

        #: An empty arm, written `if (c) { }` on one line or with the `}`
        #: beneath -- the renderer does both, and an arm whose emptiness is
        #: only visible on the next line is the same lost condition.
        inline = bool(_IF_EMPTY.search(stripped))
        split = bool(_IF_OPEN.search(stripped)) and nxt == "}"
        if inline or split:
            hit("empty_arm", i)
            if _empty_else(lines, i + 1 if inline else i + 2):
                hit("two_empty_arms", i)

        #: Two assignments to one name in a row, then a statement reading it
        #: more than once: one scratch slot carrying several operands, which
        #: is what `get_percent_of_range` computed `a0 - a0 * (a0 / 100)`
        #: out of.
        first = _ASSIGN.match(line)
        if first:
            second = _ASSIGN.match(lines[i + 1]) if i + 1 < len(lines) else None
            if second and first.group(1) == second.group(1):
                name = first.group(1)
                for j in range(i + 2, min(i + 5, len(lines))):
                    uses = len(re.findall(r"(?<![\w.])" + re.escape(name)
                                          + r"(?!\w)", lines[j]))
                    if uses >= 2:
                        hit("double_assign", i)
                        break
                    if _ASSIGN.match(lines[j]):
                        break

        counts: Dict[str, int] = {}
        for m in _CALL_TEXT.finditer(line):
            text_of = _norm(m.group(0))
            if re.match(r"(?:if|while|for|switch|return)\(", text_of):
                continue
            counts[text_of] = counts.get(text_of, 0) + 1
        if any(n >= DUPLICATION_LIMIT for n in counts.values()):
            hit("duplicated_call", i)

    return hits


def sweep(root: str, stock: bool = False) -> Tuple[Dict[str, int],
                                                   Dict[str, List[str]]]:
    """Sweep every `.bgt` file under one directory.

    Returns the counts per signature and the rows, each `file:line  text`.
    """
    counts = dict((k, 0) for k in KINDS)
    rows: Dict[str, List[str]] = dict((k, []) for k in KINDS)
    for base, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".bgt"):
                continue
            path = os.path.join(base, name)
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            if not stock and _STOCK_MARKER in text[:4000]:
                continue
            rel = os.path.relpath(path, root)
            for kind, line, body in scan(text):
                counts[kind] += 1
                rows[kind].append("%s:%d  %s" % (rel, line, body[:160]))
    return counts, rows


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="bgt signatures",
        description="shapes in recovered text that no author would write")
    ap.add_argument("project", help="a directory of recovered .bgt files")
    ap.add_argument("--against", metavar="DIR",
                    help="a second tree: print both counts side by side, "
                         "which is what says whether the decompiler moved")
    ap.add_argument("--detail", metavar="SIGNATURE",
                    help="print every row of one signature (or `all`)")
    ap.add_argument("--stock", action="store_true",
                    help="include files replaced by BGT's own source, whose "
                         "text is the engine's rather than the recovery's")
    ap.add_argument("--json", metavar="FILE")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any signature is reported")
    args = ap.parse_args(argv)

    if args.detail and args.detail != "all" and args.detail not in KINDS:
        sys.stderr.write("bgt signatures: no signature named %r; have %s\n"
                         % (args.detail, ", ".join(KINDS)))
        return 2
    for path in (args.project, args.against):
        if path and not os.path.isdir(path):
            sys.stderr.write("bgt signatures: not a directory: %s\n" % path)
            return 2

    counts, rows = sweep(args.project, args.stock)
    files = sum(1 for base, _d, fs in os.walk(args.project)
                for f in fs if f.endswith(".bgt"))
    if not files:
        sys.stderr.write("bgt signatures: NO .bgt FILES -- this swept "
                         "nothing\n")
        return 1

    if args.against:
        other, _ = sweep(args.against, args.stock)
        width = max(len(k) for k in KINDS) + 2
        print("%-*s %8s %8s" % (width, "signature", "this", "against"))
        for kind in KINDS:
            moved = "" if counts[kind] == other[kind] else "   <<< MOVED"
            print("%-*s %8d %8d%s"
                  % (width, kind, counts[kind], other[kind], moved))
    else:
        print("%d .bgt file%s swept" % (files, "" if files == 1 else "s"))
        for kind in KINDS:
            print("  %-16s %6d" % (kind, counts[kind]))

    if args.detail:
        for kind in (KINDS if args.detail == "all" else (args.detail,)):
            if not rows[kind]:
                continue
            print("\n## %s" % kind)
            for row in rows[kind]:
                print("   " + row)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"counts": counts, "rows": rows}, fh, indent=2)

    if args.strict and any(counts.values()):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
