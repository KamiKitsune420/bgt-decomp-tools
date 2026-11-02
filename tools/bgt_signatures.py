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
| `empty_arm` | "an `if` with an empty arm is a condition that has lost its value" -- either arm, since a fold that collapses the second one leaves `} else { }` |
| `two_empty_arms` | the stronger form, which found the folded `\\|\\|` chain |
| `double_assign` | a name assigned twice in a row and then read several times in one expression -- `get_percent_of_range`. The DESTINATION of an assignment is not a read of it: counting it made BGT's own `x = f(x)` chain a hit, 81 rows of 105 |
| `identity_cast` | `double(int(x))`, which is only an identity when `x` is already integral -- the weakest of these, since the text cannot tell a truncation from a no-op |
| `bare_read` | a statement that only reads -- the borrowed handle hoisted out of its guard |
| `duplicated_call` | the same call text three or more times in one statement, a numeric conversion excepted -- re-evaluating `int(x)` costs nothing |
| `same_argument` | one call reading one slot for several arguments -- a safezone whose six bounds are one number |
| `collapsed_chain` | a condition chaining three or more terms and testing one of them twice -- a movement test whose timer term was overwritten |

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

#: A slot tested for truth, the way the renderer spells a term of a
#: short-circuit chain: `(local_14 != 0)`. A chain's terms are each their own
#: value, so one appearing twice means a term was lost.
_CHAIN_TERM = re.compile(r"\((" + r"(?:local|arg)_?\d+" + r")\s*(?:!=|==)\s*0\)")
#: The head of a condition worth looking at. Only `if` and `while`: a `for`
#: header holds three clauses, so one name in two of them is ordinary.
_CONDITION = re.compile(r"\b(?:if|while)\s*\(")
#: How many short-circuit operators make a CHAIN. Two, because a chain needs
#: three terms before the compiler has to recycle a destination slot: with one
#: operator there is a single merge and a single destination, and nothing to
#: overwrite.
CHAIN_OPERATORS = 2

#: What `bgt recover` writes at the top of a file it replaced with BGT's own
#: source. Such a file's text is the engine's, not the recovery's, so its
#: shapes say nothing about this decompiler.
_STOCK_MARKER = "BGT's own copy of this file"

KINDS = ("self_identical", "tautology", "empty_arm", "two_empty_arms",
         "same_argument", "collapsed_chain",
         "double_assign", "identity_cast", "bare_read", "duplicated_call")

#: How many times one call text has to appear in a single statement before it
#: is worth reporting. Two is the ordinary cost of a short-circuit rendered
#: without a temporary; three is what `file_menu` and `play_extended_1d`
#: looked like, and what this file records as a correctness number.
DUPLICATION_LIMIT = 3


def _condition_text(line: str, at: int):
    """The bracket-matched condition starting at the `(` at `at`.

    Bracket-matched rather than patterned, for the reason `same_argument`
    already records: a pattern with one level of nesting cannot see
    `(local_1 < float(maxpos))`, and a condition is full of those. None when
    the brackets do not close on this line, which is the honest answer rather
    than a truncated condition read as a whole one.
    """
    depth = 0
    for i in range(at, len(line)):
        if line[i] == "(":
            depth += 1
        elif line[i] == ")":
            depth -= 1
            if depth == 0:
                return line[at:i + 1]
    return None


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


def _arm_above_was_empty(lines: List[str], j: int) -> bool:
    """Whether the `if` arm this `else` belongs to was already reported.

    Both arms empty is one construct and one row: the `if` line fires
    `empty_arm` -- and `two_empty_arms` -- so firing again at the `else`
    would count one lost condition twice.
    """
    if j >= 1 and _IF_EMPTY.search(lines[j - 1].strip()):
        return True
    return (j >= 2 and bool(_IF_OPEN.search(lines[j - 2].strip()))
            and lines[j - 1].strip() == "}")


#: A call's name and the text between its brackets, found by bracket
#: matching rather than by a pattern. A pattern with one level of nesting in
#: it cannot see `base(double(int(stn(local_16))), ...)`, which is exactly
#: the shape `same_argument` is for: written that way the sweep reported 9
#: rows on `cs`'s server where there are 38, and under-reported the very
#: baseline it was meant to measure.
_NAME_OPEN = re.compile(_IDENT + r"\(")
#: ...and the slot an argument reads, through any run of conversions:
#: `local_16`, `stn(local_17)`, `double(int(stn(local_16)))`.
_WRAP = re.compile(r"^" + _IDENT + r"\((.*)\)$")
_SLOT = re.compile(r"^((?:local|arg)_?\d+)$")
#: a write to a slot, which `_ASSIGN` nearly is -- but a HANDLE is
#: reassigned with `@`, and `_ASSIGN` is shared with `double_assign`,
#: whose own measurement should not move for this. Manamon 1's two
#: rows are handle writes, and without the `@` they read as none.
_SLOT_WRITE = re.compile(r"^\s*@?(" + _IDENT + r")\s*=\s*[^=].*;\s*$")


def _calls(line: str):
    for m in _NAME_OPEN.finditer(line):
        depth, i = 0, m.end() - 1
        while i < len(line):
            if line[i] == "(":
                depth += 1
            elif line[i] == ")":
                depth -= 1
                if depth == 0:
                    yield m.group(0)[:-1], line[m.end():i]
                    break
            i += 1


def _split_args(text: str) -> List[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _arg_slot(text: str) -> str | None:
    text = text.strip()
    for _ in range(8):
        got = _SLOT.match(text)
        if got:
            return got.group(1)
        got = _WRAP.match(text)
        if not got:
            return None
        text = got.group(1).strip()
    return None


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
        #: **An empty ELSE under a non-empty arm is the same signal**, and
        #: this shape could not see one: `_empty_else` was consulted only to
        #: upgrade an already-empty `if` arm. A collapsed fold leaves exactly
        #: that when the arm that folded away is the second one -- `cs`'s
        #: `netloop` lost a nested ternary's two string arms and came out
        #:
        #:     if (get_player_index_from(local_15) > -1) {
        #:         local_15 = local_59[local_33];
        #:     } else {
        #:     }
        #:
        #: and the sweep read 0 while every admin was listed with no AFK
        #: marker. Only the literal audit caught it.
        #:
        #: Counted at the `else` rather than at the `if`, so a run of them
        #: cannot be collapsed into one row by accident, and only when this
        #: line is not itself the empty-arm case already reported above.
        elif _empty_else(lines, i) and not _arm_above_was_empty(lines, i):
            hit("empty_arm", i)

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
                    #: **The destination is not a read**, and counting it
                    #: made BGT's own chain a hit: each
                    #: `local_1 = string_replace(local_1, ...)` mentions the
                    #: name twice, so every chain of three or more scored,
                    #: and `cs`'s server alone had forty of them. What this
                    #: shape is for is one value read twice in ONE
                    #: expression, so only the right-hand side counts.
                    rhs = lines[j]
                    assigned = _ASSIGN.match(rhs)
                    if assigned and assigned.group(1) == name:
                        rhs = rhs.split("=", 1)[1]
                    uses = len(re.findall(r"(?<![\w.])" + re.escape(name)
                                          + r"(?!\w)", rhs))
                    if uses >= 2:
                        hit("double_assign", i)
                        break
                    if _ASSIGN.match(lines[j]):
                        break

        #: One call reading ONE slot for two or more of its arguments,
        #: where that slot is written more than once just above. The
        #: compiler builds each argument through one scratch slot and
        #: consumes it as it goes, so the writes and the uses interleave,
        #: and rendering the slot's NAME gives every argument whatever it
        #: held last: `cs`'s map loader built `safezone(stn(local_17) x6)`,
        #: six bounds that are one number, and `load_bases` passed a base's
        #: three coordinates as its health value.
        #:
        #: The writes are what make a repeat a defect rather than the author
        #: passing one value twice -- `CapturePapillon::setZone` passes one
        #: coordinate twice and may well be deliberate.
        for callee, inner in _calls(line):
            args = _split_args(inner)
            if len(args) < 2:
                continue
            slots = [s for s in (_arg_slot(a) for a in args) if s]
            dup = {s for s in slots if slots.count(s) > 1}
            if not dup:
                continue
            writes = 0
            for prev in lines[max(0, i - 14):i]:
                got = _SLOT_WRITE.match(prev)
                if got and got.group(1) in dup:
                    writes += 1
            if writes > 1:
                hit("same_argument", i)
                break

        #: **A chain of three or more terms that tests one of them twice.**
        #: Each term of an `&&` is its own value, so a chain reading one slot
        #: twice has lost a term -- and what it lost is whatever that slot
        #: held first.
        #:
        #: The compiler nests `&&` to the left and cycles two or three
        #: scratch slots through the merges, so in a long chain a slot is a
        #: destination more than once. Rendered as variables, each arm's
        #: computation becomes an unconditional statement and the later
        #: merges overwrite the earlier terms. Field Wars' movement is the
        #: case: `flytimer.elapsed > flytime && !inac && me.x < maxpos &&
        #: key_up(KEY_LSHIFT) && key_up(KEY_RSHIFT)` came out as
        #:
        #:     if (key_down(KEY_RIGHT) && (local_14 != 0) && (local_22 != 0)
        #:         && (local_24 != 0) && (local_14 != 0) && (local_22 != 0))
        #:
        #: with the timer term and the `!inac` term gone and two terms tested
        #: twice. The game compiled, ran, and nothing moved on a held key.
        #:
        #: **Nine shapes swept that title and reported nothing**, which is
        #: why this one exists: the assignments interleave across three
        #: slots, so `double_assign` wants two in a row and does not see
        #: them, and the repeat is `x != 0 && ... && x != 0` rather than
        #: `x == x`, so `tautology` does not either.
        for m in _CONDITION.finditer(line):
            cond = _condition_text(line, m.end() - 1)
            if cond is None:
                continue
            if cond.count("&&") + cond.count("||") < CHAIN_OPERATORS:
                continue
            terms = _CHAIN_TERM.findall(cond)
            if any(terms.count(t) > 1 for t in terms):
                hit("collapsed_chain", i)
                break

        counts: Dict[str, int] = {}
        for m in _CALL_TEXT.finditer(line):
            text_of = _norm(m.group(0))
            if re.match(r"(?:if|while|for|switch|return)\(", text_of):
                continue
            #: **A numeric CONVERSION is not a call in the sense that
            #: matters.** This shape is a correctness number -- running a
            #: call once per read runs it once per read -- and re-evaluating
            #: `int(local_10)` costs nothing and changes nothing. All six of
            #: Paladin's rows were `int(local_10)` three times in one
            #: condition, and `bag[int(pocket_cursor)]` twice.
            if re.match(_NUMERIC + r"\(", text_of):
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
