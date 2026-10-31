"""
bgt_audit -- the module is the oracle: did the recovery LOSE a value?

`bgt recover --compile` says whether recovered source is *valid*, `bgt apicheck`
says whether every call *resolves*, and `bgt libcheck` compares a body against
BGT's own shipped library source -- which reaches 149 of Paladin's 926 bodies.
Every bug ever reported from playing these games has been in the other 777, and
those had never been compared against anything.

There is a better oracle for them, and it was in hand the whole time: **the
module**. A call instruction is a call, a `STR` operand is a literal and a
`SetV*` operand is a number, so for every body the bytecode gives the exact
multiset of callees, of string constants and of numeric constants -- and the
decompiler cannot lose or invent one without being wrong. Three audits, over
every body that pairs unambiguously between the module and the recovered text:

| audit | ground truth | what it found when it was a scratch script |
|---|---|---|
| callees | `CALL`/`CALLSYS`/`CALLINTF`/`Thiscall1`/`ALLOC` | 26 Paladin bodies, all `super()` or a generated construction |
| literals | `STR` and `PGA` operands | the dropped initialiser list -- 134 literals in 4 bodies |
| constants | `SetV1`/`SetV2`/`SetV4`/`SetV8` | 44 Paladin rows: the flattened `-1` sentinel and the whole in-fiction clock |

**A row is a lead, not a verdict.** A constant can legitimately vanish into a
folded comparison (`CMPIi` carries its own immediate), the original's own dead
store is correctly dropped, and a stock library file's text is BGT's source
rather than the recovery's. What makes the instrument worth keeping is that the
leads it produced were real: `time.add_minutes(30)` had become
`add_minutes(1)` thirty-two times, every `uint8` field of Psycho Strike's
`voice_set` read 1, and Manamon 1's `sleep_in_bed` had a `PshGPtr` rendered as
`""`.

## The three comparison rules, each of which was a row that cost an afternoon

* **An escape is not the byte it escapes.** The recovery writes any byte above
  0x7F as `\\xNN`, deliberately, so comparing bytecode *bytes* against the
  literal's *source text* compares an escape against the byte it escapes. Eight
  of Manamon 1's rows were exactly that -- monster descriptions carrying a
  Windows-1252 right single quote. `unescape` reads a rendered literal back the
  way the engine's lexer does, and is written from the lexer's rules rather than
  as the inverse of the renderer's table: an inverse built from the same table
  would agree with a wrong table.
* **A number is a number, not a spelling.** `-100.0` and `-100` are the same
  constant. Four of Paladin's six residual rows and four of Psycho Strike's
  eight were only that, because a substituted stock file's text is BGT's own
  source and spells a float constant `-100`. Constants compare numerically,
  with a tolerance, never as strings.
* **The same bits have more than one honest reading.** Three of Psycho Strike's
  rows are a one-byte `255` the text correctly spells `-1`, which is
  `this.walk(-1, false)` into an `int8` parameter. `readings` therefore offers
  the unsigned value, the signed value at every width whose high bit those bits
  set, and the IEEE-754 reading at the opcode's width -- and a match against any
  of them is a match. Accepting either reading of one bit pattern is the honest
  answer: the module does not record which the source wrote, and a check that
  picks one would report the other as lost.

## What it declines, and counts rather than guessing at

A call the recovered text has **no syntax for** is not a lost call: a property
accessor is written `pool.pan_step`, an operator method is written `+`, a
behaviour is a construction or a destruction, and the string factory *is* the
literal. Those are excluded by name and the exclusions are counted, so an audit
that reports nothing still says how much it looked at -- the lesson `bgt
apicheck` records as "a check that reports nothing may simply be blind".

A body counts only when exactly one function in the module and exactly one body
in the text carry its name. A class's constructor and its factory share a name,
so constructors are usually declined; that is the same pairing the published
figures were measured with.

## Measured in both directions

`tests/test_audit.py` injects three defects into a synthetic project -- a
dropped literal, a constant flattened to 1, a deleted call -- and requires each
to be reported, because a check only reporting on a clean tree cannot be told
from one that is blind.

    bgt audit recovered/ game.exe
    bgt audit recovered/ game.exe --module work/game_bytecode.bin --constants
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import os
import re
import struct
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:                      # installed as a package
    from . import as_disasm, bgt_apicheck, bgtlib
except ImportError:       # run directly from a checkout
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import as_disasm
    import bgt_apicheck
    import bgtlib


# --------------------------------------------------------------------------
# reading a rendered literal back
# --------------------------------------------------------------------------

#: The escapes the renderer emits and the engine's lexer accepts. BGT was asked
#: rather than assumed: `"\xac\x71\x96"` compiles with no warning and produces
#: those three bytes, while the octal form `"\254"` is `Warning: Invalid escape
#: sequence` -- so nothing else here is treated as an escape at all.
_LEXER_ESCAPES = {"\\": b"\\", '"': b'"', "'": b"'",
                  "n": b"\n", "r": b"\r", "t": b"\t"}
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def unescape(text: str) -> bytes:
    """A rendered literal, as the bytes the engine's lexer would build from it.

    Written from the lexer's rules, deliberately **not** as the inverse of the
    renderer's escape table: `\\xNN` is two hex digits, `\\\\`, `\\"`, `\\'`,
    `\\n`, `\\r` and `\\t` stand for themselves, and everything else is its own
    UTF-8 bytes -- because the project file is written UTF-8 and that is the
    encoding the engine's bytes come from. An inverse built from the renderer's
    own table would agree with a wrong table, which is the trap
    `tests/nvgt/test_regressions.LiteralRenderingTests` exists for.

    A backslash that opens nothing the lexer knows stands for itself, which is
    what BGT does after warning about it.
    """
    out = bytearray()
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c != "\\" or i + 1 >= n:
            out += c.encode("utf-8", "surrogateescape")
            i += 1
            continue
        kind = text[i + 1]
        if (kind == "x" and i + 3 < n
                and text[i + 2] in _HEX_DIGITS and text[i + 3] in _HEX_DIGITS):
            out.append(int(text[i + 2:i + 4], 16))
            i += 4
        elif kind in _LEXER_ESCAPES:
            out += _LEXER_ESCAPES[kind]
            i += 2
        else:
            out += b"\\"
            i += 1
    return bytes(out)


# --------------------------------------------------------------------------
# the recovered text
# --------------------------------------------------------------------------

class Body:
    """One function body found in the recovered text."""

    __slots__ = ("name", "label", "path", "relpath", "line", "raw",
                 "scrubbed", "stock")

    def __init__(self, name: str, label: str, path: str, relpath: str,
                 line: int, raw: str, scrubbed: str, stock: bool) -> None:
        self.name = name
        self.label = label             # `owner::name`, as function_label says
        self.path = path
        self.relpath = relpath
        self.line = line
        self.raw = raw                 # the brace-delimited slice, verbatim
        self.scrubbed = scrubbed       # the same slice with comments and
        self.stock = stock             # string bodies blanked, offsets intact

    def where(self) -> str:
        return "%s:%d" % (self.relpath, self.line)


#: The identifier a `(` opens against. The lookbehind excludes only a word
#: character, so a method on an INDEXED receiver is seen:
#: `global_interacts[slot].add_event(` matches at the `.`. The pattern that
#: consumed a dotted chain instead could not reach such a name at all, and the
#: first version of the call audit reported 67 lost `add_event` calls that were
#: every one of them present.
_CALL = re.compile(r"(?<![\w])\.?\s*([A-Za-z_]\w*)\s*\(")

#: A word that takes a parenthesised clause without being a call, so it is
#: never a function head either.
_CLAUSE_WORDS = frozenset((
    "if", "while", "for", "switch", "do", "else", "return", "catch", "case",
    "and", "or", "not", "cast", "break", "continue", "default", "sizeof",
))

#: The header a substituted stock library file carries. Its text is BGT's own
#: source rather than the recovery's, so a row from one is a comparison against
#: a different artefact -- four of Paladin's six residual constant rows and four
#: of Psycho Strike's eight are a stock file spelling a float `-100`.
_STOCK_MARKER = "BGT's own copy of this file"


def _matching(text: str, start: int, pair: str) -> Optional[int]:
    """The index of the bracket closing the one at `start`, or None."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == pair[0]:
            depth += 1
        elif text[i] == pair[1]:
            depth -= 1
            if depth == 0:
                return i
    return None


def function_heads(scrubbed: str) -> List[Tuple[str, int, int, int]]:
    """(name, head, open_brace, close_brace) for every function body.

    A head is an identifier, a balanced parameter list, an optional `const`,
    and then `{` -- which is what a function definition is and what nothing
    else is. `if (x) {` has the same shape and is excluded by name; a
    declaration without a body ends in `;` and never reaches the brace.
    """
    out: List[Tuple[str, int, int, int]] = []
    for match in _CALL.finditer(scrubbed):
        name = match.group(1)
        if name in _CLAUSE_WORDS:
            continue
        close = _matching(scrubbed, match.end() - 1, "()")
        if close is None:
            continue
        i = close + 1
        while i < len(scrubbed) and scrubbed[i].isspace():
            i += 1
        if scrubbed.startswith("const", i):
            i += 5
            while i < len(scrubbed) and scrubbed[i].isspace():
                i += 1
        if i >= len(scrubbed) or scrubbed[i] != "{":
            continue
        end = _matching(scrubbed, i, "{}")
        if end is None:
            continue
        out.append((name, match.start(), i, end))
    return out


#: `class X : base {` or `namespace rhythm {`. The class's name is what makes a
#: method's label, and it has to be the qualified one: Manamon 2 declares
#: `sound_pool` both globally and in namespace `rhythm`, and keying a method by
#: its bare name conflates the two -- the same collision that once wrote both
#: classes' property tables into one block.
_SCOPE = re.compile(r"\b(class|namespace)\s+([A-Za-z_]\w*)")


def scopes(scrubbed: str) -> List[Tuple[str, str, int, int]]:
    """(kind, name, open_brace, close_brace) for every class and namespace."""
    out = []
    for match in _SCOPE.finditer(scrubbed):
        brace = scrubbed.find("{", match.end())
        if brace < 0:
            continue
        # Nothing but a base-class list may stand between the name and the
        # brace; a forward declaration ends in `;` and has no body.
        between = scrubbed[match.end():brace]
        if ";" in between or "}" in between or "(" in between:
            continue
        end = _matching(scrubbed, brace, "{}")
        if end is not None:
            out.append((match.group(1), match.group(2), brace, end))
    return out


def body_label(found: Sequence[Tuple[str, str, int, int]], name: str,
               head: int) -> str:
    """`owner::name` for a body at `head`, the way `function_label` spells it.

    A method's owner is its namespace-qualified class; anything else is
    `<global>::name`, because the module records no owner for a free function
    even inside a namespace.
    """
    enclosing = [s for s in found if s[2] < head < s[3]]
    classes = [s for s in enclosing if s[0] == "class"]
    if not classes:
        return "<global>::%s" % name
    owner = max(classes, key=lambda s: s[2])
    prefix = "".join("%s::" % s[1] for s in enclosing
                     if s[0] == "namespace" and s[2] < owner[2])
    return "%s%s::%s" % (prefix, owner[1], name)


def text_bodies(project: str) -> Dict[str, List[Body]]:
    """Every function body in the project's `.bgt` files, by `owner::name`.

    Each file is scrubbed once -- comments and string bodies blanked, byte
    positions preserved -- because every question below is asked of either the
    scrubbed text (where a number inside a comment or a string is not a number)
    or the raw text at the same offsets (where a literal's bytes are).

    Keyed by the qualified label rather than the bare name, because the bare
    name pairs almost nothing: Paladin declares `reset` in twenty-two classes,
    so by bare name every one of them is ambiguous on both sides at once.
    """
    out: Dict[str, List[Body]] = collections.defaultdict(list)
    for base, _dirs, files in os.walk(project):
        for name in sorted(files):
            if not name.endswith(".bgt"):
                continue
            path = os.path.join(base, name)
            with open(path, encoding="utf-8", errors="surrogateescape") as fh:
                raw = fh.read()
            scrubbed = bgt_apicheck.scrub(raw)
            stock = _STOCK_MARKER in raw[:600]
            relpath = os.path.relpath(path, project).replace("\\", "/")
            found = scopes(scrubbed)
            for fname, head, start, end in function_heads(scrubbed):
                label = body_label(found, fname, head)
                out[label].append(Body(
                    fname, label, path, relpath, raw.count("\n", 0, head) + 1,
                    raw[start:end + 1], scrubbed[start:end + 1], stock))
    return out


# --------------------------------------------------------------------------
# what the text holds
# --------------------------------------------------------------------------

def text_calls(body: Body) -> "collections.Counter[str]":
    """Every call in the body, by callee name."""
    got: "collections.Counter[str]" = collections.Counter()
    text = body.scrubbed
    for match in _CALL.finditer(text):
        name = match.group(1)
        if name in _CLAUSE_WORDS:
            continue
        got[name] += 1
    return got


def text_literals(body: Body) -> "collections.Counter[bytes]":
    """Every string literal in the body, as the bytes the engine would build.

    The quote characters survive scrubbing and their contents do not, so a
    quote in the scrubbed text is always a real delimiter -- a `"` inside a
    comment, and an escaped `\\"` inside a literal, are both blanked. The
    bytes come from the raw text at the same offsets.
    """
    got: "collections.Counter[bytes]" = collections.Counter()
    scrubbed, raw = body.scrubbed, body.raw
    i, n = 0, len(scrubbed)
    while i < n:
        c = scrubbed[i]
        if c in "\"'":
            j = scrubbed.find(c, i + 1)
            if j < 0:
                break
            got[unescape(raw[i + 1:j])] += 1
            i = j + 1
        else:
            i += 1
    return got


#: A numeric literal: hex, or decimal with an optional fraction, exponent and
#: `f` suffix. The lookbehind keeps `local_4` and `v3` out, and a `.` in front
#: keeps a member of a numbered name out.
_NUMBER = re.compile(
    r"(?<![\w.$])(0[xX][0-9a-fA-F]+"
    r"|(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?[fF]?)")


def text_numbers(body: Body) -> List[float]:
    """Every number the body's text spells, as a value.

    Read off the SCRUBBED text, so `"30 seconds"` is not a 30 and a commented
    out line is not evidence. A `-` directly in front contributes the negative
    reading as well, because a negative literal in source is unary minus over a
    positive one and the bytecode's constant is already signed.
    """
    values: List[float] = []
    text = body.scrubbed
    for match in _NUMBER.finditer(text):
        token = match.group(1)
        try:
            if token[:2].lower() == "0x":
                value: float = int(token, 16)
            else:
                value = float(token.rstrip("fF"))
        except ValueError:                      # pragma: no cover - defensive
            continue
        values.append(value)
        if match.start() and text[match.start() - 1] == "-":
            values.append(-value)
    return values


# --------------------------------------------------------------------------
# what the bytecode holds
# --------------------------------------------------------------------------

#: Every opcode that names a callee. `Thiscall1` goes through the same
#: `FindFunction` in `asCReader::TranslateFunction` as `CALL`, `CALLSYS` and
#: `CALLINTF`, and `ALLOC`'s second operand is a ONE-BASED index into the same
#: table -- which `as_disasm` resolves under the role `ctorfunc`, so the
#: one-based rule is applied in exactly one place.
_CALL_OPCODES = frozenset(("CALL", "CALLSYS", "CALLINTF", "CALLBND",
                           "Thiscall1", "ALLOC"))

#: Width in bytes of the constant each `SetV*` carries, which is what the
#: opcode name means and what decides the signed readings below.
_SET_WIDTH = {"SetV1": 1, "SetV2": 2, "SetV4": 4, "SetV8": 8}

#: Engine functions the recovered text has no syntax for, so their absence is
#: not a lost call. Named rather than guessed:
#:   `_beh_N_`      a behaviour -- construction, destruction, a list factory
#:   `get_`/`set_`  a property accessor, written `pool.pan_step`
#:   `opAdd`, ...   an operator method, written `+`
#:   the factories  the string, delegate, list and template-stub factories,
#:                  each of which IS the literal or the `{...}` in the text
#: Both spellings of each factory are listed, because a registered name is a
#: per-build field: BGT 1.3 calls the string factory `_string_factory_` and
#: Manamon 1's fork calls it `$str`.
_FACTORY_NAMES = frozenset((
    "_string_factory_", "$str", "%delegate_factory", "$dlgte",
    "factstub", "$list", "_builtin_function_",
))


def invisible_in_source(name: str, owned: bool = True) -> bool:
    """Is this callee one the recovered text cannot spell as a call?

    `owned` says whether the callee is a method, and it is load-bearing for
    the accessor rule. A property accessor is rewritten to `pool.pan_step`,
    which needs a receiver -- so only a *method* accessor is invisible. BGT
    registers `set_sound_storage` and `set_sound_decryption_key` as ordinary
    global functions, which the text calls by name, and a blanket `set_`
    prefix declined both. That is the dangerous direction: a name this wrongly
    holds is a lost call it will never report, and
    `set_sound_decryption_key` is the one call in these games whose loss is
    the difference between a recovery with sound and one without.
    """
    if name in _FACTORY_NAMES:
        return True
    if name.startswith(("_beh_", "$beh")):
        return True
    if owned and name.startswith(("get_", "set_")):
        return True
    # `opAdd`, `opIndex`, `opImplConv` -- but not `open` or `option`.
    return name.startswith("op") and len(name) > 2 and name[2].isupper()


def bytecode_callees(dis: Dict[str, Any]) -> Tuple[
        "collections.Counter[str]", int]:
    """(callee multiset, how many calls were declined as invisible).

    The name is taken from the operand `as_disasm` already resolved, and
    reduced to its bare half: the text writes `pool.play_stationary(...)`,
    never `sound_pool::play_stationary(...)`.
    """
    got: "collections.Counter[str]" = collections.Counter()
    declined = 0
    for ins in dis["instructions"]:
        if ins["name"] not in _CALL_OPCODES:
            continue
        for arg in ins["args"]:
            if arg.get("role") not in ("function", "ctorfunc"):
                continue
            label = arg.get("text")
            if not label:                       # unresolved, or no constructor
                continue
            owner, _, bare = label.rpartition("::")
            if not bare or not (bare[0].isalpha() or bare[0] == "_"):
                continue                        # `<no constructor>`
            if invisible_in_source(bare, owner not in ("", "<global>")):
                declined += 1
            else:
                got[bare] += 1
    return got, declined


def bytecode_literals(mod: as_disasm.Module,
                      dis: Dict[str, Any]) -> "collections.Counter[bytes]":
    """Every string constant the body loads, as the module's own bytes.

    The operand's *role* comes from `as_disasm` -- `string` for `STR`,
    `globalptr` for `PGA` and friends -- and so does the per-build answer to
    whether a global pointer carries a table-selector bit
    (`Module.plain_global_index`). Nothing here re-decides either. The bytes
    are read out of `used_strings` directly rather than through
    `Module.resolve`, which renders a literal for a *reader* and truncates it
    at 60 characters.
    """
    got: "collections.Counter[bytes]" = collections.Counter()
    strings = mod.used_strings
    for ins in dis["instructions"]:
        for arg in ins["args"]:
            role, value = arg.get("role"), arg["value"]
            if role == "string":
                index = value
            elif role == "globalptr":
                # A build whose global pointers are plain indices gives its
                # literals their own `STR`, so a `PGA` there is never one.
                if mod.plain_global_index or value & 1:
                    continue
                index = value >> 1
            else:
                continue
            if 0 <= index < len(strings):
                got[bytes(strings[index])] += 1
    return got


def bytecode_constants(dis: Dict[str, Any]) -> "collections.Counter[Tuple[int, int]]":
    """(value, width) for every `SetV*` immediate in the body."""
    got: "collections.Counter[Tuple[int, int]]" = collections.Counter()
    for ins in dis["instructions"]:
        width = _SET_WIDTH.get(ins["name"])
        if width is None or len(ins["args"]) < 2:
            continue
        got[(ins["args"][1]["value"], width)] += 1
    return got


def readings(value: int, width: int) -> List[float]:
    """Every number one bit pattern may honestly spell.

    An operand arrives from `as_opcodes` already *signed*, so the bits are
    recovered first -- `SetV4 4, -1027080192` and `SetV4 4, 0xC2C80000` are one
    instruction, and only the second reads as the float `-100.0`.

    What comes back: the unsigned value; the signed value, because the module
    records no sign and the text may spell either -- `this.walk(-1, false)`
    into an `int8` parameter is a one-byte `255` in the bytecode; and the
    IEEE-754 reading, because AngelScript has no float-constant opcode and
    `16.0` is a `SetV8` carrying the double's bits.

    The signed reading is taken at the opcode's OWN width and at the operand
    field's width, and at no other. Offering it at every narrower width as
    well is tempting and wrong: `SetV4 250` would then also read as the
    int8 `-6`, which nothing stores four bytes wide, and each spurious reading
    is one more way for a lost constant to find a match in the text and go
    unreported.

    Accepting both the signed and the unsigned reading of one bit pattern is
    deliberate, and it is the honest answer rather than the convenient one:
    nothing in a stripped module says which the source wrote, so a check that
    picked one would report the other as a lost constant.
    """
    bits = max(width, 4) * 8                  # the operand field, not the type
    raw = value & ((1 << bits) - 1)
    out: List[float] = [raw]
    for width_bits in {width * 8, bits}:
        if (1 << (width_bits - 1)) <= raw < (1 << width_bits):
            out.append(raw - (1 << width_bits))
    if width == 8:
        out.append(struct.unpack("<d", struct.pack("<Q", raw))[0])
    else:
        out.append(struct.unpack("<f", struct.pack("<I", raw & 0xFFFFFFFF))[0])
    # Deduplicated, with the readings no source could have written dropped: a
    # NaN, an infinity, and a denormal. The last of those is not cosmetic --
    # the float reading of a small integer is a denormal a hair above zero
    # (`SetV4 250` reads as 3.5e-43), and with an absolute tolerance in the
    # comparison that silently matched any `0.0` in the text. So the constant
    # audit reported nothing while a flattened 250 sat in front of it.
    seen: List[float] = []
    for candidate in out:
        if isinstance(candidate, float):
            if (math.isnan(candidate) or math.isinf(candidate)
                    or 0.0 < abs(candidate) < 1e-30):
                continue
        if candidate not in seen:
            seen.append(candidate)
    return seen


def same_number(a: float, b: float) -> bool:
    """`-100.0` and `-100` are the same constant; a spelling diff is not one.

    Relative tolerance only. An ABSOLUTE tolerance looks harmless and is not:
    it makes every tiny value equal to zero, and a zero is in almost every
    body's text.
    """
    if a == b:
        return True
    if math.isnan(a) or math.isnan(b) or math.isinf(a) or math.isinf(b):
        return False
    return math.isclose(a, b, rel_tol=1e-9, abs_tol=0.0)


# --------------------------------------------------------------------------
# the audits
# --------------------------------------------------------------------------

#: Skipped on the constant audit: both the commonest values in any module and
#: the two a `bool` can hold honestly, so a row carrying one says nothing.
_UNINFORMATIVE = (0, 1)


class Row:
    """One body, one audit, and what the bytecode holds that the text does not."""

    __slots__ = ("audit", "name", "where", "stock", "values")

    def __init__(self, audit: str, body: Body, values: List[str]) -> None:
        self.audit = audit
        self.name = body.name
        self.where = body.where()
        self.stock = body.stock
        self.values = values

    def as_dict(self) -> Dict[str, Any]:
        return {"audit": self.audit, "name": self.name, "where": self.where,
                "stock": self.stock, "values": self.values}

    def __str__(self) -> str:
        return "%-34s %-34s %s%s" % (
            self.name, self.where, ", ".join(self.values),
            "   [stock library file: its text is BGT's source]"
            if self.stock else "")


def _show_bytes(raw: bytes, limit: int = 48) -> str:
    """A literal, printable, with its length -- never silently truncated."""
    text = raw.decode("latin-1")
    out = "".join(c if 0x20 <= ord(c) < 0x7F and c != '"' else
                  "\\x%02x" % ord(c) for c in text[:limit])
    return '"%s"%s' % (out, "... (%d bytes)" % len(raw) if len(raw) > limit
                       else "")


def _show_number(value: int, width: int) -> str:
    """The constant and every reading of it, so a row can be triaged by eye."""
    every = readings(value, width)
    extra = ", ".join("%r" % r for r in every[1:])
    return "SetV%d %s%s" % (width, every[0],
                            " (= %s)" % extra if extra else "")


def pair_bodies(mod: as_disasm.Module, project: str) -> Tuple[
        List[Tuple[Dict[str, Any], Body]], Dict[str, int]]:
    """Bodies whose name is unique on BOTH sides, and the counts around them.

    Ambiguity is declined rather than resolved: a class's constructor and its
    factory share a name, and so can a method and a global function, and the
    module keeps no file information that could separate them in the text.
    """
    texts = text_bodies(project)
    functions = [f for f in mod.functions if f.get("body")]
    by_name = collections.Counter(as_disasm.function_label(f)
                                  for f in functions)
    pairs = []
    ambiguous = 0
    for f in functions:
        name = as_disasm.function_label(f)
        if by_name[name] != 1:
            ambiguous += 1
            continue
        bodies = texts.get(name)
        if not bodies:
            continue
        if len(bodies) != 1:
            ambiguous += 1
            continue
        pairs.append((f, bodies[0]))
    return pairs, {"module_bodies": len(functions),
                   "text_bodies": sum(len(v) for v in texts.values()),
                   "paired": len(pairs), "ambiguous": ambiguous}


def audit(project: str, exe: Optional[str] = None,
          module_path: Optional[str] = None,
          mod: Optional[as_disasm.Module] = None,
          which: Sequence[str] = ("calls", "literals", "constants"),
          ) -> Dict[str, Any]:
    """Run the selected audits over `project` against its module.

    Pass an already-parsed `as_disasm.Module` to avoid re-reading it; otherwise
    `module_path` plus `exe` (for the opcode table) are read here.
    """
    if mod is None:
        if not module_path:
            raise ValueError("a module is required")
        mod = as_disasm.load(module_path, exe)
    pairs, counts = pair_bodies(mod, project)

    rows: List[Row] = []
    totals: Dict[str, Dict[str, int]] = {
        name: {"bodies": 0, "values": 0, "declined": 0} for name in which}

    for f, body in pairs:
        dis = as_disasm.disassemble_function(mod, f)

        if "calls" in which:
            want, declined = bytecode_callees(dis)
            totals["calls"]["declined"] += declined
            lost = want - text_calls(body)
            if lost:
                rows.append(Row("calls", body, [
                    "%s%s" % (n, "" if c == 1 else " x%d" % c)
                    for n, c in sorted(lost.items())]))
                totals["calls"]["bodies"] += 1
                totals["calls"]["values"] += sum(lost.values())

        if "literals" in which:
            lost_strings = bytecode_literals(mod, dis) - text_literals(body)
            if lost_strings:
                rows.append(Row("literals", body, [
                    "%s%s" % (_show_bytes(s), "" if c == 1 else " x%d" % c)
                    for s, c in sorted(lost_strings.items())]))
                totals["literals"]["bodies"] += 1
                totals["literals"]["values"] += sum(lost_strings.values())

        if "constants" in which:
            spelled = text_numbers(body)
            lost_numbers = []
            for (value, width), _count in sorted(
                    bytecode_constants(dis).items()):
                if value in _UNINFORMATIVE:
                    totals["constants"]["declined"] += 1
                    continue
                candidates = readings(value, width)
                if not any(same_number(c, s)
                           for c in candidates for s in spelled):
                    lost_numbers.append(_show_number(value, width))
            if lost_numbers:
                rows.append(Row("constants", body, lost_numbers))
                totals["constants"]["bodies"] += 1
                totals["constants"]["values"] += len(lost_numbers)

    return {"project": project, "counts": counts, "totals": totals,
            "rows": [r.as_dict() for r in rows], "_rows": rows,
            "audits": list(which)}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _find_module(project: str) -> Optional[str]:
    for name in sorted(os.listdir(project)):
        if name.endswith("_bytecode.bin"):
            return os.path.join(project, name)
    return None


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="bgt audit",
        description="the module is the oracle: every callee, literal and "
                    "numeric constant the bytecode holds, against the "
                    "recovered text",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project", help="a directory `bgt recover` wrote")
    ap.add_argument("executable", help="the game it was recovered from")
    ap.add_argument("--module", help="the module (default: "
                                     "<project>/*_bytecode.bin, else unpacked "
                                     "from the executable)")
    ap.add_argument("--calls", action="store_true", help="only the callee audit")
    ap.add_argument("--literals", action="store_true",
                    help="only the string-literal audit")
    ap.add_argument("--constants", action="store_true",
                    help="only the numeric-constant audit")
    ap.add_argument("--limit", type=int, default=40,
                    help="rows printed per audit (0 = all)")
    ap.add_argument("--stock", action="store_true",
                    help="include rows from substituted stock library files, "
                         "whose text is BGT's own source")
    ap.add_argument("--json", metavar="FILE", help="write the whole report")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any row is reported")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.project):
        print("bgt audit: no such project directory: %s" % args.project,
              file=sys.stderr)
        return 2

    which = [name for name, on in (("calls", args.calls),
                                   ("literals", args.literals),
                                   ("constants", args.constants)) if on]
    which = which or ["calls", "literals", "constants"]

    module_path = args.module or _find_module(args.project)
    temporary = None
    if not module_path or not os.path.isfile(module_path):
        # One command, no preparation: the executable carries the module.
        try:
            layers = bgtlib.unpack_file(args.executable)
        except Exception as exc:                     # noqa: BLE001
            print("bgt audit: no module, and %s would not unpack: %s"
                  % (args.executable, exc), file=sys.stderr)
            return 2
        handle, module_path = tempfile.mkstemp(suffix="_bytecode.bin")
        with os.fdopen(handle, "wb") as fh:
            fh.write(layers.bytecode)
        temporary = module_path

    try:
        report = audit(args.project, args.executable, module_path, which=which)
    finally:
        if temporary:
            os.unlink(temporary)

    counts = report["counts"]
    print("%d of %d module bodies paired with one in the text "
          "(%d declined as ambiguous)"
          % (counts["paired"], counts["module_bodies"], counts["ambiguous"]))
    if not counts["paired"]:
        # The failure this check exists to avoid: no rows because nothing was
        # looked at. Never a silent zero.
        sys.stdout.flush()
        print("bgt audit: NOTHING PAIRED -- this audit measured nothing",
              file=sys.stderr)
        return 1

    rows: List[Row] = report["_rows"]
    for name in report["audits"]:
        total = report["totals"][name]
        shown = [r for r in rows if r.audit == name
                 and (args.stock or not r.stock)]
        hidden = sum(1 for r in rows if r.audit == name and r.stock
                     and not args.stock)
        print("\n%s: %d bod%s, %d value%s the text does not hold%s%s"
              % (name, len(shown), "y" if len(shown) == 1 else "ies",
                 sum(len(r.values) for r in shown),
                 "" if sum(len(r.values) for r in shown) == 1 else "s",
                 "" if not total["declined"] else
                 "   (%d declined)" % total["declined"],
                 "" if not hidden else
                 "   (%d stock-file rows hidden; --stock shows them)" % hidden))
        limit = len(shown) if args.limit == 0 else args.limit
        for row in shown[:limit]:
            print("   " + str(row))
        if len(shown) > limit:
            print("   ... %d more" % (len(shown) - limit))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({k: v for k, v in report.items() if k != "_rows"},
                      fh, indent=2, default=str)

    if args.strict and rows:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
