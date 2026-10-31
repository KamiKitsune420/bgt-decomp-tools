"""
bgt_libcheck -- check lifted code against source nobody here wrote.

BGT ships the source of its standard library (`dynamic_menu.bgt`,
`sound_pool.bgt`, `form.bgt`, ...) in its install's `include/` folder, and games
compile those files in. That makes the library the one part of a game whose
original text is known, so the lifter can be scored against it objectively
instead of by reading output that looks plausible:

    bgt libcheck work/strike_bytecode.bin strike.exe
    bgt libcheck module.bin game.exe --include "C:/Program Files (x86)/BGT/include" -v

For every function that appears exactly once in both the library source and the
recovered module, it compares:

* **the sequence of calls**, in *evaluation* order. A call runs when its `)`
  closes, so `speak(input_box_speak(find(x)))` is `find, input_box_speak,
  speak` -- the order the bytecode runs them. Property accessors (`get_*`,
  `set_*`), index operators and constructors are left out, because source
  writes them as syntax (`h.pan = x`, `text[i]`) and bytecode as calls.
* **the multiset of string literals**. As a multiset, not a sequence: the
  compiler evaluates arguments LAST TO FIRST, so `string_replace(c, "&", "")`
  materialises `""` before `"&"`, and a sequence comparison would call a
  correct lift wrong.

## What it caught

Every one of these read plausibly and was wrong until this comparison showed the
recovered code disagreeing with the real source:

* every multi-argument call rendered with its arguments reversed;
* every non-void function with several `return`s returning the value of
  whichever path came last -- `sound_pool::destroy_sound` read as always
  returning false;
* guard clauses (`if (!handle.active) return;`) nesting the rest of the body in
  a branch, which reordered what followed;
* branches with no join point printed in reverse (`form.bgt`'s `edit_silent`).

Psycho Strike went from 107 to 151 of 155 matching call sequences.

## Reading the result

A mismatch is a lead, not a verdict. Games often ship a *different version* of
the library than the one installed -- Manamon 2's `sound_pool` has
`is_playing` and a destroy callback that BGT 1.3's does not -- and then the two
texts genuinely differ. Compare against the version the game was built with
where you can; titles built with the same BGT release as the installed one are
the meaningful reference.
"""

import argparse
import collections
import difflib
import json
import glob
import os
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:                      # installed as a package
    from . import as_disasm, as_lift
except ImportError:       # run directly from a checkout
    import as_disasm
    import as_lift

DEFAULT_INCLUDE_DIRS = (
    r"C:\Program Files (x86)\BGT\include",
    r"C:\Program Files\BGT\include",
)

KEYWORDS = frozenset(("if", "while", "for", "switch", "return", "catch", "else",
                      "do", "cast"))
# Constructions and conversions: calls in bytecode, types in source.
TYPE_NAMES = frozenset(("string", "int", "uint", "double", "float", "bool", "int8",
                        "int16", "int64", "uint8", "uint16", "uint64", "array",
                        "dictionary", "vector"))
#: Operators the source writes as syntax, so neither side should count them as
#: calls. `opAdd_r` is the **reversed** form, which the engine registers for
#: `<number> + <string>`: `form.bgt` writes `speak(selections.length() + "
#: items deleted.", true)` and the lifter renders the registered method the
#: compiler actually calls. It was absent only because a string literal is
#: blanked before matching, so no receiver was left to reach it -- the same
#: blindness as the indexed receiver above, one receiver kind over.
#:
#: This set is widened one measured occurrence at a time, deliberately: a name
#: in here is dropped from BOTH sides, so every addition makes the comparison
#: weaker. `opAdd_r` is the only `op*` name the corpus produces that is not
#: already here.
OPERATOR_METHODS = frozenset(("opIndex", "opAssign", "opEquals", "opAdd",
                              "opAdd_r", "opCmp"))

#: The identifier a `(` opens against. **Not** a receiver chain: this used to be
#: `(?<![\w.])(?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*)\s*\(`, which named the callee by
#: consuming the dotted chain in front of it -- and the `.` in that lookbehind is
#: what made `global_interacts[slot].add_event(...)` invisible. The chain
#: alternative cannot cross the `]`, and starting at `add_event` instead is
#: refused because the character before it is a dot. So every method called on an
#: indexed receiver was dropped from the sequence this checker compares, on BOTH
#: sides -- a call it cannot see is a call it cannot report as missing.
#:
#: The receiver was never what identifies a call; **adjacency to the `(` is**. So
#: there is nothing to enumerate: match the whole identifier the paren opens
#: against, and let the one lookbehind say "whole identifier". That reaches
#: `a[i].m()`, `a[i][j].m()`, `this.list[n].m()` and `a[f(i)].m()` without
#: knowing anything about brackets, where a chain pattern taught to span `[...]`
#: would have to stop at a nested `[` -- and would swallow a call written inside
#: the subscript, because `finditer` resumes past whatever the match consumed.
_CALL = re.compile(r"(?<!\w)([A-Za-z_]\w*)\s*\(")
_STRING = re.compile(r'"((?:\\.|[^"\\])*)"')
_FUNC_HEAD = re.compile(r"([A-Za-z_][\w@\[\]<>&:]*\s+)?(~?[A-Za-z_]\w*)\s*"
                        r"\(([^;{}()]*)\)\s*(const\s*)?\{")
_CLASS_HEAD = re.compile(r"\bclass\s+(\w+)[^{;]*\{")


# --------------------------------------------------------------------------
# reading the library source
# --------------------------------------------------------------------------

def _skip_string(src: str, i: int) -> int:
    """Index just past the string literal that starts at src[i] == '"'."""
    j = i + 1
    while j < len(src) and src[j] != '"':
        j += 2 if src[j] == "\\" else 1
    return j + 1


def strip_comments(src: str) -> str:
    """Remove // and /* */ comments, leaving string literals intact."""
    out: List[str] = []
    i, n = 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif src[i] == '"':
            j = _skip_string(src, i)
            out.append(src[i:j])
            i = j
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def source_functions(text: str) -> Dict[str, List[str]]:
    """`owner::name` -> list of bodies, for every function in a .bgt source.

    A small brace-matching scanner, not a parser: it tracks class nesting to know
    each function's owner and skips string literals so a `{` inside one does not
    count. Free functions are owned by `<global>`, as as_disasm labels them.
    Overloads share a label, which is why bodies come back as a list.
    """
    src = strip_comments(text)
    funcs: Dict[str, List[str]] = collections.defaultdict(list)
    classes: List[Tuple[str, int]] = []            # (name, depth it opened at)
    depth = i = 0
    while i < len(src):
        m = _CLASS_HEAD.match(src, i)
        if m:
            classes.append((m.group(1), depth))
            depth += 1
            i = m.end()
            continue
        in_class_body = bool(classes) and depth == classes[-1][1] + 1
        m = _FUNC_HEAD.match(src, i)
        if m and (depth == 0 or in_class_body) and m.group(2) not in KEYWORDS:
            j, d = m.end(), 1
            while j < len(src) and d:
                if src[j] == '"':
                    j = _skip_string(src, j)
                    continue
                d += {"{": 1, "}": -1}.get(src[j], 0)
                j += 1
            owner = classes[-1][0] if in_class_body else "<global>"
            funcs["%s::%s" % (owner, m.group(2))].append(src[m.end():j - 1])
            i = j
            continue
        c = src[i]
        if c == '"':
            i = _skip_string(src, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if classes and depth == classes[-1][1]:
                classes.pop()
        i += 1
    return dict(funcs)


def library_functions(include_dirs: Sequence[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = collections.defaultdict(list)
    for folder in include_dirs:
        for path in sorted(glob.glob(os.path.join(folder, "*.bgt"))):
            with open(path, encoding="latin1") as fh:
                for label, bodies in source_functions(fh.read()).items():
                    out[label].extend(bodies)
    return dict(out)


# --------------------------------------------------------------------------
# comparing
# --------------------------------------------------------------------------

def _noise(name: str) -> bool:
    return (name in KEYWORDS or name in TYPE_NAMES or name in OPERATOR_METHODS
            or name.startswith(("get_", "set_", "_beh_", "$beh")))


def calls(text: str) -> List[str]:
    """Call names in EVALUATION order -- sorted by where each call's `)` closes.

    The rule is unchanged by the pattern above seeing more calls than it used to:
    a method on an indexed receiver is placed by its own `)`, exactly as any
    other method is, so `global_interacts[slot].add_event(find(x))` is
    `find, add_event` -- the order the bytecode runs them. What *is* new is that
    a call on a call's result (`f(x).m()`) now yields both `f` and `m` rather
    than `f` alone; both are real calls and the `)` rule orders them correctly.

    Because it tracks no brackets at all, a nested subscript costs it nothing:
    `a[b[i]].m()` is `m`, and a call written *inside* a subscript is still its
    own match -- `a[fetch(i)].m()` is `fetch, m`. What it still does not see is a
    call through a funcdef held in an array (`events[i](this)`), which has no
    name to report at all.

    One thing an indexed receiver is not the only kind of: a receiver that is not
    a plain identifier. A **string literal** is another, and literals are blanked
    to `""` two lines down, so `" items deleted.".opAdd_r(n)` was unreachable for
    exactly the same reason and is reachable now. `OPERATOR_METHODS` is the list
    that keeps an operator the source writes as syntax out of the comparison, and
    it does not hold `opAdd_r` -- so the one reversed concatenation in this
    corpus (Psycho Strike's lifted `audio_form::delete_list_selections`, where
    the source writes `selections.length() + " items deleted."`) is now reported
    as a difference it is not. That is the measured cost of this pattern, kept
    separate from it on purpose: adding the name here would move a score for a
    second reason in the same breath.
    """
    text = _STRING.sub('""', text)
    found = []
    for m in _CALL.finditer(text):
        name = m.group(1)
        if _noise(name):
            continue
        j, d = m.end(), 1
        while j < len(text) and d:
            d += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
        found.append((j, name))
    return [name for _, name in sorted(found)]


#: `\xNN`, the escape the engine's lexer reads as one byte.
_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _same_string(literal: str) -> bytes:
    """One literal reduced to the bytes the engine would build from it.

    Two spellings of the same string must compare equal, or this measures
    spelling. Stock `form.bgt` writes `"\\xa3"` as the raw byte 0xA3 in a
    latin-1 file and recovered source writes it as the escape, because a lone
    0xA3 is not valid UTF-8 and emitting it as a character into a UTF-8 file
    would hand the engine two bytes instead of one.

    That difference is worth stating plainly: before the escape existed those
    two *did* compare equal, and the comparison was flattering a real bug --
    the recovered literal was wrong and matched the source anyway.
    """
    text = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), literal)
    for escape, char in (("\\\\", "\\"), ('\\"', '"'), ("\\n", "\n"),
                         ("\\r", "\r"), ("\\t", "\t")):
        text = text.replace(escape, char)
    return text.encode("utf-8", "surrogateescape")


def literals(text: str) -> collections.Counter:
    return collections.Counter(_same_string(s) for s in _STRING.findall(text))


class Comparison:
    __slots__ = ("label", "source_calls", "lifted_calls", "ratio", "literals_equal")

    def __init__(self, label: str, source: str, lifted: str) -> None:
        self.label = label
        self.source_calls = calls(source)
        self.lifted_calls = calls(lifted)
        a, b = self.source_calls, self.lifted_calls
        self.ratio = difflib.SequenceMatcher(None, a, b).ratio() if (a or b) else 1.0
        self.literals_equal = literals(source) == literals(lifted)

    @property
    def identical(self) -> bool:
        return self.source_calls == self.lifted_calls


def compare(mod: "as_disasm.Module",
            library: Dict[str, List[str]]) -> List[Comparison]:
    """Compare every function present exactly once on both sides."""
    recovered: Dict[str, List[dict]] = collections.defaultdict(list)
    for f in mod.functions:
        recovered[as_disasm.function_label(f)].append(f)
    out = []
    for label in sorted(library):
        bodies = library[label]
        if len(bodies) != 1 or len(recovered.get(label, ())) != 1:
            continue             # absent, or overloaded: no unambiguous pair
        lifted = as_lift.lift_function(mod, recovered[label][0])
        out.append(Comparison(label, bodies[0], "\n".join(as_lift.structure(lifted))))
    return out


def compare_decompiled(module_path: str, exe_path: Optional[str],
                       opcodes: Optional[str],
                       library: Dict[str, List[str]]) -> List[Comparison]:
    """The same comparison, against the decompiler rather than the lifter.

    `bgt recover` emits compilable source through a different path -- the IR
    adapter and the decompiler -- and a clean compile says nothing about
    meaning. This is the check that does: per function, the sequence of calls
    in evaluation order and the string literals as a multiset, against source
    nobody here wrote.
    """
    try:                      # installed as a package
        from . import bgt_asir
        from .nvgt import decompile
    except ImportError:       # run directly from a checkout
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "nvgt"))
        import bgt_asir
        import decompile

    table = None
    if opcodes:
        with open(opcodes, encoding="utf-8") as fh:
            table = {int(k): v for k, v in json.load(fh).items()}
    module = bgt_asir.load(module_path, exe_path, table)
    renderer = decompile.ModuleDecompiler(module)

    recovered: Dict[str, List[Any]] = collections.defaultdict(list)
    for f in module.saved_functions:
        if not f.bytecode:
            continue
        owner = f.object_type.name if f.object_type is not None else "<global>"
        recovered["%s::%s" % (owner, f.name)].append(f)
    out = []
    for label in sorted(library):
        bodies = library[label]
        if len(bodies) != 1 or len(recovered.get(label, ())) != 1:
            continue             # absent, or overloaded: no unambiguous pair
        text = chr(10).join(renderer._body(recovered[label][0], 0))
        out.append(Comparison(label, bodies[0], text))
    return out


def find_include_dirs(explicit: Optional[Sequence[str]]) -> List[str]:
    if explicit:
        return [d for d in explicit if os.path.isdir(d)]
    return [d for d in DEFAULT_INCLUDE_DIRS if os.path.isdir(d)]


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="bgt libcheck", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("module", help="recovered bytecode (from bgt unpack)")
    ap.add_argument("exe", nargs="?", help="the game exe, for its opcode table")
    ap.add_argument("--opcodes", help="opcode table JSON instead of the exe")
    ap.add_argument("--include", action="append",
                    help="BGT include folder (default: the usual install paths); repeatable")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show every function that is not identical")
    ap.add_argument("--decompiler", action="store_true",
                    help="score the decompiler (bgt recover) instead of the lifter")
    args = ap.parse_args(argv)

    dirs = find_include_dirs(args.include)
    if not dirs:
        print("bgt libcheck: no BGT include folder found -- pass --include <dir>",
              file=sys.stderr)
        return 2
    library = library_functions(dirs)
    if args.decompiler:
        results = compare_decompiled(args.module, args.exe, args.opcodes, library)
    else:
        mod = as_disasm.load(args.module, args.exe, args.opcodes)
        results = compare(mod, library)
    if not results:
        print("no library function appears in this module under the same name")
        return 1

    identical = sum(r.identical for r in results)
    close = sum(1 for r in results if not r.identical and r.ratio >= 0.8)
    lits = sum(r.literals_equal for r in results)
    print("%d library functions compared against %s" % (len(results), ", ".join(dirs)))
    print("  call sequence identical   %d" % identical)
    print("  call sequence close       %d   (>= 80%% similar)" % close)
    print("  call sequence differs     %d" % (len(results) - identical - close))
    print("  string literals identical %d" % lits)
    shown = [r for r in results if not r.identical]
    shown.sort(key=lambda r: r.ratio)
    for r in shown if args.verbose else shown[:8]:
        print("\n  %.2f  %s" % (r.ratio, r.label))
        for op, i1, i2, j1, j2 in difflib.SequenceMatcher(
                None, r.source_calls, r.lifted_calls).get_opcodes():
            if op != "equal":
                print("        %-7s source %s  recovered %s"
                      % (op, r.source_calls[i1:i2], r.lifted_calls[j1:j2]))
    if len(shown) > 8 and not args.verbose:
        print("\n  ... %d more (-v shows all)" % (len(shown) - 8))
    print("\nA difference is a lead, not a verdict: games often ship a different "
          "version of the library than the installed one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
