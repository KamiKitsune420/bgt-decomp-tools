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
import glob
import os
import re
import sys
from typing import Dict, List, Optional, Sequence, Tuple

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
OPERATOR_METHODS = frozenset(("opIndex", "opAssign", "opEquals", "opAdd", "opCmp"))

_CALL = re.compile(r"(?<![\w.])(?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*)\s*\(")
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
    """Call names in EVALUATION order -- sorted by where each call's `)` closes."""
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


def literals(text: str) -> collections.Counter:
    return collections.Counter(_STRING.findall(text))


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
    args = ap.parse_args(argv)

    dirs = find_include_dirs(args.include)
    if not dirs:
        print("bgt libcheck: no BGT include folder found -- pass --include <dir>",
              file=sys.stderr)
        return 2
    library = library_functions(dirs)
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
                print("        %-7s source %s  lifted %s"
                      % (op, r.source_calls[i1:i2], r.lifted_calls[j1:j2]))
    if len(shown) > 8 and not args.verbose:
        print("\n  ... %d more (-v shows all)" % (len(shown) - 8))
    print("\nA difference is a lead, not a verdict: games often ship a different "
          "version of the library than the installed one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
