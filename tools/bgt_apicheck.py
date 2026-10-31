"""
bgt_apicheck -- every call in a recovered project's TEXT, against every arity
anything declares.

`bgt recover --compile` is the measure of whether recovered source is valid,
and on the largest title in the corpus it measures nothing. Manamon 2 was
built with a newer BGT, so its 33 diagnostics are all *parse* errors on
`protected` and `weakref<T>`; a parse error stops the compiler before it
checks a single call, and 171,000 lines have never been read back by
anything.

This reads them back. The simulation pops a callee's declared arity by
construction, so an arity mismatch cannot exist in the IR -- but the rendered
source is a different artefact. It has been through temporary folding, slot
promotion, scope qualification and stock-include substitution, and each of
those has dropped a real argument at least once in this repository's history.
A check on the text is the only thing that sees them.

## The oracle, and what it declines to judge

Three sources between them know every callee, and none of them is a guess:

* **The module's own `usedFunctions`** -- the strongest, because it carries
  each callee's parameter list and default arguments *as the engine that
  compiled this module declared them*. A title built with a fork is checked
  against its fork.
* **The game's own runtime**, whose registration strings are the whole
  interface of that build (`bgt_api.registered`).
* **What the script declares** -- its classes, their methods, its global
  functions, and every local and parameter in the recovered text.

What it will not judge, it counts instead of guessing at:

* **A constructor of a registered type.** AngelScript registers every
  constructor and factory under the literal name `f`, with the owner type as
  a separate string argument, so `vector @f()` and `void f(float, float y=0,
  float z=0)` sit in the binary with nothing to say which type either belongs
  to. Taking the union of every `f` would accept 0 to 3 arguments for
  anything, which is not a check.
* **A call through a funcdef-typed local or parameter**, whose arity is the
  funcdef's and not the variable's.

    bgt apicheck recovered/ game.exe
"""
from __future__ import annotations

import argparse
import collections
import os
import re
import sys
from typing import Dict, List, Optional, Sequence, Set, Tuple

try:                      # installed as a package
    from . import as_opcodes, bgt_api, bgt_asir
except ImportError:       # run directly from a checkout
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import as_opcodes
    import bgt_api
    import bgt_asir

#: Words that take a parenthesised clause without being a call.
KEYWORDS = frozenset((
    "if", "while", "for", "switch", "return", "else", "do", "case", "default",
    "break", "continue", "cast", "and", "or", "not", "sizeof", "null", "true",
    "false", "this", "super", "in", "out", "inout", "const", "void",
))
#: A primitive's name used as a call is a cast: `int(x)`, `float(y)`.
PRIMITIVES = frozenset((
    "bool", "int", "uint", "float", "double", "int8", "int16", "int64",
    "uint8", "uint16", "uint64",
))
#: What may stand immediately before a call's name and still leave it a call.
#: A DECLARATION is `<type> name(`, so what precedes the name there is a type.
CALL_KEYWORDS = frozenset(("return", "case", "else", "do", "new", "and", "or",
                           "not"))
#: ...and these can never be the type in `<type> name`, however much they look
#: like one. `return alert(x)` and `const string s` are both shaped
#: `<word> <word><punct>`; adopting `alert` and `string` as names the script
#: declares costs 479 of Manamon 2's checked calls, silently.
NOT_A_TYPE = KEYWORDS | frozenset((
    "delete", "new", "namespace", "class", "enum", "funcdef", "interface",
    "typedef", "import", "shared", "external", "abstract", "final",
    "override", "private", "protected", "mixin",
))

#: Any call, method calls included. A pattern that excludes a leading `.`
#: hides every `pool.play_stationary(...)` in the corpus.
CALL = re.compile(r"(?<![\w])\.?\s*([A-Za-z_]\w*)\s*\(")
PRECEDING = re.compile(r"([A-Za-z_]\w*|[@\]])\s*$")
#: `<type> <name>` at a declaration: a parameter, a local, a member, a function.
#: The marker run **repeats**, because a type may carry more than one:
#: `interact@[]` is a handle array and `collect@[]@` a handle to one. Accepting
#: a single marker lost every such declaration -- and so reported Manamon 1's
#: five generated `__nvgt_global_init_N` initialisers as declared nowhere while
#: each sat in the file that calls it. Same family as `bgt_api`'s array return
#: and its handle marker against either side: a type has more spellings than it
#: looks, and this set is what decides whether an absence gets reported.
DECLARED = re.compile(r"(?<![\w.])([A-Za-z_]\w*)(?:\s*@|\s*\[\s*\])*"
                      r"\s+([A-Za-z_]\w*)\s*[(=;,){\[]")


def scrub(text: str) -> str:
    """Blank comments and string bodies in ONE left-to-right pass.

    Two regexes applied in sequence cannot do this, because each construct
    can contain the other's opener. Manamon 2 calls

        url_get("http://www.vgstorm.com/playmmn.txt");

    and a comment pass run first eats `//www.vgstorm...` as a line comment,
    taking the string's closing quote with it -- after which every quote in
    the rest of the file pairs with the wrong partner. That desync reported
    a one-argument call as taking ten, and then thirty-three.

    Byte positions are preserved, so an offset into the result is the same
    offset in the original.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n
                                 and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            i = min(i + 2, n)
        elif c in "\"'":
            quote = c
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\":                  # an escaped quote does
                    out[i] = " "                     # not close the literal
                    i += 1
                    if i < n:
                        out[i] = " "
                        i += 1
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            i += 1
        else:
            i += 1
    return "".join(out)


def split_args(text: str, open_paren: int) -> Optional[Tuple[List[str], int]]:
    """The top-level arguments of the call whose `(` is at `open_paren`."""
    depth, start, args, i = 0, open_paren + 1, [], open_paren
    while i < len(text):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                piece = text[start:i].strip()
                if piece or args:
                    args.append(piece)
                return args, i
        elif c == "," and depth == 1:
            args.append(text[start:i].strip())
            start = i + 1
        i += 1
    return None


def declaration_arity(signature: str) -> Tuple[int, int]:
    """(required, total) for one engine declaration string."""
    inner = signature[signature.index("(") + 1:signature.rindex(")")]
    params, depth, piece = [], 0, ""
    for c in inner:
        if c in "<([":
            depth += 1
        elif c in ">)]":
            depth -= 1
        if c == "," and depth == 0:
            params.append(piece)
            piece = ""
        else:
            piece += c
    if piece.strip():
        params.append(piece)
    params = [p.strip() for p in params if p.strip()]
    return sum(1 for p in params if "=" not in p), len(params)


def is_a_declaration(text: str, start: int) -> bool:
    """Is the name at `start` being declared rather than called?

    `string serialize(dictionary@ d)` in a class body is a definition; read
    as a call it is a two-argument call to the engine's one-argument
    `serialize`, and every class in Manamon 2 that declares one produced
    that false positive. What tells them apart is the token before the
    name: a declaration has a *type* there, a call has an operator, a
    bracket, or one of the few keywords that can precede a call.
    """
    head = PRECEDING.search(text[max(0, start - 64):start])
    return head is not None and head.group(1) not in CALL_KEYWORDS


def funcdef_names(module, registrations: Dict[str, List[str]]) -> Set[str]:
    """Names that are funcdefs, whose call syntax means something else.

    `pathfinder_callback(arg0.callbackPf)` does not *call* the callback with
    the five arguments it declares -- it constructs a delegate, binding one
    method. A funcdef in call position always takes exactly one argument,
    whatever its own signature says, and reading it the other way reported
    all thirteen of Crazy Party's delegates as arity mismatches.

    The module names its own. A *registered* funcdef is told from a
    registered function by the same evidence that names one in the first
    place: its name is used as a parameter type somewhere in the
    registrations, which is true of a callback and of nothing else.
    """
    names = {f.name.split("::")[-1]
             for f in getattr(module, "funcdefs", ()) or () if f.name}
    as_parameter: Set[str] = set()
    for signatures in registrations.values():
        for text in signatures:
            match = bgt_api.REGISTRATION.match(text)
            if match is None:
                continue
            for part in match.group("params").split(","):
                word = re.search(r"[A-Za-z_]\w*", part.replace("const", "", 1))
                if word is not None:
                    as_parameter.add(word.group())
    return names | (as_parameter & set(registrations))


def arities(module, registrations: Dict[str, List[str]]
            ) -> Dict[str, Set[Tuple[int, int]]]:
    """name -> every (low, high) anything declares for it.

    A name may legitimately have several, from overloads and from methods of
    unrelated types sharing a name, so this is a set and a call is judged
    against all of it. That is deliberately weaker than resolving the
    receiver's type: without a type checker the receiver is not known, and a
    check that reports unless *nothing* fits cannot produce a false alarm
    from an overload it failed to consider.
    """
    out: Dict[str, Set[Tuple[int, int]]] = collections.defaultdict(set)
    #: A funcdef's own parameter list is never what a *call* of its name
    #: takes, so it is kept out of the table rather than overwritten later:
    #: `event` is a global funcdef in Manamon 2 **and** the class
    #: `rhythm::event`, and replacing its entry threw the class's
    #: constructor away and reported five good `event()` calls as taking too
    #: few arguments. The same name-collision lesson as `string::insert`
    #: hiding behind `array::insert_at`: a name-keyed oracle unions, it
    #: never replaces.
    callbacks = funcdef_names(module, registrations)

    def take(f) -> None:
        if not getattr(f, "name", None):
            return
        if getattr(f, "func_type", 0) == 4:          # a funcdef declaration
            return
        total = len(f.param_types)
        defaults = sum(1 for d in (f.default_args or ()) if d)
        out[f.name.split("::")[-1]].add((total - defaults, total))

    for f in module.used_functions:
        if f is not None:
            take(f)
    for f in list(module.script_functions) + list(module.global_functions):
        take(f)
    for t in list(module.classes) + list(module.used_types):
        for f in (list(getattr(t, "methods", ()) or ())
                  + list(getattr(t, "vft", ()) or ())
                  + list(getattr(t, "constructors", ()) or ())
                  + list(getattr(t, "factories", ()) or ())):
            take(f)
        # A script class is constructible by name. Whatever it declares, the
        # implicit default and copy constructors exist too -- that is the
        # language, not an assumption about this class.
        if getattr(t, "kind", "") == "class" and getattr(t, "name", None):
            out[t.name.split("::")[-1]] |= {(0, 0), (1, 1)}
    for name, signatures in registrations.items():
        if name in callbacks:                        # likewise a funcdef
            continue
        for text in signatures:
            try:
                out[name].add(declaration_arity(text))
            except ValueError:
                continue
    for word in PRIMITIVES:
        out[word].add((1, 1))                        # a cast
    # A funcdef in call position is a delegate construction and takes the one
    # method it binds -- never the arguments its own signature declares.
    for word in callbacks:
        out[word].add((1, 1))
    return out


def sources(project: str) -> List[str]:
    found = []
    for root, _, files in os.walk(project):
        for name in sorted(files):
            if name.endswith(".bgt"):
                found.append(os.path.join(root, name))
    return sorted(found)


def read_scrubbed(paths: Sequence[str]) -> List[Tuple[str, str, str]]:
    """(path, raw, scrubbed) for each file. Scrubbing is the expensive part --
    a character loop over the whole project -- so it happens once."""
    out = []
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        out.append((path, raw, scrub(raw)))
    return out


def script_locals(files: Sequence[Tuple[str, str, str]]) -> Set[str]:
    """Every name the recovered text declares.

    The module does not know about these: the decompiler's own generated
    initialisers, and every local and parameter -- a funcdef-typed one is
    *called*, and its arity is the funcdef's.
    """
    names: Set[str] = set()
    for _, _, text in files:
        for found in DECLARED.finditer(text):
            if found.group(1) not in NOT_A_TYPE:
                names.add(found.group(2))
    return names


def check(project: str, exe: str, module_path: Optional[str] = None,
          module=None) -> Dict[str, object]:
    """Read every call in `project` back against what `exe`'s build declares.

    `bgt recover` passes the module it has already read; everything else
    passes a path and this reads it.
    """
    registrations = bgt_api.registered(exe)
    if module is None:
        module = bgt_asir.load(module_path, exe,
                               opcodes=as_opcodes.extract(exe)["table"])
    known = arities(module, registrations)
    # A registered TYPE used as a call is a constructor or a cast, and its
    # arity is not separable from the binary -- see the module docstring.
    types = bgt_api.registered_types(decls=registrations)
    paths = sources(project)
    files = read_scrubbed(paths)
    local = script_locals(files)

    verdicts: collections.Counter = collections.Counter()
    problems: List[str] = []
    undeclared: collections.Counter = collections.Counter()
    for path, raw, text in files:
        for match in CALL.finditer(text):
            callee = match.group(1)
            where = match.start()
            if callee in KEYWORDS:
                verdicts["keyword"] += 1
                continue
            if ("." not in match.group(0)
                    and is_a_declaration(text, where)):
                verdicts["a declaration, not a call"] += 1
                continue
            if callee not in known:
                if callee in types:
                    verdicts["constructor of a registered type"] += 1
                elif callee in local:
                    verdicts["through a local or parameter"] += 1
                else:
                    verdicts["NOTHING DECLARES IT"] += 1
                    undeclared[callee] += 1
                continue
            split = split_args(text, text.index("(", where))
            if split is None:
                verdicts["unbalanced"] += 1
                continue
            args = split[0]
            if any(low <= len(args) <= high for low, high in known[callee]):
                verdicts["arity ok"] += 1
            else:
                verdicts["ARITY MISMATCH"] += 1
                problems.append(
                    "%s:%d  %s called with %d, declared %s"
                    % (os.path.relpath(path, project),
                       raw[:where].count("\n") + 1, callee, len(args),
                       ", ".join("%d-%d" % a for a in sorted(known[callee]))))
    return {"verdicts": dict(verdicts), "problems": problems,
            "undeclared": dict(undeclared), "files": len(paths),
            "checked": verdicts["arity ok"] + verdicts["ARITY MISMATCH"]}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="bgt apicheck",
        description=__doc__.split("\n")[2],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project", help="a directory `bgt recover` wrote")
    ap.add_argument("executable", help="the game it was recovered from")
    ap.add_argument("--module", help="the module (default: <project>/*_bytecode.bin)")
    ap.add_argument("--quiet", action="store_true", help="only the problems")
    args = ap.parse_args(argv)

    module_path = args.module
    if not module_path:
        for name in sorted(os.listdir(args.project)):
            if name.endswith("_bytecode.bin"):
                module_path = os.path.join(args.project, name)
                break
    if not module_path or not os.path.isfile(module_path):
        print("bgt apicheck: no module -- pass --module", file=sys.stderr)
        return 2

    result = check(args.project, args.executable, module_path)
    if not args.quiet:
        print("%d files, %d calls checked" % (result["files"], result["checked"]))
        for kind, n in sorted(result["verdicts"].items(),      # type: ignore
                              key=lambda kv: -kv[1]):
            print("%8d  %s" % (n, kind))
    for name, n in sorted(result["undeclared"].items(),        # type: ignore
                          key=lambda kv: -kv[1]):
        print("  nothing declares %s (%d call%s)"
              % (name, n, "" if n == 1 else "s"))
    for line in result["problems"]:                            # type: ignore
        print("  " + line)
    return 1 if result["problems"] or result["undeclared"] else 0


if __name__ == "__main__":
    sys.exit(main())
