"""
script_files -- which source files a compiled module was built from.

    bgt files work/strike_bytecode.bin strike.exe          # BGT: module + exe (opcode table)
    bgt files game.exe                                      # NVGT: executable or module
    bgt files module.bin --nvgt --include C:/nvgt/include --json files.json

## What a module keeps, and what it does not

A script's file names live in AngelScript's debug information: every function's
script section. BGT always compiles with `noDebugInfo = 1`, and NVGT strips it
from release builds (`SaveByteCode(stream, !g_debug)`), so in anything shipped
the names are simply gone -- not hidden, not encrypted. An NVGT *debug* build
keeps them, and `bgt nvgt recover` already uses them.

Two things survive stripping, and together they recover most of the structure:

**Order.** The builder processes script sections one after another, so
declarations come out of the module grouped by file, in two passes (types, and
global functions), each walking the files in the same order. Checked on
NVGT debug builds, where the true file of every function is known: every file
is one contiguous run per pass. A change of file along that order is therefore
a real file boundary. The converse does not hold -- two of the game's own files
side by side look like one -- so this recovers *where files split*, never how
many unnamed files a run holds.

**Known sources.** BGT and NVGT ship their standard library as source
(`include/*.bgt`, `include/*.nvgt`). A run that declares what one of those files
declares is that file, and it gets its real name. That also anchors the game's
own code: whatever lies between two library files is the game's.

## How a match is decided

A name is not enough -- a game may well have its own `menu` class. A class is
attributed to a library file only when their METHOD names agree (at least half
of the source's methods present, and at least half of the module's methods in
the source), and a file counts as included only when most of what it declares
is present AND it explains at least one declaration no other file does. A
partially matching file is reported as a candidate, not claimed.

Scored against NVGT debug builds, where every declaration's true file is known:
439 / 439 across the 26 modules of the library corpus.
Library code a game edited still matches by declaration; `bgt libcheck` then
says whether the bodies are the shipped ones.
"""

import argparse
import collections
import glob
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

try:                      # installed as a package
    from . import bgt_libcheck
except ImportError:       # run directly from a checkout
    import bgt_libcheck

GAME = None               # attribution of a declaration no library file claims

DEFAULT_NVGT_INCLUDE_DIRS = (r"C:\nvgt\include", r"C:\Program Files\nvgt\include")

# A file is "included" when at least this share of its declarations is present.
INCLUDED_COVERAGE = 0.6
# A class matches a library class when both directions of method overlap reach this.
METHOD_AGREEMENT = 0.5


# --------------------------------------------------------------------------
# library sources
# --------------------------------------------------------------------------

@dataclass
class SourceFile:
    """What one library source file declares at namespace level."""
    name: str
    classes: Dict[str, Set[str]] = field(default_factory=dict)   # class -> method names
    functions: Set[str] = field(default_factory=set)
    enums: Set[str] = field(default_factory=set)
    globals: Set[str] = field(default_factory=set)      # global variables
    includes: List[str] = field(default_factory=list)   # base names, in order

    def declarations(self) -> int:
        return len(self.classes) + len(self.functions) + len(self.enums) + len(self.globals)


_CLASS = re.compile(r"(?:(?:shared|final|abstract|external|mixin)\s+)*"
                    r"(class|interface)\s+([A-Za-z_]\w*)[^{;]*\{")
_ENUM = re.compile(r"(?:(?:shared|external)\s+)*enum\s+([A-Za-z_]\w*)[^{;]*\{")
_NAMESPACE = re.compile(r"namespace\s+([A-Za-z_][\w:]*)\s*\{")
_INCLUDE = re.compile(r'#\s*include\s*"([^"]+)"')      # `#include"form.nvgt"` occurs
_FUNC = re.compile(r"(?:[A-Za-z_][\w@\[\]<>&:,\s]*?[\s@&>\]])?(~?[A-Za-z_]\w*)\s*"
                   r"\(([^;{}()]*(?:\([^;{}()]*\)[^;{}()]*)*)\)\s*"
                   r"((?:const|override|final|explicit|property|\s)*)\{")
_DECLARATOR = re.compile(r"^\s*([A-Za-z_]\w*)\s*$")
# `type name`, where type may be qualified, templated, a handle, an array, const
_FIRST_DECLARATION = re.compile(
    r"^\s*(?:const\s+)?[A-Za-z_][\w:]*(?:\s*<[^;]*>)?(?:\s*\[\s*\])*\s*[@&]?\s*"
    r"(?<=[\s@&>\]])([A-Za-z_]\w*)\s*$")
_NOT_VARIABLES = re.compile(r"\s*(?:funcdef|typedef|import|class|interface|enum|mixin|"
                            r"shared|external|using|return|namespace)\b")
_NOT_FUNCTIONS = frozenset(("if", "while", "for", "switch", "return", "catch", "else",
                            "do", "cast", "try", "funcdef", "namespace", "class",
                            "interface", "enum", "import"))


def _skip_block(src: str, i: int) -> int:
    """Index just past the `}` matching the `{` at src[i - 1]."""
    depth = 1
    while i < len(src) and depth:
        c = src[i]
        if c == '"' or c == "'":
            quote, i = c, i + 1
            while i < len(src) and src[i] != quote:
                i += 2 if src[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return i


def _variable_names(statement: str) -> List[str]:
    """Names a namespace-level `type a = 1, b;` declares; [] for anything else.

    Split at top-level commas (not inside brackets or string literals), cut
    each part at `=` or `(` (a constructor call). The first part must be
    `type name`; each later one a bare name."""
    if _NOT_VARIABLES.match(statement):
        return []
    parts, depth, start, k = [], 0, 0, 0
    while k < len(statement):
        c = statement[k]
        if c in "\"'":
            quote, k = c, k + 1
            while k < len(statement) and statement[k] != quote:
                k += 2 if statement[k] == "\\" else 1
        elif c in "(<[{":
            depth += 1
        elif c in ")>]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(statement[start:k])
            start = k + 1
        k += 1
    parts.append(statement[start:])
    heads = [re.split(r"[=(]", part, maxsplit=1)[0] for part in parts]
    first = _FIRST_DECLARATION.match(heads[0])
    if not first:
        return []
    names = [first.group(1)]
    for head in heads[1:]:
        m = _DECLARATOR.match(head)
        if not m:
            return []
        names.append(m.group(1))
    return names


def scan_source(text: str, name: str = "") -> SourceFile:
    """Declarations at namespace level: classes with their methods, free
    functions, enums, named `ns::name` inside a namespace -- as the module
    names them. A small scanner, not a parser: it has to find heads and skip
    bodies, nothing more."""
    src = bgt_libcheck.strip_comments(text)
    out = SourceFile(name)
    out.includes = [os.path.basename(m.group(1).replace("\\", "/"))
                    for m in _INCLUDE.finditer(src)]

    def scope(i: int, end: int, owner: Optional[str], ns: str = "") -> None:
        def q(name: str) -> str:
            return ns + "::" + name if ns else name

        while i < end:
            c = src[i]
            if c in "\"'":
                quote, i = c, i + 1
                while i < end and src[i] != quote:
                    i += 2 if src[i] == "\\" else 1
                i += 1
                continue
            if c == "}" or c.isspace() or c == ";":
                i += 1
                continue
            if c == "#":                                 # preprocessor line
                j = src.find("\n", i)
                i = end if j < 0 else j + 1
                continue
            m = _NAMESPACE.match(src, i) if owner is None else None
            if m:
                close = _skip_block(src, m.end())
                scope(m.end(), close - 1, None, q(m.group(1)))
                i = close
                continue
            m = _CLASS.match(src, i) if owner is None else None
            if m:
                out.classes.setdefault(q(m.group(2)), set())
                close = _skip_block(src, m.end())
                scope(m.end(), close - 1, q(m.group(2)))
                i = close
                continue
            m = _ENUM.match(src, i) if owner is None else None
            if m:
                out.enums.add(q(m.group(1)))
                i = _skip_block(src, m.end())
                continue
            m = _FUNC.match(src, i)
            if m and m.group(1) not in _NOT_FUNCTIONS:
                fname = m.group(1)
                short = owner.rpartition("::")[2] if owner else ""
                if owner is None:
                    out.functions.add(q(fname))
                elif fname not in (short, "~" + short):  # constructors, destructors
                    out.classes[owner].add(fname)
                i = _skip_block(src, m.end())
                continue
            # anything else -- a property, a funcdef, a global variable with
            # an initialiser block -- skip to the end of its statement
            j = i
            while j < end and src[j] not in ";{":
                j += 1
            if owner is None and j < end and src[j] == ";":
                out.globals.update(q(n) for n in _variable_names(src[i:j]))
            i = _skip_block(src, j + 1) if j < end and src[j] == "{" else j + 1
    scope(0, len(src), None)
    return out


def library_index(include_dirs: Sequence[str], extensions=("*.bgt", "*.nvgt")) -> List[SourceFile]:
    files = []
    for folder in include_dirs:
        for pattern in extensions:
            for path in sorted(glob.glob(os.path.join(folder, pattern))):
                with open(path, encoding="latin1") as fh:
                    files.append(scan_source(fh.read(), os.path.basename(path)))
    return files


# --------------------------------------------------------------------------
# module declarations, in module order
# --------------------------------------------------------------------------

@dataclass
class Entity:
    kind: str                         # "class" | "function" | "enum" | "global"
    name: str
    members: Set[str] = field(default_factory=set)   # method names, for classes
    truth: Optional[str] = None       # the real file, when debug info says
    # For a compiler-made function -- an NVGT lambda -- the declaration whose
    # body creates it, as (kind, name). Lambdas are compiled after everything
    # declared, so their position says nothing; their creator's file is theirs.
    container: Optional[Tuple[str, str]] = None


def bgt_entities(mod) -> List[Entity]:
    """Declarations of a BGT module (an `as_disasm.Module`), in module order.

    Function records come class by class and then global function by global
    function. A factory is recorded as a global function named after its
    class; it belongs to the class.
    """
    try:
        from . import as_disasm
    except ImportError:
        import as_disasm
    classes = set(mod.script_classes)
    out: List[Entity] = []
    index: Dict[str, Entity] = {}
    for f in mod.functions:
        label = as_disasm.function_label(f)
        owner, _, name = label.rpartition("::")
        if owner != "<global>":
            entity = index.get(owner)
            if entity is None:
                entity = index[owner] = Entity("class", owner)
                out.append(entity)
            if name not in (owner.rpartition("::")[2], "~" + owner.rpartition("::")[2]):
                entity.members.add(name)
        elif name in classes:
            continue
        else:
            # A namespaced function is `ns::name`, so a game's namespaced copy
            # of library code (Manamon 2's `rhythm::position_sound_1d`) is not
            # mistaken for the library's own.
            ns = f.get("namespace") or ""
            qualified = ns + "::" + name if ns else name
            if not any(e.kind == "function" and e.name == qualified for e in out[-1:]):
                out.append(Entity("function", qualified))  # overloads collapse
    for enum in mod.info.get("enums", []):
        out.append(Entity("enum", enum["name"] if isinstance(enum, dict) else str(enum)))
    for g in (mod.tail or {}).get("global_properties", []):
        ns = g.get("namespace") or ""
        out.append(Entity("global", ns + "::" + g["name"] if ns else g["name"]))
    return out


def nvgt_entities(module) -> List[Entity]:
    """Declarations of an NVGT module (`nvgt.asreader.Module`), in module order.

    Global functions first, then classes -- the two passes the builder makes.
    In a debug build each entity carries the file it really came from.
    """
    def base(path: str) -> Optional[str]:
        return os.path.basename(path.replace("\\", "/")) if path else None

    classes = {c.name for c in module.classes}
    creators: Dict[str, Tuple[str, str]] = {}
    def qualified(x) -> str:
        return x.namespace_ + "::" + x.name if x.namespace_ else x.name

    bodies_by_owner = [(("function", qualified(f)), f) for f in module.script_functions
                       if f is not None and f.object_type is None]
    bodies_by_owner += [(("class", qualified(c)), f) for c in module.classes
                        for f in c.methods + c.vft + c.constructors + c.factories]
    for owner, f in bodies_by_owner:
        for ins in f.bytecode:
            ref = getattr(ins, "func_ref", None)
            if ins.name == "FuncPtr" and ref is not None and ref.name.startswith("__nvgt_lambda_"):
                creators.setdefault(ref.name, owner)
    out: List[Entity] = []
    for f in module.script_functions:
        if f is None or f.object_type is not None or f.name in classes:
            continue
        name = f.namespace_ + "::" + f.name if f.namespace_ else f.name
        if out and out[-1].kind == "function" and out[-1].name == name:
            continue                                      # overloads collapse
        out.append(Entity("function", name, truth=base(f.script_section),
                          container=creators.get(f.name)))
    for c in module.classes:
        if getattr(c, "kind", "") == "enum" or c.enum_values:
            continue
        bodies = [m for m in (c.methods + c.constructors + c.factories) if m.script_section]
        # `methods` lists inherited methods too, under their base class. The
        # class's OWN methods -- what its source declares -- are the entries
        # it owns; comparing the full list failed every derived class.
        own = {m.name for m in c.methods + c.vft
               if m.object_type is not None and m.object_type.name == c.name}
        members = own or {m.name for m in c.methods}
        out.append(Entity("class", c.namespace_ + "::" + c.name if c.namespace_ else c.name,
                          members - {c.name, "~" + c.name},
                          truth=base(bodies[0].script_section) if bodies else None))
    for e in module.enums:
        out.append(Entity("enum", e.namespace_ + "::" + e.name if e.namespace_ else e.name))
    for g in module.globals:
        out.append(Entity("global", g.namespace_ + "::" + g.name if g.namespace_ else g.name))
    return out


# --------------------------------------------------------------------------
# attribution
# --------------------------------------------------------------------------

def class_agreement(module_methods: Set[str], source_methods: Set[str]) -> float:
    """How well a module class's own methods match a source class's: the
    smaller of the two overlap ratios, so a match has to hold both ways."""
    if not source_methods and not module_methods:
        return 1.0
    if not source_methods or not module_methods:
        return 0.0
    shared = len(module_methods & source_methods)
    return min(shared / len(source_methods), shared / len(module_methods))


@dataclass
class Attribution:
    entities: List[Entity]
    owner: List[Optional[str]]                 # a library file name, or GAME
    included: List[Tuple[str, int, int]]       # (file, matched, declared)
    candidates: List[Tuple[str, int, int]]     # partial matches, not claimed

    def runs(self, kind_filter: Optional[Set[str]] = None) -> List[Tuple[Optional[str], List[Entity]]]:
        """Consecutive entities with one owner, in module order."""
        out: List[Tuple[Optional[str], List[Entity]]] = []
        for e, o in zip(self.entities, self.owner):
            if (kind_filter and e.kind not in kind_filter) or e.container:
                continue                    # a lambda's position is not its file's
            if out and out[-1][0] == o:
                out[-1][1].append(e)
            else:
                out.append((o, [e]))
        return out

    def accuracy(self) -> Optional[Tuple[int, int]]:
        """(right, known) against debug information, when the module has it.
        A game file is right when attributed to no library file."""
        library = {f for f, _, _ in self.included} | {f for f, _, _ in self.candidates}
        known = [(e, o) for e, o in zip(self.entities, self.owner) if e.truth]
        if not known:
            return None
        right = sum(1 for e, o in known
                    if o == e.truth or (o is GAME and e.truth not in library))
        return right, len(known)


def _fill_enclosed(entities: List[Entity], owner: List[Optional[str]]) -> None:
    """Unclaimed declarations with ONE library file on both sides are that file's.

    Files are contiguous in each pass, so nothing from another file can sit in
    the middle of one. This is what attributes what no name can: compiler-made
    lambdas (`__nvgt_lambda_...`), and declarations the source scanner missed.
    """
    for kinds in ({"class"}, {"function"}, {"enum"}, {"global"}):
        idx = [i for i, e in enumerate(entities) if e.kind in kinds and not e.container]
        k = 0
        while k < len(idx):
            if owner[idx[k]] is not GAME:
                k += 1
                continue
            j = k
            while j < len(idx) and owner[idx[j]] is GAME:
                j += 1
            before = owner[idx[k - 1]] if k > 0 else GAME
            after = owner[idx[j]] if j < len(idx) else GAME
            if before is not GAME and before == after:
                for m in idx[k:j]:
                    owner[m] = before
            k = j


def attribute(entities: List[Entity], library: List[SourceFile]) -> Attribution:
    # 1. every declaration a library file could own, method agreement included
    matches: List[Set[str]] = []
    for e in entities:
        found = set()
        if e.kind == "class":
            # Two files can declare the same class -- NVGT ships sound_pool
            # and legacy_sound_pool. The one whose methods agree best wins.
            scores = {f.name: class_agreement(e.members, f.classes[e.name])
                      for f in library if e.name in f.classes}
            best = max(scores.values(), default=0.0)
            if best >= METHOD_AGREEMENT:
                found = {n for n, s in scores.items() if s == best}
        elif e.kind == "function":
            found = {f.name for f in library if e.name in f.functions}
        elif e.kind == "enum":
            found = {f.name for f in library if e.name in f.enums}
        elif e.kind == "global":
            found = {f.name for f in library if e.name in f.globals}
        matches.append(found)

    # 2. a file is included when most of what it declares is present
    # distinct names: a game may carry a second copy of library code
    matched = collections.Counter(
        name for name, _ in {(n, (e.kind, e.name)) for e, found in zip(entities, matches)
                             for n in found})
    by_name = {f.name: f for f in library}
    included, candidates = [], []
    for name, count in matched.items():
        declared = by_name[name].declarations()
        row = (name, count, declared)
        (included if declared and count / declared >= INCLUDED_COVERAGE else candidates).append(row)
    # ...and explains at least one declaration no other candidate does. A file
    # whose every match another file explains as well is no evidence of its
    # own: NVGT's legacy_sound_pool shares sound_pool's globals and helpers,
    # and those alone cleared the coverage bar.
    exclusive = collections.Counter(next(iter(found)) for found in matches if len(found) == 1)
    for row in [r for r in included if not exclusive[r[0]]]:
        included.remove(row)
        candidates.append(row)
    included_names = {name for name, _, _ in included}

    # 3. each declaration to one included file; ties go to a neighbour's file
    owner: List[Optional[str]] = []
    for i, found in enumerate(matches):
        found = found & included_names
        if len(found) > 1:
            near = [o for o in owner[-1:]] + [next(iter(m & included_names))
                                               for m in matches[i + 1:i + 2]
                                               if len(m & included_names) == 1]
            found = {o for o in near if o in found} or found
        owner.append(sorted(found)[0] if found else GAME)
    _fill_enclosed(entities, owner)
    where = {(e.kind, e.name): o for e, o in zip(entities, owner)}
    for i, e in enumerate(entities):
        if e.container and e.container in where:
            owner[i] = where[e.container]
    included.sort(key=lambda r: min((i for i, o in enumerate(owner) if o == r[0]), default=0))
    candidates.sort()
    return Attribution(entities, owner, included, candidates)


# --------------------------------------------------------------------------
# one file order out of two passes
# --------------------------------------------------------------------------

@dataclass
class Segment:
    """One stretch of the recovered file order."""
    file: Optional[str]                  # a library file, or GAME
    classes: List[Entity] = field(default_factory=list)
    functions: List[Entity] = field(default_factory=list)
    note: str = ""


def file_order(a: Attribution, library: List[SourceFile]) -> Tuple[List[Segment], List[str]]:
    """Merge the type pass and the function pass into one file order.

    Both passes walk the files in the same order, but each only shows the
    files that declare something of its kind: a library file of nothing but
    functions is invisible among the types. The library files are anchors seen
    in one pass or both; the game's runs are then placed between the anchors
    their own pass shows around them.

    A file seen in only one pass is placed after the library file that
    `#include`s it when there is one (includes are processed depth first, so
    it follows its includer), else by its neighbours in its own pass. Returns
    the segments and any problems -- two passes that disagree about the order
    of files they both show are reported, never forced together.
    """
    problems: List[str] = []
    passes = [a.runs({"class"}), a.runs({"function"})]
    sequences = [[o for o, _ in runs if o is not GAME] for runs in passes]
    shared = [f for f in sequences[0] if f in sequences[1]]
    if shared != [f for f in sequences[1] if f in sequences[0]]:
        problems.append("the two passes order the library files differently: %s vs %s"
                        % (shared, [f for f in sequences[1] if f in sequences[0]]))
    # Several files can include one file (form.nvgt comes in through
    # input_forms, menu and virtual_dialogs alike): keep every includer.
    includes = {f.name: set(f.includes) for f in library}

    def includes_directly(parent: Optional[str], child: str) -> bool:
        return parent is not None and child in includes.get(parent, ())

    merged = list(sequences[0])
    notes: Dict[str, str] = {}
    for k, f in enumerate(sequences[1]):
        if f in merged:
            continue
        # Its own pass bounds it first: after its predecessor there, before its
        # successor. That is direct evidence and always wins -- NVGT's speech
        # and form include each other, and the function pass shows speech
        # first whichever the include graph would suggest.
        prev = next((x for x in reversed(sequences[1][:k]) if x in merged), None)
        nxt = next((x for x in sequences[1][k + 1:] if x in merged), None)
        lo = merged.index(prev) + 1 if prev else 0
        hi = merged.index(nxt) if nxt else len(merged)
        at = lo
        if hi > lo:
            # Several places fit. A file that includes it settles which:
            # includes are processed straight after their includer.
            parent = next((x for x in merged[max(lo - 1, 0):hi] if includes_directly(x, f)), None)
            if parent is not None:
                at = merged.index(parent) + 1
                while at < hi and includes_directly(parent, merged[at]):
                    at += 1                    # after earlier siblings
                notes[f] = "included by %s" % parent
            else:
                notes[f] = "position among %s uncertain" % merged[lo:hi]
        merged.insert(at, f)

    # gap g is the stretch after merged[g - 1]; gap 0 precedes every anchor
    segments: Dict[int, Segment] = {g: Segment(GAME) for g in range(len(merged) + 1)}
    for kind, runs in (("classes", passes[0]), ("functions", passes[1])):
        anchors = [o for o, _ in runs if o is not GAME]
        seen = 0
        for owner, entities in runs:
            if owner is not GAME:
                seen += 1
                continue
            first = merged.index(anchors[seen - 1]) + 1 if seen else 0
            last = merged.index(anchors[seen]) if seen < len(anchors) else len(merged)
            # A gap straight after an includer and before what it includes
            # holds nothing: the included file is processed immediately.
            possible = [g for g in range(first, last + 1)
                        if not (0 < g < len(merged) and includes_directly(merged[g - 1], merged[g]))]
            target = segments[possible[0] if possible else first]
            getattr(target, kind).extend(entities)
            if len(possible) > 1:
                end = "the end" if possible[-1] == len(merged) else merged[possible[-1]]
                target.note = ("these %s lie somewhere from here to %s; the pass that "
                               "holds them shows no file boundary in between" % (kind, end))
    out: List[Segment] = []
    for g in range(len(merged) + 1):
        if segments[g].classes or segments[g].functions:
            out.append(segments[g])
        if g < len(merged):
            out.append(Segment(merged[g], note=notes.get(merged[g], "")))
    return out, problems


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def top_level_includes(a: Attribution, library: List[SourceFile]) -> List[str]:
    """The included library files the game's own code must `#include` itself.

    A file is nested when a file EARLIER in the recovered order includes it --
    includes are processed after their includer. Earlier, not any: NVGT's
    form.nvgt and speech.nvgt include each other, and "included by another
    included file" then made neither of them top level.
    """
    names = [n for n, _, _ in a.included]
    order = [s.file for s in file_order(a, library)[0] if s.file in names]
    order += [n for n in names if n not in order]
    includes = {f.name: set(f.includes) for f in library}
    return [f for i, f in enumerate(order)
            if not any(f in includes.get(g, ()) for g in order[:i])]


def _names(entities: List[Entity], limit: int = 6) -> str:
    names = [e.name for e in entities]
    shown = ", ".join(names[:limit])
    return shown + (", ... (%d)" % len(names) if len(names) > limit else "")


def report(a: Attribution, library: Optional[List[SourceFile]] = None) -> str:
    lines = []
    if a.included:
        lines.append("library files this module was built with (declarations matched):")
        for name, count, declared in a.included:
            lines.append("  %-28s %d / %d" % (name, count, declared))
    else:
        lines.append("no shipped library file matched")
    if a.candidates:
        lines.append("partial matches, not claimed (a game class sharing a library name, "
                     "or a heavily edited copy):")
        for name, count, declared in a.candidates:
            lines.append("  %-28s %d / %d" % (name, count, declared))
    lines.append("")
    lines.append("file layout, in declaration order -- every change of owner is a real "
                 "file boundary; one game run may still hold several files:")
    for title, kinds in (("types", {"class"}), ("global functions", {"function"}),
                         ("global variables (order within the module; not used to place files)",
                          {"global"})):
        runs = a.runs(kinds)
        if not runs:
            continue
        lines.append("  %s:" % title)
        game = 0
        for owner, entities in runs:
            if owner is GAME:
                game += 1
                lines.append("    [game code %d]  %s" % (game, _names(entities)))
            else:
                lines.append("    %-16s %s" % (owner, _names(entities)))
    if library is not None:
        segments, problems = file_order(a, library)
        lines.append("")
        lines.append("recovered file order (both passes merged):")
        game = 0
        for s in segments:
            if s.file is GAME:
                game += 1
                has_main = any(e.name == "main" for e in s.functions)
                lines.append("  [game code %d]%s" % (game, "  -- declares main()" if has_main else ""))
                if s.classes:
                    lines.append("      classes    %s" % _names(s.classes))
                if s.functions:
                    lines.append("      functions  %s" % _names(s.functions))
                if s.note:
                    lines.append("      (%s)" % s.note)
            else:
                lines.append("  %s%s" % (s.file, "   (%s)" % s.note if s.note else ""))
        for problem in problems:
            lines.append("  ! " + problem)
    acc = a.accuracy()
    if acc:
        lines.append("")
        lines.append("checked against this module's debug information: %d / %d "
                     "declarations attributed correctly" % acc)
    if a.included:
        lines.append("")
        lines.append("as source (top-level includes; the rest come in through these):")
        lines.extend('  #include "%s"' % name for name in top_level_includes(a, library or []))
    return "\n".join(lines)


def as_json(a: Attribution) -> dict:
    return {
        "included": [{"file": n, "matched": c, "declared": d} for n, c, d in a.included],
        "candidates": [{"file": n, "matched": c, "declared": d} for n, c, d in a.candidates],
        "declarations": [{"kind": e.kind, "name": e.name, "file": o, "debug_file": e.truth}
                         for e, o in zip(a.entities, a.owner)],
        "accuracy": a.accuracy(),
    }


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------

def _is_nvgt(path: str) -> bool:
    try:
        from . import engine
    except ImportError:
        import engine
    try:
        return engine.identify(path).engine == engine.NVGT
    except Exception:                                    # noqa: BLE001 -- not decisive
        return False


def load_entities(module: str, exe: Optional[str], nvgt: bool,
                  opcodes: Optional[str] = None) -> Tuple[List[Entity], str]:
    if nvgt:
        try:
            from .nvgt import decompile as nvgt_decompile
        except ImportError:
            from nvgt import decompile as nvgt_decompile
        return nvgt_entities(nvgt_decompile.load_any(module)), "nvgt"
    try:
        from . import as_disasm
    except ImportError:
        import as_disasm
    return bgt_entities(as_disasm.load(module, exe, opcodes)), "bgt"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="bgt files", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("module", help="BGT bytecode (from bgt unpack), or an NVGT game / module")
    ap.add_argument("exe", nargs="?", help="BGT: the game exe, for its opcode table")
    ap.add_argument("--opcodes", help="BGT: opcode table JSON instead of the exe")
    ap.add_argument("--nvgt", action="store_true",
                    help="read the module as NVGT (automatic for an NVGT executable)")
    ap.add_argument("--include", action="append",
                    help="library source folder (default: the usual BGT / NVGT install); repeatable")
    ap.add_argument("--json", metavar="FILE", help="also write the attribution as JSON")
    args = ap.parse_args(argv)

    nvgt = args.nvgt or (not args.exe and not args.opcodes) or _is_nvgt(args.module)
    if not nvgt and not (args.exe or args.opcodes):
        print("bgt files: a BGT module needs its exe (or --opcodes)", file=sys.stderr)
        return 2
    dirs = args.include or [d for d in (list(DEFAULT_NVGT_INCLUDE_DIRS) if nvgt else
                                        list(bgt_libcheck.DEFAULT_INCLUDE_DIRS))
                            if os.path.isdir(d)]
    if nvgt and not args.include and os.environ.get("NVGT_INCLUDE"):
        dirs = [os.environ["NVGT_INCLUDE"]]
    dirs = [d for d in dirs if os.path.isdir(d)]
    if not dirs:
        print("bgt files: no library source folder found -- pass --include <dir>",
              file=sys.stderr)
        return 2
    entities, engine_name = load_entities(args.module, args.exe, nvgt, args.opcodes)
    library = library_index(dirs, ("*.nvgt",) if nvgt else ("*.bgt",))
    result = attribute(entities, library)
    print("%s module, %d declarations; library sources from %s\n"
          % (engine_name.upper(), len(entities), ", ".join(dirs)))
    print(report(result, library))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(as_json(result), fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
