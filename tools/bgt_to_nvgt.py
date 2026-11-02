"""
bgt_to_nvgt -- turn a recovered BGT project into one NVGT compiles.

    bgt nvgt convert recovered/ -o ported/
    bgt nvgt convert recovered/ -o ported/ --no-compile

The two engines share a language and almost nothing else, so this is a smaller
job than it sounds and a *measurable* one. Converted naively -- rename the
files, repoint the includes, add NVGT's own `bgt_compat.nvgt` -- a whole
5,302-line title came out at **two** compiler errors. That number is the
reason this tool exists in the shape it does: the work is not translating a
language, it is finding the handful of names and shapes that genuinely differ.

## Why this can be honest where the BGT side cannot

`bgt compile` drives a GUI program and puts a modal dialog on somebody's
screen, which is why this document keeps calling a whole-title compile a thing
to spend deliberately. **NVGT's compiler is a console program.** So a
conversion can be compiled on every run, and this reports what the compiler
said rather than what it hopes. A converter that cannot check itself is a
text substitution with ambitions.

## What it will not do

Guess at a semantic difference. Egg Hunt's second error is
`!downloader.get_progress()`, and NVGT's equivalent returns a `float` where
BGT's is used as a truth value -- those are not the same question, and
rewriting it would produce something that compiles and may poll forever.
Renames are applied; differences in *meaning* are reported with the file and
line so a person decides. The rule this whole repository runs on is that
plausible and wrong is the worst outcome available.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

#: Names the two engines spell differently. Each is read off NVGT's own
#: registration rather than guessed, and the comment says where.
RENAMES: Dict[str, str] = {
    # sound.cpp: `bool load_memory(const string&in data)`
    "load_from_memory": "load_memory",
}

#: BGT names `bgt_compat.nvgt` supplies, so a call to one of these is fine
#: even though NVGT's engine has no such registration. Derived from that file
#: at run time rather than listed here -- see `compat_names`.
_COMPAT_FILE = "bgt_compat.nvgt"

#: **The two quoted strings are not adjacent**, which the first real run
#: found: NVGT wraps each one in its own `_O(...)` translation macro --
#:
#:     RegisterObjectMethod(_O("timer"), _O("void restart()"), ...)
#:
#: -- so a pattern demanding `",\s*"` between the type and the declaration
#: matches nothing of the sort, and `timer::restart` was reported as a name
#: NVGT does not have. Every quoted string in the call is read instead, which
#: cannot care how they are wrapped.
_REGISTER = re.compile(
    r"Register(?:Global(?:Function|Property)"
    r"|Object(?:Method|Behaviour|Property))\s*\(")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_NAME_IN_DECL = re.compile(r"([A-Za-z_]\w*)\s*\(")
_SCRIPT_DECL = re.compile(
    r"^\s*(?:[A-Za-z_][\w:]*(?:\s*[@&\[\]]+)?\s+)+([A-Za-z_]\w*)\s*\(", re.M)
_CALL = re.compile(r"(?<!\w)([A-Za-z_]\w*)\s*\(")
_TYPE_BEFORE = re.compile(r"[A-Za-z_][\w:]*(?:\s*[@&\[\]]+)*\s*$")
#: Methods BGT spells with the `get_` accessor prefix and NVGT spells plain,
#: but only ON SOME TYPES -- which is why these cannot go in `RENAMES` and
#: get their own pass. Each was put to NVGT's compiler rather than read off a
#: registration, because a registration says a name exists somewhere and the
#: question is whether it exists HERE:
#:
#:     string[] a;  a.length()      compiles
#:                  a.get_length()  "No matching symbol 'get_length'"
#:     sound s;     s.get_length()  compiles -- `uint64 get_length() property`
#:
#: So a blanket rename would break every sound. The receiver's declared type
#: decides, and the project's own text is where that is written down.
TYPED_RENAMES: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    # name            -> (NVGT's spelling, the receiver types it applies to)
    "get_length": ("length", ("array", "string")),
}

#: Accessor calls that are a plain PROPERTY in NVGT, so the call brackets
#: come off as well as the prefix. Read off NVGT's own registration, which
#: says `RegisterObjectProperty` rather than a getter:
#:
#:     RegisterObjectProperty(_O("network_event"), _O("const uint64 peer_id"))
#:
#: BGT registers the same four as accessors, so a recovered script writes
#: `e.get_peer_id()` and NVGT answers "No matching symbol". Type-guarded for
#: the same reason as `TYPED_RENAMES`: `get_type` is a real method on other
#: things, and renaming it everywhere would break them.
PROPERTY_RENAMES: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "get_type":    ("type",    ("network_event",)),
    "get_peer_id": ("peer_id", ("network_event",)),
    "get_channel": ("channel", ("network_event",)),
    "get_message": ("message", ("network_event",)),
}

#: Differences in MEANING, which are reported with their sites and never
#: rewritten -- a rewrite here would compile and do something else, which
#: this repository treats as the worst outcome available. Each one was read
#: off NVGT's registration beside BGT's.
SEMANTIC: Dict[str, str] = {
    "call":
        "NVGT's `library::call` returns `var@` where BGT's returns "
        "`dictionary@`, so the result cannot be assigned to a "
        "`dictionary@` and is not read with `.get(...)`. Every `dllib.call` "
        "site needs its result handled as a `var@`.",
    "get_progress":
        "NVGT's `downloader::progress` is a `float` where BGT's "
        "`get_progress()` is used as a truth value, so `!d.get_progress()` "
        "is not a test for 'finished' -- written straight across it would "
        "compile and poll forever.",
    "request":
        "NVGT's `network::request` returns a `const network_event@`, so the "
        "handle it is assigned to has to be `const` too.",
}

#: `T name`, `T@ name`, `T[] name`, `T@[] name` -- a declaration, as the
#: recovered text writes one. The type's trailing markers are kept, because
#: they are what says "array".
_DECLARED = re.compile(
    r"^[ \t]*((?:const\s+)?[A-Za-z_][\w:]*(?:\s*[@&]|\s*\[\s*\])*)"
    r"\s+([A-Za-z_]\w*)\s*[;=,)(]", re.M)


def declared_types(scripts: Sequence[Tuple[str, str]]) -> Dict[str, str]:
    """Each name's declared type, where every declaration of it AGREES.

    A name declared one way in one file and another way elsewhere is dropped
    rather than guessed at: renaming on a disagreement is how a correct
    `sound.get_length()` would become a broken `sound.length()`.
    """
    seen: Dict[str, Set[str]] = {}
    for _path, text in scripts:
        for match in _DECLARED.finditer(_scrub(text)):
            kind, name = match.group(1).strip(), match.group(2)
            if name in RESERVED or kind in RESERVED and "[" not in kind:
                continue
            seen.setdefault(name, set()).add(re.sub(r"\s+", "", kind))
    return {name: next(iter(kinds)) for name, kinds in seen.items()
            if len(kinds) == 1}


def _receiver_kind(kind: str) -> str:
    """What a declared type IS, for the purpose of naming a method on it.

    `string[]`, `string[]@` and `weapon@[]` are all arrays; `string` and
    `const string&` are a string; `sound@` is a sound. A handle to a thing
    takes the same methods as the thing, so the markers come off first --
    `string[]@` ends in `@`, not in `]`, which is the whole reason the first
    version of this declined every handle-to-array in the corpus.

    `lstrip("const")` is NOT how a prefix comes off: it strips any of those
    five CHARACTERS, so it turned `string[]@` into `ring[]@`.
    """
    bare = kind.strip()
    if bare.startswith("const"):
        bare = bare[len("const"):].strip()
    bare = bare.rstrip("@& 	")
    if bare.endswith("]"):
        return "array"
    if bare == "string":
        return "string"
    return bare


def nearest_type(text: str, name: str, before: int) -> Optional[str]:
    """`name`'s type from the NEAREST declaration above offset `before`.

    A recovered local is called `local_16` in every function that has one, so
    a project-wide map drops it for disagreeing with itself -- and that is
    right, because the name really does mean a different thing in each body.
    What a reader does instead is look up, and the hoisting in these files
    makes that correct: every local is declared at the top of its own
    function. `bgt signatures` resolves an unsigned comparison the same way
    and for the same reason.
    """
    found: Optional[str] = None
    for match in _DECLARED.finditer(text, 0, before):
        if match.group(2) == name:
            found = re.sub(r"\s+", "", match.group(1).strip())
    return found


def apply_typed_renames(text: str, types: Dict[str, str]) -> Tuple[str, List[str]]:
    """Rename `recv.get_length()` only where `recv`'s type says to."""
    notes: List[str] = []
    scrubbed = _scrub(text)
    for old, (new, kinds) in TYPED_RENAMES.items():
        pattern = re.compile(r"(?<![\w.])([A-Za-z_]\w*)((?:\.[A-Za-z_]\w*|"
                             r"\[[^\[\]]*\])*)\." + re.escape(old) + r"\s*\(")
        done = [0]
        declined = [0]

        def swap(match, old=old, new=new, kinds=kinds, done=done,
                 declined=declined):
            root, middle = match.group(1), match.group(2)
            #: a subscript or a further member makes the value an ELEMENT, so
            #: the declared array type is not what the method is called on
            if "[" in middle or "." in middle:
                declined[0] += 1
                return match.group(0)
            kind = nearest_type(scrubbed, root, match.start()) or types.get(root)
            if kind is None or _receiver_kind(kind) not in kinds:
                declined[0] += 1
                return match.group(0)
            done[0] += 1
            return "%s%s.%s(" % (root, middle, new)

        text = pattern.sub(swap, text)
        if done[0]:
            notes.append("%s -> %s on %d receiver%s of a known type"
                         % (old, new, done[0], "" if done[0] == 1 else "s"))
        if declined[0]:
            notes.append("%s left alone %d time%s: the receiver's type is not "
                         "written down here, and NVGT keeps `%s` on some types"
                         % (old, declined[0], "" if declined[0] == 1 else "s",
                            old))
    #: ...and the accessors that are a PROPERTY there, which lose their
    #: brackets as well as their prefix.
    for old, (new, kinds) in PROPERTY_RENAMES.items():
        pattern = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\."
                             + re.escape(old) + r"\s*\(\s*\)")
        done = [0]

        def swap(match, new=new, kinds=kinds, done=done):
            root = match.group(1)
            kind = nearest_type(scrubbed, root, match.start()) or types.get(root)
            if kind is None or _receiver_kind(kind) not in kinds:
                return match.group(0)
            done[0] += 1
            return "%s.%s" % (root, new)

        text = pattern.sub(swap, text)
        if done[0]:
            notes.append("%s() -> .%s on %d receiver%s: NVGT registers it as "
                         "a property" % (old, new, done[0],
                                         "" if done[0] == 1 else "s"))
    return text, notes


#: A recovered local or parameter. A call through one is a call through a
#: funcdef-typed variable, whose name is this decompiler's own invention, so
#: no engine can be expected to declare it -- `bgt_apicheck` declines the
#: same shape for the same reason.
_FRAME_SLOT = re.compile(r"^(?:local|arg)_?\d+$")

#: words that may sit where a type would and are not one
RESERVED = frozenset("""and or not xor is in out inout return if else while for
do switch case default break continue true false null new delete cast const
void int uint int8 int16 int64 uint8 uint16 uint64 float double bool string
funcdef class enum typedef namespace private protected mixin shared external
abstract final override property interface try catch throw""".split())

#: The primitive TYPE names out of that list. They are reserved -- nothing is
#: called `int` -- but they are also exactly what marks a declaration, so the
#: two purposes have to be told apart: `string serialize(dictionary@ d)` was
#: read as a CALL to `serialize` because `string` sat in one set doing the
#: other set's job.
TYPE_WORDS = frozenset("""void int uint int8 int16 int64 uint8 uint16 uint64
float double bool string""".split())

#: ...so the declaration test asks about the words that may stand where a
#: type would and are NOT one: the word operators and the control keywords.
NOT_A_TYPE = RESERVED - TYPE_WORDS


def engine_names(nvgt_src: str) -> Set[str]:
    """Every name NVGT's own engine registers, read out of its source.

    The source is the authority and it is ordinarily right here: NVGT is open,
    so unlike BGT there is no need to recover an interface from a binary's
    declaration strings. Both global functions and object methods count,
    because a script calls `x.load(...)` and `load(...)` with the same token.
    """
    found: Set[str] = set()
    for root, _dirs, files in os.walk(nvgt_src):
        for name in files:
            if not name.endswith((".cpp", ".h")):
                continue
            try:
                with open(os.path.join(root, name), encoding="utf-8",
                          errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            for match in _REGISTER.finditer(text):
                #: the strings belonging to this one registration. A statement
                #: ends at its `;`, and 600 characters is well past the
                #: longest declaration in NVGT's source.
                tail = text[match.end():match.end() + 600]
                stop = tail.find(";")
                if stop != -1:
                    tail = tail[:stop]
                for quoted in _QUOTED.findall(tail):
                    hit = _NAME_IN_DECL.search(quoted)
                    if hit:
                        found.add(hit.group(1))
                    else:
                        #: a property -- `"const string failures"` -- or the
                        #: owning type's own name, which is a constructor and
                        #: so a legitimate call either way.
                        word = re.findall(r"([A-Za-z_]\w*)", quoted)
                        if word:
                            found.add(word[-1])
    return found


def compat_names(include_dir: str) -> Set[str]:
    """Every name NVGT's `include/*.nvgt` declares, `bgt_compat.nvgt` first.

    These matter as much as the engine's: `string_mid`, `absolute` and the
    whole `screen_reader_*` family are not registered by NVGT at all, they are
    script in that compatibility layer. Counting only the engine would report
    dozens of absences that are not absences.
    """
    found: Set[str] = set()
    if not os.path.isdir(include_dir):
        return found
    for name in os.listdir(include_dir):
        if not name.endswith(".nvgt"):
            continue
        try:
            with open(os.path.join(include_dir, name), encoding="utf-8",
                      errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for match in _SCRIPT_DECL.finditer(text):
            found.add(match.group(1))
        for match in re.finditer(r"^\s*class\s+([A-Za-z_]\w*)", text, re.M):
            found.add(match.group(1))
    return found


def _scrub(text: str) -> str:
    """Blank comments and string literals in ONE left-to-right pass.

    Two regexes in sequence desynchronise, because each construct can contain
    the other's opener -- the lesson `bgt_apicheck` records, where a URL inside
    a string ate the rest of a file.
    """
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"' or c == "'":
            quote = c
            out.append(" ")
            i += 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
                out.append(" ")
            i += 1
            out.append(" ")
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif text.startswith("/*", i):
            while i < n and not text.startswith("*/", i):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def calls_in(text: str) -> List[Tuple[int, str]]:
    """Every call in a script, as (line, name).

    A declaration is not a call -- what separates them is the token before the
    name, which for a declaration is a *type*. Same rule `bgt_apicheck` uses,
    and for the same reason: without it every method a class declares is
    reported as a call to something of that arity.
    """
    scrubbed = _scrub(text)
    out: List[Tuple[int, str]] = []
    for match in _CALL.finditer(scrubbed):
        name = match.group(1)
        if name in RESERVED:
            continue
        before = scrubbed[max(0, match.start() - 80):match.start()]
        stripped = before.rstrip()
        if stripped.endswith("."):
            pass                           # a method call, still a call
        elif _TYPE_BEFORE.search(stripped):
            word = re.findall(r"([A-Za-z_]\w*)", stripped[-40:])
            if word and word[-1] not in NOT_A_TYPE:
                continue                   # a declaration
        out.append((scrubbed.count("\n", 0, match.start()) + 1, name))
    return out

#: Where NVGT usually is. The checkout's `release/` holds the compiler, its
#: `include/` and `bgt_compat.nvgt`; an installed copy has the same shape.
DEFAULT_ROOTS = (
    os.path.join(os.path.expanduser("~"), "Documents", "GitHub", "nvgt",
                 "release"),
    r"C:\nvgt",
    r"C:\Program Files\nvgt",
)


class Nvgt:
    """Where NVGT is, and what it knows.

    `compiler` is the console program -- `nvgt -c script.nvgt` -- which is the
    whole reason this tool can check itself on every run where the BGT side
    cannot. `include` is the script library, `bgt_compat.nvgt` among it, and
    `src` is the engine source when a checkout is at hand, so the registered
    names come from the authority rather than from a list kept here.
    """

    def __init__(self, compiler: str, include: str, src: Optional[str]):
        self.compiler = compiler
        self.include = include
        self.src = src
        self._known: Optional[Set[str]] = None
        self._linked: Optional[Set[str]] = None

    @property
    def known(self) -> Set[str]:
        """Every name a converted script may call without explanation."""
        if self._known is None:
            found = compat_names(self.include)
            if self.src:
                found |= engine_names(self.src)
            self._known = found
        return self._known

    @property
    def linked(self) -> Set[str]:
        """Only the names a converted project really has in scope.

        **Narrower than `known` on purpose, and the two directions are not
        symmetric.** For reporting an ABSENCE a broad set is right: a name
        wrongly held is a gap never reported, so `known` takes every
        `include/*.nvgt`. For reporting a CONFLICT the opposite holds -- a
        conflict wrongly reported is noise -- and a converted project
        includes `bgt_compat.nvgt` and nothing else of NVGT's library. So
        `map`, `focus` and `dynamic_menu` are declared in files nobody
        included and are not conflicts, while `sleep` is an engine
        registration and is one.
        """
        if self._linked is None:
            found: Set[str] = set()
            if self.src:
                found |= engine_names(self.src)
            compat = os.path.join(self.include, _COMPAT_FILE)
            if os.path.isfile(compat):
                with open(compat, encoding="utf-8", errors="replace") as fh:
                    text = _scrub(fh.read())
                for match in _SCRIPT_DECL.finditer(text):
                    found.add(match.group(1))
                for match in re.finditer(r"^\s*class\s+([A-Za-z_]\w*)",
                                         text, re.M):
                    found.add(match.group(1))
            self._linked = found
        return self._linked

    def compile(self, entry: str, timeout: int = 600) -> Tuple[int, str]:
        """`nvgt -c` on one script. Returns (exit code, what it said).

        `-w 1` asks for warnings, because a warning here is free: there is no
        modal dialog to answer and nobody's screen to interrupt.
        """
        try:
            done = subprocess.run(
                [self.compiler, "-c", "-w", "1", os.path.basename(entry)],
                cwd=os.path.dirname(os.path.abspath(entry)),
                capture_output=True, text=True, errors="replace",
                stdin=subprocess.DEVNULL, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 1, "the compiler did not finish within %ds" % timeout
        except OSError as exc:
            return 1, "could not run %s: %s" % (self.compiler, exc)
        return done.returncode, (done.stdout or "") + (done.stderr or "")


def find_nvgt(explicit: Optional[str] = None) -> Optional[Nvgt]:
    """Locate NVGT, or None with nothing guessed.

    A converter that cannot compile its own output is a text substitution
    with ambitions, so this failing is reported rather than worked around.
    """
    roots: List[str] = []
    if explicit:
        roots.append(explicit)
    env = os.environ.get("NVGT_COMPILER")
    if env:
        roots.append(os.path.dirname(env) if env.lower().endswith(".exe") else env)
    roots.extend(DEFAULT_ROOTS)
    found = shutil.which("nvgt")
    if found:
        roots.append(os.path.dirname(found))
    for root in roots:
        if not root:
            continue
        exe = root if os.path.isfile(root) else os.path.join(root, "nvgt.exe")
        if not os.path.isfile(exe):
            continue
        base = os.path.dirname(exe)
        include = os.path.join(base, "include")
        if not os.path.isdir(include):
            continue
        #: the engine source, when this is a checkout: release/ sits beside src/
        src = os.path.join(os.path.dirname(base), "src")
        return Nvgt(exe, include, src if os.path.isdir(src) else None)
    return None


#: `#include "x.bgt"` -- BGT's own spelling, and the converted tree's files
#: are `.nvgt`, so every one has to be repointed. The quote style is either,
#: because a recovered project writes `"` and a hand-written one may not.
_INCLUDE = re.compile(r'(#include\s*)(["<])([^">]+)\.bgt([">])')


def convert_text(text: str, renames: Dict[str, str]) -> Tuple[str, List[str]]:
    """One script's text, converted. Returns (text, what was renamed).

    Only the two mechanical changes are made here: the include extensions,
    and the names the two engines spell differently. A name is replaced on a
    word boundary and only where it is CALLED, so a local or a member that
    happens to share the spelling is left alone.
    """
    notes: List[str] = []
    text = _INCLUDE.sub(lambda m: m.group(1) + m.group(2) + m.group(3)
                        + ".nvgt" + m.group(4), text)
    for old, new in renames.items():
        pattern = re.compile(r"(?<!\w)" + re.escape(old) + r"(\s*\()")
        text, count = pattern.subn(new + r"\1", text)
        if count:
            notes.append("%s -> %s (%d call%s)"
                         % (old, new, count, "" if count == 1 else "s"))
    return text, notes


def convert(project: str, out: str, nvgt: Optional[Nvgt] = None,
            compile_it: bool = True) -> Dict[str, Any]:
    """Convert a recovered BGT project into one NVGT compiles.

    Three mechanical steps and one honest report. The steps: every `.bgt`
    becomes a `.nvgt`, every `#include` is repointed, and the entry script
    gains `#include "bgt_compat.nvgt"` -- which is NVGT's own compatibility
    layer and the reason this is a small job. The report: every name the
    converted text calls that neither NVGT's engine, nor that layer, nor the
    project itself declares.

    Nothing is guessed at. A name that differs in MEANING rather than in
    spelling is reported with its file and line, because rewriting one would
    produce source that compiles and may do the wrong thing -- which this
    repository treats as the worst outcome available.
    """
    project = os.path.abspath(project)
    out = os.path.abspath(out)
    if not os.path.isdir(project):
        raise SystemExit("no such project: %s" % project)
    if os.path.abspath(os.path.join(out, "")) .startswith(
            os.path.abspath(os.path.join(project, ""))):
        raise SystemExit("the output folder is inside the project")

    report: Dict[str, Any] = {"project": project, "out": out, "files": 0,
                              "renames": [], "unknown": [], "entry": None,
                              "compile": None}
    os.makedirs(out, exist_ok=True)
    entry: Optional[str] = None
    scripts: List[Tuple[str, str]] = []           # (written path, text)

    for root, _dirs, files in os.walk(project):
        rel = os.path.relpath(root, project)
        dest_dir = out if rel == "." else os.path.join(out, rel)
        os.makedirs(dest_dir, exist_ok=True)
        for name in sorted(files):
            src = os.path.join(root, name)
            if name.endswith(".bgt"):
                with open(src, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                text, notes = convert_text(text, RENAMES)
                report["renames"].extend("%s: %s" % (name, n) for n in notes)
                dest = os.path.join(dest_dir, name[:-4] + ".nvgt")
                with open(dest, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
                report["files"] += 1
                scripts.append((dest, text))
                #: the entry script is the one at the top that includes others
                if rel == "." and "#include" in text and entry is None:
                    entry = dest
            elif name == "recovery.json":
                continue                   # a report about the BGT project
            else:
                shutil.copy2(src, os.path.join(dest_dir, name))

    #: **The typed renames need the whole project first**, because the
    #: receiver's declaration may be in another file -- a class member used by
    #: a function, which is most of them. So this is a second pass over what
    #: the first one wrote.
    types = declared_types(scripts)
    rewritten: List[Tuple[str, str]] = []
    for path, text in scripts:
        text, notes = apply_typed_renames(text, types)
        if notes:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            report["renames"].extend(
                "%s: %s" % (os.path.basename(path), n) for n in notes)
        rewritten.append((path, text))
    scripts = rewritten

    if entry is None and scripts:
        entry = scripts[0][0]
    report["entry"] = entry

    #: **`bgt_compat.nvgt` is what makes this a small job.** It is NVGT's own
    #: file, supplying `string_mid`, `absolute`, the `screen_reader_*` family
    #: and the rest of BGT's library as script. Added to the entry only, since
    #: `#include` is textual and the project is its files concatenated.
    if entry is not None:
        with open(entry, encoding="utf-8") as fh:
            text = fh.read()
        if _COMPAT_FILE not in text:
            banner = ('// Converted from BGT by `bgt tonvgt`. This include is\n'
                      '// NVGT\'s own BGT compatibility layer, and supplies the\n'
                      '// library functions BGT registered in its engine.\n'
                      '#include "%s"\n\n' % _COMPAT_FILE)
            with open(entry, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(banner + text)
            report["compat"] = _COMPAT_FILE

    #: what the project declares itself -- a call to one of these needs no
    #: engine behind it
    declared: Set[str] = set()
    for _path, text in scripts:
        scrubbed = _scrub(text)
        for match in _SCRIPT_DECL.finditer(scrubbed):
            declared.add(match.group(1))
        for match in re.finditer(r"^\s*class\s+([A-Za-z_]\w*)", scrubbed, re.M):
            declared.add(match.group(1))

    if nvgt is not None:
        known = nvgt.known | declared
        seen: Set[str] = set()
        for path, text in scripts:
            for line, name in calls_in(text):
                if name in known or name in seen:
                    continue
                if _FRAME_SLOT.match(name):
                    continue
                seen.add(name)
                report["unknown"].append(
                    {"name": name, "file": os.path.relpath(path, out),
                     "line": line})
        report["unknown"].sort(key=lambda r: r["name"])

    #: ...and the differences in MEANING, with every site, because a person
    #: decides these and a tool that rewrote them would be guessing.
    report["semantic"] = []
    for path, text in scripts:
        for line, name in calls_in(text):
            if name in SEMANTIC:
                report["semantic"].append(
                    {"name": name, "file": os.path.relpath(path, out),
                     "line": line, "why": SEMANTIC[name]})
    report["semantic"].sort(key=lambda r: (r["name"], r["file"], r["line"]))

    if compile_it and nvgt is not None and entry is not None:
        code, said = nvgt.compile(entry)
        #: **`ERROR:` is the compiler's own marker**, and counting any line
        #: with "error" in it counts the `Compilation error: file: ...`
        #: heading too -- so one real error read as two. A count that
        #: flatters or inflates is the thing this repository keeps paying
        #: for.
        report["compile"] = {
            "exit": code, "output": said.strip(),
            "errors": [l.strip() for l in said.splitlines()
                       if l.strip().startswith(("ERROR:", "WARNING:"))]}
        #: **A name the GAME declares that NVGT already has**, taken from the
        #: compiler rather than from a scan of the text. A scan needs to know
        #: what is in SCOPE, and a static one got that wrong in both
        #: directions at once: it missed Manamon 1's `sleep`, which is the
        #: only error in all 83,371 of its lines, and reported `map` and
        #: `note`, which NVGT declares in files nobody included. The
        #: compiler's own message is exact and complete, so it is read
        #: instead -- which is this repository's first rule, applied one
        #: engine over.
        report["conflicts"] = [
            {"name": m.group(1)} for m in
            re.finditer(r"Name conflict\. '([^']+)' is a global",
                        said)]
    return report


def _wrap(text: str, width: int) -> List[str]:
    """Wrap one sentence to `width`, so a report reads in a terminal."""
    words, lines, line = text.split(), [], ""
    for word in words:
        if line and len(line) + 1 + len(word) > width:
            lines.append(line)
            line = word
        else:
            line = word if not line else line + " " + word
    if line:
        lines.append(line)
    return lines


def summary(report: Dict[str, Any]) -> str:
    """The report, as the lines a person reads."""
    out: List[str] = []
    out.append("%d script(s) converted into %s"
               % (report["files"], report["out"]))
    if report.get("compat"):
        out.append("  %-22s %s" % ("compatibility layer",
                                   "#include \"%s\" added to %s"
                                   % (report["compat"],
                                      os.path.basename(report["entry"] or ""))))
    for note in report["renames"][:12]:
        out.append("  %-22s %s" % ("renamed", note))
    extra = len(report["renames"]) - 12
    if extra > 0:
        out.append("  %-22s ...and %d more" % ("", extra))
    conflicts = report.get("conflicts") or []
    if conflicts:
        out.append("  %-22s %d name(s) this game declares that NVGT already"
                   % ("rename these yourself", len(conflicts)))
        out.append("  %-22s has. The cure is a project-wide rename, which is"
                   % "")
        out.append("  %-22s yours to judge: a class name reaches into string"
                   % "")
        out.append("  %-22s literals and saved data too." % "")
        for row in conflicts[:8]:
            out.append("      %s" % row["name"])
        if len(conflicts) > 8:
            out.append("      ...and %d more" % (len(conflicts) - 8))
    semantic = report.get("semantic") or []
    if semantic:
        kinds: Dict[str, int] = {}
        for row in semantic:
            kinds[row["name"]] = kinds.get(row["name"], 0) + 1
        out.append("  %-22s %d site(s) whose MEANING differs, not spelling:"
                   % ("read these by hand", len(semantic)))
        for name, count in sorted(kinds.items()):
            first = next(r for r in semantic if r["name"] == name)
            out.append("      %s  (%d site%s, first %s:%d)"
                       % (name, count, "" if count == 1 else "s",
                          first["file"], first["line"]))
            for chunk in _wrap(SEMANTIC[name], 66):
                out.append("          %s" % chunk)
    unknown = report["unknown"]
    if unknown:
        out.append("  %-22s %d name(s) nothing here declares -- a difference in"
                   % ("to decide by hand", len(unknown)))
        out.append("  %-22s MEANING is not renamed, it is reported:" % "")
        for row in unknown[:10]:
            out.append("      %-28s %s:%d" % (row["name"], row["file"],
                                              row["line"]))
        if len(unknown) > 10:
            out.append("      ...and %d more" % (len(unknown) - 10))
    done = report.get("compile")
    if done is None:
        out.append("  %-22s not run" % "nvgt -c")
    elif done["exit"] == 0:
        out.append("  %-22s compiled cleanly" % "nvgt -c")
    else:
        errors = done["errors"]
        out.append("  %-22s %d error line(s), exit %d"
                   % ("nvgt -c", len(errors), done["exit"]))
        for line in errors[:8]:
            out.append("      %s" % line)
    return "\n".join(out)


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="bgt tonvgt",
        description="turn a recovered BGT project into one NVGT compiles")
    parser.add_argument("project", help="a directory of recovered .bgt files")
    parser.add_argument("-o", "--output", required=True,
                        help="where to write the converted project")
    parser.add_argument("--nvgt", metavar="PATH",
                        help="nvgt.exe, or the folder holding it "
                             "(else NVGT_COMPILER, else the usual places)")
    parser.add_argument("--no-compile", action="store_true",
                        help="convert without asking the compiler, which is "
                             "the one check this tool can make for free")
    parser.add_argument("--json", metavar="FILE", help="write the report")
    args = parser.parse_args(argv)

    nvgt = find_nvgt(args.nvgt)
    if nvgt is None:
        print("NVGT was not found, so neither its registered names nor its\n"
              "compiler can be consulted: converting anyway, and reporting\n"
              "only what can be known without them. Pass --nvgt or set\n"
              "NVGT_COMPILER to get the check this tool is for.")
    report = convert(args.project, args.output, nvgt,
                     compile_it=not args.no_compile)
    print(summary(report))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=1)
        print("  %-22s %s" % ("report", args.json))
    done = report.get("compile")
    return 0 if (done is None or done["exit"] == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
