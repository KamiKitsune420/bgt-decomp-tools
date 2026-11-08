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

try:                      # installed as a package
    from .nvgt import nvgt_compiler
except ImportError:       # run directly from a checkout
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.join(
        _os.path.dirname(_os.path.abspath(__file__)), "nvgt"))
    import nvgt_compiler

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
    #: **`http::get_progress` is a RENAME, not a difference in meaning**, and
    #: this file listed it as the latter for as long as nobody read both
    #: registrations side by side:
    #:
    #:     BGT   bool  http::get_progress() const
    #:     NVGT  float http::get_progress() property
    #:     NVGT  bool  http::get_running()  property
    #:
    #: BGT's answers "is it still going?" -- which is what the loop that uses
    #: it says, `while (!h.get_progress()) break; s += h.request();` -- and
    #: NVGT spells that `running`, reserving `progress` for the fraction.
    #: `is_running()` behind it is `worker.isRunning()`, read out of NVGT's
    #: own source, so the two are the same question.
    #:
    #: The type is `http` in BOTH engines, so nothing else has to move: NVGT
    #: registers these methods on `"http"`, and `request()` returns a `string`
    #: there as it does here.
    "get_progress": ("get_running", ("http",)),
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
    "get_file":
        ("`pack_file::get_file` returns a `file@` in BGT and a `datastream@` "
        "in NVGT, so a local that holds either a real file or a pack entry "
        "cannot be declared the same way in both. A `cast<file@>` compiles "
        "and returns NULL on a pack entry at run time, so it is not done "
        "here: declare the local `datastream@` and cast only where the value "
        "really is a file, which is the branch that calls `open` on it."),
    "call":
        "NVGT's `library::call` returns `var@` where BGT's returns "
        "`dictionary@`, so the result cannot be assigned to a "
        "`dictionary@` and is not read with `.get(...)`. Every `dllib.call` "
        "site needs its result handled as a `var@`.",
    "request":
        "NVGT's `network::request` returns a `const network_event@`, so the "
        "handle it is assigned to has to be `const` too.",
    "generate_computer_id":
        "NVGT's `bgt_compat.nvgt` answers this with "
        "`generate_system_fingerprint`, which is a different number on the "
        "same machine -- so a ported game cannot validate a registration key "
        "the player already holds, and says nothing about why. BGT's own "
        "answer is `bgt computerid`, and it is the same algorithm in every "
        "engine from 1.3 to the 2019 fork.",
    "string_compress":
        "NVGT's `bgt_compat.nvgt` answers this with `string_deflate`, which "
        "is zlib, where BGT's is its own LZ77 with a trailing "
        "\" <uncompressed length>\" -- the same codec as the module "
        "container. So a ported game cannot read a file its BGT build "
        "wrote, and the save path of a title that compresses before "
        "encrypting fails at the decrypt with no mention of compression.",
    "string_decompress":
        "The other half of `string_compress`: NVGT's shim is `string_inflate` "
        "and BGT's format is LZ77 plus a trailing decimal length, so an old "
        "save decompresses to nothing rather than reporting a bad format.",
    "serialize":
        "BGT writes a dictionary as `base64(key)` NUL `<type byte>` "
        "`<value text>` NUL per entry, with type 1 int, 2 double written "
        "\"%f\", 3 base64 of the string and 4 bool \"1\"/\"0\" -- and "
        "arrays and nested dictionaries dropped silently. NVGT's "
        "`dictionary::serialize` is its own format, so a ported game cannot "
        "read a save its BGT build wrote.",
    "deserialize":
        "The other half of `serialize`, and the one that fails quietly: a "
        "blob in BGT's format leaves NVGT's dictionary empty rather than "
        "reporting a bad save, so a loaded game silently starts over.",
    "string_encrypt":
        "NVGT's `bgt_compat.nvgt` answers this with `string_aes_encrypt`, "
        "whose own comment says it does not work with existing BGT data: it "
        "hashes the key straight with SHA-256 where BGT puts it through a "
        "derivation of its own, takes the IV from every other digest byte "
        "where BGT takes the first sixteen, and does not wrap the plaintext "
        "in BGT's `printf<len>` header. This is the third link of a save "
        "path, so it fails even where the other two agree.",
    "string_decrypt":
        "The other half of `string_encrypt`. BGT's is self-checking -- the "
        "plaintext has to begin `printf` and declare its own length -- so a "
        "wrong arrangement returns nothing rather than rubbish, which is the "
        "one mercy in this family.",
    "file_encrypt":
        "NVGT's `bgt_compat.nvgt` answers this with `asset_encryptor`, and "
        "BGT writes a different container again -- `SWCR`, the length as a "
        "little-endian u32 three times, a 16-byte tag, then AES-256-ECB of "
        "the data, which is also how an entry inside an SFPv asset pack is "
        "encrypted. Not the same format as `string_encrypt`, so a game that "
        "uses both needs both.",
    "file_decrypt":
        "The other half of `file_encrypt`, and worth its own line because "
        "the shim it replaces reports success: a wrong key writes an empty "
        "file and returns true, where BGT's tag refuses the key outright.",
}

#: Which receiver types a `SEMANTIC` entry is ABOUT, where it is about one.
#:
#: `SEMANTIC` is keyed by the bare call name and was matched that way, so a
#: note about one type fired on every type that shares a method name. Super
#: Egg Hunt is the case: it reads a download in chunks with `h.request()` on
#: an `http`, and got the note for `network::request` -- which returns a
#: `const network_event@` and has nothing to do with it. A report that cannot
#: be acted on is worse than no report, because the next one is read with less
#: attention.
#:
#: A site whose receiver type cannot be read STILL reports, which is the safe
#: direction: this narrows a false alarm, it does not hide a real difference.
#: An entry absent from here is about the name wherever it appears -- which is
#: right for `string_compress` and the rest, since those are global functions
#: with no receiver at all.
SEMANTIC_TYPES: Dict[str, Tuple[str, ...]] = {
    "get_file": ("pack_file",),
    "request": ("network",),
    "call": ("library",),
}

#: `T name`, `T@ name`, `T[] name`, `T@[] name` -- a declaration, as the
#: recovered text writes one. The type's trailing markers are kept, because
#: they are what says "array".
_DECLARED = re.compile(
    r"^[ \t]*((?:const\s+)?[A-Za-z_][\w:]*(?:\s*[@&]|\s*\[\s*\])*)"
    r"\s+([A-Za-z_]\w*)\s*[;=,)(]", re.M)


def _semantic_receiver(scrubbed: str, types: Dict[str, str], name: str,
                       line: int) -> Optional[str]:
    """The declared type of what `name` is called on, on `line`, or None.

    None where there is no receiver or its type is not written down, and the
    caller reports the difference in that case rather than suppressing it.
    """
    start = 0
    for _ in range(line - 1):
        nxt = scrubbed.find("\n", start)
        if nxt < 0:
            return None
        start = nxt + 1
    end = scrubbed.find("\n", start)
    text = scrubbed[start:] if end < 0 else scrubbed[start:end]
    match = re.search(r"(?<![\w.])([A-Za-z_]\w*)\s*\.\s*" + re.escape(name)
                      + r"\s*\(", text)
    if match is None:
        return None
    root = match.group(1)
    return nearest_type(scrubbed, root, start + match.start()) or types.get(root)


def declared_types(scripts: Sequence[Tuple[str, str]]) -> Dict[str, str]:
    """Each name's declared type, where every declaration of it AGREES.

    A name declared one way in one file and another way elsewhere is dropped
    rather than guessed at: renaming on a disagreement is how a correct
    `sound.get_length()` would become a broken `sound.length()`.
    """
    seen: Dict[str, Set[str]] = {}
    #: **A class member is not a global, and this map is keyed by bare name.**
    #: Paladin's class `map` declares `int[][] world` and the project declares
    #: a global `map[] world`, so the two disagreed and the name was dropped
    #: -- after which nothing knew what `world.get_length()` was called on,
    #: and 67 of that title's 72 errors were that one question unanswered.
    #: Members are kept apart in `class_members`, where they can be looked up
    #: against their own class.
    members = class_members(scripts)
    member_names = {name for table in members.values() for name in table}
    for _path, text in scripts:
        for match in _DECLARED.finditer(_scrub(text)):
            kind, name = match.group(1).strip(), match.group(2)
            if name in RESERVED or kind in RESERVED and "[" not in kind:
                continue
            tidy = re.sub(r"\s+", "", kind)
            #: A member's own declaration is skipped here rather than every
            #: declaration of that name: a LOCAL called `world` is still a
            #: local, and dropping those would lose what the rename needs.
            if name in member_names and any(
                    table.get(name) == tidy for table in members.values()):
                continue
            seen.setdefault(name, set()).add(tidy)
    return {name: next(iter(kinds)) for name, kinds in seen.items()
            if len(kinds) == 1}


#: `class X {` / `shared class X : Base {` at the start of a line, which is how
#: the recovered text writes one.
_CLASS_OPEN = re.compile(r"^[ \t]*(?:shared\s+)?class\s+([A-Za-z_]\w*)", re.M)

#: `interact@[] interacts;` at class scope. The terminator is what separates a
#: member from a method signature, which is why it is required.
_MEMBER_DECL = re.compile(
    r"\s*(?:private\s+|protected\s+|const\s+)*"
    r"([A-Za-z_][\w:]*(?:\s*[@&]|\s*\[\s*\])*)"
    r"\s+([A-Za-z_]\w*)\s*[;=,]")


def class_members(scripts: Sequence[Tuple[str, str]]) -> Dict[str, Dict[str, str]]:
    """Each class's own members and their declared types.

    Needed for two things that were one bug. A member is **not** a global, and
    the flat `declared_types` map is keyed by bare name, so Paladin's class
    `map` -- which has a member `int[][] world` -- collided with the global
    `map[] world` and the name was dropped as disagreeing. Nothing then knew
    what `world.get_length()` was called on.

    And a member's type is what resolves a CHAIN: `world[i].interacts` is an
    array because `map::interacts` is declared `interact@[]`.

    A member is a declaration at brace depth 1 inside the class body. Depth 2
    and beyond is a method's locals, which belong to nobody but the method.
    """
    out: Dict[str, Dict[str, str]] = {}
    for _path, text in scripts:
        scrubbed = _scrub(text)
        for match in _CLASS_OPEN.finditer(scrubbed):
            brace = scrubbed.find("{", match.end())
            if brace < 0:
                continue
            depth, i, n = 0, brace, len(scrubbed)
            body_start = brace + 1
            while i < n:
                if scrubbed[i] == "{":
                    depth += 1
                elif scrubbed[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            body = scrubbed[body_start:i]
            members = out.setdefault(match.group(1), {})
            depth, start = 0, 0
            for pos, char in enumerate(body):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth = max(0, depth - 1)
                #: **A `;` terminates as well as a newline**, because a class
                #: written on one line has no newline at depth 0 at all --
                #: Paladin's `class character { dragonstrike[] strikes; }`
                #: came out with no members, so the chain through it declined
                #: and the rename was declined with it.
                elif (char == ";" or char == "\n") and depth == 0:
                    segment = body[start:pos + 1]
                    decl = _MEMBER_DECL.match(segment)
                    if decl:
                        members.setdefault(
                            decl.group(2), re.sub(r"\s+", "", decl.group(1)))
                    start = pos + 1
    return out


def _strip_one_array(kind: str) -> Optional[str]:
    """`map[]` -> `map`, `int[][]` -> `int[]`, `character@[]` -> `character@`."""
    kind = kind.strip()
    if kind.endswith("[]"):
        return kind[:-2]
    return None


def resolve_chain(root_kind: str, middle: str,
                  members: Dict[str, Dict[str, str]]) -> Optional[str]:
    """The declared type a `root<middle>.method()` call lands on, or None.

    `middle` is the `[...]` and `.name` steps between the root and the method,
    exactly as the rename pattern captures them. Each step is taken from the
    project's own declarations:

        world[i].interacts      map[] -> map -> interact@[]

    **None at the first step it cannot take**, which is the whole safety
    argument: a chain is renamed only when every link is written down, so an
    unknown member or an unknown element type declines rather than guesses.
    """
    kind = re.sub(r"\s+", "", root_kind)
    for step in re.finditer(r"\[[^\[\]]*\]|\.([A-Za-z_]\w*)", middle):
        name = step.group(1)
        if name is None:                       # a subscript: one array level off
            kind = _strip_one_array(kind)
            if kind is None:
                return None
            continue
        #: A handle and the thing it points at take the same members.
        owner = kind.rstrip("@&")
        if owner.endswith("]"):
            return None                        # a member OF an array: no such thing
        table = members.get(owner)
        if not table or name not in table:
            return None
        kind = table[name]
    return kind


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


#: A function or method signature, with its parameter list captured. The line
#: must END at the closing paren -- the recovered text puts the `{` on the
#: next line -- which is what tells a signature from a call or from a
#: constructor-form declaration, both of which carry a `;` or an argument that
#: is not a type.
_SIGNATURE = re.compile(
    r"^[ \t]*(?:(?:private|protected|shared|external|abstract|final|override)"
    r"\s+)*(?:const\s+)?[A-Za-z_][\w:]*(?:\s*[@&]|\s*\[\s*\])*\s+"
    r"[A-Za-z_]\w*\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*"
    r"(?:const\s*)?\{?[ \t]*$", re.M)

#: One parameter of such a list: `vector[] arg0`, `const string&in arg1`.
_PARAMETER = re.compile(
    r"^\s*(?:const\s+)?([A-Za-z_][\w:]*(?:\s*[@&]|\s*\[\s*\])*)"
    r"\s+([A-Za-z_]\w*)")


def signature_parameters(text: str) -> List[Tuple[int, str, str]]:
    """Every parameter's `(position, name, declared type)`.

    **A parameter is declared in the signature, not as a statement**, and
    `_DECLARED` is anchored at the start of a line -- so on

        vector[] remove_vector(vector[] arg0, vector arg1, bool arg2 = true)

    it captures `remove_vector` as a name of type `vector[]` and never sees
    `arg0` at all. Every receiver in a recovered body is either a local or a
    parameter, so half of them had no type: that was the last 10 of Paladin's
    errors, all of the shape `arg0.statuses.get_length()`.

    The position is the signature's own, which is above every use in the body
    and below the function before it -- so `nearest_type`'s "look up" answer
    is right without it having to know about scopes.
    """
    found: List[Tuple[int, str, str]] = []
    for match in _SIGNATURE.finditer(text):
        for piece in _split_arguments(match.group(1)):
            param = _PARAMETER.match(piece)
            if param:
                found.append((match.start(), param.group(2),
                              re.sub(r"\s+", "", param.group(1))))
    return found


def _split_arguments(text: str) -> List[str]:
    """Split a parameter list on its TOP-LEVEL commas.

    A default argument may hold one of its own -- `string arg1 = string("a,b")`
    -- so a plain `split(",")` would cut a parameter in half and leave the
    half-piece looking like a declaration of something else.
    """
    pieces: List[str] = []
    depth, start = 0, 0
    for pos, char in enumerate(text):
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "," and depth == 0:
            pieces.append(text[start:pos])
            start = pos + 1
    pieces.append(text[start:])
    return pieces


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
    at = -1
    for match in _DECLARED.finditer(text, 0, before):
        if match.group(2) == name:
            found = re.sub(r"\s+", "", match.group(1).strip())
            at = match.start()
    #: ...and the parameters, which are declared in a signature rather than in
    #: a statement. Taken by position against the statement declarations, so
    #: a local that shadows a parameter still wins where it is declared below
    #: it, which is where the hoisting puts one.
    for pos, pname, kind in signature_parameters(text):
        if pos < before and pname == name and pos > at:
            found, at = kind, pos
    return found


#: Value types BGT gives a COPY CONSTRUCTOR and NVGT does not.
#:
#: BGT registers `void f(const vector &in)`, so `vector(v)` is a copy there;
#: NVGT registers only `void f()` and `void f(float x, float y, float z = 0)`,
#: and `vector(v)` is *"No matching signatures to 'vector(vector)'"*.
#:
#: Dropping the call is exact rather than near enough, and the engine is the
#: authority for both halves: NVGT registers the type `asOBJ_POD`, so
#: AngelScript gives it a bitwise copy for free, and `vector b = a;` and
#: `c = a;` were both put to `nvgt -c` before either was emitted.
#:
#: **Only where the argument's own type is the same type.** BGT's other
#: constructor takes floats with defaults, so `vector(1.0)` is a legal
#: one-argument call that means something else entirely -- and `vector(v.x)`
#: is that call. The chain resolver answers which, and declines where it
#: cannot, exactly as it does for a rename.
COPY_CONSTRUCTED = ("vector",)


def apply_copy_constructors(text: str, types: Dict[str, str],
                            members: Dict[str, Dict[str, str]]
                            ) -> Tuple[str, List[str]]:
    """Drop `T(x)` where `T` is POD in NVGT and `x` is already a `T`."""
    notes: List[str] = []
    scrubbed = _scrub(text)
    #: `local_27`, `this.pos`, `points[i]` -- one argument and no comma, so the
    #: float-triple constructor can never be reached from here.
    arg = r"([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\[\]]*\])*)"
    for kind in COPY_CONSTRUCTED:
        def resolve(root: str, middle: str, at: int) -> Optional[str]:
            found = nearest_type(scrubbed, root, at) or types.get(root)
            if found is not None and middle:
                found = resolve_chain(found, middle, members)
            return found

        def split(expr: str) -> Tuple[str, str]:
            head = re.match(r"\s*([A-Za-z_]\w*)", expr)
            return head.group(1), expr[head.end():]

        done = [0]

        #: A DECLARATION with a constructor argument: the construction is the
        #: declaration, so the cure is the initialiser form rather than
        #: nothing at all.
        decl = re.compile(r"^([ \t]*)" + re.escape(kind) + r"\s+([A-Za-z_]\w*)"
                          r"\s*\(\s*" + arg + r"\s*\)\s*;", re.M)

        def swap_decl(match, kind=kind, done=done):
            root, middle = split(match.group(3))
            if _receiver_kind(resolve(root, middle, match.start()) or "") != kind:
                return match.group(0)
            done[0] += 1
            return "%s%s %s = %s;" % (match.group(1), kind, match.group(2),
                                      match.group(3))

        text = decl.sub(swap_decl, text)
        scrubbed = _scrub(text)

        #: ...and the same call in expression position, where the copy is the
        #: whole of what it does.
        call = re.compile(r"(?<![\w.])" + re.escape(kind)
                          + r"\s*\(\s*" + arg + r"\s*\)")

        def swap_call(match, kind=kind, done=done):
            root, middle = split(match.group(1))
            if _receiver_kind(resolve(root, middle, match.start()) or "") != kind:
                return match.group(0)
            done[0] += 1
            return match.group(1)

        text = call.sub(swap_call, text)
        scrubbed = _scrub(text)
        if done[0]:
            notes.append("%s(%s) -> the value itself, %d time%s: NVGT has no "
                         "copy constructor for it and registers it POD, so a "
                         "plain copy is the same program"
                         % (kind, kind, done[0], "" if done[0] == 1 else "s"))
    return text, notes


#: A call NVGT declares as returning a CONST handle where BGT's is not, with
#: the receiver's type and the type returned.
#:
#: NVGT registers `const network_event@ network::request()`, so a local that
#: receives one has to be `const` too -- *"Can't implicitly convert from
#: 'const network_event@' to 'network_event@'"*, on every BGT game that reads
#: its network. The declaration is the whole fix, and it was put to `nvgt -c`
#: on a real recovery before it was emitted.
#:
#: **Only the declaration, and only where it is already a plain handle of the
#: right type.** A non-const handle still assigns INTO a const one, so the
#: same local may be filled from somewhere else and stay correct; and code
#: that writes THROUGH the handle stops compiling, which is a visible failure
#: rather than a silent one.
CONST_HANDLE_RETURNS = {
    "request": ("network", "network_event"),
}


def apply_const_handles(text: str, types: Dict[str, str],
                        members: Dict[str, Dict[str, str]]
                        ) -> Tuple[str, List[str]]:
    """Declare `const` the locals that receive a const handle from NVGT."""
    notes: List[str] = []
    scrubbed = _scrub(text)
    for call, (recv_kind, held) in CONST_HANDLE_RETURNS.items():
        wanted = set()
        pattern = re.compile(r"@\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)"
                             r"((?:\.[A-Za-z_]\w*|\[[^\[\]]*\])*)\."
                             + re.escape(call) + r"\s*\(")
        for match in pattern.finditer(scrubbed):
            root, middle = match.group(2), match.group(3)
            kind = nearest_type(scrubbed, root, match.start()) or types.get(root)
            if kind is not None and middle:
                kind = resolve_chain(kind, middle, members)
            if kind is None or _receiver_kind(kind) != recv_kind:
                continue
            wanted.add(match.group(1))
        done = 0
        for name in sorted(wanted):
            decl = re.compile(r"^([ \t]*)" + re.escape(held) + r"(\s*@\s*)"
                              + re.escape(name) + r"(\s*;)", re.M)
            text, count = decl.subn(
                lambda m: "%sconst %s%s%s%s" % (m.group(1), held, m.group(2),
                                                name, m.group(3)), text)
            done += count
        if done:
            notes.append("%s() -> its local declared `const %s@`, %d time%s: "
                         "NVGT returns a const handle where BGT does not"
                         % (call, held, done, "" if done == 1 else "s"))
            scrubbed = _scrub(text)
    return text, notes


#: Calls whose FIRST argument is text in BGT and a number in NVGT, with the
#: receiver's type.
#:
#: BGT's own `tone_synth` is inconsistent and NVGT fixed it. Both engines take
#: a note NAME as a string -- `note`, `note_ms`, `note_bend`, `note_bend_ms`
#: -- and BGT takes a FREQUENCY as a string too, where NVGT takes the number:
#:
#:     BGT    bool freq_ms(string& in, double& in)
#:     NVGT   bool freq_ms(double freq, int ms)
#:
#: so a game passes `freq_ms(("" + freq), 40.0)`, stringifying a double it
#: already had. Unwrapping that is exact, and the `ms` argument needs nothing:
#: AngelScript converts the double to an int with no warning, which was
#: measured rather than assumed.
STRINGIFIED_NUMBER_ARGS = {
    "freq": ("tone_synth",),
    "freq_ms": ("tone_synth",),
    "freq_bend": ("tone_synth",),
    "freq_bend_ms": ("tone_synth",),
}

#: The types whose value a `"" +` was hiding. A cast spelled as a call --
#: `double(x)` -- counts, because that is how the recovery writes a conversion.
NUMERIC_TYPES = frozenset("""int uint int8 int16 int64 uint8 uint16 uint64
float double""".split())


def _numeric_expression(expr: str, scrubbed: str, types: Dict[str, str],
                        members: Dict[str, Dict[str, str]],
                        at: int) -> bool:
    """Whether `expr` is provably a number rather than text.

    `"" + x` is only a stringified NUMBER when `x` is one: `"" + name` where
    `name` holds a string is an ordinary concatenation, and unwrapping it
    would hand the engine the wrong thing.
    """
    expr = expr.strip()
    if re.fullmatch(r"[-+]?\d+(?:\.\d*)?(?:[eE][-+]?\d+)?f?", expr):
        return True
    cast = re.match(r"([A-Za-z_]\w*)\s*\(", expr)
    if cast and cast.group(1) in NUMERIC_TYPES:
        return True
    chain = re.fullmatch(r"([A-Za-z_]\w*)((?:\.[A-Za-z_]\w*|\[[^\[\]]*\])*)",
                         expr)
    if chain is None:
        return False
    kind = nearest_type(scrubbed, chain.group(1), at) or types.get(chain.group(1))
    if kind is not None and chain.group(2):
        kind = resolve_chain(kind, chain.group(2), members)
    if kind is None:
        return False
    return _receiver_kind(kind) in NUMERIC_TYPES


def _wraps_whole(expr: str) -> bool:
    """Whether a leading `(` is matched by the LAST character.

    `(a) + (b)` starts with `(` and ends with `)` and encloses nothing, so
    stripping the pair would change what the expression means -- which is a
    mistake this file records costing a whole title's `while` statements.
    """
    depth = 0
    for pos, char in enumerate(expr):
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
            if depth == 0:
                return pos == len(expr) - 1
    return False


def _first_argument(text: str, open_paren: int) -> Optional[Tuple[int, int]]:
    """The span of the first argument of the call whose `(` is at `open_paren`.

    Bracket-matched rather than split on a comma, because an argument may hold
    one of its own -- `freq_ms(("" + f(a, b)), 40)`.
    """
    depth = 0
    start = open_paren + 1
    for pos in range(open_paren, len(text)):
        char = text[pos]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
            if depth == 0:
                return start, pos
        elif char == "," and depth == 1:
            return start, pos
    return None


def apply_stringified_numbers(text: str, types: Dict[str, str],
                              members: Dict[str, Dict[str, str]]
                              ) -> Tuple[str, List[str]]:
    """Unwrap `("" + x)` where NVGT wants the number `x`."""
    notes: List[str] = []
    for call, kinds in STRINGIFIED_NUMBER_ARGS.items():
        done = 0
        declined = 0
        while True:
            #: The scan restarts after each rewrite, so a site already fixed
            #: is seen again and would be counted as declined every round --
            #: `freq_ms` reported 3 left alone where 2 are. Only the LAST
            #: pass, which rewrites nothing, is the one that counts.
            declined = 0
            scrubbed = _scrub(text)
            pattern = re.compile(
                r"(?<![\w.])([A-Za-z_]\w*)((?:\.[A-Za-z_]\w*|\[[^\[\]]*\])*)\."
                + re.escape(call) + r"\s*\(")
            moved = False
            for match in pattern.finditer(scrubbed):
                root, middle = match.group(1), match.group(2)
                kind = (nearest_type(scrubbed, root, match.start())
                        or types.get(root))
                if kind is not None and middle:
                    kind = resolve_chain(kind, middle, members)
                if kind is None or _receiver_kind(kind) not in kinds:
                    continue
                span = _first_argument(scrubbed, match.end() - 1)
                if span is None:
                    continue
                arg = text[span[0]:span[1]]
                inner = arg.strip()
                #: one layer of the recovery's own parentheses
                if inner.startswith("(") and _wraps_whole(inner):
                    inner = inner[1:-1].strip()
                #: **A first argument that is already a number is already
                #: right**, and saying nothing about it is the difference
                #: between a report and noise: the scan restarts after each
                #: rewrite, so without this a site this pass had just FIXED
                #: came back as one it had left alone.
                if _numeric_expression(inner, scrubbed, types, members,
                                       match.start()):
                    continue
                stringify = re.match(r'^""\s*\+\s*(.+)$', inner, re.S)
                if stringify is None:
                    declined += 1
                    continue
                value = stringify.group(1).strip()
                if not _numeric_expression(value, scrubbed, types, members,
                                           match.start()):
                    declined += 1
                    continue
                text = text[:span[0]] + value + text[span[1]:]
                done += 1
                moved = True
                break
            if not moved:
                break
        if done:
            notes.append("%s(\"\" + n) -> %s(n), %d time%s: NVGT takes the "
                         "frequency as a NUMBER where BGT takes it as text"
                         % (call, call, done, "" if done == 1 else "s"))
        if declined:
            notes.append("%s left alone %d time%s: its first argument is text "
                         "NVGT wants as a number, and this one is not provably "
                         "a stringified number -- read it by hand"
                         % (call, declined, "" if declined == 1 else "s"))
    return text, notes


def apply_typed_renames(text: str, types: Dict[str, str],
                        members: Optional[Dict[str, Dict[str, str]]] = None
                        ) -> Tuple[str, List[str]]:
    """Rename `recv.get_length()` only where `recv`'s type says to.

    `members` is each class's own members, which is what lets a CHAIN resolve:
    `world[i].interacts.get_length()` is an array because the project declares
    `map[] world` and `map::interacts` as `interact@[]`. Without it the chain
    is declined, which is correct and, on Paladin, was 67 compiler errors.
    """
    notes: List[str] = []
    members = members or {}
    scrubbed = _scrub(text)
    for old, (new, kinds) in TYPED_RENAMES.items():
        pattern = re.compile(r"(?<![\w.])([A-Za-z_]\w*)((?:\.[A-Za-z_]\w*|"
                             r"\[[^\[\]]*\])*)\." + re.escape(old) + r"\s*\(")
        done = [0]
        declined = [0]

        def swap(match, old=old, new=new, kinds=kinds, done=done,
                 declined=declined):
            root, middle = match.group(1), match.group(2)
            kind = nearest_type(scrubbed, root, match.start()) or types.get(root)
            if kind is not None and middle:
                #: a subscript or a further member makes the value an ELEMENT
                #: or a MEMBER, so the root's own type is not what the method
                #: is called on -- the chain is walked instead, and declines
                #: at the first link the project does not declare
                kind = resolve_chain(kind, middle, members)
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
        pattern = re.compile(r"(?<![\w.])([A-Za-z_]\w*)((?:\.[A-Za-z_]\w*|"
                             r"\[[^\[\]]*\])*)\." + re.escape(old)
                             + r"\s*\(\s*\)")
        done = [0]

        def swap(match, new=new, kinds=kinds, done=done):
            root, middle = match.group(1), match.group(2)
            kind = nearest_type(scrubbed, root, match.start()) or types.get(root)
            if kind is not None and middle:
                kind = resolve_chain(kind, middle, members)
            if kind is None or _receiver_kind(kind) not in kinds:
                return match.group(0)
            done[0] += 1
            return "%s%s.%s" % (root, middle, new)

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
                #: **Two spaces for an escape, because it consumed two
                #: characters.** One space made the output SHORTER than the
                #: input from the first backslash in a file onward, so every
                #: offset taken from it drifted -- and this function exists to
                #: be searched by offset. `nearest_type` quietly looked in the
                #: wrong place, and a rewrite that sliced the real text at a
                #: scrubbed offset truncated the file: `Unexpected end of
                #: file`, from a rename that was otherwise correct.
                #: Clamped, because an escape as the LAST character of the
                #: file would consume one and blank two.
                step = min(2 if text[i] == "\\" else 1, n - i)
                i += step
                out.append(" " * step)
            #: ...and the closing quote is blanked only if there IS one. An
            #: unterminated literal at end of file otherwise got a space for
            #: a character that was not there, which drifts the same way in
            #: the other direction.
            if i < n:
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
            #: The closer only if it is there -- an unterminated block comment
            #: at end of file otherwise got two spaces for no characters.
            blanked = min(2, n - i)
            out.append(" " * blanked)
            i += blanked
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

#: Where NVGT usually is -- taken from `nvgt.nvgt_compiler`, which is the one
#: answer the whole toolkit uses. Three copies of this list used to disagree.
DEFAULT_ROOTS = nvgt_compiler.ROOTS


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


#: Which `SEMANTIC` names an NVGT build answers in BGT's own format already, and
#: the symbol in `bgt_compat.nvgt` that says so. A fork carrying BGT's exact
#: compression, dictionary wire format and computer id routes the shim to these,
#: so the difference is real of upstream NVGT and resolved there -- and reporting
#: it anyway would send somebody to fix what is already fixed.
EXACT_SHIMS: Dict[str, Tuple[str, ...]] = {
    "string_compress": ("bgt_string_compress",),
    "string_decompress": ("bgt_string_decompress",),
    "serialize": ("bgt_serialize",),
    "deserialize": ("bgt_serialize",),
    "generate_computer_id": ("bgt_generate_computer_id",),
    "string_encrypt": ("bgt_string_encrypt",),
    "string_decrypt": ("bgt_string_decrypt",),
    "file_encrypt": ("bgt_swcr_encrypt",),
    "file_decrypt": ("bgt_swcr_decrypt",),
}


def exact_shims(nvgt: Optional[Nvgt]) -> Set[str]:
    """The names this NVGT's own `bgt_compat.nvgt` already answers exactly.

    Asked of the file rather than assumed from a version, for the reason every
    other question here is asked of the authority: the answer is a property of
    the build in hand, and there is more than one NVGT.
    """
    if nvgt is None:
        return set()
    path = os.path.join(nvgt.include, "bgt_compat.nvgt")
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return set()
    return {name for name, symbols in EXACT_SHIMS.items()
            if all(symbol in text for symbol in symbols)}


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
            compile_it: bool = True, fix_names: bool = False) -> Dict[str, Any]:
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
    members = class_members(scripts)
    rewritten: List[Tuple[str, str]] = []
    for path, text in scripts:
        text, notes = apply_typed_renames(text, types, members)
        text, copy_notes = apply_copy_constructors(text, types, members)
        notes += copy_notes
        text, const_notes = apply_const_handles(text, types, members)
        notes += const_notes
        text, num_notes = apply_stringified_numbers(text, types, members)
        notes += num_notes
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
    exact = exact_shims(nvgt)
    report["exact_shims"] = sorted(exact)
    for path, text in scripts:
        scrubbed = _scrub(text)
        for line, name in calls_in(text):
            if name not in SEMANTIC:
                continue
            #: A note about one receiver type is not a note about another that
            #: happens to share the method name. Only a receiver whose type is
            #: READ and disagrees is skipped; an unknown one still reports.
            kinds = SEMANTIC_TYPES.get(name)
            if kinds:
                kind = _semantic_receiver(scrubbed, types, name, line)
                if kind is not None and _receiver_kind(kind) not in kinds:
                    continue
            report["semantic"].append(
                {"name": name, "file": os.path.relpath(path, out),
                 "line": line, "why": SEMANTIC[name],
                 "resolved": name in exact})
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
        #: **The other conflict message carries no name**, and that is why a
        #: whole title reported nothing actionable. An exact signature clash
        #: -- the game declares `void sleep(uint)` and so does NVGT -- is
        #: *"A function with the same name and parameters already exists"*,
        #: with a file and a line and no name in it. Paladin's only error is
        #: that one, so the report said `1 error line(s)` and left a person
        #: to open the file themselves.
        #:
        #: It is read off the DECLARATION the compiler pointed at, which is
        #: the authority for both halves: the compiler decides there is a
        #: clash, and the line it names says which function. A name clash on
        #: its own is not a conflict and must not be reported as one --
        #: `speak`, `clear` and `stop` all clash by name in Super Egg Hunt
        #: and compile cleanly, because the parameters differ and NVGT takes
        #: them as overloads.
        report["conflicts"] += _signature_clashes(said)
        #: ...and fix the ones that are provable, then ask the compiler again,
        #: because a verdict about the source before the fix is not a verdict
        #: about what is on disk now. One round only: every rename here is
        #: taken from this pass's own diagnostics, so a second pass would be
        #: reporting the same clash against a name that no longer exists.
        if fix_names:
            moved = fix_conflicts(out, report["conflicts"])
            if moved:
                code, said = nvgt.compile(entry)
                report["compile"] = {
                    "exit": code, "output": said.strip(),
                    "errors": [l.strip() for l in said.splitlines()
                               if l.strip().startswith(("ERROR:", "WARNING:"))]}
    return report


#: `void sleep(uint arg0)` -- a declaration at the start of a line, which is
#: how the recovered text writes a global function. Indentation would make it
#: a member, and a member of the game's own class clashes with nothing.
_GLOBAL_DECL = re.compile(
    r"^(?:const\s+)?[A-Za-z_][\w:]*(?:\s*[@&]|\s*\[\s*\])*\s+"
    r"([A-Za-z_]\w*)\s*\(")


def _signature_clashes(said: str) -> List[Dict[str, Any]]:
    """Name every function NVGT already has with the same parameters.

    The compiler reports this one without the name, so the name comes from
    the line it points at. Anything that line does not read as a global
    declaration is left out rather than guessed at -- a wrong name here would
    send somebody renaming the wrong function.
    """
    found: List[Dict[str, Any]] = []
    pending: Optional[Tuple[str, int]] = None
    path, line = None, None
    for raw in said.splitlines():
        text = raw.strip()
        match = re.match(r"(?:Compilation error: )?file: (.+)$", text)
        if match:
            path, line = match.group(1).strip(), None
            continue
        match = re.match(r"line: (\d+)", text)
        if match:
            line = int(match.group(1))
            continue
        if "same name and parameters already exists" not in text:
            continue
        if not path or not line:
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                source = handle.read().splitlines()
        except OSError:
            continue
        if line > len(source):
            continue
        decl = _GLOBAL_DECL.match(source[line - 1])
        if decl is None:
            continue
        found.append({"name": decl.group(1), "kind": "signature",
                      "file": os.path.basename(path), "line": line})
    seen = set()
    unique = []
    for row in found:
        key = (row["name"], row["file"], row["line"])
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique


def renameable(name: str) -> bool:
    """Whether renaming the game's own global function is PROVABLY safe.

    It is, when BGT registers and documents nothing of that name: then every
    unqualified `name(` in a recovered BGT project resolved to the game's own
    declaration, so moving the declaration and those calls together cannot
    change which function runs. Paladin's `sleep` is that case -- `bgt api
    sleep` answers "this engine neither documents nor registers it".

    It is NOT provable when BGT has the name, and the reason is a limit this
    file records elsewhere: **a registration string carries no owner**, so
    `registered()` cannot tell a global `speak` from `tts_voice::speak`. With
    a global of that name in BGT, an unqualified call might have gone to the
    engine rather than to the game, and a tool that renamed it would be
    guessing. Those are reported instead.
    """
    try:
        from . import bgt_api
    except ImportError:
        import bgt_api
    try:
        if name in bgt_api.registered():
            return False
    except Exception:                       # noqa: BLE001 -- no engine here
        return False
    return True


def global_variable(out: str, name: str) -> Optional[Tuple[str, int, str]]:
    """Where the project declares `name` as a GLOBAL VARIABLE, if it does.

    `Name conflict. 'X' is a global function.` gives the name and not the kind
    of the game's own declaration, and the kind is what decides whether this
    can be fixed. Aliens Attack declares `sound power;` and `sound exp2;` at
    file scope, and NVGT has a global *function* of each name -- which BGT
    allowed and NVGT does not, so two sounds stopped the whole title
    compiling.

    A CLASS of that name is deliberately not looked for: this file declines
    renaming one all along, because a class name reaches into string literals
    and saved data. A variable's name reaches its declaration and its reads.
    """
    for path, text in _scripts(out):
        scrubbed = _scrub(text)
        #: file scope is brace depth 0, counted up to each candidate
        depth = 0
        cursor = 0
        for match in _DECLARED.finditer(scrubbed):
            depth += (scrubbed.count("{", cursor, match.start())
                      - scrubbed.count("}", cursor, match.start()))
            cursor = match.start()
            if depth != 0 or match.group(2) != name:
                continue
            #: a signature opens a parameter list; a variable does not
            if match.group(0).rstrip().endswith("("):
                continue
            line = scrubbed.count("\n", 0, match.start()) + 1
            return path, line, re.sub(r"\s+", "", match.group(1).strip())
    return None


def _scripts(out: str) -> List[Tuple[str, str]]:
    """Every `.nvgt` under `out`, as `(path, text)`."""
    found = []
    for root, _dirs, files in os.walk(out):
        for name in sorted(files):
            if name.endswith(".nvgt"):
                path = os.path.join(root, name)
                with open(path, encoding="utf-8", errors="replace") as handle:
                    found.append((path, handle.read()))
    return found


def fix_conflicts(out: str, conflicts: Sequence[Dict[str, Any]]
                  ) -> List[Dict[str, Any]]:
    """Rename each provably-safe clashing global, in place. Returns what moved.

    The declaration and every UNQUALIFIED call, and nothing else: `x.sleep()`
    is a method on the game's own class and clashes with nothing, and a class
    named `sleep` is a different fix that this deliberately does not attempt
    -- a class name reaches into string literals and saved data, which is why
    this file has declined that one all along.
    """
    done: List[Dict[str, Any]] = []
    paths = [os.path.join(root, f)
             for root, _dirs, files in os.walk(out)
             for f in files if f.endswith(".nvgt")]
    texts = {path: open(path, encoding="utf-8", errors="replace").read()
             for path in paths}
    for row in conflicts:
        name = row.get("name")
        if not name:
            continue
        if row.get("kind") == "signature":
            #: a global FUNCTION, which is only provably safe where BGT has
            #: no such name -- see `renameable`
            if not renameable(name):
                continue
        else:
            #: ...or a global VARIABLE, which is safe whatever BGT has: a
            #: variable's name is read, never called, so renaming it cannot
            #: change which function runs. That is the doubt `renameable`
            #: exists for, and it does not reach a variable.
            where = global_variable(out, name)
            if where is None:
                continue
            row["kind"] = "variable"
            row["file"] = os.path.basename(where[0])
            row["line"] = where[1]
            row["declared"] = where[2]
        #: A suffix rather than a prefix, so the name still reads as itself in
        #: a stack trace, and checked against the whole project so the cure is
        #: not a second clash.
        new_name = name + "_"
        while any(re.search(r"(?<![\w.])%s(?![\w])" % re.escape(new_name), t)
                  for t in texts.values()):
            new_name += "_"
        if row.get("kind") == "variable":
            #: **Every use EXCEPT a call.** The engine's function of that name
            #: is still reachable and still meant wherever the text calls it,
            #: so `power(a, b)` is left exactly as it is while `power.play()`
            #: and a bare `power` are the game's own variable.
            pattern = re.compile(r"(?<![\w.])%s(?![\w])(?!\s*\()"
                                 % re.escape(name))
        else:
            pattern = re.compile(r"(?<![\w.])%s(\s*\()" % re.escape(name))
        moved = 0
        for path, text in list(texts.items()):
            scrubbed = _scrub(text)
            pieces, last = [], 0
            for match in pattern.finditer(scrubbed):
                pieces.append(text[last:match.start()])
                pieces.append(new_name)
                last = match.start() + len(name)
                moved += 1
            if pieces:
                pieces.append(text[last:])
                texts[path] = "".join(pieces)
        if moved:
            row["renamed_to"] = new_name
            row["sites"] = moved
            done.append(row)
    for path, text in texts.items():
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    return done


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
    fixed = [r for r in conflicts if r.get("renamed_to")]
    left = [r for r in conflicts if not r.get("renamed_to")]
    if fixed:
        out.append("  %-22s %d name(s) this game declares that NVGT also has,"
                   % ("renamed for you", len(fixed)))
        out.append("  %-22s which BGT has none of -- so every unqualified call"
                   % "")
        out.append("  %-22s was the game's own and moving them together cannot"
                   % "")
        out.append("  %-22s change which function runs:" % "")
        for row in fixed[:8]:
            out.append("      %s -> %s (%d site%s)"
                       % (row["name"], row["renamed_to"], row["sites"],
                          "" if row["sites"] == 1 else "s"))
    if left:
        out.append("  %-22s %d name(s) this game declares that NVGT already"
                   % ("rename these yourself", len(left)))
        out.append("  %-22s has, and which this will not rename for you: BGT"
                   % "")
        out.append("  %-22s has the name too and its registrations carry no"
                   % "")
        out.append("  %-22s owner, so an unqualified call may have meant the"
                   % "")
        out.append("  %-22s engine's. A class name also reaches into string"
                   % "")
        out.append("  %-22s literals and saved data." % "")
        for row in left[:8]:
            where = ("  %s:%d" % (row["file"], row["line"])
                     if row.get("file") else "")
            out.append("      %s%s" % (row["name"], where))
        if len(left) > 8:
            out.append("      ...and %d more" % (len(left) - 8))
    semantic = report.get("semantic") or []
    exact = set(report.get("exact_shims") or ())
    if semantic:
        kinds: Dict[str, int] = {}
        for row in semantic:
            kinds[row["name"]] = kinds.get(row["name"], 0) + 1
        open_kinds = {n: c for n, c in kinds.items() if n not in exact}
        done_kinds = {n: c for n, c in kinds.items() if n in exact}
        if open_kinds:
            total = sum(open_kinds.values())
            out.append("  %-22s %d site(s) whose MEANING differs, not spelling:"
                       % ("read these by hand", total))
            for name, count in sorted(open_kinds.items()):
                first = next(r for r in semantic if r["name"] == name)
                out.append("      %s  (%d site%s, first %s:%d)"
                           % (name, count, "" if count == 1 else "s",
                              first["file"], first["line"]))
                for chunk in _wrap(SEMANTIC[name], 66):
                    out.append("          %s" % chunk)
        if done_kinds:
            #: Named rather than dropped: a difference this NVGT resolves is
            #: still a difference every other one has, so a project moved to a
            #: stock build needs to know which ones were being answered for it.
            out.append("  %-22s this NVGT already answers in BGT's own format: %s"
                       % ("answered exactly",
                          ", ".join("%s (%d site%s)"
                                    % (n, c, "" if c == 1 else "s")
                                    for n, c in sorted(done_kinds.items()))))
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
    parser.add_argument("--fix-conflicts", action="store_true",
                        help="rename the game's own globals that clash with "
                             "NVGT's, where BGT has no such name and the "
                             "rename is therefore provably the same program")
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
                     compile_it=not args.no_compile,
                     fix_names=args.fix_conflicts)
    print(summary(report))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=1)
        print("  %-22s %s" % ("report", args.json))
    done = report.get("compile")
    return 0 if (done is None or done["exit"] == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
