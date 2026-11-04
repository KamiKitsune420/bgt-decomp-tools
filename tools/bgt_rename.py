"""Give a recovered BGT project's placeholder slots names a person can read.

A release build of BGT keeps class, method, property, global and function
names, and every string literal -- but it throws away the name of every
*local* and *parameter*, so `bgt recover` writes `local_7` and `arg0`.  This
pass replaces those with names inferred from what the code around them does.

Nothing here invents a fact.  Every name comes from one of five sources, in
descending order of authority:

1.  **The engine's own documentation.**  `bgt.chm` carries a parameter name
    per engine function and method -- `bool wait(int milliseconds)`,
    `bool set_sound_storage(string filename)` -- so an argument passed to one
    is named by the engine itself.
2.  **The game's own identifiers.**  A slot assigned from a member, a global,
    a constructor, an array element or a getter takes its name from that
    member, global, type or getter, because the author named those.
3.  **The slot's role in the control flow.**  A `for` counter is `i`; a slot
    only ever used as a subscript is an index; a slot read before a call and
    compared after it is an `ancien...` snapshot.
4.  **Propagation.**  Once a parameter has a name, every argument passed to it
    can take it, and once a local has one, the parameter it feeds can.  Run to
    a fixpoint.
5.  **The declared type**, which is always known, as the last resort -- a
    `sound@` with no other evidence is a `son`, never a `local_7`.

The transform is a token-level substitution inside one function body, so it
cannot move a declaration or change an expression.  Two things make it safe:

*   **A new name may not collide with anything visible.**  The recovery writes
    a member access bare (`nbPiece = nbPiece + 1`), so a local called
    `nbPiece` would shadow the member and change the program.  Every candidate
    is checked against the enclosing class's members and those of its bases,
    every global, every function, every type, every enum value, the engine's
    whole registered interface and the language's keywords.
*   **The rewrite is verified mechanically.**  `verify()` re-lexes both trees
    and requires the token streams to be identical except where a placeholder
    token became its new name, with one consistent mapping per body.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

try:
    from . import bgt_api
except ImportError:  # run directly
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import bgt_api  # type: ignore


# --------------------------------------------------------------------------
# masking: strings and comments must never be seen by a scanner

_SKIP = re.compile(
    "//[^\\n]*"                        # a line comment
    "|/\\*.*?(?:\\*/|$)"               # a block comment, unterminated allowed
    '|"(?:\\\\.|[^"\\\\\\n])*"?'       # a string, escapes and all
    "|'(?:\\\\.|[^'\\\\\\n])*'?",      # the same with the other quote
    re.S)


def mask(text: str) -> str:
    """Return `text` with every comment and string *body* blanked to spaces.

    Lengths and newlines are preserved, so an offset into the mask is an
    offset into the original.  The quotes themselves are kept, which is what
    lets a caller tell a string literal from an identifier at the same spot.

    One left-to-right alternation does it, so a `//` inside a string cannot
    start a comment and a quote inside a comment cannot start a string --
    which is the whole reason a reader is tempted to walk this one character
    at a time.
    """
    out = None
    for m in _SKIP.finditer(text):
        if out is None:
            out = list(text)
        body = m.group(0)
        if body[0] == "/":
            lo, hi = m.start(), m.end()             # a comment goes entirely
        else:
            lo = m.start() + 1                      # keep the opening quote
            closed = len(body) > 1 and body[-1] == body[0]
            hi = m.end() - 1 if closed else m.end()
        for i in range(lo, hi):
            if out[i] != "\n":
                out[i] = " "
    return text if out is None else "".join(out)


_IDENT = re.compile(r"[A-Za-z_]\w*")
_TOKEN = re.compile(r"[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+\.\d*|\.\d+|\d+|\S")


def tokens_with_pos(text: str) -> List[Tuple[str, int]]:
    """Every token of `text` as `(token, offset)`, strings kept whole.

    Comments are dropped and a string literal is one token, so a placeholder
    that happens to sit inside one can never be read as code.
    """
    masked = mask(text)
    out: List[Tuple[str, int]] = []
    i, n = 0, len(text)
    while i < n:
        c = masked[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == '"' or c == "'":
            j = i + 1
            while j < n and masked[j] != c:
                j += 1
            out.append((text[i:j + 1], i))
            i = j + 1
            continue
        m = _TOKEN.match(masked, i)
        if not m:
            i += 1
            continue
        out.append((m.group(0), i))
        i = m.end()
    return out


def tokens(text: str) -> List[str]:
    """Every token of `text`, with comments dropped and strings kept whole."""
    return [t for t, _ in tokens_with_pos(text)]


# --------------------------------------------------------------------------
# vocabulary

KEYWORDS = {
    "and", "or", "not", "xor", "is", "in", "out", "inout", "true", "false",
    "null", "if", "else", "while", "do", "for", "switch", "case", "default",
    "break", "continue", "return", "class", "enum", "funcdef", "interface",
    "typedef", "namespace", "const", "private", "cast", "super", "this",
    "void", "bool", "int", "int8", "int16", "int64", "uint", "uint8",
    "uint16", "uint64", "float", "double", "string", "array", "auto",
    "import", "mixin", "shared", "final", "override", "abstract", "get",
    "set", "property", "ref", "long",
}

#: Words that can never be the name of a function, so that a `<type> name(`
#: at class scope really is a method.
#:
#: This is *not* `KEYWORDS`, and the difference cost a whole class body:
#: `get` and `set` are in that set because AngelScript spells a property
#: accessor with them, but those take a brace and no parentheses, while a
#: **method** called `get` is ordinary -- this game's `ChoixCombat::get` is
#: one.  Rejecting it left eleven slots in that body unreachable, so they
#: kept their placeholders while every count said the pass was complete.
NOT_A_FUNCTION_NAME = {
    "if", "else", "while", "do", "for", "switch", "case", "default",
    "break", "continue", "return", "class", "enum", "funcdef", "interface",
    "typedef", "namespace", "const", "private", "cast", "super", "and",
    "or", "not", "xor", "is", "in", "out", "inout", "true", "false", "null",
    "import", "mixin", "shared", "final", "override", "abstract",
}

TYPE_NOUN = {
    "string": "texte",
    "int": "nombre", "uint": "nombre", "int8": "nombre", "int16": "nombre",
    "int64": "nombre", "uint8": "nombre", "uint16": "nombre",
    "uint64": "nombre", "long": "nombre",
    "double": "valeur", "float": "valeur",
    "bool": "condition",
    "sound": "son", "sound_pool": "pool", "sound_pool_item": "elementPool",
    "dynamic_menu": "menu", "dynamic_menu_item": "elementMenu",
    "timer": "chrono", "dictionary": "dico", "file": "fichier",
    "pack_file": "paquet", "tts_voice": "voix", "network": "reseau",
    "network_event": "evenement", "vector": "point", "vector3": "point",
    "calendar": "date", "joystick": "manette", "logger": "journal",
    "settings": "reglages", "http": "requete", "instance": "objetJeu",
    "library": "bibliotheque", "library_structure": "structure",
    "tone_synth": "synthe", "pathfinder": "chemin", "combination": "tirage",
    "number_speaker": "diseurNombre", "audio_form": "formulaire",
    "soundtrack": "musiqueFond",
}

#: Prefixes a getter wears, longest first so `get_` beats `get`.
GETTER = ("get_", "is_", "has_", "read_", "fetch_", "get", "is", "has")

#: Functions whose string argument is something spoken to the player.
SPEECH = {
    "dis", "dit", "parle", "alert", "speak", "speak_wait", "speak_interrupt",
    "screen_reader_speak", "screen_reader_speak_interrupt", "input_box",
    "question", "annonce", "say", "speak_to_file", "output", "dis_attends",
}

#: Functions whose string argument names a sound or a file.
ASSET = {
    "joueSon", "joue_son", "stream", "load", "play", "play_stationary",
    "play_1d", "play_2d", "play_3d", "set_sound_storage", "open",
    "play_extended_1d", "play_extended_2d", "play_stationary_extended",
    "file_exists", "file_delete", "chargeSon", "precharge", "joueMusique",
}

#: Names that say nothing.  They are legitimate as a last resort for one
#: slot, and poison as evidence for another: these are the names the pass
#: itself invents when it has nothing, and propagating them through a call
#: spreads one shrug over every call site.  Three of this game's four
#: most-called helpers are decompiled, so their own parameters are invented,
#: and without this their names reached several thousand slots.
NO_INFORMATION = {
    "texte", "valeur", "nombre", "condition", "resultat", "elements",
    "sortie", "valeurGardee", "index", "objet", "liste", "donnees",
    "succes", "message",
}


def says_nothing(name):
    """True when a name is a shrug, with or without a disambiguator."""
    if not name:
        return True
    low = name
    for q in QUALIFIERS:
        if low.startswith(q) and len(low) > len(q):
            low = _lower_first(low[len(q):])
            break
    return low in NO_INFORMATION or bool(SLOT_SHAPED.match(name))


#: Calls whose string key names the slot they fill -- a lookup, and nothing
#: else.  `dictionary::get` and `exists` are the engine's; a game's own
#: wrapper is reached through propagation instead of being guessed at here.
_LOOKUP = {"get", "exists", "get_value", "read", "lis", "recupere", "lit"}

#: Disambiguating prefixes, tried in order when a candidate collides.
QUALIFIERS = ("ancien", "autre", "valeur", "mon", "courant", "second",
              "nouveau", "copie", "local")


def _lower_first(name: str) -> str:
    if not name:
        return name
    if name.isupper() and len(name) > 1:
        return name.lower()
    return name[0].lower() + name[1:]


def _upper_first(name: str) -> str:
    return name[0].upper() + name[1:] if name else name


def _camel(words: Sequence[str]) -> str:
    if not words:
        return ""
    head = _lower_first(words[0])
    return head + "".join(_upper_first(w) for w in words[1:])


def _split_words(name: str) -> List[str]:
    """`set_sound_storage` / `getNbPiece` -> ['set','sound','storage'] etc."""
    parts: List[str] = []
    for chunk in name.split("_"):
        if not chunk:
            continue
        parts.extend(re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+|[A-Z]", chunk))
    return [p for p in parts if p]


def strip_noise(name: str) -> str:
    """Drop a `g_` style prefix and a getter prefix from a name."""
    out = name
    if re.match(r"^[gms]_", out):
        out = out[2:]
    words = _split_words(out)
    if len(words) > 1 and words[0].lower() in ("get", "is", "has", "read",
                                               "fetch", "lis", "recupere"):
        words = words[1:]
    return _camel(words) or _lower_first(out)


def singular(name: str) -> str:
    """The name of one element of a collection called `name`."""
    out = strip_noise(name)
    words = _split_words(out)
    if words and words[0].lower() in ("liste", "listes", "tableau", "tab",
                                      "ensemble", "all", "tous", "toutes"):
        if len(words) > 1:
            return _camel(words[1:])
    low = out.lower()
    if low.endswith("ies") and len(out) > 4:
        return out[:-3] + "y"
    if low.endswith("ses") or low.endswith("xes") or low.endswith("ches"):
        return out[:-2]
    if low.endswith("s") and not low.endswith("ss") and len(out) > 2:
        return out[:-1]
    return out


def plural(name: str) -> str:
    low = name.lower()
    if low.endswith("s") or low.endswith("x"):
        return name
    return name + "s"


# --------------------------------------------------------------------------
# a parsed project

@dataclass
class Param:
    type_: str
    name: str
    default: str = ""
    start: int = 0          # offset of the name within the file
    end: int = 0


@dataclass
class Func:
    path: str
    owner: Optional[str]    # the class it is a method of, else None
    ret: str
    name: str
    params: List[Param]
    body_start: int         # index of the `{`
    body_end: int           # index of the matching `}`
    is_ctor: bool = False

    @property
    def label(self) -> str:
        return "%s::%s" % (self.owner or "<global>", self.name)


@dataclass
class ClassInfo:
    name: str
    base: Optional[str] = None
    members: Dict[str, str] = field(default_factory=dict)   # name -> type
    methods: Set[str] = field(default_factory=set)


def match_brace(masked: str, i: int) -> int:
    """Given the index of a `{`, `(` or `[`, the index of its partner."""
    open_c = masked[i]
    close_c = {"{": "}", "(": ")", "[": "]"}[open_c]
    depth = 0
    n = len(masked)
    while i < n:
        c = masked[i]
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _unwrap(fragment):
    """Drop the braces a statement fragment may be bounded by."""
    return fragment.strip().lstrip("{}").rstrip("{}")


def logical_lines(text: str, masked: str) -> Tuple[List[str], List[str]]:
    """Split a body after every `;`, `{` and `}`, text and mask in step.

    The recovery writes one statement per line, so a line-anchored pattern
    works on its output -- and stops working the moment anything puts two
    statements on one line, which is how `void f() { int x; x = 1; }` hid
    every declaration in it from the shadowing check.  Cutting on the
    language's own statement boundaries instead makes the scan independent of
    the formatting.

    The cuts are chosen from the mask, so a brace or a semicolon inside a
    string literal is never a boundary -- and never from inside brackets
    either, because the two semicolons of a `for` header are not statement
    boundaries and cutting on them loses the loop.
    """
    cuts = [0]
    depth = 0
    for i, c in enumerate(masked):
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth == 0 and c in ";{}\n":
            cuts.append(i + 1)
    cuts.append(len(masked))
    lines, lmasks = [], []
    for a, b in zip(cuts, cuts[1:]):
        if b > a:
            lines.append(text[a:b])
            lmasks.append(masked[a:b])
    return lines, lmasks


def split_top(text: str, masked: Optional[str] = None) -> List[str]:
    """Split on commas that are not inside brackets or a string.

    `masked` lets a caller that already has the mask avoid rebuilding it;
    the project's call sites run this once per argument of every call, which
    on a large title is a hundred thousand times.
    """
    masked = mask(text) if masked is None else masked
    out: List[str] = []
    depth, start = 0, 0
    for i, c in enumerate(masked):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(text[start:i])
            start = i + 1
    tail = text[start:]
    if tail.strip() or out:
        out.append(tail)
    return out


_PARAM = re.compile(
    r"^\s*(?:const\s+)?(.*?[\w@\]>])\s*(?:&\s*(?:in|out|inout)?\s*)?"
    r"\b([A-Za-z_]\w*)\s*(?:=\s*(.*))?$", re.S)

_TYPE_DECL = re.compile(
    r"^(?:const\s+|private\s+)*"
    r"([A-Za-z_]\w*(?:\s*<[^>]*>)?(?:\s*@)?(?:\s*\[\s*\])*(?:\s*@)?)"
    r"\s+(.*)$", re.S)

_CLASS_HEAD = re.compile(
    r"\bclass\s+([A-Za-z_]\w*)\s*(?::\s*([A-Za-z_]\w*)\s*)?\{")


class Project:
    """Every `.bgt` file of a recovered project, with its symbols located."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.files: Dict[str, str] = {}
        self.masked: Dict[str, str] = {}
        self.classes: Dict[str, ClassInfo] = {}
        self.globals: Dict[str, str] = {}
        self.funcs: List[Func] = []
        self.enum_values: Set[str] = set()
        self.func_names: Set[str] = set()
        self._load()
        self._scan()

    # -- loading ----------------------------------------------------------

    def _load(self) -> None:
        for dirpath, _dirs, names in os.walk(self.root):
            for nm in sorted(names):
                if not nm.endswith(".bgt"):
                    continue
                p = os.path.join(dirpath, nm)
                rel = os.path.relpath(p, self.root).replace("\\", "/")
                with open(p, "r", encoding="utf-8", errors="surrogateescape") as fh:
                    text = fh.read()
                self.files[rel] = text
                self.masked[rel] = mask(text)

    # -- scanning ---------------------------------------------------------

    def _scan(self) -> None:
        for rel in sorted(self.files):
            self._scan_file(rel, self.files[rel], self.masked[rel])
        self.func_names = {f.name for f in self.funcs if f.owner is None}

    def _class_spans(self, masked: str) -> List[Tuple[int, int]]:
        spans = []
        for m in _CLASS_HEAD.finditer(masked):
            s = masked.index("{", m.start())
            spans.append((m.start(), match_brace(masked, s)))
        return spans

    def _scan_file(self, rel: str, text: str, masked: str) -> None:
        for m in _CLASS_HEAD.finditer(masked):
            name, base = m.group(1), m.group(2)
            start = masked.index("{", m.start())
            end = match_brace(masked, start)
            ci = self.classes.setdefault(name, ClassInfo(name, base))
            if base and not ci.base:
                ci.base = base
            self._scan_class_body(rel, text, masked, name, start + 1, end)
        for m in re.finditer(r"\benum\s+([A-Za-z_]\w*)\s*\{", masked):
            start = masked.index("{", m.start())
            end = match_brace(masked, start)
            for part in split_top(text[start + 1:end]):
                mm = _IDENT.match(part.strip())
                if mm:
                    self.enum_values.add(mm.group(0))
        self._scan_scope(rel, text, masked)

    def _scan_class_body(self, rel, text, masked, cls, lo, hi) -> None:
        ci = self.classes[cls]
        i = lo
        while i < hi:
            c = masked[i]
            if c in " \t\r\n;":
                i += 1
                continue
            if c == "{":
                nxt = match_brace(masked, i)
                i = (nxt + 1) if nxt > 0 else hi
                continue
            j = i
            while j < hi and masked[j] not in ";{":
                j += 1
            head = text[i:j]
            if j < hi and masked[j] == "{":
                fn = self._parse_signature(rel, text, masked, i, j, owner=cls)
                if fn:
                    ci.methods.add(fn.name)
                    self.funcs.append(fn)
                nxt = match_brace(masked, j)
                i = (nxt + 1) if nxt > 0 else hi
                continue
            for name, type_ in self._parse_decl(head):
                ci.members.setdefault(name, type_)
            i = j + 1

    def _parse_decl(self, head: str) -> List[Tuple[str, str]]:
        head = head.strip()
        if not head or head.startswith(("//", "#")):
            return []
        m = _TYPE_DECL.match(head)
        if not m:
            return []
        type_ = re.sub(r"\s+", "", m.group(1))
        if type_ in ("return", "else", "case"):
            return []
        out = []
        for part in split_top(m.group(2)):
            part = part.strip()
            mm = re.match(r"^@?\s*([A-Za-z_]\w*)", part)
            if mm and mm.group(1) not in KEYWORDS:
                out.append((mm.group(1), type_))
        return out

    def _scan_scope(self, rel, text, masked) -> None:
        """File-scope declarations and functions, skipping class bodies."""
        skip = self._class_spans(masked)
        hi = len(masked)
        i = 0
        while i < hi:
            inside = False
            for a, b in skip:
                if a <= i <= b:
                    i = b + 1
                    inside = True
                    break
            if inside:
                continue
            c = masked[i]
            if c in " \t\r\n;":
                i += 1
                continue
            if c == "{":
                nxt = match_brace(masked, i)
                i = (nxt + 1) if nxt > 0 else hi
                continue
            j = i
            while j < hi and masked[j] not in ";{":
                j += 1
            head = text[i:j]
            if j < hi and masked[j] == "{":
                fn = self._parse_signature(rel, text, masked, i, j, owner=None)
                if fn:
                    self.funcs.append(fn)
                nxt = match_brace(masked, j)
                i = (nxt + 1) if nxt > 0 else hi
                continue
            stripped = head.strip()
            if not stripped.startswith(("funcdef", "#include", "enum", "class",
                                        "typedef", "namespace")):
                for name, type_ in self._parse_decl(head):
                    self.globals.setdefault(name, type_)
            i = j + 1

    def _parse_signature(self, rel, text, masked, lo, brace, owner) -> Optional[Func]:
        head_masked = masked[lo:brace]
        if "(" not in head_masked:
            return None
        popen = lo + head_masked.index("(")
        pclose = match_brace(masked, popen)
        if pclose < 0 or pclose > brace:
            return None
        before = text[lo:popen].rstrip()
        mm = re.search(r"([A-Za-z_]\w*)\s*$", before)
        if not mm:
            return None
        name = mm.group(1)
        if name in NOT_A_FUNCTION_NAME:
            return None
        ret = before[:mm.start(1)].strip()
        params: List[Param] = []
        raw = text[popen + 1:pclose]
        off = popen + 1
        if raw.strip():
            for part in split_top(raw):
                pm = _PARAM.match(part)
                if pm:
                    pname = pm.group(2)
                    pos = None
                    for q in re.finditer(r"\b%s\b" % re.escape(pname), part):
                        pos = q.start()
                    if pos is not None:
                        params.append(Param(
                            type_=re.sub(r"\s+", "", pm.group(1)),
                            name=pname,
                            default=(pm.group(3) or "").strip(),
                            start=off + pos,
                            end=off + pos + len(pname)))
                off += len(part) + 1
        end = match_brace(masked, brace)
        return Func(path=rel, owner=owner, ret=ret, name=name, params=params,
                    body_start=brace, body_end=end,
                    is_ctor=(owner is not None and name == owner))

    # -- queries ----------------------------------------------------------

    def visible_members(self, cls: Optional[str]) -> Set[str]:
        """Every member and method name reachable unqualified inside `cls`."""
        out: Set[str] = set()
        seen: Set[str] = set()
        while cls and cls in self.classes and cls not in seen:
            seen.add(cls)
            ci = self.classes[cls]
            out |= set(ci.members)
            out |= ci.methods
            cls = ci.base
        return out

    def member_type(self, cls: Optional[str], member: str) -> Optional[str]:
        seen: Set[str] = set()
        while cls and cls in self.classes and cls not in seen:
            seen.add(cls)
            ci = self.classes[cls]
            if member in ci.members:
                return ci.members[member]
            cls = ci.base
        return None


# --------------------------------------------------------------------------
# the engine's own parameter names, which are the one external authority

#: The help file names its parameters in English; the game is French, so the
#: ones that recur are translated to keep one language in the output.  A name
#: not in here is used as the engine wrote it, camel-cased.
ENGINE_WORD = {
    "milliseconds": "millisecondes", "filename": "nomFichier",
    "the_string": "texte", "the_search": "recherche",
    "replacement": "remplacement", "replace_all": "toutRemplacer",
    "start_position": "debut", "count": "nombre", "value": "valeur",
    "volume": "volume", "pan": "balance", "pitch": "hauteur",
    "key": "clef", "text": "texte", "index": "index", "position": "position",
    "min": "minimum", "max": "maximum", "looping": "enBoucle",
    "persistent": "persistant", "expression": "expression",
    "directory_name": "nomDossier", "directories": "dossiers",
    "source": "source", "destination": "destination",
    "overwrite": "ecraser", "device_id": "idPeripherique",
    "new_length": "nouvelleTaille", "size": "taille",
    "start_index": "indexDebut", "object": "objet", "list": "liste",
    "days": "jours", "hours": "heures", "minutes": "minutes",
    "seconds": "secondes", "months": "mois", "years": "annees",
    "year": "annee", "month": "mois", "day": "jour", "hour": "heure",
    "minute": "minute", "second": "seconde", "items": "elements",
    "force_encryption": "forcerChiffrement", "message": "message",
    "title": "titre", "prompt": "invite", "default_text": "texteParDefaut",
    "the_list": "liste", "separator": "separateur", "number": "nombre",
    "decimal_places": "decimales", "length": "longueur",
    "x": "x", "y": "y", "z": "z", "width": "largeur", "height": "hauteur",
    "left": "gauche", "right": "droite", "url": "adresse", "host": "hote",
    "port": "port", "data": "donnees", "mode": "mode", "flags": "drapeaux",
    "algorithm": "algorithme", "binary": "binaire", "password": "motDePasse",
    "name": "nom", "path": "chemin", "line": "ligne", "column": "colonne",
    "offset": "decalage", "amount": "quantite", "delay": "delai",
    # the sound pool, which every one of this game's audio helpers forwards to
    "start_pan": "pan", "start_volume": "volume", "start_pitch": "hauteur",
    "listener_x": "x", "listener_y": "y", "listener_z": "z",
    "sound_x": "xSon", "sound_y": "ySon", "sound_z": "zSon",
    "left_range": "porteeGauche", "right_range": "porteeDroite",
    "backward_range": "porteeArriere", "forward_range": "porteeAvant",
    "slot": "slot", "open_mode": "mode", "require_full": "exigeComplet",
    "behind_pitch_decrease": "baisseHauteurArriere",
    "max_distance": "distanceMax", "pan_step": "pasBalance",
    "volume_step": "pasVolume", "start_offset": "decalage",
}

_SIG = re.compile(
    r"^\s*(?:const\s+)?[\w@\[\]<>: ]*?\b([A-Za-z_]\w*)\s*\((.*)\)\s*(?:const)?\s*$")


def engine_params(chm=None, cache=None):
    """Map a function or method name to its documented parameter names.

    A name is **not** a function here: `set` is `dictionary::set(key, value)`
    and `calendar::set(year, month, day, hour, minute, second)`, and nothing
    in a decompiled call says which.  So a position keeps a name only when
    every documented overload of that name agrees on it; otherwise it has
    none.  Keeping the longest overload instead -- which is what this did
    first -- named the argument of every `x.set(v)` in the project after a
    calendar's year.

    That is the rule this file's own history prescribes for a name-keyed
    oracle: it unions, and it never replaces.  A position the documentation
    leaves unnamed is "".
    """
    try:
        api = bgt_api.read(chm, cache)
    except Exception:
        return {}
    seen: Dict[str, List[Set[str]]] = {}

    def take(sig):
        m = _SIG.match(sig.strip())
        if not m:
            return
        name, raw = m.group(1), m.group(2)
        names = []
        if raw.strip():
            for part in split_top(raw):
                part = part.strip()
                if not part:
                    names.append("")
                    continue
                pm = re.match(
                    r"^(?:const\s+)?[\w@\[\]<>?]+(?:\s*&\s*(?:in|out|inout)?)?"
                    r"\s+([A-Za-z_]\w*)", part)
                names.append(pm.group(1) if pm else "")
        slots = seen.setdefault(name, [])
        while len(slots) < len(names):
            slots.append(set())
        for pos, nm in enumerate(names):
            if nm:
                slots[pos].add(nm)

    for sigs in (api.get("functions") or {}).values():
        for sig in sigs:
            take(sig)
    for info in (api.get("types") or {}).values():
        for sig in (info.get("methods") or []):
            take(sig)
    return _unanimous(seen)


def _unanimous(seen):
    """Keep a parameter name only where every overload of that name agrees.

    `seen` is `{name: [ {candidate, ...}, ... ]}`, one set per position.  A
    position the overloads disagree on gets "", because nothing in a
    decompiled call says which overload it is.
    """
    return {name: [next(iter(s)) if len(s) == 1 else "" for s in slots]
            for name, slots in seen.items()}


def read_lexicon(path):
    """Load a per-title lexicon: `{"params": {name: [parameter, ...]}}`.

    Some of a game's own helpers cannot be named from anything the engine
    documents, because what their parameters *mean* is only in their bodies:
    `att(duree, enSaisie)` guards exactly the hotkeys that collide with
    typing, and `disl(clef, remplacement1..6)` substitutes `%1`..`%6`.  Those
    readings are a fact about one title, so they are data rather than code --
    this toolkit holds no per-title findings -- and a lexicon is how a reader
    hands them in.

    An entry wins over every inference except a parameter stored straight
    into a member, because it was read out of the body by a person and
    checked against the call sites, which is the strongest evidence short of
    debug information.  A position to leave alone is "".
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out = {}
    for name, names in (data.get("params") or {}).items():
        if isinstance(names, list):
            out[name] = [str(x or "") for x in names]
    return out


def engine_methods(chm=None, cache=None):
    """`{type: {method: [parameter name, ...]}}`, from the help file.

    The unanimity rule in `engine_params` is what keeps a name honest when
    nothing says which type a method belongs to -- and it costs real names:
    `dictionary::get(key, value)` loses `key` to some other type's `get`.
    Where the receiver's type *is* knowable from the text, that type's own
    signature is authoritative and no unioning is needed.
    """
    try:
        api = bgt_api.read(chm, cache)
    except Exception:
        return {}
    out: Dict[str, Dict[str, List[str]]] = {}
    for tname, info in (api.get("types") or {}).items():
        table = out.setdefault(tname, {})
        for sig in (info.get("methods") or []):
            m = _SIG.match(sig.strip())
            if not m:
                continue
            names = []
            if m.group(2).strip():
                for part in split_top(m.group(2)):
                    pm = re.match(
                        r"^\s*(?:const\s+)?[\w@\[\]<>?]+"
                        r"(?:\s*&\s*(?:in|out|inout)?)?\s+([A-Za-z_]\w*)",
                        part)
                    names.append(pm.group(1) if pm else "")
            if m.group(1) not in table or len(names) > len(table[m.group(1)]):
                table[m.group(1)] = names
    return out


def engine_globals(chm=None, cache=None):
    """Every name that resolves bare in a script: engine functions and types."""
    try:
        api = bgt_api.read(chm, cache)
    except Exception:
        return set()
    out = set(api.get("functions") or {})
    out |= set(api.get("types") or {})
    return out


def engine_word(name):
    """The engine's parameter name, in the output's own language."""
    if name in ENGINE_WORD:
        return ENGINE_WORD[name]
    return _camel(_split_words(name)) or name


# --------------------------------------------------------------------------
# the slots of one function, and what the body says about each

PLACEHOLDER = re.compile(
    r"\b(?:local_\d+|arg\d+|tmp\d+|__nvgt_[a-z]+_\d+(?:_\d+)?)\b")

#: A name that still carries a slot number, however it got there.  Refusing
#: only `PLACEHOLDER` is not enough: `singular("local_23")` is `local23`,
#: which no longer matches it, so 1,318 names in one title came out as
#: `local2` or `ancienLocal67` -- a placeholder with the honesty filed off.
SLOT_SHAPED = re.compile(
    r"^(?:ancien|autre|valeur|mon|courant|second|nouveau|copie|local)?"
    r"(?:local|arg|tmp|Local|Arg|Tmp)_?\d+$")

#: An argument the project wraps in one numeric conversion.  The game's own
#: helpers forward their parameters to the engine through these -- `joueSon`
#: hands `float(valeur)` to `play_stationary_extended`, whose third parameter
#: the help file names `start_pan` -- so an exact-match test on a bare
#: placeholder cannot see the one call that would name it.
_CONVERSION = re.compile(
    r"^\s*(?:int|uint|int8|int16|int64|uint8|uint16|uint64|double|float"
    r"|string)\s*\(\s*(" + PLACEHOLDER.pattern + r")\s*\)\s*$")


def _bare_slot(fragment):
    """The name of the slot an argument is, through at most one conversion.

    Returns the slot's own name -- not the text of the conversion around it,
    which is what the first version handed back, so every wrapped argument
    looked up a slot called `float(arg5)` and found nothing.
    """
    m = PLACEHOLDER.fullmatch(fragment.strip())
    if m:
        return m.group(0)
    m = _CONVERSION.match(fragment)
    return m.group(1) if m else None


# Priorities.  A smaller number wins.  Propagation sits at 50 so that it beats
# only the type fallback and the weakest role evidence.
P_MEMBER_TARGET = 10     # a parameter stored into a member is named after it
P_HELPER_PARAM = 12      # a lexicon entry for one of the game's own helpers
P_CTOR_LITERAL = 13      # @x = Tile("vegetation", ...)
P_CTOR = 14              # @x = Joueur(...)
P_MEMBER_READ = 16       # x = this.nbPiece
P_STORED_INTO = 17       # nbPiece = x, the other way round
P_COMPARED = 18          # if (x == nbQuestion)
P_DICT_KEY = 18          # d.get("voice.pitch", x)
P_RETURNED = 35          # return x, in a function that has a name
P_INDEX_READ = 20        # x = listeJoueur[i]
P_THIS = 11              # @x = this
P_GETTER = 22            # x = j.getPseudo()
P_LOOP = 19              # a for counter, which outranks what it indexes
P_LITERAL_ROLE = 30      # a string that is spoken, or that names an asset
P_BOOL_GATE = 32         # a bool that guards a block, named for what it guards
P_CALL_RESULT = 34       # x = de.jette()
P_ENGINE_PARAM = 40      # the engine documents the parameter it is passed to
P_PROPAGATED = 50        # a game function's parameter name, once known
P_INDEX_ROLE = 60        # only ever used as a subscript
P_LITERAL_PLAIN = 70     # it holds a string literal and nothing says more
P_NULL_ONLY = 80         # a handle only ever set to null, only ever compared
P_TYPE = 90              # the declared type, which is always known


@dataclass
class Slot:
    name: str
    kind: str                      # 'param' or 'local'
    type_: str = ""
    cands: List[Tuple[int, str]] = field(default_factory=list)
    arg_of: List[Tuple[str, int]] = field(default_factory=list)
    final: str = ""

    def offer(self, priority, name):
        """Record a candidate, unless it is derived from another placeholder.

        A rule that reads a name out of the code can pick up a slot that has
        not been renamed yet -- `local_1 = arg0[i]` offered `singular("arg0")`,
        which is `arg0`, so the slot kept a placeholder for a name and the
        whole point was lost.  Nothing derived from a placeholder is evidence
        about anything, so it is refused here, in the one place every rule
        goes through.
        """
        if name and _IDENT.fullmatch(name) and not SLOT_SHAPED.match(name):
            self.cands.append((priority, name))

    def best(self):
        """The best candidate: lowest priority, and on a tie the first seen.

        The tie used to go to the shorter word, which is arbitrary -- it made
        a plain `texte` beat the `message` that a speech call had just
        established.  Insertion order is at least the order the body reads in.
        """
        if not self.cands:
            return None
        return min(enumerate(self.cands), key=lambda iv: (iv[1][0], iv[0]))[1][1]


#: An argument the project wraps in one numeric conversion.  The game's own
#: wrappers forward their parameters to the engine through these -- `joueSon`
#: hands `float(valeur)` to `play_stationary_extended`, whose third parameter
#: the help file names `start_pan` -- so an exact-match test on a bare
#: placeholder cannot see the one call that would name it.
_CONVERSION = re.compile(
    r"^\s*(?:int|uint|int8|int16|int64|uint8|uint16|uint64|double|float"
    r"|string)\s*\(\s*(" + PLACEHOLDER.pattern + r")\s*\)\s*$")


def _bare_slot(fragment):
    """The name of the slot an argument is, through at most one conversion.

    Returns the slot's own name -- not the text of the conversion around it,
    which is what the first version handed back, so every wrapped argument
    looked up a slot called `float(arg5)` and found nothing.
    """
    m = PLACEHOLDER.fullmatch(fragment.strip())
    if m:
        return m.group(0)
    m = _CONVERSION.match(fragment)
    return m.group(1) if m else None


_KEY_SPLIT = re.compile(r"[^0-9A-Za-z]+")


def _dict_key_name(literal):
    """A dictionary key as a variable name: "voice.pitch" gives pitch."""
    body = literal.strip()
    if len(body) < 2 or not body.startswith('"'):
        return ""
    body = body[1:-1] if body.endswith('"') else body[1:]
    if "\\x" in body or len(body) > 40:
        return ""
    words = [w for w in _KEY_SPLIT.split(body) if w]
    if not words or len(words) > 4:
        return ""
    name = _camel(words)
    if not name or not re.match(r"^[A-Za-z_]", name):
        return ""
    return name


class BodyNamer:
    """Reads one function body and offers a name for each of its slots."""

    def __init__(self, proj, fn, eng_params, eng_methods=None, lexicon=None):
        self.p = proj
        self.fn = fn
        self.eng = eng_params
        self.eng_methods = eng_methods or {}
        self.lexicon = lexicon or {}
        #: Declared types of this body's own non-placeholder locals, so a
        #: receiver like `menu` resolves as well as a renamed slot does.
        self.locals_types = {}
        self.text = proj.files[fn.path]
        self.masked = proj.masked[fn.path]
        self.body = self.text[fn.body_start:fn.body_end + 1]
        self.body_masked = self.masked[fn.body_start:fn.body_end + 1]
        self.slots = {}
        #: `slot -> {slot, ...}`, slots the body shows to hold one value.
        self.aliases = {}
        #: Slots assigned from a clock reading, so a comparison against one
        #: says the other side is a duration.
        self.clocks = set()
        #: Slots whose every assignment is the literal `null`.
        self.null_only = {}
        self.members = proj.visible_members(fn.owner)
        for prm in fn.params:
            if PLACEHOLDER.fullmatch(prm.name):
                self.slots[prm.name] = Slot(prm.name, "param", prm.type_)
        for m in PLACEHOLDER.finditer(self.body_masked):
            self.slots.setdefault(m.group(0), Slot(m.group(0), "local"))
        for m in _BODY_DECL.finditer(self.body_masked):
            if m.group(1) in self.p.classes or m.group(1) in TYPE_NOUN:
                self.locals_types.setdefault(m.group(3),
                                             m.group(1) + m.group(2))

    # -- helpers ----------------------------------------------------------

    def _is_type(self, word):
        return (word in self.p.classes or word in TYPE_NOUN
                or word in ("array", "void"))

    def _lexicon_for(self, owner, name):
        """A lexicon entry for `owner::name`, else for `name` alone.

        An owner-qualified key is what makes an entry safe to write for a
        method: `active` is a card's combat method on one class and something
        else elsewhere, and a bare key would name both.
        """
        if owner:
            seen = set()
            cls = owner
            while cls and cls not in seen:
                seen.add(cls)
                got = self.lexicon.get("%s::%s" % (cls, name))
                if got:
                    return got
                info = self.p.classes.get(cls)
                cls = info.base if info else None
        return self.lexicon.get(name)

    def _agrees(self, slot, stem):
        """False when `stem` names something of a different type than `slot`.

        A name is only worth having if it is true.  Naming a slot after a
        member whose type it does not share produces `double ancienTile` for
        a `Tile@` member's modifier, `int ancienItem` for a sound slot and
        `Terrain@ variationObjectifPathX` for a handle -- and a reader
        grepping for the member lands on hundreds of false hits.

        Unknown on either side is agreement: the check refuses a name it can
        prove wrong, and never one it merely cannot confirm.
        """
        if not slot.type_ or not stem:
            return True
        mine = _clean_type(slot.type_)
        if not mine:
            return True
        theirs = (self.p.member_type(self.fn.owner, stem)
                  or self.p.globals.get(stem)
                  or self.locals_types.get(stem))
        if not theirs:
            return True
        other = _clean_type(theirs)
        if not other or other == mine:
            return True
        # an element of a collection is not the collection
        if slot.type_.count("[]") != theirs.count("[]"):
            return False
        numeric = {"int", "uint", "int8", "int16", "int64", "uint8",
                   "uint16", "uint64", "double", "float", "long"}
        if mine in numeric and other in numeric:
            return True        # a width difference is not a type difference
        return False

    # -- the scan ---------------------------------------------------------

    def scan(self):
        lines, lmasks = logical_lines(self.body, self.body_masked)
        lines = [_unwrap(x) for x in lines]
        lmasks = [_unwrap(x) for x in lmasks]
        counters = []
        for n, (line, lmask) in enumerate(zip(lines, lmasks)):
            if not PLACEHOLDER.search(lmask):
                continue
            self._declaration(lmask)
            self._for_header(lmask, counters)
            self._assignment(line, lmask)
            self._arguments(line, lmask)
            self._subscripts(lmask)
            self._grid(lmask)
            self._bool_gate(lmask, lmasks, n)
            self._member_arithmetic(lmask)
            self._alias(lmask)
            self._duration(lmask)
        self._flow_aliases()
        wanted = self._lexicon_for(self.fn.owner, self.fn.name)
        if wanted:
            for pos, prm in enumerate(self.fn.params):
                s = self.slots.get(prm.name)
                if s is not None and pos < len(wanted) and wanted[pos]:
                    s.offer(P_HELPER_PARAM, wanted[pos])
        for n, slot_name in enumerate(counters):
            s = self.slots.get(slot_name)
            if s:
                s.offer(P_LOOP, "ijklmn"[n] if n < 6 else "compteur%d" % n)
        self._fallbacks()

    def _bool_gate(self, lmask, lmasks, n):
        """`if (x) { dis(...) }` -- a bool is named for what it lets happen.

        A guard flag is one of the commonest parameters in these games and it
        has no other evidence at all: nothing assigns it and nothing compares
        it, so without this it falls through to the type and reads
        `condition`.  What the guarded block *does* is the only thing that
        says what the flag means.
        """
        m = re.match(r"^\s*(?:\}\s*else\s+)?if\s*\(\s*(!?)\s*("
                     + PLACEHOLDER.pattern + r")\s*\)\s*\{?\s*$", lmask)
        if not m:
            return
        s = self.slots.get(m.group(2))
        if s is None or (s.type_ and not s.type_.startswith("bool")):
            return
        for ahead in lmasks[n + 1:n + 4]:
            call = re.search(r"\b([A-Za-z_]\w*)\s*\(", ahead)
            if not call:
                continue
            callee = call.group(1)
            if callee in KEYWORDS:
                continue
            if callee in SPEECH:
                s.offer(P_BOOL_GATE, "annonce")
            else:
                s.offer(P_BOOL_GATE, "doit" + _upper_first(
                    _camel(_split_words(callee))))
            return

    def _alias(self, lmask):
        """`valeur = double(nombre);` -- one quantity held in two slots.

        The decompiler writes a conversion per width change, so a value that
        the source held once is spread over several slots here.  Linking them
        lets evidence found at one end reach the other, which is the only way
        a slot that is merely converted and compared ever gets a name.
        """
        m = re.match(r"^\s*@?\s*(" + PLACEHOLDER.pattern + r")\s*=\s*"
                     r"(?:(?:int|uint|int64|uint64|int8|int16|uint8|uint16"
                     r"|double|float)\s*\(\s*)?@?\s*("
                     + PLACEHOLDER.pattern + r")\s*\)?\s*;\s*$", lmask)
        if not m or m.group(1) == m.group(2):
            return
        self.aliases.setdefault(m.group(1), set()).add(m.group(2))
        self.aliases.setdefault(m.group(2), set()).add(m.group(1))

    def _duration(self, lmask):
        """A number measured against a clock reading is a duration.

        `att` busy-waits on a timer rather than calling the engine's `wait`,
        so nothing documented names its parameter -- and that one parameter
        is passed from hundreds of call sites.  What the body does say is
        that the value is compared with an elapsed time, and the clock read
        is a statement of its own, so the cue has to be remembered across
        lines rather than looked for on one.
        """
        # A value handed to a timer's "has it been this long yet" is a
        # duration outright -- this game's own `att` busy-waits with
        # `hasReached` rather than reading the clock into a slot, so the
        # comparison cue below never sees it.
        for m in re.finditer(r"\b(?:hasReached|has_reached)\s*\(([^()]*"
                             r"(?:\([^()]*\)[^()]*)*)\)", lmask):
            for part in split_top(m.group(1), m.group(1)):
                name = _bare_slot(part)
                if name and name in self.slots:
                    self.slots[name].offer(P_COMPARED, "duree")
        m = re.match(r"^\s*@?\s*(" + PLACEHOLDER.pattern + r")\s*=\s*.*?"
                     r"\b(?:get_elapsed|get_elapsed_seconds|elapsed)\b", lmask)
        if m:
            self.clocks.add(m.group(1))
            s = self.slots.get(m.group(1))
            if s is not None:
                s.offer(P_GETTER, "tempsEcoule")
            return
        cmp_m = re.search(r"(" + PLACEHOLDER.pattern + r")\s*(?:==|!=|<=|>=|<|>)"
                          r"\s*(" + PLACEHOLDER.pattern + r")", lmask)
        if not cmp_m:
            return
        left, right = cmp_m.group(1), cmp_m.group(2)
        for a, b in ((left, right), (right, left)):
            if a in self.clocks and b not in self.clocks:
                s = self.slots.get(b)
                if s is not None:
                    s.offer(P_COMPARED, "duree")

    def _flow_aliases(self, rounds=2):
        """Let a named slot lend its name to the slots holding the same value."""
        for _ in range(rounds):
            moved = 0
            for name, others in self.aliases.items():
                s = self.slots.get(name)
                if s is None:
                    continue
                mine = min((c[0] for c in s.cands), default=P_TYPE)
                for other in others:
                    o = self.slots.get(other)
                    if o is None:
                        continue
                    theirs = min((c[0] for c in o.cands), default=P_TYPE)
                    if theirs < mine and theirs < P_PROPAGATED:
                        best = o.best()
                        if best:
                            s.offer(P_PROPAGATED, best)
                            moved += 1
            if not moved:
                break

    def _member_arithmetic(self, lmask):
        """`nbPiece = nbPiece + x` -- `x` is a variation of that member.

        A `mod...` function takes a delta rather than a new value, so the
        member-target rule cannot name it: there is no `member = x` to see,
        only arithmetic on the member with the parameter in it.
        """
        m = re.match(r"^\s*(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*"
                     r"(\+|-|\*|/)?=\s*(.+);\s*$", lmask)
        if not m or m.group(1) not in self.members:
            return
        member, op, rhs = m.group(1), m.group(2), m.group(3)
        # `nbPiece += p` is the same statement as `nbPiece = nbPiece + p`,
        # and a `mod...` method is written either way; without the compound
        # form the rule misses `modScore`, `modVie`, `modNbMort` and the rest.
        if not op and not re.search(r"\b%s\b" % re.escape(member), rhs):
            return
        stem = _upper_first(strip_noise(member))
        for name in set(PLACEHOLDER.findall(rhs)):
            s = self.slots.get(name)
            if s is not None:
                s.offer(P_COMPARED, "variation" + stem)

    def _declaration(self, lmask):
        m = re.match(r"^\s*(?:const\s+)?([A-Za-z_]\w*(?:\s*<[^>]*>)?"
                     r"(?:\s*@)?(?:\s*\[\s*\])*(?:\s*@)?)\s+@?\s*("
                     + PLACEHOLDER.pattern + r")\s*(;|=)", lmask)
        if not m:
            return
        head = re.sub(r"\s+", "", m.group(1))
        base = re.match(r"^([A-Za-z_]\w*)", head)
        if not base or not self._is_type(base.group(1)):
            return
        s = self.slots.get(m.group(2))
        if s is not None and not s.type_:
            s.type_ = head

    def _for_header(self, lmask, counters):
        m = re.search(r"\bfor\s*\(", lmask)
        if not m:
            return
        open_i = lmask.index("(", m.start())
        close_i = match_brace(lmask, open_i)
        if close_i < 0:
            return
        parts = lmask[open_i + 1:close_i].split(";")
        if len(parts) != 3:
            return
        found = PLACEHOLDER.findall(parts[2]) or PLACEHOLDER.findall(parts[0])
        for cand in found:
            if cand not in counters:
                counters.append(cand)
            break

    def _assignment(self, line, lmask):
        m = re.match(r"^\s*(?:(?:const\s+)?[\w@\[\]<>]+\s+)?@?\s*("
                     + PLACEHOLDER.pattern + r")\s*(?:\+|-|\*|/)?=\s*(.+?);?\s*$",
                     lmask)
        if m:
            a, b = m.start(2), m.end(2)
            self._from_rhs(m.group(1), line[a:b], lmask[a:b])
            return
        m = re.match(r"^\s*@?\s*(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*=\s*("
                     + PLACEHOLDER.pattern + r")\s*;\s*$", lmask)
        if m and (m.group(1) in self.members or m.group(1) in self.p.globals):
            s = self.slots.get(m.group(2))
            stem = strip_noise(m.group(1))
            if s is not None and s.kind == "param":
                s.offer(P_MEMBER_TARGET,
                        (stem + "Initial") if self.fn.is_ctor
                        else ("nouveau" + _upper_first(stem)))
            elif s is not None and self._agrees(s, m.group(1)):
                # a local the body computes and then stores: the member it
                # lands in is what it holds.
                s.offer(P_STORED_INTO, stem)
            return
        # `return x;` -- the function's own name says what it answers
        m = re.match(r"^\s*return\s+@?\s*(" + PLACEHOLDER.pattern
                     + r")\s*;\s*$", lmask)
        if m:
            s = self.slots.get(m.group(1))
            if s is not None:
                stem = strip_noise(self.fn.name)
                s.offer(P_RETURNED, stem if stem and stem != self.fn.name
                        else "resultat")
            return
        # `if (x <op> member)` -- what it is measured against names it
        for m in re.finditer(r"(" + PLACEHOLDER.pattern
                             + r")\s*(?:==|!=|<=|>=|<|>)\s*"
                             r"(?:this\s*\.\s*)?([A-Za-z_]\w*)\b", lmask):
            s = self.slots.get(m.group(1))
            word = m.group(2)
            if (s is not None and (word in self.members
                                   or word in self.p.globals)
                    and self._agrees(s, word)):
                # A bound whose name ends in an axis letter names the axis,
                # not itself: `p < tailleX` makes `p` an x, where naming it
                # after the member makes it the *dimension* -- which is how
                # a grid class's whole public surface came out as
                # `inTerrain(ancienTailleX, ancienTailleY)`.
                axis = re.match(r"^(?:taille|max|min|o[Tt]aille|nb)([XYZ])$",
                                strip_noise(word))
                if axis and (s.type_ or "int").startswith(("int", "uint")):
                    s.offer(P_COMPARED - 1, axis.group(1).lower())
                s.offer(P_COMPARED, strip_noise(word))

    def _from_rhs(self, target, rhs, rmask):
        s = self.slots.get(target)
        if s is None:
            return
        rm = rmask.strip()
        m = re.match(r"^\(?\s*(?:cast\s*<\s*)?([A-Za-z_]\w*)\s*@?\s*>?\s*\(", rm)
        if m and m.group(1) in self.p.classes:
            s.offer(P_CTOR, noun_for_type(m.group(1)))
        m = re.match(r"^\(?\s*(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*\)?$", rm)
        if m:
            word = m.group(1)
            if ((word in self.members or word in self.p.globals)
                    and self._agrees(s, word)):
                s.offer(P_MEMBER_READ, strip_noise(word))
        m = re.match(r"^\(?\s*[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*\.\s*"
                     r"([A-Za-z_]\w*)\s*\)?$", rm)
        if m and self._agrees(s, m.group(1)):
            s.offer(P_MEMBER_READ, strip_noise(m.group(1)))
        # An element read -- and only an element read.  Without the closing
        # bracket this also matched `item[x][y].getSlotSon()`, so an `int`
        # sound slot was named `item` after the two-dimensional `Item@[][]`
        # member it was merely fetched through, and the getter that says what
        # it really is lost to it on priority.
        m = re.match(r"^\(?\s*(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*\[.*\]\s*\)?$",
                     rm)
        if m and not SLOT_SHAPED.match(m.group(1)):
            s.offer(P_INDEX_READ, singular(m.group(1)))
        m = re.search(r"\b([A-Za-z_]\w*)\s*\(", rm)
        if m:
            callee = m.group(1)
            if callee not in KEYWORDS and not self._is_type(callee):
                words = _split_words(callee)
                if words and words[0].lower() in ("get", "is", "has", "lis",
                                                  "recupere", "read"):
                    stem = strip_noise(callee)
                    if self._agrees(s, stem):
                        s.offer(P_GETTER, stem)
                elif s.kind != "param":
                    # A parameter's inbound value is by construction not the
                    # result of a call made inside the body: `round(p, 0)`
                    # names the operation performed on it, not what it holds.
                    s.offer(P_CALL_RESULT,
                            "resultat" + _upper_first(_camel(words)))
        if rm.startswith('"'):
            s.offer(P_LITERAL_PLAIN, "texte")
        # A copy of `this` is unambiguous, and the alternatives are not: the
        # decompiler materialises one in order to pass the object to
        # something, and a role name picked up elsewhere in the body then
        # claims it is a different object -- one came out as `nouveauPartie`
        # for a `Combat@`, naming it after a class it merely has a member of.
        if rm == "this":
            s.offer(P_THIS, "ce" + _upper_first(
                noun_for_type(self.fn.owner or "objet")))
        if rm == "null":
            self.null_only[target] = self.null_only.get(target, 0) + 1
        elif target in self.null_only:
            self.null_only[target] = -99      # it holds something real too

    def _receiver_type(self, lmask, at):
        """The declared type of the receiver of a call starting at `at`.

        Walks back over `a.b[c].d(` and resolves the first link against the
        frame, the class and the globals, then follows each `.member`.  Only
        a type the project or the engine declares is returned, so nothing is
        guessed; an unresolvable receiver answers None and the caller falls
        back to the unanimous table.
        """
        head = lmask[:at]
        chain = re.search(r"((?:[A-Za-z_]\w*|\[[^\[\]]*\])"
                          r"(?:\s*\.\s*(?:[A-Za-z_]\w*|\[[^\[\]]*\]))*)"
                          r"\s*\.\s*$", head)
        if not chain:
            return None
        links = [p.strip() for p in chain.group(1).split(".")]
        if not links:
            return None
        first = links[0]
        arrays = first.count("[")
        base = re.match(r"^([A-Za-z_]\w*)", first)
        if not base:
            return None
        word = base.group(1)
        slot = self.slots.get(word)
        if slot is not None and slot.type_:
            type_ = slot.type_
        elif word == "this" and self.fn.owner:
            type_ = self.fn.owner
        else:
            type_ = (self.p.member_type(self.fn.owner, word)
                     or self.p.globals.get(word)
                     or self.locals_types.get(word))
        if not type_:
            return None
        for link in links[1:]:
            arrays += link.count("[")
            nm = re.match(r"^([A-Za-z_]\w*)", link)
            cur = _clean_type(type_)
            if not nm or cur not in self.p.classes:
                return None
            type_ = self.p.member_type(cur, nm.group(1))
            if not type_:
                return None
        cleaned = _clean_type(type_)
        depth = type_.count("[]") - arrays
        return cleaned if depth <= 0 else None

    def _arguments(self, line, lmask):
        for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", lmask):
            callee = m.group(1)
            if callee in KEYWORDS:
                continue
            open_i = m.end() - 1
            close_i = match_brace(lmask, open_i)
            if close_i < 0:
                continue
            chunk = lmask[open_i + 1:close_i]
            parts = split_top(chunk, chunk)
            parts_real = split_top(line[open_i + 1:close_i], chunk)
            prev_literal, lit_at = "", -1
            for pos, part in enumerate(parts):
                pm = _bare_slot(part)
                real = parts_real[pos] if pos < len(parts_real) else ""
                if pm is None:
                    if re.match(r'^\s*"', part):
                        prev_literal, lit_at = real.strip(), pos
                    continue
                s = self.slots.get(pm)
                if s is None:
                    continue
                s.arg_of.append((callee, pos))
                owner = self._receiver_type(lmask, m.start())
                owner_hint = owner or (self.fn.owner if "." not in
                                       lmask[max(0, m.start() - 1):m.start()]
                                       else None)
                given = self._lexicon_for(owner_hint, callee)
                if given and pos < len(given) and given[pos]:
                    s.offer(P_HELPER_PARAM, given[pos])
                names = None
                if owner:
                    names = (self.eng_methods.get(owner) or {}).get(callee)
                if names is None:
                    names = self.eng.get(callee)
                if names and pos < len(names) and names[pos]:
                    s.offer(P_ENGINE_PARAM, engine_word(names[pos]))
                # The key only names the slot beside it when the call really
                # is a lookup filling that slot.  Offered after any literal,
                # it named all six padding arguments of
                # `lng("vousNulPiece", "", "", ...)` after the key.
                if (prev_literal and pos > 0 and lit_at == pos - 1
                        and (callee in _LOOKUP
                             or pm.startswith("__nvgt_out"))):
                    guess = _dict_key_name(prev_literal)
                    if guess:
                        s.offer(P_DICT_KEY, guess)
                if s.type_.startswith("string"):
                    if callee in SPEECH:
                        s.offer(P_LITERAL_ROLE, "message")
                    elif callee in ASSET:
                        s.offer(P_LITERAL_ROLE, "nomSon")

    def _grid(self, lmask):
        """`tile[a][b]` -- `a` is an x and `b` is a y.

        A grid class's whole public surface takes a coordinate pair, and
        nothing else in the body names it: the parameter is only ever
        compared with `tailleX` and used as a subscript, so the
        member-comparison rule called it `ancienTailleX` -- the *dimension*
        rather than the position in it.

        Gated on the member really having two array levels, so an ordinary
        `listeJoueur[i]` can never be read as a coordinate.
        """
        for m in re.finditer(r"(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*"
                             r"\[\s*([^\[\]]*?)\s*\]\s*\[\s*([^\[\]]*?)\s*\]",
                             lmask):
            owner = m.group(1)
            declared = (self.p.member_type(self.fn.owner, owner)
                        or self.p.globals.get(owner)
                        or self.locals_types.get(owner))
            if not declared or declared.count("[]") < 2:
                continue
            for axis, group in (("x", m.group(2)), ("y", m.group(3))):
                name = _bare_slot(group)
                if name and name in self.slots:
                    self.slots[name].offer(P_COMPARED, axis)

    def _subscripts(self, lmask):
        for m in re.finditer(r"\[\s*(?:int\s*\(\s*)?(" + PLACEHOLDER.pattern
                             + r")\s*\)?\s*\]", lmask):
            s = self.slots.get(m.group(1))
            if s is not None:
                s.offer(P_INDEX_ROLE, "index")

    def _fallbacks(self):
        for s in self.slots.values():
            if s.name.startswith("__nvgt_list"):
                s.offer(P_LITERAL_PLAIN, "elements")
            elif s.name.startswith("__nvgt_ret"):
                s.offer(P_LITERAL_PLAIN,
                        "succes" if s.type_.startswith("bool") else "resultat")
            elif s.name.startswith("__nvgt_out"):
                s.offer(P_LITERAL_PLAIN, "sortie")
            elif s.name.startswith("__nvgt_held"):
                s.offer(P_LITERAL_PLAIN, "valeurGardee")
            if self.null_only.get(s.name, 0) > 0:
                # Only ever `null`: this is the decompiler's own sentinel for
                # `x !is null`, so it must not hold the name the real object
                # under test wants.  Everything it had claimed is dropped.
                s.cands = [c for c in s.cands if c[0] >= P_NULL_ONLY]
                s.offer(P_NULL_ONLY,
                        "nul" + _upper_first(type_noun(s.type_, self.p)))
            s.offer(P_TYPE, type_noun(s.type_, self.p))


def _clean_type(type_):
    """`Joueur@[]` -> `Joueur`: the type with its handle and arrays removed."""
    t = (type_ or "").replace(" ", "").replace("[]", "").replace("@", "")
    return re.sub(r"<.*>", "", t)


def noun_for_type(name):
    """A variable name for a type: `dynamic_menu` gives `menu`.

    A library class is declared in the project like any other, so the
    constructor rule reaches `dynamic_menu` and `sound_pool` -- snake_case
    names that read badly beside the game's own camelCase.  The type noun
    comes first; anything else is camel-cased.
    """
    if name in TYPE_NOUN:
        return TYPE_NOUN[name]
    return _camel(_split_words(name)) or _lower_first(name)


def type_noun(type_, proj):
    """A noun for a declared type: sound@ gives son, Joueur@[] gives joueurs."""
    if not type_:
        return "valeur"
    t = type_.replace(" ", "")
    arrays = t.count("[]")
    t = t.replace("[]", "").replace("@", "")
    t = re.sub(r"<.*>", "", t)
    if t in TYPE_NOUN:
        base = TYPE_NOUN[t]
    elif t in proj.classes:
        base = noun_for_type(t)
    else:
        base = noun_for_type(t) or "valeur"
    if arrays:
        base = "liste" + _upper_first(plural(base))
    return base


# --------------------------------------------------------------------------
# naming the whole project

@dataclass
class Report:
    slots: int = 0
    named: int = 0
    by_source: Dict[str, int] = field(default_factory=dict)
    qualified: int = 0
    repairs: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    #: Shadowing the recovery already had, which this pass neither caused
    #: nor can fix -- reported so a clean run is not confused with a dirty one.
    inherited: List[str] = field(default_factory=list)


SOURCE_OF = {
    P_MEMBER_TARGET: "the member a parameter is stored into",
    P_HELPER_PARAM: "the lexicon, for one of the game's own helpers",
    P_CTOR_LITERAL: "the literal it is constructed with",
    P_CTOR: "the type it is constructed from",
    P_MEMBER_READ: "the member or global it is read from",
    P_STORED_INTO: "the member or global it is stored into",
    P_COMPARED: "the member or global it is compared with",
    P_RETURNED: "the function it is the answer of",
    P_DICT_KEY: "the dictionary key beside it",
    P_INDEX_READ: "the collection it is indexed out of",
    P_GETTER: "the getter that produced it",
    P_LOOP: "a loop counter",
    P_LITERAL_ROLE: "the role of the literal it holds",
    P_BOOL_GATE: "what the block it guards does",
    P_LITERAL_PLAIN: "it holds a string literal",
    P_THIS: "it is a copy of this",
    P_NULL_ONLY: "it is only ever null",
    P_CALL_RESULT: "the call that produced it",
    P_ENGINE_PARAM: "the engine's own parameter name",
    P_PROPAGATED: "the parameter it is passed to",
    P_INDEX_ROLE: "it is only ever a subscript",
    P_TYPE: "its declared type",
}


class Renamer:
    """Names every placeholder slot of a project, then rewrites it."""

    def __init__(self, proj, eng_params=None, eng_names=None,
                 eng_methods=None, lexicon=None):
        self.p = proj
        self.eng = eng_params if eng_params is not None else engine_params()
        self.eng_names = eng_names if eng_names is not None else engine_globals()
        self.eng_methods = (eng_methods if eng_methods is not None
                            else engine_methods())
        self.lexicon = lexicon or {}
        self.report = Report()
        self.namers = {}
        #: One row per slot: where it was, what it became, and on what
        #: evidence.  A name nobody can trace back to a slot is not auditable.
        self.map = []
        #: `(function label, parameter index) -> name`, for propagation.
        self.param_name = {}
        self.base_forbidden = (
            set(KEYWORDS) | set(self.p.classes) | set(self.p.globals)
            | set(self.p.func_names) | set(self.p.enum_values)
            | set(self.eng_names) | set(TYPE_NOUN))

    # -- phase 1: read every body ----------------------------------------

    def analyse(self):
        for fn in self.p.funcs:
            namer = BodyNamer(self.p, fn, self.eng, self.eng_methods,
                              self.lexicon)
            namer.scan()
            self.namers[id(fn)] = namer

    # -- phase 2: propagate ----------------------------------------------

    def propagate(self, rounds=4):
        """Push names along call edges until nothing new is learnt.

        A parameter with no evidence of its own takes the name of an argument
        passed to it, and a local with none takes the name of the parameter it
        is passed to.  Only unnamed slots are filled, so this can never
        override direct evidence.
        """
        for _ in range(rounds):
            learnt = 0
            # a parameter learns from its callers' arguments
            fresh: Dict[Tuple[str, int], Set[str]] = {}
            for fn in self.p.funcs:
                namer = self.namers[id(fn)]
                for pos, prm in enumerate(fn.params):
                    s = namer.slots.get(prm.name)
                    if s is None:
                        continue
                    chosen = s.best()
                    if (chosen and min(c[0] for c in s.cands) < P_TYPE
                            and not says_nothing(chosen)):
                        fresh.setdefault((fn.name, pos), set()).add(chosen)
            # Two overloads of one name are two different parameters at the
            # same position -- this game declares `lng` twice -- so a
            # position only lends a name when every function of that name
            # agrees on it.  Keying on the name alone pushed one overload's
            # name onto the other's callers.
            for key, names in fresh.items():
                if len(names) != 1:
                    continue
                name = next(iter(names))
                if self.param_name.get(key) != name:
                    self.param_name[key] = name
                    learnt += 1
            # a local learns from the parameter it is passed to
            for fn in self.p.funcs:
                namer = self.namers[id(fn)]
                for s in namer.slots.values():
                    if any(c[0] < P_PROPAGATED for c in s.cands):
                        continue
                    for callee, pos in s.arg_of:
                        name = self.param_name.get((callee, pos))
                        if name and callee not in self.eng_names:
                            s.offer(P_PROPAGATED, name)
                            learnt += 1
                            break
            if not learnt:
                break

    # -- phase 3: settle on a name per slot ------------------------------

    def settle(self):
        for fn in self.p.funcs:
            namer = self.namers[id(fn)]
            forbidden = set(self.base_forbidden) | namer.members
            taken = set()
            for prm in fn.params:
                if not PLACEHOLDER.fullmatch(prm.name):
                    taken.add(prm.name)
            for m in _IDENT.finditer(namer.body_masked):
                word = m.group(0)
                if not PLACEHOLDER.fullmatch(word):
                    taken.add(word)
            order = list(fn.params) + []
            names_in_order = [p.name for p in fn.params if p.name in namer.slots]
            for nm in sorted(namer.slots):
                if nm not in names_in_order:
                    names_in_order.append(nm)
            for nm in names_in_order:
                s = namer.slots[nm]
                self.report.slots += 1
                wanted = s.best() or type_noun(s.type_, self.p)
                src = min((c[0] for c in s.cands), default=P_TYPE)
                final = self._unique(wanted, forbidden | taken)
                if final != wanted:
                    self.report.qualified += 1
                s.final = final
                taken.add(final)
                self.report.named += 1
                label = SOURCE_OF.get(src, "its declared type")
                self.report.by_source[label] = \
                    self.report.by_source.get(label, 0) + 1
                self.map.append({
                    "file": fn.path, "function": fn.label, "slot": nm,
                    "name": final, "type": s.type_, "from": label})

    def _unique(self, wanted, used):
        wanted = _lower_first(re.sub(r"\W", "", wanted)) or "valeur"
        if not re.match(r"^[A-Za-z_]", wanted):
            wanted = "valeur" + _upper_first(wanted)
        if wanted not in used:
            return wanted
        # Never stack two disambiguators.  `ancienNouveauObjectifPath` is two
        # prefixes dodging one collision, and it reads as though both words
        # meant something; strip whichever one the name already carries and
        # substitute, rather than prepending a second.
        stem = wanted
        for q in QUALIFIERS:
            if stem.startswith(q) and len(stem) > len(q):
                stem = _lower_first(stem[len(q):])
                break
        for q in QUALIFIERS:
            cand = q + _upper_first(stem)
            if cand not in used:
                return cand
        n = 2
        while True:
            cand = "%s%d" % (wanted, n)
            if cand not in used:
                return cand
            n += 1

    # -- phase 4: rewrite -------------------------------------------------

    def rewrite(self):
        """Apply every settled name, one function at a time, back to front.

        Back to front so that an edit never moves an offset this pass has yet
        to use, which is what keeps the spans the parser recorded valid.
        """
        edits = {}
        for fn in self.p.funcs:
            namer = self.namers[id(fn)]
            mapping = {nm: s.final for nm, s in namer.slots.items() if s.final}
            if not mapping:
                continue
            spans = edits.setdefault(fn.path, [])
            masked = self.p.masked[fn.path]
            for prm in fn.params:
                if prm.name in mapping:
                    spans.append((prm.start, prm.end, mapping[prm.name]))
            lo, hi = fn.body_start, fn.body_end + 1
            for m in PLACEHOLDER.finditer(masked, lo, hi):
                new = mapping.get(m.group(0))
                if new:
                    spans.append((m.start(), m.end(), new))
        for rel, spans in edits.items():
            text = self.p.files[rel]
            # Assemble once.  Splicing the file per edit is quadratic in the
            # number of renames, and a large title has twenty thousand of
            # them in one file -- which is the whole of why this pass looked
            # like it had hung rather than like it was slow.
            pieces, last = [], 0
            for start, end, new in sorted(spans):
                if start < last:
                    continue
                pieces.append(text[last:start])
                pieces.append(new)
                last = end
            pieces.append(text[last:])
            text = "".join(pieces)
            self.p.files[rel] = text
            self.p.masked[rel] = mask(text)

    def run(self):
        self.analyse()
        self.propagate()
        self.settle()
        self.rewrite()
        return self.report


# --------------------------------------------------------------------------
# the one repair: a member initialiser list rendered as a frame slot

_MEMBER_LIST = re.compile(
    r"^([ \t]*)((?:const\s+)?[A-Za-z_]\w*(?:\s*\[\s*\])+(?:\s*@)?)\s+"
    r"([A-Za-z_]\w*)\s*=\s*\{([^{}]*)\}\s*;[ \t]*$", re.M)


def repair_member_lists(proj, report):
    """Put a member's initialiser list back on the member.

    The compiler builds each inner list of a nested initialiser into one
    reused buffer slot and copies it into the member, so the decompiler
    writes the member as `{local_4, local_4, ...}` -- the same slot name
    repeated, which does not even compile at class scope -- and leaves the
    real lists as assignments to that slot in the constructor, each
    overwritten by the next.

    The repair is refused unless every one of these holds, so it can only
    ever fire on the shape it was written for:

    *   every element of the member's list is the same identifier, and that
        identifier is a local of the class's own constructor;
    *   the constructor assigns to that local exactly as many times as the
        member's list has elements, each time from a list local;
    *   nothing else in the constructor reads the slot.
    """
    for rel in sorted(proj.files):
        text = proj.files[rel]
        for _attempt in range(8):
            done = _repair_one(rel, text, report)
            if done is None:
                break
            text = done
        if text != proj.files[rel]:
            proj.files[rel] = text
            proj.masked[rel] = mask(text)


def _brace_group(text, masked, at):
    """The `{...}` starting at `at`, brace-matched through any string."""
    end = match_brace(masked, at)
    return text[at:end + 1] if end > 0 else None


def _repair_one(rel, text, report):
    """One member list repaired, or None when the file holds no more."""
    masked = mask(text)
    for m in _MEMBER_LIST.finditer(masked):
        elements = [e.strip() for e in m.group(4).split(",") if e.strip()]
        if len(elements) < 2 or len(set(elements)) != 1:
            continue
        slot = elements[0]
        if not PLACEHOLDER.fullmatch(slot):
            continue
        member = m.group(3)
        # the stores into that slot, in the order the constructor makes them
        stores = [(mm.start(), mm.end(), mm.group(1)) for mm in re.finditer(
            r"[ \t]*@?\s*%s\s*=\s*(__nvgt_list_\d+_\d+)\s*;[ \t]*\r?\n"
            % re.escape(slot), masked)]
        if len(stores) != len(elements):
            continue
        # the slot must be a write-only staging post: one declaration, N
        # stores, and nothing that reads it
        if len(re.findall(r"\b%s\b" % re.escape(slot), masked)) \
                != len(stores) + 1 + len(elements):
            continue
        decl = re.search(r"[ \t]*[A-Za-z_][\w@\[\]]*\s+@?%s\s*;[ \t]*\r?\n"
                         % re.escape(slot), masked)
        if decl is None:
            continue
        lists = []
        cuts = [(decl.start(), decl.end())]
        for _s, _e, name in stores:
            lm = re.search(r"[ \t]*[A-Za-z_][\w@\[\]]*\s+%s\s*=\s*"
                           % re.escape(name), masked)
            if lm is None:
                break
            group = _brace_group(text, masked, masked.index("{", lm.end() - 1))
            if group is None:
                break
            tail = masked.index(";", lm.end() + len(group) - 1) + 1
            while tail < len(masked) and masked[tail] in "\r\n":
                tail += 1
            lists.append(group)
            cuts.append((lm.start(), tail))
        if len(lists) != len(stores):
            continue
        cuts.extend((s, e) for s, e, _n in stores)
        pad = m.group(1)
        joined = (",\n%s    " % pad).join(lists)
        replacement = "%s%s %s = {\n%s    %s\n%s};" % (
            pad, m.group(2), member, pad, joined, pad)
        cuts.append((m.start(), m.end()))
        pieces, last = [], 0
        for start, end in sorted(cuts):
            pieces.append(text[last:start])
            if start == m.start():
                pieces.append(replacement)
            last = end
        pieces.append(text[last:])
        report.repairs.append(
            "%s: %s keeps the %d initialiser lists its constructor was "
            "overwriting" % (rel, member, len(lists)))
        return "".join(pieces)
    return None


# --------------------------------------------------------------------------
# verification

def verify(before, after, scopes=None):
    """Require the two trees to differ only where a placeholder was renamed.

    Re-lexes both and walks the token streams side by side.  A difference is
    allowed only when the left token is a placeholder and the right one is an
    identifier, and the mapping has to be consistent **within one function**:
    a slot may not become two names there, and two slots may not collapse onto
    one.

    The scope matters, and getting it wrong is what the first version of this
    did: `local_1` in two methods of one class is two unrelated slots, so a
    per-file mapping reported 143 renames as contradictions on a tree that was
    correct.  `scopes` is `{path: [(start, end), ...]}` from the project the
    rename was computed against, which is what says where one slot ends and
    the next begins.
    """
    problems = []
    if set(before) != set(after):
        problems.append("the file list changed")
        return problems
    scopes = scopes or {}
    for rel in sorted(before):
        a = tokens_with_pos(before[rel])
        b = tokens(after[rel])
        if len(a) != len(b):
            problems.append("%s: %d tokens before, %d after"
                            % (rel, len(a), len(b)))
            continue
        spans = sorted(scopes.get(rel, []))
        pairs: Dict[str, str] = {}
        back: Dict[str, str] = {}
        scope = None
        # The tokens arrive in increasing position order, so one pointer into
        # the sorted spans is enough.  Scanning the whole span list per token
        # is what made this the slowest thing in the pass on a large title.
        at_span = 0
        for (x, at), y in zip(a, b):
            while at_span < len(spans) and spans[at_span][1] < at:
                at_span += 1
            here = None
            if at_span < len(spans) and spans[at_span][0] <= at:
                here = spans[at_span]
            if here != scope:
                scope, pairs, back = here, {}, {}
            if x == y:
                continue
            if not PLACEHOLDER.fullmatch(x) or not _IDENT.fullmatch(y):
                problems.append("%s: %r became %r, which is not a rename"
                                % (rel, x, y))
                break
            if pairs.setdefault(x, y) != y:
                problems.append("%s: %s became both %s and %s"
                                % (rel, x, pairs[x], y))
                break
            if back.setdefault(y, x) != x:
                problems.append("%s: %s and %s both became %s"
                                % (rel, back[y], x, y))
                break
    return problems


_BODY_DECL = re.compile(
    r"^\s*(?:const\s+)?([A-Za-z_]\w*)((?:\s*<[^>]*>)?(?:\s*@)?"
    r"(?:\s*\[\s*\])*(?:\s*@)?)\s+@?\s*([A-Za-z_]\w*)\s*(?:;|=[^=])", re.M)


def collisions(proj):
    """Any local or parameter that would shadow something visible.

    The recovery writes a member access bare, so a local of the same name
    takes over every unqualified use of that member in the body -- the
    program still compiles and means something else.  This is the check that
    says no name does that, and it must run against the project **as
    written**: a rename changes the length of the text, so a span recorded
    before the rewrite points at the next function afterwards, and the first
    version of this reported eighty renames as shadowing because of it.
    """
    out = []
    base = (set(KEYWORDS) | set(proj.classes) | set(proj.globals)
            | set(proj.func_names) | set(proj.enum_values))
    for fn in proj.funcs:
        masked = proj.masked[fn.path]
        body = masked[fn.body_start:fn.body_end + 1]
        forbidden = base | proj.visible_members(fn.owner)
        declared = set()
        _, stmts = logical_lines(body, body)
        flat = "\n".join(_unwrap(x) for x in stmts)
        for m in _BODY_DECL.finditer(flat):
            if m.group(1) in KEYWORDS and m.group(1) not in (
                    "bool", "int", "int8", "int16", "int64", "uint", "uint8",
                    "uint16", "uint64", "float", "double", "string", "array",
                    "const"):
                continue        # `return x;` is not a declaration
            declared.add(m.group(3))
        for prm in fn.params:
            declared.add(prm.name)
        for name in sorted(declared & forbidden):
            out.append("%s (%s): %s shadows a visible name"
                       % (fn.label, fn.path, name))
    return out


# --------------------------------------------------------------------------
# CLI

def rename_project(root, chm=None, cache=None, repair=True, check=True,
                   names_path=None, lexicon=None):
    """Name every slot of the project at `root`, in place.  Returns a Report."""
    report = Report()

    def write(p):
        for rel, text in p.files.items():
            path = os.path.join(root, rel.replace("/", os.sep))
            with open(path, "w", encoding="utf-8", errors="surrogateescape",
                      newline="") as fh:
                fh.write(text)

    # The repair goes first and on its own.  It has to: it reads the slot name
    # out of the member's list and out of the constructor's stores, and the
    # rename changes one of those and not the other.
    if repair:
        staged = Project(root)
        repair_member_lists(staged, report)
        if report.repairs:
            write(staged)

    proj = Project(root)
    before = dict(proj.files)
    # What the recovery already shadowed is not this pass's doing, and
    # reporting it as a problem makes a clean run look like a dirty one: the
    # decompiler's own generated global initialiser declares a local with the
    # global's own name.  Only a *new* shadow is a problem here.
    was_shadowed = set(collisions(proj)) if check else set()
    scopes: Dict[str, List[Tuple[int, int]]] = {}
    for fn in proj.funcs:
        lo = min([fn.body_start] + [p.start for p in fn.params])
        scopes.setdefault(fn.path, []).append((lo, fn.body_end))
    rn = Renamer(proj, engine_params(chm, cache), engine_globals(chm, cache),
                 engine_methods(chm, cache), lexicon)
    rn.report = report
    rn.run()
    if check:
        report.problems.extend(verify(before, proj.files, scopes))
    write(proj)
    if check:
        # re-read what was written: a span from before the rewrite points at
        # the next function once the text has changed length.
        now = collisions(Project(root))
        report.problems.extend(c for c in now if c not in was_shadowed)
        report.inherited = sorted(set(now) & was_shadowed)
    if names_path:
        with open(names_path, "w", encoding="utf-8") as fh:
            json.dump(rn.map, fh, indent=1, ensure_ascii=False)
    report.counts = {
        "files": len(proj.files),
        "classes": len(proj.classes),
        "globals": len(proj.globals),
        "functions": len(proj.funcs),
    }
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="bgt rename",
        description="give a recovered project's local and parameter slots "
                    "names inferred from what the code does with them")
    ap.add_argument("project", help="the directory bgt recover wrote")
    ap.add_argument("--chm", help="path to bgt.chm, for the engine's own "
                                  "parameter names")
    ap.add_argument("--cache", help="where to keep the unpacked help file")
    ap.add_argument("--no-repair", action="store_true",
                    help="leave a member initialiser list alone")
    ap.add_argument("--no-check", action="store_true",
                    help="skip the token-stream and shadowing checks")
    ap.add_argument("--json", help="write the report here as well")
    ap.add_argument("--names", help="write every slot, its new name and the "
                                    "evidence for it, as JSON")
    ap.add_argument("--lexicon", help="a per-title JSON lexicon naming the "
                                      "parameters of the game's own helpers")
    args = ap.parse_args(argv)

    report = rename_project(args.project, args.chm, args.cache,
                            repair=not args.no_repair, check=not args.no_check,
                            names_path=args.names,
                            lexicon=(read_lexicon(args.lexicon)
                                     if args.lexicon else None))
    print("slots named          %d of %d" % (report.named, report.slots))
    print("needed a qualifier   %d" % report.qualified)
    for label, n in sorted(report.by_source.items(), key=lambda kv: -kv[1]):
        print("  %-44s %d" % (label, n))
    for line in report.repairs:
        print("repair  %s" % line)
    for line in report.inherited:
        print("already %s (the recovery's own, not this pass's)" % line)
    if report.problems:
        print("PROBLEMS (%d):" % len(report.problems))
        for line in report.problems[:40]:
            print("  %s" % line)
    else:
        print("checks               token streams match, nothing shadowed")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"named": report.named, "slots": report.slots,
                       "qualified": report.qualified,
                       "by_source": report.by_source,
                       "repairs": report.repairs,
                       "problems": report.problems}, fh, indent=2)
    return 1 if report.problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
