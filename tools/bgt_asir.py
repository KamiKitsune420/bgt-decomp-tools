"""
bgt_asir -- present a BGT module as the AngelScript IR the decompiler reads.

`as_module` is the BGT reader: it knows both string dialects, every record
layout difference between the two generations of `asCReader` BGT was built
against, and it carries the field trace that `as_write` replays for a
byte-exact rewrite. It yields plain dicts.

`nvgt/asreader.py` is the reader for the *other* engine's modules, and it
yields dataclasses -- `Module`, `TypeInfo`, `DataType`, `Function`, `Instr` --
which `nvgt/decompile.py` consumes to emit compilable source.

This file is the translation between the two, so BGT gets that decompiler
without a second BGT reader existing. Keeping one reader matters for the same
reason `as_write` replays a trace instead of duplicating the format: two models
of one format drift, and the drift is silent.

## Why a BGT module can drive that decompiler at all

Two facts, both checked rather than assumed (see `tests/test_recovery.py`):

* **The opcode tables are the same.** All 200 opcodes BGT's own `asBCInfo[]`
  declares match the newer engine's numbering *and* name exactly. The
  decompiler dispatches on the name, so the instruction layer needs no
  translation -- only the per-build widths, which come from BGT's table rather
  than from the newer one.

* **BGT is the "legacy" generation `asreader` already models.** Its token ids
  are the older `eTokenType` numbering, recovered by `t + (t>=36) + (t>=64)` --
  BGT's 65/68/79/92 are the newer 67/70/81/94, i.e. bool/int/float/double. And
  the only three opcodes whose operand count disagrees are exactly the three
  `asreader`'s legacy mode overrides: `CALLSYS`, `ALLOC` and `CallPtr`, all of
  them pointer-width differences of a 32-bit build.

The operand-count agreement is asserted per module rather than trusted: a
width that silently disagreed would decode every later instruction of that body
wrongly while still producing plausible opcode names.

## What does not survive, and is therefore not invented here

BGT compiles with `noDebugInfo = 1`, so there are no local names, no parameter
names, no line numbers and no script-section names. The IR is built with
`has_debug_info = False`, which is the same path the decompiler takes for a
stripped build -- the one checked by `bgt nvgt libcheck` on 25 stripped library
modules. Object-variable info and try/catch spans *are* kept, because they are
not debug info: they drive temporary lifetimes and object scopes.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

try:                      # installed as a package
    from . import as_module, as_opcodes, bgt_api
    from .nvgt import asreader
except ImportError:       # run directly from a checkout
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvgt"))
    import as_module
    import as_opcodes
    import asreader
    import bgt_api

DataType = asreader.DataType
Function = asreader.Function
GlobalProperty = asreader.GlobalProperty
Instr = asreader.Instr
Module = asreader.Module
TypeInfo = asreader.TypeInfo


SIGNATURE_PARAMS = re.compile(r"\((.*)\)\s*(?:const)?$")
#: The identifier inside a declaration's parameter: `pathfinder_callback@
#: callback` -> `pathfinder_callback`.
_BARE_WORD = re.compile(r"[A-Za-z_]\w*")


def _name_from_registrations(m: Module, exe: str,
                             named: Dict[str, TypeInfo]) -> int:
    """The same naming, read off a runtime instead of the help file.

    The documentation is only available where BGT is *installed*, and
    recovery does not need BGT: the one executable that is always present is
    the game's own, and its registration strings are the whole interface of
    the build that compiled this module.

    The test for "this parameter names a funcdef" is direct rather than
    shaped. A registered **funcdef** is declared the way a function is --
    `int pathfinder_callback(int x, int y, int parent_x, int parent_y,
    string data)` -- so it appears in `registered()` under its own name,
    while a registered **type** never does: a type's constructors and
    factories are all declared under the literal name `f`, with the owner as
    a separate string. So a parameter whose type is itself a registered
    declaration is a callback, and nothing else is.

    An arity that matches more than one overload with *different* answers is
    declined rather than guessed at.
    """
    declarations = bgt_api.registered(exe)
    if not declarations:
        return 0
    count = 0
    for f in m.used_functions:
        if f is None or not f.param_types:
            continue
        holes = [i for i, dt in enumerate(f.param_types)
                 if dt.obj_type is not None
                 and dt.obj_type.name == BUILTIN_FUNCTION]
        if not holes:
            continue
        answers: Dict[int, set] = {i: set() for i in holes}
        for text in declarations.get(f.name, ()):
            match = bgt_api.REGISTRATION.match(text)
            if match is None:
                continue
            params = [p.strip() for p in match.group("params").split(",")
                      if p.strip()]
            if len(params) != len(f.param_types):
                continue
            for i in holes:
                word = _BARE_WORD.search(params[i].replace("const", "", 1))
                if word is not None and word.group() in declarations:
                    answers[i].add(word.group())
        for i in holes:
            if len(answers[i]) != 1:
                continue
            word = answers[i].pop()
            ti = named.get(word)
            if ti is None:
                ti = named[word] = TypeInfo(name=word, kind="app")
            f.param_types[i].obj_type = ti
            count += 1
    return count


def name_engine_funcdefs(m: Module, api: Optional[Dict[str, Any]] = None,
                         exe: Optional[str] = None) -> int:
    """Give the `_builtin_function_` placeholder the name the engine gives it.

    AngelScript records every funcdef-typed value under one placeholder with
    no signature, so a registered callback parameter arrives as
    `_builtin_function_@` and nothing in the module can say which funcdef it
    is. Two sources outside the module can, and both are consulted: the
    engine's documentation (`bgt api pathfinder` gives `bool
    set_callback_function(pathfinder_callback@ callback)`) and, where that
    cannot be read or does not reach, the registration strings in the game's
    own runtime.

    Without it, `pf.set_callback_function(obj.method)` is emitted with the
    bare method and rejected twice over ("Can't pass class method as arg
    directly"), which was the last error left on Crazy Party. With it the
    delegate can be written `pathfinder_callback(obj.method)`.

    **How much surface this has is now measured rather than assumed, and it
    is one name.** Every BGT binary available here -- 1.3, Paladin, Super Egg
    Hunt and Crazy Party at 432 registrations, Psycho Strike's fork at 453,
    Manamon 2's at 509, spanning 2010 to 2019 -- registers exactly one
    funcdef, `pathfinder_callback`, taken by exactly one method,
    `pathfinder::set_callback_function`. Not even the fork that added
    Crypto++ and a newer AngelScript adds a second callback type. So this is
    a complete answer to the question rather than a sample of it.

    This lives on the BGT side on purpose: the sources are BGT's, and the
    decompiler stays an AngelScript decompiler. Returns how many parameters
    were named, and does nothing at all when neither source can be read.
    """
    named: Dict[str, TypeInfo] = {}
    count = 0
    if api is None:
        try:
            api = bgt_api.read()
        except (RuntimeError, OSError):
            api = None
    types: Dict[str, Any] = (api or {}).get("types") or {}
    for f in m.used_functions:
        owner = getattr(f, "object_type", None) if f is not None else None
        if owner is None or not f.param_types:
            continue
        entry = types.get(owner.name)
        if not entry:
            continue
        for line in entry.get("methods") or ():
            head, _, rest = line.partition("(")
            if head.split()[-1:] != [f.name]:
                continue
            match = SIGNATURE_PARAMS.search(line)
            if match is None:
                continue
            documented = [p.strip() for p in match.group(1).split(",") if p.strip()]
            if len(documented) != len(f.param_types):
                continue
            for dt, text in zip(f.param_types, documented):
                if (dt.obj_type is None
                        or dt.obj_type.name != BUILTIN_FUNCTION):
                    continue
                # `pathfinder_callback@ callback` -> the type, handle dropped.
                word = text.split()[0].rstrip("@&")
                if not word or not word[0].isalpha():
                    continue
                ti = named.get(word)
                if ti is None:
                    ti = named[word] = TypeInfo(name=word, kind="app")
                dt.obj_type = ti
                count += 1
            break
    # Whatever the documentation did not reach, the runtime may. It is asked
    # second rather than first because a documented signature carries the
    # parameter *name* as well, and only the help file has that.
    if exe:
        count += _name_from_registrations(m, exe, named)
    return count


class AdapterError(ValueError):
    pass


# Which instruction field each operand of a bytecode type lands in, in the
# order the operands are written. This mirrors asreader's `_read_bytecode`
# exactly; it is spelled out as data here so the operand count can be checked
# against the count BGT's own asBCInfo[] declares.
BC_FIELDS: Dict[str, Tuple[str, ...]] = {
    "asBCTYPE_NO_ARG": (),
    "asBCTYPE_W_ARG": ("w_arg",),
    "asBCTYPE_wW_ARG": ("w_arg",),
    "asBCTYPE_rW_ARG": ("w_arg",),
    "asBCTYPE_DW_ARG": ("dw_arg",),
    "asBCTYPE_QW_ARG": ("qw_arg",),
    "asBCTYPE_rW_DW_ARG": ("w_arg", "dw_arg"),
    "asBCTYPE_wW_DW_ARG": ("w_arg", "dw_arg"),
    "asBCTYPE_W_DW_ARG": ("w_arg", "dw_arg"),
    "asBCTYPE_DW_DW_ARG": ("dw_arg", "qw_arg"),
    "asBCTYPE_wW_rW_ARG": ("w_arg", "w_arg2"),
    "asBCTYPE_rW_rW_ARG": ("w_arg", "w_arg2"),
    "asBCTYPE_wW_W_ARG": ("w_arg", "w_arg2"),
    "asBCTYPE_W_rW_ARG": ("w_arg", "w_arg2"),
    "asBCTYPE_QW_DW_ARG": ("qw_arg", "dw_arg"),
    "asBCTYPE_rW_QW_ARG": ("w_arg", "qw_arg"),
    "asBCTYPE_wW_QW_ARG": ("w_arg", "qw_arg"),
    "asBCTYPE_wW_rW_rW_ARG": ("w_arg", "w_arg2", "qw_arg"),
    "asBCTYPE_wW_rW_DW_ARG": ("w_arg", "w_arg2", "dw_arg"),
    "asBCTYPE_rW_W_DW_ARG": ("w_arg", "w_arg2", "dw_arg"),
    "asBCTYPE_rW_DW_DW_ARG": ("w_arg", "dw_arg", "qw_arg"),
    "asBCTYPE_W_DW_DW_ARG": ("w_arg", "dw_arg", "qw_arg"),
    "asBCTYPE_W_QW_DW_ARG": ("w_arg", "qw_arg", "dw_arg"),
}

MASK = {"w_arg": 0xFFFF, "w_arg2": 0xFFFF, "dw_arg": 0xFFFFFFFF,
        "qw_arg": 0xFFFFFFFFFFFFFFFF}

# A 32-bit build writes a pointer-sized operand as one dword where the 64-bit
# table says quadword. The operand still means the same thing, and
# TranslateFunction reads it from the quadword field, so these three keep the
# 64-bit field assignment -- which is what asreader's legacy mode does.
LEGACY_BC_TYPE = {"ALLOC": "asBCTYPE_QW_DW_ARG",
                  "CALLSYS": "asBCTYPE_DW_ARG",
                  "CallPtr": "asBCTYPE_rW_ARG"}

# The opcodes whose operand is a global pointer: a global property, or (for the
# two that can carry one) a string constant.
GLOBAL_PTR_OPS = ("PGA", "PshGPtr", "LDG", "PshG4", "LdGRdR4",
                  "CpyGtoV4", "CpyVtoG4", "SetG4")


def _slot_fields(bc_type: str) -> Tuple[str, ...]:
    """Which of a bytecode type's operands are frame slots.

    The type's own name says so: `wW` is a slot written, `rW` one read, and a
    plain `W` is some other word -- an object-property index, say. Deriving it
    from the name rather than listing it per opcode keeps the two in step.
    """
    parts = bc_type[len("asBCTYPE_"):-len("_ARG")].split("_")
    return tuple(field for field, part in zip(BC_FIELDS[bc_type], parts)
                 if part in ("wW", "rW"))


SLOT_FIELDS: Dict[str, Tuple[str, ...]] = {
    bc_type: _slot_fields(bc_type) for bc_type in BC_FIELDS}

INT, UINT, I64, U64, FLT, DBL, BOOL, I16 = 70, 77, 73, 80, 81, 94, 67, 72

# Opcodes that name the type of their operands, per slot, in the order
# BC_FIELDS lists them (0 where an operand is not a slot or says nothing).
# AngelScript has a separate opcode per operand type for every arithmetic,
# comparison and two-slot conversion, which makes these authoritative.
TYPED_SLOT_OPS: Dict[str, Tuple[int, ...]] = {}
for _ops, _token in (
        (("ADDi", "SUBi", "MULi", "DIVi", "MODi", "POWi"), INT),
        (("ADDu", "SUBu", "MULu", "DIVu", "MODu", "POWu"), UINT),
        (("ADDf", "SUBf", "MULf", "DIVf", "MODf", "POWf"), FLT),
        (("ADDd", "SUBd", "MULd", "DIVd", "MODd", "POWd"), DBL),
        (("ADDi64", "SUBi64", "MULi64", "DIVi64", "MODi64", "POWi64"), I64),
        (("DIVu64", "MODu64", "POWu64"), U64)):
    for _op in _ops:                      # wW_rW_rW: destination, then both sources
        TYPED_SLOT_OPS[_op] = (_token, _token, _token)
TYPED_SLOT_OPS.update({
    "POWdi": (DBL, DBL, INT),             # double ** int
    # rW_rW comparisons: both operands
    "CMPi": (INT, INT), "CMPu": (UINT, UINT), "CMPf": (FLT, FLT),
    "CMPd": (DBL, DBL), "CMPi64": (I64, I64), "CMPu64": (U64, U64),
    # rW_DW comparisons against an immediate
    "CMPIi": (INT, 0), "CMPIu": (UINT, 0), "CMPIf": (FLT, 0),
    # wW_rW_DW arithmetic with an immediate
    "ADDIi": (INT, INT, 0), "SUBIi": (INT, INT, 0), "MULIi": (INT, INT, 0),
    "ADDIf": (FLT, FLT, 0), "SUBIf": (FLT, FLT, 0), "MULIf": (FLT, FLT, 0),
    # rW unary, acting on the slot itself
    "IncVi": (INT,), "DecVi": (INT,), "NEGi": (INT,), "NEGf": (FLT,),
    "NEGd": (DBL,), "NEGi64": (I64,),
    # wW_rW conversions: destination type, then source type. The in-place
    # ones (iTOf, fTOi, dTOi64 ...) say nothing about a single slot, because
    # the slot holds the source before and the result after.
    "iTOd": (DBL, INT), "uTOd": (DBL, UINT), "fTOd": (DBL, FLT),
    "dTOi": (INT, DBL), "dTOu": (UINT, DBL), "dTOf": (FLT, DBL),
    "i64TOf": (FLT, I64), "u64TOf": (FLT, U64), "fTOi64": (I64, FLT),
    "fTOu64": (U64, FLT), "uTOi64": (I64, UINT), "iTOi64": (I64, INT),
    "i64TOi": (INT, I64),
})

# Opcodes that give a slot's width but not its type. A guess, taken only where
# nothing above fired: AngelScript writes a bool with SetV1 far more often than
# an int8, and a 4-byte slot is an int more often than a float -- and when it
# is wrong the compiler says so, which is why these are kept separate.
WIDTH_SLOT_OPS: Dict[str, int] = {
    "SetV1": BOOL, "WRTV1": BOOL, "RDR1": BOOL,
    "SetV2": I16, "WRTV2": I16, "RDR2": I16,
    "SetV4": INT, "CpyVtoV4": INT, "PshV4": INT, "WRTV4": INT, "RDR4": INT,
    "CpyVtoR4": INT, "CpyRtoV4": INT, "CpyVtoG4": INT, "CpyGtoV4": INT,
    "SetV8": DBL, "CpyVtoV8": DBL, "PshV8": DBL, "WRTV8": DBL, "RDR8": DBL,
    "CpyVtoR8": DBL, "CpyRtoV8": DBL,
    "BNOT": INT, "BAND": INT, "BOR": INT, "BXOR": INT,
    "BSLL": INT, "BSRL": INT, "BSRA": INT,
    "BNOT64": I64, "BAND64": I64, "BOR64": I64, "BXOR64": I64,
    "BSLL64": I64, "BSRL64": I64, "BSRA64": I64,
}

# A slot these touch holds a handle rather than an object: the engine's own
# record says which slots are objects but not which are references to one.
HANDLE_SLOT_OPS = ("RefCpyV", "ClrVPtr", "STOREOBJ", "LOADOBJ")

# The type a funcdef-typed value is recorded under in this generation. In a
# data type it is followed by the whole nested signature, which identifies the
# funcdef; in `objVariableTypes` it stands alone and identifies nothing.
BUILTIN_FUNCTION = "_builtin_function_"


def _s16(value: int) -> int:
    """A frame slot is a signed short; negative offsets are the parameters."""
    return value - 0x10000 if value >= 0x8000 else value


def _token(t: int) -> int:
    """BGT's eTokenType id in the numbering the newer reader uses.

    Two tokens were inserted into `eTokenType` between the two generations, at
    36 (`variadic`) and 64 (`foreach`), so every id at or above those shifts up
    by one. Confirmed from both ends: BGT's own primitive ids (65 bool, 68 int,
    79 float, 92 double, from its shipped class sources and member widths) map
    onto 67/70/81/94, which is what the newer reader calls those types.
    """
    return t + int(t >= 36) + int(t >= 64)


class _Translator:
    """Holds `.module` so asreader's own TranslateFunction port can run on it.

    Instruction resolution -- call targets, string constants, global and
    property names, jump targets -- is `asCReader::TranslateFunction`, and it is
    identical for both engines because the serialised operands are. Rather than
    transcribe it a second time, the two methods are borrowed from the reader
    that already has it.
    """
    _post_process = asreader._Reader._post_process
    _translate_function = asreader._Reader._translate_function

    def __init__(self, module: Module) -> None:
        self.module = module


class Builder:
    def __init__(self, data: bytes, info: Dict[str, Any],
                 opcodes: Dict[int, Dict[str, Any]]) -> None:
        self.data = data
        self.info = info
        self.opcodes = opcodes
        self.m = Module(debug_info=False)
        self.m.bytecode_profile = "bgt_%s" % info["dialect"]
        self._types: Dict[int, TypeInfo] = {}      # id(type_info dict) -> TypeInfo
        self._named: Dict[Tuple[str, str], TypeInfo] = {}
        self._dts: Dict[int, DataType] = {}
        self._fns: Dict[int, Function] = {}
        self._order: List[Function] = []
        # (data type, nested signature record) for every `_builtin_function_`
        self._builtin_functions: List[Tuple[DataType, Dict[str, Any]]] = []
        # The funcdefs this module declares, for the placeholder above.
        self._funcdefs: List[TypeInfo] = []
        self._script_object = (as_module.ASOBJ_SCRIPT_OBJECT_TAGGED
                               if info["dialect"] == as_module.TAGGED
                               else as_module.ASOBJ_SCRIPT_OBJECT)

    # -- types -------------------------------------------------------------

    def _is_interface(self, decl: Dict[str, Any]) -> bool:
        return bool(decl["flags"] & self._script_object) and decl["size"] == 0

    def declared(self, kind: str, name: str, ns: str, **kw: Any) -> TypeInfo:
        """A type the module declares. Registered by name so references find it."""
        ti = self._named.get((ns, name))
        if ti is None:
            ti = TypeInfo(kind=kind, name=name, namespace_=ns, **kw)
            self._named[(ns, name)] = ti
        else:
            ti.kind = kind
            for key, value in kw.items():
                setattr(ti, key, value)
        return ti

    def ti(self, ref: Optional[Dict[str, Any]]) -> Optional[TypeInfo]:
        """Resolve one ReadTypeInfo record to a TypeInfo."""
        if ref is None or "kind" not in ref:       # null, or an unresolved back-ref
            return None
        cached = self._types.get(id(ref))
        if cached is not None:
            return cached

        kind = ref["kind"]
        if kind == "named":
            ti = self._named.get((ref["namespace"], ref["name"]))
            if ti is None:
                ti = self.declared("app", ref["name"], ref["namespace"])
        elif kind == "template":
            # A template instance is a type of its own; its arguments live on
            # the DataType that refers to it.
            ti = TypeInfo(kind="template", name=ref["name"],
                          namespace_=ref.get("namespace", ""))
            # BGT's one template is the array, and its source syntax is `T[]`:
            # the compiler's own registered signatures say so
            # (`string[]@ string_split(const string& in, const string& in,
            # bool)`, read out of bgt.exe). Written `array<string>` it is
            # "Identifier 'array' is not a data type".
            if ref["name"] == "array" and not ref.get("namespace"):
                ti.template_syntax = "suffix"
        elif kind == "subtype":
            ti = TypeInfo(kind="subtype", name=ref["name"],
                          template_typename=ref["name"])
        elif kind == "child":
            owner = self.ti(ref.get("owner"))
            ti = TypeInfo(kind="funcdef", name=ref["name"], parent_class=owner,
                          namespace_=owner.namespace_ if owner else "")
        elif kind == "listpattern":
            ti = TypeInfo(kind="list", name="$list")
        else:                                      # pragma: no cover - guarded above
            raise AdapterError("unknown type-info kind %r" % kind)
        self._types[id(ref)] = ti
        return ti

    def dt(self, d: Optional[Dict[str, Any]]) -> DataType:
        """Resolve one ReadDataType record to a DataType."""
        if d is None or "token" not in d:
            return DataType()
        cached = self._dts.get(id(d))
        if cached is not None:
            return cached
        out = DataType(token_type=_token(d["token"]),
                       is_object_handle=d["handle"],
                       is_handle_to_const=d["const"],
                       is_reference=d["reference"],
                       is_readonly=d["readonly"])
        self._dts[id(d)] = out                     # before subtypes: they may recurse
        ref = d.get("type")
        out.obj_type = self.ti(ref)
        if isinstance(d.get("funcdef"), dict):
            self._builtin_functions.append((out, d["funcdef"]))
        out.template_subtypes.extend(self.subtypes(ref))
        return out

    def subtypes(self, ref: Optional[Dict[str, Any]]) -> List[DataType]:
        """A template reference's arguments, in order.

        `'s'` introduces a whole data type; the other form writes a single
        encoded value, and that value is a **token type**, not an engine type
        id. Psycho Strike's are 65, 68, 75 and 76 -- this generation's bool,
        int, uint and uint8 -- so `int[] get_list_selections(int)` came out as
        `tok0[]`, which is not a type the compiler knows.
        """
        if not isinstance(ref, dict) or ref.get("kind") != "template":
            return []
        out = []
        for sub in ref.get("subtypes", []):
            if "token" in sub:
                out.append(self.dt(sub))
            else:
                out.append(DataType(token_type=_token(sub.get("typeid", 0))))
        return out

    def dt_of_type(self, ref: Optional[Dict[str, Any]],
                   handle: bool = False) -> DataType:
        """A DataType for an object whose record is a bare ReadTypeInfo.

        `objVariableTypes` names a slot's type that way. A template's arguments
        belong to the DataType rather than to the type, so they have to be
        carried across here too -- without them the slot is declared `array@`,
        and this generation has no `array` identifier: its arrays are `T[]`.
        """
        return DataType(token_type=5, obj_type=self.ti(ref),
                        is_object_handle=handle,
                        template_subtypes=self.subtypes(ref))

    # -- functions ---------------------------------------------------------

    def fn(self, rec: Optional[Dict[str, Any]]) -> Optional[Function]:
        """Build (once) the Function for one ReadFunction record."""
        if rec is None or "name" not in rec:       # null marker, or a bad back-ref
            return None
        cached = self._fns.get(id(rec))
        if cached is not None:
            return cached

        params = [self.dt(p) for p in rec.get("params", [])]
        defaults: List[Optional[str]] = list(rec.get("defaults", []))
        # The list is written **last parameter first** (`asCReader` assigns the
        # n-th string read to `defaultArgs[length - n - 1]`), and only the
        # parameters that have one are written, so they are the trailing ones.
        # Reverse, then pad at the front.
        #
        # Read in file order instead, every default lands on the wrong
        # parameter -- which still prints a plausible declaration, and changes
        # what a call that omits an argument does. Paladin's
        # `storyline_scroll(string, bool = true, bool = true, bool = false,
        # STORYLINE_LOOP@ = null)` came out as `bool = null, bool = false,
        # bool = true, STORYLINE_LOOP@ = true`: 220 errors, and the compiler's
        # own candidate line is what showed it.
        defaults = ([None] * max(0, len(params) - len(defaults))
                    + list(reversed(defaults)))
        inout = list(rec.get("inOut", []))
        inout += [0] * max(0, len(params) - len(inout))

        f = Function(name=rec["name"],
                     return_type=self.dt(rec.get("returns")),
                     param_types=params,
                     in_out_flags=inout,
                     default_args=defaults,
                     func_type=rec.get("funcType") or 0,
                     namespace_=rec.get("namespace") or "",
                     flags_byte=rec.get("traits", 0),
                     vf_table_idx=rec.get("vfTableIdx", 0))
        self._fns[id(rec)] = f
        self._order.append(f)
        owner = self.ti(rec.get("owner"))
        if owner is not None:
            if owner.kind == "funcdef":            # a class-scoped funcdef
                f.parent_class = owner.parent_class
            else:
                f.object_type = owner
        f.has_debug_info = False
        f.variable_space = rec.get("stackNeeded", 0)
        f.obj_variable_info = list(rec.get("objInfo", []))
        f.try_catch_info = [(t, c, 0) for t, c in rec.get("tryCatch", [])]
        if rec.get("body"):
            f.bytecode = self.decode(rec["body"], rec["instructions"], rec["name"])
            self.slot_types(f, rec)
        return f

    # -- slot types --------------------------------------------------------

    def slot_types(self, f: Function, rec: Dict[str, Any]) -> None:
        """Fill `f.variables` with one typed, unnamed entry per frame slot.

        The newer engine saves a declaration for every local -- offset and type
        always, name only with debug info -- and that is what tells a
        decompiler which slots are real variables rather than compiler
        scratch. This generation saves it only for *object* locals
        (`objVariableTypes`), so the scalar slots have to be typed from the
        bytecode, which is a sound source for them: AngelScript's arithmetic,
        comparison and conversion opcodes each name their operand type.

        Why it matters beyond readability: a slot with no type cannot be
        declared, so the decompiler folds it into the expressions that read it.
        Folded into *several* reads, a call is then written -- and run -- once
        per read. That is how one body came out as a 21,000-character
        expression calling `enemies_in_range` fourteen times where the source
        called it once.

        Object types come from the engine's own record and win over anything
        inferred; between inferences, a type-tagged opcode beats a width-only
        hint, because `SetV4` is as true of an int as of a float.
        """
        strong: Dict[int, List[int]] = {}
        weak: Dict[int, int] = {}
        handles: set = set()

        for ins in f.bytecode:
            slots = SLOT_FIELDS.get(ins.bc_type, ())
            if ins.name in HANDLE_SLOT_OPS:
                handles.add(_s16(ins.w_arg))
            typed = TYPED_SLOT_OPS.get(ins.name)
            if typed is not None:
                for field, token in zip(BC_FIELDS[ins.bc_type], typed):
                    if token and field in slots:
                        votes = strong.setdefault(_s16(getattr(ins, field)), [])
                        if token not in votes:
                            votes.append(token)
                continue
            width = WIDTH_SLOT_OPS.get(ins.name)
            if width is not None:
                for field in slots:
                    weak.setdefault(_s16(getattr(ins, field)), width)

        variables = []
        for token, offset in ((ov[0], ov[-1]) for ov in rec.get("objVars", [])):
            dt = self.dt_of_type(token, handle=offset in handles)
            if dt.obj_type is not None and dt.obj_type.name == BUILTIN_FUNCTION:
                # The placeholder type a funcdef-typed variable is recorded
                # under. `objVariableTypes` carries no signature with it, so
                # which funcdef it is cannot be read off the record -- and
                # `_builtin_function_@` is not a type any source can name.
                #
                # One funcdef in the module makes it unambiguous. Otherwise
                # the slot is left to whatever the opcodes say, which is the
                # right answer more often than it sounds: a slot recorded as
                # an object *and* used by integer opcodes is a reused slot,
                # and the placeholder is the half that cannot be declared
                # (Paladin's `puck::act` uses slot 9 with RDR4 and PshV4).
                if len(self._funcdefs) != 1:
                    continue
                dt = DataType(token_type=5, obj_type=self._funcdefs[0],
                              is_object_handle=True)
            variables.append(asreader.ScriptVariable(stack_offset=offset, type=dt))
            strong.pop(offset, None)
            weak.pop(offset, None)
        for offset, votes in strong.items():
            if offset <= 0:
                continue
            for token in self._slot_votes(offset, votes, weak):
                variables.append(asreader.ScriptVariable(
                    stack_offset=offset, type=DataType(token_type=token)))
        for offset, token in weak.items():
            if offset > 0 and offset not in strong:
                variables.append(asreader.ScriptVariable(
                    stack_offset=offset, type=DataType(token_type=token)))
        f.variables = variables
        # **This list has no declaration order, and saying so matters.** The
        # newer engine writes one declaration per local in the order the
        # builder declared them, which is what tells a decompiler where the
        # source's own locals stop and the compiler's scratch begins. Nothing
        # here is in that order: object slots come from `objVariableTypes` in
        # record order, and every scalar is appended the first time a typed
        # opcode happens to mention it -- bytecode order, which says nothing
        # about scope. A consumer that reads meaning into it is reading a
        # field that exists and means nothing, so it is flagged rather than
        # left to look like the real thing.
        f.synthetic_variables = True

    @staticmethod
    def _slot_votes(offset: int, votes: List[int],
                    weak: Dict[int, int]) -> List[int]:
        """The declarations to record for one slot, given its evidence.

        One slot serves several source locals, and without debug information
        there is nothing to say which is live where: `clear_pathway` uses slot
        1 as an int it returns *and* as the bool it writes to a `bool&out`
        parameter. Where the evidence is a bool and a number both, both
        declarations are recorded -- which is exactly what the newer format
        would hold for a reused slot, and what the decompiler already reads to
        pick the numeric type and convert the boolean uses. Typed as a bool
        alone it was 104 errors in that one body.

        Any other disagreement keeps the first vote: two numeric types in one
        slot is a width difference the bytecode does not usually make, and
        guessing between them would be a worse answer than the first thing
        seen.
        """
        numeric = [token for token in votes if token != 67]
        if not numeric:
            return votes[:1]
        # The bool evidence can be a width-only one: `clear_pathway` writes
        # slot 1 with SetV1 and WRTV1 -- one byte, through a `bool&out`
        # parameter -- and reads it with RDR4 and CMPIi as the int it returns.
        # The type-tagged int wins the declaration either way; what matters is
        # recording that the slot is also used as a bool, so the boolean uses
        # are converted instead of assigned straight across.
        if 67 in votes or weak.get(offset) == 67:
            return [67, numeric[0]]
        return votes[:1]

    # -- bytecode ----------------------------------------------------------

    def decode(self, span: Tuple[int, int], count: int, where: str) -> List[Instr]:
        """Decode one function body into instructions.

        Positions are dword offsets, using the instruction widths BGT's own
        opcode table declares -- not the 64-bit widths -- so every position and
        every restored jump target is in the units the runtime uses.
        """
        start, end = span
        p, pos = start, 0
        out: List[Instr] = []
        for _ in range(count):
            op = self.data[p]
            p += 1
            bgt = self.opcodes.get(op)
            if bgt is None:
                raise AdapterError("%s: unknown opcode 0x%02X" % (where, op))
            name, bc_type, _size, _stack = asreader.OPCODES[op]
            if name != bgt["name"]:
                raise AdapterError("%s: opcode 0x%02X is %r here and %r there"
                                   % (where, op, bgt["name"], name))
            bc_type = LEGACY_BC_TYPE.get(name, bc_type)
            fields = BC_FIELDS[bc_type]
            # The check that makes the shared table safe: this build's own
            # operand count has to match the one the field layout implies, or
            # every instruction after this one is decoded at the wrong offset.
            if len(fields) != bgt["operands"]:
                raise AdapterError(
                    "%s: %s takes %d operands here, %s implies %d"
                    % (where, name, bgt["operands"], bc_type, len(fields)))
            ins = Instr(pos=pos, op=op, name=name, bc_type=bc_type,
                        size=bgt["dwords"])
            for field in fields:
                v, p = as_module.read_encoded_uint(self.data, p)
                setattr(ins, field, v & MASK[field])
            out.append(ins)
            pos += ins.size
        if p != end:
            raise AdapterError("%s: body decoded to 0x%X, record ends at 0x%X"
                               % (where, p, end))
        return out

    # -- the module --------------------------------------------------------

    def build(self) -> Module:
        info, m = self.info, self.m
        tail = info.get("tail") or {}

        for e in info["enums"]:
            m.enums.append(self.declared("enum", e["name"], e["namespace"],
                                         flags=0, size=e["size"],
                                         enum_values=list(e["members"])))
        for t in tail.get("typedefs", []):
            ti = self.declared("typedef", t["name"], t["namespace"], flags=0)
            ti.typedef_target = DataType(token_type=_token(t.get("token", 0)))
            m.typedefs.append(ti)

        # Class declarations come before anything that can refer to them, so a
        # reference from inside a method body resolves to the same TypeInfo.
        decls = info["classes"]
        for decl in decls:
            self.declared("class", decl["name"], decl["namespace"],
                          flags=0, size=decl["size"],
                          is_interface=self._is_interface(decl),
                          is_shared=bool(decl["flags"] & as_module.ASOBJ_SHARED))

        for rec in info["funcdefs"]:
            f = self.fn(rec)
            if f is not None:
                m.funcdefs.append(f)
                # A funcdef is also a type: a variable or parameter can hold one.
                self._funcdefs.append(self.declared("funcdef", f.name, f.namespace_))

        # Blocks are read interfaces-first, then everything else, and paired to
        # declarations by position within each of those two groups -- the same
        # way phase 3 pairs property tables, and for the same reason: two
        # classes may share a name in different namespaces.
        ifaces = [d for d in decls if self._is_interface(d)]
        others = [d for d in decls if not self._is_interface(d)]
        for decl, block in zip(ifaces + others, info["blocks"]):
            ti = self._named[(decl["namespace"], decl["name"])]
            m.classes.append(ti)
            ti.derived_from = self.ti(block.get("derivedFrom"))
            ti.interfaces = [t for t in (self.ti(i) for i in block["interfaces"]) if t]
            ti.destructor = self.fn(block.get("destructor"))
            for ctor, factory in block["ctors"]:
                cf, ff = self.fn(ctor), self.fn(factory)
                if cf is not None:
                    ti.constructors.append(cf)
                if ff is not None:
                    ti.factories.append(ff)
            ti.methods = [f for f in (self.fn(x) for x in block["methods"]) if f]
            ti.vft = [f for f in (self.fn(x) for x in block["virtuals"]) if f]
            ti.properties = [(p["name"], self.dt(p["type"]), p["flags"])
                             for p in block.get("properties", [])]
            for f in ti.constructors + ti.factories + ti.methods + ti.vft:
                if f.object_type is None:
                    f.object_type = ti

        for g in tail.get("global_properties", []):
            m.globals.append(GlobalProperty(name=g["name"], namespace_=g["namespace"],
                                            type=self.dt(g["type"]),
                                            init_func=self.fn(g.get("init")),
                                            from_module=True))
        m.script_functions = [f for f in (self.fn(r) for r in
                                          tail.get("module_functions", [])) if f]
        m.global_functions = [f for f in (self.fn(r) for r in
                                          tail.get("global_functions", [])) if f]

        m.used_types = [self.ti(t) for t in tail.get("used_types", [])]
        m.used_type_ids = [self.dt(d) for d in tail.get("used_type_ids", [])]
        m.used_functions = [self.fn(r) for r in tail.get("used_functions", [])]
        m.used_globals = [GlobalProperty(name=g["name"], namespace_=g["namespace"],
                                         type=self.dt(g["type"]),
                                         from_module=g["module"])
                          for g in tail.get("used_global_props", [])]
        m.used_strings = [s.decode("latin1") for s in tail.get("used_string_constants", [])]
        m._by_name["__used_obj_props__"] = [
            (self.ti(p["owner"]), p["name"]) for p in tail.get("used_object_props", [])]
        m.saved_functions = list(self._order)
        for f in m.saved_functions:
            m._by_name.setdefault(f.name, f)

        self.mark_inherited(m)
        self.name_funcdef_types(m)
        self.normalise(m)
        _Translator(m)._post_process()
        return m

    def mark_inherited(self, m: Module) -> None:
        """Flag the properties a class inherits rather than declares.

        A derived class's property table opens with its base's table, in the
        base's order, and this generation records no flag to say so -- the
        flags here are only 0 and 1 (private). Re-declared in the derived
        class, every one of them is a "Name conflict ... is an object
        property": 1,700 of Psycho Strike's 1,827 first errors were this.

        The newer format has a bit for it and the renderer already honours
        that bit, so the prefix is marked with the same bit rather than
        dropped -- the entries are still needed to resolve a member access by
        name.
        """
        done: set = set()

        def own(ti: TypeInfo) -> None:
            if id(ti) in done:
                return
            done.add(id(ti))
            base = ti.derived_from
            if base is None or base.kind != "class":
                return
            own(base)
            inherited = [name for name, _, flags in base.properties]
            # Trust the prefix only where it actually is one; a table that
            # does not start with the base's is not understood, and marking it
            # by position would hide a real property.
            prefix = [name for name, _, _ in ti.properties[:len(inherited)]]
            if prefix != inherited:
                return
            ti.properties = [
                (name, dt, flags | (4 if index < len(inherited) else 0))
                for index, (name, dt, flags) in enumerate(ti.properties)]

        for ti in m.classes:
            own(ti)

    def name_funcdef_types(self, m: Module) -> None:
        """Give a funcdef-typed parameter the funcdef's name.

        This generation stores such a parameter as the placeholder type
        `_builtin_function_` followed by a whole nested signature, where the
        newer one names the funcdef directly. The nested signature is what the
        funcdef declares, so it identifies which funcdef this is -- and it has
        to, because `_builtin_function_@` is not a type any source can name.
        """
        by_shape: Dict[str, TypeInfo] = {}
        for f in m.funcdefs:
            ti = self._named.get((f.namespace_, f.name))
            if ti is None:
                continue
            by_shape.setdefault(self._shape(f.return_type, f.param_types), ti)
        if not by_shape:
            return
        for dt, nested in self._builtin_functions:
            shape = self._shape(self.dt(nested.get("returns")),
                                [self.dt(p) for p in nested.get("params", [])])
            match = by_shape.get(shape)
            if match is not None:
                dt.obj_type = match

    @staticmethod
    def _shape(ret: DataType, params: List[DataType]) -> str:
        return "%s(%s)" % (ret.format(), ",".join(p.format() for p in params))

    def normalise(self, m: Module) -> None:
        """Put the operands and names in the form TranslateFunction reads.

        Both differences below are this generation writing the same thing in a
        different place or under a different name -- not a different meaning --
        so they are normalised once here rather than branched on everywhere
        downstream.
        """
        tagged = self.info["dialect"] == as_module.TAGGED
        for f in m.saved_functions:
            # A behaviour's name is `_beh_N_` in this generation and `$behN` in
            # the newer one, for the same N: `_beh_0_` is the constructor (seen
            # with no arguments, with a copy argument and with a parameter
            # list), `_beh_2_` the destructor, and `_beh_3_` the factory, which
            # returns a handle and has no owner.
            if f.name.startswith("_beh_") and f.name.endswith("_"):
                digits = f.name[5:-1]
                if digits.isdigit():
                    f.original_name = f.name
                    f.name = "$beh" + digits
            for ins in f.bytecode:
                if ins.name == "CallPtr":
                    # One operand here, two there, and the variable holding
                    # the funcdef is the *second* one -- which is where
                    # everything downstream looks for it. Left in the first,
                    # the call read slot 0 as its target (`this`) and took the
                    # slot number as the argument count: `this(local_8, <?>,
                    # <?>, ...)` nine times over, in 20 of Paladin's errors.
                    ins.w_arg2, ins.w_arg = ins.w_arg, 0
                elif ins.name == "STR":
                    # STR's string index is a word operand here and a dword one
                    # there. Left in the word field it resolves to whichever
                    # literal sits at index 0 -- a real string, in every body
                    # that has one, which is why this fails quietly.
                    ins.dw_arg = ins.w_arg
                elif tagged and ins.name in GLOBAL_PTR_OPS:
                    # The operand carries a table selector in its low bit in
                    # the newer dialect and no selector at all in the older
                    # one, where a string literal has its own STR opcode.
                    # Pre-shift it so the selector says what the operand meant:
                    # the global-property table.
                    #
                    # Only the pointer-sized field: a global pointer is always
                    # the quadword operand (TranslateFunction reads no other),
                    # and `SetG4` carries the value being stored in the dword
                    # one. Shifting that too rewrote every constant assigned to
                    # a global as 2n+1 -- `const int male = 1` came out as 3,
                    # which is a plausible constant and not a plausible error.
                    ins.qw_arg = ins.qw_arg * 2 + 1


def load(module_path: str, exe_path: Optional[str] = None,
         opcodes: Optional[Dict[int, Dict[str, Any]]] = None) -> Module:
    """Read a recovered BGT module and return it as an AngelScript IR Module."""
    if opcodes is None:
        if exe_path is None:
            raise AdapterError("function bodies need an opcode table: "
                               "pass the game executable or a table")
        opcodes = as_opcodes.extract(exe_path)["table"]
    with open(module_path, "rb") as fh:
        data = fh.read()
    info = as_module.summarize(module_path, opcodes=opcodes)
    if not info.get("tail"):
        raise AdapterError("module tail did not land on EOF: %s"
                           % (info.get("tail_error") or "unknown"))
    m = Builder(data, info, opcodes).build()
    # The engine names the funcdefs the module records only as
    # `_builtin_function_` -- from its documentation where BGT is installed,
    # and otherwise from the registration strings in the game's own runtime,
    # which is the one executable always on hand. Neither available changes
    # nothing.
    name_engine_funcdefs(m, exe=exe_path)
    return m


if __name__ == "__main__":
    mod = load(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    bodies = [f for f in mod.saved_functions if f.bytecode]
    print("profile        %s" % mod.bytecode_profile)
    print("enums          %d" % len(mod.enums))
    print("classes        %d" % len(mod.classes))
    print("funcdefs       %d" % len(mod.funcdefs))
    print("globals        %d" % len(mod.globals))
    print("module funcs   %d" % len(mod.script_functions))
    print("global funcs   %d" % len(mod.global_functions))
    print("bodies         %d  (%d instructions)"
          % (len(bodies), sum(len(f.bytecode) for f in bodies)))
    print("used funcs     %d" % len(mod.used_functions))
    print("used strings   %d" % len(mod.used_strings))
