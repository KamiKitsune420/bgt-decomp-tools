"""Which calls may be dropped: a purity analysis over a saved module.

The decompiler drops an expression whose value nothing reads. That is
behaviour-preserving **only if the expression is pure**, and a call is not
necessarily pure -- `random` advances the generator, `joueSon` plays a
sound, `sound::load` opens a file. So before a lost call can be put back,
something has to answer *which* calls may be dropped, and that is a purity
question rather than a reachability one.

Most of it is computable from the module itself, and the two halves of the
answer come from different places:

* **A script function carries its own bytecode**, so its purity is a
  fixpoint over the call graph: assume every script function pure, then
  repeatedly mark impure any function that writes outside its own frame or
  calls something not yet known pure, until nothing changes. Starting
  optimistic is what makes mutual recursion between two otherwise-pure
  functions come out pure rather than looping.
* **A registered (engine) function has no bytecode at all**, so it needs a
  list. `ENGINE_PURE` below is that list, one checked name at a time.

**The direction of the risk decides every judgement call in this file.** A
name wrongly held pure is a lost call that will never be reported -- the
defect this analysis exists to find, hidden by the instrument meant to find
it. A name wrongly held impure costs one extra statement in the recovered
source. So every rule here is the one that errs toward impure, and
`bgt audit --calls` -- which compares the bytecode's callees against the
recovered text, and owes nothing to this file -- is the independent check
on it.

Public API:

    p = Purity(module)
    p.is_pure(fn)          # may a call to this function be dropped?
    p.is_pure_call(instr)  # ...asked at a call site, which also knows the
                           #    opcode, and so whether the target is the
                           #    function that will actually run
    p.reason(fn)           # the first reason it is impure, or "" if pure
"""
from __future__ import annotations

from typing import Optional

try:                      # installed as a package
    from .asreader import Function, Instr, Module
except ImportError:       # run directly from a checkout
    from asreader import Function, Instr, Module


# ---------------------------------------------------------------------------
# Opcode sets
#
# Every name below is spelled as `tools/nvgt/opcodes.py` spells it, which is
# generated from the pinned angelscript.h rather than transcribed -- so a
# name that is not in that table is not in this file either, and a typo here
# is a set that silently never matches. `_assert_known_opcodes()` at the
# bottom of this module checks each name against `OPCODES`, because a
# pattern that matches nothing does not fail a test, it just makes its own
# branch dead.
# ---------------------------------------------------------------------------

#: Writes to a global, with the destination named in the instruction.
#:
#: There is no `SetG8` and no `CpyVtoG8` in this instruction set -- checked
#: against the generated table, not assumed. A 64-bit global is written
#: through its address instead (`LDG` then `WRTV8`), which `REF_WRITES`
#: catches.
GLOBAL_WRITES = frozenset({"SetG4", "CpyVtoG4"})

#: Writes through an address rather than to a named slot.
#:
#: These are the conservative core of the analysis. `WRTV4` writes wherever
#: the reference register points, and the bytecode does not say where that
#: is: it may be a global, an object member, an `&out` parameter, or one of
#: the function's own locals reached through `GETREF`. **So a function that
#: writes to one of its own locals through a reference is reported impure
#: too.** That costs a few extra statements in the recovered source and
#: cannot cost correctness, which is the trade this whole file is built on.
#:
#: `INC*`/`DEC*` are in the set because they act through the reference
#: register -- `this.c_form[a0].list_length--` is one of them, and it is a
#: write to a member. `IncVi`/`DecVi` are *not*, because they name the
#: variable they increment, so that write is provably frame-local.
#:
#: `COPY` is in the set for the same reason as `WRTV*`: it pops a
#: destination address and copies through it.
#:
#: `PopRPtr` is deliberately absent. It loads the reference register and
#: writes nothing; the write that follows is a `WRTV*` or a `REFCPY`, and
#: both are listed. Reading the register (`RDR*`, `PshRPtr`) is a read.
REF_WRITES = frozenset({
    "WRTV1", "WRTV2", "WRTV4", "WRTV8",
    "REFCPY", "RefCpyV", "COPY",
    "INCi8", "INCi16", "INCi", "INCi64", "INCf", "INCd",
    "DECi8", "DECi16", "DECi", "DECi64", "DECf", "DECd",
})

#: Every opcode that transfers control into another function.
#:
#: `FuncPtr` is not one: it *creates* a delegate, it does not run it. What
#: the caller later does with that delegate is the caller's purity, not
#: this function's.
CALL_OPS = frozenset({
    "CALL", "CALLSYS", "CALLINTF", "CALLBND", "Thiscall1", "CallPtr", "ALLOC",
})

#: Call opcodes whose target cannot be named from the module.
#:
#: `CallPtr` calls the funcdef held in a variable -- the target is whatever
#: delegate was bound into that slot, so nothing is known about it.
#: `CALLBND` calls an imported function, whose body is in another module.
#:
#: `CALLINTF` is here for a reason worth stating, because the operand *does*
#: resolve to a real function and believing it would be wrong.
#: `decompile.py`'s `_calls_a_base_method` records the evidence: for a
#: virtual dispatch the owner the module records is the class that first
#: **declared** the method, not the one that will run. Paladin's
#: `door::door` is `PshVPtr this ; CALLINTF interact::reset`, and the
#: function that runs is `door::reset`. So the resolved callee's purity says
#: nothing about the implementation that executes, and the honest answer is
#: that the target is unknown.
UNKNOWN_TARGET_OPS = frozenset({"CALLINTF", "CALLBND", "CallPtr"})


# -- What this deliberately does not count, and what that costs ------------
#
# Three things a body can do are observable and are not treated as
# impurities, each because counting it would make the analysis answer
# "impure" for essentially every function in the module and so report
# nothing at all. They are the known ceiling on what "pure" means here:
#
# * `FREE`, which releases a reference. AngelScript script classes have no
#   destructors, so for script code there is nothing to run, and a `FREE` of
#   a local temp at the end of its scope is the compiler's own cleanup and
#   appears in nearly every body with a string in it. A registered type
#   whose release does something observable is the gap.
# * `CHKREF`, `ChkRefS`, `ChkNullV`, `ChkNullS`, which raise a script
#   exception on a null pointer -- and a dropped expression raises nothing.
#   They sit in front of almost every member access.
# * `AllocMem`, `SetListSize`, `PshListElmnt`, `SetListType`, which build an
#   initialisation-list buffer. The buffer is a local that `AllocMem` put
#   there, so nothing outside the frame is reached; the element writes
#   themselves go through `PopRPtr`/`WRTV*`, which are counted.
#
# `IncVi`, `DecVi`, `SetV*`, `CpyVtoV*`, `CpyRtoV*`, `CpyGtoV*`, `LDV`,
# `STOREOBJ`, `GETOBJ` and `ClrVPtr` all name the slot they write, so those
# writes are provably frame-local and are not impurities either -- that one
# is a fact about the instruction rather than a concession.


# ---------------------------------------------------------------------------
# The engine set
# ---------------------------------------------------------------------------

#: Registered engine functions that compute a value from their arguments and
#: touch nothing else.
#:
#: **Every name here was put to the engine's own API before being listed**,
#: with `bgt api <name>`, which answers from two sources: the reference
#: pages in `bgt.chm` and the registration strings in `bgt.exe` itself. A
#: name the engine neither documents nor registers is not in this set, and
#: neither is a name whose registration says it can do more than compute.
#:
#: Two mechanical rules decide membership, so that growing the set is a
#: check rather than a judgement:
#:
#: * **A method is listed only if every registered overload of that name is
#:   marked `const`.** AngelScript's `const` on a registered method is the
#:   engine saying the method does not modify the object, and the set is
#:   keyed by bare name, so one non-const overload is enough to keep the
#:   name out. That is what excludes `opIndex` (`T &opIndex(uint)` hands out
#:   a writable reference) and `opCmp` (`int opCmp(const calendar&in)` is
#:   not const).
#: * **A global is listed only if its documented signature takes its inputs
#:   and returns a value**, with no handle to anything the engine owns and
#:   no name that plays, loads, streams, speaks, reads a key, touches a file
#:   or a pack, or carries state between calls.
#:
#: `string_hash`, `string_reverse`, `string_base64_encode` and `string_mid`
#: carry more than a signature's worth of evidence: CLAUDE.md records each
#: being run against the engine and compared byte for byte with Python.
#:
#: This is BGT's interface. NVGT registers its own names, and a name this
#: set does not hold is simply impure -- which is the safe default, so the
#: set needs no NVGT half to be correct, only to be useful there.
ENGINE_PURE = frozenset({
    # -- maths. Documented, every one `double f(double...)`.
    "absolute", "arc_cosine", "arc_sine", "arc_tangent", "ceiling",
    "cosine", "exponent", "floor", "log", "log10", "power", "round",
    "sine", "square_root", "tangent",

    # -- value conversions. `string ascii_to_character(int)`,
    #    `int character_to_ascii(string)`, `string hex_to_string(string)`,
    #    `string number_to_hex_string(double)`,
    #    `string number_to_words(double, bool)`,
    #    `uint crc32(const string&in)`,
    #    `double hex_string_to_number(const string&in)`,
    #    `string url_encode(string)`, `string url_decode(string)`.
    #    The last two are string transforms; `url_get` and `url_post`, which
    #    reach the network, are not here.
    "ascii_to_character", "character_to_ascii", "crc32",
    "hex_string_to_number", "hex_to_string", "number_to_hex_string",
    "number_to_words", "url_decode", "url_encode",

    # -- string functions. Each takes strings and returns a value:
    #    `string string_left(string, uint)`, `double string_len(string)`,
    #    `string string_mid(string, uint, uint)`,
    #    `string string_replace(string, string, string, bool)`,
    #    `int string_contains(string, string, int)`,
    #    `int string_distance(string, string)`,
    #    `string string_hash(string, int, bool)`,
    #    `string string_encrypt(string, string)` and its inverse,
    #    `string[] string_split(string, string, bool)`.
    #    `string_compress`, `string_decompress`: registered, not documented.
    "string_base64_decode", "string_base64_encode", "string_compress",
    "string_contains", "string_decompress", "string_decrypt",
    "string_distance", "string_encrypt", "string_hash",
    "string_is_alphabetic", "string_is_alphanumeric", "string_is_digits",
    "string_is_lower_case", "string_is_upper_case", "string_left",
    "string_len", "string_mid", "string_replace", "string_reverse",
    "string_right", "string_split", "string_to_hex",
    "string_to_lower_case", "string_to_number", "string_to_upper_case",
    "string_trim_left", "string_trim_right",

    # -- container and value-type accessors. Every registered overload of
    #    each name is `const`:
    #      uint length() const            (array, string)
    #      float length() const           (vector)
    #      uint get_length() const / double get_length() const
    #      uint get_size() const / double get_size() const
    #      bool is_empty() const
    #      bool opEquals(const array<T>&in) const, and string/vector/vector3
    #      string opAdd(const string&in) const, and vector/vector3
    #      string opAdd_r(double) const, and int/uint/bool
    #      vector opSub/opMul/opDiv(...) const, and vector3
    "length", "get_length", "get_size", "is_empty",
    "opEquals", "opAdd", "opAdd_r", "opSub", "opMul", "opDiv",
})

#: Names considered and rejected, kept here because the reasons are the
#: argument for the rules above and re-deriving them is not free.
#:
#: * `find` -- all three registered overloads are `const`, and one of them
#:   is `vector[]@ find(int&in, int&in, int&in, int&in, string) const`,
#:   which is `pathfinder::find`. That runs a search that **calls back into
#:   script** through `pathfinder_callback`, so a `const` marker is no
#:   evidence at all here. The clearest example of why a name must be
#:   checked for what it does rather than for how it is spelled.
#: * `opIndex`, `opCmp` -- a non-const registered overload each, see above.
#:   Dropping an `opIndex` would also drop the `Index out of bounds` the
#:   engine raises for a bad index, which is observable.
#: * `opAssign`, `opAddAssign` -- they modify the receiver, as their
#:   registrations say (`string &opAssign(const string&in)`).
#: * `random`, `random_get_state`, `random_set_state` -- `random` advances
#:   the generator, which is exactly the lost call this analysis is for.
#: * `get_last_error`, `get_last_error_text`, `get_call_stack`,
#:   `get_call_stack_size`, `get_sound_master_volume`, `get_sound_storage`
#:   -- they read mutable engine state. Harmless to drop in all likelihood,
#:   and listed nowhere because nothing needs them and the set only grows on
#:   evidence.
#: * `assert` -- documented `bool assert(bool)`, and an assertion that fires
#:   is observable.
#: * `serialize`, `deserialize` -- value transforms, but over a `dictionary`
#:   the engine owns; not needed, so not claimed.
#: * `convert_to_currency`, `position_sound_1d`, `position_sound_2d`,
#:   `position_sound_custom_1d`, `position_sound_custom_2d` -- documented
#:   and registered **nowhere**, because they are BGT's own *library script*
#:   code (`finance.bgt`, `sound_positioning.bgt`). They arrive carrying
#:   bytecode, so the fixpoint answers for them and a list entry would be
#:   answering a question twice.
#: * `maximum`, `minimum` -- this engine neither documents nor registers
#:   either one.
ENGINE_REJECTED = frozenset({
    "find", "opIndex", "opCmp", "opAssign", "opAddAssign",
    "random", "random_get_state", "random_set_state",
    "get_last_error", "get_last_error_text", "get_call_stack",
    "get_call_stack_size", "get_sound_master_volume", "get_sound_storage",
    "assert", "serialize", "deserialize", "garbage_collect",
    "convert_to_currency", "position_sound_1d", "position_sound_2d",
    "position_sound_custom_1d", "position_sound_custom_2d",
    "maximum", "minimum",
})


# asEFuncType (angelscript.h), as `asreader.FUNC_TYPES` names them.
_FT_SYSTEM = 0
_FT_SCRIPT = 1
_FT_INTERFACE = 2
_FT_VIRTUAL = 3
_FT_FUNCDEF = 4
_FT_IMPORTED = 5
_FT_DELEGATE = 6

#: Function types that mean "registered by the application, no bytecode
#: exists anywhere".
#:
#: `6` is in here for a reason that is not obvious from `FUNC_TYPES`, which
#: calls it `delegate`. `asreader._read_used_function` overwrites the stream's
#: funcType with 6 for a `usedFunctions` entry tagged `'a'` or `'s'` -- the
#: application and system tags -- so on a call target, 6 means *registered*.
#: A real delegate is impure anyway, since no delegate name is in
#: `ENGINE_PURE`, so the two readings of 6 agree on the answer.
_REGISTERED_TYPES = frozenset({_FT_SYSTEM, _FT_DELEGATE})


def _signature_key(fn: Function) -> str:
    """The identity a call site and a function body agree on.

    A stub and its body agree on this key by construction rather than by
    luck: `asreader`'s body path (`_read_function`) and its call-operand
    path (`_read_used_function`) both build their `Function` by calling the
    one `_read_function_signature`, so every field this key reads -- return
    type, parameter types, owner, namespace, the `const` bit -- is filled
    from the same stream layout by the same code in both.

    `with_param_names=False` is load-bearing, and parameter names are the
    one thing that does *not* come from there. They survive only in debug
    info, so a body built from a debug build has them and a signature stub
    never does -- keyed with names, no stub would ever find its body, every
    script call would read as unknown, and the analysis would answer
    nothing while still looking like it worked.
    """
    return fn.signature(with_param_names=False)


# There is deliberately no looser fallback key -- no owner-and-arity match,
# no bare name. A fallback can only ever turn an *unresolved* callee, which
# this analysis reports impure, into a resolved one, which it may report
# pure. That is the unsafe direction: a stub matched to the wrong overload is
# a purity answer about some other function, and the cost of being wrong
# there is a lost call that is never reported again. The cost of having no
# fallback is an extra statement in the recovered source.
#
# It was not a hypothetical. A first version of this file carried an
# owner-name-and-arity fallback, and the tests for the exact key all passed
# with the exact key disabled -- the fallback was answering every one of
# them, so the primary identity was untested and the looser rule was doing
# the work. `test_a_signature_mismatched_stub_is_impure` pins its absence.


def _bodies(module: Module):
    """Every distinct Function in the module that carries bytecode.

    Mirrors the walk `asreader._Reader._translate_all` does to find the
    functions it has to translate -- class members and vftable entries,
    global-variable initialisers, module and global functions -- because
    those are exactly the functions with bodies. Identity dedup, since back
    references hand back the same object.
    """
    out = []
    seen = set()

    def take(f: Optional[Function]) -> None:
        if f is not None and id(f) not in seen and f.bytecode:
            seen.add(id(f))
            out.append(f)

    for ti in module.classes:
        take(ti.destructor)
        for group in (ti.constructors, ti.factories, ti.methods, ti.vft):
            for f in group:
                take(f)
    for gp in module.globals:
        take(gp.init_func)
    for f in module.script_functions:
        take(f)
    for f in module.global_functions:
        take(f)
    return out


class Purity:
    """Which functions of one module may have a call to them dropped.

    Construction is free; the analysis runs on the first question asked.
    """

    def __init__(self, module: Module):
        self.module = module
        self._impure: dict = {}      # id(body) -> reason
        self._bodies: list = []
        self._by_signature: dict = {}
        self._ready = False

    # -- the public three ---------------------------------------------------

    def is_pure(self, fn: Optional[Function]) -> bool:
        """May a call to `fn` be dropped when nothing reads its value?

        True only when the analysis can say so: an unresolved callee, a
        registered name that is not in `ENGINE_PURE`, and anything the
        fixpoint could not clear all answer False.
        """
        return not self.reason(fn)

    def reason(self, fn: Optional[Function]) -> str:
        """Why `fn` is impure, or `""` when it is pure.

        The string is for a report, not for parsing.
        """
        self._ensure()
        if fn is None:
            return "callee did not resolve"
        body = self._body_of(fn)
        if body is not None:
            return self._impure.get(id(body), "")
        if fn.func_type in _REGISTERED_TYPES:
            if fn.name in ENGINE_PURE:
                return ""
            return f"registered function {fn.name!r} is not in ENGINE_PURE"
        if fn.func_type == _FT_IMPORTED:
            return f"{fn.name!r} is imported from another module"
        if fn.func_type == _FT_FUNCDEF:
            return f"{fn.name!r} is a funcdef: the bound target is unknown"
        return f"no body found for {_signature_key(fn)!r}"

    def is_pure_call(self, instr: Instr) -> bool:
        """May the call this instruction makes be dropped?

        Separate from `is_pure` because the **opcode** carries evidence the
        callee does not. A `CALL` names one implementation and the resolved
        function is the one that runs; a `CALLINTF` goes through the
        vftable, and the function the module records for it is the class that
        declared the method rather than the override that will execute. A
        `CallPtr`'s target is whatever delegate was bound into a slot.

        An instruction that is not a call at all is pure: it answers the
        question "may this be dropped", and only a call can carry a side
        effect this analysis is about.
        """
        self._ensure()
        if instr.name not in CALL_OPS:
            return True
        if instr.name in UNKNOWN_TARGET_OPS:
            return False
        if instr.name == "ALLOC":
            # `ALLOC`'s second operand is a one-based `usedFunctions` index,
            # and 0 means "this type has no script constructor" -- in which
            # case nothing resolves and the engine's own factory runs, which
            # this analysis cannot see. So a construction is pure only when
            # its constructor resolves and is itself pure. Conservative, and
            # the decompiler handles constructions on its own anyway.
            return instr.func_ref is not None and self.is_pure(instr.func_ref)
        return self.is_pure(instr.func_ref)

    # -- the analysis -------------------------------------------------------

    def _ensure(self) -> None:
        if self._ready:
            return
        self._ready = True
        self._bodies = _bodies(self.module)
        for body in self._bodies:
            self._by_signature.setdefault(_signature_key(body), []).append(body)
        self._fixpoint()

    def _body_of(self, fn: Function) -> Optional[Function]:
        """The body that will run for `fn`, or None if there is none here.

        A call operand does not hand you a body. `asreader._read_used_function`
        builds a fresh `Function` and reads only its signature -- even for a
        module function, where the entry is tagged `'m'` and the real body
        has already been read -- so `instr.func_ref` for a `CALL` of a script
        function is a *stub with an empty `bytecode` list*. Without this
        lookup every script call would read as "no body", every caller would
        be impure, and the analysis would answer nothing.
        """
        if fn.bytecode:
            return fn
        if fn.func_type in _REGISTERED_TYPES or fn.func_type == _FT_IMPORTED:
            return None
        exact = self._by_signature.get(_signature_key(fn))
        if exact and len(exact) == 1:
            return exact[0]
        return None              # absent, or ambiguous: no body at all

    def _fixpoint(self) -> None:
        """Assume every script body pure, then take purity away.

        Optimistic rather than pessimistic, and that is what makes mutual
        recursion terminate with the right answer: two functions that call
        only each other never acquire a reason to be impure, so the loop
        settles with both pure. A pessimistic start would need the same
        number of passes to give the same answer and would have to special-
        case the cycle to avoid calling it impure.
        """
        callees: dict = {}       # id(body) -> [body] for script calls
        for body in self._bodies:
            local = []
            reason = ""
            for ins in body.bytecode:
                name = ins.name
                if name in GLOBAL_WRITES:
                    reason = reason or (
                        f"{name} writes global {ins.global_name or ins.qw_arg}")
                elif name in REF_WRITES:
                    reason = reason or f"{name} writes through a reference"
                elif name in CALL_OPS:
                    target = self._call_target(ins)
                    if isinstance(target, Function):
                        local.append(target)
                    elif target:
                        reason = reason or target
            callees[id(body)] = local
            if reason:
                self._impure[id(body)] = reason

        changed = True
        while changed:
            changed = False
            for body in self._bodies:
                if id(body) in self._impure:
                    continue
                for target in callees[id(body)]:
                    if id(target) in self._impure:
                        self._impure[id(body)] = (
                            f"calls {_signature_key(target)}, which is impure")
                        changed = True
                        break

    def _call_target(self, ins: Instr):
        """What one call instruction calls.

        Returns the callee's body (a `Function` with bytecode) when the call
        is to script code the module holds, `""` when the call is to
        something already known pure, and a reason string otherwise.
        """
        if ins.name in UNKNOWN_TARGET_OPS:
            return f"{ins.name} target is not known from the module"
        fn = ins.func_ref
        if fn is None:
            if ins.name == "ALLOC":
                return "ALLOC with no constructor index: the engine's own factory"
            return f"{ins.name} operand did not resolve to a function"
        body = self._body_of(fn)
        if body is not None:
            return body
        return self.reason(fn)


def _assert_known_opcodes() -> None:
    """Every opcode name in this file must be in the generated table.

    CLAUDE.md records three separate occasions on which a pattern stopped
    matching anything and nothing failed -- a dead branch is not a test
    failure. These sets are the same hazard: a misspelled opcode name is a
    write this analysis never sees, which is a lost call it never reports.
    """
    try:
        from .opcodes import OPCODES
    except ImportError:
        from opcodes import OPCODES
    known = {entry[0] for entry in OPCODES.values()}
    unknown = sorted((GLOBAL_WRITES | REF_WRITES | CALL_OPS
                      | UNKNOWN_TARGET_OPS) - known)
    if unknown:
        raise AssertionError(f"not opcode names: {unknown}")


_assert_known_opcodes()
