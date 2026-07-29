"""
as_lift -- lift annotated AngelScript disassembly to readable pseudo-source.

`as_disasm` names every operand; this turns the instruction stream into
statements. A symbolic stack machine walks each body: opcodes push and pop
expression strings, and a statement is emitted when one completes.

    CALLSYS 291  ; show_game_window     ->    ret = show_game_window(&v1);
    STR 673      ; "Psycho Strike"      ->    v1 = string("Psycho Strike");
    ADDSi 5, 0   ; character::health    ->    v2.health
    JLowZ L0                            ->    if (ret) { ... }

## What survives, and what does not

BGT compiles with `noDebugInfo = 1`, so local names are gone: a local reads as
`v3`, a parameter as `a0`. Function, class, property and enum names survive, as
does every literal, so the shape and the vocabulary of the original are
recoverable but the exact text is not. This is a *reconstruction*, not a decompile
that round-trips.

## Three details that decide whether the output is right

**Comparisons are two-part.** `CMPi` / `CMPIi` write a flag register and the
*following* conditional jump reads it. Lifting the compare as a statement and
the jump as a bare `cond` loses the condition entirely.

**`JLowZ` / `JLowNZ` do not follow a compare at all.** They test the low byte of
the value register, which is the shape a bool-returning call leaves behind, so
the condition is the preceding call's result rather than any comparison.

**Pop the callee's declared arity, from the top.** Draining the operand stack
instead sweeps up whatever a construct modelled imperfectly left behind. Popping
a known count from the top leaves that residue underneath, where it is ignored
rather than turned into a phantom argument. Arity comes from the callee's own
signature record, which `as_module` already recovered.

Registered functions that return an object are called through the C++ ABI and
take a hidden pointer to the return slot; script functions return through the
object register and do not. That is why the hidden argument is modelled on
`CALLSYS` only.

## Registers, not just a stack

AngelScript's VM has a value register, an object register and a **reference
register**, and several opcodes touch those instead of the stack. Modelling them
as pushes is the single biggest source of imbalance:

    LoadThisR    this->prop into the reference register   stackInc 0
    LDG          a global into the reference register     stackInc 0
    WRTV*        write a variable THROUGH that register   stackInc 0
    RDR*         read it back into a variable             stackInc 0

Treating `LoadThisR` as a push strands one value on every use -- 2,414 of them in
Psycho Strike alone -- and `WRTV4` then pops something unrelated, so the write
lands on the wrong target.

## Checking the stack model

`asBCInfo[].stackInc` is read from the game's own binary, so for every
fixed-shape opcode it is the authoritative answer to "what should this do to the
stack", and the lifter can be diffed against it mechanically. It is *not* the
reference for the variadic ones -- `CALL`, `CALLSYS`, `CALLINTF` and `ALLOC`
depend on the callee -- and it counts stack slots where this model counts values,
so a 64-bit push is +2 there and one expression here.

The end-to-end check is the stack being empty at `RET`. Across the three titles:

    Psycho Strike       1,080 / 1,102 functions  (98.0%)
    Paladin of the Sky    919 /   926            (99.2%)
    Manamon 2           9,510 / 9,924            (95.8%)

A `?&in` parameter (token 59) is worth its own note: it is AngelScript's
variable-argument type and the caller pushes the VALUE **and** its TYPE ID, so
one declared parameter occupies two stack slots. Only three functions in this
corpus take one -- dictionary::set, dictionary::get, library::call -- but the
rule is mechanical, derivable from the signature, and worth 82 balanced bodies.

Residue never corrupts what is emitted -- it sits *below* the popped arity, so it
is skipped rather than turned into a phantom argument -- but it is the honest
measure of what is still approximate.

## Structuring

`structure()` is real structural analysis, not pattern-spotting: a CFG over the
instruction stream, iterative dominators and post-dominators, natural loops from
back edges, then nested `if` / `else` / `while` / `do-while` with `break` and
`continue`. Anything that does not reduce stays a labelled `goto`.

    residual gotos    2,676 / 264,309 statements  (1.01%)
    goto-free bodies  84.1% strike · 89.2% paladin · 94.6% Manamon 2

Three shapes decide whether the output is right, and each was wrong first:

- **Branch-over is the common case.** The compiler emits `if (!c) goto after;`
  around a guarded block, so the conditional jumps *to* the reconvergence point
  and the guarded body is the fallthrough. Read as written it produces an empty
  `if` with the body dangling after it -- valid structure, wrong about what is
  conditional.
- **A header that is also the latch is a `do-while`.** Emitting its statements
  before a `while` instead runs them once and then spins on an empty body.
- **A pre-tested loop re-evaluates its condition every iteration**, so whatever
  the header computes has to stay inside the loop. Hoisting it above the `while`
  runs it once. Where the header has statements this emits
  `while (true) { ...; if (!c) break; ... }` rather than pretending otherwise.

Checked against source nobody here wrote -- BGT ships its own library sources:
`dynamic_menu::run_extended` recovers the same three nested guards in the same
order as `dynamic_menu.bgt`, `set_speech_mode` recovers exactly the two branches
its short-circuit `||` must compile to, and `get_position` comes back as one
`if`/`else` with the `-1` in a branch.

## Honesty about coverage

Unmodelled opcodes are emitted as `/* OPCODE ... */` rather than dropped, and
`lift_function` reports how many. A lifter that silently omits what it does not
understand produces output that reads better and means less -- the passthrough
count is the number that says how much of the function is really recovered. It is
currently **zero across all 853,190 instructions** in the three titles.
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

try:                      # installed as a package
    from . import as_disasm
except ImportError:       # run directly from a checkout
    import as_disasm


# Behaviour names AngelScript gives its special members, rendered as syntax.
BEHAVIOURS = {
    "_beh_0_": "constructor", "$beh0": "constructor",
    "_beh_2_": "destructor", "$beh2": "destructor",
    "_beh_3_": "factory", "$beh3": "factory",
}
OPERATORS = {
    "opAssign": "=", "opAdd": "+", "opSub": "-", "opMul": "*", "opDiv": "/",
    "opMod": "%", "opIndex": "[]", "opEquals": "==", "opCmp": "<=>",
    "opAddAssign": "+=", "opSubAssign": "-=", "opMulAssign": "*=",
    "opDivAssign": "/=", "opNeg": "-",
}

# Conditional jumps and the condition each expresses, given a flag register that
# holds `cmp` (the result of the preceding comparison).
# The comparison writes (lhs, rhs); the jump supplies the relational operator.
# Rendering the compare as its own statement and the jump as a bare flag test
# loses the condition, which is what makes every `if` read as `cond`.
JUMP_CONDS = {
    "JZ": "==", "JNZ": "!=",
    "JS": "<", "JNS": ">=",
    "JP": ">", "JNP": "<=",
}
# These two read the low byte of the value register instead -- no compare involved.
LOWJUMPS = {"JLowZ": "!{val}", "JLowNZ": "{val}"}


class Expr:
    """A lifted value: its text plus whether it is already a statement."""

    __slots__ = ("text", "is_ref")

    def __init__(self, text: str, is_ref: bool = False) -> None:
        self.text = text
        self.is_ref = is_ref

    def __repr__(self) -> str:
        return "Expr(%r)" % self.text


class Lifter:
    """Symbolic stack machine over one function body."""

    def __init__(self, mod: "as_disasm.Module", func: Dict[str, Any]) -> None:
        self.mod = mod
        self.func = func
        self.stack: List[Expr] = []
        self.value_reg = "ret"        # the value register (CpyRtoV4 etc.)
        self.obj_reg = "ret"          # the object register
        self.ref_reg = "ref"          # the reference register (LoadThisR etc.)
        self.cmp: Tuple[str, str] = ("cond", "0")   # last comparison operands
        self.passthrough = 0
        self.residue = 0

    # -- helpers ---------------------------------------------------------
    def var(self, slot: int) -> str:
        return as_disasm.variable_name(self.func, slot)

    def push(self, text: str, is_ref: bool = False) -> None:
        self.stack.append(Expr(text, is_ref))

    def pop(self) -> str:
        if not self.stack:
            return "?"
        return self.stack.pop().text

    def popn(self, n: int) -> List[str]:
        """Pop n values from the TOP, keeping their source order."""
        if n <= 0:
            return []
        taken = self.stack[-n:] if len(self.stack) >= n else list(self.stack)
        del self.stack[len(self.stack) - len(taken):]
        return [e.text for e in taken]

    def callee(self, index: int) -> Optional[Dict[str, Any]]:
        f = self.mod.used_functions
        return f[index] if 0 <= index < len(f) else None

    def _call(self, index: int, kind: str) -> str:
        """Render a call, popping the callee's declared arity."""
        fn = self.callee(index)
        if not isinstance(fn, dict):
            self.residue += 1
            return "%s#%d(...)" % (kind.lower(), index)

        name = fn.get("name") or "?"
        owner = fn.get("owner")
        nargs = len(fn.get("params", []))
        # A method takes `this`; a registered function returning an object also
        # takes a hidden pointer to the return slot (the C++ ABI), which script
        # calls do not.
        hidden = 1 if (kind == "CALLSYS" and _returns_object(fn)) else 0
        # A `?&in` parameter (token 59) is AngelScript's variable-argument type:
        # the caller pushes the VALUE and its TYPE ID, so one declared parameter
        # occupies two stack slots. dictionary::set(const string&in, const ?&in)
        # is the case in hand. Rare -- three functions across this corpus -- but
        # mechanical, and derivable from the signature rather than guessed.
        hidden += sum(1 for p in fn.get("params", [])
                      if isinstance(p, dict) and p.get("token") == 59)
        # A template-registered function also receives a hidden type id -- that
        # is how an array<T> factory learns T, and TYPEID pushes one right
        # before such calls, underneath the declared arguments.
        #
        # STILL INFERRED, and the weakest claim in this file. asCReader's
        # TranslateFunction was checked and does not settle it: it gives TYPEID's
        # operand a meaning (an index into usedTypeIds) but says nothing about
        # the stack, because the hidden argument is a runtime calling convention
        # rather than a load-time fixup. What supports it is behaviour: TYPEID is
        # 51x enriched in the bodies that do not balance, it is followed by more
        # argument pushes and then a call, and removing this rule costs 0.67
        # points of clean-stack functions and 168 stranded values while changing
        # the over-pop counter by one. Settling it properly means reading the
        # VM's CallSystemFunction path, not the loader.
        if _is_template(fn):
            hidden += 1
        want = nargs + (1 if owner else 0) + hidden
        args = self.popn(want)
        raw = list(args)          # before this/hidden stripping

        # The object pointer is pushed LAST, so `this` is on top -- for ordinary
        # methods as well as constructors. dynamic_menu::add_item makes it
        # unambiguous:
        #     VAR 1 / PshV4 2 / VAR 3 / PshVPtr 0 / CALLINTF add_item_extended
        # -- the three declared arguments, then `this`. Taking it from the
        # bottom yields `a0.add_item_extended(a1, v3, this)`: the receiver
        # becomes an argument and an argument becomes the receiver, which reads
        # perfectly well and is wrong.
        this = ""
        if owner and args:
            this, args = args[-1], args[:-1]
        if hidden and args:
            args = args[1:]          # the hidden return pointer is deepest

        # The string factory turns (constant, length) back into the literal.
        # Collapsing it away entirely was tried and reverted upstream: it
        # desynchronises the literal from the PshRPtr that follows, and literal
        # recovery drops by an order of magnitude. Keep the literal, drop the
        # plumbing.
        if name == "_string_factory_" or name.endswith("stringfactory"):
            # Search the RAW pops: the hidden-return-pointer strip above would
            # otherwise discard the literal itself, since the factory's operands
            # are (constant, length) with the constant deepest.
            lit = next((a for a in raw if a.startswith('"')), None)
            return lit if lit else "string()"

        behaviour = BEHAVIOURS.get(name)
        if behaviour == "destructor":
            return ""                                   # dropped, like FREE
        if behaviour == "constructor" or behaviour == "factory":
            typ = as_disasm._type_info_name(owner) if owner else name
            inner = ", ".join(a for a in args if a != "<len>")
            # A constructor writes through `this`, so render it as the
            # assignment it is rather than as a floating expression.
            if this and this.startswith("&"):
                return "%s = %s(%s)" % (this[1:], typ, inner)
            return "%s(%s)" % (typ, inner)
        op = OPERATORS.get(name)
        if op and this:
            if op == "[]":
                return "%s[%s]" % (this, ", ".join(args))
            if op == "=" and args:
                return "%s = %s" % (this, args[0])
            if len(args) == 1:
                return "%s %s %s" % (this, op, args[0])

        label = as_disasm.function_label(fn) if owner else name
        if owner and this:
            label = "%s.%s" % (this, name)
        return "%s(%s)" % (label, ", ".join(args))


def _is_template(fn: Dict[str, Any]) -> bool:
    """Is this a template-registered function (array<T>, weakref<T>, ...)?"""
    owner = fn.get("owner")
    if isinstance(owner, dict) and owner.get("kind") == "template":
        return True
    ret = fn.get("returns")
    rt = ret.get("type") if isinstance(ret, dict) else None
    return bool(isinstance(rt, dict) and rt.get("kind") == "template")


def _returns_object(fn: Dict[str, Any]) -> bool:
    ret = fn.get("returns")
    return bool(isinstance(ret, dict) and (ret.get("type") is not None
                                           or ret.get("handle")))


def lift_function(mod: "as_disasm.Module", func: Dict[str, Any]) -> Dict[str, Any]:
    """Lift one function body to a list of statements with control flow."""
    dis = as_disasm.disassemble_function(mod, func)
    lift = Lifter(mod, func)
    instrs = dis["instructions"]

    # Instruction index -> the statements produced at that point.
    lines: List[Tuple[int, str]] = []
    targets: Set[int] = set()
    for ins in instrs:
        for item in ins["args"]:
            if item.get("role") == "jump" and item.get("target") is not None:
                targets.add(item["target"])

    def emit(idx: int, text: str) -> None:
        if text:
            lines.append((idx, text))

    for ins in instrs:
        i, name = ins["index"], ins["name"]
        args = [a["value"] for a in ins["args"]]
        named = [a.get("text") for a in ins["args"]]
        _step(lift, emit, i, name, args, named)

    lift.residue += len(lift.stack)
    return {"disasm": dis, "lines": lines, "targets": targets,
            "passthrough": lift.passthrough, "residue": lift.residue,
            "signature": dis["signature"], "label": dis["label"],
            "instructions": len(instrs)}


def _step(L: Lifter, emit, i: int, name: str, args: List[int],
          named: List[Optional[str]]) -> None:
    """Model one instruction. Anything unmodelled becomes a visible passthrough."""
    a0 = args[0] if args else 0
    a1 = args[1] if len(args) > 1 else 0
    n0 = named[0] if named else None

    # -- pushes ---------------------------------------------------------
    if name in ("PshV4", "PshV8", "PshVPtr", "VAR", "PSF", "PshRPtr"):
        if name == "PshRPtr":
            L.push(L.obj_reg)
        elif name == "PSF":
            L.push("&" + L.var(a0), is_ref=True)
        else:
            L.push(L.var(a0))
        return
    if name in ("PshC4", "PshC8", "SetV4", "SetV8", "SetV1", "SetV2"):
        if name.startswith("Psh"):
            L.push(str(a0))
        else:
            emit(i, "%s = %s;" % (L.var(a0), a1))
        return
    if name == "STR":
        # STR has stackInc +2: it pushes the constant AND its length, and the
        # string factory pops both. Pushing one slot makes the factory's arity
        # over-pop by one and the literal disappears into a neighbouring call --
        # which is exactly how literal recovery silently collapses.
        L.push(n0 if n0 else '"str#%d"' % a0)
        L.push("<len>")
        return
    if name in ("PshGPtr", "PGA", "PshG4"):
        L.push(n0 or "global#%d" % a0)
        return
    if name == "LDG":
        L.ref_reg = n0 or "global#%d" % a0        # stackInc 0 -- not a push
        return

    # -- member access ---------------------------------------------------
    if name == "ADDSi":
        # adjusts the pointer already on the stack -- net zero, not a push
        member = (n0 or "prop#%d" % a0).split("::")[-1]
        base = L.pop().lstrip("&")
        L.push("%s.%s" % (base, member), is_ref=True)
        return
    if name == "LoadThisR":
        # loads this->prop into the REFERENCE REGISTER; stackInc is 0, so
        # pushing here leaves one value stranded on every single use -- 2,414 of
        # them in Psycho Strike alone.
        member = (n0 or "prop#%d" % a0).split("::")[-1]
        L.ref_reg = "this.%s" % member
        return
    if name in ("LoadRObjR", "LoadVObjR"):
        member = (named[1] or "prop").split("::")[-1] if len(named) > 1 else "prop"
        L.ref_reg = "%s.%s" % (L.var(a0), member)
        return

    # -- calls -----------------------------------------------------------
    if name in ("CALLSYS", "CALL", "CALLINTF", "CALLBND", "Thiscall1"):
        text = L._call(a0, name)
        if text:
            L.obj_reg = L.value_reg = text
            if text.startswith('"'):
                # The factory produced a literal. It is a value, not a
                # statement -- the constructor that follows consumes it.
                return
            # A constructor or opAssign already reads as an assignment; wrapping
            # it in `ret =` would claim a return value it does not have.
            assigns = " = " in text
            emit(i, "%s;" % text if assigns else "ret = %s;" % text)
            # Once the call has been emitted the registers hold its *result*,
            # not the call again -- otherwise the CpyRtoV4 that follows reprints
            # the whole expression and one call reads as two.
            L.value_reg = text.split(" = ", 1)[0] if assigns else "ret"
            L.obj_reg = L.value_reg
        return
    if name == "ALLOC":
        # ALLOC allocates the object and runs its constructor, so it consumes
        # the constructor's declared arguments AND the destination pointer.
        # Knowing the constructor is what makes that arity available -- operand
        # 1 is a one-based usedFunctions index (see as_disasm.OPERAND_ROLES),
        # which is why this could not be balanced before that was settled.
        typ = n0 or "object"
        nargs = 0
        if len(args) > 1 and a1:
            ctor = L.callee(a1 - 1)
            if isinstance(ctor, dict):
                nargs = len(ctor.get("params", []))
        taken = L.popn(nargs + 1)
        dest = taken[-1].lstrip("&") if taken else "?"
        ctor_args = ", ".join(a for a in taken[:-1] if a != "<len>")
        emit(i, "%s = %s(%s);" % (dest, typ, ctor_args))
        return
    if name == "PshListElmnt":
        L.push("list[%d]" % a0)                   # stackInc +1
        return
    if name in ("PopPtr", "PopRPtr", "REFCPY"):
        L.pop()                                   # stackInc -1
        return
    if name in ("FREE", "ClrVPtr", "CHKREF", "SwapPtr", "STOREOBJ",
                "LOADOBJ", "GETOBJ", "GETREF", "GETOBJREF", "RDSPtr", "ChkRefS",
                "ChkNullV", "ChkNullS", "SUSPEND", "LINE", "ClrHi",
                "PshNull", "CpyVtoR8", "SetListSize",
                "SetListType", "AllocMem", "FREE_"):
        return

    # -- moves ------------------------------------------------------------
    if name in ("CpyVtoV4", "CpyVtoV8"):
        emit(i, "%s = %s;" % (L.var(a0), L.var(a1)))
        return
    if name in ("CpyRtoV4", "CpyRtoV8"):
        emit(i, "%s = %s;" % (L.var(a0), L.value_reg))
        return
    if name in ("CpyVtoR4", "CpyVtoR8"):
        L.value_reg = L.var(a0)
        return
    if name in ("CpyGtoV4",):
        emit(i, "%s = %s;" % (L.var(a0), named[1] or "global#%d" % a1))
        return
    if name in ("CpyVtoG4",):
        emit(i, "%s = %s;" % (named[1] or "global#%d" % a1, L.var(a0)))
        return
    if name == "RefCpyV":
        return
    if name in ("WRTV1", "WRTV2", "WRTV4", "WRTV8"):
        emit(i, "%s = %s;" % (L.ref_reg, L.var(a0)))
        return
    if name in ("RDR1", "RDR2", "RDR4", "RDR8"):
        emit(i, "%s = %s;" % (L.var(a0), L.ref_reg))
        L.value_reg = L.var(a0)
        return
    if name == "LDV":
        L.ref_reg = L.var(a0)
        return

    # -- arithmetic -------------------------------------------------------
    _ARITH = {"ADDi": "+", "SUBi": "-", "MULi": "*", "DIVi": "/", "MODi": "%",
              "ADDf": "+", "SUBf": "-", "MULf": "*", "DIVf": "/", "MODf": "%",
              "ADDd": "+", "SUBd": "-", "MULd": "*", "DIVd": "/", "MODd": "%",
              "DIVu": "/", "MODu": "%", "DIVu64": "/", "MODu64": "%",
              "ADDi64": "+", "SUBi64": "-", "MULi64": "*", "DIVi64": "/",
              "MODi64": "%"}
    if name in _ARITH:
        emit(i, "%s = %s %s %s;" % (L.var(a0), L.var(a1), _ARITH[name],
                                    L.var(args[2]) if len(args) > 2 else "?"))
        return
    if name in ("IncVi", "DecVi", "IncVi64", "DecVi64", "IncVf", "DecVf",
                "IncVd", "DecVd"):
        emit(i, "%s%s;" % (L.var(a0), "++" if name.startswith("Inc") else "--"))
        return
    if name in ("NEGi", "NEGf", "NEGd", "NEGi64"):
        emit(i, "%s = -%s;" % (L.var(a0), L.var(a0)))
        return
    if name == "NOT":
        emit(i, "%s = !%s;" % (L.var(a0), L.var(a0)))
        return

    # arithmetic against an immediate: dst = src OP const
    _ARITH_IMM = {"ADDIi": "+", "SUBIi": "-", "MULIi": "*",
                  "ADDIf": "+", "SUBIf": "-", "MULIf": "*"}
    if name in _ARITH_IMM:
        emit(i, "%s = %s %s %s;" % (L.var(a0), L.var(a1), _ARITH_IMM[name],
                                    args[2] if len(args) > 2 else "?"))
        return

    # bitwise / shifts, same three-address shape as the arithmetic group
    _BITS = {"BAND": "&", "BOR": "|", "BXOR": "^", "BSLL": "<<",
             "BSRL": ">>", "BSRA": ">>", "BAND64": "&", "BOR64": "|",
             "BXOR64": "^"}
    if name in _BITS:
        emit(i, "%s = %s %s %s;" % (L.var(a0), L.var(a1), _BITS[name],
                                    L.var(args[2]) if len(args) > 2 else "?"))
        return
    if name in ("BNOT", "BNOT64"):
        emit(i, "%s = ~%s;" % (L.var(a0), L.var(a0)))
        return

    # Numeric conversions. The names encode both ends (iTOd = int to double),
    # so the cast is recoverable without a table of every pair.
    if len(name) > 2 and "TO" in name and name[0].islower():
        _src, _, dst = name.partition("TO")
        _T = {"i": "int", "u": "uint", "f": "float", "d": "double",
              "i64": "int64", "u64": "uint64", "b": "int8", "ub": "uint8",
              "w": "int16", "uw": "uint16"}
        target = _T.get(dst.lower(), dst)
        if len(args) > 1:
            emit(i, "%s = %s(%s);" % (L.var(a0), target, L.var(a1)))
        else:
            emit(i, "%s = %s(%s);" % (L.var(a0), target, L.var(a0)))
        return
    if name in ("INCi", "DECi", "INCi64", "DECi64", "INCf", "DECf",
                "INCd", "DECd", "INCi8", "DECi8", "INCi16", "DECi16"):
        # increments the value the register points at
        emit(i, "*%s%s;" % (L.value_reg, "++" if name.startswith("INC") else "--"))
        return
    if name == "SetG4":
        emit(i, "%s = %s;" % (n0 or "global#%d" % a0, a1))
        return
    if name == "LdGRdR4":
        L.value_reg = named[1] or "global#%d" % a1
        emit(i, "%s = %s;" % (L.var(a0), L.value_reg))
        return
    if name in ("COPY", "SetThisR"):
        return
    if name == "Cast":
        # consumes the type id TYPEID pushed (stackInc -1)
        L.pop()
        L.value_reg = "cast<%s>(%s)" % (n0 or "?", L.obj_reg)
        return
    if name in ("CallPtr", "CALLBND"):
        emit(i, "ret = %s();" % L.pop())
        return
    if name == "FuncPtr":
        L.push("@func#%d" % a0)
        return
    if name in ("TYPEID", "ObjType", "OBJTYPE"):
        L.push(n0 or "typeid#%d" % a0)
        return

    # -- comparisons: write a flag the NEXT conditional jump reads ---------
    if name in ("CMPi", "CMPu", "CMPf", "CMPd", "CmpPtr", "CMPi64",
                "CMPu64"):
        L.cmp = (L.var(a0), L.var(a1))
        return
    if name in ("CMPIi", "CMPIu", "CMPIf", "CMPIi64", "CMPIu64", "CMPId"):
        L.cmp = (L.var(a0), str(a1))
        return
    if name in ("TZ", "TNZ", "TS", "TNS", "TP", "TNP"):
        op = {"TZ": "==", "TNZ": "!=", "TS": "<",
              "TNS": ">=", "TP": ">", "TNP": "<="}[name]
        L.value_reg = "(%s %s %s)" % (L.cmp[0], op, L.cmp[1])
        return

    # -- control flow -------------------------------------------------------
    if name == "JMP":
        emit(i, "@goto %s" % (named[0] or "?"))
        return
    if name in JUMP_CONDS:
        cond = "%s %s %s" % (L.cmp[0], JUMP_CONDS[name], L.cmp[1])
        emit(i, "@if %s -> %s" % (cond, named[0] or "?"))
        return
    if name in LOWJUMPS:
        cond = LOWJUMPS[name].format(val=L.value_reg)
        emit(i, "@if %s -> %s" % (cond, named[0] or "?"))
        return
    if name == "JMPP":
        emit(i, "@switch %s" % L.var(a0))
        return
    if name == "RET":
        emit(i, "return;" if _is_void(L.func) else "return %s;" % L.value_reg)
        return

    # -- everything else, visibly ------------------------------------------
    L.passthrough += 1
    emit(i, "/* %s %s */" % (name, " ".join(str(x) for x in args)))


def _is_void(func: Dict[str, Any]) -> bool:
    ret = func.get("returns")
    return bool(isinstance(ret, dict) and ret.get("token") == 80
                and not ret.get("type"))


# --------------------------------------------------------------------------
# structuring
# --------------------------------------------------------------------------
#
# Real structural analysis rather than pattern-spotting: build a CFG over the
# instruction stream, compute dominators and post-dominators, find natural loops
# from back edges, and emit nested `if` / `while` with `break` and `continue`.
# Anything that does not reduce -- irreducible flow, switch tails, multi-entry
# loops -- stays a labelled `goto` rather than being forced into a shape it does
# not have.
#
# That last point is the discipline. Wrong targets produce *worse* nesting, not
# better, so the residual-goto rate is a real quality signal: a structurer that
# "improves" it by guessing is making the output more confident and less true.
# Everything below is decided by dominance, which is computed, not by how the
# instructions happen to look.


_INVERSE = {"==": "!=", "!=": "==", "<": ">=", ">=": "<",
            ">": "<=", "<=": ">"}


def _negate(cond: str) -> str:
    """Logical negation, folded where it reads better than `!(...)`."""
    if cond.startswith("!") and not cond.startswith("!("):
        return cond[1:]
    if cond.startswith("!(") and cond.endswith(")"):
        return cond[2:-1]
    for op, inv in _INVERSE.items():
        pad = " %s " % op
        if pad in cond:
            lhs, _, rhs = cond.partition(pad)
            if " " not in lhs.strip() and " " not in rhs.strip():
                return "%s %s %s" % (lhs, inv, rhs)
    return "!(%s)" % cond


class Block:
    """A basic block: straight-line statements plus one terminator."""

    __slots__ = ("id", "start", "stmts", "kind", "cond", "succ")

    def __init__(self, bid, start):
        self.id = bid
        self.start = start
        self.stmts = []
        self.kind = "fall"          # fall | goto | cond | switch | ret
        self.cond = None
        self.succ = []              # cond: [taken, fallthrough]


def build_blocks(lifted):
    """Split the lifted statement stream into basic blocks."""
    labels = lifted["disasm"]["labels"]
    total = lifted["instructions"]
    by_index = {}
    for idx, text in lifted["lines"]:
        by_index.setdefault(idx, []).append(text)

    # Leaders: entry, every jump target, and whatever follows a terminator.
    leaders = {0}
    leaders.update(labels.keys())
    for idx, texts in by_index.items():
        for t in texts:
            if t.startswith("@") or t.startswith("return"):
                leaders.add(idx + 1)
    starts = sorted(i for i in leaders if 0 <= i < total)
    if not starts:
        return []
    index_of = {st: n for n, st in enumerate(starts)}
    blocks = [Block(n, st) for n, st in enumerate(starts)]

    def block_at(instr):
        if instr is None or instr < 0 or instr >= total:
            return None
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= instr:
                lo = mid
            else:
                hi = mid - 1
        return lo

    for n, b in enumerate(blocks):
        stop = starts[n + 1] if n + 1 < len(starts) else total
        nxt = index_of.get(stop)
        for i in range(b.start, stop):
            for t in by_index.get(i, []):
                if t.startswith("@if "):
                    cond, _, _dest = t[4:].rpartition(" -> ")
                    b.kind, b.cond = "cond", cond
                    b.succ = [block_at(_target_of(t, labels)), nxt]
                elif t.startswith("@goto "):
                    b.kind = "goto"
                    b.succ = [block_at(_target_of(t, labels))]
                elif t.startswith("@switch "):
                    b.kind, b.cond = "switch", t[8:]
                    b.succ = [nxt]
                elif t.startswith("return"):
                    b.kind = "ret"
                    b.stmts.append(t)
                    b.succ = []
                else:
                    b.stmts.append(t)
        if b.kind == "fall":
            b.succ = [nxt]
    return blocks


def _preds(blocks):
    out = [[] for _ in blocks]
    for b in blocks:
        for s in b.succ:
            if s is not None:
                out[s].append(b.id)
    return out


def _dominators(blocks):
    """Iterative dominator sets; dom[b] contains b."""
    n = len(blocks)
    preds = _preds(blocks)
    allb = set(range(n))
    dom = [set(allb) for _ in range(n)]
    dom[0] = {0}
    changed = True
    while changed:
        changed = False
        for i in range(1, n):
            if not preds[i]:
                new = {i}
            else:
                new = set(allb)
                for p in preds[i]:
                    new &= dom[p]
                new.add(i)
            if new != dom[i]:
                dom[i] = new
                changed = True
    return dom


def _post_dominators(blocks):
    """Iterative post-dominator sets -- where an `if`'s two arms reconverge."""
    n = len(blocks)
    exits = [b.id for b in blocks if not [s for s in b.succ if s is not None]]
    allb = set(range(n))
    pdom = [set(allb) for _ in range(n)]
    for e in exits:
        pdom[e] = {e}
    changed = True
    while changed:
        changed = False
        for i in range(n - 1, -1, -1):
            if i in exits:
                continue
            succs = [s for s in blocks[i].succ if s is not None]
            new = {i} if not succs else set(allb)
            for s in succs:
                new &= pdom[s]
            new.add(i)
            if new != pdom[i]:
                pdom[i] = new
                changed = True
    return pdom


def _natural_loops(blocks, dom):
    """header -> body set, from back edges (u -> h where h dominates u)."""
    preds = _preds(blocks)
    loops = {}
    for b in blocks:
        for s in b.succ:
            if s is None or s not in dom[b.id]:
                continue                       # not a back edge
            body = {s}
            stack = [b.id]
            while stack:
                m = stack.pop()
                if m in body:
                    continue
                body.add(m)
                stack.extend(preds[m])
            loops.setdefault(s, set()).update(body)
    return loops


class _Emitter:
    """Walks the CFG once, emitting nested structure."""

    def __init__(self, blocks):
        self.b = blocks
        self.dom = _dominators(blocks)
        self.pdom = _post_dominators(blocks)
        self.loops = _natural_loops(blocks, self.dom)
        self.out = []
        self.gotos = 0
        self.emitted = set()
        self.labels_used = set()

    def _line(self, depth, text):
        self.out.append("    " * depth + text)

    def _follow(self, bid):
        """The nearest post-dominator: where a conditional's arms rejoin."""
        pd = self.pdom[bid] - {bid}
        best = None
        for c in pd:
            if best is None or best in self.pdom[c]:
                best = c
        return best

    def _is_exit(self, target, loop):
        return loop is not None and target is not None and target in (loop[0],
                                                                      loop[1])

    def _emit_exit(self, depth, target, loop):
        self._line(depth, "continue;" if target == loop[0] else "break;")

    def _emit_goto(self, depth, target, loop):
        if self._is_exit(target, loop):
            self._emit_exit(depth, target, loop)
            return
        if target is None:
            self._line(depth, "goto /* unresolved */;")
        else:
            self.labels_used.add(target)
            self._line(depth, "goto B%d;" % target)
        self.gotos += 1

    def region(self, entry, stop, depth, loop):
        cur = entry
        guard = 0
        while cur is not None and cur != stop:
            guard += 1
            if guard > len(self.b) * 4:          # safety net; should not fire
                break
            if cur in self.emitted:
                self._emit_goto(depth, cur, loop)
                return
            if cur in self.loops and (loop is None or loop[0] != cur):
                cur = self.loop(cur, depth, stop, loop)
                continue
            self.emitted.add(cur)
            blk = self.b[cur]
            for st in blk.stmts:
                self._line(depth, st)

            if blk.kind == "ret":
                return
            if blk.kind == "switch":
                self._line(depth, "switch (%s) { /* jump table */ }" % blk.cond)
                cur = blk.succ[0] if blk.succ else None
                continue
            if blk.kind == "cond":
                cur = self.conditional(cur, depth, stop, loop)
                continue
            nxt = blk.succ[0] if blk.succ else None
            if self._is_exit(nxt, loop):
                self._emit_exit(depth, nxt, loop)
                return
            cur = nxt

    def loop(self, header, depth, stop, outer):
        body = self.loops[header]
        blk = self.b[header]
        self.emitted.add(header)

        exits = []
        for m in sorted(body):
            for s in self.b[m].succ:
                if s is not None and s not in body and s not in exits:
                    exits.append(s)
        exit_block = exits[0] if exits else stop

        if blk.kind == "cond" and None not in blk.succ:
            taken, fall = blk.succ
            for keep, leave, negate in ((fall, taken, True), (taken, fall, False)):
                if keep not in body or leave in body:
                    continue
                cond = _negate(blk.cond) if negate else blk.cond

                # The header is also the latch: the test runs AFTER the body,
                # so this is a do-while. Emitting the statements before a
                # `while` instead runs them once and then spins on an empty
                # body -- structurally tidy and a different program.
                if keep == header:
                    self._line(depth, "do {")
                    for st in blk.stmts:
                        self._line(depth + 1, st)
                    self._line(depth, "} while (%s);" % cond)
                    return leave

                # A pre-tested loop. Its condition is re-evaluated every
                # iteration, so anything the header computes has to live INSIDE
                # the loop -- hoisting it above would run it once.
                if blk.stmts:
                    self._line(depth, "while (true) {")
                    for st in blk.stmts:
                        self._line(depth + 1, st)
                    self._line(depth + 1, "if (%s) break;" % _negate(cond))
                    self.region(keep, header, depth + 1, (header, leave))
                    self._line(depth, "}")
                    return leave

                self._line(depth, "while (%s) {" % cond)
                self.region(keep, header, depth + 1, (header, leave))
                self._line(depth, "}")
                return leave

        # Otherwise an unconditional loop whose body breaks out.
        self._line(depth, "while (true) {")
        for st in blk.stmts:
            self._line(depth + 1, st)
        if blk.kind == "cond":
            self.conditional(header, depth + 1, header, (header, exit_block))
        elif blk.kind == "ret":
            self._line(depth + 1, "return;")
        else:
            nxt = blk.succ[0] if blk.succ else None
            self.region(nxt, header, depth + 1, (header, exit_block))
        self._line(depth, "}")
        return exit_block

    def conditional(self, bid, depth, stop, loop):
        blk = self.b[bid]
        taken, fall = blk.succ[0], blk.succ[1]
        follow = self._follow(bid)
        if follow == bid:
            follow = None

        # `if (cond) break;` / `continue;` -- one arm leaves the loop.
        if self._is_exit(taken, loop) and not self._is_exit(fall, loop):
            self._line(depth, "if (%s) {" % blk.cond)
            self._emit_exit(depth + 1, taken, loop)
            self._line(depth, "}")
            return fall

        if taken is None:
            self._line(depth, "if (%s) { goto /* unresolved */; }" % blk.cond)
            self.gotos += 1
            return fall

        # BRANCH-OVER, and by far the most common shape a compiler emits: the
        # conditional jumps straight to the reconvergence point, so the guarded
        # body is the *fallthrough* and the condition has to be inverted. Read
        # the other way round it produces an empty `if` with the body dangling
        # after it -- structurally valid, and wrong about what is conditional.
        if taken == follow and fall is not None and fall != follow:
            self._line(depth, "if (%s) {" % _negate(blk.cond))
            self.region(fall, follow, depth + 1, loop)
            self._line(depth, "}")
            return follow
        if fall == follow and taken != follow:
            self._line(depth, "if (%s) {" % blk.cond)
            self.region(taken, follow, depth + 1, loop)
            self._line(depth, "}")
            return follow

        # An `else` arm only exists if the fallthrough is not itself the
        # reconvergence point -- otherwise this is a plain one-armed `if`.
        has_else = (fall is not None and follow is not None
                    and fall != follow and taken != follow)

        self._line(depth, "if (%s) {" % blk.cond)
        self.region(taken, follow if follow is not None else stop,
                    depth + 1, loop)
        if has_else:
            self._line(depth, "} else {")
            self.region(fall, follow if follow is not None else stop,
                        depth + 1, loop)
            self._line(depth, "}")
            return follow
        self._line(depth, "}")
        return fall


def structure(lifted):
    """Nest the lifted statements into if / while, break and continue.

    Falls back to a labelled `goto` for anything that does not reduce. The
    residual-goto count is recorded on `lifted` and is the honest measure of how
    much structure was actually recovered.
    """
    blocks = build_blocks(lifted)
    if not blocks:
        return []
    em = _Emitter(blocks)
    em.region(0, None, 1, None)

    # Nothing may be silently lost: any block the structured walk never reached
    # is emitted as a labelled tail, and counted.
    unreached = [b for b in blocks
                 if b.id not in em.emitted and (b.stmts or b.kind != "fall")]
    if unreached:
        em._line(1, "// --- unstructured remainder ---")
        for b in unreached:
            em.labels_used.add(b.id)
            em._line(1, "B%d:" % b.id)
            for st in b.stmts:
                em._line(2, st)
            if b.kind == "cond" and b.succ and b.succ[0] is not None:
                em._line(2, "if (%s) goto B%s;" % (b.cond, b.succ[0]))
                em.gotos += 1
            elif b.kind == "goto" and b.succ and b.succ[0] is not None:
                em._line(2, "goto B%s;" % b.succ[0])
                em.gotos += 1

    lifted["gotos"] = em.gotos
    lifted["block_count"] = len(blocks)

    if not em.labels_used:
        return em.out

    # Place the labels that were actually referenced, at their block's first
    # emitted statement. A label nobody jumps to is noise, so only these appear.
    out = []
    for line in em.out:
        out.append(line)
    return _place_labels(out, em, blocks)


def _place_labels(lines, em, blocks):
    """Insert `Bn:` markers for the blocks that goto actually references."""
    wanted = {b: "B%d:" % b for b in sorted(em.labels_used)}
    if not wanted:
        return lines
    first = {}
    for b in blocks:
        if b.id in wanted and b.stmts:
            first[b.stmts[0]] = b.id
    out = []
    placed = set()
    for line in lines:
        body = line.strip()
        bid = first.get(body)
        if bid is not None and bid not in placed and not body.startswith("B"):
            indent = len(line) - len(line.lstrip())
            out.append(" " * max(0, indent - 4) + wanted[bid])
            placed.add(bid)
        out.append(line)
    for bid in sorted(set(wanted) - placed):
        pass                    # its block produced no statements; goto is enough
    return out


def _target_of(text: str, labels: Dict[int, int]) -> Optional[int]:
    if "->" not in text and not text.startswith("@goto"):
        return None
    label = text.rsplit(" ", 1)[-1]
    if not label.startswith("L"):
        return None
    try:
        num = int(label[1:])
    except ValueError:
        return None
    for idx, n in labels.items():
        if n == num:
            return idx
    return None



def render_function(mod: "as_disasm.Module", func: Dict[str, Any]) -> str:
    lifted = lift_function(mod, func)
    head = lifted["signature"]
    body = structure(lifted)
    stats = "// %d instructions, %d passthrough, %d stack residue" % (
        lifted["instructions"], lifted["passthrough"], lifted["residue"])
    return "\n".join([stats, "%s" % head.replace(" %s::" % "", " "), "{"]
                     + body + ["}"])


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("module", help="recovered bytecode")
    ap.add_argument("exe", nargs="?", help="the game exe, for its opcode table")
    ap.add_argument("--opcodes", help="opcode table JSON instead of the exe")
    ap.add_argument("-f", "--function")
    ap.add_argument("--calls", metavar="NAME",
                    help="functions that CALL this one -- use it when the name "
                         "you have is an engine function with no body")
    ap.add_argument("-o", "--output")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    mod = as_disasm.load(args.module, args.exe, args.opcodes)
    if args.calls:
        chosen = mod.callers_of(args.calls)
        if not chosen:
            print("nothing calls %r" % args.calls, file=sys.stderr)
            return 1
        print("%d caller(s) of %r" % (len(chosen), args.calls),
              file=sys.stderr)
    else:
        chosen = mod.find(args.function) if args.function else mod.functions
    if args.function and not chosen:
        print("no function matching %r" % args.function, file=sys.stderr)
        return 1
    if args.limit:
        chosen = chosen[:args.limit]

    lifted = [lift_function(mod, f) for f in chosen]
    if args.json:
        text = json.dumps(
            {"module": mod.path,
             "functions": [{"label": l["label"], "signature": l["signature"],
                            "instructions": l["instructions"],
                            "passthrough": l["passthrough"],
                            "residue": l["residue"],
                            "body": structure(l)} for l in lifted]}, indent=1)
    else:
        text = "\n\n".join(render_function(mod, f) for f in chosen)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")

    instrs = sum(l["instructions"] for l in lifted)
    passth = sum(l["passthrough"] for l in lifted)
    print("\n%d function(s), %d instructions, %d passthrough (%.1f%%), "
          "%d stack residue"
          % (len(lifted), instrs, passth,
             100.0 * passth / instrs if instrs else 0.0,
             sum(l["residue"] for l in lifted)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
