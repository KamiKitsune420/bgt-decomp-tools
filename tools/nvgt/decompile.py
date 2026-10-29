"""AngelScript bytecode decompiler — reconstructs readable source.

Pipeline:
    raw stream -> asreader.read_module() -> Module IR
               -> per-function stack/register simulation -> statements
               -> structured control flow (if/else/while from jump analysis)
               -> pretty-printed AngelScript

VM protocol (verified against as_context.cpp + compiled micro-tests):
  * Register-style ops act directly on frame variables: ADDi d,s1,s2,
    CpyVtoR4 s (value register), CpyRtoV4 d, SetV4 d,imm, CpyVtoV4 d,s.
  * LdGRdR4 v,g loads a global into v and leaves &g in the value register;
    a later WRTV4 v writes v back through it (compound assignment pattern).
  * Calls push args, then (for value-object returns) a hidden out-ref,
    then `this` on top (CALLSYS); script CALL has no `this` (object
    register instead for ctors). Args are consumed in reverse pop order.
  * $beh0/$beh1 = construct/copy-construct, $beh2/$beh3 = destruct,
    opAssign/opAdd/... render as operators, opCmp folds into comparisons.
  * Forward conditional jump = negated condition (skips the if-body);
    backward conditional jump = loop back edge with the condition as-is.

Usage:
    python decompile.py module.bin [-o out.as] [--comments] [--disasm]
    (--raw for streams without our 12-byte ASBC test wrapper)
"""

from __future__ import annotations

import sys
import argparse
import re
import struct
import collections
import copy
from pathlib import Path
from dataclasses import dataclass, field

try:                      # installed as a package
    from .asreader import DataType, Function, Instr, Module, TypeInfo, read_module, unwrap_bytecode
    from .signatures import function_signature, format_parameters, funcdef_declaration, class_header, namespace_block
except ImportError:       # run directly from a checkout
    from asreader import DataType, Function, Instr, Module, TypeInfo, read_module, unwrap_bytecode
    from signatures import function_signature, format_parameters, funcdef_declaration, class_header, namespace_block

# --------------------------------------------------------------------------
# opcode tables
# --------------------------------------------------------------------------

BINARY = {
    "ADDi": "+", "SUBi": "-", "MULi": "*", "DIVi": "/", "MODi": "%",
    "ADDi64": "+", "SUBi64": "-", "MULi64": "*", "DIVi64": "/", "MODi64": "%",
    "ADDu": "+", "SUBu": "-", "MULu": "*", "DIVu": "/", "MODu": "%",
    "ADDu64": "+", "SUBu64": "-", "MULu64": "*", "DIVu64": "/", "MODu64": "%",
    "ADDf": "+", "SUBf": "-", "MULf": "*", "DIVf": "/", "MODf": "%",
    "ADDd": "+", "SUBd": "-", "MULd": "*", "DIVd": "/", "MODd": "%",
    "BAND": "&", "BOR": "|", "BXOR": "^",
    "BAND64": "&", "BOR64": "|", "BXOR64": "^",
    # AngelScript: `>>` is the logical right shift, `>>>` the arithmetic one.
    "BSLL": "<<", "BSRL": ">>", "BSRA": ">>>",
    "BSLL64": "<<", "BSRL64": ">>", "BSRA64": ">>>",
    "POWi": "**", "POWi64": "**", "POWu": "**", "POWu64": "**",
    "POWf": "**", "POWd": "**", "POWdi": "**",
}
NUMERIC_TYPES = {"i": 70, "u": 77, "i64": 73, "u64": 80, "f": 81, "d": 94}

def _numeric_type(opcode):
    suffix = next((s for s in ("i64", "u64", "i", "u", "f", "d") if opcode.endswith(s)), None)
    return DataType(token_type=NUMERIC_TYPES[suffix]) if suffix else None
IMM_BINARY = {"ADDIi": "+", "SUBIi": "-", "MULIi": "*",
              "ADDIf": "+", "SUBIf": "-", "MULIf": "*",
              "ADDIi64": "+", "SUBIi64": "-", "MULIi64": "*"}
CONV_OPS = {
    "iTOi64", "iTOu64", "iTOf", "iTOd", "iTOb", "iTOw", "iTOu",
    "uTOi64", "uTOf", "uTOd", "uTOi", "uTOu64",
    "sbTOi", "swTOi", "ubTOi", "uwTOi",
    "fTOi", "fTOi64", "fTOu", "fTOu64", "fTOd",
    "dTOi", "dTOi64", "dTOu", "dTOu64", "dTOf",
    "i64TOi", "i64TOf", "i64TOd", "i64TOu", "u64TOd", "u64TOf", "u64TOi64",
}
#: Opcodes that assign to the frame slot in their FIRST operand (`w_arg`).
#: Used to tell the slots a short-circuit arm computes in -- which belong to
#: the compiler -- from the ones it merely reads, which may be the source's
#: own. Reading is not writing: an arm that calls a method on a local pushes
#: that local's slot, and counting the push would unforce a real variable.
_SLOT_WRITE_OPS = (
    {"SetV1", "SetV2", "SetV4", "SetV8",
     "CpyVtoV4", "CpyVtoV8", "CpyRtoV4", "CpyRtoV8",
     "CpyGtoV4", "CpyGtoV8", "RDR1", "RDR2", "RDR4", "RDR8",
     "NOT", "NEGi", "NEGf", "NEGd", "NEGi64", "IncVi", "DecVi"}
    | set(BINARY) | set(IMM_BINARY) | CONV_OPS
)

# Jump name -> comparison operator of the taken path.  The T* instructions
# are value-register tests, not branches (see as_context.cpp).
JUMP_OPS = {"JS": "<", "JNS": ">=", "JP": ">", "JNP": "<=",
            "JZ": "==", "JNZ": "!=",
            "JLowZ": "==", "JLowNZ": "!=", "JLowS": "<", "JLowNS": ">="}
TEST_OPS = {"TS": "<", "TNS": ">=", "TP": ">", "TNP": "<=",
            "TZ": "==", "TNZ": "!="}
COMPLEMENT = {"<": ">=", ">=": "<", ">": "<=", "<=": ">",
              "==": "!=", "!=": "=="}
ASSIGN_OPS = {"opAddAssign": "+=", "opSubAssign": "-=", "opMulAssign": "*=",
              "opDivAssign": "/=", "opModAssign": "%=", "opAndAssign": "&=",
              "opOrAssign": "|=", "opXorAssign": "^=", "opShlAssign": "<<=",
              "opShrAssign": ">>=", "opUShrAssign": ">>>="}
SKIP_OPS = {"CHKREF", "ChkRefS", "ChkNullS", "ChkNullV", "SUSPEND", "ClrHi",
            "JitEntry",
            "LINE", "LABEL", "ObjInfo", "Block", "VarDecl", "TryBlock",
            "SetListSize", "SetListType", "PshListElmnt", "AllocMem"}
CTORS = {"$beh0", "$beh1"}     # default ctor / copy ctor
DTORS = {"$beh2", "$beh3"}


def _s16(v: int) -> int:
    return v - 0x10000 if v >= 0x8000 else v


def _s32(v: int) -> int:
    return v - (1 << 32) if v >= (1 << 31) else v


def _s64(v: int) -> int:
    return v - (1 << 64) if v >= (1 << 63) else v


_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _esc(s: str) -> str:
    """Render a literal so the engine ends up with the module's exact bytes.

    The engine reads source as bytes, and a recovered literal is bytes. So the
    only property that matters is that whatever is written here, encoded the
    way the project file is written (UTF-8), is byte for byte what the module
    held. Getting that wrong fails in the worst way available: Super Egg Hunt's
    pack key is a 32-byte AES blob in a literal, every byte of it above 0x7F
    was emitted as a character, and a UTF-8 file turned each one into two. The
    project compiled, ran, and said `Decryption failed because the key was
    incorrect` -- a recovery that looks complete and has no sound.

    Two cases, and the test between them is decoding rather than taste:

    * The bytes **are** valid UTF-8. Then the characters they decode to encode
      back to exactly those bytes, so they are written as themselves: a French
      game's `caractère` stays `caractère` and stays correct.
    * They are not. Then no character spelling can be trusted, and every byte
      from 0x7F up is written `\\xNN`. BGT was asked rather than assumed --
      `"\\xac\\x71\\x96"` compiles with no warning and produces those three
      bytes, while the octal form `"\\254"` is `Warning: Invalid escape
      sequence`.

    A control character is escaped either way: it is not source anyone can read
    and `\\xNN` round-trips it.
    """
    if all(ord(character) <= 0xFF for character in s):
        raw = s.encode("latin-1")
        try:
            # Valid UTF-8: the decoded text re-encodes to these same bytes, so
            # it can be written as text without changing what the engine gets.
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            return "".join(_ESCAPES.get(chr(b), chr(b)) if 32 <= b < 0x7F
                           else "\\x%02x" % b for b in raw)
    result = []
    for character in s:
        value = ord(character)
        if character in _ESCAPES:
            result.append(_ESCAPES[character])
        elif 0xdc80 <= value <= 0xdcff:
            # A byte that was not decodable text when the module was read.
            result.append("\\x%02x" % (value - 0xdc00))
        elif value < 32 or value == 127:
            result.append("\\x%02x" % value)
        else:
            result.append(character)
    return "".join(result)


def _jump_target(ins: Instr) -> int:
    """Dword position a jump goes to (reader pre-computes jump_target from
    the instruction-number delta; fall back to the raw delta)."""
    if getattr(ins, "jump_target", None) is not None:
        return ins.jump_target
    return ins.pos + 2 + _s32(ins.dw_arg)


_FLIP = {"<=": ">", ">=": "<", "<": ">=", ">": "<=", "==": "!=", "!=": "==",
         "is": "!is", "!is": "is"}
# Longest first, so `<=` is not read as `<` and `!is` not as `is`.
_COMPARISONS = ("!is", "<=", ">=", "==", "!=", "is", "<", ">")


def _scan_depth0(text: str):
    """Yield (index, char) for characters outside brackets and string literals."""
    depth, i, n = 0, 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0:
            yield i, ch
        i += 1


def _outer_wrapped(c: str) -> bool:
    """Is `c` one parenthesised expression -- does its first `(` close last?

    `(a - b) < (c + d)` starts with `(` and ends with `)` but is NOT wrapped;
    treating it as wrapped negated it to `!(a - b) < (c + d` -- a different
    condition, which NVGT rejects as "Illegal operation on this datatype".
    """
    if not (c.startswith("(") and c.endswith(")")):
        return False
    depth = 0
    for i, ch in enumerate(c):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and i != len(c) - 1:
                return False
    return depth == 0


def _split_comparison(c: str):
    """(lhs, op, rhs) when `c` is a single top-level comparison, else None."""
    tops = "".join(ch for _, ch in _scan_depth0(c))
    if "&&" in tops or "||" in tops or "?" in tops:
        return None
    for i, _ch in _scan_depth0(c):
        for op in _COMPARISONS:
            token = " %s " % op
            if c.startswith(token, i - 1) and i > 0:
                return c[:i - 1], op, c[i - 1 + len(token):]
    return None


def _atomic(s: str) -> bool:
    """True if `s` has no top-level operator -- an identifier, member access,
    call or index -- so it needs no parentheses after a `!`. A top-level space
    (outside parens, brackets and string literals) marks a binary operator or a
    ternary; there is none in `getf(x)` or `a.b[i]`."""
    depth = 0
    i = 0
    while i < len(s):
        c = s[i]
        if c == '"' or c == "'":
            i += 1
            while i < len(s) and s[i] != c:
                i += 2 if s[i] == "\\" else 1
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == " " and depth == 0:
            return False
        i += 1
    return True


def _negate_cond(c: str) -> str:
    """Negate a condition, flipping a comparison where there is one."""
    if c in ("0", "false"):
        return "true"
    if c in ("1", "true"):
        return "false"
    if c.startswith("!"):
        rest = c[1:]                 # negating `!x` or `!(x)` gives `x`
        return rest[1:-1] if _outer_wrapped(rest) else rest
    inner = c[1:-1] if _outer_wrapped(c) else c
    parts = _split_comparison(inner)
    if parts is not None:
        a, op, b = parts
        return f"({a} {_FLIP[op]} {b})"
    return f"!{inner}" if _atomic(inner) else f"!({inner})"


def _condition(c: str) -> str:
    """AngelScript requires parentheses after if/while.

    Whether the text already has them is `_encloses`'s question, not a
    `startswith`/`endswith` one: `(0 + 2) < (x)` begins with `(` and ends
    with `)` while enclosing nothing, so the naive test added no
    parentheses and emitted `while (0 + 2) < (x) {`. That was 110 of
    Crazy Party's compiler errors, in `while` and `do while` alike.
    """
    return c if _encloses(c) else f"({c})"


def _type_stack_size(dt: DataType) -> int:
    """AngelScript frame slots used by compiler parameters."""
    if dt.is_reference or dt.is_object_handle or dt.obj_type is not None:
        return 1
    return 2 if dt.format().replace("const ", "") in ("int64", "uint64", "double") else 1


def _method_key(fn: Function) -> tuple:
    """A method's identity for overriding: name, parameter types, const-ness.

    The owner is deliberately left out -- an override and the stub it replaces
    belong to different classes but are the same method.
    """
    return (fn.name, tuple(dt.format() for dt in fn.param_types),
            tuple(fn.in_out_flags), bool(fn.flags_byte & 1))


def _parameter_layout(fn: Function) -> list[tuple[int, str]]:
    names = list(fn.param_names)
    names.extend(f"arg{i}" for i in range(len(names), len(fn.param_types)))
    pos = -1 if fn.object_type is not None else 0
    if _needs_out_ref(fn.return_type) and not (fn.object_type and fn.name == fn.object_type.name):
        pos -= 1
    result = []
    for dt, name in zip(fn.param_types, names):
        result.append((pos, name))
        pos -= _type_stack_size(dt)
    return result


def _needs_out_ref(dt: DataType) -> bool:
    """Value-object returns take a hidden caller-supplied out-ref param."""
    if dt.is_object_handle or dt.is_reference:
        return False
    if dt.obj_type and (dt.obj_type.flags & 1 or dt.obj_type.return_via_object_register
                        or dt.obj_type.return_via_value_register):
        return False
    return dt.obj_type is not None and dt.obj_type.kind not in ("enum", "typedef")


# --------------------------------------------------------------------------
# atoms: values living on the simulated stack / in variable slots
# --------------------------------------------------------------------------

@dataclass
class Atom:
    kind: str                    # const|var|global|prop|call|null|this|raw
    text: str = ""
    dw_size: int = 1             # stack footprint in dwords (for GETOBJ walk)
    is_ptr: bool = False         # PSF/VAR-style address atom
    offset: int | None = None    # stack offset for var-backed atoms
    data_type: DataType | None = None
    list_index: int | None = None
    constant_bits: int | None = None
    ternary: tuple[str, Atom, Atom] | None = None


#: the object a call is made on, and the method: `this.terrain.getTailleX()`
#: has receiver `this.terrain`, not `this`. Taking the leading identifier
#: instead made `this` the receiver of every method call on a member, and
#: since almost every statement in a method mentions `this`, the invalidation
#: test below matched everything -- which cost Crazy Party four loops.
_CALL_RECEIVER = re.compile(
    r"((?:@?[A-Za-z_]\w*)(?:\.[A-Za-z_]\w*)*)\.([A-Za-z_]\w*)\s*\(")


def _mutates(statement: str, receiver: str) -> bool:
    """Could this statement have changed what `receiver` holds?

    Mentioning it is not enough, and that is the whole difficulty.
    `@local_7 = this.terrain;` reads `this.terrain` and cannot change it,
    while `item_list.resize(...)` changes `item_list`. So what counts is a
    call *on* the receiver, or an assignment *to* it -- not an appearance of
    its name on the right of one.
    """
    name = re.escape(receiver)
    return bool(
        # a method call on it: `item_list.resize(...)`
        re.search(r"(?<![\w.])" + name + r"\s*\.\s*[A-Za-z_]\w*\s*\(", statement)
        # or an assignment to it, including compound and indexed
        or re.search(r"(?<![\w.])@?" + name + r"\s*(?:\[[^\]]*\])?\s*"
                     r"(?:[-+*/%|&^]|<<|>>)?=(?!=)", statement))


def _is_repeatable(a: Atom) -> bool:
    """Whether writing this value at several reads keeps the program's meaning.

    A constant, a variable, `this` or a plain property read can be repeated:
    reading it again costs nothing and yields the same thing. A call cannot --
    repeating it calls it again -- and neither can anything built out of one,
    which is why the test is on the text as well as the kind.
    """
    if a.kind in ("const", "null", "this", "typeid"):
        return True
    if a.kind in ("var", "global", "prop", "raw"):
        return "(" not in a.text
    return False


NUMERIC_TOKENS = (70, 71, 72, 73, 77, 78, 79, 80)   # int, int8/16/64, uint...


#   <type> <name> ;|=|(      -- a declaration, with or without an initialiser.
# The keyword guard matters in both directions: `return local_6;` read as a
# declaration both suppresses the declaration local_6 actually needs and makes
# every `case` arm look as though it declares something.
DECL_RE = re.compile(r"^\s*(?!(?:return|break|continue|case|default|else|goto|"
                     r"while|if|for|do|switch|super|new|delete)\b)"
                     r"(?:const\s+)?[A-Za-z_][\w:]*(?:<[^>]*>)?(?:@|\[\])*@?\s+"
                     r"([A-Za-z_]\w*)\s*[;=(]")
SLOT_NAME_RE = re.compile(r"\b((?:local|tmp)_?\d+)\b")
#: any bare identifier, for asking which of a frame's own slots an
#: expression reads. Intersecting with `var_names` is what keeps a
#: property or method name out of the answer:
#: `arg0.interacts[local_2].mode` names three things and only `local_2`
#: is a slot.
_IDENT = re.compile(r"[A-Za-z_]\w*")
# Locals this decompiler generates. They belong to the function, never to the
# block they were written in.
GENERATED_LOCAL = re.compile(r"__nvgt_(?:out|ret|list|hold)_")

#: how many folds of one non-repeatable value make it worth promoting to a
#: variable. Promoting is not free -- a value the structurer needed as an
#: expression becomes a statement before a jump, and the loop stops being a
#: loop -- so this is a measured threshold, not a principle. At 2 it cost
#: Crazy Party **36 residual gotos and 36 compiler errors** against 0, while
#: the duplications worth catching are far worse than doubled:
#: `file_menu` reads one menu result 4 times and `play_extended_1d` read one
#: `reserve_slot()` 45 times.
#:
#: **Two for a value that CALLS something was tried, and measured, and is
#: not it either.** `_is_repeatable` rejects any text with a bracket in it,
#: so it cannot tell `do_damage(a, b)` from `(y - backward_range)`, and
#: lowering the threshold only for the former looks like exactly the
#: narrowing this comment asks for. It removes 561 duplicated calls from
#: Crazy Party and costs that title **14 residual gotos -> 30**: Paladin,
#: Super Egg Hunt and Psycho Strike all hold at their own counts and
#: compile, which is what makes it tempting. The duplications it would have
#: fixed are real and some are serious -- Paladin's four hp-drain attacks
#: each call `do_damage` twice, once to say the number and once to apply
#: it, so the damage spoken is a different roll from the damage dealt --
#: but 16 new errors on a title that compiles cleanly is not a trade this
#: file takes. What the measurement says is that the threshold is the wrong
#: lever: the folds that must stay folded are the ones inside a condition,
#: and *that* is the distinction to find.
DUPLICATE_FOLDS = 3


def _declare_read_before_written(lines: list[str], fd: "FuncDecompiler",
                                 indent: int) -> list[str]:
    """Declare any slot the body reads but never assigns.

    A frame slot the function reads before writing holds what the frame was
    given: null for a handle, a default-constructed object. The write that
    would have declared it may not exist at all -- a constructor's generated
    member initialisation is dropped, and a slot zeroed at entry is never
    assigned -- and then the reads are "'local_19' is not declared".

    The declaration is emitted without an initialiser, which is exactly the
    state the slot was in. A slot whose type cannot be named in source is left
    alone rather than declared as something it is not.
    """
    declared = {match.group(1) for line in lines
                if (match := DECL_RE.match(line))}
    used: dict[str, int] = {}
    for line in lines:
        for name in SLOT_NAME_RE.findall(_mask_strings(line)):
            used.setdefault(name, 0)
    missing = []
    for name in used:
        if name in declared:
            continue
        off = next((o for o in fd.var_names if fd.name_of(o) == name), None)
        dt = fd.var_types.get(off) if off is not None else None
        if dt is None:
            continue
        text = dt.format().removeprefix("const ").replace("&", "").strip()
        if (not text or "tok" in text or "$" in text
                or text.startswith("_builtin_function_")):
            continue                      # not a type source can name
        missing.append("    " * indent + "%s %s;" % (text, name))
    return missing + lines


def _mask_strings(line: str) -> str:
    """The line with string literals blanked, so a name inside one is not a use."""
    out, in_str, escape = [], False, False
    for char in line:
        if in_str:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_str = False
            out.append(" ")
            continue
        if char == '"':
            in_str = True
            out.append(" ")
            continue
        out.append(char)
    return "".join(out)


def _member_array_sizes(c: TypeInfo) -> dict:
    """Lengths the constructor's generated prologue gives array members.

    `double[] down_count(256);` compiles to the length factory called in every
    constructor and stored into the member. That store is generated code and
    is dropped, so re-emitting the property declaration is what has to carry
    the length -- and it is the only place it can go.
    """
    shape = ["STOREOBJ", "PshVPtr", "PshVPtr", "ADDSi", "REFCPY"]
    out = {}
    for f in list(c.constructors) + list(c.factories):
        code = f.bytecode or []
        for k, ins in enumerate(code):
            if ins.name not in ("CALL", "CALLSYS") or ins.func_ref is None:
                continue
            if ins.func_ref.name != "factstub" or not ins.func_ref.param_types:
                continue
            parameter = ins.func_ref.param_types[0]
            if parameter.obj_type is not None or parameter.is_reference:
                continue                       # the list factory, not a length
            if [i.name for i in code[k + 1:k + 1 + len(shape)]] != shape:
                continue
            previous = code[k - 1] if k else None
            if previous is None or previous.name not in ("PshC4", "PshV4"):
                continue
            name = (code[k + 4].prop_name or "").split(".")[-1]
            if not name:
                continue
            out.setdefault(name, str(_s32(previous.dw_arg))
                           if previous.name == "PshC4" else None)
            if out[name] is None:
                del out[name]
    return out


# AngelScript's delegate factory, which binds an object and one of its
# methods into a funcdef handle. Its name differs between versions, and
# the call renders as `Type(object.method)` rather than as a call to it:
# left as the factory's own name, Crazy Party emitted
# `fadeOut(arg0, %delegate_factory(), arg1)` 132 times, which is not an
# expression. BGT 1.3 compiles the delegate form, asked directly.
DELEGATE_FACTORIES = ("$dlgte", "%delegate_factory")


# A statement that ends its block. `goto` is not one of these; see
# `_drop_unreachable` for why.
TERMINATOR = re.compile(r"(return\b|break;|continue;)")


class UnstructuredSwitch(Exception):
    """A computed jump whose table neither switch matcher recognised.

    Raised rather than worked around: the alternative is emitting the arms
    with no `switch` around them, which is unparseable rather than merely
    ugly. See the `JMPP` branch of `step`.
    """


def _drop_unreachable(lines: list[str]) -> list[str]:
    """Remove statements that follow a terminator in the same block.

    A `return`, `break` or `continue` ends its block, so anything after it at
    the same indentation cannot run. The compiler says so -- "Unreachable
    code" -- and a warning is not harmless in practice: BGT shows a modal
    report for warnings as well as errors and waits on it, which stops an
    unattended compile from ever writing its executable.

    Dropping them cannot change behaviour, because nothing reaches them. It
    can change the *source* from what the original said, which is why it is
    the last pass and nothing else depends on it.
    """
    out: list[str] = []
    dead: int | None = None
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if dead is not None:
            if (indent < dead or stripped.startswith(("}", "case ", "default:", "else"))
                    or indent > dead):
                dead = None            # the block ended, or a label made it live
            else:
                continue
        out.append(line)
        # `goto` is deliberately NOT a terminator. A `return`, `break` or
        # `continue` ends its block; a `goto` only leaves, and what follows
        # it is a jump target reached from somewhere else -- labels this
        # decompiler does not even emit, so nothing here could prove
        # otherwise. Counting it dropped seven live lines from Manamon 2
        # `character::cure_all_statuses`, the `if (...) {` among them, which
        # left `} else {` with no `if` and a file that cannot parse.
        if TERMINATOR.match(stripped):
            dead = indent
    return out


BOOL_WRAP = re.compile(r"^\((.*) \? 1 : 0\)$", re.S)


def _unwrap_bool(text: str) -> str:
    """`(X ? 1 : 0)` is X wherever only its truth matters.

    One slot serves several source locals, so a bool-valued operand stored in
    a slot typed numeric renders with that wrapper (`_normalize_arg`). The
    bool-literal simplification below then stopped matching, and `x == false`
    came back as `(!getf(arg0) ? 1 : 0) == (false ? 1 : 0)` -- correct, and
    saying nothing.

    The balance check is not decoration: `"(a ? 1 : 0) + (b ? 1 : 0)"` also
    begins with `(` and ends with `)`, and a greedy match would hand back the
    unbalanced middle.
    """
    match = BOOL_WRAP.match(text)
    if match is None:
        return text
    inner = match.group(1)
    depth = 0
    for char in inner:
        depth += (char == "(") - (char == ")")
        if depth < 0:
            return text
    return text if depth else inner




def _ends_in_terminator(lines) -> bool:
    """Whether this arm cannot fall through into the next one."""
    for _, text in reversed(lines):
        if text.strip() in ("", "}", "{"):
            continue
        return bool(TERMINATOR.match(text.strip()))
    return False


def _default_last(arms):
    """Move the `default:` arm to the end, when that changes nothing.

    AngelScript rejects a `default` that is not last ("The default case must
    be the last one"), and the arms come out in bytecode order, where a dense
    jump table's default target is the code immediately after the table --
    physically *before* every case body. So the default is often first, and
    the switch does not compile.

    Reordering is only safe when the default arm neither falls through nor is
    fallen into: its own statements must end in a `return`, `break` or
    `continue`, and the arm above it (if any) must too. Both hold for the
    common shape, where every arm returns. When they do not, the arms are left
    in the order the bytecode gives them -- a switch that does not compile is
    better than one that compiles and runs the wrong arm.
    """
    index = next((k for k, (names, _) in enumerate(arms) if "default:" in names), None)
    if index is None or index == len(arms) - 1:
        return arms
    names, lines = arms[index]
    if not _ends_in_terminator(lines):
        return arms
    if index > 0 and not _ends_in_terminator(arms[index - 1][1]):
        return arms
    return arms[:index] + arms[index + 1:] + [(names, lines)]


def _constructor_type(dt: DataType) -> str:
    """The type as a *constructor expression* can name it.

    BGT writes an array as `T[]` in a declaration, and that form is a
    declaration and nothing else: `weapon@[]()` is a parse error ("Expected
    ';', instead found '@'"), because the parser takes `weapon@[]` as the start
    of one. The template's own name works as an expression -- `array<weapon@>()`
    compiles -- so a constructor uses that form while declarations keep the
    idiomatic one. Both were checked against the compiler.
    """
    if (dt.obj_type is not None and dt.obj_type.template_syntax == "suffix"
            and dt.template_subtypes):
        inner = ", ".join(sub.format() for sub in dt.template_subtypes)
        return "%s<%s>" % (dt.obj_type.name, inner)
    return dt.format().removeprefix("const ").rstrip("&").rstrip("@")


def _initialiser(dt: DataType, expr: str) -> str | None:
    """How source writes this initialiser, or None if the declaration IS it.

    Two shapes cannot be written as an assignment:

    * A reference type registered with a factory -- `sound`, `timer` and
      `tts_voice` in BGT -- is created by being declared. `sound music =
      sound();` is "No appropriate opAssign method found in 'sound'", because
      creating one and assigning one are different things and only the first
      exists here.
    * An array made by the template factory stub is rendered as its own
      construction (`character@[]()`), which the first rule then reduces to
      the declaration: `character@[] fighters;`.

    And a one-byte value reads as a bool where the declared type is an
    integer, which will not take one: `uint8 game_diff = true;`.
    """
    bare = dt.format().removeprefix("const ").strip()
    if expr in (f"{bare}()", f"{_constructor_type(dt)}()"):
        return None
    if dt.token_type in NUMERIC_TOKENS and expr in ("true", "false"):
        return "1" if expr == "true" else "0"
    if dt.token_type == 67 and expr in ("0", "1"):
        return "true" if expr == "1" else "false"
    return expr


def _deref_ptr(mod: Module, a: Atom) -> Atom:
    """Turn a PSF/VAR address atom into the value it points at (var only;
    temp resolution happens in FuncDecompiler._deref which knows the temps)."""
    if a.is_ptr and a.offset is not None:
        return Atom("var", str(a.text), 1)
    return a


# --------------------------------------------------------------------------
# per-function simulation
# --------------------------------------------------------------------------

@dataclass
class Event:
    kind: str                    # stmt|branch|jump|label|nop
    pos: int                     # dword position of the instruction
    data: object = None


class FuncDecompiler:
    """Simulates one function body and produces structured source lines."""

    def __init__(self, module: Module, fn: Function, comments: bool = False):
        self.m = module
        self.fn = fn
        self.comments = comments
        self.instrs = fn.bytecode
        self.pos_of = {i.pos: k for k, i in enumerate(self.instrs)}
        #: (branch position, join position) for every forward conditional
        #: jump. A value computed between the two is computed on only one
        #: path, so once the join is passed it can no longer be folded into a
        #: read -- see `_conditionally_bound`.
        self.cond_spans = [(i.pos, _jump_target(i)) for i in self.instrs
                           if i.name in JUMP_OPS and _jump_target(i) > i.pos]
        #: ...and the same for a forward **unconditional** jump, which is how
        #: the *second* arm of a diamond gets skipped. `if (c) { x = 0; }
        #: else { x = 26; } f(x);` compiles to
        #:
        #:     JNZ else ; SetV4 x,0 ; JMP join ; else: SetV4 x,26 ; join: f(x)
        #:
        #: The conditional jump lands *at* the first store, not after it, so
        #: only the `JMP` says the second store is skipped on the other path.
        #: To a linear walk a diamond looks like an ordinary reassignment, and
        #: the read then folds whichever arm came last in the bytecode:
        #: Paladin's `create_room` emitted `if (arg6 == 14) { } else { }` and
        #: `add_clock(26, 6, -2, -2)`, the else arm's constants, so every
        #: layout_2 cabin put its clock where the other layout's goes.
        #: `back_edges` has always counted `JMP` for the loop case; this is
        #: the same instruction mattering for the same reason.
        #:
        #: **Treating every forward `JMP` as a conditional span is too
        #: broad** -- every `break`, `continue` and guard tail is one, and
        #: measured against BGT's shipped library it promoted enough extra
        #: slots to cost 8 of 149 functions their exact call sequence and 3
        #: their literals. So this list stays separate, and the diamond test
        #: that uses it also demands the same slot be written on the path
        #: that skips the bind -- which is what makes it a diamond rather
        #: than an ordinary jump over an assignment.
        self.jmp_spans = [(i.pos, _jump_target(i)) for i in self.instrs
                          if i.name == "JMP" and _jump_target(i) > i.pos]
        #: Where each frame slot is written, by bytecode position.
        self.slot_writes: dict[int, list[int]] = {}
        for op in self.instrs:
            if op.name in _SLOT_WRITE_OPS:
                self.slot_writes.setdefault(_s16(op.w_arg), []).append(op.pos)
        #: (loop head, back edge) for every backward jump. A read inside the
        #: loop runs once per iteration, so a value computed before the loop
        #: cannot be folded into it -- the loop body may assign the slot, and
        #: the next iteration would then read something else.
        self.back_edges = [(_jump_target(i), i.pos) for i in self.instrs
                           if i.name in (*JUMP_OPS, "JMP")
                           and _jump_target(i) < i.pos]
        self.var_names = {v.stack_offset: v.name for v in fn.variables if v.name}
        self.var_types = {v.stack_offset: v.type for v in fn.variables}
        self.var_names.update(_parameter_layout(fn))
        self.parameter_slots = {off for off, _ in _parameter_layout(fn)}
        self.var_types.update({off: dt for (off, _), dt in
                               zip(_parameter_layout(fn), fn.param_types)})
        self.mixed_boolean_slots = set()
        slot_types = {}
        for variable in fn.variables:
            slot_types.setdefault(variable.stack_offset, []).append(variable.type)
        for off, types in slot_types.items():
            tokens = {t.token_type for t in types}
            # A slot a stripped build shares between a bool and a number. With
            # no debug positions there is no telling which declaration is
            # live where, so the slot takes the numeric type and bools are
            # written as 1/0 and read back as `!= 0`. Floats and doubles
            # included: touch.nvgt reuses one slot for `bool in_bounds` and
            # `float dist_sq_start`.
            numeric = (70, 77, 94, 81)                   # int, uint, double, float
            if off > 0 and 67 in tokens and tokens & set(numeric) and all(
                    t.obj_type is None and t.token_type in (67,) + numeric for t in types):
                chosen = next(tok for tok in numeric if tok in tokens)
                self.var_types[off] = DataType(token_type=chosen)
                self.mixed_boolean_slots.add(off)
        self.global_types = {(g.namespace_ + "::" if g.namespace_ else "") + g.name: g.type
                             for g in module.globals + module.used_globals}
        self.property_types = {f"{c.name}.{name}": dt
                               for c in module.classes + module.used_types if c
                               for name, dt, _ in c.properties}
        # Stripped bytecode keeps types and slots but loses names.  Slots used
        # as mutable scalar locals or stored object locals must remain lvalues;
        # folding them into temporary expressions changes the program.
        forced = set()
        prefix_types = {}
        highest = 0
        prefix_forced: set[int] = set()
        for variable in fn.variables:
            off = variable.stack_offset
            if off <= 0:
                continue
            # Source locals from separate scopes can reuse a counter slot
            # before later locals appear. Repeated slots of the same type
            # don't mark the start of compiler scratch variables.
            repeated_local = prefix_types.get(off) == variable.type.format()
            if off < highest and not repeated_local:
                prefix_forced.update(prefix_types)
                break
            prefix_types[off] = variable.type.format()
            highest = max(highest, off)
        # **That rule reads declaration ORDER, and a short-circuit's scratch
        # slot must not be caught by it.** The newer engine writes one
        # declaration per local in the order the builder declared them, which
        # is what makes "the prefix before the first backward step is the
        # source's own locals" mean anything. BGT records no scalar local at
        # all, so `bgt_asir` synthesises the list and appends each slot the
        # first time a typed opcode mentions it -- bytecode order, with no
        # scope in it -- and the rule then finds a backward step wherever the
        # bytecode happens to touch a lower slot later.
        #
        # That is how `use_screen_reader` lost two thirds of its condition.
        # `screen_reader && voice.reader > -2 && voice.sapi_only == false`
        # compiles to two merges over three scratch slots, and the compiler
        # reuses them: slot 3 carries `screen_reader` and then `sapi_only`,
        # slot 1 carries `reader > -2` and then a literal. Forced to be
        # variables, each arm's computation is emitted as an *unconditional*
        # statement, so every term is overwritten before the `if` reads it and
        # the whole condition collapses to `!sapi_only`. It returned true
        # where the source returns false, so every `speak` went to
        # `screen_reader_speak_interrupt(-1, ...)`, which fails:
        # `run_extended` returns -1 when it cannot speak its intro,
        # `file_menu` turns that into "", and Paladin's main loop reads that
        # as "no TTS" and reopens the voice selector. Selecting a voice fixed
        # nothing, because the selector's own `speak_sapi_only()` is what made
        # speech work while it was open -- so it asked again, forever.
        #
        # **Dropping the rule outright is the wrong cure, and measuring says
        # so: Crazy Party went from 0 residual gotos to 44**, which is 44
        # compiler errors, because the rule is load-bearing for the mutable
        # scalars it was written for. Only the slots a short-circuit carries
        # its value through are excluded, and those are recognisable from the
        # bytecode alone -- a slot that holds an `&&` is never one of the
        # source's own locals.
        self.short_circuit_slots = self._short_circuit_slots()
        forced |= prefix_forced - self.short_circuit_slots
        self.sparse_switches = {index: pattern for index in range(len(self.instrs))
                               if (pattern := self._sparse_switch_pattern(index)) is not None}
        # The dense form -- a jump table -- yields the same tuple, so the rest
        # of the pipeline does not care which one it was.
        for index in range(len(self.instrs)):
            if index in self.sparse_switches:
                continue
            pattern = self._dense_switch_pattern(index)
            if pattern is not None:
                self.sparse_switches[index] = pattern
        self.stored_const_types = self._stored_constant_types()
        self.generated_member_init = self._generated_member_initialisers()
        for index, (_, cases, default, join, _) in self.sparse_switches.items():
            first_case = min([target for _, target in cases] + [default])
            for op in self.instrs:
                off = _s16(op.w_arg)
                # A scalar updated in several cases is one mutable local,
                # rather than an expression composed by walking every arm.
                if (first_case <= op.pos < join and op.name in IMM_BINARY
                        and op.w_arg == op.w_arg2 and off > 0
                        and off in self.var_types
                        and self.var_types[off].token_type == _numeric_type(op.name).token_type
                        and any(prev.pos < self.instrs[index].pos
                                and prev.name.startswith("SetV") and prev.w_arg == op.w_arg
                                for prev in self.instrs)):
                    forced.add(off)
        for op in self.instrs:
            if op.name in ("LoadRObjR", "LoadVObjR"):
                off = _s16(op.w_arg)
                if off > 0 and off in self.var_types and self.var_types[off].obj_type:
                    forced.add(off)
            persists_into_try = (op.name in IMM_BINARY and op.w_arg == op.w_arg2
                and any(start <= op.pos and any(prev.pos < start and prev.w_arg == op.w_arg
                        and prev.name.startswith("SetV") for prev in self.instrs)
                        for start, _, _ in fn.try_catch_info))
            if op.name in ("IncVi", "DecVi", "LDV") or persists_into_try:
                off = _s16(op.w_arg)
                if off > 0 and off in self.var_types:
                    forced.add(off)
        for off in forced:
            self.var_names.setdefault(off, f"local_{off}")
        self.declared: set[int] = {off for off, _ in _parameter_layout(fn)}
        # simulation state
        self.stack: list[Atom] = []
        self.temps: dict[int, Atom] = {}       # temp offset -> value atom
        self.value_reg: Atom = Atom("raw", "<?reg>")
        self.obj_reg: Atom | None = None
        self.pending_global: str | None = None  # LdGRdR4 target for WRTV4
        self.cmp_pair: tuple[Atom, Atom] | None = None
        self.cmp_is_handle = False
        rt = fn.return_type.format() if fn.return_type else "void"
        self.returns_value = rt not in ("", "void")
        self.return_slot = -1 if fn.object_type and _needs_out_ref(fn.return_type) else 0
        # output events
        self.events: list[Event] = []
        self.skip_indexes: set[int] = set()
        self.bool_merges: list[dict] = []
        self.pending_value_call: str | None = None
        # deferred call text -> (return type, its out-argument locals, position)
        self.deferred_out_calls: dict[str, tuple] = {}
        self.pending_value_call_pos: int = 0
        self.consumed_temps: set[int] = set()
        # slots this simulation promoted from temporary to variable
        self.forced_slots: set[int] = set()
        #: {slot: (bytecode position, statements emitted)} when its temp was
        #: bound, so `_stale_fold` can tell an immediate read from a later one
        #: and put the variable's assignment back where the value was computed.
        self.temp_bound: dict[int, tuple[int, int]] = {}
        #: statements emitted so far, and their text. Events are sorted by
        #: position at the end, not kept in append order, which is what lets a
        #: promotion insert its assignment where it belongs rather than here.
        self.stmt_count = 0
        self.stmt_texts: list[str] = []
        #: {(slot, bind position): folds} for a value that is not repeatable.
        #: Counted so the *next* simulation of this function can promote the
        #: ones folded more than once -- see `_body`.
        self.fold_reads: dict[tuple[int, int], int] = {}
        #: (slot, bind position) pairs a previous pass found folded more than
        #: once. Promoted on sight here, which is the only way to get the
        #: assignment in before the first read rather than after it.
        self.duplicate_binds: set[tuple[int, int]] = set()
        self.list_values: dict[int, dict[int, Atom]] = {}
        self.list_sizes: dict[int, int] = {}
        self.list_types: dict[int, dict[int, DataType]] = {}
        self.object_branch_snapshots: dict[int, dict[int, Atom]] = {}

    # -- variable helpers ---------------------------------------------------

    def _generated_member_initialisers(self) -> set[int]:
        """Instructions of the member initialisation a constructor is given.

        A member declared by value but held by reference -- `timer movement;`,
        `weapon@[] temporary_weapons;` -- is created by code the compiler puts
        at the top of every constructor, which source never wrote:

            CALLSYS $beh3()          create one
            STOREOBJ v               keep it
            PshVPtr v / PshVPtr 0    the new object, then `this`
            ADDSi character.movement the member's address
            REFCPY                   store it
            PopPtr / FREE v          drop the temporary

        `_refcpy` already drops the store itself, for exactly this reason, and
        re-emitting the property declarations reproduces the whole prologue on
        the way back in. What was left behind was the creation -- `@local_3 =
        weapon@[]();` -- which is both noise and, for an array of handles,
        not even expressible: BGT's parser takes `weapon@[]` as a declaration
        and nothing else, so there is no constructor call to write.

        The shape alone is not enough to call it generated, because
        `@this.handle_member = timer();` compiles to the same eight
        instructions. What settles it is the member being declared *by value*:
        then no source statement can produce this, and the prologue is the
        only explanation.
        """
        out: set[int] = set()
        if self.fn.object_type is None:
            return out
        shape = ["STOREOBJ", "PshVPtr", "PshVPtr", "ADDSi", "REFCPY",
                 "PopPtr", "FREE"]
        for k in range(len(self.instrs) - len(shape)):
            if self.instrs[k].name not in ("CALL", "CALLSYS"):
                continue
            if [i.name for i in self.instrs[k + 1:k + 1 + len(shape)]] != shape:
                continue
            slot = _s16(self.instrs[k + 1].w_arg)
            if slot <= 0 or _s16(self.instrs[k + 2].w_arg) != slot:
                continue
            if _s16(self.instrs[k + 7].w_arg) != slot:
                continue
            if _s16(self.instrs[k + 3].w_arg) != 0:      # not `this`
                continue
            dt = self.property_types.get(self.instrs[k + 4].prop_name)
            if dt is None or dt.is_object_handle:
                continue                                  # a real assignment
            out.update(range(k, k + 1 + len(shape)))
        return out

    def name_of(self, off: int) -> str:
        n = self.var_names.get(off)
        if n:
            return n
        if off == 0 and self.fn.object_type is not None:
            return "this"           # slot 0 is `this` inside methods
        return f"tmp{off}" if off >= 0 else f"tmp_{-off}"

    def is_named(self, off: int) -> bool:
        return off in self.var_names

    def var_atom(self, off: int) -> Atom:
        return Atom("var", self.name_of(off), 1, data_type=self.var_types.get(off))

    def _deref(self, a: Atom) -> Atom:
        """Resolve an address atom to the value it points at, preferring
        the expression bound to a temp slot over the placeholder name."""
        if a.kind == "list_elem":
            return self.list_values.get(a.offset, {}).get(a.list_index, Atom("raw", "<?>"))
        if a.is_ptr and a.offset is not None:
            if a.offset in self.temps:
                value = self._read_temp(a.offset)
                # A slot whose value is read twice is a variable, not a
                # temporary. Twice means the SAME value twice: a slot written
                # again between the reads is an ordinary reused temporary, and
                # folding each value into its one read is both correct and
                # what lets the structurer see a loop condition as an
                # expression rather than as a statement before the jump. Folding an expression into every read writes --
                # and runs -- it once per read: a stripped build with no
                # declaration for the slot turned one `enemies_in_range()`
                # call into fourteen, in a 21,000-character expression. Only
                # an impure value forces this; a constant or another variable
                # can be repeated without changing what the program does.
                return value
            # An object slot the frame zeroed and nothing wrote holds null:
            # a handle member's initialisation, and the default for an omitted
            # handle argument, both read it. Rendered as the variable it is
            # not, the reads are "'local_6' is not declared" -- 204 of
            # Paladin's errors -- and the call then looks as though it passed
            # an int. Only where null is what it would hold: a numeric slot
            # read before it is written reads as 0, not null.
            # A slot under list construction has been written -- its values
            # live in `list_values`, not in `temps` -- so it is not one of
            # these: `array<string>(null)` for an initialiser list is "No
            # matching signatures to 'string[](<null handle>)'".
            if (a.offset > 0 and a.offset not in self.declared
                    and a.offset not in self.parameter_slots
                    and a.offset not in self.list_values
                    and a.offset not in self.list_sizes
                    and a.offset not in self.list_types):
                dt = self.var_types.get(a.offset)
                if dt is None or dt.is_object_handle or dt.obj_type is not None:
                    return Atom("null", "null")
            return self.var_atom(a.offset)
        if a.is_ptr:
            # pointer into an object (property, global): reading through it
            # yields the member itself as a value
            value = copy.copy(a)
            value.dw_size, value.is_ptr = 1, False
            return value
        return a

    def _discarded_call(self, off: int) -> None:
        """A call whose result nothing reads still ran: emit it where it ran.

        `_bind` parks a value in `temps[off]` and emits nothing, on the
        assumption that some later read will fold it in. A call that nothing
        reads has no such read -- so the call itself disappears, and a call
        is not a value, it is something the program did.

        BGT's own `audio_form::create_window` is the clearest case. Stock
        `form.bgt` opens

            if(!active)
            {
            get_characters();
            }

        where `get_characters` returns a string nobody wants, because the
        point of calling it is to drain the keyboard buffer. The bytecode is
        `PSF 2 ; CALLSYS get_characters ; PSF 2 ; CALLSYS $beh2`, and the
        recovered source was `if (!active) { }` -- so a recovered form never
        drains the buffer and stale keystrokes leak into the first field. It
        compiles, it runs, and nothing reports it.

        `FREE` has handled this since the value-register work; these are the
        other three ends of a temp's life, and the statement is emitted at
        the position the value was *bound* rather than here, because events
        are sorted by bytecode position at the end of the simulation.
        """
        value = self.temps.get(off)
        if (value is None or value.kind != "call"
                or off in self.consumed_temps):
            return
        bound = self.temp_bound.get(off)
        if bound is None:
            return
        self.stmt_count += 1
        self.stmt_texts.append("")
        self.events.append(Event("stmt", bound[0], ("", f"{value.text};")))
        self.consumed_temps.add(off)

    def _bind(self, off: int, a: Atom) -> None:
        """Store a value into frame slot `off` (statement or temp alias).

        **Flushing a discarded call here was tried and is wrong**, and the
        measurement is why: a rebind is not proof that the previous value
        went unread. A short-circuit merge binds its condition slot, the
        branch reads it, and the slot is written again -- and every
        intermediate of a built-up expression does the same, so Paladin's
        `clock::reset` came out as

            get_time(false);
            ("The time is " + get_time(false));
            (("The time is " + get_time(false)) + "[/]Today's date is ");
            this.speeches[this.mode] = ((((...)));

        with each partial expression emitted *and* folded into the final
        statement. That is not recovering a dropped call, it is running
        `recorder.rand(...)` five extra times. The ends of a temp's life
        that really are ends -- `FREE`, a destructor, the end of the body --
        are handled where they happen.
        """
        a = self._deref(a) if a.is_ptr else a
        if (a.kind == "const" and off in self.var_types
                # ...unless this constant was typed from where it is stored
                # rather than from the slot it passes through. Re-normalising
                # to the slot's type is what turned 1.5f back into `true`:
                # `_typed_constant` drops the bits for a bool, so nothing
                # downstream could recover the value.
                and self.k not in self.stored_const_types):
            a = self._normalize_arg(a, self.var_types[off])
        if off == self.return_slot and self.returns_value and off not in self.parameter_slots:
            if _needs_out_ref(self.fn.return_type):
                self.consumed_temps.discard(off)
                self.temps[off] = a
                return
        if self.is_named(off):
            self._emit_assign(off, a)
        else:
            self.consumed_temps.discard(off)
            self.temps[off] = a
            # Where this value was computed, and how much had been emitted by
            # then. A fold is only safe while nothing has run in between --
            # see `_stale_fold`.
            self.temp_bound[off] = (self._pos(), self.stmt_count)

    def _emit_declare(self, off: int) -> None:
        """Emit a bare declaration for a named variable (default-constructed)."""
        if off in self.declared:
            return
        self.declared.add(off)
        dt = self.var_types.get(off)
        tn = (dt.format() if dt else "").replace("&", "").strip()
        self.events.append(Event("stmt", self._pos(), (tn, f"{self.name_of(off)};")))

    def _emit_assign(self, off: int, a: Atom) -> None:
        # The statement supersedes any expression still aliased to this slot.
        # A folded short-circuit is bound to its slot so later reads see the
        # whole value; left there after the slot is assigned again, every
        # later read came back as that stale `(A && B)` -- 104 of Psycho
        # Strike's errors were one `clear_pathway` temporary read six times.
        self.temps.pop(off, None)
        self.consumed_temps.discard(off)
        if off in self.var_types:
            a = self._normalize_arg(a, self.var_types[off])
        if off in self.mixed_boolean_slots:
            if a.text in ("true", "false"):
                a = Atom("const", "1" if a.text == "true" else "0")
            elif a.data_type and a.data_type.token_type == 67:
                a = Atom("call", f"({a.text} ? 1 : 0)")
        name = self.name_of(off)
        if off not in self.declared:
            self.declared.add(off)
            dt = self.var_types.get(off)
            tn = dt.format() if dt else ""
            tn = tn.replace("&", "").strip()
            if dt and dt.obj_type and not dt.is_object_handle and a.text.startswith(tn + "(") and a.text.endswith(")"):
                text = f"{name}{a.text[len(tn):]};"
            else:
                text = f"{name} = {a.text};"
            self._append_stmt(tn, text)
        else:
            # A handle variable is REASSIGNED with `@`. Without it the statement
            # is a value copy into the object the handle points at, which
            # `sound` and every funcdef type refuse: "No appropriate opAssign
            # method found in 'sound' for value assignment".
            dt = self.var_types.get(off)
            prefix = "@" if dt is not None and dt.is_object_handle else ""
            self._append_stmt("", f"{prefix}{name} = {a.text};")

    def _pos(self) -> int:
        return self.instrs[self.k].pos

    def _stmt(self, text: str) -> None:
        self._append_stmt("", text)

    def _append_stmt(self, type_name: str, text: str) -> None:
        self._order_out_arguments(text)
        self.stmt_count += 1
        self.stmt_texts.append(text)
        self.events.append(Event("stmt", self._pos(), (type_name, text)))

    def _order_out_arguments(self, text: str) -> None:
        """Run a deferred call before the first statement that reads its output.

        A call whose value is used later -- typically as a condition -- is
        deferred and folded into that later expression. When it also writes an
        `out` argument, the compiler copies the output into its destination
        straight after the call, *before* the condition is tested:

            if (!d.get("item", @fetched)) return -4;

        compiles to call; copy output into `fetched`; test. Folding the call
        into the condition put the copy first, reading `fetched` before `get`
        had written it. So when a statement mentions a deferred call's output
        local, the call is declared into a local of its own here, and every
        pending expression that embedded it reads that local instead.
        """
        for calltxt, (ret, locals_, pos) in list(self.deferred_out_calls.items()):
            if not any(re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", text)
                       for name in locals_):
                continue
            del self.deferred_out_calls[calltxt]
            holders = [a for a in [self.value_reg, *self.temps.values()]
                       if a is not None and calltxt in a.text]
            if not holders:
                continue                     # already consumed, in order
            local = f"__nvgt_ret_{pos}"
            dt = copy.copy(ret)
            dt.is_reference = dt.is_readonly = False
            self.events.append(Event("stmt", pos, (dt.format(), f"{local} = {calltxt};")))
            for a in holders:
                a.text = a.text.replace(calltxt, local)
            # The call has been emitted here; if its own return value was never
            # consumed it is still pending as a bare statement, and flushing that
            # would emit the call a second time (`d.get(...)` twice).
            if self.pending_value_call == calltxt:
                self.pending_value_call = None

    # -- main loop ------------------------------------------------------------

    def run(self) -> list[Event]:
        n = len(self.instrs)
        self.k = 0
        # temp-lifetime ends from objVariableInfo (option 0): clear the alias
        # so stale expressions don't leak into later statements
        self.objvar_ends: dict[int, int] = {}
        for pos, off, opt in self.fn.obj_variable_info:
            if opt == 0 and off:
                self.objvar_ends[pos] = off
        # Sibling scopes reuse a slot: form.bgt declares `dictionary args =
        # {...}` in several blocks, all at one offset. Declaring a slot only on
        # its first assignment left every later block writing `args = ...`
        # with no declaration in scope ("No matching symbol 'args'"). Debug
        # info records each declaration separately, so each one starts a new
        # declaration here.
        redeclare: dict[int, list] = {}
        if self.fn.has_debug_info:
            by_slot: dict[int, list] = {}
            for v in self.fn.variables:
                if v.name and v.stack_offset > 0:
                    by_slot.setdefault(v.stack_offset, []).append(v)
            for off, decls in by_slot.items():
                if len({v.declared_at for v in decls}) > 1:
                    for v in decls:
                        redeclare.setdefault(v.declared_at, []).append(v)
        self.skip_indexes.update(self.generated_member_init)
        while self.k < n:
            if self.k in self.skip_indexes:
                self.k += 1
                continue
            ins = self.instrs[self.k]
            for v in redeclare.pop(ins.pos, ()):
                off = v.stack_offset
                self.declared.discard(off)
                # The declaration's own name and type -- touch.nvgt's `bool
                # in_bounds` and `float dist_sq_start` share a slot in sibling
                # blocks, and one type per slot assigned a bool to a float.
                # Not for the bool/int slots merged deliberately above, and
                # without `const`: the slot is still written more than once.
                if off not in self.mixed_boolean_slots:
                    self.var_names[off] = v.name
                    vt = copy.copy(v.type)
                    vt.is_readonly = False
                    self.var_types[off] = vt
            # Linear simulation visits cleanup on a returning then-path before
            # the else-path. That cleanup cannot erase an object still alive
            # on the branch which jumps over it.
            for off, value in self.object_branch_snapshots.pop(ins.pos, {}).items():
                current = self.temps.get(off)
                if current and current.kind == "null":
                    self.consumed_temps.discard(off)
                    self.temps[off] = value
            # Object lifetime metadata can precede the instruction consuming
            # its last value. FREE and explicit stores maintain aliases.
            self.step(ins)
            self.k += 1
        # **Sweeping the leftover temps here was tried and is unsound.** A
        # call still parked in `temps` at the end of the body has not
        # necessarily gone unread -- a value consumed inside a loop is still
        # sitting there afterwards -- and emitting those put spurious
        # `key_down()`, `key_pressed()` and `length()` statements into
        # `audio_form::check_shortcuts` and `get_list_selections`. Measured
        # against BGT's own shipped source it cost two functions their exact
        # call sequence and bought one real recovery, so it is not here.
        # `RET` flushes the value register, which is where the cases that
        # *are* provable arrive.
        # Ignored non-void calls can be recognized only after later opcodes
        # overwrite their result. Keep their original location in the CFG.
        return sorted(self.events, key=lambda event: event.pos)

    def _is_reference_type(self, dt: DataType) -> bool:
        """Is this a reference type -- one that is only ever held by handle?

        Every script class is (script objects are ref types). A registered
        type is when its values were seen coming back through the object
        register (asreader infers that from STOREOBJ after a call).
        """
        ti = dt.obj_type
        if ti is None or ti.kind in ("enum", "typedef"):
            return False
        if any(ti is c or (ti.name == c.name and ti.namespace_ == c.namespace_)
               for c in self.m.classes):
            return True
        return bool(ti.flags & 1 or ti.return_via_object_register)

    def _inherited_property(self, name: str) -> bool:
        """Is `name` a property this class inherits rather than declares?

        AngelScript accepts an inherited PRIVATE property through `this.` and
        rejects the bare name ("Illegal access to inherited private property"),
        which the owned test `this.secret = true;` vs `secret = true;` shows.
        `this.` is always valid for an inherited member, so it is always used.
        """
        cls = self.fn.object_type
        if cls is None:
            return False
        return any(prop == name and flags & 4 for prop, _dt, flags in cls.properties)

    def _is_base_of_current(self, ti) -> bool:
        cls = self.fn.object_type
        base = cls.derived_from if cls is not None else None
        while base is not None:
            if base is ti or base.format_name() == ti.format_name():
                return True
            base = base.derived_from
        return False

    def _short_prop(self, prop_name: str | None, w: int) -> str:
        """Reader-side prop names are 'Class.member'; inside a method the
        class prefix is redundant."""
        if prop_name and "." in prop_name:
            return prop_name.split(".", 1)[1]
        return prop_name or f"<?prop{w}>"

    def step(self, ins: Instr) -> None:
        name = ins.name
        if self.k in self.sparse_switches:
            end, cases, default, join, offset = self.sparse_switches[self.k]
            self._flush_pending_call()
            self.events.append(Event("switch", ins.pos,
                                     (self._slot_atom(offset).text, cases, default, join)))
            self.skip_indexes.update(range(self.k + 1, end))
            return
        if name == "SUSPEND":
            self._flush_pending_call()
            return
        if name == "AllocMem":
            self.list_values[_s16(ins.w_arg)] = {}
            self.temps.pop(_s16(ins.w_arg), None)
            return
        if name == "SetListSize":
            self.list_sizes[_s16(ins.w_arg)] = ins.qw_arg
            return
        if name == "SetListType":
            if ins.data_type:
                self.list_types.setdefault(_s16(ins.w_arg), {})[ins.dw_arg + 1] = ins.data_type
            return
        if name == "PshListElmnt":
            self.stack.append(Atom("list_elem", "<?list>", 1, is_ptr=True,
                                   offset=_s16(ins.w_arg), list_index=ins.dw_arg))
            return
        if name in SKIP_OPS:
            return

        if name == "SwapPtr":
            # Exchanges the two pointers on top of the stack (asBC_SwapPtr).
            # The compiler uses it to put an object back on top as the
            # receiver after pushing a hidden result address:
            # `ADDSi val / PSF 7 / SwapPtr / CALLSYS var::opImplConv`. As a
            # no-op the receiver and the result slot traded places, and the
            # converted value was lost ("No matching symbol 'tmp7'").
            if len(self.stack) >= 2:
                self.stack[-1], self.stack[-2] = self.stack[-2], self.stack[-1]
            return

        if name == "ClrVPtr":
            self._bind(_s16(ins.w_arg), Atom("const", "null", 2))
            return

        # ---- register-style arithmetic / moves --------------------------
        if name in BINARY:
            d, s1, s2 = _s16(ins.w_arg), _s16(ins.w_arg2), _s16(ins.qw_arg & 0xFFFF)
            self._binop_vars(d, s1, BINARY[name], s2, numeric_type=_numeric_type(name))
            return
        if name in IMM_BINARY:
            d, s = _s16(ins.w_arg), _s16(ins.w_arg2)
            self._binop_vars(d, s, IMM_BINARY[name], None, _s32(ins.dw_arg), _numeric_type(name))
            return
        if name in CONV_OPS:
            d = _s16(ins.w_arg)
            # Many conversions (iTOf, fTOi, etc.) operate in place. Reading
            # their absent second argument used to substitute slot 0 / this.
            s = d if ins.bc_type == "asBCTYPE_rW_ARG" else _s16(ins.w_arg2)
            src = self._slot_atom(s)
            target = name.split("TO", 1)[1]
            target = {"i": "int", "u": "uint", "f": "float", "d": "double",
                      "i64": "int64", "u64": "uint64", "b": "int8",
                      "w": "int16"}.get(target, "int")
            self._bind(d, Atom("call", f"{target}({src.text})"))
            return
        if name in ("NEGf", "NEGi", "NEGi64", "NEGd"):
            s = _s16(ins.w_arg)
            self._bind(s, Atom("call", f"-({self._slot_atom(s).text})"))
            return
        if name in ("CpyVtoR4", "CpyVtoR8"):
            # Any earlier call still in the value register was intentionally
            # ignored; preserve its side effect before the register is reused.
            self._flush_pending_call()
            off = _s16(ins.w_arg)
            value = self._slot_atom(off)
            while self.bool_merges and self.bool_merges[-1]["dest"] == off \
                    and ins.pos >= self.bool_merges[-1]["merge"]:
                merge = self.bool_merges.pop()
                # Both sides of `&&` / `||` are bools, and the compiler reuses
                # int temporaries for them, so the slot's declared type is
                # often int: `(c) && local_1` is "No conversion from 'int' to
                # 'bool' available".
                operand = self._normalize_arg(value, DataType(token_type=67))
                value = Atom("call",
                             f"({merge['first'].text} {merge['op']} {operand.text})",
                             data_type=DataType(token_type=67))
                if not self.is_named(off):
                    # Only a temporary carries the merged value onward; a
                    # named variable keeps its own identity, and its later
                    # writes are statements that this alias would outlive.
                    self.consumed_temps.discard(off)
                    self.temps[off] = value
            self.value_reg = value
            return
        if name in ("CpyRtoV4", "CpyRtoV8"):
            self._bind(_s16(ins.w_arg), self.value_reg)
            self.pending_value_call = None
            return
        if name in ("CpyVtoV4", "CpyVtoV8"):
            src = _s16(ins.w_arg2)
            value = self._slot_atom(src)
            # A stored short-circuit result: `bool b = A && B` copies the merged
            # slot into b here. Fold (A op B) into b so its later reads -- in an
            # if, a ternary or an expression -- get the whole value, not just B.
            while self.bool_merges and self.bool_merges[-1]["dest"] == src \
                    and ins.pos >= self.bool_merges[-1]["merge"]:
                merge = self.bool_merges.pop()
                operand = self._normalize_arg(value, DataType(token_type=67))
                value = Atom("call",
                             f"({merge['first'].text} {merge['op']} {operand.text})",
                             data_type=DataType(token_type=67))
            self._bind(_s16(ins.w_arg), value)
            return
        if name in ("SetV4", "SetV8", "SetV2", "SetV1"):
            if ins.string_const is not None:
                a = Atom("const", f'"{_esc(ins.string_const)}"', 2)
            else:
                off = _s16(ins.w_arg)
                v = ins.qw_arg if name == "SetV8" else _s32(ins.dw_arg)
                a = self._typed_constant(
                    v, self.stored_const_types.get(self.k) or self.var_types.get(off),
                    name == "SetV8")
            self._bind(_s16(ins.w_arg), a)
            return
        if name == "LdGRdR4":
            g = ins.global_name or "<?global>"
            self._bind(_s16(ins.w_arg),
                       Atom("global", g, data_type=self.global_types.get(g)))
            self.pending_global = g
            # the value register now holds &global (WRTV4 writes through it)
            self.value_reg = Atom("global", g, 1, is_ptr=True,
                                  data_type=self.global_types.get(g))
            return
        if name in ("WRTV1", "WRTV2", "WRTV4", "WRTV8"):
            v = self._slot_atom(_s16(ins.w_arg))
            g = self.pending_global
            self.pending_global = None
            if self.value_reg.kind == "list_elem":
                ptr = self.value_reg
                dt = self.list_types.get(ptr.offset, {}).get(ptr.list_index)
                self.list_values.setdefault(ptr.offset, {})[ptr.list_index] = self._normalize_arg(v, dt) if dt else v
            elif self.value_reg.kind == "global" and self.value_reg.is_ptr:
                self._emit_global_write(self.value_reg.text, v)
            elif self.value_reg.is_ptr:
                # write through a pointer held in the value register
                # (LoadThisR: `this.prop = value`)
                if self.value_reg.data_type:
                    v = self._normalize_arg(v, self.value_reg.data_type)
                self._stmt(f"{self.value_reg.text} = {self._deref(v).text};")
            return
        if name == "CpyGtoV4":
            # value register -> frame slot (the reverse of CpyVtoG4). With the
            # global's declared type: a bool global copied into a slot the
            # bytecode uses as an int is "Can't implicitly convert from 'bool'
            # to 'int'" without it, where the conversion is what the compiler
            # itself would have written.
            self._bind(_s16(ins.w_arg),
                       Atom("global", ins.global_name or "<?global>",
                            data_type=self.global_types.get(ins.global_name)))
            self.value_reg = Atom("raw", "<?reg>")
            return
        if name == "CpyVtoG4":
            self._emit_global_write(ins.global_name or "<?global>",
                                    self._slot_atom(_s16(ins.w_arg)))
            return
        if name == "SetG4":
            self._emit_global_write(ins.global_name or "<?global>",
                                    Atom("const", str(_s32(ins.dw_arg))))
            return
        if name == "LDG":
            g = ins.global_name or "<?global>"
            self.pending_global = g
            # With the global's type: a `bool` global read through this
            # pointer into a slot the bytecode also uses as an int needs the
            # conversion the compiler would have written (`RDR1` reads one
            # byte, and the slot is declared from the wider use).
            self.value_reg = Atom("global", g, 1, is_ptr=True,
                                  data_type=self.global_types.get(g))
            return
        if name in ("RDR1", "RDR2", "RDR4", "RDR8"):
            # RDR* reads *through* the pointer in the value register into a
            # frame slot: `off = *ptr` (e.g. LoadThisR + RDR4 = read this.prop)
            a = self._deref(self.value_reg) if self.value_reg.is_ptr \
                else self.value_reg
            self._bind(_s16(ins.w_arg), a)
            return
        if name == "LDV":
            off = _s16(ins.w_arg)
            self.value_reg = Atom("ptr", self.name_of(off), 1, is_ptr=True, offset=off)
            self.pending_global = None
            return
        if name in ("IncVi", "DecVi"):
            self._stmt(f"{self.name_of(_s16(ins.w_arg))}"
                       f"{'++' if name == 'IncVi' else '--'};")
            return
        if name.startswith("INC"):
            self._stmt(f"{self._ptr_target_text()} += 1;" if self.value_reg.is_ptr
                       else "// INC (unsupported target)")
            return
        if name.startswith("DEC") and not name.startswith("DECi"):
            self._stmt(f"{self._ptr_target_text()} -= 1;" if self.value_reg.is_ptr
                       else "// DEC (unsupported target)")
            return
        if name in ("DECi", "DECi8", "DECi16", "DECi64"):
            self._stmt(f"{self._ptr_target_text()} -= 1;" if self.value_reg.is_ptr
                       else "// DEC (unsupported target)")
            return
        if name == "ADDProp":
            self._stmt(f"{self._ptr_target_text()} += {ins.prop_name};")
            return

        # ---- comparisons & jumps ----------------------------------------
        if name in ("CMPi", "CMPi64", "CMPu", "CMPu64", "CMPf", "CMPd"):
            self._flush_pending_call()
            dt = _numeric_type(name)
            self.cmp_pair = (self._normalize_arg(self._compared(_s16(ins.w_arg)), dt),
                             self._normalize_arg(self._compared(_s16(ins.w_arg2)), dt))
            return
        if name == "CmpPtr" and self._begin_ref_cast(ins):
            return
        if name == "CmpPtr":
            self._flush_pending_call()
            self.cmp_pair = (self._compared(_s16(ins.w_arg)),
                             self._compared(_s16(ins.w_arg2)))
            # Handle identity: `a !is b`, not `a != b`, which asks the type
            # for an opEquals -- "No matching operator that takes the types
            # 'music_track@&' and 'music_track@&'".
            self.cmp_is_handle = True
            return
        if name in ("CMPIi", "CMPIi64", "CMPIu", "CMPIu64", "CMPIf", "CMPIf64"):
            self._flush_pending_call()
            off = _s16(ins.w_arg)
            self.cmp_pair = (self._compared(off),
                             self._typed_constant(_s32(ins.dw_arg), _numeric_type(name)))
            return
        if name in ("EQi", "EQf", "EQu", "EQi64", "EQu64", "EQd", "EQPtr"):
            self.cmp_pair = (self._slot_atom(_s16(ins.w_arg)),
                             self._slot_atom(_s16(ins.w_arg2)))
            return
        if name in TEST_OPS:
            op = TEST_OPS[name]
            if self.cmp_pair is not None and self.cmp_is_handle and op in ("==", "!="):
                op = "is" if op == "==" else "!is"       # handle identity
            self.cmp_is_handle = False
            if self.cmp_pair is not None:
                a, b = self.cmp_pair
                self.cmp_pair = None
                text = f"({a.text} {op} {b.text})"
                # `x == true` is `x`, `x == false` is `!x`, ... -- the same
                # simplification _taken_condition does, but for a comparison
                # used as a value inside a larger `&&` / `||`.
                if op in ("==", "!="):
                    left, right = _unwrap_bool(a.text), _unwrap_bool(b.text)
                    for lit, other in ((right, left), (left, right)):
                        if lit in ("true", "false"):
                            keep = (op == "==") == (lit == "true")
                            text = other if keep else _negate_cond(other)
                            break
                self.value_reg = Atom("call", text, data_type=DataType(token_type=67))
            else:
                self.value_reg = Atom("call", f"({self.value_reg.text} {op} 0)", data_type=DataType(token_type=67))
            return
        if name == "NOT":
            off = _s16(ins.w_arg)
            value = self._normalize_arg(self._slot_atom(off), DataType(token_type=67))
            self._bind(off, Atom("call", _negate_cond(value.text), data_type=DataType(token_type=67)))
            return
        if name in ("BNOT", "BNOT64"):
            off = _s16(ins.w_arg)
            self._bind(off, Atom("call", f"~({self._slot_atom(off).text})"))
            return
        if name in JUMP_OPS:
            if self._begin_bool_merge(ins):
                return
            if self._begin_value_merge(ins):
                return
            self._branch(ins)
            return
        if name == "JMP":
            self._flush_pending_call()
            target = _jump_target(ins)
            if self._is_void_return_target(target):
                self.events.append(Event("stmt", self._pos(), ("", "return;")))
            elif self.returns_value and self._is_return_target(target):
                if _needs_out_ref(self.fn.return_type):
                    value = self.temps.get(self.return_slot)
                elif self.fn.return_type.obj_type and self.obj_reg is not None:
                    value = self.obj_reg
                else:
                    value = self.value_reg
                if value is not None and value.kind != "raw":
                    value = self._normalize_arg(value, self.fn.return_type)
                    self._stmt(f"return {value.text};")
                else:
                    self.events.append(Event("jump", self._pos(), target))
            else:
                self.events.append(Event("jump", self._pos(), target))
            return
        if name == "JMPP":
            if self._begin_switch(ins):
                return
            # Neither matcher claimed this table, so its entries are not
            # skipped: each becomes a `goto` and each arm is emitted as an
            # ordinary block, closing braces and all, with nothing that
            # opened them. Manamon 2's `number_key_pressed` came out with ten
            # unmatched `}` -- which does not parse, and which the compiler
            # blames on a declaration hundreds of lines later.
            #
            # A counted failure is worth more than that. The whole body is
            # given up on rather than half-emitted, which `_body` turns into a
            # `// [decompiler error: ...]` line and `bgt recover` counts under
            # "bodies that failed".
            raise UnstructuredSwitch(
                "jump table at 0x%X claimed by neither switch matcher" % ins.pos)

        # ---- stack ops ----------------------------------------------------
        if name == "LoadThisR":
            # PshVPtr 0 + ADDSi + PopRPtr fused: value register = &this.prop.
            # w_arg is the property index (resolved to a name by the reader).
            pname = self._short_prop(ins.prop_name, ins.w_arg)
            if self.fn.object_type is None:
                pname = f"{self._slot_atom(0).text}.{pname}"
            elif pname in self.var_names.values() or self._inherited_property(pname):
                pname = f"this.{pname}"
            self.value_reg = Atom("prop", pname, 1, is_ptr=True,
                                  data_type=self.property_types.get(ins.prop_name))
            return
        if name in ("LoadRObjR", "LoadVObjR"):
            base = self._slot_atom(_s16(ins.w_arg))
            pname = self._short_prop(ins.prop_name, ins.w_arg2)
            self.value_reg = Atom("prop", f"{base.text}.{pname}", 1, is_ptr=True,
                                  data_type=self.property_types.get(ins.prop_name))
            return
        if name == "ADDSi":
            # add a member offset to the pointer on top of the stack
            if self.stack and ins.prop_name:
                pname = self._short_prop(ins.prop_name, ins.w_arg)
                base = self._deref(self.stack[-1]).text
                text = pname if base in ("this", pname) else f"{base}.{pname}"
                if base == "this" and (pname in self.var_names.values()
                                       or self._inherited_property(pname)):
                    text = f"this.{pname}"
                self.stack[-1] = Atom("prop", text, 1, is_ptr=True,
                                       data_type=self.property_types.get(ins.prop_name))
            return
        if name in ("PSF", "PshVPtr", "VAR"):
            off = _s16(ins.w_arg)
            label = self.name_of(off)
            # With the slot's declared type: a write THROUGH this pointer is
            # the only thing that says what the destination is, and without it
            # an int slot written to a `bool&out` parameter came out as
            # `arg0 = local_1;` -- "Can't implicitly convert from 'int' to
            # 'bool&'" -- instead of the conversion the compiler would have
            # made itself.
            self.stack.append(Atom("ptr", label, 2, is_ptr=True, offset=off,
                                   data_type=self.var_types.get(off)))
            return
        if name in ("PshV4", "PshV8"):
            a = self._slot_atom(_s16(ins.w_arg))
            a = copy.copy(a)
            a.dw_size = 2 if name == "PshV8" else 1
            self.stack.append(a)
            return
        if name == "PshC4":
            self.stack.append(Atom("const", str(_s32(ins.dw_arg)), 1))
            return
        if name == "PshC8":
            self.stack.append(Atom("const", str(_s64(ins.qw_arg)), 2))
            return
        if name == "PshNull":
            self.stack.append(Atom("null", "null", 2))
            return
        if name == "PshRPtr":
            self.stack.append(self.value_reg)
            self.pending_value_call = None
            return
        if name == "PopRPtr":
            self.value_reg = self.stack.pop() if self.stack else Atom("raw", "<?reg>")
            return
        if name == "RDSPtr":
            if self.stack:
                self.stack[-1] = self._deref(self.stack[-1])
            return
        if name == "STR":
            # The older engine (BGT's AngelScript) has a dedicated opcode for a
            # string literal: STR pushes the constant's address and then its
            # length, and the registered string factory pops both to build the
            # string. stackInc is 2 there for exactly that reason, so pushing
            # one slot makes the factory's arity over-pop and the literal
            # disappears into a neighbouring call.
            self.stack.append(Atom("const", f'"{_esc(ins.string_const)}"', 1)
                              if ins.string_const is not None
                              else Atom("raw", f"<?str#{ins.dw_arg}>"))
            self.stack.append(Atom("const", "<strlen>", 1))
            return
        if name in ("PshG4", "PshGPtr", "PGA"):
            if ins.string_const is not None and name in ("PGA", "PshGPtr"):
                self.stack.append(Atom("const", f'"{_esc(ins.string_const)}"', 1))
            else:
                self.stack.append(Atom("global", ins.global_name or "<?global>", 1,
                                       is_ptr=name != "PshG4",
                                       data_type=self.global_types.get(ins.global_name)))
            return
        if name == "PopPtr":
            if self.stack:
                self.stack.pop()          # statement boundary
            return
        if name == "COPY":
            dest = self.stack.pop() if self.stack else None
            src = self.stack[-1] if self.stack else Atom("raw", "<?>")
            if dest is not None:
                value = self._deref(src)
                if dest.offset is not None:
                    self._bind(dest.offset, value)
                else:
                    self._stmt(f"{dest.text} = {value.text};")
                if self.stack:
                    self.stack[-1] = dest
            return
        if name == "GETREF":
            # VAR already represents the frame-slot address in our model.
            # GETREF turns an encoded slot index into that address, whereas
            # GETOBJ/GETOBJREF read the object pointer held in the slot.
            return
        if name in ("GETOBJ", "GETOBJREF"):
            self._getobj(ins)
            return
        if name == "LOADOBJ":
            off = _s16(ins.w_arg)
            self.obj_reg = self._slot_atom(off)
            self.consumed_temps.add(off)
            if not self.is_named(off):
                self.consumed_temps.discard(off)
                self.temps[off] = Atom("null", "null", 2)
            return
        if name == "STOREOBJ":
            src = self.obj_reg or (self.value_reg
                                   if not self.value_reg.is_ptr else None)
            self._bind(_s16(ins.w_arg), src or Atom("raw", "<?objreg>"))
            self.obj_reg = None
            self.value_reg = Atom("raw", "<?reg>")
            self.pending_value_call = None
            # STOREOBJ consumes the object register, not the evaluation
            # stack. Outer call arguments may remain below this result.
            return

        # ---- calls / allocation / cleanup --------------------------------
        if name in ("CALL", "CALLSYS", "CALLBND", "CALLINTF", "Thiscall1"):
            self._call(ins)
            return
        if name == "CallPtr":
            self._call_ptr(ins)
            return
        if name == "ALLOC":
            self._alloc(ins)
            return
        if name == "FREE":
            off = _s16(ins.w_arg)
            value = self.temps.pop(off, None)
            if value is not None and value.kind == "call" and off not in self.consumed_temps:
                self._stmt(f"{value.text};")
            self.consumed_temps.discard(off)
            # FREE also zeroes the frame slot. The compiler uses this to pass
            # null handles even when no ClrVPtr instruction is present.
            if not self.is_named(off):
                self.consumed_temps.discard(off)
                self.temps[off] = Atom("null", "null", 2)
            return                       # end of a temp lifetime: no source
        if name in ("RefCpyV", "REFCPY"):
            self._refcpy(ins)
            return
        if name == "Cast":
            # Cast's operand is the target handle type (`sword@`); the result
            # is always a handle, so write it as one.
            t = (ins.type_ref.format_name() + "@") if ins.type_ref else f"type#{ins.dw_arg}"
            src = self.stack.pop() if self.stack else Atom("raw", "<?>")
            self.value_reg = Atom("call", f"cast<{t}>({self._deref(src).text})")
            return
        if name == "TYPEID":
            t = ins.data_type.format() if ins.data_type else str(ins.dw_arg)
            self.stack.append(Atom("typeid", t, 1, data_type=ins.data_type))
            return
        if name == "FuncPtr":
            fr = ins.func_ref
            name = ((fr.namespace_ + "::" if fr.namespace_ else "") + fr.name) if fr else "<?fn>"
            self.stack.append(Atom("const", f"@{name}", 2))
            return
        if name == "RET":
            if self.returns_value:
                # **Only the branch that actually returns the value register
                # may discard the pending call**, because only there is the
                # call already written -- inside the `return`. Discarding it
                # unconditionally loses a *different*, unrelated call that
                # merely happened to be the last one to touch that register:
                # `character::find_target` ends
                # `CALLINTF set_target_x ; LOADOBJ 8 ; RET`, returns the
                # OBJECT register, and lost the setter entirely, leaving the
                # arm it sat in empty. Same shape in `create_character`,
                # which ends `CALL create_person ; LOADOBJ 1 ; RET`.
                returned_the_register = False
                if _needs_out_ref(self.fn.return_type):
                    if self.return_slot in self.temps:
                        self._stmt(f"return {self.temps[self.return_slot].text};")
                elif self.fn.return_type.obj_type is not None and self.obj_reg is not None:
                    self._stmt(f"return {self.obj_reg.text};")
                elif self.value_reg.kind != "raw" and not self.value_reg.is_ptr:
                    value = self._normalize_arg(self.value_reg, self.fn.return_type)
                    self._stmt(f"return {value.text};")
                    returned_the_register = True
                elif 0 in self.temps:
                    # value was copy-constructed into the hidden return slot
                    self._stmt(f"return {self.temps[0].text};")
                if returned_the_register:
                    self.pending_value_call = None
                else:
                    self._flush_pending_call()
            else:
                self._flush_pending_call()
            self.stack.clear()
            return

        self._stmt(f"// {name} (unhandled)")

    # -- helpers ------------------------------------------------------------

    def _compared(self, off: int) -> Atom:
        """A slot's value as read by a comparison -- which USES it.

        A call result held in a temp and then compared is consumed by the
        condition. Unmarked, the FREE that ends the temp's life emitted the call
        again as a statement, so `if (get_sound_default_pack() is null)` came
        out preceded by a second, standalone `get_sound_default_pack();`.
        """
        if off in self.temps:
            self.consumed_temps.add(off)
        return self._slot_atom(off)

    def _slot_atom(self, off: int) -> Atom:
        """Value of a frame slot: temp alias if bound, else the variable.

        A value *pushed from a slot* reads through here, and this used to fold
        unconditionally -- promoting these to variables once cost 400
        diagnostics against 93, from declarations landing in the wrong scope.
        The duplication it would have caught was measured instead and left.

        It is not only duplication. `dynamic_menu::add_item_extended` keeps
        `item_list.length()` in a local **before** resizing, and folding that
        call into its four later reads re-evaluates it *after* the resize:

            int new_index = item_list.length();      // the source
            item_list.resize(new_index + 1);
            item_list[new_index].option = filename;

            item_list.resize(item_list.length() + 1);          // folded
            item_list[item_list.length()].option = arg0;       // out of bounds

        That compiles, and Crazy Party's recovered menu dies on the first item
        with `A runtime error occurred.` -- so this is a wrong *program*, not
        only a duplicated call.

        **Routing every non-repeatable read through `_read_temp` was tried and
        is wrong**, and the number that says so is not the diagnostic count:
        Super Egg Hunt went from **0 residual gotos to 182**, and from 0
        compiler errors to 187, while still verifying its split. `_read_temp`
        promotes the slot to a variable, and a loop condition the structurer
        could read as an expression becomes a statement before a jump, so the
        loop stops being a loop. The fold is load-bearing for structuring.

        `_stale_fold` is the distinction those two cases turn on, and it is
        the one the bug is actually about: whether anything has *run* between
        the value being computed and this read.
        """
        if off in self.temps:
            if self._stale_fold(off):
                return self._promote_temp(off)
            bound = self.temp_bound.get(off)
            if bound is not None and not _is_repeatable(self.temps[off]):
                # Counted, not acted on: a call folded into two reads runs
                # twice, and the only place to fix that is before the first
                # read. `_body` re-simulates with these marked.
                #
                # **Only a fold with a statement between it and the bind**,
                # and that is what lets the threshold be two. Several folds
                # inside ONE expression are the case the fold exists for --
                # a loop condition the structurer can read as an expression
                # -- and promoting those is what took Super Egg Hunt from 0
                # residual gotos to 182. Once a statement has run there is no
                # expression left to preserve and the duplication is the
                # whole of what is there.
                #
                # Paladin's `add_event` is the shape this was blind to. The
                # value is a BARE call, so there is no receiver for
                # `_stale_fold` to be invalidated through, and the source
                # kept it in a local precisely because the statement in
                # between makes it unaskable twice:
                #
                #     int gslot = get_global_slot(old);
                #     global_interacts.remove_at(gslot);
                #     slot = arg0.add_event(..., gslot);
                #
                # Folded into both reads, the second `get_global_slot(old)`
                # searched a list the line above had just removed `old` from
                # and returned -1, so the replacement event was given the
                # wrong global slot.
                key = (off, bound[0])
                self.fold_reads[key] = self.fold_reads.get(key, 0) + 1
            self.consumed_temps.add(off)
            return self.temps[off]
        return self.var_atom(off)

    def _stale_fold(self, off: int) -> bool:
        """Would folding this temp here re-evaluate it after something ran?

        A fold writes the temp's expression at the read instead of where the
        value was computed, so it is faithful only while those are the same
        moment. They stop being the same moment as soon as a statement is
        emitted in between -- and a value built out of a call can be a
        different value by then, which is how `item_list.length()` came to be
        read after the `resize` that changed it.

        A repeatable value -- a constant, a plain variable, `this` -- is the
        same at both moments by definition, so it still folds.

        "Something ran" is still too broad, and the measurement says so:
        taking it literally cost Super Egg Hunt 46 residual gotos against 0,
        because a value computed before a loop body and read at the latch had
        statements in between and had not changed. So what is required is that
        something ran **that touched what this value reads** -- an intervening
        statement naming the call's own receiver. `item_list.length()` is
        invalidated by `item_list.resize(...)` and by nothing else in that
        function, which is exactly the dependency the source expressed by
        keeping the result in a local.
        """
        value = self.temps[off]
        if off <= 0:
            return False
        bound = self.temp_bound.get(off)
        if bound is None:
            return False
        if (off, bound[0]) in self.duplicate_binds:
            # A previous pass folded this exact value into more than one read.
            # It is a call, so each fold *runs* it again: Paladin's `file_menu`
            # came out running its menu four times --
            # `if (menu.run_extended(...) == -1)`, then twice more in the next
            # condition, then once in the return -- where the source ran it
            # once and kept the result. The menu reappeared after every
            # selection, which is what that looks like from the inside.
            return True
        declarable = (value.data_type or self.var_types.get(off)) is not None
        # **Only a REPEATABLE value**, which is a constant, a plain variable,
        # `this` or a bare property read. Promoting a *computed* value the
        # same way is a different question (duplication, not a dead branch)
        # and far too broad: on Paladin it emitted a hold for binds the source
        # never held at all, `__nvgt_hold_7_116 = __nvgt_out_7_215;` among
        # them, and took 0 compiler errors to 16.
        #
        # This said "only a constant" until a parameter copy proved the line
        # was in the wrong place. `dynamic_menu::run_extended` opens with
        # `bool initial = auto_speak_first;` and clears it at five sites once
        # the first item has been announced. A parameter is repeatable, so the
        # fold took it before this test could run, every read became `arg3`
        # -- which never changes -- and all five `initial = false;` stores
        # went with it. The block then re-armed `speak_item` on every
        # iteration: arrow to an item, stop, and the menu says its name again
        # and again, forever. It is the same defect as `|| true` and
        # `if (false)`, and what decides it is whether the slot is written
        # again on another path, not what kind of value it happened to start
        # with.
        if declarable and self._conditionally_bound(bound[0], off):
            # Computed on one path and read past the join: the read is
            # reachable without that path, so folding is wrong whatever the
            # value is -- a constant most of all. This is how
            # `dynamic_menu::run_extended` came out with
            # `if (key_pressed(KEY_UP) || key_pressed(KEY_I) || true)`: the
            # joystick term is a slot set to false inside a branch, folded
            # into a read after it. The menu's arrow keys did nothing,
            # because that arm is always taken.
            return True
        if _is_repeatable(value):
            # **...but a plain VARIABLE is only repeatable while it still
            # holds the same value.** `_is_repeatable` says a variable can be
            # written at several reads because reading it again costs nothing
            # and yields the same thing -- which stops being true the moment
            # something assigns it in between.
            #
            # Paladin's `get_percent` is the whole bug in six instructions:
            #
            #     SetV8 v4, 0.0        local_4 = 0.0
            #     v2 = v4 ; v2 = arg1 ; DIVd v4, v2
            #                          local_4 = arg1 / arg0
            #     v2 = v4              <- the temp captures the RATIO
            #     SetV8 v4, 100.0      local_4 = 100.0
            #     MULd  v4, v2         100.0 * <the ratio>
            #
            # The temp holds the plain variable `local_4`, so the fold was
            # taken and the read wrote `local_4` -- by which time it was
            # 100.0. The recovered function computed `100.0 * 100.0`, and
            # pressing G in a battle to hear the enemy's health said
            # **10000 percent**. Every percentage in the game was that.
            # **...and an expression BUILT OUT OF a variable is no more
            # repeatable than that variable is.** This asked whether the
            # whole value *was* one variable, which a property read through
            # it is not: `arg0.interacts[local_2].mode` is kind `prop` with
            # no call in its text, so it satisfies both halves of
            # `_is_repeatable` while depending on a slot that gets
            # reassigned.
            #
            # Paladin's `add_event` is the whole bug in five lines. Replacing
            # an event has to keep the old interact's mode *before* removing
            # it, because afterwards there is nothing left to read it from:
            #
            #     int mode = arg0.interacts[slot].mode;   // slot 12
            #     arg0.interacts.remove_at(slot);
            #     slot = arg0.add_event(..., gslot);      // slot 2 rewritten
            #     global_interacts[slot].set_mode(mode);
            #
            # Folded, that last line read `arg0.interacts[local_2].mode` with
            # `local_2` now holding the *new* event's index and the element
            # it named already removed. Loading a save runs `init_events`,
            # so every save that had ever replaced an event died there.
            slot_of = {n: s for s, n in self.var_names.items()}
            if value.kind == "var":
                names = {value.text.lstrip("@")}
            else:
                names = set(_IDENT.findall(_mask_strings(value.text)))
            if any(any(bound[0] < write <= self._pos()
                       for write in self.slot_writes.get(slot_of[name], ()))
                   for name in names if name in slot_of):
                return True
            return False
        if bound[1] == self.stmt_count:
            return False            # nothing has run since: the same moment
        receivers = [m.group(1) for m in _CALL_RECEIVER.finditer(value.text)]
        if not receivers:
            # No receiver to be invalidated through. A bare call's result can
            # still go stale through engine state -- `reserve_slot()` hands
            # out a different slot each time -- but that is the duplication
            # case, measured by `bgt libcheck` and not guessed at here.
            return False
        if not any(_mutates(text, receiver)
                   for text in self.stmt_texts[bound[1]:]
                   for receiver in receivers):
            return False
        return declarable

    def _diamond_bind(self, bind_pos: int, off: int, now: int) -> bool:
        """Is the value at `bind_pos` one arm of an if/else over slot `off`?

        Both arms assign, so the read after the join has two possible
        sources and neither may be folded into it. The arm that comes second
        in the bytecode is the one a linear walk keeps, which is why
        Paladin's `create_room` rendered `add_clock(26, 6, -2, -2)` -- the
        else arm's coordinates -- with both arms of the `if` left empty.

        **A short-circuit merge slot is never one of these**, however much
        it looks like one: `(a && b)` is two assignments to one slot on
        mutually exclusive paths and a read after the join, which is the
        diamond shape exactly. Promoting it makes each operand's
        computation an unconditional statement, so every term is overwritten
        before the `if` reads it -- `(local_13.x < 4) && (local_13.y >= 6)`
        came out as `(local_6 < 4) && (local_6 != 0)`, reading one slot
        twice. That is the `use_screen_reader` defect this file already
        records, reached from a new direction.
        """
        if off in self.short_circuit_slots:
            return False
        for jump, join in self.jmp_spans:
            if not (bind_pos < join <= now):
                continue
            index = self.pos_of.get(jump)
            if index is None or index + 1 >= len(self.instrs):
                continue
            arm = self.instrs[index + 1].pos          # start of the second arm
            if not (arm <= bind_pos):
                continue
            # Some conditional jump has to enter that second arm, and the
            # first arm -- between it and the `JMP` -- has to write this slot.
            for branch, target in self.cond_spans:
                if target != arm or branch >= jump:
                    continue
                if any(branch < write < jump
                       for write in self.slot_writes.get(off, ())):
                    return True
        return False

    def _conditionally_bound(self, bind_pos: int, off: int | None = None) -> bool:
        """Was a value computed at `bind_pos` computed on only one path,
        relative to where the simulation is reading it now?

        The simulation walks the bytecode linearly, so a store inside a branch
        and a read after the join look like one straight line. They are not:
        if a forward conditional jump starts before the store and lands after
        it but at or before this read, then the store is skipped on the other
        path while the read happens either way.
        """
        now = self._pos()
        if any(branch < bind_pos < join <= now
               for branch, join in self.cond_spans):
            return True
        # **A diamond assigns the same slot on both arms**, and the arm that
        # comes second in the bytecode is skipped by the first arm's
        # *unconditional* jump, not by the conditional one -- which lands at
        # the first store rather than after it. So to a linear walk
        #
        #     if (c) { x = 0; } else { x = 26; } f(x);
        #
        # is just two assignments and a read, and the read folds whichever
        # came last. Paladin's `create_room` emitted both arms empty and
        # `add_clock(26, 6, -2, -2)` -- the else arm's coordinates -- so
        # every layout_2 cabin put its clock where the other layout's goes,
        # and `create_hallways` lost a pair of door coordinates the same way.
        #
        # What distinguishes it from an ordinary jump over an assignment is
        # the *earlier write to the same slot*: the value this read wants
        # exists on one path and that other write supplies the other, so
        # neither may be folded.
        # The shape has to be matched structurally, not approximated. "Some
        # earlier write to this slot, plus some forward `JMP` that skips the
        # bind" is true inside any loop that contains a `break`, and that
        # looseness cost 8 of BGT's 149 library functions their exact call
        # sequence. What a diamond really looks like is
        #
        #     JNZ -> else ; <then: writes off> ; JMP -> join
        #     else: <... bind_pos ...> ; join: <the read>
        #
        # so the conditional jump must target the instruction *immediately
        # after* that `JMP`, and the then-arm between them must write this
        # very slot.
        if off is not None and self._diamond_bind(bind_pos, off, now):
            return True
        # ...or computed before a loop and read inside it. The read runs once
        # per iteration while the computation ran once, so any assignment the
        # body makes to that slot is what the next iteration sees.
        # `dynamic_menu`'s `bool speak_item = false;` sits before the loop and
        # is set true by every arrow branch inside it; folded, the loop read
        # `if (false)` and the menu never spoke an item. Arrowing moved the
        # position silently, which is indistinguishable from arrowing being
        # broken -- and these are audio games, so it is worse than that.
        return any(bind_pos < head <= now <= back
                   for head, back in self.back_edges)

    def _promote_temp(self, off: int) -> Atom:
        """Hold this value in a local of its own, declared where it was computed.

        **The slot gets one name, not a name per promotion.** A fresh local per
        promotion was tried and is wrong in the opposite direction: a slot
        carrying one source variable then gets two names, and its writes and
        reads come apart. `dynamic_menu`'s joystick edge flag split into
        `__nvgt_hold_20_403 = 0` with the UP arm reading it and the UP arm
        *writing* `__nvgt_hold_20_1152 = 1`, which only the DOWN arm read -- so
        pressing up disarmed down. One slot, one name.

        What keeps that safe is `_stale_fold` promoting **only a constant**: a
        slot carrying several unrelated values in turn, like Paladin's
        `gift::get_gift` slot 7 holding both operands of a short-circuit, is
        never promoted at all and goes on folding each value into its one read.

        The assignment cannot be emitted here -- here is the read, and the
        value has to be computed where the bytecode computed it. It does not
        have to be: events are sorted by bytecode position at the end of the
        simulation rather than kept in append order, so an event carrying the
        bind position lands exactly where that store was.
        """
        value = self.temps[off]
        pos, _ = self.temp_bound[off]
        name = self.var_names.setdefault(off, f"local_{off}")
        # **The slot's own type wins; the value's is only the fallback.**
        # Overriding with the value's type was tried and is badly wrong: a
        # scratch slot that carries a bool here and an int there then gets
        # declared `bool`, and every numeric use of it becomes an error.
        # Paladin went from compiling cleanly to **377 errors** that way, all
        # of them `Can't implicitly convert from 'int' to 'bool'` on slots the
        # source uses as both.
        self.var_types.setdefault(off, value.data_type)
        known = self.var_types.get(off)
        if (known is not None and known.obj_type is None
                and known.token_type in NUMERIC_TOKENS
                and value.data_type is not None
                and value.data_type.obj_type is None
                and value.data_type.token_type == 67):
            # A bool value promoted into a numerically-typed slot is the mixed
            # bool/int slot this file already models: the slot keeps the
            # numeric type, the store writes 1/0, and reads convert back with
            # `!= 0`. Without the mark the store compiled and the *conditions*
            # did not -- `if (!local_3)`, `local_3 || ...`.
            self.mixed_boolean_slots.add(off)
        # Hoisted: the store may be inside a branch or a loop while a later
        # read is not, and a declaration inside that block is out of scope.
        self.forced_slots.add(off)
        self.stmt_count += 1
        self.stmt_texts.append("")
        self.events.append(Event("stmt", pos, ("", f"{name} = {value.text};")))
        replacement = Atom("var", name, 1, data_type=known)
        self.temps[off] = replacement
        self.temp_bound[off] = (pos, self.stmt_count)
        self.consumed_temps.add(off)
        return replacement

    def _is_unwritten(self, atom: Atom) -> bool:
        """Whether this argument is a slot the program never wrote.

        BGT exposes its variadic-looking APIs as long signatures of `?&in`
        parameters that all default to null -- `nwengine.call(signature,
        ?&in = null, ...)` -- and the compiler materialises a slot per
        default it fills in. The source passed nothing there and the slot
        holds nothing, so reading it emits a name with no declaration: 1,825
        of SBYW's errors, from one API.
        """
        name = atom.text.lstrip("@")
        off = next((o for o, n in self.var_names.items() if n == name), None)
        return (off is not None and off > 0 and off not in self.declared
                and off not in self.temps and off not in self.parameter_slots)

    def _read_temp(self, off: int) -> Atom:
        """Read a temporary, and make it a variable if that is what it is.

        A slot whose value is read twice is a variable, not a temporary.
        Folding an expression into every read writes -- and runs -- it once
        per read: `sound_pool::play_extended_1d` called `reserve_slot()`
        forty-five times where the source called it once and kept the result,
        and a stripped build with no declaration for the slot turned one
        `enemies_in_range()` call into fourteen, in a 21,000-character
        expression.

        Twice means the SAME value twice: a slot written again between the
        reads is an ordinary reused temporary, and folding each value into its
        one read is both correct and what lets the structurer still see a loop
        condition as an expression rather than a statement before the jump.

        Only where the slot can be *declared*: a name with no type is emitted
        as a bare assignment and the compiler never sees a declaration for it.
        An expression written twice is wrong, but a variable that does not
        exist does not compile at all, so the type decides. Both read paths --
        a value pushed from a slot, and an address dereferenced -- come
        through here, because either one can be the second read.
        """
        value = self.temps[off]
        known = self.var_types.get(off) or value.data_type
        if known is not None and known.obj_type is not None                 and known.obj_type.name.startswith("$"):
            # An engine-internal type (`$list`, the initialiser-list buffer)
            # has no name source can write, so a slot cannot be declared with
            # it: `$list local_6;` is "Expected expression value".
            known = None
        if (off > 0 and off in self.consumed_temps
                and known is not None and not _is_repeatable(value)):
            self.var_names.setdefault(off, f"local_{off}")
            self.var_types.setdefault(off, known)
            # Its declaration has to be hoisted: the first write may be inside
            # a branch while a later read is not, and a declaration inside the
            # branch is out of scope there.
            self.forced_slots.add(off)
        self.consumed_temps.add(off)
        return value

    def _stored_constant_types(self) -> dict:
        """A constant that is only ever stored, typed by where it is stored.

        `self.var_types` types a slot from the opcodes that *compute* with it,
        which says nothing about a value that is written straight out:

            SetV4 v2, 0x3FC00000           the bits of 1.5f -- width only
            PshGPtr pool ; ADDSi pan_step ; PopRPtr
            WRTV4 v2

        No float opcode touches slot 2, and in Psycho Strike's `main` that
        slot is a bool elsewhere, so `pool.pan_step = 1.5` came out as
        `pool.pan_step = true` -- which the compiler rejects on a `float`, and
        which was the only error in that title that was not its missing
        plugin.

        The destination's *declared* type settles it, and typing the constant
        rather than the slot is what keeps this cheap: declaring the slot
        would make it a variable, and a slot that is a variable is no longer
        folded into its use. Tried that way, `sound_pool::reset` went from
        nine lines identical to BGT's own source to thirty-six lines of slot
        traffic.

        Returns {instruction index: DataType}. A reader that is anything but
        that one write leaves the constant alone, because this answers one
        question and guessing the rest is how a plausible wrong type gets in.
        """
        widths = {"WRTV4": 81, "WRTV8": 94}            # float, double
        loads = ("ADDSi", "LoadThisR", "LoadRObjR", "LoadVObjR")
        typed = {}
        for index, ins in enumerate(self.instrs):
            if ins.name not in ("SetV4", "SetV8"):
                continue
            off = _s16(ins.w_arg)
            known = self.var_types.get(off)
            if known is not None and (known.obj_type is not None
                                      or known.token_type in (81, 94)):
                continue                               # already float enough
            destination = None
            for j in range(index + 1, min(index + 9, len(self.instrs))):
                nxt = self.instrs[j]
                if widths.get(nxt.name) == widths.get(ins.name.replace("SetV", "WRTV"))                         and _s16(nxt.w_arg) == off:
                    for back in range(j - 1, index, -1):
                        previous = self.instrs[back]
                        if previous.name in loads:
                            destination = self.property_types.get(previous.prop_name)
                            break
                        if previous.name in ("LDG", "LdGRdR4"):
                            destination = self.global_types.get(previous.global_name)
                            break
                    break
                # Anything else that could read the slot, or could have
                # replaced the address, ends the search.
                if (nxt.name.startswith(("J", "CALL", "SUSPEND"))
                        or _s16(nxt.w_arg) == off or _s16(nxt.w_arg2) == off):
                    break
            if destination is None or destination.obj_type is not None:
                continue
            want = widths[ins.name.replace("SetV", "WRTV")]
            if destination.token_type == want:
                typed[index] = destination
            elif (known is not None and known.obj_type is None
                  and known.token_type == 67            # the slot reads as bool
                  and destination.token_type != 67):    # the member is not
                # **A bool slot destroys an integer constant, not just a
                # float one.** This rule was written for `pool.pan_step =
                # 1.5` and so only accepted a float or double destination,
                # which left the far worse case alone: `_typed_constant`
                # renders any non-zero constant in a bool slot as `true`, and
                # `true` assigned to an `int` member is **1**.
                #
                # Paladin's `drunken_bert` introduces Gabriel with
                #
                #     SetV4 v1, 20 ; LoadRObjR v7 ; WRTV4 v1
                #     SetV4 v2, 12 ; LoadRObjR v7 ; WRTV4 v2
                #     SetV4 v2, 80 ; LoadRObjR v7 ; WRTV4 v2
                #
                # over two slots the compiler reuses, both of which
                # `slot_types` has no typed opcode for and which therefore
                # read as bool. All seven stats came out as `1`:
                # `strength = 1`, `av_damage = 1`, **`max_health = 1`**. The
                # recovered game reached its tutorial battle, dealt one
                # damage and died to one hit, and every number in it was
                # wrong the same way. It compiles, it runs, and it is
                # unplayable.
                typed[index] = destination
        return typed

    def _typed_constant(self, value: int, dt: DataType | None,
                        wide: bool = False) -> Atom:
        bits = value & (0xFFFFFFFFFFFFFFFF if wide else 0xFFFFFFFF)
        if dt is not None:
            typename = dt.format().replace("const ", "").replace("&", "")
            if typename == "bool":
                return Atom("const", "true" if value else "false")
            if typename == "float":
                value = struct.unpack("<f", struct.pack("<I", value & 0xFFFFFFFF))[0]
                return Atom("const", repr(value), constant_bits=bits)
            if typename == "double":
                # The stream reader already decoded the integer bit pattern.
                value = struct.unpack("<d", struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))[0]
                return Atom("const", repr(value), 2, constant_bits=bits)
            if typename == "int64":
                value = _s64(value & 0xFFFFFFFFFFFFFFFF)
            elif typename == "uint64":
                value &= 0xFFFFFFFFFFFFFFFF
            elif typename in ("int", "int8", "int16", "uint", "uint8", "uint16"):
                width = {"int": 32, "uint": 32, "int8": 8, "uint8": 8, "int16": 16, "uint16": 16}[typename]
                value &= (1 << width) - 1
                if typename.startswith("int") and value & (1 << (width - 1)):
                    value -= 1 << width
            if dt.obj_type is not None and dt.obj_type.kind == "enum":
                for name, enum_value in dt.obj_type.enum_values:
                    if enum_value == value:
                        return Atom("const", name)
            # An integer constant meeting a by-value object type can only be an
            # enum -- a real object would have been constructed first. Engine
            # enums (`spec::path_style`, `sound`'s positioning mode) have no
            # values in the module to name, and a bare `3` does not convert
            # implicitly: "No matching signatures to 'path::to_string(const
            # int)'". `Enum(3)` is AngelScript's explicit conversion, checked
            # against the installed compiler.
            if (dt.obj_type is not None and not dt.is_object_handle
                    and dt.obj_type.kind in ("enum", "app")):
                return Atom("const", f"{dt.obj_type.format_name()}({value})",
                            constant_bits=bits)
        return Atom("const", str(value), 2 if wide else 1, constant_bits=bits)

    def _normalize_arg(self, atom: Atom, dt: DataType) -> Atom:
        source = atom.data_type
        if (dt.is_object_handle and source and source.obj_type
                and any(source.obj_type is cls for cls in self.m.classes) and not source.is_object_handle
                and not atom.text.startswith("@")):
            return Atom(atom.kind, "@" + atom.text, data_type=dt)
        # Each arm of a ternary takes the target type: bool, or an enum whose
        # constants have names -- `right ? HANDEDNESS_RIGHT : ..._LEFT` is two
        # ints in bytecode, and ints do not convert to the enum.
        enum_target = (dt.obj_type is not None and not dt.is_object_handle
                       and dt.obj_type.kind in ("enum", "app"))
        if (dt.token_type == 67 or enum_target) and atom.ternary:
            condition, yes, no = atom.ternary
            yes = self._normalize_arg(yes, dt)
            no = self._normalize_arg(no, dt)
            return Atom("call", f"({condition} ? {yes.text} : {no.text})", data_type=dt)
        if dt.token_type == 67 and source and source.obj_type is None and source.token_type in (70, 77, 81, 94):
            return Atom("call", f"({atom.text} != 0)", data_type=dt)
        # ...and the other way. A stripped build records no type for a scalar
        # slot, and one slot serves several source locals: `clear_pathway`
        # uses slot 1 as an int and as a bool. Convert explicitly at the use
        # rather than mistyping the declaration -- the value is the same one
        # the compiler would have converted implicitly if it allowed it.
        if (dt.token_type in NUMERIC_TOKENS and atom.kind != "const"
                and source is not None and source.obj_type is None
                and source.token_type == 67):
            # ...unless the atom is a bare slot name that is *declared*
            # numeric. Then the bool on the atom is stale -- it came from the
            # value the slot was last given, not from the slot -- and wrapping
            # gives `local_24 = (local_3 ? 1 : 0);` with `int local_3`, which
            # is "Expression must be of boolean type". The declaration is the
            # better witness about a name than an atom that outlived its
            # value.
            if not self._declared_numeric(atom.text):
                return Atom("call", f"({atom.text} ? 1 : 0)", data_type=dt)
            return Atom(atom.kind, atom.text, atom.stack_size, data_type=dt)
        if atom.kind != "const":
            return atom
        if atom.constant_bits is not None:
            return self._typed_constant(atom.constant_bits, dt, _type_stack_size(dt) == 2)
        if atom.text in ("true", "false") and dt.token_type in NUMERIC_TOKENS:
            # A one-byte constant reads as a bool, and an integer destination
            # will not take one: writing an int8 property gave `x = true;`,
            # "Can't implicitly convert from 'bool' to 'int&'".
            return Atom("const", "1" if atom.text == "true" else "0", data_type=dt)
        try:
            value = int(atom.text)
        except ValueError:
            return atom
        return self._typed_constant(value, dt, _type_stack_size(dt) == 2)

    def _flush_pending_call(self) -> None:
        if self.pending_value_call:
            self.events.append(Event("stmt", self.pending_value_call_pos,
                                     ("", f"{self.pending_value_call};")))
            self.pending_value_call = None

    def _is_void_return_target(self, target: int) -> bool:
        return not self.returns_value and self._is_return_target(target)

    def _is_return_target(self, target: int) -> bool:
        if target not in self.pos_of:
            return False
        tail = self.instrs[self.pos_of[target]:]
        return any(i.name == "RET" for i in tail) and all(
            i.name in ("FREE", "RET", "SUSPEND", "ClrVPtr") for i in tail)

    def _binop_vars(self, d: int, s1: int, op: str, s2: int | None = None,
                    imm: int | None = None, numeric_type: DataType | None = None) -> None:
        a = self._slot_atom(s1)
        b = Atom("const", str(imm)) if imm is not None else self._slot_atom(s2 or 0)
        if numeric_type:
            a = self._normalize_arg(a, numeric_type)
            b = self._normalize_arg(b, numeric_type)
        self._bind(d, Atom("call", f"({a.text} {op} {b.text})"))

    def _emit_global_write(self, g: str, a: Atom) -> None:
        a = self._deref(a)
        if g in self.global_types:
            a = self._normalize_arg(a, self.global_types[g])
        self._stmt(f"{g} = {a.text};")

    def _ptr_target_text(self) -> str:
        # value register holds a pointer (from LdGRdR4/LoadThisR etc.)
        if self.value_reg.kind == "prop" and self.value_reg.is_ptr:
            return self.value_reg.text
        if self.value_reg.is_ptr:
            return self.value_reg.text
        return "<?ptr>"

    def _getobj(self, ins: Instr) -> None:
        """Convert the argument at the serialized stack offset in place.

        SaveByteCode normalizes pointer footprints to one dword, including
        GETOBJ offsets (asCWriter::AdjustGetOffset), even on 64-bit engines.
        """
        want = ins.w_arg & 0xFFFF
        acc = 0
        for idx in range(len(self.stack) - 1, -1, -1):
            a = self.stack[idx]
            size = 1 if a.is_ptr or a.kind == "null" else a.dw_size
            if acc <= want < acc + size:
                # GETOBJREF passes a REFERENCE to the object a variable holds
                # -- how an `out` argument receives its target -- so the slot's
                # address is kept for the output-argument handling in _call.
                # Dereferencing it here turned `dictionary.get(key, tmp)` into
                # `d.get(key, array<string>())`: "Output argument expression
                # is not assignable". Arguments are dereferenced later anyway.
                if a.is_ptr and ins.name != "GETOBJREF":
                    self.stack[idx] = self._deref(a)
                return
            acc += size

    #: How far a borrowed handle's `FREE` may sit from its `RefCpyV`. The
    #: whole point is that the pair brackets *one* subexpression, so the
    #: window is small on purpose: `find_walls` frees three instructions
    #: later. Classifying the slot instead -- "any handle written inside a
    #: short-circuit arm" -- was tried and catches real variables, costing
    #: Paladin 477 lines and scrambling `load_event_flags`; see the
    #: measurements in CLAUDE.md.
    BORROW_WINDOW = 4

    def _borrowed_handle(self, off: int) -> bool:
        """Is this `RefCpyV` only keeping an object alive for one expression?

        Three things, all local to the instruction stream: the slot is
        released by `FREE` within a few instructions, nothing in between
        names the slot -- the following instruction reads the stack copy --
        and nothing in between is a jump, so the borrow cannot straddle a
        branch and reach a `FREE` that belongs to another path.
        """
        for ins in self.instrs[self.k + 1:self.k + 1 + self.BORROW_WINDOW]:
            if ins.name == "FREE" and _s16(ins.w_arg) == off:
                return True
            if ins.name in JUMP_OPS or ins.name in ("JMP", "RET"):
                return False
            if _s16(getattr(ins, "w_arg", 0)) == off and ins.name != "RefCpyV":
                return False
        return False

    def _refcpy(self, ins: Instr) -> None:
        if ins.name == "RefCpyV":
            # RefCpyV == PSF dest + REFCPY: source address stays on the
            # stack (the following ALLOC consumes it); peek, don't pop.
            src = self.stack[-1] if self.stack else Atom("raw", "<?>")
            off = _s16(ins.w_arg)
            if self._borrowed_handle(off):
                # **A handle borrowed for one expression is not a statement.**
                # The source stays on the stack, so the instruction that
                # follows reads *that* copy and never looks at the slot: the
                # slot exists only to keep the object alive across it, and
                # `FREE` releases it a few instructions later without
                # anything having read it.
                #
                # `find_walls` is what emitting it costs. Its loops are
                #
                #     while (true) { i += 1;
                #         if (arg2.length() <= i || arg2[i].length() <= j
                #             || arg2[i][j] == 0 || play_wall_tone(i, j)) ... }
                #
                # and the third operand borrows `arg2[i]` exactly this way.
                # `objVariableTypes` names every object slot, so the copy was
                # emitted as `@local_11 = arg2[int(local_10)];` -- and an
                # event sorts by its own bytecode position while the branch
                # sorts by the end of the chain, so it landed ahead of the
                # whole `if`. The index then ran before the bounds check
                # guarding it, and *entering* any map threw `Index out of
                # bounds`, because `find_walls` always scans out to a wall or
                # the edge. The westward and southward loops index `-1`
                # before testing `< 0`, so the edge is reached at once.
                self.consumed_temps.discard(off)
                self.temps[off] = self._deref(src)
                self.temp_bound[off] = (self._pos(), self.stmt_count)
                self.consumed_temps.add(off)
                return
            self._bind(off, self._deref(src))
        else:  # REFCPY
            dest = self.stack.pop() if self.stack else Atom("raw", "<?>")
            src = self.stack[-1] if self.stack else Atom("raw", "<?>")
            value = self._deref(src)
            if dest.kind == "list_elem":
                self.list_values.setdefault(dest.offset, {})[dest.list_index] = value
            elif dest.kind == "global":
                if dest.text in self.global_types:
                    value = self._normalize_arg(value, self.global_types[dest.text])
                prefix = "@" if self.global_types.get(dest.text) and self.global_types[dest.text].is_object_handle else ""
                self._stmt(f"{prefix}{dest.text} = {value.text};")
            elif dest.is_ptr and dest.offset is not None:
                self._emit_assign(dest.offset, value)
            elif dest.kind == "prop" and dest.data_type is not None                     and dest.data_type.is_object_handle:
                # `@h.item = b`: PshVPtr h / ADDSi item / REFCPY. The address
                # is a member, not a frame slot, and without this branch the
                # assignment vanished -- and the output still compiled.
                # Only for members DECLARED as handles: a by-value member of
                # a reference type (music.nvgt's `mixer music_mixer;`) is
                # also REFCPY'd, by the constructor's generated member
                # initialisation, which the source never wrote.
                self._stmt(f"@{dest.text} = {value.text};")
            elif dest.is_ptr and dest.kind == "call":
                # **`@party[i] = c`: the destination is the reference
                # `opIndex` returned**, not a frame slot or a member, so none
                # of the branches above claims it and the assignment was
                # dropped on the floor.
                #
                # `deserialize_all` loads a saved game with
                #
                #     party.resize(n);
                #     for (i = 0; i < n; i++) {
                #         character@ c = character();
                #         @party[i] = c;
                #         party[i].deserialize(d, "party_" + i);
                #     }
                #
                # and `resize` leaves null handles, so without the middle
                # line `party[i]` is null and `.deserialize` dereferences it:
                # **loading any save died with `Null pointer access`** in
                # `deserialize_all` -> `load` -> `handle_file_menu`.
                #
                # The bytecode is not ambiguous about the direction --
                # `VAR v23 ; PshV4 i ; PshGPtr party ; CALLSYS opIndex ;
                # PshRPtr ; REFCPY` leaves the element reference on top, and
                # `REFCPY` pops the destination first. Rendered without this
                # branch the statement vanished; an earlier revision of the
                # borrowed-handle rule emitted it *backwards*, as
                # `@local_23 = party[i];`, which compiles and silently keeps
                # the null.
                self._stmt(f"@{dest.text} = {value.text};")
            self.value_reg = value

    # -- calls ----------------------------------------------------------------

    def _call(self, ins: Instr) -> None:
        self._flush_pending_call()
        # Whatever the object register held belongs to code before this call.
        # A call returning an object replaces it; leaving the old value there
        # let a LOADOBJ from one branch reach the STOREOBJ after a call on the
        # other: settings::keys() returned the empty-list branch's temporary
        # from its `data_helper.list_keys()` branch too.
        self.obj_reg = None
        fr = ins.func_ref
        if fr is not None and fr.name in DELEGATE_FACTORIES:
            method = self.stack.pop() if self.stack else Atom("raw", "<?method>")
            owner = self._deref(self.stack.pop()) if self.stack else Atom("raw", "<?owner>")
            expression = f"{owner.text}.{method.text.lstrip('@')}"
            following = next((i for i in self.instrs[self.k + 1:] if i.name not in ("FREE", "SUSPEND")), None)
            dt = self.var_types.get(_s16(following.w_arg)) if following and following.name == "STOREOBJ" else None
            if dt and dt.obj_type:
                expression = f"{dt.obj_type.name}({expression})"
            else:
                # No `STOREOBJ` after it means the delegate is passed straight
                # as an argument, so there is no slot to take the funcdef from.
                # The bound method's own signature names it instead: the
                # compiler rejects the bare method ("Can't pass class method as
                # arg directly"), and Crazy Party passes `Jeu::att(int, bool)`
                # where the module declares exactly one matching funcdef,
                # `void CbFade(int, bool)`.
                bound = next((i.func_ref for i in reversed(self.instrs[:self.k])
                              if i.name == "FuncPtr" and i.func_ref is not None), None)
                funcdef = (self._funcdef_matching(bound)
                           or self._funcdef_from_consumer())
                if funcdef:
                    expression = f"{funcdef}({expression})"
            self.value_reg = Atom("call", expression)
            self.pending_value_call = None
            return
        sig = ins.func_name or f"fn#{ins.dw_arg}"
        nparams = len(fr.param_types) if fr else 0
        ret = fr.return_type if fr else None
        has_this = fr is not None and fr.object_type is not None
        has_out = ret is not None and _needs_out_ref(ret)

        # VM layout, top of stack first: [this] [out-ref] [param0] [param1]...
        # (params pushed in reverse, then out-ref, then this; verified against
        # as_callfunc.cpp: retPointer = *(void**)args right after skipping this)
        pop_this = self.stack.pop() if has_this and self.stack else None
        pop_out = self.stack.pop() if has_out and self.stack else None
        args = []
        out_locals = []
        handle_any_args = set()
        for index in range(nparams):
            arg = self.stack.pop() if self.stack else Atom("raw", "<?>")
            dt = fr.param_types[index]
            output_type = dt
            if dt.token_type == 60 and dt.is_reference:
                # ?& parameters occupy a pointer plus a hidden TYPEID.
                typeid = self.stack.pop() if self.stack else None
                if typeid is not None and typeid.kind == "typeid" and typeid.data_type:
                    output_type = typeid.data_type
                    # The hidden TYPEID says what the source passed. A handle
                    # type id means `@b` -- written as plain `b` the compiler
                    # passes the OBJECT instead, and `dictionary.set("k", b)`
                    # stores a copy where the original stored a reference.
                    if output_type.is_object_handle:
                        handle_any_args.add(index)
            direction = fr.in_out_flags[index] if index < len(fr.in_out_flags) else 0
            if direction & 2 and arg.is_ptr and arg.offset is not None and arg.offset > 0:
                off = arg.offset
                if not self.is_named(off):
                    value = self.temps.get(off)
                    local = f"__nvgt_out_{off}_{ins.pos}"
                    output_type = copy.copy(output_type)
                    output_type.is_reference = output_type.is_readonly = False
                    # A `?&out` receiving a REFERENCE type receives a handle:
                    # the source declares `ini_section@ tmp` and passes `@tmp`.
                    # Declared by value it needs a default constructor the
                    # type does not have ("No default constructor for object
                    # of type 'ini_section'") and would copy, not hand over.
                    as_handle = (dt.token_type == 60 and self._is_reference_type(output_type))
                    if as_handle:
                        output_type.is_object_handle = True
                    # Scratch slots are reused with different types later;
                    # give an output argument its own source-level lifetime.
                    # Emitted WITH its type on the event, so the hoisting pass
                    # can recognise a declaration and lift it out of whatever
                    # block the call was in: an output filled inside an `if`
                    # and read after it is "'__nvgt_out_17_502' is not
                    # declared" -- 1,868 of SBYW's errors came from that one
                    # shape.
                    if direction & 3 == 3 and value and value.kind != "raw":
                        value = self._normalize_arg(value, output_type)
                        self._append_stmt(output_type.format(),
                                          f"{local} = {value.text};")
                    else:
                        self._append_stmt(output_type.format(), f"{local};")
                    arg = Atom("var", ("@" if as_handle else "") + local,
                               data_type=output_type)
                    out_locals.append(local)
                    self.consumed_temps.discard(off)
                    self.temps[off] = Atom("var", local, data_type=output_type)
                else:
                    arg = self.var_atom(off)
            args.append(arg)
        # popping yields parameter order directly (verified CALL + CALLSYS)
        args = [self._deref(a) for a in args]
        if fr is not None:
            args = [self._normalize_arg(a, fr.param_types[i])
                    for i, a in enumerate(args)]
        args = [Atom(a.kind, "@" + a.text, a.dw_size, data_type=a.data_type)
                if i in handle_any_args and a.kind != "null"
                and not a.text.startswith("@") and a.text != "null" else a
                for i, a in enumerate(args)]
        # Release NVGT exposes several convenience APIs as long fixed-arity
        # signatures whose trailing parameters default to null.  The compiler
        # materializes bookkeeping slots for those defaults; source does not
        # need them and their values are intentionally uninitialized.
        if fr is not None and fr.default_args:
            while args and len(args) <= len(fr.default_args) \
                    and fr.default_args[len(args) - 1] == "null" \
                    and (args[-1].text.startswith("tmp")
                         or args[-1].text in ("<?>", "null")
                         or self._is_unwritten(args[-1])):
                args.pop()

        # call name without the return type (use the resolved function name)
        base = fr.name if fr is not None else sig.split("(", 1)[0]
        cls, meth = (base.split("::", 1) + [""])[:2] if "::" in base else ("", base)
        if (has_this and pop_this is not None and pop_this.offset is not None
                and pop_this.offset > 0 and not self.is_named(pop_this.offset)
                and pop_this.offset in self.temps and pop_this.offset in self.var_types
                and not self.var_types[pop_this.offset].is_object_handle
                and not fr.flags_byte & 1 and not meth.startswith("$")
                and meth not in ("opAssign",)):
            # A mutable object must keep its identity across later reads.
            # Repeating a folded factory expression would mutate a different
            # fresh object on every use (e.g. array().insertLast(...)).
            off = pop_this.offset
            value = self.temps.pop(off)
            self.var_names[off] = f"local_{off}"
            self._emit_assign(off, value)

        # A template factory stub creates an instance of the template it
        # returns: `GenerateTemplateFactoryStub` emits OBJTYPE + CALLSYS +
        # RET, so its one apparent argument is the hidden object type and not
        # anything source wrote. Say what it makes -- `weapon@[]()` -- rather
        # than naming the stub, which no source can call.
        if meth == "factstub" and ret is not None:
            typename = _constructor_type(ret)
            # Its *declared* arguments are real: the array template has a
            # factory taking a length, and `double[]@ factstub(uint)` is that
            # one. Dropping the length left two member arrays unsized in
            # Paladin's `input_recorder`, and its constructor then wrote past
            # the end of them -- which the engine reports as "Failed to
            # initialize global variable 'recorder'" and nothing else.
            # (A `factstub()` with no declared parameter is the plain
            # factory; the value pushed at such a call is the hidden object
            # type, and `args` is empty for it either way.)
            # ...but only the arguments that are *values*. The template also
            # has a list factory, whose parameter is the initialiser-list
            # buffer the compiler fills -- an engine-internal object with no
            # name source can write, and `array<string>(local_6)` is both an
            # undeclared name and the wrong type.
            # The two parameterised factories differ exactly here: the
            # length one takes `uint` by value (`double[]@ factstub(uint)`)
            # and the list one takes the buffer by reference
            # (`string[]@ factstub(int&in)`). Only a by-value primitive is
            # something source wrote.
            lengths = [a.text for index, a in enumerate(args)
                       if index < len(fr.param_types)
                       and fr.param_types[index].obj_type is None
                       and not fr.param_types[index].is_reference]
            inner = ", ".join(lengths)
            self.value_reg = Atom("call", f"{typename}({inner})", data_type=ret)
            self.pending_value_call = None
            if has_out and pop_out is not None and pop_out.is_ptr \
                    and pop_out.offset is not None:
                self._bind(pop_out.offset, self.value_reg)
            return

        # The older engine's string literals arrive as a call to the
        # registered string factory over the pair STR pushed. The literal is
        # the whole content of the call, and the factory returns
        # `const string&`, so nothing else rides on its frame. Collapsing the
        # call away entirely instead was tried in the lifter and reverted: it
        # desynchronises the literal from the PshRPtr that pushes the result.
        if meth == "_string_factory_" or meth.endswith("stringfactory"):
            literal = next((a.text for a in args
                            if a.kind == "const" and a.text.startswith('"')), None)
            self.value_reg = Atom("const", literal if literal is not None else '""',
                                  data_type=ret)
            self.pending_value_call = None
            return

        # constructors: $beh0(out) = copy-construct (this=dest, out=source),
        # $beh0() = default. The chained temp form leaves the initializer
        # address on the stack for the following ALLOC (dest pushed deepest).
        if meth in CTORS and (ret is None or ret.format() == "void"):
            dst = pop_this
            # Qualified: a registered type in a namespace is only reachable by
            # its full name -- `spec::path(temppath)` rendered as `path(...)`
            # is "No matching symbol 'path'".
            typename = fr.object_type.format_name() if fr and fr.object_type else "string"
            bare = fr.object_type.name if fr and fr.object_type else "string"
            copy_ctor = (len(args) == 1 and fr is not None and
                         fr.param_types[0].obj_type is not None and
                         fr.param_types[0].obj_type.name == bare)
            if dst is not None and dst.kind == "list_elem":
                value = args[0] if copy_ctor else Atom("call", f"{typename}({', '.join(a.text for a in args)})")
                self.list_values.setdefault(dst.offset, {})[dst.list_index] = value
                return
            if dst is not None and dst.is_ptr and dst.offset is not None:
                if not args:
                    if self.is_named(dst.offset):
                        self._emit_declare(dst.offset)   # `string s;`
                    else:
                        self.consumed_temps.discard(dst.offset)
                        self.temps[dst.offset] = Atom("const", '""') if typename == "string" else Atom("call", f"{typename}()")
                    return
                src = self._deref(args[0]) if copy_ctor else Atom(
                    "call", f"{typename}({', '.join(a.text for a in args)})")
                if self.is_named(dst.offset):
                    self._emit_assign(dst.offset, src)
                else:
                    self.consumed_temps.discard(dst.offset)
                    self.temps[dst.offset] = src
                return          # leftover stack slot (if any) feeds the ALLOC
            self.value_reg = Atom("call", args[0].text if args else '""')
            return
        if meth.startswith("$") and ret is not None and ret.format() != "void":
            # A factory return replaces the VM object register. An earlier
            # LOADOBJ on a returning branch must not win at the next STOREOBJ.
            self.obj_reg = None
            tname = ret.format().removeprefix("const ").rstrip("@&").strip()
            pair_lists = ("dictionary", "name_value_collection", "internet_message_header", "http_request", "http_response")
            if meth.startswith("$list") and ret.obj_type and ret.obj_type.name in ("array",) + pair_lists and args:
                off = next((o for o in self.list_values if self.name_of(o) == args[0].text), None)
                values = self.list_values.get(off, {})
                size = self.list_sizes.get(off, -1)
                dictionary = ret.obj_type.name in pair_lists
                if off is not None and len(values) == size * (2 if dictionary else 1):
                    local = f"__nvgt_list_{off}_{ins.pos}"
                    items = [self._normalize_arg(values[i], ret.template_subtypes[0]).text
                             if ret.obj_type.name == "array" and ret.template_subtypes else values[i].text
                             for i in sorted(values)]
                    if dictionary:
                        items = ["{" + items[i] + ", " + items[i + 1] + "}" for i in range(0, len(items), 2)]
                    expr = "{" + ", ".join(items) + "}"
                    self._stmt(f"{tname} {local} = {expr};")
                    self.value_reg = Atom("var", local, data_type=ret)
                    return
            calltxt = f"{tname}({', '.join(a.text for a in args)})"
            self.value_reg = Atom("call", calltxt)
            self.pending_value_call = calltxt
            self.pending_value_call_pos = self._pos()
            return
        if meth in DTORS or meth.startswith("$list") or meth.startswith("$dlgte"):
            # Destructing a value is not reading it. A temporary built by a
            # call and then thrown away is exactly the discarded-result case
            # -- `get_characters()` in `audio_form::create_window` -- and
            # popping the receiver has already marked the slot consumed, so
            # no later sweep can see it.
            if meth in DTORS and pop_this is not None:
                off = pop_this.offset
                if off is not None and not self.is_named(off):
                    held = self.temps.get(off)
                    if held is not None and held.kind == "call":
                        self._discarded_call(off)
            return

        # A base-class constructor called on `this` from a derived constructor
        # is `super(...)` in source. Rendered as a method call it read
        # `this.settings_helper(parent);`, which does not compile -- and the
        # compiler then also demands an explicit base constructor call.
        if (has_this and pop_this is not None and fr is not None
                and fr.object_type is not None and meth == fr.object_type.name
                and self._deref(pop_this).text == "this"
                and self._is_base_of_current(fr.object_type)):
            self._stmt(f"super({', '.join(a.text for a in args)});")
            return

        # operator methods on the object
        if has_this and pop_this is not None:
            obj = self._deref(pop_this)
            # `cast<T@>(value)` on a dictionaryValue (or any type with a
            # `?&out` opCast) compiles to `value.opCast(@tmp)`. Called by name
            # it does not resolve -- "No matching signatures to
            # 'dictionaryValue::opCast(stat@&) const'" -- so say what it is.
            if (meth == "opCast" and len(args) == 1 and args[0].text.startswith("@")
                    and args[0].data_type is not None):
                target = args[0].data_type.format().rstrip("@")
                self._stmt(f"{args[0].text} = cast<{target}@>({obj.text});")
                return
            result: Atom | None = None          # value produced, if any
            # Assignment operators return a reference to their receiver, and
            # code uses it: `var@ opAssign(const string&in v) { return val =
            # v; }` compiles to the call, then PshRPtr of its result. Leaving
            # the register empty rendered `return <?reg>;`.
            receiver = Atom("prop" if obj.kind == "prop" else "var", obj.text, 1,
                            is_ptr=True, offset=pop_this.offset if pop_this.is_ptr else None,
                            data_type=obj.data_type)
            if meth in ASSIGN_OPS and args:
                self._stmt(f"{obj.text} {ASSIGN_OPS[meth]} {args[0].text};")
                self.value_reg = receiver
                # A result returned BY VALUE goes through the hidden out slot
                # (`var::opAddAssign` returns a string). The value of `x += y`
                # is x's new value, so the slot holds x -- left unset, `return
                # var(val += value)` came out as `var(tmp1)`.
                if (has_out and pop_out is not None and pop_out.is_ptr
                        and pop_out.offset is not None):
                    # ...converted to what the operator returns: `var::
                    # opAddAssign` returns a string, and `var(val)` with val a
                    # var is ambiguous where `var(string(val))` is not.
                    rtype = ret.format().removeprefix("const ").rstrip("&") if ret else ""
                    same = obj.data_type is not None and \
                        obj.data_type.format().removeprefix("const ").rstrip("@&") == rtype
                    text = obj.text if same or not rtype else f"{rtype}({obj.text})"
                    self._bind(pop_out.offset, Atom("call", text, data_type=ret))
                return
            if meth == "opAssign" and args:
                if pop_this.kind == "list_elem":
                    self.list_values.setdefault(pop_this.offset, {})[pop_this.list_index] = args[0]
                elif pop_this.is_ptr and pop_this.offset is not None:
                    self._bind(pop_this.offset, args[0])
                else:
                    self._stmt(f"{obj.text} = {args[0].text};")
                self.value_reg = receiver
                return
            if meth == "opAdd" and len(args) == 1:
                result = Atom("call", f"({obj.text} + {args[0].text})")
            elif meth == "opAdd_r" and len(args) == 1:
                result = Atom("call", f"({args[0].text} + {obj.text})")
            elif meth == "opSub" and len(args) == 1:
                result = Atom("call", f"({obj.text} - {args[0].text})")
            elif meth in ("opIndex", "get_opIndex"):
                result = Atom("call",
                              f"{obj.text}[{', '.join(a.text for a in args)}]")
            elif meth == "opEquals" and len(args) == 1:
                result = Atom("call", f"({obj.text} == {args[0].text})")
            elif meth == "opCall":
                result = Atom("call",
                              f"{obj.text}({', '.join(a.text for a in args)})")
            elif meth == "opNeg":
                result = Atom("call", f"(-{obj.text})")
            elif meth == "opCom":
                result = Atom("call", f"(~{obj.text})")
            elif meth == "opNot":
                result = Atom("call", f"(!{obj.text})")
            elif meth == "opImplConv":
                result = obj
            elif meth == "opConv" and not args and ret is not None:
                # An explicit conversion. Called by name it is ambiguous when
                # the type converts to several things -- dictionaryValue has
                # one opConv per target, so `args["key"].opConv()` is
                # "Multiple matching signatures". The return type is the
                # conversion the source wrote: `int(args["key"])`.
                target = ret.format().removeprefix("const ").rstrip("&")
                result = Atom("call", f"{target}({obj.text})")
            elif meth == "opCmp" and len(args) == 1:
                self.cmp_pair = (obj, args[0])
                calltxt = f"{obj.text}.opCmp({args[0].text})"
                self.value_reg = Atom("call", calltxt)
                self.pending_value_call = calltxt
                self.pending_value_call_pos = self._pos()
                return
            if result is not None:
                if ret is not None:
                    result.is_ptr = ret.is_reference
                    result.data_type = ret
                # store into the hidden out-ref slot when the caller supplied one
                if has_out and pop_out is not None and pop_out.is_ptr \
                        and pop_out.offset is not None:
                    self._bind(pop_out.offset, result)
                else:
                    self.value_reg = result
                return
            # plain method call
            calltxt = f"{obj.text}.{meth}({', '.join(a.text for a in args)})"
            # From a const method, a non-const method is callable by its bare
            # name but not through `this.` (whose type is const there) --
            # touch.nvgt's `get_available() const` calls `is_available()`, and
            # the explicit form is "No matching signatures to
            # 'touch_gesture_manager::is_available() const'". Write it the way
            # the compiler accepted it.
            if (obj.text == "this" and self.fn.flags_byte & 1
                    and fr is not None and not fr.flags_byte & 1):
                calltxt = f"{meth}({', '.join(a.text for a in args)})"
            # The owner is `fr.object_type`, not the `cls` parsed out of the
            # name: a method's `Function.name` is the bare one (`reset`), so
            # `cls` is empty here and reading the base off it finds nothing.
            elif obj.text == "this" and self._calls_a_base_method(
                    fr.object_type.name if fr is not None
                    and fr.object_type is not None else cls, meth, ins.name):
                cls = (fr.object_type.name if fr is not None
                       and fr.object_type is not None else cls)
                # **A base class's method, through `this`, needs the base
                # named.** The call's operand resolved to a body owned by an
                # ancestor, and this class declares the name too -- so
                # `this.m()` would resolve to *this* class's override
                # instead, which for the same name is itself.
                #
                # Paladin's `person : interact` opens its override with
                # `interact::reset();`, which came out as `this.reset();`.
                # That is unbounded recursion: starting a new game died with
                # `Stack overflow` after 10,000 frames of `person::reset`,
                # from `create_room_passengers` building the first passenger.
                # It compiles, and nothing short of running it can see it.
                # `base::method()` was put to BGT before being emitted.
                calltxt = f"{cls}::{meth}({', '.join(a.text for a in args)})"
        else:
            qualified = (fr.namespace_ + "::" if fr and fr.namespace_ else "") + base
            # A global function the enclosing class also has a method for
            # needs the global scope said out loud, or the method shadows it
            # and the compiler reports the wrong candidate: Crazy Party's
            # `Case::lanceMenu` calls the global 8-parameter `lanceMenu`, and
            # unqualified that read as a 6-parameter method called with 8
            # arguments. `::f(...)` was put to the compiler before being
            # emitted.
            if (fr is not None and fr.object_type is None and not fr.namespace_
                    and self._shadowed_by_enclosing_class(base)):
                qualified = "::" + base
            calltxt = f"{qualified}({', '.join(a.text for a in args)})"

        if has_out and pop_out is not None and pop_out.is_ptr \
                and pop_out.offset is not None:
            # result lands directly in the caller's slot
            self._bind(pop_out.offset, Atom("call", calltxt))
        elif ret is not None and ret.format() != "void":
            self.value_reg = Atom("call", calltxt, is_ptr=ret.is_reference, data_type=ret)
            self.pending_value_call = calltxt
            self.pending_value_call_pos = self._pos()
            if out_locals:
                self.deferred_out_calls[calltxt] = (ret, out_locals, self._pos())
        else:
            self._stmt(f"{calltxt};")

    def _alloc(self, ins: Instr) -> None:
        tname = ins.type_ref.format_name() if ins.type_ref else f"type#{ins.qw_arg}"
        fr = ins.func_ref
        nparams = len(fr.param_types) if fr else 0
        # VM layout: [dest pushed first] [args reversed] (obj pushed by VM);
        # pops yield args in forward order, then the destination slot.
        args = [self._deref(self.stack.pop() if self.stack else Atom("raw", "<?>"))
                for _ in range(nparams)]
        dest = self.stack.pop() if self.stack else None
        txt = f"{tname}({', '.join(a.text for a in args)})"
        # `string(x)` where x is already a string expression -> just x
        if (tname in ("string",) and len(args) == 1
                and not args[0].text.startswith('""')):
            txt = args[0].text
            if fr and (fr.param_types[0].obj_type is None or
                       fr.param_types[0].obj_type.name != "string"):
                txt = f"{tname}({args[0].text})"
        if dest is not None and dest.kind == "list_elem":
            self.list_values.setdefault(dest.offset, {})[dest.list_index] = Atom("call", txt)
        elif dest is not None and dest.is_ptr and dest.offset is not None:
            if self.is_named(dest.offset):
                self._emit_assign(dest.offset, Atom("call", txt))
            else:
                self.consumed_temps.discard(dest.offset)
                self.temps[dest.offset] = Atom("call", txt)
        elif dest is not None and dest.text:
            # destination is a property/global address (e.g. `wname = n`)
            self._stmt(f"{dest.text} = {txt};")
        else:
            self.value_reg = Atom("call", txt)

    def _calls_a_base_method(self, owner: str, name: str,
                             opcode: str = "CALL") -> bool:
        """Is this `this.name()` really a call to a BASE class's `name`?

        Three things have to hold. The function the operand resolved to must
        belong to an ancestor of the class this body is in; that class must
        declare the name as well, because where it does not the unqualified
        call already reaches the base's one and saying so adds nothing; and
        **the call must not be a virtual dispatch.**

        Only `derived_from` is walked, so an interface's methods -- reached
        through `interfaces` -- can never match here and cannot be pinned to
        a base by mistake.

        **The opcode is load-bearing, and this file used to say it was not.**
        It recorded that gating on it "kept `person::reset` qualified while
        letting `clock::reset` fall back to `this.reset()` ... although both
        sites disassemble to a plain `CALL`", and concluded the opcode was
        the wrong field. `clock::reset` really is a plain `CALL` of
        `interact::reset`, so a gate on the opcode keeps it qualified; that
        conclusion came from an experiment that was measuring something
        else, and taking it on trust left the bug below in place.

        What the opcode separates is a base call from an *override reached
        virtually*. `CALL` names one implementation; `CALLINTF` goes through
        the vftable, and the owner the module records for it is the class
        that first **declared** the method, not the one that will run:

            door::door    PshVPtr this ; CALL connection::connection
                          PshVPtr this ; CALLINTF interact::reset
            door::reset   PshVPtr this ; CALL connection::reset

        So `door()` is `super(); reset();` -- a virtual call that runs
        `door::reset` -- while `door::reset` is `connection::reset();`.
        Qualified alike, every derived constructor in Paladin came out as
        `super(); interact::reset();`, which runs the *base's* reset and
        nothing else. `door::reset` is what sets `connection_type = 1`, and
        `get_floor_of_residence` looks for exactly that, so no cabin could
        be matched to its floor and starting a new game died with `Index out
        of bounds` on `world[-1]`. Of 93 such sites in Paladin, 60 are
        `CALL` and 33 are `CALLINTF`.
        """
        if opcode == "CALLINTF":
            return False
        here = self.fn.object_type
        if here is None or not owner or owner == here.name:
            return False
        if not any(m is not None and m.name == name
                   for m in (here.methods or ())):
            return False
        base = getattr(here, "derived_from", None)
        seen = set()
        while base is not None and id(base) not in seen:
            seen.add(id(base))
            if base.name == owner:
                return True
            base = getattr(base, "derived_from", None)
        return False

    def _shadowed_by_enclosing_class(self, name: str) -> bool:
        """Does the class this body belongs to declare a method of this name?

        Only then does an unqualified call to a global function resolve to the
        wrong thing. Inherited methods shadow too, so the bases are walked.
        """
        owner = self.fn.object_type
        seen = set()
        while owner is not None and id(owner) not in seen:
            seen.add(id(owner))
            for method in owner.methods or ():
                if method is not None and method.name == name:
                    return True
            owner = getattr(owner, "derived_from", None)
        return False

    def _funcdef_matching(self, fn) -> str:
        """The module's funcdef with this function's signature, if just one has it.

        Ambiguity is left alone rather than guessed: an unwrapped delegate
        does not compile, which is a visible failure, where the wrong funcdef
        would compile and bind the wrong callback.
        """
        if fn is None:
            return ""
        want = (fn.return_type.format(),
                tuple(p.format() for p in fn.param_types))
        hits = []
        for fd in getattr(self.m, "funcdefs", ()) or ():
            if fd is None:
                continue
            if (fd.return_type.format(),
                    tuple(p.format() for p in fd.param_types)) == want:
                hits.append((fd.namespace_ + "::" if fd.namespace_ else "") + fd.name)
        return hits[0] if len(hits) == 1 else ""

    def _funcdef_from_consumer(self) -> str:
        """The funcdef named by the parameter this delegate is passed into.

        A *registered* funcdef is not in the module's own list, and the module
        records every funcdef-typed value under the `_builtin_function_`
        placeholder, so neither the slot nor `_funcdef_matching` can name it.
        The call that consumes the delegate can: Crazy Party's
        `JoueurTerrain::setPf` binds `Terrain::callbackPf` and passes it to
        `pathfinder::set_callback_function`, whose parameter the BGT adapter
        has already named `pathfinder_callback` from the engine's own
        documentation.

        Only a registered type counts -- one the module does not declare as a
        class -- and only when the callee has exactly one such parameter, so
        there is nothing to choose between.
        """
        declared = {c.name for c in getattr(self.m, "classes", ()) or () if c}
        for ins in self.instrs[self.k + 1:]:
            if not ins.name.startswith("CALL"):
                continue
            fr = ins.func_ref
            if fr is None:
                return ""
            names = []
            for dt in fr.param_types:
                ot = dt.obj_type
                if (ot is None or ot.name in declared
                        or ot.name == "_builtin_function_"
                        or getattr(ot, "kind", "") != "app"):
                    continue
                names.append(ot.name)
            return names[0] if len(names) == 1 else ""
        return ""

    def _call_ptr(self, ins: Instr) -> None:
        self._flush_pending_call()
        off = _s16(ins.w_arg2)
        dt = self.var_types.get(off)
        type_name = dt.obj_type.name if dt and dt.obj_type else ""
        if not type_name:
            # The slot may carry no declared type -- BGT records a
            # funcdef-typed local under a placeholder that names no funcdef --
            # but the value in it does: `global_events[i]` is an element of an
            # `event@[]`, and that is what says the call takes one argument.
            value = self._slot_atom(off)
            if value.data_type is not None and value.data_type.obj_type is not None:
                type_name = value.data_type.obj_type.name
        fr = next((f for f in self.m.funcdefs if f.name == type_name), None)
        nparams = len(fr.param_types) if fr is not None else ins.w_arg
        ret = fr.return_type if fr is not None else None
        has_out = ret is not None and _needs_out_ref(ret)
        pop_out = self.stack.pop() if has_out and self.stack else None
        args = [self._deref(self.stack.pop() if self.stack else Atom("raw", "<?>"))
                for _ in range(nparams)]
        if fr is not None:
            args = [self._normalize_arg(a, fr.param_types[index]) for index, a in enumerate(args)]
        callable_text = self._slot_atom(off).text.lstrip("@")
        calltxt = f"{callable_text}({', '.join(a.text for a in args)})"
        if has_out and pop_out is not None and pop_out.offset is not None:
            self._bind(pop_out.offset, Atom("call", calltxt))
        elif ret is not None and ret.format() != "void":
            self.value_reg = Atom("call", calltxt, is_ptr=ret.is_reference, data_type=ret)
            self.pending_value_call = calltxt
            self.pending_value_call_pos = self._pos()
        else:
            self._stmt(f"{calltxt};")

    # -- branches -----------------------------------------------------------

    def _sparse_switch_pattern(self, index):
        """Recognize the compiler's high guard / equality dispatch / default.

        Require a shared switch exit in the case tails. Ordinary comparison
        chains and partially recognized mixed table dispatches remain intact.
        """
        if index + 4 >= len(self.instrs):
            return None
        high, guard = self.instrs[index:index + 2]
        if high.name not in ("CMPIi", "CMPIu") or guard.name != "JP":
            return None
        default = _jump_target(guard)
        cases = []
        cursor = index + 2
        while cursor + 1 < len(self.instrs):
            compare, branch = self.instrs[cursor:cursor + 2]
            if (compare.name != high.name or compare.w_arg != high.w_arg
                    or branch.name != "JZ"):
                break
            value = _s32(compare.dw_arg) if high.name == "CMPIi" else compare.dw_arg
            cases.append((value, _jump_target(branch)))
            cursor += 2
        if (not cases or cursor >= len(self.instrs)
                or self.instrs[cursor].name != "JMP"
                or _jump_target(self.instrs[cursor]) != default
                or len({value for value, _ in cases}) != len(cases)
                or max(value for value, _ in cases) !=
                   (_s32(high.dw_arg) if high.name == "CMPIi" else high.dw_arg)):
            return None
        entries = sorted({target for _, target in cases} | {default})
        if entries[0] <= self.instrs[cursor].pos:
            return None
        joins = []
        for begin, end in zip(entries, entries[1:]):
            body = [op for op in self.instrs if begin <= op.pos < end and op.name not in SKIP_OPS]
            if body and body[-1].name == "JMP" and _jump_target(body[-1]) >= entries[-1]:
                joins.append(_jump_target(body[-1]))
        if not joins or len(set(joins)) != 1:
            return None
        return cursor + 1, cases, default, joins[0], _s16(high.w_arg)

    def _dense_switch_pattern(self, index):
        """Recognize the compiler's jump-table dispatch.

        A `switch` over a dense range compiles to a bounds check, a
        normalisation and a computed jump into a table of unconditional jumps,
        one per value:

            CMPIi arg0, 31 ; JP  after        high bound
            CMPIi arg0, 1  ; JS  after        low bound
            CMPIi arg0, 12 ; JP  next_range   this table's own high bound
            SUBIi v1, arg0, 1                 normalise to zero
            JMPP  v1                          jump to table[v1]
            JMP case1 / JMP case2 / JMP default / ...

        So the table is the run of jumps after `JMPP`, entry *i* is the value
        `i + offset` where the `SUBIi` supplies the offset, and the value
        switched on is that instruction's *source* rather than the normalised
        slot. Unrecognised, each table entry prints as `goto` -- which
        AngelScript has no keyword for, so every one of them is an error: 26 of
        Paladin's 28 and 50 of Psycho Strike's, all in nine bodies.

        The result is the same tuple the sparse form produces, so everything
        downstream is shared.
        """
        table = self._dense_table(index)
        if table is None:
            return None
        cursor, cases, default, selector, next_range = table

        # One source `switch` over scattered values compiles to SEVERAL dense
        # tables, each guarded by its own range check and jumping to the next
        # range when the value is outside it. Read as one table each, the
        # first switch's extent swallows the later ranges' bodies -- they come
        # out as `return` statements with no `case` above them, which compiles
        # and answers the wrong thing. So follow the chain and merge.
        seen = {index}
        while next_range is not None:
            following = self.pos_of.get(next_range)
            if following is None:
                break
            nxt = next((i for i in range(following, min(following + 12, len(self.instrs)))
                        if self.instrs[i].name == "JMPP"), None)
            if nxt is None or nxt in seen:
                # The chain's last link need not be another table: a single
                # remaining value is an equality compare, not a range.
                link = self._equality_chain(following, cursor, selector, default)
                if link is None:
                    break
                cursor, more_cases, next_range = link
                cases += [case for case in more_cases if case[1] != default]
                continue
            more = self._dense_table(nxt)
            if more is None or more[3] != selector:
                break
            seen.add(nxt)
            cursor = max(cursor, more[0])
            cases += [case for case in more[1] if case[1] != default]
            next_range = more[4]
        # The tables merged in are inside the span the switch handler skips
        # (`self.k + 1` to `cursor`), so they never dispatch on their own; no
        # separate bookkeeping is needed, and `skip_indexes` does not exist
        # yet when this runs.
        if not cases:
            return None

        entries = sorted({target for _, target in cases} | {default})
        if entries[0] <= self.instrs[cursor - 1].pos:
            return None                   # a table entry jumping backwards
        joins = []
        for begin, end in zip(entries, entries[1:]):
            body = [op for op in self.instrs
                    if begin <= op.pos < end and op.name not in SKIP_OPS]
            if body and body[-1].name == "JMP" and _jump_target(body[-1]) >= entries[-1]:
                joins.append(_jump_target(body[-1]))
        if not joins or len(set(joins)) != 1:
            return None
        return cursor, cases, default, joins[0], selector

    def _equality_chain(self, index, cursor, selector, default):
        """The tail of a switch chain written as compares rather than a table.

        A `switch` over scattered values compiles to one dense table per
        dense range, each guard sending the value on to the next. Where a
        range holds a *single* value there is no table to build, so the
        compiler emits the compare directly:

            CMPIi v35, 27 ; JZ case27
            JMP   exit                       the switch's own default

        Read as a table that is not there, the chain simply stops, and the
        compare is left behind as a branch to the switch's exit -- a block the
        switch handler has already consumed, so it is a `goto` to a label that
        is never emitted. One source `switch` in Super Egg Hunt's
        `submit_score` is exactly this: `case 1..3` as a table, `case 27`
        as a compare.

        Returns `(cursor, cases, next range)`, or None when this is not that
        shape. Two conditions keep it honest: the compare must test the
        selector the table normalised, and the chain must begin exactly where
        the table's entries ended. The second matters because `cursor` is the
        span the switch handler skips -- extending it to a block that is not
        adjacent would swallow whatever lies between.
        """
        if index != cursor:
            return None
        cases = []
        while index + 1 < len(self.instrs):
            compare, jump = self.instrs[index], self.instrs[index + 1]
            if (compare.name not in ("CMPIi", "CMPIu")
                    or _s16(compare.w_arg) != selector or jump.name != "JZ"):
                break
            target = _jump_target(jump)
            if target is None:
                return None
            cases.append((_s32(compare.dw_arg), target))
            index += 2
        if not cases:
            return None
        # The fall-through is where a value matching nothing here goes: the
        # switch's own default, or the next link of the chain.
        tail = self.instrs[index] if index < len(self.instrs) else None
        if tail is None or tail.name != "JMP":
            return None
        following = _jump_target(tail)
        return index + 1, cases, None if following == default else following

    def _dense_table(self, index):
        """One jump table: (end index, cases, default, selector, next range).

        `next range` is where the guard sends a value outside this table's
        range, which is where the next table of the same switch lives.
        """
        jmpp = self.instrs[index]
        if jmpp.name != "JMPP":
            return None
        targets = []
        cursor = index + 1
        while cursor < len(self.instrs) and self.instrs[cursor].name == "JMP":
            targets.append(_jump_target(self.instrs[cursor]))
            cursor += 1
        if len(targets) < 2 or any(target is None for target in targets):
            return None

        # The normalisation immediately before, if any: it names both the
        # value switched on and the first entry's label.
        selector = _s16(jmpp.w_arg)
        offset = 0
        previous = self.instrs[index - 1] if index else None
        if (previous is not None and previous.name in ("SUBIi", "ADDIi")
                and _s16(previous.w_arg) == selector):
            selector = _s16(previous.w_arg2)
            delta = _s32(previous.dw_arg)
            offset = delta if previous.name == "SUBIi" else -delta

        # The guards before it: the last one skips this table's own range, the
        # ones before it bound the switch as a whole.
        guards = [op for op in self.instrs[max(0, index - 8):index]
                  if op.name in ("JP", "JS", "JNS", "JNP")]
        next_range = _jump_target(guards[-1]) if guards else None

        # **Where the guards agree, they name the default outright.** A
        # switch that is one table has no next range to be sent to, so every
        # guard jumps to the same place and that place is the default. Say so
        # rather than counting.
        #
        # Counting is what was here, on the argument that the compiler fills
        # a range's gaps with the default label -- true, and bounded: it
        # starts a new table when `values[n-1] + 5 < values[n]`, read out of
        # `asCCompiler::CompileSwitchStatement`, so a run of filler is at
        # most four. But several case labels stacked on one body,
        #
        #     case 1: case 2: case 3: speak("..."); break;
        #
        # put that arm in the table as many times, and nothing stops a real
        # case outnumbering the gaps. Manamon 2 has two: `ms_davidson`'s
        # table is `[38, 45, 45, 52, 59, 66, 144]` with the default at 0x95,
        # which is not in the table at all -- counted, the default became the
        # arm two cases share, and the real default arm was dropped. It
        # compiles, it runs, and a dialogue function answers the wrong line.
        counts = collections.Counter(targets)
        default, repeats = counts.most_common(1)[0]
        guard_targets = {_jump_target(op) for op in guards}
        if len(guard_targets) == 1:
            default = next(iter(guard_targets))
        elif repeats == 1:
            # No repeated entry and the guards disagree: this table is a link
            # in a chain, so it has no default of its own and the outermost
            # guard -- the one bounding the whole switch -- supplies it.
            if not guards:
                return None
            default = _jump_target(guards[0])
        cases = [(value + offset, target)
                 for value, target in enumerate(targets) if target != default]
        return cursor, cases, default, selector, next_range

    def _begin_switch(self, ins: Instr) -> bool:
        """Recognize the guarded dense jump-table protocol, without guessing."""
        if self.k < 5:
            return False
        high, high_jump, low, low_jump, subtract = self.instrs[self.k - 5:self.k]
        if (high.name not in ("CMPIi", "CMPIu") or high_jump.name != "JP"
                or low.name not in ("CMPIi", "CMPIu") or low_jump.name != "JS"
                or subtract.name != "SUBIi" or subtract.w_arg != ins.w_arg
                or high.w_arg != low.w_arg or high.w_arg != subtract.w_arg2
                or _jump_target(high_jump) != _jump_target(low_jump)):
            return False
        table = []
        for index in range(self.k + 1, len(self.instrs)):
            entry = self.instrs[index]
            if entry.name != "JMP":
                break
            table.append((index, _jump_target(entry)))
        minimum = _s32(subtract.dw_arg)
        if not table or minimum != _s32(low.dw_arg) or minimum + len(table) - 1 != _s32(high.dw_arg):
            return False
        default = _jump_target(low_jump)
        entries = sorted({target for _, target in table} | {default})
        if entries[0] <= self.instrs[table[-1][0]].pos:
            return False
        joins = []
        for begin, end in zip(entries, entries[1:]):
            body = [i for i in self.instrs if begin <= i.pos < end and i.name not in SKIP_OPS]
            if body and body[-1].name == "JMP" and _jump_target(body[-1]) >= entries[-1]:
                joins.append(_jump_target(body[-1]))
        if not joins or len(set(joins)) != 1:
            return False
        join = joins[0]
        self.events = [e for e in self.events if e.pos not in (high_jump.pos, low_jump.pos)]
        self.events.append(Event("switch", ins.pos,
            (self._slot_atom(_s16(subtract.w_arg2)).text,
             [(minimum + index, target) for index, (_, target) in enumerate(table)], default, join)))
        self.skip_indexes.update(index for index, _ in table)
        return True

    def _branch(self, ins: Instr) -> None:
        self.pending_value_call = None
        target = _jump_target(ins)
        cond = self._taken_condition(ins)
        if target > self._pos():
            self.object_branch_snapshots.setdefault(target, {}).update({
                off: value for off, value in self.temps.items()
                if value.kind != "null" and off in self.var_types
                and self.var_types[off].obj_type is not None})
            cond = _negate_cond(cond)
        self.events.append(Event("branch", self._pos(), (cond, target)))

    def _declared_numeric(self, text: str) -> bool:
        """Is this text a bare slot name whose declaration is a number?"""
        if not re.fullmatch(r"[A-Za-z_]\w*", text):
            return False
        off = next((o for o, n in self.var_names.items() if n == text), None)
        dt = self.var_types.get(off) if off is not None else None
        return (dt is not None and dt.obj_type is None
                and dt.token_type in NUMERIC_TOKENS)

    def _as_bool_text(self, text: str, atom: Optional[Atom] = None) -> str:
        """Make this condition text something the engine accepts as a bool.

        Two ways in, because the text does not always still belong to its atom.
        When it does, `_normalize_arg` types it. When `_unwrap_bool` has peeled
        a `(x ? 1 : 0)` wrapper off, what is left is the bare inner expression
        with no atom to ask -- and if that is a numerically-typed slot, peeling
        turned a valid condition into an `int` one. So a bare name is looked up
        among the slots and converted by its declared type.
        """
        if atom is not None and text == atom.text:
            return self._normalize_arg(atom, DataType(token_type=67)).text
        if self._declared_numeric(text):
            return f"({text} != 0)"
        return text

    def _taken_condition(self, ins: Instr) -> str:
        """Condition under which a jump instruction transfers control."""
        op = JUMP_OPS[ins.name]
        if self.cmp_pair is not None and self.cmp_is_handle and op in ("==", "!="):
            op = "is" if op == "==" else "!is"
        self.cmp_is_handle = False
        if self.cmp_pair is not None:
            a, b = self.cmp_pair
            self.cmp_pair = None
            # A comparison against a bool literal is just the value or its
            # negation: `x == true` -> x, `x == false` -> !x, `x != true` -> !x,
            # `x != false` -> x. _negate_cond also cancels a double negation, so
            # `!(getf()) == false` collapses to `getf()`.
            if op in ("==", "!="):
                left, right = _unwrap_bool(a.text), _unwrap_bool(b.text)
                for lit, other, atom in ((right, left, a), (left, right, b)):
                    if lit not in ("true", "false"):
                        continue
                    keep = (op == "==") == (lit == "true")
                    # Dropping the comparison leaves the operand *as the
                    # condition*, so a numerically-typed one still has to be
                    # read as a bool. `x == false` became `!x` and `x == true`
                    # became `x`, which is an error on an int slot -- and the
                    # same operand two lines earlier, reached through the
                    # value register, converted correctly. All 7 of Paladin's
                    # came through here: `if (!local_3)`, `if (local_26)`,
                    # `(local_3 ? 1 : 0)` and the `||` that held one.
                    other = self._as_bool_text(other, atom)
                    return other if keep else _negate_cond(other)
            cond = f"({a.text} {op} {b.text})"
            # drop the wrapping parens the binop simulation added
            if a.text.startswith("(") and a.text.endswith(")"):
                cond = f"{a.text} {op} {b.text}"
        else:
            v = self._normalize_arg(self.value_reg, DataType(token_type=67)).text if op in ("==", "!=") else self.value_reg.text
            if v == "1":
                v = "true"
            elif v == "0":
                v = "false"
            cond = v if op in ("==", "!=") else f"({v} {op} 0)"
            if op == "!=":
                cond = v
            elif op == "==":
                cond = f"!({v})"
            else:
                cond = f"({v} {op} 0)"
        return cond

    def _emit_global_write_special(self) -> None:  # pragma: no cover
        pass

    def _begin_ref_cast(self, ins: Instr) -> bool:
        """Recognise the compiler's null-safe reference cast, `cast<T@>(x)`.

            CmpPtr x, null / JZ L          x null?  then the result is null
            PshVPtr x / CALL* opCast       else ask x to convert itself
            STOREOBJ d / JMP J
            L: ClrVPtr d
            J: ...                          d is the cast result

        Walked linearly the null arm is simulated last and wins, so
        `cast<pack_file@>(sound_default_pack).pack_name` read
        `null.get_pack_name()`. Every instruction of the shape is checked; any
        deviation leaves it to the general branch handling.
        """
        k, code = self.k, self.instrs
        if k + 6 >= len(code):
            return False
        x, null_slot = _s16(ins.w_arg), _s16(ins.w_arg2)
        jz, push, call, store, jmp, clear = code[k + 1:k + 7]
        held = self.temps.get(null_slot)      # ClrVPtr binds a `null` constant
        null_known = held is not None and (held.kind == "null" or held.text == "null")
        if not (null_known and jz.name == "JZ" and push.name == "PshVPtr"
                and _s16(push.w_arg) == x
                and call.name in ("CALL", "CALLSYS", "CALLINTF")
                and call.func_ref is not None
                and call.func_ref.name in ("opCast", "opImplCast")
                and store.name == "STOREOBJ" and jmp.name == "JMP"
                and clear.name == "ClrVPtr" and _s16(clear.w_arg) == _s16(store.w_arg)
                and _jump_target(jz) == clear.pos
                and k + 7 < len(code) and _jump_target(jmp) == code[k + 7].pos):
            return False
        ret = call.func_ref.return_type
        target = ret.format().removeprefix("const ").rstrip("&")
        if not target.endswith("@"):
            target += "@"
        source = self._compared(x)            # the cast consumes x
        self._flush_pending_call()
        self._bind(_s16(store.w_arg),
                   Atom("call", f"cast<{target}>({source.text})", data_type=ret))
        self.skip_indexes.update(range(k + 1, k + 7))
        return True

    def _begin_bool_merge(self, ins: Instr) -> bool:
        """Recognize the compiler's short-circuit A&&B / A||B value merge."""
        if ins.name not in JUMP_OPS or self.k + 2 >= len(self.instrs):
            return False
        setv, jump = self.instrs[self.k + 1:self.k + 3]
        if setv.name not in ("SetV1", "SetV2", "SetV4") or jump.name != "JMP":
            return False
        expected = _s32(setv.dw_arg)
        if expected not in (0, 1) or _jump_target(ins) <= ins.pos:
            return False
        merge_pos = _jump_target(jump)
        merge_idx = self.pos_of.get(merge_pos)
        if merge_idx is None:
            return False
        # **A handle release can sit on the merge point**, and it says nothing
        # about the shape. The last operand of `interact_in_location`'s
        # ten-term `&&` lands on `FREE 4` -- the chain borrowed the array
        # element and the compiler released it exactly there -- while every
        # earlier merge in the same chain lands straight on its `CpyVtoR4`:
        #
        #     0x13C CpyVtoV4 v8 <- v7
        #     0x13E FREE 4            <- the jump target
        #     0x140 CpyVtoR4 v8       <- the merge
        #
        # Declining the merge detached the final operand from the chain and
        # the `return true` went with it, so the recovered test was
        # `if (interacts[i].type != 16) return true;` -- every interact that
        # is not type 16 blocks the player, in every direction, from the
        # moment a map is entered. The other nine terms, `is_solid` among
        # them, were emitted as an `if` with two empty arms and dropped.
        #
        # `merge` is only ever used as a lower bound on position, so the
        # recorded `finish_pos` stays the jump target; only the instruction
        # the *shape* is read from moves.
        shape_idx = merge_idx
        while (shape_idx < len(self.instrs)
               and self.instrs[shape_idx].name in ("FREE", "SUSPEND")):
            shape_idx += 1
        if shape_idx >= len(self.instrs):
            return False
        merge_ins = self.instrs[shape_idx]
        result_dest = _s16(setv.w_arg)
        # `&&` / `||` produce a bool. The same shape with a non-bool
        # destination is a ternary over constants -- basic_character_
        # controller's `right ? HANDEDNESS_RIGHT : HANDEDNESS_LEFT` (1 and 0)
        # read as `is_right_handed || 0`, which does not convert to the enum.
        # Only an ENUM or object destination rules it out: the compiler reuses
        # int temporaries for bools, so an int-typed slot is still an `&&`
        # (form.bgt's `@cb != null && cb(f, ..., {...}) == 1`).
        dest_type = self.var_types.get(result_dest)
        if dest_type is not None and dest_type.obj_type is not None:
            return False
        # ...and neither does type alone: basic_character_controller's
        # `right ? RIGHT : LEFT` has an int temporary too. Structure settles
        # it -- in `a || b` the other arm COMPUTES b, while a ternary over
        # constants has a single constant store there. (`x || false` is not
        # something anyone writes.)
        other_start = self.pos_of.get(_jump_target(ins))
        if other_start is not None:
            other = [op for op in self.instrs[other_start:merge_idx]
                     if op.name != "SUSPEND"]
            if (len(other) == 1 and other[0].name in ("SetV1", "SetV2", "SetV4")
                    and _s16(other[0].w_arg) == result_dest):
                return False
        finish_pos = merge_pos
        if merge_ins.name == "CpyVtoV4" and _s16(merge_ins.w_arg2) == result_dest:
            # The result is stored into another slot and read later -- a named
            # `bool b = A && B` used in an `if`, a ternary or an expression, not
            # a value fed straight to the register. The CpyVtoV4 at the merge
            # folds (A op B) into the stored slot (see the CpyVtoV4 handler), and
            # every later read of that slot sees the whole value, however far.
            # Only when the stored slot is a bool: the same shape storing a uint
            # is a ternary over values, which _begin_value_merge handles -- and
            # folding it as `A op uint` gave "No conversion from 'uint' to
            # 'bool'". A short-circuit's value is always a bool.
            stored = _s16(merge_ins.w_arg)
            b_type = self.var_types.get(stored)
            if ((b_type is None or b_type.format() != "bool")
                    and not self._tested_as_bool(stored, shape_idx + 1)):
                # Typing is not the only evidence, and on a compiler scratch
                # slot it is the weaker one: `slot_types` reads widths, and
                # `SetV4` is as true of an int as of a bool. The bytecode says
                # it outright when the stored value is tested with `JLow*`,
                # which tests the low byte -- the bool protocol and nothing
                # else. Without this, `dynamic_menu::run_extended`'s
                # `stick.get_y() < -100 && !stick_moved` was declined here,
                # emitted as an `if` with two empty arms, and dropped out of
                # the condition it belonged to: the recovered menu read
                # `key_pressed(KEY_UP) || key_pressed(KEY_I) || true` and the
                # arrow keys did nothing.
                return False
        elif merge_ins.name != "CpyVtoR4" or _s16(merge_ins.w_arg) != result_dest:
            return False
        taken = self._taken_condition(ins)
        self.pending_value_call = None
        first = taken if expected == 0 else _negate_cond(taken)
        self.bool_merges.append({"first": Atom("call", first), "dest": result_dest,
                                 "merge": finish_pos,
                                 "op": "&&" if expected == 0 else "||"})
        self.skip_indexes.update((self.k + 1, self.k + 2))
        return True

    def _short_circuit_slots(self) -> set[int]:
        """Slots the compiler carries a short-circuit `&&` / `||` value through.

        Recognised from the bytecode alone, because this has to be known
        *before* the simulation decides which slots are variables -- and a
        slot that holds half of an `&&` is never one of the source's own
        locals, whatever a declaration order suggests.

        The shape is the one `_begin_bool_merge` consumes: a conditional jump
        over `SetV<dest>, 0|1` and a `JMP` to the merge, where the merge
        either loads `dest` into the value register or copies it onward. Two
        kinds of slot are the compiler's and not the source's:

        * `dest`, which the merge's value arrives in on both paths;
        * every slot the *arm* writes, which holds a piece of the right-hand
          operand and exists only while that operand is being computed.

        **The slot the jump tested is deliberately NOT one of them**, and
        that distinction is the whole difference between this working and
        doing harm. The left-hand operand is usually a perfectly ordinary
        local -- `int d = get_total_distance(a, b); if (d > limit && ...)` --
        so excluding it unforces a real variable and the value folds into
        each of its reads instead. Measured on Super Egg Hunt that cost three
        duplicated calls: `sound_pool` ran `get_total_distance` twice, a menu
        ran its item callback twice, and the "erase all data" confirmation
        asked *twice* while the branch that chose the other wording of the
        prompt vanished. Those read as ordinary code and are not ordinary
        code, which is the failure mode this whole file is organised around.

        Shape-only: no type test, no simulation state, since this has to be
        known before the simulation starts. A false positive costs a slot its
        forced name, which the fold rules and the duplicate-fold count still
        guard; a false negative costs a condition its meaning, which nothing
        downstream can see.
        """
        slots: set[int] = set()
        for k, ins in enumerate(self.instrs):
            if ins.name not in JUMP_OPS or k + 2 >= len(self.instrs):
                continue
            setv, jump = self.instrs[k + 1:k + 3]
            if setv.name not in ("SetV1", "SetV2", "SetV4") or jump.name != "JMP":
                continue
            if _s32(setv.dw_arg) not in (0, 1) or _jump_target(ins) <= ins.pos:
                continue
            merge_idx = self.pos_of.get(_jump_target(jump))
            if merge_idx is None:
                continue
            dest = _s16(setv.w_arg)
            merge_ins = self.instrs[merge_idx]
            loads_dest = (merge_ins.name in ("CpyVtoR4", "CpyVtoR8")
                          and _s16(merge_ins.w_arg) == dest)
            stores_dest = (merge_ins.name in ("CpyVtoV4", "CpyVtoV8")
                           and _s16(merge_ins.w_arg2) == dest)
            if not (loads_dest or stores_dest):
                continue
            slots.add(dest)
            arm_idx = self.pos_of.get(_jump_target(ins))
            if arm_idx is None:
                continue
            for index in range(arm_idx, merge_idx):
                op = self.instrs[index]
                if op.name in _SLOT_WRITE_OPS:
                    off = _s16(op.w_arg)
                    if off > 0:
                        slots.add(off)
                elif op.name == "PSF":
                    # **An object slot is written by a behaviour, not by an
                    # opcode that names it.** A string is filled by pushing
                    # its address and calling the constructor -- `PSF n` then
                    # `CALLSYS string::_beh_0_` -- and emptied by `_beh_2_`,
                    # so no entry in `_SLOT_WRITE_OPS` mentions slot `n` at
                    # all. A slot constructed or destroyed *inside* an arm
                    # belongs to that arm: one declared outside is built and
                    # torn down outside.
                    #
                    # Paladin's `item_type_to_function` is
                    # `arg0 == "healing potion" || arg0 == "medical miracle"
                    # || arg0 == "levelup erb" || arg0 == "perfect healing"`,
                    # with one string slot reused for all four literals.
                    # Forced to be a variable, the four assignments were
                    # hoisted out ahead of the `if` and every comparison read
                    # the last one, so three of the four healing items were
                    # classified as something else.
                    off = _s16(op.w_arg)
                    if off <= 0:
                        continue
                    nxt = next((self.instrs[j] for j in range(index + 1, merge_idx)
                                if self.instrs[j].name != "SUSPEND"), None)
                    callee = getattr(getattr(nxt, "func_ref", None), "name", "")
                    # **A behaviour has two spellings**, the same trap as the
                    # delegate factory's `%delegate_factory` / `$dlgte`. The
                    # disassembler prints `string::_beh_0_`, which is what a
                    # reader sees and reaches for; the name the module stores
                    # and the IR carries is `$beh0`. Matching only the pretty
                    # one matched nothing at all, silently.
                    if (callee or "").startswith(("$beh", "_beh_")):
                        slots.add(off)
        return slots

    def _tested_as_bool(self, slot: int, start: int, window: int = 4) -> bool:
        """Is this slot loaded and then tested as a boolean, right here?

        `JLowZ` / `JLowNZ` / `JLowS` / `JLowNS` follow no compare: they test
        the low byte of the value register, which is what a bool leaves there.
        So a slot copied to the register and tested that way is a bool whatever
        a width-based type inference called it.

        **A handle release sits between the merge and the test, and says
        nothing about either.** Skipping only `SUSPEND` made this bail on the
        `FREE` that ends the borrowed array element's lifetime, which is the
        same instruction that broke the merge-shape lookup in
        `_begin_bool_merge`. `map::check_interacts` is what that cost:

            can_interact() && (interact_keys() || on_approach)

        The inner `||` stores into a slot the width inference calls `int`, so
        it needs this test -- and the slot *is* loaded and tested with
        `CpyVtoR4 v7 ; JLowZ`, two instructions after a `FREE 4`. Declined,
        the `||` was emitted as an `if` with one empty arm, its value thrown
        away, and the outer `&&` paired `can_interact` with `on_approach`
        directly. An interact then fired only when it triggers on approach,
        whatever key was pressed -- so in the recovered game **nobody could
        be talked to**.
        """
        seen_load = False
        for idx in range(start, min(start + window, len(self.instrs))):
            op = self.instrs[idx]
            if op.name in ("SUSPEND", "FREE"):
                continue
            if not seen_load:
                if op.name in ("CpyVtoR4", "CpyVtoR8") and _s16(op.w_arg) == slot:
                    seen_load = True
                    continue
                return False
            return op.name in ("JLowZ", "JLowNZ", "JLowS", "JLowNS")
        return False

    def _begin_value_merge(self, ins: Instr) -> bool:
        """Fold side-effect-free ternary arms which write a common temp.

        Evaluate each arm in an isolated simulation. Reject branches, emitted
        statements, stack-shape changes and named destinations so an ordinary
        if/else or a side-effecting expression cannot be folded accidentally.
        """
        else_idx = self.pos_of.get(_jump_target(ins))
        if else_idx is None or else_idx <= self.k + 1:
            return False
        term = next((j for j in range(self.k + 1, else_idx)
                     if self.instrs[j].name == "JMP" and
                     _jump_target(self.instrs[j]) > _jump_target(ins)), None)
        if term is None:
            return False
        merge_idx = self.pos_of.get(_jump_target(self.instrs[term]))
        if merge_idx is None or merge_idx <= else_idx:
            return False
        while merge_idx < len(self.instrs) and self.instrs[merge_idx].name == "SUSPEND":
            merge_idx += 1
        if merge_idx >= len(self.instrs):
            return False
        load = self.instrs[merge_idx]
        stack_merge = load.name == "RDSPtr"
        recognized = (load.name in ("CpyVtoR4", "CpyVtoR8", "PSF", "VAR",
                                    "PshV4", "PshV8", "LOADOBJ")
                      or load.name in CONV_OPS)
        if recognized:
            off = _s16(load.w_arg2 if load.name in CONV_OPS and load.bc_type != "asBCTYPE_rW_ARG" else load.w_arg)
            if self.is_named(off):
                return False
        elif load.name in BINARY or load.name in IMM_BINARY or load.name in (
                "CMPi", "CMPi64", "CMPu", "CMPu64", "CMPf", "CMPd"):
            # The ternary's value is not pushed or returned but read straight
            # into a numeric operand -- `ADDi slot = 10 + <ternary slot>`. Its
            # slot is derived from the arms below (the one slot both wrote), and
            # the arithmetic instruction that reads it runs normally. Restricted
            # to arithmetic and comparison merges: a diamond that produces a
            # handle or a short-circuit bool is an ordinary branch, or belongs
            # to `_begin_bool_merge`, and folding it as a value ternary put a
            # `bool` where a handle, float or double was expected.
            off = None
        else:
            return False

        def simulate(lo, hi):
            child = copy.copy(self)
            child.stack = list(self.stack)
            child.temps = dict(self.temps)
            child.events = []
            child.declared = set(self.declared)
            child.consumed_temps = set(self.consumed_temps)
            child.list_values = {off: dict(values) for off, values in self.list_values.items()}
            child.list_sizes = dict(self.list_sizes)
            child.list_types = {off: dict(types) for off, types in self.list_types.items()}
            child.skip_indexes = set()
            child.bool_merges = []
            child.pending_value_call = None
            child.cmp_pair = None
            for idx in range(lo, hi):
                op = self.instrs[idx]
                if op.name in JUMP_OPS or op.name in ("JMP", "RET", "JMPP"):
                    return None
                child.k = idx
                child.step(op)
                if child.events:
                    return None
            if off is not None and off not in child.temps:
                return None
            return child

        yes, no = simulate(self.k + 1, term), simulate(else_idx, merge_idx)
        if yes is None or no is None or len(yes.stack) != len(no.stack):
            return False
        if stack_merge and (len(yes.stack) != len(self.stack) + 1
                            or yes.stack[:-1] != self.stack or no.stack[:-1] != self.stack):
            return False
        if off is None and not stack_merge:
            # Both arms must write exactly one common temporary -- that is the
            # ternary's value slot; the instruction after the merge reads it.
            def written(child):
                return {o for o in child.temps if o > 0 and
                        (o not in self.temps or child.temps[o] is not self.temps[o])}
            common = written(yes) & written(no)
            if len(common) != 1:
                return False
            off = common.pop()
            if self.is_named(off):
                return False
        condition = _negate_cond(self._taken_condition(ins))
        self.temps.update(no.temps)
        yes_value = yes.stack[-1] if stack_merge else yes.temps[off]
        no_value = no.stack[-1] if stack_merge else no.temps[off]
        a, b = yes_value.text, no_value.text
        def boolean(text):
            return text in ("true", "false") or text.startswith("!") or any(f" {op} " in text for op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"))
        yes_bool = boolean(a) or bool(yes_value.data_type and yes_value.data_type.format() == "bool")
        no_bool = boolean(b) or bool(no_value.data_type and no_value.data_type.format() == "bool")
        if yes_bool and b in ("0", "1"):
            b = "true" if b == "1" else "false"
        if no_bool and a in ("0", "1"):
            a = "true" if a == "1" else "false"
        value = Atom("call", f"({condition} ? {a} : {b})", ternary=(condition, yes_value, no_value))
        self.stack = no.stack
        if stack_merge:
            value.is_ptr = yes_value.is_ptr and no_value.is_ptr
            value.data_type = yes_value.data_type
            self.stack[-1] = value
        else:
            self.consumed_temps.discard(off)
            self.temps[off] = value
        self.pending_value_call = None
        self.skip_indexes.update(range(self.k + 1, merge_idx))
        return True


# --------------------------------------------------------------------------
# structured control flow
# --------------------------------------------------------------------------

class LoopCtx:
    """Enclosing-loop info used to synthesize break/continue."""

    __slots__ = ("head", "cond_lo", "cond_hi", "exit")

    def __init__(self, head: int, cond_lo: int, cond_hi: int, exit_pos: int):
        self.head = head          # dword pos of the loop body top
        self.cond_lo = cond_lo    # first pos of the condition block
        self.cond_hi = cond_hi    # pos of the condition branch (the latch)
        self.exit = exit_pos      # first pos AFTER the loop

    def is_continue(self, target: int) -> bool:
        return self.cond_lo <= target <= self.cond_hi

    def is_break(self, target: int) -> bool:
        return target >= self.exit


class SwitchCtx:
    def __init__(self, join, parent):
        self.join, self.parent = join, parent

    @property
    def exit(self):
        """Where a `break` out of the switch lands, named as a loop names it.

        The structurer passes whichever construct encloses a branch, so a
        branch inside a switch is handed this object where a loop would
        otherwise be, and asked for `.exit`. Without it, any conditional
        branch inside a switch raised AttributeError and the whole body came
        out as a decompiler error (`set_state` in Psycho Strike).
        """
        return self.join

    def is_break(self, target):
        return target == self.join

    def is_continue(self, target):
        return self.parent is not None and self.parent.is_continue(target)


def _recover_plain_scopes(events, function, classes):
    """Restore saved straight-line object scopes only when bindings stay inside.

    Crossing branches, returns, hoisted handles and reused bindings are left to
    the control-flow recovery rather than assuming a lexical lifetime.
    """
    class_types = {name for cls in classes for name in (cls.name, cls.format_name())}
    stack, regions = [], []
    for position, offset, option in function.obj_variable_info:
        if option == 2:
            stack.append(position)
        elif option == 3 and stack:
            start = stack.pop()
            inside = [event for event in events if start <= event.pos < position]
            if not inside or any(event.kind != "stmt" or
                                 event.data[1].lstrip().startswith(("return", "break", "continue", "goto"))
                                 for event in inside):
                continue
            names = []
            for event in inside:
                typename, text = event.data
                if typename in class_types:
                    match = re.match(r"([A-Za-z_][A-Za-z_0-9]*)\s*[=(;]", text)
                    if match:
                        names.append(match.group(1))
            if not names:
                continue
            outside = [event for event in events if not start <= event.pos < position]
            if any(re.search(r"\b" + re.escape(name) + r"\b", str(event.data))
                   for name in names for event in outside):
                continue
            regions.append((start, position))
    return sorted(regions, key=lambda region: (region[0], -region[1]))


class Structurer:
    """Converts flat events (stmts, branches, jumps) into indented source.

    AngelScript's compiler rotates while/for loops: an unconditional JMP to
    the condition block opens the loop, the body precedes the condition, and
    a backward conditional branch (the latch) closes it.  If/else uses a
    forward conditional branch to the else block plus an unconditional JMP
    terminating the then block; a then-block terminator that leaves the
    enclosing loop is really a break/continue, and absorbing the statements
    after the merge into the else is then semantics-preserving (the then
    path can never reach them).
    """

    def __init__(self, events: list[Event], function: Function | None = None, scope_regions=()):
        self.ev = [e for e in events if e.kind != "nop"]
        self.pos_index = {}
        for index, event in enumerate(self.ev):
            self.pos_index.setdefault(event.pos, index)
        self.scope_regions = list(scope_regions)
        self.handled_scopes = set()
        self.out: list[tuple[int, str]] = []      # (indent, line)
        self.done = [False] * len(self.ev)
        self.try_regions = []
        self.handled_tries = set()
        self.handled_plain_loops = set()
        self.handled_do_loops = set()
        if function is not None:
            for start, catch, _ in function.try_catch_info:
                preceding = [i for i in function.bytecode if start <= i.pos < catch and i.name not in SKIP_OPS]
                if preceding and preceding[-1].name == "JMP":
                    join = _jump_target(preceding[-1])
                    if join >= catch:
                        self.try_regions.append((start, catch, join))

    def render(self, base_indent: int = 0) -> list[str]:
        self._block(base_indent, 0, len(self.ev), None)
        return [ind * "    " + line for ind, line in self.out]

    def _next_index(self, pos: int) -> int:
        """Index of the first event at or after dword position `pos`.

        The miss is cached as well as the hit. Rescanning every event on every
        miss is quadratic in the body, which is invisible on a normal function
        and not on a large one: it was the single biggest cost in a
        20,000-instruction body, and Manamon 2 has one of 68,692.
        """
        idx = self.pos_index.get(pos)
        if idx is not None:
            return idx
        found = len(self.ev)
        for i, e in enumerate(self.ev):
            if e.pos >= pos:
                found = i
                break
        self.pos_index[pos] = found
        return found

    # -- loop detection -----------------------------------------------------

    def _find_latch(self, i: int, cond_pos: int, end: int) -> tuple[int, int] | None:
        """Rotated-loop signature for the forward JMP at index i targeting
        cond_pos: a backward branch at some L whose target is at/below the
        JMP, with no statement events between the condition block and the
        latch (statements there would mean this is an if/else merge block,
        not a loop condition)."""
        for j in range(i + 1, end):
            e = self.ev[j]
            if (e.kind == "branch" and not self.done[j]
                    and self.ev[i].pos < e.data[1] <= cond_pos
                    and e.pos >= cond_pos):
                c_idx = self._next_index(cond_pos)
                for k in range(c_idx, j):
                    if self.ev[k].kind != "stmt" or self.done[k]:
                        continue
                    # A statement in the condition block usually means this is
                    # an if/else merge rather than a loop condition. But a
                    # pre-tested loop re-evaluates its condition every
                    # iteration, and the compiler materialises what that
                    # condition reads: `for (i = 0; i < bag[n].items.length();
                    # i++)` emits `@handle = bag;` there. A plain assignment
                    # with no call in it is that materialisation; anything
                    # that calls something is not, and still rules the loop
                    # out.
                    text = self.ev[k].data[1]
                    if "(" in text or not re.match(r"@?[\w.\[\]]+ = ", text):
                        return None
                return (j, e.data[1])
        return None

    # -- block structuring ---------------------------------------------------

    def _block(self, indent: int, start: int, end: int,
               loop: LoopCtx | None) -> None:
        """Emit events[start:end] with structured control flow."""
        # do-while: the slice ends with a backward branch whose target lies
        # inside the slice (no entry JMP precedes a do-while)
        if end - 1 > start:
            e = self.ev[end - 1]
            if (e.kind == "branch" and not self.done[end - 1]
                    and e.data[1] <= e.pos):
                t_idx = self._next_index(e.data[1])
                if start <= t_idx < end - 1:
                    # skip the do-while reading when a forward jump targets
                    # the condition: that is a rotated while/for loop
                    rotated = False
                    for q in range(start, end - 1):
                        qe = self.ev[q]
                        if (qe.kind == "jump" and not self.done[q]
                                and qe.pos < qe.data <= e.pos):
                            rotated = True
                            break
                    if not rotated:
                        if start < t_idx:
                            self._block(indent, start, t_idx, loop)
                        self.done[end - 1] = True
                        self.out.append((indent, "do {"))
                        self._block(indent + 1, t_idx, end - 1,
                                    LoopCtx(e.data[1], e.pos, e.pos, e.pos + 2))
                        # `_condition`, not the raw text: this site emitted
                        # `} while (local_4 - local_1) < 1;` on Crazy Party.
                        self.out.append((indent, f"}} while {_condition(e.data[0])};"))
                        return

        i = start
        while i < end:
            if self.done[i]:
                i += 1
                continue
            e = self.ev[i]
            scope = next((region for region in self.scope_regions
                          if region not in self.handled_scopes
                          and self._next_index(region[0]) == i
                          and i < self._next_index(region[1]) <= end), None)
            if scope is not None:
                self.handled_scopes.add(scope)
                scope_end = self._next_index(scope[1])
                self.out.append((indent, "{"))
                self._block(indent + 1, i, scope_end, loop)
                self.out.append((indent, "}"))
                i = scope_end
                continue
            region = next((r for r in self.try_regions if r not in self.handled_tries
                           and self._next_index(r[0]) == i
                           and self._next_index(r[2]) <= end), None)
            if region is not None:
                self.handled_tries.add(region)
                catch_idx = self._next_index(region[1])
                join_idx = self._next_index(region[2])
                try_end = catch_idx
                if try_end > i and self.ev[try_end - 1].kind == "jump" and self.ev[try_end - 1].data == region[2]:
                    try_end -= 1
                    self.done[try_end] = True
                self.out.append((indent, "try {"))
                self._block(indent + 1, i, try_end, loop)
                self.out.append((indent, "} catch {"))
                self._block(indent + 1, catch_idx, join_idx, loop)
                self.out.append((indent, "}"))
                i = join_idx
                continue
            do_latches = [j for j in range(i + 1, end)
                          if not self.done[j] and self.ev[j].kind == "branch"
                          and self.ev[j].data[1] <= self.ev[j].pos
                          and self._next_index(self.ev[j].data[1]) == i]
            if do_latches and i not in self.handled_do_loops:
                tail = do_latches[-1]
                lat = self.ev[tail]
                head = lat.data[1]
                rotated = any(ev.kind == "jump" and ev.pos < head
                              and head < ev.data <= lat.pos for ev in self.ev[:i])
                if not rotated:
                    self.handled_do_loops.add(i)
                    self.done[tail] = True
                    condition_pos = min([lat.pos] + [ev.data for ev in self.ev[i:tail]
                                         if ev.kind == "jump" and ev.pos < ev.data <= lat.pos
                                         and self._next_index(ev.data) == tail])
                    self.out.append((indent, "do {"))
                    self._block(indent + 1, i, tail,
                                LoopCtx(head, condition_pos, lat.pos, lat.pos + 2))
                    self.out.append((indent, f"}} while {_condition(lat.data[0])};"))
                    i = tail + 1
                    continue
            plain_latches = [j for j in range(i + 1, end)
                             if not self.done[j] and self.ev[j].kind == "jump"
                             and self.ev[j].data <= self.ev[j].pos
                             and self._next_index(self.ev[j].data) == i]
            if plain_latches and i not in self.handled_plain_loops:
                tail = plain_latches[-1]
                self.handled_plain_loops.add(i)
                self.done[tail] = True
                head = self.ev[tail].data
                self.out.append((indent, "while (true) {"))
                self._block(indent + 1, i, tail,
                            LoopCtx(head, head, self.ev[i].pos, self.ev[tail].pos + 2))
                self.out.append((indent, "}"))
                i = tail + 1
                continue
            if e.kind == "switch":
                selector, cases, default, join = e.data
                self.done[i] = True
                labels = {}
                for value, target in cases:
                    labels.setdefault(target, []).append(f"case {value}:")
                labels.setdefault(default, []).append("default:")
                positions = sorted(labels)
                # Render the arms first: AngelScript requires `default` last,
                # and whether it already is only becomes answerable once each
                # arm's statements exist. See `_default_last`.
                arms = []
                for index, target in enumerate(positions):
                    boundary = positions[index + 1] if index + 1 < len(positions) else join
                    mark = len(self.out)
                    self._block(indent + 2, self._next_index(target),
                                self._next_index(boundary), SwitchCtx(join, loop))
                    arms.append((labels[target], self.out[mark:]))
                    del self.out[mark:]
                self.out.append((indent, f"switch ({selector}) {{"))
                for names, lines in _default_last(arms):
                    for label in names:
                        self.out.append((indent + 1, label))
                    start = len(self.out)
                    self.out.extend(lines)
                    # A declaration directly under `case` is "Variables cannot
                    # be declared in switch cases, except inside statement
                    # blocks". An arm's declarations belong to that arm, and a
                    # block around them changes nothing else -- a fallthrough
                    # still falls through to the next label.
                    if any(DECL_RE.match(text) for _, text in self.out[start:]):
                        self.out.insert(start, (indent + 1, "{"))
                        self.out.append((indent + 1, "}"))
                self.out.append((indent, "}"))
                i = self._next_index(join)
                continue
            if e.kind == "stmt":
                mods, text = e.data
                self.out.append((indent, mods + " " + text if mods else text))
                self.done[i] = True
                i += 1
                continue
            if e.kind == "jump":
                self.done[i] = True
                t = e.data
                if self._next_index(t) == i + 1:
                    # Serialized cleanup/label instructions can separate a
                    # jump from the next source event. No source action is
                    # skipped, so the jump is simply a fallthrough.
                    i += 1
                    continue
                if loop and loop.is_break(t):
                    self.out.append((indent, "break;"))
                elif loop and loop.is_continue(t):
                    self.out.append((indent, "continue;"))
                else:
                    latch = self._find_latch(i, t, end)
                    if latch is not None:
                        l_idx, head = latch
                        lat = self.ev[l_idx]
                        self.done[l_idx] = True
                        body_end = l_idx
                        continue_pos = t
                        update = self._next_index(t) - 1
                        if (i < update < l_idx and self.ev[update].kind == "stmt"
                                and re.fullmatch(r"[A-Za-z_]\w*(?:\+\+|--);", self.ev[update].data[1])
                                and any(ev.kind == "jump" and ev.data < t
                                        and self._next_index(ev.data) == update
                                        for ev in self.ev[i + 1:update])
                                # ...and nothing jumps straight to the
                                # condition, past the update. Such a jump is a
                                # `continue` in a loop whose increment is part
                                # of the body; hoisting the increment into a
                                # `for` header makes it run on that path too,
                                # which is a behaviour change -- and the jump
                                # itself then has no form to be written in, so
                                # it came out as the one `goto` left in
                                # Paladin (`storyline_scroll`).
                                and not any(ev.kind == "jump" and ev.data == t
                                            for ev in self.ev[i + 1:l_idx])):
                            # A for-loop continue lands on its update, before
                            # the condition. Move that update into the header
                            # so source continue still executes it exactly once.
                            increment = self.ev[update].data[1][:-1]
                            self.out.append((indent, f"for (; {_condition(lat.data[0])[1:-1]}; {increment}) {{"))
                            self.done[update] = True
                            body_end = update
                            continue_pos = min(ev.data for ev in self.ev[i + 1:update]
                                               if ev.kind == "jump" and ev.data < t
                                               and self._next_index(ev.data) == update)
                        else:
                            self.out.append((indent, f"while {_condition(lat.data[0])} {{"))
                        ctx = LoopCtx(head, continue_pos, lat.pos, lat.pos + 2)
                        self._block(indent + 1, i + 1, body_end, ctx)
                        self.out.append((indent, "}"))
                        i = l_idx + 1
                        continue
                    self.out.append((indent, f"goto L{t:04x};"))
                i += 1
                continue
            if e.kind == "label":
                i += 1
                continue
            if e.kind != "branch":
                i += 1
                continue

            # ---- conditional branch: if / if-else ---------------------------
            self.done[i] = True
            cond, target = e.data
            t_idx = self._next_index(target)
            if loop and (loop.is_continue(target) or target == loop.exit):
                keyword = "continue" if loop.is_continue(target) else "break"
                self.out.append((indent, f"if {_condition(_negate_cond(cond))} {{"))
                self.out.append((indent + 1, f"{keyword};"))
                self.out.append((indent, "}"))
                i += 1
                continue
            if t_idx <= i:              # backward latch with no entry JMP
                if t_idx == i:
                    # The back edge resolves to this branch itself, so no
                    # *event* lies between the target and here: the loop body
                    # folded entirely into the condition. `do { y =
                    # random(0, h - 1); } while (absolute(c - y) < 3);` comes
                    # through as one expression doing the work and one branch
                    # repeating it, which an empty-bodied loop says exactly:
                    # the condition is re-evaluated per iteration either way.
                    # 15 of Crazy Party's 17 gotos are this, almost all of
                    # them a `placeZone` picking a spot that is far enough
                    # from somewhere, and a `goto` does not compile at all.
                    self.out.append((indent, f"while {_condition(cond)} {{"))
                    self.out.append((indent, "}"))
                else:
                    self.out.append((indent, f"goto L{target:04x};"))
                i += 1
                continue

            # Conventional head-tested loop: condition branches to the exit,
            # while the body ends with an unconditional back edge.
            back = None
            for j in range(t_idx - 1, i, -1):
                ej = self.ev[j]
                if (ej.kind == "jump" and not self.done[j] and ej.data <= e.pos
                        and not (loop and loop.is_continue(ej.data))):
                    back = j
                    break
            if back is not None:
                self.out.append((indent, f"while {_condition(cond)} {{"))
                self.done[back] = True
                self._block(indent + 1, i + 1, back,
                            LoopCtx(self.ev[back].data, self.ev[back].data, e.pos, target))
                self.out.append((indent, "}"))
                i = t_idx
                continue

            # The compiler places the then/else separator at the tail of
            # the then slice. Earlier jumps can be nested breaks/continues.
            term = None
            for j in range(t_idx - 1, i, -1):
                ej = self.ev[j]
                if ej.kind == "jump" and not self.done[j] and ej.data > target:
                    term = j
                break

            if term is None:            # plain if (then falls into the merge)
                self.out.append((indent, f"if {_condition(cond)} {{"))
                self._block(indent + 1, i + 1, t_idx, loop)
                self.out.append((indent, "}"))
                i = t_idx
                continue

            m = self.ev[term].data
            if loop and (loop.is_break(m) or loop.is_continue(m)):
                # The terminator may belong to a nested conditional. Keep
                # every path in the then slice; only paths that actually
                # execute the jump leave the loop.
                self.out.append((indent, f"if {_condition(cond)} {{"))
                self._block(indent + 1, i + 1, t_idx, loop)
                self.out.append((indent, "}"))
                i = t_idx
                continue

            # normal if/else: the terminator jumps past the else block
            m_idx = self._next_index(m)
            self.out.append((indent, f"if {_condition(cond)} {{"))
            self._block(indent + 1, i + 1, term, loop)
            self.out.append((indent, "} else {"))
            self._block(indent + 1, t_idx, m_idx, loop)
            self.out.append((indent, "}"))
            i = m_idx


# --------------------------------------------------------------------------
# module rendering
# --------------------------------------------------------------------------

def _encloses(s):
    """True if s is `(...)` where the first paren matches the last -- one pair
    enclosing the whole expression, so removing it changes nothing. String
    literals are skipped so a paren inside one never counts."""
    if len(s) < 2 or s[0] != "(" or s[-1] != ")":
        return False
    depth = 0
    i = 0
    while i < len(s):
        c = s[i]
        if c == '"' or c == "'":
            i += 1
            while i < len(s) and s[i] != c:
                i += 2 if s[i] == "\\" else 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and i != len(s) - 1:
                return False
        i += 1
    return depth == 0


def _strip(s):
    return s[1:-1] if _encloses(s) else s


_RET = re.compile(r"^(\s*return )(.+)(;)$")
_HEAD = re.compile(r"^(\s*(?:\} )?(?:if|while) )\((.+)\)( \{| ?;)$")
_FOR = re.compile(r"^(\s*for \(.*?; )(.+?)(; .*\) \{)$")


def _drop_redundant_parens(lines):
    """Drop one fully-enclosing paren pair from a return value or a loop/branch
    condition -- `return (x);` -> `return x;`, `if ((a)) {` -> `if (a) {`."""
    out = []
    for line in lines:
        m = _RET.match(line)
        if m:
            out.append(m.group(1) + _strip(m.group(2)) + m.group(3))
            continue
        m = _HEAD.match(line)
        if m:
            out.append(m.group(1) + "(" + _strip(m.group(2)) + ")" + m.group(3))
            continue
        m = _FOR.match(line)
        if m:
            out.append(m.group(1) + _strip(m.group(2)) + m.group(3))
            continue
        out.append(line)
    return out


_COMPOUND = re.compile(r"^(\s*)([\w.\[\]]+) = \((.+)\);$")


def _use_compound_assignment(lines):
    """`x = (x + y);` -> `x += y;`, and `x = (x + 1);` -> `x++;`.

    Only for a simple lvalue with no call in it (so the target is not evaluated
    for its side effects), and only when the right-hand side begins with exactly
    that lvalue and a binary operator -- so the value is unchanged.
    """
    out = []
    for line in lines:
        m = _COMPOUND.match(line)
        if m and "(" not in m.group(2):
            indent, lhs, expr = m.groups()
            em = re.match(r"^%s (\+|-|\*|/|%%|&|\||\^|<<|>>>?) (.+)$"
                          % re.escape(lhs), expr)
            if em:
                op, rest = em.group(1), em.group(2)
                if rest == "1" and op in ("+", "-"):
                    out.append("%s%s%s;" % (indent, lhs, op * 2))
                    continue
                out.append("%s%s %s= %s;" % (indent, lhs, op, rest))
                continue
        out.append(line)
    return out


_FOR_WHILE = re.compile(r"while (\(.+\)) \{$")
_FOR_INIT = re.compile(r"((?:[\w:<>@\[\], ]+? )?([A-Za-z_]\w*) = .+);$")


def _reconstruct_for_loops(lines: list[str]) -> list[str]:
    """`init; while (cond) { body; incr; }` -> `for (init; cond; incr) { body; }`.

    A cosmetic, behaviour-preserving rewrite, applied only where it is safe: the
    loop must contain no `continue` (which skips the increment in a while but
    runs it in a for), the line before the while must assign the variable the
    condition tests, and the loop's last statement must increment that same
    variable. The matching close brace is found by indentation, so `{}` inside
    an initializer never confuses it.
    """
    out = list(lines)
    i = 0
    while i < len(out):
        m = _FOR_WHILE.match(out[i].strip())
        if not m or i == 0:
            i += 1
            continue
        cond = m.group(1)
        indent = len(out[i]) - len(out[i].lstrip())
        pad = " " * indent
        init_line = out[i - 1]
        im = _FOR_INIT.match(init_line.strip())
        if not im or len(init_line) - len(init_line.lstrip()) != indent:
            i += 1
            continue
        var = im.group(2)
        if not re.search(r"(?<![\w.])" + re.escape(var) + r"\b", cond):
            i += 1
            continue
        close = next((j for j in range(i + 1, len(out)) if out[j] == pad + "}"), None)
        if close is None or close == i + 1:
            i += 1
            continue
        body = out[i + 1:close]
        if any(re.search(r"(?<!\w)continue\s*;", b) for b in body):
            i += 1
            continue
        incm = re.match(r"(" + re.escape(var) + r"(?:\+\+|--)|"
                        + re.escape(var) + r" [-+*/%|&^]?= .+);$", body[-1].strip())
        if not incm:
            i += 1
            continue
        for_line = pad + "for (%s; %s; %s) {" % (im.group(1), cond, incm.group(1))
        out = out[:i - 1] + [for_line] + body[:-1] + out[close:]
        i += 1
    return out


class ModuleDecompiler:
    def __init__(self, module: Module, comments: bool = False):
        self.m = module
        self.comments = comments
        self.lines: list[str] = []

    def emit(self, s: str = "") -> None:
        self.lines.append(s)

    def _wrap_namespace(self, start, namespace):
        if namespace:
            self.lines[start:] = namespace_block("\n".join(self.lines[start:]), namespace).splitlines()

    def render(self) -> str:
        m = self.m
        info = getattr(m, "nvgt_info", None)
        if info is not None:
            for plugin in info.plugins:
                self.emit(f"#pragma plugin {plugin}")
            for system, namespace in info.namespaces:
                self.emit(f"#pragma namespace {system} {namespace}")
            if info.no_auto_chdir:
                self.emit("#pragma no_auto_chdir")
            self.emit()
        self.emit("// Decompiled from NVGT/AngelScript bytecode.")
        self.emit("// Comments and original formatting are not recoverable;")
        self.emit("// Names are preserved where available; some temporaries are synthesized.")
        self.emit()

        for e in m.enums:
            start = len(self.lines)
            # `shared` is part of the declaration: shared code may only use
            # shared types, so dropping it made every shared class using this
            # enum fail ("Shared code cannot use non-shared type").
            modifiers = ("external " if e.is_external else "") + ("shared " if e.is_shared else "")
            self.emit(f"{modifiers}enum {e.name} {{")
            for n, v in e.enum_values:
                self.emit(f"    {n} = {v},")
            self.emit("}")
            self._wrap_namespace(start, e.namespace_)
            self.emit()
        for t in m.typedefs:
            start = len(self.lines)
            self.emit(f"typedef {t.typedef_target.format()} {t.name};")
            self._wrap_namespace(start, t.namespace_)
            self.emit()

        for f in m.funcdefs:
            if f.parent_class is None:
                self.emit(namespace_block(funcdef_declaration(f), f.namespace_))
        if m.funcdefs:
            self.emit()

        for imported in m.imported_functions:
            function = imported.signature
            declaration = "import " + function_signature(function, include_modifiers=False)
            declaration += f' from "{_esc(imported.module)}";'
            self.emit(namespace_block(declaration, function.namespace_))
        if m.imported_functions:
            self.emit()
        for c in m.classes:
            self._render_class(c)
        self._member_funcs = {id(f) for c in m.classes
                              for f in (c.methods + c.constructors + c.factories
                                        + ([c.destructor] if c.destructor else []))}
        self._render_globals()
        seen: set[str] = set()
        for f in m.script_functions:
            if f.object_type is not None or "$" in f.name:
                continue      # class methods render with their class
            if f.signature(False) in seen:
                continue
            seen.add(f.signature(False))
            self._render_function(f)
            self.emit()
        for f in m.global_functions:
            if f.signature(False) in seen or f.object_type is not None:
                continue
            seen.add(f.signature(False))
            self._render_function(f)
            self.emit()
        return "\n".join(self.lines).rstrip() + "\n"

    def _render_class(self, c: TypeInfo) -> None:
        start = len(self.lines)
        self.emit(class_header(c) + " {")
        for f in self.m.funcdefs:
            if f.parent_class is c:
                self.emit("    " + funcdef_declaration(f))
        sizes = _member_array_sizes(c)
        for pname, dt, flags in c.properties:
            if flags & 4:
                continue  # inherited properties are declared by the base
            # stored object members carry a spurious is_reference bit;
            # references are not storable, so the declaration never has &
            decl = dt.format()
            if decl.endswith("&"):
                decl = decl[:-1].rstrip()
            visibility = "private " if flags & 1 else "protected " if flags & 2 else ""
            # An array member declared with a length is created with it by the
            # constructor's generated prologue, which is dropped: the length
            # only survives on the declaration. Without it `input_recorder`'s
            # constructor wrote past the end of two members, and the engine
            # said only "Failed to initialize global variable 'recorder'".
            length = sizes.get(pname)
            suffix = f"({length})" if length is not None else ""
            self.emit(f"    {visibility}{decl} {pname}{suffix};")
        if c.properties:
            self.emit()
        seen_ctors: set[str] = set()
        for f in c.constructors:
            key = f.signature(False)
            if key in seen_ctors:
                continue
            seen_ctors.add(key)
            pnames = [name for _, name in _parameter_layout(f)]
            self.emit("    " + function_signature(f, pnames) + " {")
            for line in self._body(f, 2):
                self.emit(line)
            self.emit("    }")
            self.emit()
        seen_methods: set[str] = set()
        for f in c.methods:
            if "$" in f.name:
                continue
            # A class's method list is ALL its virtual methods, inherited ones
            # included, as asFUNC_VIRTUAL stubs owned by whichever class first
            # declared them; the bodies live in the VFT, each owned by the
            # class that implements it. Pair them by name, parameters and
            # const-ness -- NOT by owner-qualified signature, which never
            # matches an override (`ini_settings_helper::raw_dump` vs the stub
            # `settings_helper::raw_dump`): the override's body was lost to
            # `// (no code)` while inherited bodies were copied into the
            # derived class, touching the base's private members.
            body_f = f
            if not body_f.bytecode:
                impl = next((vf for vf in c.vft if vf.bytecode
                             and _method_key(vf) == _method_key(f)), None)
                if impl is not None:
                    body_f = impl
            owner = body_f.object_type
            if (not c.is_interface and owner is not None and owner is not c
                    and owner.format_name() != c.format_name()):
                continue            # inherited, not overridden: the base declares it
            key = body_f.signature(False)
            if key in seen_methods:
                continue
            seen_methods.add(key)
            if c.is_interface:
                self.emit(self._signature(body_f, indent=1) + ";")
                continue
            self.emit(self._signature(body_f, indent=1))
            self.emit("    {")
            for line in self._body(body_f, 2):
                self.emit(line)
            self.emit("    }")
            self.emit()
        if c.destructor is not None and not c.is_interface:
            self.emit(self._signature(c.destructor, indent=1))
            self.emit("    {")
            for line in self._body(c.destructor, 2):
                self.emit(line)
            self.emit("    }")
            self.emit()
        self.emit("}")
        self._wrap_namespace(start, c.namespace_)
        self.emit()

    def _signature(self, f: Function, indent: int = 0) -> str:
        pnames = [name for _, name in _parameter_layout(f)]
        return "    " * indent + function_signature(f, pnames)

    def _body(self, f: Function, indent: int) -> list[str]:
        if not f.bytecode:
            return [f"{'    ' * indent}// (no code)"]
        try:
            fd = FuncDecompiler(self.m, f, self.comments)
            initial_names = dict(fd.var_names)
            ev = fd.run()
            # A mutable object may first be recognized at a method call, after
            # its constructor or writes in earlier branches. Simulate again
            # with the discovered lvalues so those earlier writes are retained.
            # Repeat while each pass finds more: a slot folded into another
            # slot's expression only becomes visible once that one is a
            # variable, so one pass is not a fixed point.
            # A value folded into more than one read is a call run more than
            # once, and the fix has to land *before* the first read -- so it
            # takes a second simulation that already knows. Paladin's
            # `file_menu` ran its menu four times where the source ran it once
            # and compared the result three ways; the menu came back after
            # every selection.
            duplicates = {key for key, n in fd.fold_reads.items()
                          if n >= DUPLICATE_FOLDS}
            rounds = 0
            while rounds < 4 and (fd.var_names != initial_names or duplicates):
                rounds += 1
                discovered, types = dict(fd.var_names), dict(fd.var_types)
                forced = set(fd.forced_slots)
                carried = set(fd.duplicate_binds) | duplicates
                fd = FuncDecompiler(self.m, f, self.comments)
                initial_names = dict(fd.var_names)
                fd.var_names.update(discovered)
                fd.var_types.update(types)
                fd.forced_slots.update(forced)
                fd.duplicate_binds = carried
                ev = fd.run()
                # Only genuinely new ones, or this never reaches a fixed point:
                # a promoted bind is no longer folded, so it stops being
                # counted, and re-adding it would loop.
                duplicates = {key for key, n in fd.fold_reads.items()
                              if n >= DUPLICATE_FOLDS and key not in carried}
            # Stripped metadata reuses scalar slots across sibling blocks.
            # Keep one declaration in the function and initialization at its
            # original position, rather than declaring in just the first arm.
            declarations = []
            hoisted_names: set[str] = set()

            def _is_scalar(dt):
                return (dt.obj_type is None or dt.obj_type.kind == "enum"
                        or dt.is_object_handle or dt.obj_type.name == "string")

            scalar_names = {fd.name_of(off) for off, dt in fd.var_types.items()
                            if off > 0 and fd.is_named(off) and _is_scalar(dt)}
            # A reused slot carries several debug variables at different scopes
            # (slot 2 is `int i` in one loop, then `int total`); var_names keeps
            # only the last, so a transient scalar name like a loop's `i` would
            # be missing here and its declaration left un-hoisted -- and a
            # second `i` on another slot then makes two `int i = 0;` at one
            # scope, "'i' is already declared". Take every scalar name.
            scalar_names |= {v.name for v in f.variables
                             if v.name and v.stack_offset > 0 and _is_scalar(v.type)}
            # A slot the simulation promoted to a variable is hoisted whatever
            # its type: it was promoted because it is read in more than one
            # place, and those places are not always one scope.
            scalar_names |= {fd.name_of(off) for off in fd.forced_slots}
            for event in ev:
                if event.kind != "stmt":
                    continue
                typename, text = event.data
                if not typename:
                    continue
                # Up to the first non-identifier character, so the
                # constructor form counts too: `string local_11("");` is a
                # declaration, and matching on the first *word* missed it --
                # it then stayed inside the block it was written in while
                # later statements in the enclosing one used it ("'local_11'
                # is not declared").
                match = re.match(r"[A-Za-z_][A-Za-z_0-9]*", text)
                name = match.group(0) if match else ""
                # A local this decompiler generates belongs to the function,
                # not to the block the call happened to be in.
                if name in scalar_names or GENERATED_LOCAL.match(name):
                    # One hoisted declaration per name: a slot declared in
                    # several sibling scopes shows up here once per scope.
                    # Hoisted WITHOUT its initialiser, so a `const` local
                    # would then be assigned: "Expression is not an l-value"
                    # (basic_character_controller's `const float idx = ...`).
                    decl = "    " * indent + f"{typename.removeprefix('const ')} {name};"
                    # One per NAME, not per text: two loops can each declare
                    # `i` -- one `uint`, one `int` -- and both hoisted is
                    # "'i' is already declared".
                    if name not in hoisted_names:
                        hoisted_names.add(name)
                        declarations.append(decl)
                    off = next((off for off in fd.var_names if fd.name_of(off) == name), None)
                    is_handle = off is not None and fd.var_types.get(off) and fd.var_types[off].is_object_handle
                    prefix = "@" if is_handle and text != name + ";" else ""
                    if text.startswith(name + "("):
                        # The constructor form has to become an assignment:
                        # with the declaration hoisted away, `local_11("");`
                        # on its own is a call to something that is not there.
                        bare = typename.removeprefix("const ").strip()
                        text = "%s = %s%s" % (name, bare, text[len(name):])
                    event.data = ("", "" if text == name + ";" else prefix + text)
            ev = [e for e in ev if e.kind != "stmt" or e.data != ("", "")]
            scopes = _recover_plain_scopes(ev, f, self.m.classes)
            st = Structurer(ev, f, scopes)
            body = _use_compound_assignment(declarations + st.render(indent))
            body = _declare_read_before_written(body, fd, indent)
            body = _drop_unreachable(body)
            return _drop_redundant_parens(_reconstruct_for_loops(body))
        except Exception as ex:               # decompilation must not crash
            return [f"{'    ' * indent}// [decompiler error: {ex!r}]"]

    def _render_function(self, f: Function) -> None:
        if id(f) in getattr(self, "_member_funcs", ()):  # rendered in its class
            return
        start = len(self.lines)
        self.emit(self._signature(f))
        self.emit("{")
        for line in self._body(f, 1):
            self.emit(line)
        self.emit("}")
        self._wrap_namespace(start, f.namespace_)

    def _render_globals(self) -> None:
        original = self.m
        try:
            start_index = 0
            while start_index < len(original.globals):
                namespace = original.globals[start_index].namespace_
                end = start_index + 1
                while end < len(original.globals) and original.globals[end].namespace_ == namespace:
                    end += 1
                self.m = copy.copy(original)
                self.m.globals = original.globals[start_index:end]
                start = len(self.lines)
                self._render_global_group(namespace, start_index)
                self._wrap_namespace(start, namespace)
                start_index = end
        finally:
            self.m = original

    def _render_global_group(self, namespace, start_index=0) -> None:
        m = self.m
        if not m.globals:
            return
        init_stmts: dict[str, list[str]] = {}
        for g in m.globals:
            if g.init_func is not None and g.init_func.bytecode:
                try:
                    fd = FuncDecompiler(m, g.init_func, False)
                    ev = fd.run()
                    st = Structurer(ev, g.init_func)
                    init_stmts[g.name] = st.render()
                except Exception:
                    init_stmts[g.name] = []
        helpers = []
        for index, g in enumerate(m.globals, start_index):
            list_expr = self._global_list_expr(g)
            if list_expr is not None:
                self.emit(f"{g.type.format()} {g.name} = {list_expr};")
                continue
            stmts = init_stmts.get(g.name) or []
            # fold the final assignment into the declaration
            decl = f"{g.type.format()} {g.name};"
            if len(stmts) == 1:
                last = stmts[-1].strip()
                qualified = (namespace + "::" if namespace else "") + g.name
                if last.startswith(f"{qualified} = "):
                    expr = last[len(qualified) + 3:-1] if last.endswith(";") \
                        else last[len(qualified) + 3:]
                    initialiser = _initialiser(g.type, expr)
                    decl = (f"{g.type.format()} {g.name};" if initialiser is None
                            else f"{g.type.format()} {g.name} = {initialiser};")
                    stmts = stmts[:-1]
            if stmts:
                qualified = (namespace + "::" if namespace else "") + g.name
                # Replace identifier tokens without changing string literals.
                pattern = re.compile(r'''("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|//[^\n]*|/\*[\s\S]*?\*/)|(?<![A-Za-z_0-9:])'''
                                     + re.escape(qualified) + r"\b")
                stmts = [pattern.sub(lambda match: match.group(0) if match.group(1) else g.name, stmt)
                         for stmt in stmts]
                # Executable initializer statements belong in a function;
                # emitting them at module scope is invalid AngelScript.
                helper = f"__nvgt_global_init_{index}"
                self.emit(f"{g.type.format()} {g.name} = {helper}();")
                local_type = copy.copy(g.type)
                local_type.is_readonly = False
                helpers.append((helper, local_type.format(), g.name, stmts))
            else:
                self.emit(decl)
        self.emit()
        for helper, typename, name, stmts in helpers:
            self.emit(f"{typename} {helper}() {{")
            self.emit(f"    {typename} {name};")
            for stmt in stmts:
                self.emit("    " + stmt)
            self.emit(f"    return {name};")
            self.emit("}")
            self.emit()

    @staticmethod
    def _global_list_expr(g) -> str | None:
        """Recover the initializer-list protocol used by AngelScript.

        The list buffer itself is VM bookkeeping. String arrays and the
        dictionary form used by NVGT's settings library can be expressed
        directly in source, preserving their values without leaking those
        low-level instructions into the output.
        """
        f = g.init_func
        if f is None or not any(i.name == "AllocMem" for i in f.bytecode):
            return None
        strings = [i.string_const for i in f.bytecode
                   if i.string_const is not None]
        size = next((i.qw_arg for i in f.bytecode
                     if i.name == "SetListSize"), None)
        typename = g.type.obj_type.name if g.type.obj_type else ""
        if typename == "array" and len(g.type.template_subtypes) == 1 \
                and g.type.template_subtypes[0].format().replace("const ", "") == "string" \
                and size == len(strings):
            return "{" + ", ".join(f'\"{_esc(s)}\"' for s in strings) + "}"
        if typename == "dictionary":
            funcs = [i.func_ref for i in f.bytecode if i.name == "FuncPtr"]
            if size == len(strings) == len(funcs) and all(funcs):
                entries = [f'{{\"{_esc(key)}\", @{fn.name}}}'
                           for key, fn in zip(strings, funcs)]
                return "{" + ", ".join(entries) + "}"
        return None


# --------------------------------------------------------------------------

def decompile_module(m: Module, comments: bool = False) -> str:
    return ModuleDecompiler(m, comments).render()


def load_stream(path: str, raw: bool = False) -> Module:
    data = Path(path).read_bytes()
    if not raw:
        data = unwrap_bytecode(data)
    return read_module(data)


def load_any(path: str) -> Module:
    """Load from anything: raw bytecode, ASBC-wrapped stream, or a packaged
    NVGT executable (delegates the payload to extract.py)."""
    data = Path(path).read_bytes()
    if data[:4] == b"ASBC":
        return load_stream(path, raw=False)
    if data[:2] == b"MZ" or data[:4] == b"\x7fELF":
        try:                      # installed as a package
            from . import extract
        except ImportError:       # run directly from a checkout
            import extract
        info, stream = extract.extract(Path(path))
        module = read_module(info.bytecode)
        module.nvgt_info = info
        return module
    return load_stream(path, raw=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--raw", action="store_true")
    parser.add_argument("--comments", action="store_true")
    parser.add_argument("--disasm", action="store_true")
    args = parser.parse_args()
    try:
        module = load_stream(args.input, raw=True) if args.raw else load_any(args.input)
        if args.disasm:
            try:                      # installed as a package
                from .disasm import Disassembler
            except ImportError:       # run directly from a checkout
                from disasm import Disassembler
            result = Disassembler(module).render()
        else:
            result = decompile_module(module, comments=args.comments)
        if args.output:
            if args.output.resolve() == Path(args.input).resolve():
                raise ValueError("output must differ from input")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(result, encoding="utf-8", newline="\n")
        else:
            sys.stdout.write(result)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Decompilation failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
