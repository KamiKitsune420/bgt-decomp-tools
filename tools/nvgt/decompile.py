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
            "SwapPtr", "JitEntry",
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


def _esc(s: str) -> str:
    """Encode source literals without losing binary bytes in saved strings."""
    escapes = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    result = []
    for character in s:
        value = ord(character)
        if character in escapes:
            result.append(escapes[character])
        elif 0xdc80 <= value <= 0xdcff:
            result.append(f"\\x{value - 0xdc00:02x}")
        elif value < 32 or value == 127:
            result.append(f"\\x{value:02x}")
        else:
            result.append(character)
    return "".join(result)


def _jump_target(ins: Instr) -> int:
    """Dword position a jump goes to (reader pre-computes jump_target from
    the instruction-number delta; fall back to the raw delta)."""
    if getattr(ins, "jump_target", None) is not None:
        return ins.jump_target
    return ins.pos + 2 + _s32(ins.dw_arg)


def _negate_cond(c: str) -> str:
    """Negate a comparison like (a <= b) -> (a > b); fall back to !(...)."""
    import re as _re
    if c in ("0", "false"):
        return "true"
    if c in ("1", "true"):
        return "false"
    if c.startswith("!(") and c.endswith(")"):
        return c[2:-1]
    m = _re.match(r"^\((.+) (<=|>=|<|>|==|!=) (.+)\)$", c)
    if m and all(part.count("(") == part.count(")") for part in (m.group(1), m.group(3))):
        a, op, b = m.groups()
        flip = {"<=": ">", ">=": "<", "<": ">=", ">": "<=",
                "==": "!=", "!=": "=="}
        return f"({a} {flip[op]} {b})"
    return f"!({c[1:-1]})" if c.startswith("(") and c.endswith(")") else f"!({c})"


def _condition(c: str) -> str:
    """AngelScript requires parentheses after if/while."""
    return c if c.startswith("(") and c.endswith(")") else f"({c})"


def _type_stack_size(dt: DataType) -> int:
    """AngelScript frame slots used by compiler parameters."""
    if dt.is_reference or dt.is_object_handle or dt.obj_type is not None:
        return 1
    return 2 if dt.format().replace("const ", "") in ("int64", "uint64", "double") else 1


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
            if off > 0 and 67 in tokens and tokens & {70, 77} and all(
                    t.obj_type is None and t.token_type in (67, 70, 77) for t in types):
                self.var_types[off] = DataType(token_type=70 if 70 in tokens else 77)
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
        for variable in fn.variables:
            off = variable.stack_offset
            if off <= 0:
                continue
            # Source locals from separate scopes can reuse a counter slot
            # before later locals appear. Repeated slots of the same type
            # don't mark the start of compiler scratch variables.
            repeated_local = prefix_types.get(off) == variable.type.format()
            if off < highest and not repeated_local:
                forced.update(prefix_types)
                break
            prefix_types[off] = variable.type.format()
            highest = max(highest, off)
        self.sparse_switches = {index: pattern for index in range(len(self.instrs))
                               if (pattern := self._sparse_switch_pattern(index)) is not None}
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
        rt = fn.return_type.format() if fn.return_type else "void"
        self.returns_value = rt not in ("", "void")
        self.return_slot = -1 if fn.object_type and _needs_out_ref(fn.return_type) else 0
        # output events
        self.events: list[Event] = []
        self.skip_indexes: set[int] = set()
        self.bool_merges: list[dict] = []
        self.pending_value_call: str | None = None
        self.pending_value_call_pos: int = 0
        self.consumed_temps: set[int] = set()
        self.list_values: dict[int, dict[int, Atom]] = {}
        self.list_sizes: dict[int, int] = {}
        self.list_types: dict[int, dict[int, DataType]] = {}
        self.object_branch_snapshots: dict[int, dict[int, Atom]] = {}

    # -- variable helpers ---------------------------------------------------

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
                self.consumed_temps.add(a.offset)
                return self.temps[a.offset]
            return self.var_atom(a.offset)
        if a.is_ptr:
            # pointer into an object (property, global): reading through it
            # yields the member itself as a value
            value = copy.copy(a)
            value.dw_size, value.is_ptr = 1, False
            return value
        return a

    def _bind(self, off: int, a: Atom) -> None:
        """Store a value into frame slot `off` (statement or temp alias)."""
        a = self._deref(a) if a.is_ptr else a
        if a.kind == "const" and off in self.var_types:
            a = self._normalize_arg(a, self.var_types[off])
        if off == self.return_slot and self.returns_value and off not in self.parameter_slots:
            if _needs_out_ref(self.fn.return_type):
                self.temps[off] = a
                return
        if self.is_named(off):
            self._emit_assign(off, a)
        else:
            self.temps[off] = a

    def _emit_declare(self, off: int) -> None:
        """Emit a bare declaration for a named variable (default-constructed)."""
        if off in self.declared:
            return
        self.declared.add(off)
        dt = self.var_types.get(off)
        tn = (dt.format() if dt else "").replace("&", "").strip()
        self.events.append(Event("stmt", self._pos(), (tn, f"{self.name_of(off)};")))

    def _emit_assign(self, off: int, a: Atom) -> None:
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
            self.events.append(Event("stmt", self._pos(), (tn, text)))
        else:
            self.events.append(Event("stmt", self._pos(), ("", f"{name} = {a.text};")))

    def _pos(self) -> int:
        return self.instrs[self.k].pos

    def _stmt(self, text: str) -> None:
        self.events.append(Event("stmt", self._pos(), ("", text)))

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
        while self.k < n:
            if self.k in self.skip_indexes:
                self.k += 1
                continue
            ins = self.instrs[self.k]
            # Linear simulation visits cleanup on a returning then-path before
            # the else-path. That cleanup cannot erase an object still alive
            # on the branch which jumps over it.
            for off, value in self.object_branch_snapshots.pop(ins.pos, {}).items():
                current = self.temps.get(off)
                if current and current.kind == "null":
                    self.temps[off] = value
            # Object lifetime metadata can precede the instruction consuming
            # its last value. FREE and explicit stores maintain aliases.
            self.step(ins)
            self.k += 1
        # Ignored non-void calls can be recognized only after later opcodes
        # overwrite their result. Keep their original location in the CFG.
        return sorted(self.events, key=lambda event: event.pos)

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
                value = Atom("call", f"({merge['first'].text} {merge['op']} {value.text})")
                self.temps[off] = value
            self.value_reg = value
            return
        if name in ("CpyRtoV4", "CpyRtoV8"):
            self._bind(_s16(ins.w_arg), self.value_reg)
            self.pending_value_call = None
            return
        if name in ("CpyVtoV4", "CpyVtoV8"):
            self._bind(_s16(ins.w_arg), self._slot_atom(_s16(ins.w_arg2)))
            return
        if name in ("SetV4", "SetV8", "SetV2", "SetV1"):
            if ins.string_const is not None:
                a = Atom("const", f'"{_esc(ins.string_const)}"', 2)
            else:
                off = _s16(ins.w_arg)
                v = ins.qw_arg if name == "SetV8" else _s32(ins.dw_arg)
                a = self._typed_constant(v, self.var_types.get(off), name == "SetV8")
            self._bind(_s16(ins.w_arg), a)
            return
        if name == "LdGRdR4":
            g = ins.global_name or "<?global>"
            self._bind(_s16(ins.w_arg), Atom("global", g))
            self.pending_global = g
            # the value register now holds &global (WRTV4 writes through it)
            self.value_reg = Atom("global", g, 1, is_ptr=True)
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
            # value register -> frame slot (the reverse of CpyVtoG4)
            self._bind(_s16(ins.w_arg), Atom("global", ins.global_name or "<?global>"))
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
            self.value_reg = Atom("global", g, 1, is_ptr=True)
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
            self.cmp_pair = (self._normalize_arg(self._slot_atom(_s16(ins.w_arg)), dt),
                             self._normalize_arg(self._slot_atom(_s16(ins.w_arg2)), dt))
            return
        if name == "CmpPtr":
            self._flush_pending_call()
            self.cmp_pair = (self._slot_atom(_s16(ins.w_arg)),
                             self._slot_atom(_s16(ins.w_arg2)))
            return
        if name in ("CMPIi", "CMPIi64", "CMPIu", "CMPIu64", "CMPIf", "CMPIf64"):
            self._flush_pending_call()
            off = _s16(ins.w_arg)
            self.cmp_pair = (self._slot_atom(off),
                             self._typed_constant(_s32(ins.dw_arg), _numeric_type(name)))
            return
        if name in ("EQi", "EQf", "EQu", "EQi64", "EQu64", "EQd", "EQPtr"):
            self.cmp_pair = (self._slot_atom(_s16(ins.w_arg)),
                             self._slot_atom(_s16(ins.w_arg2)))
            return
        if name in TEST_OPS:
            op = TEST_OPS[name]
            if self.cmp_pair is not None:
                a, b = self.cmp_pair
                self.cmp_pair = None
                self.value_reg = Atom("call", f"({a.text} {op} {b.text})", data_type=DataType(token_type=67))
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
            self._stmt("// switch/jump table")
            return

        # ---- stack ops ----------------------------------------------------
        if name == "LoadThisR":
            # PshVPtr 0 + ADDSi + PopRPtr fused: value register = &this.prop.
            # w_arg is the property index (resolved to a name by the reader).
            pname = self._short_prop(ins.prop_name, ins.w_arg)
            if self.fn.object_type is None:
                pname = f"{self._slot_atom(0).text}.{pname}"
            elif pname in self.var_names.values():
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
                if base == "this" and pname in self.var_names.values():
                    text = f"this.{pname}"
                self.stack[-1] = Atom("prop", text, 1, is_ptr=True,
                                       data_type=self.property_types.get(ins.prop_name))
            return
        if name in ("PSF", "PshVPtr", "VAR"):
            off = _s16(ins.w_arg)
            label = self.name_of(off)
            self.stack.append(Atom("ptr", label, 2, is_ptr=True, offset=off))
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
                self.temps[off] = Atom("null", "null", 2)
            return                       # end of a temp lifetime: no source
        if name in ("RefCpyV", "REFCPY"):
            self._refcpy(ins)
            return
        if name == "Cast":
            t = ins.type_ref.format_name() if ins.type_ref else f"type#{ins.dw_arg}"
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
                if _needs_out_ref(self.fn.return_type):
                    if self.return_slot in self.temps:
                        self._stmt(f"return {self.temps[self.return_slot].text};")
                elif self.fn.return_type.obj_type is not None and self.obj_reg is not None:
                    self._stmt(f"return {self.obj_reg.text};")
                elif self.value_reg.kind != "raw" and not self.value_reg.is_ptr:
                    value = self._normalize_arg(self.value_reg, self.fn.return_type)
                    self._stmt(f"return {value.text};")
                elif 0 in self.temps:
                    # value was copy-constructed into the hidden return slot
                    self._stmt(f"return {self.temps[0].text};")
                self.pending_value_call = None
            else:
                self._flush_pending_call()
            self.stack.clear()
            return

        self._stmt(f"// {name} (unhandled)")

    # -- helpers ------------------------------------------------------------

    def _slot_atom(self, off: int) -> Atom:
        """Value of a frame slot: temp alias if bound, else the variable."""
        if off in self.temps:
            return self.temps[off]
        return self.var_atom(off)

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
        return Atom("const", str(value), 2 if wide else 1, constant_bits=bits)

    def _normalize_arg(self, atom: Atom, dt: DataType) -> Atom:
        source = atom.data_type
        if (dt.is_object_handle and source and source.obj_type
                and any(source.obj_type is cls for cls in self.m.classes) and not source.is_object_handle
                and not atom.text.startswith("@")):
            return Atom(atom.kind, "@" + atom.text, data_type=dt)
        if dt.token_type == 67 and atom.ternary:
            condition, yes, no = atom.ternary
            yes = self._normalize_arg(yes, dt)
            no = self._normalize_arg(no, dt)
            return Atom("call", f"({condition} ? {yes.text} : {no.text})", data_type=dt)
        if dt.token_type == 67 and source and source.obj_type is None and source.token_type in (70, 77):
            return Atom("call", f"({atom.text} != 0)", data_type=dt)
        if atom.kind != "const":
            return atom
        if atom.constant_bits is not None:
            return self._typed_constant(atom.constant_bits, dt, _type_stack_size(dt) == 2)
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
                if a.is_ptr:
                    self.stack[idx] = self._deref(a)
                return
            acc += size

    def _refcpy(self, ins: Instr) -> None:
        if ins.name == "RefCpyV":
            # RefCpyV == PSF dest + REFCPY: source address stays on the
            # stack (the following ALLOC consumes it); peek, don't pop.
            src = self.stack[-1] if self.stack else Atom("raw", "<?>")
            self._bind(_s16(ins.w_arg), self._deref(src))
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
            self.value_reg = value

    # -- calls ----------------------------------------------------------------

    def _call(self, ins: Instr) -> None:
        self._flush_pending_call()
        fr = ins.func_ref
        if fr is not None and fr.name == "$dlgte":
            method = self.stack.pop() if self.stack else Atom("raw", "<?method>")
            owner = self._deref(self.stack.pop()) if self.stack else Atom("raw", "<?owner>")
            expression = f"{owner.text}.{method.text.lstrip('@')}"
            following = next((i for i in self.instrs[self.k + 1:] if i.name not in ("FREE", "SUSPEND")), None)
            dt = self.var_types.get(_s16(following.w_arg)) if following and following.name == "STOREOBJ" else None
            if dt and dt.obj_type:
                expression = f"{dt.obj_type.name}({expression})"
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
        for index in range(nparams):
            arg = self.stack.pop() if self.stack else Atom("raw", "<?>")
            dt = fr.param_types[index]
            output_type = dt
            if dt.token_type == 60 and dt.is_reference:
                # ?& parameters occupy a pointer plus a hidden TYPEID.
                typeid = self.stack.pop() if self.stack else None
                if typeid is not None and typeid.kind == "typeid" and typeid.data_type:
                    output_type = typeid.data_type
            direction = fr.in_out_flags[index] if index < len(fr.in_out_flags) else 0
            if direction & 2 and arg.is_ptr and arg.offset is not None and arg.offset > 0:
                off = arg.offset
                if not self.is_named(off):
                    value = self.temps.get(off)
                    local = f"__nvgt_out_{off}_{ins.pos}"
                    output_type = copy.copy(output_type)
                    output_type.is_reference = output_type.is_readonly = False
                    # Scratch slots are reused with different types later;
                    # give an output argument its own source-level lifetime.
                    if direction & 3 == 3 and value and value.kind != "raw":
                        value = self._normalize_arg(value, output_type)
                        self._stmt(f"{output_type.format()} {local} = {value.text};")
                    else:
                        self._stmt(f"{output_type.format()} {local};")
                    arg = Atom("var", local, data_type=output_type)
                    self.temps[off] = arg
                else:
                    arg = self.var_atom(off)
            args.append(arg)
        # popping yields parameter order directly (verified CALL + CALLSYS)
        args = [self._deref(a) for a in args]
        if fr is not None:
            args = [self._normalize_arg(a, fr.param_types[i])
                    for i, a in enumerate(args)]
        # Release NVGT exposes several convenience APIs as long fixed-arity
        # signatures whose trailing parameters default to null.  The compiler
        # materializes bookkeeping slots for those defaults; source does not
        # need them and their values are intentionally uninitialized.
        if fr is not None and fr.default_args:
            while args and len(args) <= len(fr.default_args) \
                    and fr.default_args[len(args) - 1] == "null" \
                    and (args[-1].text.startswith("tmp") or args[-1].text in ("<?>", "null")):
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

        # constructors: $beh0(out) = copy-construct (this=dest, out=source),
        # $beh0() = default. The chained temp form leaves the initializer
        # address on the stack for the following ALLOC (dest pushed deepest).
        if meth in CTORS and (ret is None or ret.format() == "void"):
            dst = pop_this
            typename = fr.object_type.name if fr and fr.object_type else "string"
            copy_ctor = (len(args) == 1 and fr is not None and
                         fr.param_types[0].obj_type is not None and
                         fr.param_types[0].obj_type.name == typename)
            if dst is not None and dst.kind == "list_elem":
                value = args[0] if copy_ctor else Atom("call", f"{typename}({', '.join(a.text for a in args)})")
                self.list_values.setdefault(dst.offset, {})[dst.list_index] = value
                return
            if dst is not None and dst.is_ptr and dst.offset is not None:
                if not args:
                    if self.is_named(dst.offset):
                        self._emit_declare(dst.offset)   # `string s;`
                    else:
                        self.temps[dst.offset] = Atom("const", '""') if typename == "string" else Atom("call", f"{typename}()")
                    return
                src = self._deref(args[0]) if copy_ctor else Atom(
                    "call", f"{typename}({', '.join(a.text for a in args)})")
                if self.is_named(dst.offset):
                    self._emit_assign(dst.offset, src)
                else:
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
            return

        # operator methods on the object
        if has_this and pop_this is not None:
            obj = self._deref(pop_this)
            result: Atom | None = None          # value produced, if any
            if meth in ASSIGN_OPS and args:
                self._stmt(f"{obj.text} {ASSIGN_OPS[meth]} {args[0].text};")
                return
            if meth == "opAssign" and args:
                if pop_this.kind == "list_elem":
                    self.list_values.setdefault(pop_this.offset, {})[pop_this.list_index] = args[0]
                elif pop_this.is_ptr and pop_this.offset is not None:
                    self._bind(pop_this.offset, args[0])
                else:
                    self._stmt(f"{obj.text} = {args[0].text};")
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
        else:
            qualified = (fr.namespace_ + "::" if fr and fr.namespace_ else "") + base
            calltxt = f"{qualified}({', '.join(a.text for a in args)})"

        if has_out and pop_out is not None and pop_out.is_ptr \
                and pop_out.offset is not None:
            # result lands directly in the caller's slot
            self._bind(pop_out.offset, Atom("call", calltxt))
        elif ret is not None and ret.format() != "void":
            self.value_reg = Atom("call", calltxt, is_ptr=ret.is_reference, data_type=ret)
            self.pending_value_call = calltxt
            self.pending_value_call_pos = self._pos()
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
                self.temps[dest.offset] = Atom("call", txt)
        elif dest is not None and dest.text:
            # destination is a property/global address (e.g. `wname = n`)
            self._stmt(f"{dest.text} = {txt};")
        else:
            self.value_reg = Atom("call", txt)

    def _call_ptr(self, ins: Instr) -> None:
        self._flush_pending_call()
        off = _s16(ins.w_arg2)
        dt = self.var_types.get(off)
        type_name = dt.obj_type.name if dt and dt.obj_type else ""
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

    def _taken_condition(self, ins: Instr) -> str:
        """Condition under which a jump instruction transfers control."""
        op = JUMP_OPS[ins.name]
        if self.cmp_pair is not None:
            a, b = self.cmp_pair
            self.cmp_pair = None
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
        merge_ins = self.instrs[merge_idx]
        result_dest = _s16(setv.w_arg)
        finish_pos = merge_pos
        if merge_ins.name == "CpyVtoV4" and _s16(merge_ins.w_arg2) == result_dest:
            if merge_idx + 1 >= len(self.instrs):
                return False
            load = self.instrs[merge_idx + 1]
            if load.name != "CpyVtoR4" or _s16(load.w_arg) != _s16(merge_ins.w_arg):
                return False
            result_dest = _s16(merge_ins.w_arg)
            finish_pos = load.pos
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
        if load.name not in ("CpyVtoR4", "CpyVtoR8", "PSF", "VAR", "PshV4", "PshV8", "LOADOBJ") and load.name not in CONV_OPS and not stack_merge:
            return False
        off = None if stack_merge else _s16(load.w_arg2 if load.name in CONV_OPS and load.bc_type != "asBCTYPE_rW_ARG" else load.w_arg)
        if off is not None and self.is_named(off):
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
        """Index of the first event at or after dword position `pos`."""
        idx = self.pos_index.get(pos)
        if idx is not None:
            return idx
        for i, e in enumerate(self.ev):
            if e.pos >= pos:
                return i
        return len(self.ev)

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
                    if self.ev[k].kind == "stmt" and not self.done[k]:
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
                        self.out.append((indent, f"}} while {e.data[0]};"))
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
            if (plain_latches and i not in self.handled_plain_loops
                    and not (e.kind == "branch" and e.data[1] > self.ev[plain_latches[-1]].pos)):
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
                self.out.append((indent, f"switch ({selector}) {{"))
                for index, target in enumerate(positions):
                    for label in labels[target]:
                        self.out.append((indent + 1, label))
                    boundary = positions[index + 1] if index + 1 < len(positions) else join
                    self._block(indent + 2, self._next_index(target), self._next_index(boundary), SwitchCtx(join, loop))
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
                                        for ev in self.ev[i + 1:update])):
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
            self.emit(f"enum {e.name} {{")
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
        for pname, dt, flags in c.properties:
            if flags & 4:
                continue  # inherited properties are declared by the base
            # stored object members carry a spurious is_reference bit;
            # references are not storable, so the declaration never has &
            decl = dt.format()
            if decl.endswith("&"):
                decl = decl[:-1].rstrip()
            visibility = "private " if flags & 1 else "protected " if flags & 2 else ""
            self.emit(f"    {visibility}{decl} {pname};")
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
            # asFUNC_VIRTUAL stubs carry no bytecode; the VFT copy of the
            # same method holds the real body (and param names).
            body_f = f
            if not body_f.bytecode:
                for vf in c.vft:
                    if vf.signature(False) == f.signature(False) and vf.bytecode:
                        body_f = vf
                        break
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
            if fd.var_names != initial_names:
                discovered = dict(fd.var_names)
                fd = FuncDecompiler(self.m, f, self.comments)
                fd.var_names.update(discovered)
                ev = fd.run()
            # Stripped metadata reuses scalar slots across sibling blocks.
            # Keep one declaration in the function and initialization at its
            # original position, rather than declaring in just the first arm.
            declarations = []
            scalar_names = {fd.name_of(off) for off, dt in fd.var_types.items()
                            if off > 0 and fd.is_named(off) and
                            (dt.obj_type is None or dt.obj_type.kind == "enum"
                             or dt.is_object_handle or dt.obj_type.name == "string")}
            for event in ev:
                if event.kind != "stmt":
                    continue
                typename, text = event.data
                if not typename:
                    continue
                name = text.split(" ", 1)[0].rstrip(";")
                if name in scalar_names:
                    declarations.append("    " * indent + f"{typename} {name};")
                    off = next(off for off in fd.var_names if fd.name_of(off) == name)
                    prefix = "@" if fd.var_types.get(off) and fd.var_types[off].is_object_handle and text != name + ";" else ""
                    event.data = ("", "" if text == name + ";" else prefix + text)
            ev = [e for e in ev if e.kind != "stmt" or e.data != ("", "")]
            scopes = _recover_plain_scopes(ev, f, self.m.classes)
            st = Structurer(ev, f, scopes)
            return declarations + st.render(indent)
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
                    decl = f"{g.type.format()} {g.name} = {expr};"
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
