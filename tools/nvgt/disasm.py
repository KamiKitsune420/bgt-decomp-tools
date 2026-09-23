"""Human-readable AngelScript bytecode disassembler.

Renders a parsed Module (from asreader) as annotated assembly. All names
(functions, globals, strings, types, properties) are already resolved by
the reader's post-processing, so this file is purely cosmetic formatting.

Usage:
    python disasm.py module.bin          # raw stream (expects the 12-byte
                                         # ASBC wrapper our tools emit)
    python disasm.py module.bin --raw    # stream without any wrapper
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

try:                      # installed as a package
    from .asreader import DataType, Function, Module, TypeInfo, read_module, unwrap_bytecode
except ImportError:       # run directly from a checkout
    from asreader import DataType, Function, Module, TypeInfo, read_module, unwrap_bytecode

MAGIC = b"ASBC"


@dataclass
class DisasmOptions:
    show_temporaries: bool = False   # show lines for pure bookkeeping ops
    show_pos: bool = True            # dword position column
    show_lines: bool = True          # interleave source line info
    header: bool = True              # module-level header section


def _type_name(dt: DataType | None) -> str:
    return dt.format() if dt is not None else "?"


def _signed(v: int) -> int:
    """16-bit stack offsets are signed shorts."""
    return v - 0x10000 if v >= 0x8000 else v


def _var(fn: Function, off: int) -> str:
    """Render a stack offset as the variable that lives there, if known."""
    if off == 0x8000:  # unofficial: keep raw
        return "?"
    so = _signed(off)
    for v in fn.variables:
        if v.stack_offset == so and v.name:
            return v.name
    for i, p in enumerate(fn.param_types):
        pass
    return f"v{so}"


class Disassembler:
    def __init__(self, module: Module, opts: DisasmOptions | None = None):
        self.m = module
        self.o = opts or DisasmOptions()

    # -- module -------------------------------------------------------------

    def render(self) -> str:
        out: list[str] = []
        if self.o.header:
            out.append(f"; module debug info: {'yes' if self.m.debug_info else 'stripped'}")
            if self.m.globals:
                out.append("; global variables:")
                for g in self.m.globals:
                    init = f" = ... (init func)" if g.init_func else ""
                    out.append(f";   {g.type.format()} {g.name}{init}")
            if self.m.used_strings:
                out.append(f"; {len(self.m.used_strings)} string constant(s)")
            out.append("")
        for f in self.m.script_functions:
            out.extend(self.render_function(f))
            out.append("")
        return "\n".join(out).rstrip() + "\n"

    # -- function -----------------------------------------------------------

    def render_function(self, fn: Function) -> list[str]:
        out = [f"function {fn.signature()} {{"] if fn.func_type == 1 else [f"; {fn.signature()}"]
        if fn.variables:
            named = [v for v in fn.variables if v.name]
            if named:
                out.append("  ; locals: " + ", ".join(f"{v.type.format()} {v.name}" for v in named))
        # line-number lookup: pos -> line
        line_at = dict(zip(fn.line_numbers[0::2], fn.line_numbers[1::2]))
        by_pos = {}
        for i in fn.bytecode:
            by_pos[i.pos] = i
        for ins in fn.bytecode:
            if self.o.show_lines and ins.pos in line_at:
                packed = line_at[ins.pos]
                row, col = packed & 0xFFFFF, packed >> 20
                out.append(f"  ; line {row}, col {col}")
            out.append("  " + self.render_instr(ins, fn))
        out.append("}")
        return out

    # -- instruction ---------------------------------------------------------

    def render_instr(self, ins, fn: Function) -> str:
        name = ins.name
        w, w2, dw, qw = ins.w_arg, ins.w_arg2, ins.dw_arg, ins.qw_arg
        wo, w2o, dwo = _signed(w), _signed(w2), dw - (1 << 32) if dw >= (1 << 31) else dw
        qwo = qw - (1 << 64) if qw >= (1 << 63) else qw

        # jumps: stored as instruction-number delta; recompute dword target
        if name in ("JMP", "JZ", "JNZ", "JLowZ", "JLowNZ", "JS", "JNS", "JP", "JNP"):
            target = ins.jump_target if ins.jump_target is not None else ins.pos + 2 + dwo
            return f"{name} -> L{target:04d}"
        if name == "JMPP":
            return "JMPP"

        if name in ("CALL", "CALLSYS", "CALLBND", "CALLINTF", "Thiscall1"):
            return f"{name} {ins.func_name or f'fn#{dw}'}"
        if name == "ALLOC":
            ctor = f", ctor {ins.func_name}" if ins.func_name else ""
            return f"ALLOC {ins.type_ref.name if ins.type_ref else f'type#{qw}'}{ctor}"
        if name in ("FREE", "REFCPY", "OBJTYPE"):
            return f"{name} {ins.type_ref.name if ins.type_ref else f'type#{qw}'} {_var(fn, wo)}"
        if name == "TYPEID":
            return f"TYPEID {ins.type_ref.name if ins.type_ref else dw}"
        if name == "Cast":
            return f"Cast {ins.type_ref.name if ins.type_ref else dw}"

        # globals / string constants (pointer-sized arg, resolved by reader)
        if ins.global_name:
            return f"{name} global:{ins.global_name}" + (f", {_var(fn, wo)}" if name == "LdGRdR4" else "")
        if ins.string_const is not None:
            s = ins.string_const
            shown = s if len(s) <= 40 else s[:37] + "..."
            return f"{name} {shown!r}"

        # pattern-based fallbacks per bc type
        t = ins.bc_type
        if t in ("asBCTYPE_NO_ARG", "asBCTYPE_INFO"):
            return name
        if t == "asBCTYPE_W_ARG":
            return f"{name} {w}"
        if t == "asBCTYPE_wW_ARG":
            return f"{name} {_var(fn, w)}"
        if t == "asBCTYPE_rW_ARG":
            return f"{name} {_var(fn, w)}"
        if t in ("asBCTYPE_W_DW_ARG", "asBCTYPE_wW_DW_ARG", "asBCTYPE_rW_DW_ARG"):
            lhs = w if name in ("SetV1",) else _var(fn, w)
            if name in ("ADDSi", "SetV1", "CMPIi", "CMPIf", "CMPIu", "PshC4"):
                lhs = w if name == "PshC4" else _var(fn, w)
            return f"{name} {lhs}, {dwo}"
        if t == "asBCTYPE_DW_ARG":
            if name in ("PshC4",):
                return f"{name} {dwo}"
            if name in ("PshV4", "PSF", "PshVPtr"):
                return f"{name} {_var(fn, w) if False else dwo}"
            return f"{name} {dwo}"
        if t == "asBCTYPE_DW_DW_ARG":
            return f"{name} {dwo}, {qw & 0xFFFFFFFF}"
        if t == "asBCTYPE_QW_ARG":
            return f"{name} {qwo}"
        if t == "asBCTYPE_QW_DW_ARG":
            return f"{name} {qwo}, {dwo}"
        if t == "asBCTYPE_W_QW_DW_ARG":
            return f"{name} {_var(fn, w)}, {ins.type_ref.name if ins.type_ref else qwo}{', ctor ' + ins.func_name if ins.func_name else ''}"
        if t in ("asBCTYPE_rW_QW_ARG", "asBCTYPE_wW_QW_ARG"):
            return f"{name} {_var(fn, w)}, {ins.type_ref.name if ins.type_ref else qwo}"
        if t in ("asBCTYPE_wW_rW_ARG", "asBCTYPE_rW_rW_ARG"):
            return f"{name} {_var(fn, w)}, {_var(fn, w2)}"
        if t == "asBCTYPE_wW_W_ARG":
            return f"{name} {_var(fn, w)}, {w2}"
        if t == "asBCTYPE_W_rW_ARG":
            return f"{name} {w}, {_var(fn, w2)}"
        if t == "asBCTYPE_wW_rW_DW_ARG":
            return f"{name} {_var(fn, w)}, {_var(fn, w2)}, {dwo}"
        if t == "asBCTYPE_rW_W_DW_ARG":
            return f"{name} {_var(fn, w)}, {w2}, {dwo}"
        if t == "asBCTYPE_wW_rW_rW_ARG":
            return f"{name} {_var(fn, w)}, {_var(fn, w2)}, {_var(fn, qw & 0xFFFF)}"
        if t in ("asBCTYPE_rW_DW_DW_ARG", "asBCTYPE_W_DW_DW_ARG"):
            return f"{name} {_var(fn, w)}, {dwo}, {qw & 0xFFFFFFFF}"
        return f"{name} ?{t}"


def load_stream(path: str, raw: bool = False) -> Module:
    with open(path, "rb") as source:
        data = source.read()
    if not raw:
        data = unwrap_bytecode(data)
    return read_module(data)


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    opts = DisasmOptions(
        show_temporaries="--all" in sys.argv,
        show_lines="--no-lines" not in sys.argv,
        header="--no-header" not in sys.argv,
    )
    if not args:
        print(__doc__)
        return 2
    m = load_stream(args[0], raw="--raw" in sys.argv)
    sys.stdout.write(Disassembler(m, opts).render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
