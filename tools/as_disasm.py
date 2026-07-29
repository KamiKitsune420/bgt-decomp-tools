"""
as_disasm -- readable disassembly of a recovered AngelScript module.

`as_opcodes.disassemble` decodes a bytecode span into instructions; this turns
that into something a person can read, by resolving every operand that indexes
one of the module's tables:

    CALL 5343        ->  CALL  set_sound_decryption_key
    PGA  10050       ->  PGA   "data.dat"
    ADDSi 412, 88    ->  ADDSi player_object::position
    JMP  32          ->  JMP   L4

Which operand slot indexes which table was fixed by **range analysis against the
real tables**, not by assumption: every slot's observed maximum was checked
against every table's size, and the right answer saturates. Across Manamon 2's
11,085,747 decoded instructions:

    CALL / CALLSYS / CALLINTF  max 8179  vs  usedFunctions        8180   exact
    PGA (even)/2               max 10180 vs  usedStringConstants 10181   exact
    PshG4 (odd-1)/2            max 538   vs  usedGlobalProps       539   exact
    LoadThisR arg0             max 6522  vs  usedObjectProps      6523   exact
    LoadThisR arg1             max 1661  vs  usedTypeIds          1662   exact

A saturating maximum makes an off-by-one impossible: one more and it would not
fit, one fewer and the last entry would be unreachable.

## Global-pointer operands are encoded differently per dialect

This is the piece that fails quietly, in both directions.

In `len2`, `PGA` and friends do not carry a plain index -- they carry
`2 * index + tag`, where tag 0 means the string-constant table and tag 1 means
the global-property table. In Manamon 2, 149,656 `PGA` operands are even (string
literals) and 106 are odd (globals: `player`, `current_map`, `save_data`).
Reading them all as literals resolves the 106 to whatever happens to sit at that
index in the other table -- a real string, from the wrong place.

In `tagged` there is no tag bit: the operand is a plain index into
usedGlobalProps, and string literals have their own `STR` opcode so nothing has
to share the field. Psycho Strike's `PshG4` tops out at 170 against 171 globals
-- saturated -- and its operands are freely odd and even, which is what rules the
tagged-union reading out. Applying the len2 rule here halves every index and
still produces a real global name: `pack_file::open(retreave, ...)` comes out as
`pack_file::open(money_wanted, ...)`.

## Units

Two fields count **instructions, not dwords** -- the bytecode length and jump
offsets. A jump target is

    target_instruction = current_instruction + 1 + operand

(the +1 because the offset is relative to the instruction *after* the branch).
Read as dwords instead, a majority of jumps still land on a valid instruction
boundary and silently point at the wrong one.
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

try:                      # installed as a package
    from . import as_module, as_opcodes
except ImportError:       # run directly from a checkout
    import as_module
    import as_opcodes


# Primitive token ids. Each is evidence-backed in STRIKE-DECOMP.md -- from BGT's
# own shipped class sources and from member access widths -- not guessed.
TOKEN_NAMES: Dict[int, str] = {
    65: "bool", 68: "int", 69: "int8", 70: "int16", 71: "int64",
    75: "uint", 76: "uint8", 77: "uint16", 78: "uint64",
    79: "float", 80: "void", 92: "double",
}

# Which operand slot indexes which table, per opcode. Established by the range
# analysis in the module docstring. Roles:
#   function   -> usedFunctions
#   string     -> usedStringConstants
#   globalptr  -> tagged: even = usedStringConstants, odd = usedGlobalProps
#   objprop    -> usedObjectProps
#   typeid     -> usedTypeIds
#   objtype    -> usedTypes
#   jump       -> instruction-relative branch target
OPERAND_ROLES: Dict[str, Dict[int, str]] = {
    "CALL": {0: "function"}, "CALLSYS": {0: "function"},
    "CALLINTF": {0: "function"}, "CALLBND": {0: "function"},
    "Thiscall1": {0: "function"},

    "STR": {0: "string"},

    "PGA": {0: "globalptr"}, "PshGPtr": {0: "globalptr"}, "LDG": {0: "globalptr"},
    "PshG4": {0: "globalptr"}, "SetG4": {0: "globalptr"},
    "CpyGtoV4": {1: "globalptr"}, "CpyVtoG4": {1: "globalptr"},
    "LdGRdR4": {1: "globalptr"},

    # arg0 is a usedObjectProperties index in the *serialised* form; the loader
    # rewrites it into a byte offset, which is why a runtime dump shows +36.
    # ADDSi and LoadThisR share a branch in TranslateFunction, and so do
    # LoadRObjR and LoadVObjR -- all four run the same two lookups, the object
    # property (FUN_00421D10) and the type id (FUN_00423710), on the same
    # relative fields. LoadVObjR occurs only 36 times in the whole corpus, far
    # too few to settle by range analysis; it does not need to be, because it is
    # literally the same code path as LoadRObjR's 61,421.
    "ADDSi": {0: "objprop", 1: "typeid"},
    "LoadThisR": {0: "objprop", 1: "typeid"},
    "LoadRObjR": {1: "objprop", 2: "typeid"},
    "LoadVObjR": {1: "objprop", 2: "typeid"},

    "TYPEID": {0: "typeid"}, "Cast": {0: "typeid"},

    # ALLOC's second operand is a usedFunctions index that is **one-based**,
    # with 0 meaning "this type has no script constructor". Read straight, it
    # resolves to a real function that is simply the wrong one -- the owner
    # matches the allocated type in 322 of 15,619 sites. Subtracting one takes
    # that to 15,619 of 15,619, and to 1,793/1,793 and 2,460/2,460 on the other
    # two titles. asCReader::TranslateFunction is explicit about it:
    #     else if (op == 0x40) {            // ALLOC
    #         ...FindObjectType(arg0)...
    #         if (arg1 != 0) FindFunction(arg1 - 1);
    "ALLOC": {0: "objtype", 1: "ctorfunc"},
    "FREE": {1: "objtype"}, "REFCPY": {0: "objtype"}, "ObjType": {0: "objtype"},

    "JMP": {0: "jump"}, "JZ": {0: "jump"}, "JNZ": {0: "jump"},
    "JS": {0: "jump"}, "JNS": {0: "jump"}, "JP": {0: "jump"}, "JNP": {0: "jump"},
    "JLowZ": {0: "jump"}, "JLowNZ": {0: "jump"},
}

JUMP_OPCODES = frozenset(op for op, roles in OPERAND_ROLES.items()
                         if "jump" in roles.values())


def type_name(dt: Optional[Dict[str, Any]]) -> str:
    """Render a ReadDataType record as a type expression."""
    if not isinstance(dt, dict):
        return "?"
    if "ref" in dt and "token" not in dt:
        return "T%d" % dt["ref"]
    obj = dt.get("type")
    base: str
    if obj is not None:
        base = _type_info_name(obj)
    else:
        token = dt.get("token", -1)
        base = TOKEN_NAMES.get(token, "tt%s" % token)
    if dt.get("const"):
        base = "const " + base
    if dt.get("handle"):
        base += "@"
    if dt.get("reference"):
        base += "&"
    return base


def _type_info_name(obj: Optional[Dict[str, Any]]) -> str:
    if obj is None:
        return "void"
    kind = obj.get("kind")
    if kind == "named":
        return str(obj.get("name") or "?")
    if kind == "subtype":
        return str(obj.get("name") or "T")
    if kind == "child":
        return "%s::%s" % (_type_info_name(obj.get("owner")), obj.get("name", "?"))
    if kind == "listpattern":
        return "list<%s>" % _type_info_name(obj.get("of"))
    if kind == "template":
        subs = []
        for s in obj.get("subtypes", []):
            subs.append(type_name(s) if "token" in s or "ref" in s
                        else "typeid%s" % s.get("typeid"))
        return "%s<%s>" % (obj.get("name", "?"), ", ".join(subs) or "?")
    return "?"


def function_label(f: Dict[str, Any]) -> str:
    """`owner::name`, or `<global>::name` for a free function."""
    owner = _type_info_name(f["owner"]) if f.get("owner") else "<global>"
    return "%s::%s" % (owner, f.get("name", "?"))


def signature(f: Dict[str, Any]) -> str:
    params = ", ".join(type_name(p) for p in f.get("params", []))
    return "%s %s(%s)" % (type_name(f.get("returns")), function_label(f), params)


class Module:
    """A parsed module plus the tables needed to name things in its bytecode."""

    dialect = as_module.LEN2          # overridden per instance in __init__

    def __init__(self, path: str, opcodes: Dict[int, Dict[str, Any]]) -> None:
        with open(path, "rb") as fh:
            self.data = fh.read()
        self.path = path
        self.opcodes = opcodes
        self.info = as_module.summarize(path, opcodes=opcodes)
        self.dialect = self.info["dialect"]
        self.blocks = self.info["blocks"]
        self.tail = self.info["tail"] or {}
        self.parse_errors = self.info["parse_errors"]

        self.used_functions = self.tail.get("used_functions", [])
        self.used_strings = self.tail.get("used_string_constants", [])
        self.used_global_props = self.tail.get("used_global_props", [])
        self.used_object_props = self.tail.get("used_object_props", [])
        self.used_types = self.tail.get("used_types", [])
        self.used_type_ids = self.tail.get("used_type_ids", [])

        # class name -> its own property table, for naming member accesses
        self.properties: Dict[str, List[Dict[str, Any]]] = {
            b["name"]: b.get("properties", []) for b in self.blocks}

        self.functions = self._collect_functions()

    # -- gathering every record that carries a body ------------------------
    def _collect_functions(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen = set()

        def add(f):
            if isinstance(f, dict) and f.get("body") and id(f) not in seen:
                seen.add(id(f))
                out.append(f)

        for b in self.blocks:
            add(b.get("destructor"))
            for ctor, factory in b.get("ctors", []):
                add(ctor)
                add(factory)
            for m in b.get("methods", []):
                add(m)
            for v in b.get("virtuals", []):
                add(v)
        for f in self.tail.get("module_functions", []):
            add(f)
        for f in self.tail.get("global_functions", []):
            add(f)
        for g in self.tail.get("global_properties", []):
            add(g.get("init"))
        return out

    def find(self, needle: str) -> List[Dict[str, Any]]:
        """Functions whose name or `owner::name` contains `needle`."""
        low = needle.lower()
        return [f for f in self.functions
                if low in function_label(f).lower() or low == f.get("name", "").lower()]

    def callers_of(self, needle: str) -> List[Dict[str, Any]]:
        """Function bodies that call something matching `needle`.

        The function you want to read is often not the one you can name. Engine
        functions like `set_sound_decryption_key` are registered by the runtime
        and have no body -- what you actually want is whichever script function
        *calls* it, and that is what names the key. This is the step that
        recovered the pack passwords in both titles.
        """
        low = needle.lower()
        wanted = {i for i, f in enumerate(self.used_functions)
                  if isinstance(f, dict)
                  and (low in function_label(f).lower()
                       or low == (f.get("name") or "").lower())}
        if not wanted:
            return []

        out = []
        for f in self.functions:
            start, end = f["body"]
            for _off, _op, name, args in as_opcodes.disassemble(
                    self.data[start:end], self.opcodes):
                roles = OPERAND_ROLES.get(name, {})
                hit = False
                for j, a in enumerate(args):
                    role = roles.get(j)
                    if role == "function" and a in wanted:
                        hit = True
                    elif role == "ctorfunc" and a and (a - 1) in wanted:
                        hit = True
                if hit:
                    out.append(f)
                    break
        return out

    # -- operand resolution -------------------------------------------------
    def resolve(self, role: str, value: int) -> Optional[str]:
        """Render one operand, or None if it does not resolve.

        Returns None rather than a placeholder so a caller can measure how much
        of a disassembly is actually named -- a resolution rate that quietly
        includes `<invalid>` entries is not a measurement.
        """
        if role == "function":
            f = _at(self.used_functions, value)
            return function_label(f) if isinstance(f, dict) else None
        if role == "ctorfunc":
            # one-based; 0 means the type has no script constructor
            if value == 0:
                return "<no constructor>"
            f = _at(self.used_functions, value - 1)
            return function_label(f) if isinstance(f, dict) else None
        if role == "string":
            s = _at(self.used_strings, value)
            return _quote(s) if s is not None else None
        if role == "globalptr":
            # The two builds encode this differently, and range analysis over a
            # whole module separates them cleanly:
            #
            #   len2    `2 * index + tag`, tag 0 = string constant, 1 = global.
            #           PGA's even operands saturate usedStringConstants exactly
            #           (10180 of 10181) and the odd ones stay inside 539 globals.
            #   tagged  a plain index into usedGlobalProps. Psycho Strike's
            #           PshG4 tops out at 170 against 171 globals -- saturated --
            #           and operands are freely odd and even, so there is no tag
            #           bit to read. String literals get their own STR opcode in
            #           this build, so nothing needs to share the field.
            if self.dialect == as_module.TAGGED:
                g = _at(self.used_global_props, value)
                return g["name"] if isinstance(g, dict) else None
            idx, tag = value >> 1, value & 1
            if tag == 0:
                s = _at(self.used_strings, idx)
                return _quote(s) if s is not None else None
            g = _at(self.used_global_props, idx)
            return g["name"] if isinstance(g, dict) else None
        if role == "objprop":
            return self._object_property(value)
        if role == "typeid":
            dt = _at(self.used_type_ids, value)
            return type_name(dt) if dt is not None else None
        if role == "objtype":
            ti = _at(self.used_types, value)
            return _type_info_name(ti) if ti is not None else None
        return None

    def _object_property(self, value: int) -> Optional[str]:
        rec = _at(self.used_object_props, value)
        if not isinstance(rec, dict):
            return None
        owner = _type_info_name(rec.get("owner"))
        # The older build stores the property NAME in the record; the newer one
        # stores an index into the owner's property table and needs the lookup.
        if rec.get("name"):
            return "%s::%s" % (owner, rec["name"])
        props = self.properties.get(owner) or []
        i = rec.get("index", -1)
        if 0 <= i < len(props):
            return "%s::%s" % (owner, props[i]["name"])
        return "%s::prop[%d]" % (owner, i)


def _at(table: List[Any], i: int) -> Any:
    return table[i] if 0 <= i < len(table) else None


def _quote(s: bytes, limit: int = 60) -> str:
    """A string literal, with embedded NULs shown -- BGT literals really do
    contain them, and rendering them as spaces has misread a key before."""
    text = s.decode("latin1")
    if len(text) > limit:
        text = text[:limit] + "..."
    return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"') \
                       .replace("\x00", "\\0").replace("\n", "\\n")


def variable_name(f: Dict[str, Any], slot: int) -> str:
    """Best-effort name for a variable slot.

    `noDebugInfo = 1`, so the real names are gone and this is a positional
    approximation: slot 0 of a method is `this`, slots inside the parameter
    region are `aN`, everything above is `vN`. It is labelled `a`/`v` rather
    than invented names precisely so nobody mistakes it for recovered data.
    """
    base = 1 if f.get("owner") else 0
    nparams = len(f.get("params", []))
    if slot < 0:
        # Serialised variable positions can be negative -- the loader adjusts
        # them (CalculateAdjustmentByPos) and we are reading the unadjusted
        # form. Render them as distinct stack slots rather than as `v-1`, which
        # reads like an expression.
        return "s%d" % (-slot)
    if f.get("owner") and slot == 0:
        return "this"
    if base <= slot < base + nparams:
        return "a%d" % (slot - base)
    return "v%d" % slot


def disassemble_function(mod: Module, f: Dict[str, Any]) -> Dict[str, Any]:
    """Decode and annotate one function body."""
    start, end = f["body"]
    raw = as_opcodes.disassemble(mod.data[start:end], mod.opcodes)

    targets: Dict[int, int] = {}          # instruction index -> label number
    resolved = unresolved = 0

    instrs: List[Dict[str, Any]] = []
    for i, (off, op, name, args) in enumerate(raw):
        roles = OPERAND_ROLES.get(name, {})
        rendered: List[Dict[str, Any]] = []
        for j, a in enumerate(args):
            role = roles.get(j)
            item: Dict[str, Any] = {"value": a, "role": role}
            if role == "jump":
                # instructions, not dwords, and relative to the NEXT instruction
                tgt = i + 1 + a
                item["target"] = tgt
                if 0 <= tgt < len(raw):
                    targets.setdefault(tgt, len(targets))
                    item["text"] = None       # filled in below, once numbered
                    resolved += 1
                else:
                    unresolved += 1
            elif role:
                text = mod.resolve(role, a)
                item["text"] = text
                if text is None:
                    unresolved += 1
                else:
                    resolved += 1
            rendered.append(item)
        instrs.append({"index": i, "offset": off, "opcode": op,
                       "name": name, "args": rendered})

    for ins in instrs:                        # now that every label has a number
        for item in ins["args"]:
            if item.get("role") == "jump" and "target" in item:
                lab = targets.get(item["target"])
                item["text"] = "L%d" % lab if lab is not None else None

    return {"function": f, "label": function_label(f), "signature": signature(f),
            "declared_instructions": f.get("instructions"),
            "decoded_instructions": len(raw),
            "stack_needed": f.get("stackNeeded"),
            "span": [start, end], "labels": targets, "instructions": instrs,
            "resolved": resolved, "unresolved": unresolved}


def format_function(dis: Dict[str, Any]) -> str:
    """Render one disassembled function as text."""
    f = dis["function"]
    out = []
    out.append("; === %s ===" % dis["signature"])
    params = f.get("params", [])
    if params:
        out.append("; params: %s" % ", ".join(
            "a%d=%s" % (i, type_name(p)) for i, p in enumerate(params)))
    if dis["stack_needed"] is not None:
        out.append("; stack needed: %s" % dis["stack_needed"])
    declared, decoded = dis["declared_instructions"], dis["decoded_instructions"]
    flag = "" if declared == decoded else "   <-- MISMATCH"
    out.append("; instructions: %s decoded / %s declared%s" % (decoded, declared, flag))
    out.append("")
    out.append("%s:" % dis["label"])

    labels = dis["labels"]
    for ins in dis["instructions"]:
        if ins["index"] in labels:
            out.append("L%d:" % labels[ins["index"]])
        operands, comments = [], []
        for item in ins["args"]:
            operands.append(str(item["value"]))
            if item.get("text"):
                comments.append(item["text"])
        line = "    %-10s %s" % (ins["name"], " ".join(operands))
        if comments:
            line = "%-32s ; %s" % (line.rstrip(), "  ".join(comments))
        out.append(line.rstrip())
    return "\n".join(out)


def load(module_path: str, exe: Optional[str] = None,
         table_json: Optional[str] = None) -> Module:
    """Parse a module, taking the opcode table from an exe or a JSON dump."""
    if table_json:
        with open(table_json) as fh:
            table = {int(k): v for k, v in json.load(fh).items()}
    elif exe:
        table = as_opcodes.extract(exe)["table"]
    else:
        raise SystemExit("an opcode table is required: pass the game .exe or "
                         "--opcodes table.json (as_opcodes.py writes one)")
    return Module(module_path, table)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("module", help="recovered bytecode (from bgt_unpack)")
    ap.add_argument("exe", nargs="?", help="the game executable, for its opcode table")
    ap.add_argument("--opcodes", help="opcode table as JSON, instead of the exe")
    ap.add_argument("-f", "--function", help="only functions matching this name")
    ap.add_argument("--calls", metavar="NAME",
                    help="functions that CALL this one -- use it when the "
                         "name you have is an engine function with no body")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--limit", type=int, help="stop after this many functions")
    args = ap.parse_args()

    mod = load(args.module, args.exe, args.opcodes)

    if not mod.functions:
        # Distinguish "this module has no code" from "this dialect's bodies do
        # not parse yet", which is the case for the older `tagged` builds.
        print("no function bodies were recovered from %s (dialect %s)."
              % (mod.path, mod.dialect), file=sys.stderr)
        if mod.dialect == as_module.TAGGED:
            print("The tagged dialect's ReadFunction is not modelled yet -- its "
                  "headers,\nenums, class declarations and funcdefs parse, but "
                  "bodies do not, so the\nused* tables are never reached. See "
                  "'Extending the reader' in CLAUDE.md.", file=sys.stderr)
        if mod.parse_errors:
            first = mod.parse_errors[0]
            print("first failure: %s at 0x%X -- %s"
                  % (first["context"] or "<unnamed>", first["offset"],
                     first["error"]), file=sys.stderr)
        return 1

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
        print("no function matching %r (%d with bodies were recovered)"
              % (args.function, len(mod.functions)), file=sys.stderr)
        return 1
    if args.limit:
        chosen = chosen[:args.limit]

    dis = [disassemble_function(mod, f) for f in chosen]

    if args.json:
        payload = {
            "module": mod.path, "dialect": mod.dialect,
            "functions_with_bodies": len(mod.functions),
            "parse_errors": mod.parse_errors,
            "disassembly": [_jsonable(d) for d in dis],
        }
        text = json.dumps(payload, indent=1)
    else:
        text = "\n\n".join(format_function(d) for d in dis)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")

    res = sum(d["resolved"] for d in dis)
    unres = sum(d["unresolved"] for d in dis)
    total = res + unres
    exact = sum(1 for d in dis
                if d["declared_instructions"] == d["decoded_instructions"])
    print("\n%d function(s), %d/%d with the declared instruction count, "
          "%d/%d operands resolved (%.1f%%)"
          % (len(dis), exact, len(dis), res, total,
             100.0 * res / total if total else 0.0), file=sys.stderr)
    if mod.parse_errors:
        print("%d function(s) failed to parse (see the errors list)"
              % len(mod.parse_errors), file=sys.stderr)
    return 0


def _jsonable(d: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in d.items() if k != "function"}
    out["labels"] = {str(k): v for k, v in d["labels"].items()}
    return out


if __name__ == "__main__":
    sys.exit(main())
