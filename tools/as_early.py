"""The EARLY BGT module format -- the 2010 and 2011 AngelScript.

`as_module` reads the two dialects every title from 2012 on uses. This reads
the generation before them, which is a different FORMAT rather than a
different string encoding: the encoded integer has no sign flag, there is no
`noDebugInfo` byte, a type declaration carries no namespace, a template
type-info holds one subtype and no count, and a global property's initialiser
is gated on a byte. Every layout here was read out of `asCWriter` and
`asCReader` in a 2011 runtime with capstone -- the addresses are in CLAUDE.md
-- and the measure for believing any of it is this project's usual one: the
walk has to land exactly on EOF.

Two titles do: Ljudfarmen (2011-02) and Grodan Gun (2011-09), which are debug
builds, so each function record also names the source file it was compiled
from and the walk recovers all 9 and all 11 of them.

Three more early titles stop early, each on its own per-build field, and the
reader says where rather than guessing: Palace Punch-up (a 2010 beta),
Perilous Hearts (2011-11) and Antony (2012-02).

One reader stays one reader: this does not touch `as_module`, because that
one models a different generation of the format and two models of ONE format
drift. What they share is the opcode table, which comes from the game's own
runtime either way.
"""
import os
import sys


#: `asBCTypeSize`, in dwords of expanded instruction, read out of a 2011
#: runtime at 0x004C5428 -- and identical to the table this project records
#: for BGT 1.3.
BC_DWORDS = (0, 1, 1, 1, 2, 2, 3, 3, 2, 3, 2, 1, 2, 3, 2, 2, 4, 3, 2, 3, 3, 2)

#: What each bytecode type reads after its opcode byte, from
#: `ReadByteCode`'s switch: an integer is a count of RAW bytes, `None` is an
#: encoded integer. Eleven cases serve nineteen types and the groups that
#: share a case share a sequence, which is the check on the transcription.
BC_READS = {
    1:  (),
    2:  (2,),            3:  (2,),            11: (2,),
    4:  (None,),
    5:  (2, None),       12: (2, None),       18: (2, None),
    6:  (8,),
    7:  (None, None),
    8:  (2, 2, 2),
    9:  (2, 8),          17: (2, 8),
    10: (2, 2),          14: (2, 2),          15: (2, 2),
    13: (2, 2, 4),       19: (2, 2, 4),
    16: (8, 4),
}

class Stop(Exception):
    pass


class Early:
    """The early generations' module, walked field by field."""

    def __init__(self, data, namespace=False, defaults=True, table=None):
        #: The build's own `asBCInfo[]`, so a body can be stepped. Its operand
        #: COUNT is what matters here; the operands themselves use this
        #: generation's plain varint rather than the newer sign-flag form,
        #: which is why `as_opcodes.disassemble` cannot step these.
        self.table = table
        self.d = data
        self.p = 0
        self.namespace = namespace
        # Whether a signature carries a default-argument list at all. Read out
        # of the writers: Grodan Gun (2011-09) counts the non-null defaults and
        # writes them; Ljudfarmen (2011-02) goes straight from the funcType
        # bytes to the owner, and its WriteFunctionSignature is 71 bytes
        # shorter for it. The feature arrived between them, which the
        # compiler's own diagnostics agree with -- `Failed while compiling
        # default arg` is a literal in Grodan Gun's runtime and in neither
        # BGT 1.0's nor Ljudfarmen's.
        self.defaults = defaults
        #: Three candidate body fields, each offered rather than assumed.
        #: `objvar_three` is this document's own per-build field one
        #: generation earlier; the other two are what five bytes can hold.
        self.objvar_three = True
        self.objinfo_fields = 3
        self.line_numbers = True
        #: Every source path the module has named, which is the result worth
        #: having even before a walk reaches EOF.
        self.sections = set()
        self.strings = []
        self.datatypes = []
        self.functions = []
        self.notes = []

    # ---- primitives, from asCWriter -------------------------------------

    def eu(self):
        """WriteEncodedUInt at 0x004477D0 / ReadEncodedUInt at 0x004478F0.

        Plain base-128-ish: the lead byte's top bits say the width and the
        rest are the value's top bits -- except for the widest form, where
        the lead is the constant 0xF0 and all four bytes follow it, because a
        32-bit value needing five bytes has no bits to spare.
        """
        b = self.byte()
        if b < 0x80:
            return b
        if b == 0xF0:
            return int.from_bytes(self.raw(4), "big")
        for mask, match, keep, extra in ((0xC0, 0x80, 0x3F, 1),
                                         (0xE0, 0xC0, 0x1F, 2),
                                         (0xF0, 0xE0, 0x0F, 3)):
            if (b & mask) == match:
                v = b & keep
                for _ in range(extra):
                    v = (v << 8) | self.byte()
                return v
        raise Stop("unreadable encoded integer 0x%02X at 0x%X" % (b, self.p - 1))

    def byte(self):
        if self.p >= len(self.d):
            raise Stop("ran off the end at 0x%X" % self.p)
        b = self.d[self.p]
        self.p += 1
        return b

    def raw(self, n):
        if self.p + n > len(self.d):
            raise Stop("ran off the end at 0x%X" % self.p)
        b = self.d[self.p:self.p + n]
        self.p += n
        return b

    def u32(self):
        """Four bytes, big-endian: ReadData fills its destination backwards."""
        return int.from_bytes(self.raw(4), "big")

    def string(self):
        at = self.p
        tag = self.byte()
        if tag == 0x00:
            return ""
        if tag == 0x6E:                               # 'n' -- a new string
            n = self.eu()
            s = self.raw(n).decode("latin1")
            self.strings.append(s)
            return s
        if tag == 0x72:                               # 'r' -- a back-reference
            i = self.eu()
            if i >= len(self.strings):
                raise Stop("string back-reference %d of %d at 0x%X"
                           % (i, len(self.strings), at))
            return self.strings[i]
        raise Stop("bad string tag 0x%02X at 0x%X" % (tag, at))

    # ---- records --------------------------------------------------------

    def type_info(self):
        """ReadTypeInfo: 'o' is one string and NO namespace in these builds."""
        at = self.p
        tag = self.byte()
        if tag == 0x00:
            return None
        if tag == 0x6F:                               # 'o'
            return {"kind": "named", "name": self.string()}
        if tag == 0x73:                               # 's'
            return {"kind": "subtype", "name": self.string()}
        if tag == 0x61:                               # 'a' -- a template
            # ONE subtype, with no count: this AngelScript has no multi-subtype
            # template, so the subtype's own tag follows the name directly.
            name = self.string()
            at = self.p
            form = self.byte()
            if form == 0x73:                          # an object or an enum
                sub = self.type_info()
                handle = self.byte()                  # 'h' handle, 'o' value
                if handle not in (0x68, 0x6F):
                    raise Stop("a template subtype's handle byte at 0x%X is "
                               "0x%02X, which is neither 'h' nor 'o'"
                               % (self.p - 1, handle))
                sub = {"type": sub, "handle": handle == 0x68}
            elif form == 0x74:                        # a primitive token
                sub = {"token": int.from_bytes(self.raw(4), "little")}
            else:
                raise Stop("bad template subtype tag 0x%02X at 0x%X"
                           % (form, at))
            return {"kind": "template", "name": name, "subtype": sub}
        raise Stop("bad type-info tag 0x%02X at 0x%X" % (tag, at))

    def data_type(self):
        """WriteDataType at 0x0044A420 -- and ZERO means a back-reference."""
        token = self.eu()
        if token == 0:
            i = self.eu()
            return (self.datatypes[i] if i < len(self.datatypes)
                    else {"ref": i})
        slot = len(self.datatypes)
        self.datatypes.append(None)
        obj = None
        if token == 5:
            obj = self.type_info()
            self.raw(2)
        flags = self.raw(2)
        dt = {"token": token, "type": obj, "handle": bool(flags[0] & 1)}
        if token == 5 and isinstance(obj, dict) \
                and obj.get("name") == "_builtin_function_":
            dt["funcdef"] = self.function_signature()
        self.datatypes[slot] = dt
        return dt

    def function_signature(self):
        """WriteFunctionSignature at 0x00449A90."""
        name = self.string()
        ret = self.data_type()
        nparams = self.eu()
        if nparams > 0x100:
            raise Stop("implausible parameter count %d at 0x%X"
                       % (nparams, self.p))
        params = [self.data_type() for _ in range(nparams)]
        ninout = self.eu()
        inout = [self.eu() for _ in range(ninout)]
        func_type = self.u32()              # four bytes, +0x87 down to +0x84
        defaults = []
        if self.defaults:
            for _ in range(self.eu()):
                defaults.append(self.string())
        owner = self.type_info()
        traits = self.byte() if owner is not None else None
        return {"name": name, "returns": ret, "params": params,
                "funcType": func_type, "inOut": inout, "defaults": defaults,
                "owner": owner, "traits": traits}

    def function(self):
        """WriteFunction at 0x00449DC0."""
        at = self.p
        tag = self.byte()
        if tag == 0x00:
            return None
        if tag == 0x72:                               # 'r'
            i = self.eu()
            return self.functions[i] if i < len(self.functions) else {"ref": i}
        if tag != 0x66:                               # 'f'
            raise Stop("bad function tag 0x%02X at 0x%X" % (tag, at))
        rec = self.function_signature()
        self.functions.append(rec)
        if rec["funcType"] == 1:
            self.body(rec)
        elif rec["funcType"] == 3:
            self.eu()
        # The record's last field is the SCRIPT SECTION -- the path of the
        # file this function was compiled from -- or one zero byte when there
        # is none, which is every funcdef. That it is one or the other is the
        # check that makes a body shape judgeable: a desynchronised body
        # leaves something else here.
        at = self.p
        section = self.string()
        if section and not section.lower().endswith((".bgt", ".nvgt")):
            raise Stop("a function's script section at 0x%X reads %r, which is "
                       "no source file -- the body before it desynchronised"
                       % (at, section[:40]))
        rec["section"] = section
        if section:
            self.sections.add(section)
        return rec

    def body(self, rec):
        """The funcType-1 body, from WriteFunction's own branch:

            eu(instruction count) ; the instructions
            eu(objVariableTypes count)
            that many x { TypeInfo ; eu(position) ; one byte }
            eu(stackNeeded)
            eu(objVariableInfo count) ; that many x { eu ; eu ; eu }
            eu(lineNumber count) ; that many x eu
        """
        count = self.eu()
        rec["instructions"] = count
        if self.table is None:
            raise Stop("a funcType-1 body at 0x%X declaring %d instructions, "
                       "and no opcode table to step it" % (self.p, count))
        remaining = count                   # DWORDS, not instructions
        while remaining > 0:
            at = self.p
            op = self.byte()
            info = self.table.get(op)
            if info is None:
                raise Stop("opcode 0x%02X at 0x%X is not in this build's table"
                           % (op, at))
            kind = info["type"]
            reads = BC_READS.get(kind)
            if reads is None or kind >= len(BC_DWORDS):
                raise Stop("opcode %s at 0x%X has bytecode type %d, whose "
                           "operand reads are not known"
                           % (info["name"], at, kind))
            for width in reads:
                if width is None:
                    self.eu()
                else:
                    self.raw(width)
            step = BC_DWORDS[kind]
            if step <= 0:
                raise Stop("opcode %s at 0x%X has bytecode type %d, which "
                           "advances nothing" % (info["name"], at, kind))
            remaining -= step
        if remaining < 0:
            raise Stop("the bytecode overran its declared length by %d dword(s)"
                       % -remaining)
        for _ in range(self.eu()):              # object variables
            self.type_info()
            self.eu()
            if self.objvar_three:
                self.byte()
        self.eu()                               # stackNeeded
        for _ in range(self.eu()):              # objVariableInfo
            for _f in range(self.objinfo_fields):
                self.eu()
        if self.line_numbers:
            for _ in range(self.eu()):
                self.eu()

    # ---- the module -----------------------------------------------------

    def walk(self):
        d = self

        enums = d.eu()
        for _ in range(enums):
            name = d.string()
            d.u32()
            d.eu()
            if d.namespace:
                d.string()
            for _v in range(d.eu()):
                d.string()
                d.u32()
            d.notes.append("enum %s" % name)

        classes = []
        for _ in range(d.eu()):
            name = d.string()
            flags = d.u32()
            size = d.eu()
            ns = d.string() if d.namespace else ""
            classes.append({"name": name, "flags": flags, "size": size,
                            "namespace": ns})
        d.notes.append("%d class declarations, to 0x%X" % (len(classes), d.p))

        funcdefs = []
        for _ in range(d.eu()):
            funcdefs.append(d.function())
        d.notes.append("%d funcdef(s), to 0x%X" % (len(funcdefs), d.p))

        # Three passes over the classes, as WriteInner makes them: the
        # interfaces' phase 2, the classes' phase 2, then the classes'
        # property lists. `IsInterface` is `(flags & 0x10000) && size == 0`,
        # read from sub_00440FA0, which is what filters the first two.
        interfaces = [c for c in classes if self.is_interface(c)]
        bodies = [c for c in classes if not self.is_interface(c)]
        for decl in interfaces:
            d.class_phase2(decl)
        for decl in bodies:
            d.class_phase2(decl)
        d.notes.append("%d interface(s) and %d class body(ies), to 0x%X"
                       % (len(interfaces), len(bodies), d.p))
        for decl in bodies:
            d.class_phase3(decl)
        d.notes.append("class properties, to 0x%X" % d.p)

        typedefs = []
        for _ in range(d.eu()):
            typedefs.append(d.string())
            d.u32()                          # flags
            d.eu()                           # size
            d.raw(4)                         # phase 2: the aliased token
        d.notes.append("%d typedef(s), to 0x%X" % (len(typedefs), d.p))

        globals_ = []
        for _ in range(d.eu()):
            name = d.string()
            d.data_type()
            has_init = d.byte()
            if has_init not in (0, 1):
                raise Stop("a global property's init flag at 0x%X is %d, "
                           "which is neither 0 nor 1" % (d.p - 1, has_init))
            if has_init:
                d.function()
            globals_.append(name)
        d.notes.append("%d global propert(ies), to 0x%X"
                       % (len(globals_), d.p))

        module_funcs = [d.function() for _ in range(d.eu())]
        d.notes.append("%d module function(s), to 0x%X"
                       % (len(module_funcs), d.p))
        global_funcs = [d.function() for _ in range(d.eu())]
        d.notes.append("%d global function(s), to 0x%X"
                       % (len(global_funcs), d.p))
        binds = []
        for _ in range(d.eu()):
            binds.append((d.function(), d.string()))
        d.notes.append("%d bind info, to 0x%X" % (len(binds), d.p))
        used = [d.type_info() for _ in range(d.eu())]
        d.notes.append("%d usedTypes, to 0x%X" % (len(used), d.p))

        # The value types among them, with their sizes, so a module built
        # against a different build of a value type is refused rather than
        # mis-read.
        value_types = d.eu()
        for _ in range(value_types):
            d.eu()                           # the index into usedTypes
            d.eu()                           # that type's size
        d.notes.append("%d value type size(s), to 0x%X"
                       % (value_types, d.p))

        type_ids = [d.data_type() for _ in range(d.eu())]
        d.notes.append("%d usedTypeIds, to 0x%X" % (len(type_ids), d.p))

        used_funcs = []
        for _ in range(d.eu()):
            d.byte()                         # where the function comes from
            used_funcs.append(d.function_signature())
        d.notes.append("%d usedFunctions, to 0x%X" % (len(used_funcs), d.p))

        used_props = []
        for _ in range(d.eu()):
            used_props.append(d.string())
            d.data_type()
            d.byte()
        d.notes.append("%d usedGlobalProps, to 0x%X" % (len(used_props), d.p))

        literals = [d.string() for _ in range(d.eu())]
        d.notes.append("%d usedStringConstants, to 0x%X"
                       % (len(literals), d.p))

        obj_props = []
        for _ in range(d.eu()):
            d.type_info()
            obj_props.append(d.string())
        d.notes.append("%d usedObjectProps, to 0x%X" % (len(obj_props), d.p))
        if d.p != len(d.d):
            raise Stop("the tail ended at 0x%X of 0x%X, not exactly on EOF"
                       % (d.p, len(d.d)))
        return classes, funcdefs

    #: This generation's script-object flag, from sub_00440FA0.
    SCRIPT_OBJECT = 0x00010000

    def is_interface(self, decl):
        """IsInterface: the script-object flag set AND a size of zero."""
        return bool(decl["flags"] & self.SCRIPT_OBJECT) and decl["size"] == 0

    def class_phase3(self, decl):
        """The property list, WriteTypeDeclaration's phase 3."""
        for _ in range(self.eu()):
            self.string()                    # the property's name
            self.data_type()
            self.byte()                      # private / inherited

    def class_phase2(self, decl):
        """WriteTypeDeclaration's phase 2 for a class, at 0x0044AE9E."""
        self.type_info()                     # derivedFrom
        for _ in range(self.eu()):           # interfaces
            self.type_info()
        self.function()                      # three behaviours
        self.function()
        self.function()
        for _ in range(self.eu()):           # constructors and factories
            self.function()
            self.function()
        for _ in range(self.eu()):           # methods
            self.function()
        for _ in range(self.eu()):           # the virtual table
            self.function()


#: The per-build answers this reader already holds, tried first so that
#: adding a trial cannot silently re-describe a module that already landed
#: on EOF -- the same rule every per-build field in this project follows.
VERIFIED = {"namespace": False, "defaults": True, "objvar_three": True,
            "objinfo_fields": 3, "line_numbers": True}


def _candidates():
    """Every per-build combination, the verified answers first."""
    seen = []
    for namespace in (False, True):
        for defaults in (True, False):
            for three in (True, False):
                for fields in (3, 2, 1):
                    for lines in (True, False):
                        seen.append({"namespace": namespace,
                                     "defaults": defaults,
                                     "objvar_three": three,
                                     "objinfo_fields": fields,
                                     "line_numbers": lines})
    seen.sort(key=lambda c: c != VERIFIED)
    return seen


def summarize(data, table=None):
    """Walk an early module, trialling the fields that vary per build.

    Returns a dict carrying the per-build answers that won, how far the walk
    got, the source files the module named and the section counts. `eof` is
    the claim that matters: a walk that lands exactly on EOF has validated
    every field width upstream of it, because nothing follows the last table
    to absorb a mistake.
    """
    best = None
    for combo in _candidates():
        d = Early(data, namespace=combo["namespace"],
                  defaults=combo["defaults"], table=table)
        d.objvar_three = combo["objvar_three"]
        d.objinfo_fields = combo["objinfo_fields"]
        d.line_numbers = combo["line_numbers"]
        try:
            d.walk()
            stop = None
        except Stop as exc:
            stop = str(exc)
        out = dict(combo)
        out.update({"at": d.p, "size": len(data), "eof": d.p == len(data),
                    "error": stop, "sections": sorted(d.sections),
                    "notes": list(d.notes)})
        if out["eof"] and stop is None:
            return out
        key = (len(d.sections), d.p)
        if best is None or key > best[0]:
            best = (key, out)
    return best[1] if best else None


def main():
    paths = [a for a in sys.argv[1:] if not a.startswith("--")]
    # The opcode table comes from the game's own runtime, named by BGT_EXE --
    # the same way `as_module` is given one.
    exe = os.environ.get("BGT_EXE")
    table = None
    if exe:
        try:
            from . import as_opcodes
        except ImportError:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import as_opcodes
        table = as_opcodes.extract(exe)["table"]
    for path in paths:
        with open(path, "rb") as fh:
            data = fh.read()
        print("== %s  %d bytes" % (os.path.basename(path), len(data)))
        out = summarize(data, table)
        print("   namespace=%-5s defaults=%-5s objvar3=%-5s objinfo=%d "
              "lines=%-5s"
              % (out["namespace"], out["defaults"], out["objvar_three"],
                 out["objinfo_fields"], out["line_numbers"]))
        print("   reached 0x%X of 0x%X (%.1f%%)%s"
              % (out["at"], out["size"], 100.0 * out["at"] / out["size"],
                 "  -- EXACTLY ON EOF" if out["eof"] else ""))
        if out["error"]:
            print("   %s" % out["error"])
        for name in out["sections"]:
            print("      source file  %s" % name)
        for note in out["notes"]:
            print("      %s" % note)


if __name__ == "__main__":
    main()
