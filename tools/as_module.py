"""
as_module -- reader for the AngelScript module that BGT embeds in a game executable.

Two serialization dialects turn up across Aaron Baker's BGT titles, and they differ
only in how a string is written. Everything else -- big-endian integers, the encoded
varint, the record layouts -- is shared.

    TAGGED   (Psycho Strike, Paladin of the Sky)
        0x00        empty
        0x6E 'n'    new string:  eu(len) then len bytes, appended to savedStrings
        0x72 'r'    back-ref:    eu(index) into savedStrings

    LEN2     (Manamon 2 -- newer AngelScript)
        eu(v); v even -> new string of v/2 bytes, appended to savedStrings
               v odd  -> back-reference to savedStrings[(v-1)/2]

Which one a module uses is detected, not assumed: only one of them parses the enum
section to its declared member counts and lands on a coherent boundary.

Ground truth for the record layouts is asCReader in the game's own binary; see
STRIKE-DECOMP.md for the Psycho Strike derivation, which this follows.
"""

import re
import struct
from typing import Any, Dict, List, Optional, Tuple

ASOBJ_SHARED        = 0x00400000   # read from asCReader::ReadTypeDeclaration
ASOBJ_SCRIPT_OBJECT = 0x00200000
ASOBJ_ENUM          = 0x04000000
ASOBJ_TYPEDEF       = 0x10000000

# The script-object flag MOVED between the two AngelScript versions: the older
# build tests 0x00100000 where the newer one tests 0x00200000. Read out of
# ReadTypeDeclaration phase 2 in each binary --
#   strike.exe  0x0041EAA0:  if ((flags & 0x100000) && size == 0) -> interface
#   rpg.exe     0x0042ACC0:  if ((flags & 0x200000) && size == 0) -> interface
# It decides whether a class block has a behaviour section, so using the wrong
# one desynchronises on the first interface and everything after it is garbage.
ASOBJ_SCRIPT_OBJECT_TAGGED = 0x00100000

TAGGED = "tagged"
LEN2 = "len2"

IDENT = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")


class ParseError(Exception):
    pass


# (mask, match, value bits kept from the lead byte, extra bytes to read)
_ENC_WIDTHS = (
    (0x7F, 0x7F, 0x00, 8),
    (0x7E, 0x7E, 0x01, 6),
    (0x7C, 0x7C, 0x03, 5),
    (0x78, 0x78, 0x07, 4),
    (0x70, 0x70, 0x0F, 3),
    (0x60, 0x60, 0x1F, 2),
    (0x40, 0x40, 0x3F, 1),
)


def read_encoded_uint(buf: bytes, p: int) -> Tuple[int, int]:
    """AngelScript's ReadEncodedUInt64.

    This is NOT the UTF-8-style continuation-bit scheme it superficially resembles.
    The top bit of the lead byte is a **sign** flag; the width is encoded as a
    run of set bits below it, and the remaining low bits are the value's high bits:

        0xxxxxxx                     value = b            (0..63)
        10xxxxxx +1 byte             value = (b&0x3F)<<8  | next
        110xxxxx +2 bytes            ... and so on

    Getting this wrong is quiet rather than loud. Values under 64 encode as a
    single byte either way, so a wrong decoder handles the overwhelming majority
    of lengths and counts correctly and only desynchronises on the first value
    >= 64 -- which in a real module can be thousands of records in.
    """
    b = buf[p]
    p += 1
    negative = b & 0x80
    b &= 0x7F

    v = b
    for mask, match, keep, extra in _ENC_WIDTHS:
        if (b & mask) == match:
            v = b & keep                       # keep == 0 for the full 8-byte form
            for _ in range(extra):
                v = (v << 8) | buf[p]
                p += 1
            break
    return (-v if negative else v), p


class Reader:
    def __init__(self, data: bytes, dialect: str, pos: int = 0,
                 opcodes: Optional[Dict[int, Dict[str, Any]]] = None,
                 template_namespace: bool = True) -> None:
        self.d = data
        self.dialect = dialect
        self.p = pos
        # Whether ReadTypeInfo's 'a' (template) form carries a namespace string
        # after the name. It does in Psycho Strike and Manamon 2 and does NOT in
        # Paladin of the Sky -- three builds, two answers, so this is a per-build
        # variation rather than a per-dialect one and is settled by trial parse
        # against the exact-EOF landing, not assumed. Compare, in each binary's
        # ReadTypeInfo: strike 0x00420970 calls ReadString twice under 'a',
        # paladin 0x0041F560 calls it once.
        self.template_namespace = template_namespace
        self.saved: List[bytes] = []          # savedStrings
        self.types: List[Any] = []            # savedDataTypes
        self.functions: List[Any] = []        # savedFunctions
        self.opcodes = opcodes   # from as_opcodes.extract(); needed for bodies
        # Function bodies that failed to parse, with where and why. A body is the
        # one record where recovery is worth attempting: the enum and declaration
        # sections are strictly sequential, so a desync there means the whole
        # parse is wrong and skipping ahead would only hide it.
        self.parse_errors: List[Dict[str, Any]] = []
        # Optional field trace: every primitive this reader consumes, in
        # order, so as_write can replay it back into bytes. Off by default;
        # `trace_module()` turns it on. `_mute` suppresses the sub-reads a
        # composite field makes, so a string records one entry rather than
        # its length and its bytes separately.
        self.trace: Optional[List[Tuple]] = None
        self._mute = 0

    # -- primitives ---------------------------------------------------------
    def _emit(self, *entry: Any) -> None:
        """Record a composite field, ignoring the mute its parts set."""
        if self.trace is not None:
            self.trace.append(entry)

    def _rec(self, *entry: Any) -> None:
        if self.trace is not None and not self._mute:
            self.trace.append(entry)

    def eu(self) -> int:
        v, self.p = read_encoded_uint(self.d, self.p)
        self._rec("eu", v)
        return v

    def u32(self) -> int:
        v = struct.unpack_from(">I", self.d, self.p)[0]
        self.p += 4
        self._rec("u32", v)
        return v

    def i32(self) -> int:
        v = struct.unpack_from(">i", self.d, self.p)[0]
        self.p += 4
        self._rec("i32", v)
        return v

    def raw(self, n: int) -> bytes:
        """Consume n bytes verbatim -- flags, traits and tag bytes.

        Every such skip goes through here rather than bumping the cursor
        directly, because a byte the reader steps over silently is a byte the
        writer cannot reproduce.
        """
        b = self.d[self.p:self.p + n]
        self.p += n
        self._rec("raw", b)
        return b

    def string(self) -> bytes:
        self._mute += 1
        try:
            return self._string()
        finally:
            self._mute -= 1

    def _string(self) -> bytes:
        if self.dialect == LEN2:
            v = self.eu()
            # The encoding carries a sign bit. Lengths and table indices are
            # unsigned, so a negative here means we are not looking at a string --
            # and left unchecked it would drive the cursor backwards and loop.
            if v < 0:
                raise ParseError("negative string length %d at 0x%X" % (v, self.p))
            if v % 2 == 0:
                n = v // 2
                s = self.d[self.p:self.p + n]
                self.p += n
                if n:
                    self.saved.append(s)
                    self._emit("strnew", s)
                else:
                    self._emit("strempty")
                return s
            i = (v - 1) // 2
            self._emit("strref", i)
            return self.saved[i] if i < len(self.saved) else b"<ref%d>" % i

        tag = self.d[self.p]
        self.p += 1
        if tag == 0x00:
            self._emit("strempty")
            return b""
        if tag == 0x6E:          # 'n' -- new
            n = self.eu()
            s = self.d[self.p:self.p + n]
            self.p += n
            self.saved.append(s)
            self._emit("strnew", s)
            return s
        if tag == 0x72:          # 'r' -- back-reference
            i = self.eu()
            self._emit("strref", i)
            return self.saved[i] if i < len(self.saved) else b"<ref%d>" % i
        raise ParseError("bad string tag 0x%02X at 0x%X" % (tag, self.p - 1))

    # -- records ------------------------------------------------------------
    def type_decl_phase1(self) -> Dict[str, Any]:
        """asCReader::ReadTypeDeclaration phase 1 -- shared by every type kind.

            str(name) u32(flags) eu(size) str(ns) [ u8 if flags & asOBJ_SHARED ]

        Enums, classes and interfaces all enter through this same function, so the
        class section's declaration records have exactly the enum layout; only the
        later phases differ.
        """
        name = self.string()
        if not IDENT.match(name):
            raise ParseError("type name %r is not an identifier at 0x%X"
                             % (name[:24], self.p))
        flags = self.u32()
        size = self.eu()
        ns = self.string()
        # The newer reader has a conditional byte here ('e' = the type already
        # existed and was reused, or ' '); the older one has no such read at all.
        # Neither fires in practice -- no BGT type sets asOBJ_SHARED -- so this
        # is correctness rather than a fix.
        if self.dialect != TAGGED and flags & ASOBJ_SHARED:
            self.raw(1)
        return {"name": name.decode("latin1"), "flags": flags, "size": size,
                "namespace": ns.decode("latin1")}

    def type_info(self) -> Optional[Dict[str, Any]]:
        """asCReader::ReadTypeInfo -- a reference to a type, five tagged forms.

            0x00        null
            'o' 0x6F    named type:      str(name) str(ns)
            'a' 0x61    template:        str(name) str(ns) eu(nSub)
                                         nSub x { u8 tag; 's' -> datatype
                                                           else -> eu(typeId) }
            's' 0x73    template subtype by name: str(name)
            'l' 0x6C    list pattern:    recurses into ReadTypeInfo
            'c' 0x63    class-scoped child: str(name) then ReadTypeInfo

        The 'c' form is not in the older Psycho Strike model -- it names a type
        declared inside another type, and skipping it desynchronises immediately.
        """
        tag = self.raw(1)[0]
        if tag == 0x00:
            return None
        if tag == 0x6F:                      # 'o'
            return {"kind": "named", "name": self.string().decode("latin1"),
                    "namespace": self.string().decode("latin1")}
        if tag == 0x73:                      # 's'
            return {"kind": "subtype", "name": self.string().decode("latin1")}
        if tag == 0x6C:                      # 'l'
            return {"kind": "listpattern", "of": self.type_info()}
        if tag == 0x63:                      # 'c'
            name = self.string().decode("latin1")
            return {"kind": "child", "name": name, "owner": self.type_info()}
        if tag == 0x61:                      # 'a'
            name = self.string().decode("latin1")
            ns = self.string().decode("latin1") if self.template_namespace else ""
            n = self.eu()
            if not 0 <= n <= 64:
                raise ParseError("implausible subtype count %d at 0x%X" % (n, self.p))
            subs = []
            for _ in range(n):
                sub = self.raw(1)[0]
                # 's' introduces a whole ReadDataType, in BOTH dialects -- and
                # that data type is very often a one-byte back-reference, which
                # is what makes the alternative ("tag plus one encoded value")
                # look right for a while. Psycho Strike settles it: the
                # character constructor's third object variable is
                #   61 'a' r231="array" 00 01 73 | 00 05 6f r197 00 01
                # whose subtype is a full data type -- new, token 5, object
                # `object`, flags 1 -- giving array<object@>. Read as tag+eu it
                # swallows two bytes and every later record is lost.
                subs.append(self.data_type() if sub == 0x73
                            else {"typeid": self.eu()})
            return {"kind": "template", "name": name, "namespace": ns, "subtypes": subs}
        raise ParseError("bad type-info tag 0x%02X at 0x%X" % (tag, self.p - 1))

    def data_type(self) -> Dict[str, Any]:
        """asCReader::ReadDataType.

            eu(v);  v != 0 -> back-reference to savedDataTypes[v - 1]
                    v == 0 -> eu(tokenType)
                              [ ReadTypeInfo ]   only when tokenType == 5
                              u8 flags           always exactly ONE byte

        The slot in savedDataTypes is reserved *before* the object type is read, so
        a nested type takes a later index than its parent. Appending afterwards
        gets the numbering subtly wrong.
        """
        v = self.eu()
        if v != 0:
            i = v - 1
            return self.types[i] if i < len(self.types) else {"ref": i}

        slot = len(self.types)
        self.types.append(None)                  # reserve, then patch
        token = self.eu()
        obj = self.type_info() if token == 5 else None

        # ALWAYS exactly one byte, in both dialects. An early Psycho Strike model
        # had this as two bytes for object types; decoding menu_callback byte by
        # byte shows it is one -- the apparent second byte was the namespace
        # string that ReadTypeInfo had already consumed.
        flags = self.raw(1)[0]

        # The older reader recurses into ReadFunctionSignature when the object
        # type is the placeholder `_builtin_function_` -- that is how it stores a
        # funcdef-typed value, so a `menu_callback@` parameter embeds an entire
        # nested signature right here. The newer build names the funcdef type
        # directly and has no such case.
        nested = None
        if (self.dialect == TAGGED and token == 5
                and isinstance(obj, dict)
                and obj.get("name") == "_builtin_function_"):
            nested = self.function_signature()

        dt = {"token": token, "type": obj,
              "handle": bool(flags & 1), "const": bool(flags & 2),
              "reference": bool(flags & 4), "readonly": bool(flags & 8)}
        if nested is not None:
            dt["funcdef"] = nested
        self.types[slot] = dt
        return dt

    def bytecode(self) -> Tuple[int, Tuple[int, int]]:
        """asCReader::ReadByteCode -- returns (instruction count, raw span).

        The leading length is an **instruction count, not a dword count**: the
        loop decrements by one per instruction. Reading it as bytes or dwords
        lands inside the stream and every later record is lost.
        """
        if self.opcodes is None:
            raise ParseError("bytecode needs an opcode table (as_opcodes.extract)")
        self._mute += 1
        try:
            count = self.eu()
        finally:
            self._mute -= 1
        if count < 0 or count > 1 << 20:
            raise ParseError("implausible instruction count %d" % count)
        # Recorded as a marker rather than a plain integer: the writer recounts
        # the instructions that follow, so inserting or removing one keeps the
        # declared count correct. It is a count of INSTRUCTIONS, not dwords.
        self._emit("opcount", count)
        start = self.p
        for _ in range(count):
            op = self.d[self.p]
            self.p += 1
            info = self.opcodes.get(op)
            if info is None:
                raise ParseError("unknown opcode 0x%02X at 0x%X" % (op, self.p - 1))
            self._mute += 1
            try:
                args = [self.eu() for _ in range(info["operands"])]
            finally:
                self._mute -= 1
            self._emit("op", op, args)
        return count, (start, self.p)

    def function_signature(self) -> Dict[str, Any]:
        """asCReader::ReadFunctionSignature."""
        name = self.string()
        if name == b"$dlgte":
            # The delegate factory copies its whole signature from the engine's
            # registered one and reads nothing further from the stream.
            return {"name": "$dlgte", "funcType": None, "params": [], "owner": None}

        ret = self.data_type()
        nparams = self.eu()
        if not 0 <= nparams <= 0x100:
            raise ParseError("implausible parameter count %d" % nparams)
        params = [self.data_type() for _ in range(nparams)]

        # Both variable-length lists are guarded by `paramCount != 0` in the newer
        # reader and written unconditionally by the older one. A zero-parameter
        # function is therefore two bytes shorter under the newer model, and
        # reading it the wrong way takes the *next* field as funcType -- which is
        # how the tagged titles used to die on their very first funcdef.
        guarded = self.dialect != TAGGED

        if nparams or not guarded:               # inOutFlags
            n = self.eu()
            if nparams and n > nparams:
                raise ParseError("inOutFlag count %d > %d params" % (n, nparams))
            for _ in range(n):
                self.eu()

        func_type = self.eu()

        if nparams or not guarded:               # default-argument expressions
            n = self.eu()
            if nparams and n > nparams:
                raise ParseError("default-arg count %d > %d params" % (n, nparams))
            for _ in range(n):
                self.string()

        owner = self.type_info()
        if owner is not None:
            self.raw(1)                          # traits byte: private/protected/const
            ns = None
        elif func_type == 4 and self.dialect != TAGGED:   # a funcdef with no owner
            tag = self.raw(1)[0]
            if tag == 0x6F:                      # 'o' -- an owning type follows
                self.type_info()
                ns = None
            elif tag == 0x6E:                    # 'n' -- a namespace string follows
                ns = self.string().decode("latin1")
            else:
                raise ParseError("bad funcdef tag 0x%02X at 0x%X" % (tag, self.p - 1))
        else:
            ns = self.string().decode("latin1")

        return {"name": name.decode("latin1"), "returns": ret, "params": params,
                "funcType": func_type, "owner": owner, "namespace": ns}

    def _script_body_tagged(self, rec: Dict[str, Any]) -> None:
        """The older reader's funcType-1 body (strike.exe 0x0041E2A0).

        Structurally different from the newer one, not just differently encoded:

            <bytecode>                      <- NO leading flags byte
            eu(stackNeeded)
            eu(nObjVar)
            nObjVar x { typeinfo, eu, eu }  <- THREE fields, not two
            if nObjVar > 0: eu(objVariablesOnHeap)
            eu(nObjInfo)                    <- unconditional, not nested
            nObjInfo x { eu, eu, eu }
            if noDebugInfo == 0: <debug info>

        The newer build gates all of this behind a flags byte (0x04 body omitted,
        0x08 object variables present, 0x10 try/catch present). The older build
        has no such byte and no try/catch block at all -- so reading a flags byte
        here consumes the first byte of the instruction count, and every count
        after it is wrong.
        """
        rec["instructions"], rec["body"] = self.bytecode()
        rec["stackNeeded"] = self.eu()

        nobj = self.eu()
        if not 0 <= nobj <= 1 << 16:
            raise ParseError("implausible object-variable count %d" % nobj)
        objvars = []
        for _ in range(nobj):
            objvars.append((self.type_info(), self.eu(), self.eu()))
        rec["objVars"] = objvars
        if nobj > 0:
            self.eu()                            # objVariablesOnHeap

        ninfo = self.eu()
        if not 0 <= ninfo <= 1 << 18:
            raise ParseError("implausible object-info count %d" % ninfo)
        for _ in range(ninfo):
            self.eu()
            self.eu()
            self.eu()
        # debug info follows only when noDebugInfo == 0, and BGT always strips it

        # ...and then ONE trailing traits byte (bit 0 read-only, bit 1 private),
        # read unconditionally and *outside* the debug-info block. The 2/3/4
        # funcTypes jump straight past it. Missing it leaves the constructor
        # exactly one byte short, which puts the factory record that follows one
        # byte out and takes the whole class block with it.
        rec["traits"] = self.raw(1)[0]

    def function(self) -> Optional[Dict[str, Any]]:
        """asCReader::ReadFunction. Returns None for the 'no function' marker."""
        tag = self.raw(1)[0]
        if tag == 0x00:
            return None
        if tag == 0x72:                          # 'r' -- back-reference
            i = self.eu()
            return self.functions[i] if i < len(self.functions) else {"ref": i}
        if tag != 0x66:                          # 'f' -- full record
            raise ParseError("bad function tag 0x%02X at 0x%X" % (tag, self.p - 1))

        rec = {}
        self.functions.append(rec)               # reserve before reading, for back-refs
        rec.update(self.function_signature())
        ft = rec["funcType"]

        if ft == 1 and self.dialect == TAGGED:
            self._script_body_tagged(rec)
        elif ft == 1:                            # a script function
            flags = self.raw(1)[0]
            rec["flags"] = flags
            rec["existing"] = bool(flags & 0x04)
            if not flags & 0x04:                 # 0x04 => body omitted entirely
                rec["instructions"], rec["body"] = self.bytecode()
                rec["stackNeeded"] = self.eu()
                if flags & 0x08:
                    nobj = self.eu()
                    rec["objVars"] = []
                    for _ in range(nobj):
                        rec["objVars"].append((self.type_info(), self.eu()))
                    if nobj > 0:
                        self.eu()                # objVariablesOnHeap
                    ninfo = self.eu()            # NOTE: inside the 0x08 block
                    for _ in range(ninfo):
                        self.eu(), self.eu(), self.eu()
                if flags & 0x10:
                    for _ in range(self.eu()):   # try/catch spans
                        self.eu(), self.eu()
                # debug info follows only when noDebugInfo == 0
        elif ft in (2, 3):
            rec["vfTableIdx"] = self.eu()
        elif ft == 4 and self.dialect != TAGGED:
            self.raw(1)                          # funcdef traits byte; newer builds only
        return rec

    def _looks_like_function_start(self, p: int) -> bool:
        """Would a function record plausibly begin at `p`?

        Cheap shape test used only by the resynchroniser. A record opens with
        0x66 'f' (full, then a string), 0x72 'r' (back-reference, then an index)
        or 0x00 (the null marker). Requiring whatever follows to validate -- an
        identifier-shaped name, or an in-range table index -- is what keeps this
        from latching onto a stray byte inside a bytecode span.

        **0x00 is deliberately not an anchor.** It is a whole record on its own,
        so there is nothing after it to check, and NUL bytes are dense in this
        format -- accepting it means resync stops a byte or two into the record
        it was supposed to skip and reports success while still desynchronised.
        """
        if p >= len(self.d):
            return False
        tag = self.d[p]
        if tag not in (0x66, 0x72):
            return False
        probe = Reader(self.d, self.dialect, p + 1, opcodes=self.opcodes)
        probe.saved = self.saved                 # back-refs resolve against ours
        try:
            if tag == 0x72:
                i = probe.eu()
                return 0 <= i < len(self.saved)
            return bool(IDENT.match(probe.string()))
        except (ParseError, IndexError, struct.error):
            return False

    def resync_to_function(self, limit: int = 1 << 16) -> int:
        """Scan forward for the next plausible function record. Returns bytes skipped.

        Only ever called after a body has already failed. Raises if it cannot
        find one inside `limit` -- silently running to EOF would turn a local
        failure into an empty parse that still looks like a success.
        """
        start = self.p
        end = min(len(self.d), start + limit)
        p = start + 1
        while p < end:
            if self._looks_like_function_start(p):
                self.p = p
                return p - start
            p += 1
        raise ParseError("no function record within %d bytes of 0x%X"
                         % (limit, start))

    def function_or_error(self, *context: Any) -> Optional[Dict[str, Any]]:
        """ReadFunction, but a failed body is recorded and skipped rather than fatal.

        One malformed body out of 200 should cost one function, not the other
        199. The error carries the offset it failed at and how many bytes were
        skipped to recover, so a run of these is visibly a systematic format
        problem rather than isolated corruption.

        `context` is passed as unformatted pieces and only joined on the error
        path -- a large module runs this several hundred thousand times, and
        building a label for each one costs more than the parse.
        """
        at = self.p
        try:
            return self.function()
        except (ParseError, IndexError, struct.error) as exc:
            err: Dict[str, Any] = {"context": " ".join(str(c) for c in context),
                                   "offset": at,
                                   "error": "%s: %s" % (type(exc).__name__, exc)}
            self.p = at
            try:
                err["skipped"] = self.resync_to_function()
            except ParseError as exc2:
                err["skipped"] = None
                self.parse_errors.append(err)
                raise exc2
            self.parse_errors.append(err)
            return None

    @property
    def script_object_flag(self) -> int:
        return (ASOBJ_SCRIPT_OBJECT_TAGGED if self.dialect == TAGGED
                else ASOBJ_SCRIPT_OBJECT)

    def is_interface(self, decl: Dict[str, Any]) -> bool:
        """AngelScript's IsInterface(): a script object with no instance size."""
        return (decl["flags"] & self.script_object_flag) != 0 and decl["size"] == 0

    def _count(self, limit: int = 8192) -> int:
        n = self.eu()
        if not 0 <= n <= limit:
            raise ParseError("implausible count %d at 0x%X" % (n, self.p))
        return n

    def class_block(self, decl: Dict[str, Any]) -> Dict[str, Any]:
        """asCReader::ReadTypeDeclaration phase 2 for a class or interface.

            typeinfo(derivedFrom)
            eu(nInterfaces)
            nInterfaces x { typeinfo, [ eu ]        <- the eu only for non-interfaces }
            if not interface/typedef/enum:
                ReadFunction(destructor)            <- usually the null marker
                eu(nCtor)
                nCtor x { ReadFunction, ReadFunction }   <- constructor + factory
            eu(nMethods)   nMethods x ReadFunction
            eu(nVirtual)   nVirtual x ReadFunction

        The behaviour block is skipped for interfaces, but the method and virtual
        lists are NOT -- returning early on an interface is what makes this look
        like a broken format rather than a missing branch.
        """
        out = {"name": decl["name"], "derivedFrom": self.type_info(),
               "interfaces": [], "ctors": [], "methods": [], "virtuals": []}
        iface = self.is_interface(decl)
        for _ in range(self._count(256)):
            out["interfaces"].append(self.type_info())
            # The newer reader skips the vftable offset when the *declaring*
            # type is itself an interface; the older one always reads it.
            if not iface or self.dialect == TAGGED:
                self.eu()                       # interface vftable offset

        flags = decl["flags"]
        name = decl["name"]
        if not (iface or flags == ASOBJ_TYPEDEF or flags == ASOBJ_ENUM):
            out["destructor"] = self.function_or_error(name, "destructor")
            for _ in range(self._count()):
                out["ctors"].append((
                    self.function_or_error(name, "constructor"),
                    self.function_or_error(name, "factory")))

        for i in range(self._count()):
            out["methods"].append(
                self.function_or_error(name, "method", i))
        for i in range(self._count()):
            out["virtuals"].append(
                self.function_or_error(name, "virtual", i))
        return out

    def object_property(self) -> Dict[str, Any]:
        """asCReader::ReadObjectProperty -- str(name) datatype eu(flags).

        flags is a bitfield: bit0 private, bit1 protected, bit2 inherited.
        """
        name = self.string()
        dt = self.data_type()
        return {"name": name.decode("latin1"), "type": dt, "flags": self.eu()}

    def class_phase3(self, decl: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Phase 3 -- the class's own property table."""
        return [self.object_property() for _ in range(self._count())]

    def class_blocks(self, decls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Walk every class block.

        asCReader::ReadInner makes THREE passes over the class list, not one block
        per class: phase 2 for interfaces, then phase 2 for everything else, then
        **phase 3** for everything else. Interleaving them desynchronises on the
        first interface; skipping phase 3 leaves the property tables in the stream,
        where they read convincingly as the next section and quietly corrupt it.
        """
        interfaces = [c for c in decls if self.is_interface(c)]
        others = [c for c in decls if not self.is_interface(c)]
        blocks = ([self.class_block(c) for c in interfaces]
                  + [self.class_block(c) for c in others])
        by_name = {b["name"]: b for b in blocks}
        for c in others:
            props = self.class_phase3(c)
            if c["name"] in by_name:
                by_name[c["name"]]["properties"] = props
        return blocks

    # -- the tail sections -------------------------------------------------
    #
    # Everything from here to EOF is what ReadInner reads after the three class
    # passes, in this order (FUN_00427ab0, reading the calls straight down):
    #
    #     typedefs                eu(n)  n x { phase1, eu(tokenType) }
    #     global properties       eu(n)  n x ReadGlobalProperty   FUN_0042c430
    #     module functions        eu(n)  n x ReadFunction         FUN_0042a2f0
    #     global functions        eu(n)  n x ReadFunction
    #     bind/import info        eu(n)  n x { ReadFunction, ReadString }
    #     usedTypes               eu(n)  n x ReadTypeInfo         FUN_0042c870
    #     usedTypeIds             eu(n)  n x ReadDataType         FUN_0042d8f0
    #     usedFunctions           eu(n)  n x { u8 tag, signature } FUN_004294b0
    #     usedGlobalProps         eu(n)  n x { str str datatype u8 } FUN_0042d980
    #     usedStringConstants     eu(n)  n x str                  FUN_004293e0
    #     usedObjectProps         eu(n)  n x { typeinfo, eu }     FUN_0042dc10
    #
    # The last one must finish EXACTLY at EOF. That single constraint is what
    # makes the whole chain self-verifying: there is nothing after it to absorb
    # a mistake, so any wrong field width anywhere upstream shows up as an
    # overshoot or a remainder rather than as plausible-looking output.

    def global_property(self) -> Dict[str, Any]:
        """asCReader::ReadGlobalProperty (FUN_0042c430).

            str(name) str(ns) datatype ReadFunction

        The trailing ReadFunction is the variable's initialisation function, and
        it is usually the 0x00 'no function' marker. It is a full ReadFunction --
        so a global with an initialiser carries a whole function body here, and
        skipping it walks straight into the middle of one.
        """
        name = self.string()
        ns = self.string()
        dt = self.data_type()
        init = self.function_or_error(name.decode("latin1"), "initialiser")
        return {"name": name.decode("latin1"), "namespace": ns.decode("latin1"),
                "type": dt, "init": init}

    def used_function(self) -> Optional[Dict[str, Any]]:
        """One usedFunctions record (FUN_004294b0).

            u8 tag  +  ReadFunctionSignature

        The tag says where the function came from -- 'a' (0x61) application /
        engine-registered, 'm' (0x6D) module -- and a null entry is written as
        0x00 in the newer build and 'n' (0x6E) in the older one. Only the null
        case skips the signature.

        This is the table that names CALL / CALLSYS / CALLINTF operands, which is
        the difference between a disassembly that is readable and one that is
        merely decodable.
        """
        tag = self.raw(1)[0]
        if tag in (0x00, 0x6E):                  # null entry -- nothing follows
            return None
        rec = self.function_signature()
        rec["origin"] = {0x61: "application", 0x6D: "module"}.get(tag, chr(tag))
        return rec

    def used_global_prop(self) -> Dict[str, Any]:
        """One usedGlobalProps record (FUN_0042d980) -- str str datatype u8.

        Note this is NOT ReadObjectProperty: it carries a namespace and ends in a
        plain byte (isModuleProperty), where an object property has no namespace
        and ends in an encoded flags field. The two are close enough in shape that
        substituting one parses for a while before drifting.
        """
        name = self.string()
        ns = self.string()
        dt = self.data_type()
        module_prop = self.raw(1)[0]
        return {"name": name.decode("latin1"), "namespace": ns.decode("latin1"),
                "type": dt, "module": bool(module_prop)}

    def used_object_prop(self) -> Dict[str, Any]:
        """One usedObjectProps record -- typeinfo, then the property.

        Indexed by ADDSi / LoadThisR, so it is what turns a member access into
        `this->health` instead of `+36`.

        The two builds identify the property differently: the newer one writes
        an encoded index into the owner's property table, the older one writes
        the property's **name** as a string. Reading the older form as an index
        takes one byte where a string tag plus its payload was written, so the
        section drifts and cannot land on EOF.
        """
        owner = self.type_info()
        if self.dialect == TAGGED:
            return {"owner": owner, "name": self.string().decode("latin1")}
        return {"owner": owner, "index": self.eu()}

    def tail(self, verify_eof: bool = True) -> Dict[str, Any]:
        """Read every section from the typedefs to EOF.

        Returns the tables plus a per-section (offset, count) map, so a caller can
        see exactly where each one landed -- which is how a wrong field width is
        localised rather than merely detected.
        """
        out: Dict[str, Any] = {}
        where: List[Tuple[str, int, int]] = []

        def section(name, count, read):
            start = self.p
            items = [read() for _ in range(count)]
            where.append((name, start, count))
            out[name] = items
            return items

        # typedefs -- phase 1 then phase 2, which for a typedef is a single
        # encoded token type (the primitive it aliases).
        n = self._count(4096)
        section("typedefs", n, lambda: (self.type_decl_phase1(), self.eu())[0])

        section("global_properties", self._count(1 << 18), self.global_property)
        section("module_functions", self._count(1 << 18),
                lambda: self.function_or_error("module function"))
        section("global_functions", self._count(1 << 18),
                lambda: self.function_or_error("global function"))
        section("bind_info", self._count(1 << 16),
                lambda: (self.function(), self.string())[0])
        section("used_types", self._count(1 << 18), self.type_info)
        section("used_type_ids", self._count(1 << 18), self.data_type)
        section("used_functions", self._count(1 << 20), self.used_function)
        section("used_global_props", self._count(1 << 18), self.used_global_prop)
        section("used_string_constants", self._count(1 << 20), self.string)
        section("used_object_props", self._count(1 << 20), self.used_object_prop)

        out["sections"] = where
        out["end"] = self.p
        out["trailing"] = len(self.d) - self.p
        if verify_eof and self.p != len(self.d):
            raise ParseError(
                "tail ended at 0x%X, module is 0x%X bytes (%+d unexplained)"
                % (self.p, len(self.d), len(self.d) - self.p))
        return out

    def enum(self) -> Dict[str, Any]:
        """One enum, from asCReader::ReadTypeDeclaration phases 1 and 2.

            phase 1 := str(name) u32(flags) eu(size) str(ns)
                       [ u8 ]                     <- only if flags & asOBJ_SHARED
            phase 2 := eu(count) [ str(name) i32(value) ]*count

        The shared byte is the field that silently desynchronises a parser: it is
        'e' (the type already existed and was reused) or ' ', and it only appears
        for shared types, so a parser without it survives the first several records
        and then falls apart on whichever enum happens to be shared.
        """
        name = self.string()
        if not IDENT.match(name):
            raise ParseError("enum name %r is not an identifier at 0x%X"
                             % (name[:24], self.p))
        flags = self.u32()
        size = self.eu()
        ns = self.string()
        if self.dialect != TAGGED and flags & ASOBJ_SHARED:
            self.raw(1)
        count = self.eu()
        if count > 4096:
            raise ParseError("implausible member count %d" % count)
        members = []
        for _ in range(count):
            mn = self.string()
            members.append((mn.decode("latin1"), self.i32()))
        return {"name": name.decode("latin1"), "flags": flags, "size": size,
                "namespace": ns.decode("latin1"), "members": members}


def _try_parse_enums(data: bytes, dialect: str, start: int,
                     limit: int = 4096) -> Tuple[List[Dict[str, Any]], "Reader"]:
    r = Reader(data, dialect, start)
    enums = []
    try:
        while len(enums) < limit:
            enums.append(r.enum())
    except (ParseError, IndexError, struct.error):
        pass
    return enums, r


def _probe_classes(data: bytes, dialect: str, start: int,
                   enums: List[Dict[str, Any]]) -> Tuple[int, int, int]:
    """Score a candidate head by how far the class declarations get.

    The enum section alone cannot settle the head -- a module with no enums has
    nothing to count, and a wrong candidate can still yield one plausible-looking
    record. What follows the enums can settle it: an encoded class count, then
    exactly that many phase-1 declarations, each of which has to carry an
    identifier-shaped name. Only the right head parses all of them.

    Returns (all_declared_parsed, parsed, end_offset), ordered so that a
    complete class section outranks a longer partial one.
    """
    r = Reader(data, dialect, start)
    parsed = 0
    declared = 0
    try:
        for _ in range(len(enums)):
            r.enum()
        declared = r.eu()
        if declared < 0 or declared > 1 << 20:
            return (0, 0, start)
        for _ in range(declared):
            r.type_decl_phase1()
            parsed += 1
    except (ParseError, IndexError, struct.error):
        pass
    return (1 if parsed and parsed == declared else 0, parsed, r.p)


def detect(data: bytes) -> Tuple[str, int, List[Dict[str, Any]]]:
    """Return (dialect, start_offset, enums).

    The head is `eu(noDebugInfo)` then `eu(enumCount)`, so the enums start at a
    computed offset rather than a fixed one -- a module with 64 or more enums
    spends two bytes on the count. Read that header, then confirm the reading by
    parsing what it implies: the enum records, the class count, and every class
    declaration the count promises.

    Candidates from a scan of plausible start offsets are kept alongside the
    header-derived one and scored the same way, so a build whose header is not
    shaped as expected still has a route in. The ranking never rewards "parsed
    the most enums" on its own: a module can legitimately declare zero enums --
    Tomb Hunter does -- and then the only enum record any candidate finds is a
    misparse. What decides it is the class section landing whole.
    """
    candidates = []                          # (dialect, start, enums)
    for dialect in (TAGGED, LEN2):
        # The header-derived head. eu() is dialect-independent, so both dialects
        # get the same start; which one is right is settled by the probe.
        try:
            _, p = read_encoded_uint(data, 0)          # noDebugInfo
            n_enums, start = read_encoded_uint(data, p)
            if 0 <= n_enums <= 4096:
                r = Reader(data, dialect, start)
                enums = [r.enum() for _ in range(n_enums)]
                candidates.append((dialect, start, enums))
        except (ParseError, IndexError, struct.error):
            pass
        for start in range(1, 6):
            enums, _ = _try_parse_enums(data, dialect, start)
            if enums:
                candidates.append((dialect, start, enums))

    best = None
    best_score = None
    for dialect, start, enums in candidates:
        score = _probe_classes(data, dialect, start, enums) + (len(enums),)
        if best_score is None or score > best_score:
            best, best_score = (dialect, start, enums), score
    if best is None or best_score[1] == 0:
        raise ParseError("neither dialect parses a coherent module head")
    return best


def _literal_is_plausible(s: bytes) -> bool:
    """Accept a scanned literal, NUL bytes and all.

    A BGT literal may contain NUL: `"\\0\\0...melhesday\\0\\0..."` is a real
    password from a shipped title, written that way precisely so that a harvest
    looking for printable runs cannot represent it. The KDF is handed a pointer
    and a length rather than a C string, so those interior NULs are part of the
    password and the literal has to survive whole.

    Requiring every byte to be printable therefore discards exactly the literals
    worth finding. What is kept instead is text-shaped: printable ASCII, NUL or
    ordinary whitespace, with at least one printable byte so that a run of NULs
    -- which this blind scan finds by the thousand -- is not mistaken for one.
    """
    printable = 0
    for c in s:
        if 0x20 <= c <= 0x7E:
            printable += 1
        elif c not in (0x00, 0x09, 0x0A, 0x0D):
            return False
    return printable > 0


def module_strings(data: bytes, dialect: Optional[str] = None) -> List[bytes]:
    """Harvest every literal the string encoding actually yields.

    Unlike a printable-run sweep this respects the encoding, so the boundaries
    are exact -- which matters when a literal is being used as a password.

    The dialect is detected when not given. It used to default to the `len2`
    rule, which silently harvested a `tagged` module under the wrong encoding
    and returned whatever coincidence produced rather than its literals.
    """
    if dialect is None:
        try:
            dialect = detect(data)[0]
        except (ParseError, IndexError, struct.error):
            dialect = LEN2
    out = []
    seen = set()
    n = len(data)
    p = 0
    while p < n - 1:
        try:
            if dialect == TAGGED:
                if data[p] != 0x6E:
                    p += 1
                    continue
                v, q = read_encoded_uint(data, p + 1)
                length = v
            else:
                v, q = read_encoded_uint(data, p)
                if v % 2:
                    p += 1
                    continue
                length = v // 2
        except (IndexError, struct.error):
            break
        if 1 <= length <= 512 and q + length <= n:
            s = data[q:q + length]
            if s not in seen and _literal_is_plausible(s):
                seen.add(s)
                out.append(s)
        p += 1
    return out


def _walk(data: bytes, dialect: str, start: int, n_enums: int,
          opcodes: Optional[Dict[int, Dict[str, Any]]],
          template_namespace: bool) -> Dict[str, Any]:
    """One full pass over a module under one set of build assumptions."""
    r = Reader(data, dialect, start, opcodes=opcodes,
               template_namespace=template_namespace)
    classes, declared = [], None
    funcdefs, funcdefs_declared = [], None
    blocks = []
    tail: Optional[Dict[str, Any]] = None
    tail_error = None
    try:
        for _ in range(n_enums):
            r.enum()
        declared = r.eu()
        for _ in range(declared):
            classes.append(r.type_decl_phase1())
        # Funcdefs follow the class declarations. They are funcType 4, so they
        # carry no bytecode and parse without an opcode table.
        funcdefs_declared = r.eu()
        for _ in range(funcdefs_declared):
            funcdefs.append(r.function())
        # Class blocks need an opcode table, because script methods carry bytecode.
        if opcodes is not None:
            blocks.extend(r.class_blocks(classes))
            # Everything from the typedefs to EOF. Only attempted once the class
            # blocks are complete -- starting it from a desynchronised cursor
            # produces a confident, wrong table rather than an error.
            if len(blocks) == len(classes):
                try:
                    tail = r.tail()
                except (ParseError, IndexError, struct.error) as exc:
                    tail_error = "%s: %s" % (type(exc).__name__, exc)
    except (ParseError, IndexError, struct.error):
        pass

    return {"classes": classes, "classes_declared": declared,
            "funcdefs": funcdefs, "funcdefs_declared": funcdefs_declared,
            "blocks": blocks, "tail": tail, "tail_error": tail_error,
            "parse_errors": r.parse_errors, "end": r.p,
            "template_namespace": template_namespace}


def _score(w: Dict[str, Any]) -> Tuple[int, int, int]:
    """Rank one walk against another. Landing on EOF beats everything."""
    return (1 if w["tail"] else 0, len(w["blocks"]), w["end"])


def trace_module(path: str,
                 opcodes: Optional[Dict[int, Dict[str, Any]]] = None
                 ) -> Tuple[List[Tuple], Dict[str, Any]]:
    """Parse a module recording every field, so `as_write` can rebuild it.

    The trace opens with the bytes before the enum section -- the noDebugInfo
    flag and the enum count -- because `detect()` finds where the enums start
    rather than parsing that header, and a writer has to reproduce it verbatim.

    Raises unless the parse reaches EOF: a trace of a partial parse would write
    a truncated module, and that failure is much better loud than silent.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    dialect, start, enums = detect(data)

    info = summarize(path, opcodes=opcodes)
    if not info["tail"]:
        raise ParseError(
            "cannot trace %s: the parse stops at 0x%X of 0x%X (%s)"
            % (path, info["end"], info["size"],
               info["tail_error"] or "tail not reached"))

    r = Reader(data, dialect, start, opcodes=opcodes,
               template_namespace=info["template_namespace"])
    r.trace = [("raw", data[:start])]          # the header detect() stepped over
    for _ in range(len(enums)):
        r.enum()
    declared = r.eu()
    classes = [r.type_decl_phase1() for _ in range(declared)]
    for _ in range(r.eu()):
        r.function()
    r.class_blocks(classes)
    r.tail()

    if r.p != len(data):
        raise ParseError("trace ended at 0x%X, module is 0x%X bytes"
                         % (r.p, len(data)))
    return r.trace, {"dialect": dialect, "start": start, "size": len(data),
                     "template_namespace": info["template_namespace"]}


def summarize(path: str, opcodes: Optional[Dict[int, Dict[str, Any]]] = None) -> Dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read()
    dialect, start, enums = detect(data)
    members = sum(len(e["members"]) for e in enums)

    # The template-namespace field varies between builds of the same dialect, so
    # try both and keep whichever gets further. The tie-break is not "looks
    # plausible" -- it is whether the tail lands exactly on EOF, which only the
    # right answer can do.
    walk = _walk(data, dialect, start, len(enums), opcodes, True)
    if not walk["tail"]:
        other = _walk(data, dialect, start, len(enums), opcodes, False)
        if _score(other) > _score(walk):
            walk = other

    return {"path": path, "size": len(data), "dialect": dialect,
            "start": start, "no_debug_info": data[0],
            "enums": enums, "member_count": members,
            "classes": walk["classes"], "classes_declared": walk["classes_declared"],
            "funcdefs": walk["funcdefs"],
            "funcdefs_declared": walk["funcdefs_declared"],
            "blocks": walk["blocks"],
            "tail": walk["tail"], "tail_error": walk["tail_error"],
            "template_namespace": walk["template_namespace"],
            "parse_errors": walk["parse_errors"],
            "end": walk["end"]}


if __name__ == "__main__":
    import os
    import sys
    exe = os.environ.get("BGT_EXE")
    table = None
    if exe:
        import as_opcodes
        table = as_opcodes.extract(exe)["table"]
    for path in sys.argv[1:]:
        info = summarize(path, opcodes=table)
        print("=" * 68)
        print("%s  (%d bytes)" % (path, info["size"]))
        print("  dialect        %s   (enum section at +%d)"
              % (info["dialect"], info["start"]))
        print("  noDebugInfo    %d" % info["no_debug_info"])
        print("  enums parsed   %d   (%d members)"
              % (len(info["enums"]), info["member_count"]))
        for e in info["enums"][:8]:
            preview = ", ".join("%s=%d" % m for m in e["members"][:4])
            print("     %-28s %2d members   %s" % (e["name"], len(e["members"]), preview))
        if len(info["enums"]) > 8:
            print("     ... %d more" % (len(info["enums"]) - 8))
        if info["classes_declared"] is not None:
            ok = "OK" if len(info["classes"]) == info["classes_declared"] else "MISMATCH"
            print("  classes        %d / %d declared   %s   (ends 0x%X)"
                  % (len(info["classes"]), info["classes_declared"], ok, info["end"]))
            print("     %s" % ", ".join(c["name"] for c in info["classes"][:6]))
        if info["funcdefs_declared"] is not None:
            ok = "OK" if len(info["funcdefs"]) == info["funcdefs_declared"] else "MISMATCH"
            print("  funcdefs       %d / %d declared   %s"
                  % (len(info["funcdefs"]), info["funcdefs_declared"], ok))
            names = [f["name"] for f in info["funcdefs"] if f and "name" in f]
            print("     %s" % ", ".join(names[:5]))
        if info["blocks"]:
            nm = sum(len(b["methods"]) for b in info["blocks"])
            nv = sum(len(b["virtuals"]) for b in info["blocks"])
            nc = sum(len(b["ctors"]) for b in info["blocks"])
            ok = "OK" if len(info["blocks"]) == len(info["classes"]) else "PARTIAL"
            print("  class blocks   %d / %d   %s   (%d methods, %d virtuals, %d ctor pairs)"
                  % (len(info["blocks"]), len(info["classes"]), ok, nm, nv, nc))
