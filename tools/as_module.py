"""
as_module -- reader for the AngelScript module that BGT embeds in a game executable.

Two serialization dialects turn up, and **which one a module uses is a fact
about the BGT version that built it, never about who wrote the game.** One
developer with two versions of the toolkit produces two dialects; two
developers on one version produce the same one. This file used to name the
dialects after an author, which is misleading in exactly the way that
matters when a new title does not parse -- suspect a different BGT version
before suspecting a modified engine. Reported as issue #2.

    TAGGED   (the older AngelScript)
        0x00        empty
        0x6E 'n'    new string:  eu(len) then len bytes, appended to savedStrings
        0x72 'r'    back-ref:    eu(index) into savedStrings

    LEN2     (the newer AngelScript)
        eu(v); v even -> new string of v/2 bytes, appended to savedStrings
               v odd  -> back-reference to savedStrings[(v-1)/2]

**The dialects differ in RECORD LAYOUT as well, not only in strings** -- the
script-object flag moves, a funcdef gains a traits byte, an object variable is
two fields rather than three, and so on. The claim that everything but the
string encoding is shared was the single most expensive wrong sentence in this
reader's history, so it is corrected rather than softened.

Note an empty string in LEN2 does **not** occupy a savedStrings slot, which is
checkable rather than assumed: one 2.4 MB module holds 31,834 of them, the
first at its fourth field, with 76,718 back-references after it -- and its tail
lands exactly on EOF. Were they indexed, every one of those references would be
off by a growing amount and nothing would land. (Issue #3.)

Which dialect a module uses is detected, not assumed, and so is every field
that varies between builds of one dialect: each candidate is parsed and the one
whose tail lands exactly on EOF wins, with the assumptions this reader already
held tried first so a tie cannot re-describe a module that already parsed.

Ground truth for the record layouts is asCReader in the game's own binary --
it is statically linked into every BGT executable, so the layout for the build
in front of you is in the file in front of you. Do not infer it from byte
patterns: that reliably produces answers which are confident, plausible and
wrong.
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
# AngelScript's delegate factory, whose record is the name alone.
DELEGATE_FACTORY = (b"$dlgte", b"%delegate_factory")


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


#: The record layouts that move with the ENGINE RELEASE rather than per
#: build. Kept as named profiles and never as a free product: `as_module`
#: already trials four per-build fields, and this document's own rule is that
#: a trial over eight more is how a wrong story gets fitted -- which was
#: demonstrated the day this was written, when one extra free field let a
#: synthetic module with a spare byte land on EOF.
#:
#: Every field below was read out of a runtime's own `asCReader`, with the
#: exact-EOF landing as the arbiter, and the verified profile is tried first
#: and kept on a tie -- so a module that already lands cannot be
#: re-described.
RECORDS_13 = {
    #: Whether the module opens with the `noDebugInfo` byte. BGT 1.3 does;
    #: the 2010-2012 generation does not, and neither does the 2013 engine,
    #: whose `ReadInner` (0x41BBB0 in screamingStrike_en.exe) opens straight
    #: on a count. So the sign-flag integer and this byte did NOT arrive
    #: together: that engine is 2012-07-24 and has the first and not the
    #: second, which splits a window this project had as one.
    "debug_byte": True,
    #: `ReadDataType`'s convention. 1.3 reads `eu(v)`, where a NON-zero v is
    #: a back-reference and zero means a token follows, and packs the four
    #: flags into one byte. The earlier reading is the other way round --
    #: zero introduces a back-reference, a non-zero lead IS the token -- and
    #: writes the flags as separate bytes, two of them, or four when the
    #: token is 5. Both halves come out of the one function (0x419AE0), so
    #: they are one field.
    "datatype_early": False,
    #: Whether a global property's initialiser is gated on a byte.
    #: `ReadGlobalProperty` at 0x41AEB0 reads name, namespace, data type,
    #: ONE byte, and the initialiser only when that byte is 1.
    "global_init_gate": False,
    #: Whether a template type-info declares how many subtypes it has. 1.3
    #: writes a count; the AngelScript before it has no multi-subtype
    #: template, so the subtype's own tag follows the name directly.
    "template_subtype_count": True,
    #: Whether the debug block carries the scriptSections list -- the
    #: alternating index-and-string table.
    "debug_sections": True,
    #: Where the body's traits byte sits. 1.3 writes it after the variables,
    #: closing the funcType-1 branch; the 2013 engine writes it between the
    #: line numbers and the variables (0x41AC1F, right after the loop at
    #: 0x41ABE4).
    "traits_last": True,
    #: Whether a function record ends with ONE script-section string, for
    #: every funcType, instead of 1.3's scriptSection + declaredAt +
    #: parameter names. The 2013 engine reads that string at the join after
    #: its funcType switch (0x41ADBB), so a funcdef carries an empty one.
    "section_per_record": False,
    #: How far this build's `eTokenType` sits below the numbering the IR
    #: uses. Two keywords went in between BGT 1.3's AngelScript and the
    #: newer one, at 36 and 64, so 1.3 is two lower; the generation before
    #: it is four, two more having gone in between 2.19 and 1.3. Read off a
    #: known answer rather than counted: this build's `int` is 66, where
    #: 1.3's is 68 and the IR's is 70.
    "token_shift": 2,
    #: Whether the engine's BEHAVIOUR numbering is the one before 1.3's,
    #: where `_beh_1_` is the destructor and `_beh_2_` the factory rather
    #: than 1.3's copy-constructor and destructor. A separate field from the
    #: token shift, because nothing says the two had to move together --
    #: and the module's own `usedFunctions` settles it per build, since each
    #: entry records its owner and its signature:
    #:
    #:     _beh_0_  owner=string  params=0 or 1  void   -- the constructor
    #:     _beh_1_  owner=string  params=0       void   -- the DESTRUCTOR
    #:     _beh_2_  owner=None    params=0       object -- the FACTORY
    #:
    #: Read as 1.3's, `_beh_1_` is a copy-construction, so the temp holding
    #: a string literal was copy-constructed where the original destroyed
    #: it -- and the argument that should have been the literal came out
    #: `null`. `voice.speak_interrupt(null)` in Screaming Strike, 19
    #: literals across six bodies, which the bytecode audit reported and
    #: no structural check could.
    "early_behaviours": False,
    #: Whether `ALLOC`'s callee operand is translated only when the
    #: allocated type is a SCRIPT object. 1.3 resolves it for every type;
    #: the 2012-07 engine tests the script-object flag first and leaves the
    #: operand alone otherwise, so for a registered type it holds whatever
    #: the compiler put there and means nothing to a reader. Read out of
    #: that build's own `TranslateFunction` at 0x418F6E.
    "alloc_callee_script_only": False,
    #: Whether a function signature carries its NAMESPACE immediately after
    #: the name. 1.3 writes it last, after the owner and the traits byte;
    #: the generation before it writes it first. Aliens Attack (2012-03) is
    #: the first build here that writes it first while reading 1.3's
    #: sign-flag encoded integer, so this is its own field rather than part
    #: of `datatype_early`. Its `menu_callback` is what shows it:
    #:
    #:     6e 0d "menu_callback"   the name
    #:     00                      the namespace, empty    <- here
    #:     40 42                   eu(token) = 66 = int
    #:     00 00                   two flag bytes
    #:     02                      two parameters
    #:
    #: Read with the namespace last, that leading 00 is taken for 1.3's
    #: "a token follows" marker, the token for a back-reference index, and
    #: the parameter count comes out 0 on a funcdef that has two.
    "sig_namespace_first": False,
    #: Whether a funcType-1 body writes `variableSpace` before the object
    #: variables and `objVariablesOnHeap` after them. 1.3 writes both. The
    #: 2012-03 engine writes neither: its object-variable entry is three
    #: fields, the third being that variable's own on-heap flag, and the
    #: count straight after the list is `objVariableInfo`.
    #:
    #: `sound_pool_item`'s factory stub is the record that pins it --
    #: `PUSH 1 ; PSF 1 ; ALLOC 0,2 ; LOADOBJ 1 ; RET 0`, then
    #:
    #:     01                      one object variable
    #:     6f 72 00 00             its type: sound_pool_item
    #:     01 01                   position 1, on the heap
    #:     00                      objVariableInfo count       <- no room
    #:     00 00 00                line numbers, traits, variables
    #:     72 07                   the script section, by back-reference
    #:
    #: and the next record's 'f' follows immediately. There is exactly one
    #: byte spare between the object variable and the four zero counts, so
    #: only one of the three candidate fields can be there, and `reset`
    #: settles which: its count is 2 and the two triples that follow give
    #: program positions 19 and 24, which are also two of the 23 line-number
    #: positions in the same body.
    "body_scalar_fields": True,
    #: Whether a template type-info's subtype is written the way the
    #: generation before 1.3 writes it: 's' then a whole TypeInfo then one
    #: byte, 'h' for a handle and 'o' for a value, or 't' then four raw
    #: bytes for a primitive. 1.3 writes a tag and then a DataType.
    #: `array<T>`, the owner of `resize` in Aliens Attack's usedFunctions,
    #: is `61 'a' | 72 34 | 73 | 73 6e 01 "T" | 6f` -- the template, its
    #: name by back-reference, the subtype marker, the subtype's own
    #: type-info, and the value byte.
    "template_subtype_early": False,
    #: Whether the OPCODE NUMBERING is the generation before 1.3's, so an
    #: instruction's name and operand shape have to come from this build's
    #: own `asBCInfo[]` rather than from the table `asreader` models. It is
    #: a separate question from how the operands are STORED: Aliens Attack
    #: stores them 1.3's way -- an instruction count and encoded operands --
    #: and numbers them the old way, where `0x00` is `POP` and `0x01` is
    #: `PUSH` against the newer `PopPtr` and `PshGPtr`. Counted: its table
    #: has 202 entries and 16 disagree with the newer numbering, Perilous
    #: Hearts' 202 and 22, and Psycho Strike's 200 and none.
    "early_opcodes": False,
}

#: Screaming Strike's engine (2012-07-24, 394 registered names): 1.3's
#: format everywhere this reader does not say otherwise -- the same
#: sign-flag encoded integer, the same signature order with the namespace
#: last, the same tail sections in the same order -- with these nine records
#: the generation before it.
#:
#: **Derived from `RECORDS_13` rather than written out in full.** Two
#: parallel dicts of the same keys is two places to keep in step, and the
#: drift is not silent here -- it is a `KeyError` from the middle of a parse
#: the first time a module reaches a field one of them lacks, which is how
#: adding a field to 1.3's copy and not to this one took Aliens Attack from
#: landing exactly on EOF to "neither reader could parse this module".
RECORDS_2012 = dict(
    RECORDS_13,
    debug_byte=False,
    datatype_early=True,
    global_init_gate=True,
    template_subtype_count=False,
    debug_sections=False,
    traits_last=False,
    section_per_record=True,
    token_shift=4,
    early_behaviours=True,
    alloc_callee_script_only=True,
)

#: Aliens Attack's engine (NS Studios, 2012-03-09, 322 registered names):
#: Screaming Strike's profile and three records more from the generation
#: before it. It sits one month after Antony (2012-02-05, 312 names), which
#: `as_early` reads, and four months before Screaming Strike -- so it is the
#: build that **dates the sign-flag encoded integer**, which this file had as
#: "between February and July 2012" and is now between 5 February and 9
#: March 2012. Everything `as_early` reads about Antony still holds here
#: except the integer, the bytecode (an instruction count with encoded
#: operands, as 1.3 writes it) and the tail's section list.
RECORDS_2012_03 = dict(RECORDS_2012,
                       sig_namespace_first=True,
                       body_scalar_fields=False,
                       template_subtype_early=True,
                       early_opcodes=True)

#: Tried in order, verified first.
RECORD_PROFILES = (("1.3", RECORDS_13), ("2012-07", RECORDS_2012),
                   ("2012-03", RECORDS_2012_03))


class Reader:
    def __init__(self, data: bytes, dialect: str, pos: int = 0,
                 opcodes: Optional[Dict[int, Dict[str, Any]]] = None,
                 template_namespace: bool = True,
                 unguarded_lists: bool = False,
                 objvar_three: bool = False,
                 legacy_body: Optional[bool] = None,
                 records: Optional[Dict[str, bool]] = None) -> None:
        self.d = data
        #: Which release's record layouts to read. See `RECORD_PROFILES`.
        self.records = dict(RECORDS_13 if records is None else records)
        self.dialect = dialect
        self.p = pos
        # **Whether this module kept its debug information**, which is the
        # module's own first byte: 0 means it did. This file said for a long
        # time that "BGT compiles with noDebugInfo = 1" and that a game's own
        # file names and local variable names are gone for good. That is true
        # of a RELEASE build (`-C`) and false of a DEBUG one (`-c`) -- and Air
        # Puck 2PE ships both halves built with `-c`. Their modules carry the
        # source path and every parameter and local name.
        #
        # **`pos > 0` is what makes reading byte 0 meaningful.** The flag IS
        # byte 0, so only a reader whose own section starts after it has a
        # head above it to read; `detect` never returns 0, because the head is
        # at least the one byte the flag occupies. A reader built at 0 is a
        # FRAGMENT -- a class block on its own in a test, say -- whose first
        # byte is a null marker and not the flag, and taking that for a debug
        # build made it look for fields that are not there.
        self.debug_info = pos > 0 and bool(data) and data[0] == 0
        if not self.records["debug_byte"]:
            # No flag to read, so the debug fields are written whatever the
            # build: a release module of that generation carries zero line
            # numbers, zero variables and an empty section string per record
            # rather than nothing at all.
            self.debug_info = True
        # Whether ReadTypeInfo's 'a' (template) form carries a namespace string
        # after the name. It does in Psycho Strike and Manamon 2 and does NOT in
        # Paladin of the Sky -- three builds, two answers, so this is a per-build
        # variation rather than a per-dialect one and is settled by trial parse
        # against the exact-EOF landing, not assumed. Compare, in each binary's
        # ReadTypeInfo: strike 0x00420970 calls ReadString twice under 'a',
        # paladin 0x0041F560 calls it once.
        self.template_namespace = template_namespace
        # Whether the in/out and default-argument lists are written even for
        # a function with NO parameters. The newer reader guards both on
        # `paramCount != 0` and the older one writes them unconditionally,
        # which is why this used to hang off the dialect -- but Manamon 1 is
        # `len2` and writes them unconditionally, while Manamon 2 is `len2`
        # and does not (27/27 funcdefs guarded, 0/27 without). Two builds,
        # two answers, so like `template_namespace` this is per-build and is
        # settled by trial parse against the exact-EOF landing.
        #
        # Manamon 1's `phone_callback` is the record that shows it. It takes
        # no parameters, and its nine bytes only add up unguarded:
        #
        #     04        return type (void)
        #     00        parameter count = 0
        #     00        inOutFlags count   <- skipped when guarded
        #     04        funcType = 4
        #     00        default-argument count
        #     00 6E 00  owner (none), 'n', empty namespace
        #     01        funcdef traits
        #
        # Guarded, the reader takes `04` for the funcType position, reads the
        # real funcType as a type-info and raises `bad type-info tag 0x04`.
        # Nothing in the corpus had exercised a zero-parameter funcdef:
        # Manamon 2's twenty-seven all take at least one.
        self.unguarded_lists = unguarded_lists
        # Whether a funcType-1 body records THREE fields per object variable
        # (`{typeinfo, eu, eu}`) or two. The older reader writes three and
        # Manamon 1's writes two, so it travels with `legacy_body` below
        # rather than with the dialect -- and it is settled the same way,
        # by the exact-EOF landing.
        self.objvar_three = objvar_three
        # Whether a funcType-1 body opens with a FLAGS BYTE or goes straight
        # to the bytecode.
        #
        # This used to hang off the dialect, and Manamon 1 disproved that the
        # way every other field in this list was disproved: it is `len2`
        # and its bodies have no flags byte. Read out of its own reader
        # (`asCReader::ReadFunction`, FUN_004216D0 in rpg.exe) rather than
        # fitted to the bytes -- for funcType 1 it calls ReadByteCode
        # immediately after the signature, then:
        #
        #     eu(variableSpace)
        #     eu(nObjVar)   nObjVar x { ReadTypeInfo, eu }   <- TWO fields
        #     if nObjVar > 0: eu(objVariablesOnHeap)
        #     eu(nObjInfo)  nObjInfo x { eu, eu, eu }
        #     ReadData(&bits, 1)            <- read-only / private
        #
        # with no `flags & 0x08` gate on the object variables, no try/catch
        # block, and the debug-info branch dead because noDebugInfo is 1.
        #
        # Guessing it from the bytes would have got this wrong, and nearly
        # did. `elemental_node`'s constructor record ends exactly on the
        # factory that follows it (0x6559) under BOTH readings: flagged with
        # three-field object variables, and legacy with two. The flags byte
        # the first one consumes is 0x09 and the instruction count it then
        # reads is also 9, so the two differ by a one-byte shift at the
        # start of the body that three-field object variables give back at
        # the end. The factory is what tells them apart: legacy decodes it
        # as `PSF 1 ; ALLOC 1,2 ; LOADOBJ 1 ; RET 0`, which is what a
        # factory stub is, and flagged decodes four instructions that are
        # not one and overshoot the next record.
        self.legacy_body = (dialect == TAGGED if legacy_body is None
                            else legacy_body)
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
            # One subtype and NO count in the generation before 1.3: that
            # AngelScript has no multi-subtype template, so the subtype's own
            # tag follows the name directly. `objectTimer`, an `array<timer>`
            # in Screaming Strike, is the record that shows it -- 'a',
            # "array", then 's' straight away, where reading a count takes
            # that 's' for 115 subtypes.
            if not self.records["template_subtype_count"]:
                n = 1
            else:
                n = self.eu()
                if not 0 <= n <= 64:
                    raise ParseError("implausible subtype count %d at 0x%X"
                                     % (n, self.p))
            subs = []
            for _ in range(n):
                sub = self.raw(1)[0]
                if self.records["template_subtype_early"]:
                    # 's' then a whole TypeInfo then one byte -- 'h' for a
                    # handle, 'o' for a value -- or 't' then four raw bytes
                    # for a primitive. Shaped as a data type, because that is
                    # what a template argument is to everything downstream.
                    if sub == 0x73:
                        of = self.type_info()
                        handle = self.raw(1)[0]
                        if handle not in (0x68, 0x6F):
                            raise ParseError(
                                "a template subtype's handle byte at 0x%X is "
                                "0x%02X, which is neither 'h' nor 'o'"
                                % (self.p - 1, handle))
                        subs.append({"token": 5, "type": of,
                                     "handle": handle == 0x68, "const": False,
                                     "reference": False, "readonly": False})
                    elif sub == 0x74:
                        # The primitive's token, as an ENCODED integer -- the
                        # 2011 builds write four raw bytes here and `as_early`
                        # reads those, but this build writes an eu, which is
                        # the same change as its integer encoding. `keyslist`
                        # in Aliens Attack is `05 'a' r52 't' 40 42`, and
                        # `40 42` is 66, this build's `int`, giving the
                        # `int[]` the name says. Read as four raw bytes it is
                        # 0x40420000, and the two flag bytes it swallows take
                        # the global's initialiser with them.
                        subs.append({"typeid": self.eu()})
                    else:
                        raise ParseError("bad template subtype tag 0x%02X "
                                         "at 0x%X" % (sub, self.p - 1))
                    continue
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
        early = self.records["datatype_early"]
        v = self.eu()
        if (v == 0) if early else (v != 0):
            # A back-reference. The two generations spell it opposite ways
            # round: 1.3 puts the index in the lead value, and the earlier
            # reader writes a zero lead and then the index.
            i = self.eu() if early else v - 1
            return self.types[i] if i < len(self.types) else {"ref": i}

        slot = len(self.types)
        self.types.append(None)                  # reserve, then patch
        token = v if early else self.eu()
        obj = self.type_info() if token == 5 else None

        # ALWAYS exactly one byte, in both dialects. An early Psycho Strike model
        # had this as two bytes for object types; decoding menu_callback byte by
        # byte shows it is one -- the apparent second byte was the namespace
        # string that ReadTypeInfo had already consumed.
        #
        # ...and the generation before 1.3 writes them as SEPARATE bytes
        # instead, which is a different claim from the refuted one: two bytes
        # always, and two more ahead of them when the token is 5.
        if early:
            flags = 0
            if token == 5:
                flags |= 1 if self.raw(1)[0] else 0          # handle
                flags |= 2 if self.raw(1)[0] else 0          # const
            flags |= 4 if self.raw(1)[0] else 0              # reference
            flags |= 8 if self.raw(1)[0] else 0              # read-only
        else:
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
        # The only honest bound is the stream itself: every instruction costs
        # at least its opcode byte, so a count larger than the bytes remaining
        # cannot be real. A round constant here was a guess, and it was wrong
        # -- `1 << 20` rejected Crazy Party's `ajouteLangue`, a generated
        # function of 1,074,460 instructions that decodes to exactly its
        # declared count and ends on `RET`. The guard was the only thing
        # standing between that title and a full parse.
        if count < 0 or count > len(self.d) - self.p:
            raise ParseError("instruction count %d exceeds the %d bytes left"
                             % (count, len(self.d) - self.p))
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
        if name in DELEGATE_FACTORY:
            # The delegate factory copies its whole signature from the engine's
            # registered one and reads nothing further from the stream. Its
            # name differs between AngelScript versions, and the stream gives
            # no other sign: read on and the next field is taken as a
            # parameter count. Crazy Party spells it `%delegate_factory`,
            # and its `usedFunctions[334]` was where this showed up -- as an
            # inOutFlag count of 660 against 28 parameters, 200 entries into a
            # table that had been reading perfectly.
            return {"name": name.decode("latin1"), "funcType": None,
                    "params": [], "owner": None}

        # The generation before 1.3 writes the namespace here rather than
        # last. See `sig_namespace_first`.
        ns_first = (self.string().decode("latin1")
                    if self.records["sig_namespace_first"] else None)

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
        guarded = self.dialect != TAGGED and not self.unguarded_lists

        inout: List[int] = []
        if nparams or not guarded:               # inOutFlags
            n = self.eu()
            if nparams and n > nparams:
                raise ParseError("inOutFlag count %d > %d params" % (n, nparams))
            for _ in range(n):
                inout.append(self.eu())

        func_type = self.eu()

        defaults: List[str] = []
        if nparams or not guarded:               # default-argument expressions
            n = self.eu()
            if nparams and n > nparams:
                raise ParseError("default-arg count %d > %d params" % (n, nparams))
            for _ in range(n):
                defaults.append(self.string().decode("latin1"))

        owner = self.type_info()
        traits = 0
        if self.records["sig_namespace_first"]:
            # Already read, above the return type; a non-null owner still
            # closes the record with its traits byte.
            ns = ns_first
            if owner is not None:
                traits = self.raw(1)[0]
        elif owner is not None:
            traits = self.raw(1)[0]              # traits byte: private/protected/const
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
                "funcType": func_type, "owner": owner, "namespace": ns,
                "inOut": inout, "defaults": defaults, "traits": traits}

    def _script_body_legacy(self, rec: Dict[str, Any]) -> None:
        """A funcType-1 body with no flags byte.

        strike.exe 0x0041E2A0 for the older reader, and rpg.exe (Manamon 1)
        0x004216D0 -- which is `len2`, so this is not the dialect.

        Structurally different from the newer one, not just differently encoded:

            <bytecode>                      <- NO leading flags byte
            eu(stackNeeded)
            eu(nObjVar)
            nObjVar x { typeinfo, eu [, eu] }   <- three fields, or two
            if nObjVar > 0: eu(objVariablesOnHeap)
            eu(nObjInfo)                    <- unconditional, not nested
            nObjInfo x { eu, eu, eu }
            if noDebugInfo == 0: <debug info>

        The newer build gates all of this behind a flags byte (0x04 body omitted,
        0x08 object variables present, 0x10 try/catch present). This one has no
        such byte and no try/catch block at all -- so reading a flags byte
        here consumes the first byte of the instruction count, and every count
        after it is wrong.

        The object-variable field count travels with this shape rather than with
        the dialect: the older reader writes three, Manamon 1 writes two.
        """
        rec["instructions"], rec["body"] = self.bytecode()
        if self.records["body_scalar_fields"]:
            rec["stackNeeded"] = self.eu()

        nobj = self.eu()
        if not 0 <= nobj <= 1 << 16:
            raise ParseError("implausible object-variable count %d" % nobj)
        objvars = []
        for _ in range(nobj):
            ti = self.type_info()
            objvars.append((ti, self.eu(), self.eu()) if self.objvar_three
                           else (ti, self.eu()))
        rec["objVars"] = objvars
        if nobj > 0 and self.records["body_scalar_fields"]:
            self.eu()                            # objVariablesOnHeap

        ninfo = self.eu()
        if not 0 <= ninfo <= 1 << 18:
            raise ParseError("implausible object-info count %d" % ninfo)
        rec["objInfo"] = [(self.eu(), self.eu(), self.eu()) for _ in range(ninfo)]
        self.debug_head(rec)

        # ...and then ONE trailing traits byte (bit 0 read-only, bit 1 private),
        # read unconditionally. The 2/3/4 funcTypes jump straight past it.
        # Missing it leaves the constructor exactly one byte short, which puts
        # the factory record that follows one byte out and takes the whole
        # class block with it.
        #
        # **It is the last field of the branch, not the last field of the
        # record.** `debug_head` above and `debug_tail` in `function()` are
        # one debug block in the source and the traits byte is written
        # between them -- see `debug_head`.
        #
        # ...and which of the two it is moves with the release: the 2013
        # engine writes it inside the debug block instead, so `debug_head`
        # has already taken it and there is nothing here to read.
        if self.records["traits_last"]:
            rec["traits"] = self.raw(1)[0]

    def debug_head(self, rec: Dict[str, Any]) -> None:
        """The debug fields a DEBUG build writes BEFORE the traits byte.

        This reader carried `# debug info follows only when noDebugInfo == 0,
        and BGT always strips it` here, and the second half is wrong: BGT's
        `-C` strips it and its `-c` does not. Air Puck 2PE ships both halves
        compiled with `-c`, so its modules hold the source path, every
        parameter name and every local name -- the information this file
        calls "stripped and unrecoverable", which is true only of a release
        build.

        **The traits byte sits in the middle of the debug fields**, which is
        the whole of why this used to fail. The engine writes the line
        numbers, the script sections and the variables as the last thing in
        the `funcType == asFUNC_SCRIPT` branch, then closes that branch with
        the private/protected byte, and only then writes the script section,
        the declaration position and the parameter names. Read as one run --
        six fields and then the traits byte -- every record is one byte short
        and the class block desynchronises on the factory that follows.

        Two readings of that disagree and the format picks between them: the
        last three fields could belong to every funcType, since the engine
        writes them outside the branch that tests it, or to a script function
        alone. Only the second lands the tail exactly on EOF, and the first
        dies 0x1D7 bytes in -- see `function`.

        Parameters are variables here, which is why a two-parameter function
        with two locals reports four. Air Puck's `server_menu::add(item, id)`
        is the record that settled the field order: its two variables come
        back at stack offsets **-1 and -2**, which is where this file says
        parameters live, and a name read before the offset makes them 0 and
        garbage instead.
        """
        if self.debug_info:
            count = self.eu()
            if not 0 <= count <= 1 << 20:
                raise ParseError("implausible line-number count %d" % count)
            # Pairs: a program position, then the line packed with its column
            # as `line | col << 20`. `puck::puck` opens at position 0, line
            # 6, column 7.
            rec["lineNumbers"] = [self.eu() for _ in range(count)]

        if not self.records["traits_last"]:
            # The 2013 engine closes the line numbers with the traits byte and
            # only then reads the variables -- the one-byte read at 0x41AC1F,
            # immediately after the loop at 0x41ABE4. 1.3 writes it after the
            # variables instead, which is why `_script_body_legacy` reads it
            # there and this does not.
            #
            # **It is not a debug field**, which is why it is read outside the
            # guard above: the engine closes the funcType-1 branch with it
            # whether or not the build kept its debug information. Returning
            # before it left every body of a RELEASE build of such an engine
            # one byte short -- invisible until River Raiders, because the one
            # earlier sample of this generation, Screaming Strike, is a DEBUG
            # build.
            rec["traits"] = self.raw(1)[0]

        if not self.debug_info:
            return

        if self.records["debug_sections"]:
            count = self.eu()
            if not 0 <= count <= 1 << 16:
                raise ParseError("implausible section count %d" % count)
            sections = []
            for i in range(count):
                sections.append(self.eu() if i % 2 == 0 else self.string())
            rec["sections"] = sections

        count = self.eu()
        if not 0 <= count <= 1 << 16:
            raise ParseError("implausible variable count %d" % count)
        variables = []
        for _ in range(count):
            declared_at = self.eu()
            # The stack offset is stored PLAIN and signed -- not the newer
            # generation's `offset << 1 | onHeap`. Read with that shift,
            # `server_menu::add`'s two parameters both come back at -1 --
            # one of them on the heap -- instead of at -1 and -2, which is
            # one name for two parameters and reads perfectly.
            offset = self.eu()
            variables.append({"declared_at": declared_at,
                              "name": self.string(),
                              "stack_offset": offset,
                              "type": self.data_type()})
        rec["variables"] = variables

    def debug_tail(self, rec: Dict[str, Any]) -> None:
        """The debug fields that follow the traits byte. See `debug_head`.

        **The one-string form is not a debug field**, so it is read whether or
        not the build kept its debug information -- the engine writes it at
        the join after the funcType switch, outside the branch that tests it,
        and a release build carries an empty string rather than nothing. The
        same correction as the traits byte in `debug_head`, found the same
        way: River Raiders is the first RELEASE build of a generation whose
        only earlier sample, Screaming Strike, is a debug one.
        """
        if self.records["section_per_record"]:
            # One string and nothing else, read at the join after the
            # funcType switch (0x41ADBB), so a funcdef carries an empty one
            # and there is no declaredAt and no parameter-name list. That it
            # is either empty or a source path is the check that makes the
            # body before it judgeable: a desynchronised body leaves
            # something else here.
            at = self.p
            section = self.string()
            text = section.decode("latin1")
            if text and not text.lower().endswith((".bgt", ".nvgt")):
                raise ParseError(
                    "a function's script section at 0x%X reads %r, which is "
                    "no source file -- the body before it desynchronised"
                    % (at, text[:40]))
            rec["scriptSection"] = section
            return
        if not self.debug_info:
            return
        rec["scriptSection"] = self.string()
        rec["declaredAt"] = self.eu()
        count = self.eu()
        if count > len(rec.get("params") or ()):
            raise ParseError("parameter-name count %d exceeds the %d parameters"
                             % (count, len(rec.get("params") or ())))
        rec["paramNames"] = [self.string() for _ in range(count)]

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

        if ft == 1 and self.legacy_body:
            self._script_body_legacy(rec)
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
                        ti = self.type_info()
                        rec["objVars"].append(
                            (ti, self.eu(), self.eu()) if self.objvar_three
                            else (ti, self.eu()))
                    if nobj > 0:
                        self.eu()                # objVariablesOnHeap
                    ninfo = self.eu()            # NOTE: inside the 0x08 block
                    rec["objInfo"] = [(self.eu(), self.eu(), self.eu())
                                      for _ in range(ninfo)]
                if flags & 0x10:
                    rec["tryCatch"] = [(self.eu(), self.eu())
                                       for _ in range(self.eu())]
                # The newer shape carries its private/protected bits in the
                # flags byte at the top, so there is no traits byte here and
                # the two halves of the debug block are adjacent. **Unverified
                # against a sample**: every `len2` module in the corpus is a
                # release build, so this is the order `debug_head` was proved
                # in rather than a reading of a debug one.
                self.debug_head(rec)
        elif ft in (2, 3):
            rec["vfTableIdx"] = self.eu()
        elif ft == 4 and self.dialect != TAGGED:
            self.raw(1)                          # funcdef traits byte; newer builds only

        # A script function alone carries the second half. The engine writes
        # it outside the branch that tests the funcType, so applying it to
        # every record is the reading a person would take from the source --
        # and it dies on Air Puck's first virtual stub, where keeping it to
        # funcType 1 lands the tail exactly on EOF.
        if ft == 1 or self.records["section_per_record"]:
            self.debug_tail(rec)
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
        out = {"name": decl["name"], "namespace": decl.get("namespace", ""),
               "derivedFrom": self.type_info(),
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
        iface_blocks = [self.class_block(c) for c in interfaces]
        other_blocks = [self.class_block(c) for c in others]
        # Phase 3 walks the same `others` list in the same order, so each
        # property table belongs to the block at the same POSITION. Pairing them
        # by name -- as this once did -- breaks as soon as two classes share a
        # name in different namespaces: Manamon 2 declares `sound_pool` both
        # globally and in `rhythm`, and the global one's properties
        # (destroy_sound_callback among them) landed on the other block and were
        # then overwritten.
        for block, c in zip(other_blocks, others):
            block["properties"] = self.class_phase3(c)
        return iface_blocks + other_blocks

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
        init = None
        if self.records["global_init_gate"]:
            # One byte, and the function only when it is 1. Read out of
            # `ReadGlobalProperty` at 0x41AEB0: `call edx` for one byte, then
            # `cmp byte [esp+0xf], 0 / je` over the whole `ReadFunction`.
            gate = self.raw(1)[0]
            if gate not in (0, 1):
                raise ParseError("a global's initialiser gate at 0x%X is %d, "
                                 "which is neither 0 nor 1" % (self.p - 1, gate))
            if gate:
                init = self.function_or_error(name.decode("latin1"), "initialiser")
        else:
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

        Both builds write the property's **name** as a string (asCWriter finds
        the property at the used byte offset and writes its name). They differ
        only in how a string is encoded, and that is what once hid this.

        The `len2` form was read as a bare encoded index. That parses to
        exactly EOF, because a `len2` back-reference IS a single encoded value
        -- odd, `2 * index + 1`. The proof it is a string: all 6,523 of
        Manamon 2's values are odd, which chance would not produce, and read as
        strings 6,507 of them name a real property of their owner (the rest
        belong to registered types such as `vector`). Read as indices they
        resolved to `menu_properties_object::prop[11939]`, and that still
        counted as "named".
        """
        owner = self.type_info()
        return {"owner": owner, "name": self.string().decode("latin1")}

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
        section("typedefs", n,
                lambda: dict(self.type_decl_phase1(), token=self.eu()))

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


def detect(data: bytes,
           opcodes: Optional[Dict[int, Dict[str, Any]]] = None
           ) -> Tuple[str, int, List[Dict[str, Any]]]:
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
        # A build with NO `noDebugInfo` byte: the module's first field is
        # the enum count, so the records start one value in rather than two.
        # Screaming Strike is one -- its own `ReadInner` opens on a count --
        # and the two readings are indistinguishable from the bytes when the
        # counts are zero, which they are for a single-file game. The EOF
        # landing below is what separates them.
        try:
            n_enums, start = read_encoded_uint(data, 0)
            if 0 <= n_enums <= 4096:
                r = Reader(data, dialect, start, records=RECORDS_2012)
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
    if best is not None and best_score[1]:
        return best

    # **A module can declare no classes at all, and then the class section
    # cannot be the judge of anything.** `screamingStrike_en` is one: a
    # single-file 2013 game with 51 globals, 0 enums, 0 classes and 0
    # funcdefs, whose head reads perfectly by hand and which this refused
    # outright.
    #
    # The fallback is the format's own strongest check, which is what
    # `summarize` already ranks by one level up: parse the whole module and
    # see whether the tail lands EXACTLY on EOF. Nothing follows
    # `usedObjectProps`, so only the right dialect can land there, and a
    # wrong one has nothing to absorb its mistake.
    #
    # It fires only when no candidate found a single class, so no title that
    # was already being identified can be re-described by it.
    # The tail is only reached with an opcode table, because a class block
    # holds bytecode -- so without one there is nothing to rank by and the
    # refusal stands. The first version of this fallback passed None and
    # could never have succeeded.
    for dialect, start, enums in candidates:
        walk, _release = _trial(data, dialect, start, len(enums), opcodes)
        if walk["tail"]:
            return (dialect, start, enums)

    # Still nothing that lands on EOF. A head that reads is better than a
    # refusal only if the caller is told which it got, and `summarize`
    # reports `tail: False` for exactly that -- so hand back the furthest
    # reading rather than refusing a module whose head is sound.
    if candidates:
        ranked = max(candidates, key=lambda c: _score(
            _trial(data, c[0], c[1], len(c[2]), opcodes)[0]))
        return ranked
    raise ParseError("neither dialect parses a coherent module head")


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


def literal_is_cipher_shaped(s: bytes) -> bool:
    """Accept a literal that looks like a block cipher's output.

    `_literal_is_plausible` rejects any byte outside printable ASCII, which is
    right for a blind scan -- and it discards exactly the literal a BGT game
    stores its pack key in. The idiom is
    `set_sound_decryption_key(string_decrypt(h_key, "af-dc7=rqp+"))`, where
    `h_key` is a 32-byte AES-CBC blob, so a harvest that cannot represent high
    bytes cannot contain the password under any transformation. Super Egg Hunt
    was 3,392 candidates and no hits for that reason alone.

    What is accepted instead is narrow enough not to flood a blind scan: a
    whole number of 16-byte blocks, at least one block, and mostly bytes that
    are not text. Plaintext never looks like this, and a run of 32 arbitrary
    bytes picked up mid-record is cheap to test -- one AES block.
    """
    if len(s) < 16 or len(s) % 16 or len(s) > 512:
        return False
    text = sum(1 for c in s if 0x20 <= c <= 0x7E or c in (0x00, 0x09, 0x0A, 0x0D))
    return text * 2 < len(s)


def module_strings(data: bytes, dialect: Optional[str] = None,
                   accept: Optional[Any] = None) -> List[bytes]:
    """Harvest every literal the string encoding actually yields.

    Unlike a printable-run sweep this respects the encoding, so the boundaries
    are exact -- which matters when a literal is being used as a password.

    `accept` replaces the plausibility test, for a caller after literals this
    one is built to discard -- see `literal_is_cipher_shaped`.

    The dialect is detected when not given. It used to default to the `len2`
    rule, which silently harvested a `tagged` module under the wrong encoding
    and returned whatever coincidence produced rather than its literals.
    """
    if accept is None:
        accept = _literal_is_plausible
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
            if s not in seen and accept(s):
                seen.add(s)
                out.append(s)
        p += 1
    return out


def _walk(data: bytes, dialect: str, start: int, n_enums: int,
          opcodes: Optional[Dict[int, Dict[str, Any]]],
          template_namespace: bool,
          unguarded_lists: bool = False,
          objvar_three: bool = False,
          legacy_body: Optional[bool] = None,
          records: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
    """One full pass over a module under one set of build assumptions."""
    r = Reader(data, dialect, start, opcodes=opcodes,
               template_namespace=template_namespace,
               unguarded_lists=unguarded_lists,
               objvar_three=objvar_three,
               legacy_body=legacy_body,
               records=records)
    classes, declared = [], None
    funcdefs, funcdefs_declared = [], None
    enums: List[Dict[str, Any]] = []
    blocks = []
    tail: Optional[Dict[str, Any]] = None
    tail_error = None
    try:
        for _ in range(n_enums):
            enums.append(r.enum())
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
    except (ParseError, IndexError, struct.error) as exc:
        # **Say what went wrong.** This used to be `pass`, and `tail_error`
        # is set only once the class blocks are complete -- so a module that
        # died in its head reached the caller as "the tail did not land on
        # EOF: unknown", which names neither the failure nor the place. Air
        # Puck's modules died on their first class block with an exact
        # message, and a probe had to be written to see it.
        tail_error = ("%s: %s (at 0x%X of 0x%X, after %d of %s class blocks)"
                      % (type(exc).__name__, exc, r.p, len(data),
                         len(blocks),
                         "?" if declared is None else declared))

    return {"debug_byte": r.records["debug_byte"],
            "token_shift": r.records["token_shift"],
            "early_behaviours": r.records["early_behaviours"],
            "early_opcodes": r.records["early_opcodes"],
            "alloc_callee_script_only":
                r.records["alloc_callee_script_only"],
            "enums": enums, "classes": classes, "classes_declared": declared,
            "funcdefs": funcdefs, "funcdefs_declared": funcdefs_declared,
            "blocks": blocks, "tail": tail, "tail_error": tail_error,
            "parse_errors": r.parse_errors, "end": min(r.p, len(data)),
            "template_namespace": template_namespace,
            "unguarded_lists": unguarded_lists,
            "objvar_three": objvar_three,
            "legacy_body": r.legacy_body}


def _trial(data: bytes, dialect: str, start: int, n_enums: int,
           opcodes: Optional[Dict[int, Dict[str, Any]]]
           ) -> Tuple[Dict[str, Any], str]:
    """The best walk of one (dialect, start), and which release won it.

    Every axis this reader trials, in one place: the record profiles, then
    the four per-build fields. `detect` and `summarize` both need the answer
    and used to compute it separately, with `detect`'s version pinned at
    `template_namespace=True` -- so a module whose landing needs False was
    reported as not landing at all by the one that chooses the dialect, and
    then landed in the one that reports it. Two places answering one
    question, with one of them stricter: the failure this document keeps
    recording.

    The record profiles are the OUTERMOST loop and the verified one is
    first, so a module that already lands keeps the reading this reader
    already held.
    """
    legacy_first = dialect == TAGGED
    walk = None
    release = RECORD_PROFILES[0][0]
    for name, records in RECORD_PROFILES:
        for namespaced in (True, False):
            for unguarded in (False, True):
                for three in (False, True):
                    for legacy in (legacy_first, not legacy_first):
                        t = _walk(data, dialect, start, n_enums, opcodes,
                                  namespaced, unguarded, three, legacy,
                                  records=records)
                        if walk is None or _score(t) > _score(walk):
                            walk, release = t, name
                        if walk["tail"]:
                            break
                    if walk["tail"]:
                        break
                if walk["tail"]:
                    break
            if walk["tail"]:
                break
        if walk["tail"]:
            break
    return walk, release


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
    dialect, start, enums = detect(data, opcodes)

    info = summarize(path, opcodes=opcodes)
    if not info["tail"]:
        raise ParseError(
            "cannot trace %s: the parse stops at 0x%X of 0x%X (%s)"
            % (path, info["end"], info["size"],
               info["tail_error"] or "tail not reached"))

    r = Reader(data, dialect, start, opcodes=opcodes,
               template_namespace=info["template_namespace"],
               unguarded_lists=info["unguarded_lists"],
               objvar_three=info["objvar_three"],
               legacy_body=info["legacy_body"])
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
    dialect, start, enums = detect(data, opcodes)
    members = sum(len(e["members"]) for e in enums)

    # Two fields vary between builds of the same dialect: whether
    # `ReadTypeInfo`'s template form carries a namespace, and whether a
    # zero-parameter function still writes its in/out and default-argument
    # lists. Try every combination and keep whichever gets furthest. The
    # tie-break is not "looks plausible" -- it is whether the tail lands
    # exactly on EOF, which only the right answer can do.
    #
    # The default is tried first and kept on a tie, so a module that parses
    # under the assumptions this reader already held keeps them: adding the
    # second field must not silently re-describe the four titles that were
    # already landing on EOF.
    # The body shape is tried in the order that puts each dialect's known
    # answer first, so adding the dimension cannot silently re-describe a
    # module that was already landing on EOF.
    walk, release = _trial(data, dialect, start, len(enums), opcodes)

    return {"path": path, "size": len(data), "dialect": dialect,
            "start": start, "records": release,
            "token_shift": walk["token_shift"],
            "early_behaviours": walk["early_behaviours"],
            "early_opcodes": walk["early_opcodes"],
            "alloc_callee_script_only": walk["alloc_callee_script_only"],
            # The module's own first byte -- unless the build writes no such
            # byte, in which case there is nothing to report and a 0 here
            # would read as "a debug build" for every release module of that
            # generation. The debug fields are unconditional there, so the
            # answer is in the records rather than in a flag.
            "no_debug_info": (data[0] if walk["debug_byte"] else None),
            "enums": enums, "member_count": members,
            "classes": walk["classes"], "classes_declared": walk["classes_declared"],
            "funcdefs": walk["funcdefs"],
            "funcdefs_declared": walk["funcdefs_declared"],
            "blocks": walk["blocks"],
            "tail": walk["tail"], "tail_error": walk["tail_error"],
            "template_namespace": walk["template_namespace"],
            "unguarded_lists": walk["unguarded_lists"],
            "legacy_body": walk["legacy_body"],
            "objvar_three": walk["objvar_three"],
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
        print("  records        %s" % info["records"])
        if info["no_debug_info"] is None:
            print("  noDebugInfo    -- this build writes no such byte, so the "
                  "debug fields are unconditional")
        else:
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
