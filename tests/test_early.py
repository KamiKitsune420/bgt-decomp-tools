"""
Tests for as_early: the 2010 and 2011 BGT module format.

Synthetic inputs only, like the rest of the suite. Each test pins something
that failed QUIETLY while this reader was being built -- every one of these
produced a plausible answer rather than an error:

  * the widest encoded integer has NO free bits in its lead byte, so a
    reader that masked 0xF0 would accept 0xF1 and shift a real value
  * a type-13 instruction's third operand is four RAW bytes, and read as a
    varint it leaves three bytes behind that decode as a valid `POP 1` --
    so the stream re-synchronised at the next instruction and the body
    still ended on its RET, one dword short of its declared length
  * a template type-info carries ONE subtype and no count, so reading a
    count takes the subtype's own tag for 115 of them
  * a global property's initialiser is gated on a byte, and a reader that
    always expects one eats the next record
  * a walk that lands exactly on EOF is the only claim worth making, so a
    module with one byte too many must not pass

Run:  python -m pytest tests/ -q
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import pytest

import as_early
from as_early import Early, Stop


# The ladder, as `ReadEncodedUInt` at 0x004478F0 implements it. Written out
# by hand from the rule rather than produced by an encoder, because an
# encoder written as this decoder's inverse would agree with a wrong decoder.
EU_PAIRS = [
    (b"\x00", 0),
    (b"\x3f", 63),
    (b"\x7f", 127),
    (b"\x80\x80", 128),
    (b"\xbf\xff", 0x3FFF),
    (b"\xc0\x40\x00", 0x4000),
    (b"\xdf\xff\xff", 0x1FFFFF),
    (b"\xe0\x20\x00\x00", 0x200000),
    (b"\xef\xff\xff\xff", 0x0FFFFFFF),
    (b"\xf0\x10\x00\x00\x00", 0x10000000),
    (b"\xf0\xff\xff\xff\xff", 0xFFFFFFFF),
]

#: `asBCTypeSize`, in dwords, as both installed engines store it.
AS_BC_TYPE_SIZE = (0, 1, 1, 1, 2, 2, 3, 3, 2, 3, 2, 1, 2, 3, 2, 2, 4, 3, 2, 3)


def _read(data, method="eu"):
    d = Early(data)
    return getattr(d, method)(), d.p


def test_every_width_of_the_encoded_integer():
    for raw, want in EU_PAIRS:
        got, at = _read(raw)
        assert got == want, "%r read as %d, not %d" % (raw, got, want)
        assert at == len(raw), "%r consumed %d bytes, not %d" % (
            raw, at, len(raw))


def test_the_widest_form_has_no_free_bits_in_its_lead():
    # 0xF0 is a constant, not a mask: every other lead carries the value's
    # top bits, which is exactly why 0xF1 looks like it should work.
    for lead in range(0xF1, 0x100):
        with pytest.raises(Stop):
            _read(bytes([lead]) + b"\x00\x00\x00\x00")


def test_the_first_two_byte_value_is_128_not_64():
    # The newer generation's lead byte carries a SIGN flag and switches to a
    # wide form at 64. This one does not, so 0x40 is still one byte.
    assert _read(b"\x40")[0] == 64
    assert _read(b"\x40\x5b")[1] == 1


# ---- the bytecode step ----------------------------------------------------

ADDIi, RET, POP = 0x82, 0x0A, 0x00
TABLE = {
    ADDIi: {"name": "ADDIi", "type": 13, "operands": 3, "stackInc": 0},
    RET: {"name": "RET", "type": 2, "operands": 1, "stackInc": 0},
    POP: {"name": "POP", "type": 2, "operands": 1, "stackInc": 0},
}

#: One ADDIi whose dword immediate is 0x01000000, then RET 3, then an empty
#: body tail (no object variables, no stack figure, no info, no lines).
#: Those four bytes of immediate are the trap: read as a varint the first is
#: a complete value of 0 and the remaining `00 00 01` is a valid `POP 1`.
BODY = (b"\x04"                              # four dwords of instruction
        b"\x82\x00\x01\x00\x01\x00\x00\x00\x01"
        b"\x0a\x00\x03"
        b"\x00\x00\x00\x00")


def test_a_dword_operand_that_may_be_a_float_is_read_raw():
    assert as_early.BC_READS[13] == (2, 2, 4)
    assert as_early.BC_READS[19] == (2, 2, 4)
    assert as_early.BC_READS[16] == (8, 4)


def test_a_type_thirteen_body_lands_on_its_declared_length():
    d = Early(BODY, table=TABLE)
    d.body({})
    assert d.p == len(BODY), (
        "the body consumed %d of %d bytes" % (d.p, len(BODY)))


def test_reading_that_operand_as_a_varint_invents_an_instruction():
    # The failure this pins is not an exception: the leftover bytes decode
    # cleanly, so the only symptom is one extra dword against the declared
    # length -- which is what made it findable at all.
    wrong = dict(as_early.BC_READS)
    wrong[13] = (2, 2, None)
    seen = []
    d = Early(BODY, table=TABLE)
    declared = d.eu()
    used = 0
    while used < declared:
        op = d.byte()
        info = TABLE[op]
        for width in wrong[info["type"]]:
            d.eu() if width is None else d.raw(width)
        seen.append(info["name"])
        used += as_early.BC_DWORDS[info["type"]]
    # The budget runs out on the invented POP, so the body ends on an
    # instruction that is not RET -- which is the symptom, and the only one.
    assert seen == ["ADDIi", "POP"], seen
    assert used == declared == 4
    assert d.p < len(BODY) - 4, "the RET and its operand were never read"


def test_the_dword_table_is_the_engines():
    assert as_early.BC_DWORDS[:len(AS_BC_TYPE_SIZE)] == AS_BC_TYPE_SIZE


def test_every_type_that_can_be_read_can_be_stepped():
    for kind, reads in as_early.BC_READS.items():
        assert kind < len(as_early.BC_DWORDS), kind
        stored = 1 + sum(w for w in reads if w is not None)
        # A stored instruction is never longer than its expanded form: the
        # encoding is there to make the module smaller.
        assert stored <= 4 * as_early.BC_DWORDS[kind], kind


# ---- records --------------------------------------------------------------

def test_a_template_type_info_carries_one_subtype_and_no_count():
    raw = (b"\x61"                            # 'a'
           b"\x6e\x05array"
           b"\x73"                            # the subtype is an object
           b"\x6f\x6e\x06string"              # ...named 'string'
           b"\x6f")                           # by value, not a handle
    d = Early(raw)
    got = d.type_info()
    assert d.p == len(raw), "consumed %d of %d" % (d.p, len(raw))
    assert got["kind"] == "template" and got["name"] == "array"
    # One argument, shaped as a data type: that is what the IR reads.
    sub, = got["subtypes"]
    assert sub["token"] == 5 and sub["type"]["name"] == "string"
    assert sub["handle"] is False


def test_a_primitive_template_subtype_is_four_raw_bytes():
    raw = b"\x61\x6e\x05array\x74\x44\x00\x00\x00"
    d = Early(raw)
    got = d.type_info()
    assert d.p == len(raw)
    # A primitive argument is a TOKEN, not a type id -- and big-endian like
    # every other multi-byte field in the format.
    assert got["subtypes"] == [{"typeid": 0x44000000}]


def test_a_template_subtype_tag_that_is_neither_is_refused():
    # 0x73 is the subtype's own tag, and reading a COUNT there gives 115.
    with pytest.raises(Stop):
        Early(b"\x61\x6e\x05array\x05\x00").type_info()


# ---- a whole module -------------------------------------------------------

def _module(global_init=b"\x00", extra=b""):
    """The smallest early module that is still a module: one global."""
    return (b"\x00"                           # enums
            b"\x00"                           # classes
            b"\x00"                           # funcdefs
            b"\x00"                           # typedefs
            b"\x01"                           # one global property
            b"\x6e\x03abc"                    # its name
            b"\x44\x00\x00"                   # its data type
            + global_init
            + b"\x00" * 10                    # the functions and the tail
            + extra)


def test_a_minimal_module_lands_exactly_on_eof():
    out = as_early.summarize(_module())
    assert out["eof"] is True and out["error"] is None
    assert out["at"] == out["size"]


def test_the_verified_per_build_answers_win_a_tie():
    # Nothing in this module exercises the namespace field, so the answer is
    # undetermined -- and an undetermined field must keep the answer this
    # reader already holds rather than whichever trial ran first.
    out = as_early.summarize(_module())
    for field, want in as_early.VERIFIED.items():
        assert out[field] == want, field


def test_a_global_propertys_initialiser_is_gated_on_its_byte():
    # Flag 1 means a function record follows; a null one is a complete
    # record, so this module is one byte longer and still lands on EOF.
    out = as_early.summarize(_module(global_init=b"\x01\x00"))
    assert out["eof"] is True, out["error"]


def test_a_global_propertys_init_flag_must_be_zero_or_one():
    out = as_early.summarize(_module(global_init=b"\x02"))
    assert out["eof"] is False
    assert "neither 0 nor 1" in out["error"]


def test_one_byte_too_many_is_not_an_eof_landing():
    out = as_early.summarize(_module(extra=b"\x00"))
    assert out["eof"] is False, (
        "a module with a trailing byte must not read as complete")


def test_a_module_of_the_newer_generation_is_refused():
    # A `len2` module opens with noDebugInfo, which this generation does not
    # have -- so the walk must fail rather than invent sections.
    out = as_early.summarize(b"\x01\x02\x1cphone_callback" + b"\x00" * 40)
    assert out["eof"] is False

# ---- the per-build fields that vary across 2011 -------------------------

#: One class with ONE opening behaviour and a constructor/factory pair.
#: The pair's count is what discriminates: read with three behaviours, the
#: 0x01 lands where a function tag belongs and the parse fails loudly.
ONE_BEHAVIOUR = (b"\x00"               # enums
                 b"\x01"               # one class
                 b"\x6e\x01C"          # its name
                 b"\x00\x08\x00\x05"   # the November 2011 script-object bit
                 b"\x04"               # size 4: a class, not an interface
                 b"\x00"               # funcdefs
                 b"\x00\x00"           # phase 2: derivedFrom, interfaces
                 b"\x00"               # ONE behaviour, null
                 b"\x01\x00\x00"       # one constructor/factory pair
                 b"\x00\x00"           # methods, virtual table
                 b"\x00"               # phase 3: no properties
                 + b"\x00" * 12)       # the tail, every table empty


def test_the_behaviour_count_is_per_build():
    # Perilous Hearts (2011-11) opens a class block with one behaviour where
    # Grodan Gun (2011-09) opens it with three, which is read out of each
    # one of their own WriteTypeDeclaration.
    out = as_early.summarize(ONE_BEHAVIOUR)
    assert out["eof"] is True, out["error"]
    assert out["behaviours"] == 1


def test_three_behaviours_fails_loudly_on_a_one_behaviour_module():
    d = Early(ONE_BEHAVIOUR)
    d.behaviours = 3
    d.SCRIPT_OBJECT = 0x00080000
    with pytest.raises(Stop):
        d.walk()


def test_the_script_object_flag_is_derived_from_the_classes():
    d = Early(b"")
    classes = [{"flags": 0x00080001, "size": 24},
               {"flags": 0x00080005, "size": 89}]
    assert d.script_object_flag(classes) == 0x00080000
    assert d.script_object_flag(
        [{"flags": 0x00010001, "size": 32}]) == 0x00010000


def test_an_ambiguous_script_object_flag_declines():
    # Two candidate bits set in every class, or none at all, is no evidence
    # -- and the caller then keeps the default rather than picking one.
    d = Early(b"")
    assert d.script_object_flag([]) is None
    assert d.script_object_flag([{"flags": 0x00090001, "size": 1}]) is None
    assert d.script_object_flag([{"flags": 0x00000001, "size": 1}]) is None

# ---- namespaces arrived in every record at once -------------------------

#: The smallest module that exercises a namespace in two different records:
#: a global property's and a function signature's. With the flag off the
#: walk dies inside the function record; with it on it lands on EOF.
NAMESPACED = (b"\x00\x00\x00\x00"      # enums, classes, funcdefs, typedefs
              b"\x01"                  # one global property
              b"\x6e\x01g"              # its name
              b"\x00"                  # its namespace
              b"\x44\x00\x00"          # its data type
              b"\x00"                  # no initialiser
              b"\x01"                  # one module function
              b"\x66"                  # 'f'
              b"\x6e\x01f"              # its name
              b"\x00"                  # the signature's namespace
              b"\x44\x00\x00"          # its return type
              b"\x00\x00"              # no parameters, no in/out flags
              b"\x00\x00\x00\x02"      # funcType 2, so no body follows
              b"\x00"                  # no default arguments
              b"\x00"                  # no owner
              b"\x00"                  # no script section
              + b"\x00" * 9)           # the rest of the tail


def test_one_flag_gates_every_namespace():
    out = as_early.summarize(NAMESPACED)
    assert out["eof"] is True, out["error"]
    assert out["namespace"] is True


def test_without_it_the_same_module_desynchronises():
    d = Early(NAMESPACED, namespace=False)
    with pytest.raises(Stop):
        d.walk()


def test_a_type_info_carries_a_namespace_only_when_it_should():
    raw = b"\x6f\x6e\x05timer\x00"
    with_ns = Early(raw)
    with_ns.namespace = True
    got = with_ns.type_info()
    assert got["name"] == "timer" and got["namespace"] == ""
    assert with_ns.p == len(raw)

    without = Early(raw)
    got = without.type_info()
    assert got["name"] == "timer"
    assert without.p == len(raw) - 1, "it read the namespace anyway"


def test_a_template_name_is_followed_by_its_subtype_not_a_namespace():
    # The `a` form is the exception: its name runs straight into the
    # subtype tag even in the build that namespaces everything else.
    raw = b"\x61\x6e\x05array\x73\x6f\x6e\x01T\x00\x6f"
    d = Early(raw)
    d.namespace = True
    got = d.type_info()
    assert d.p == len(raw), "consumed %d of %d" % (d.p, len(raw))
    assert got["name"] == "array"
    sub, = got["subtypes"]
    assert sub["type"]["name"] == "T"

def test_a_subtype_placeholder_is_a_name_and_nothing_else():
    """`array<T>`, where T is the placeholder rather than a real type.

    The 's' form carries no namespace in any build -- only 'o' does -- and
    reading one here eats the handle byte that closes the template, which
    is what kept Antony 9% short of EOF.
    """
    raw = b"\x61\x6e\x05array\x73\x73\x6e\x01T\x6f"
    d = Early(raw)
    d.namespace = True
    got = d.type_info()
    assert d.p == len(raw), "consumed %d of %d" % (d.p, len(raw))
    sub, = got["subtypes"]
    assert sub["type"] == {"kind": "subtype", "name": "T"}


#: The `usedGlobalProps` table carries a namespace per entry in the build
#: that namespaces everything else -- the last record Antony needed.
USED_GLOBAL_PROPS = (b"\x00\x00\x00\x00"   # enums, classes, funcdefs, typedefs
                     b"\x00"               # no global properties
                     b"\x00\x00\x00"       # module, global, bind
                     b"\x00\x00\x00"       # usedTypes, value types, typeIds
                     b"\x00"               # usedFunctions
                     b"\x01"               # ONE usedGlobalProps entry
                     b"\x6e\x01g"          # its name
                     b"\x00"               # its namespace
                     b"\x44\x00\x00"       # its data type
                     b"\x00"               # its flags byte
                     b"\x00\x00")          # usedStringConstants, objectProps


def test_a_used_global_prop_carries_a_namespace_too():
    out = as_early.summarize(USED_GLOBAL_PROPS)
    assert out["eof"] is True, out["error"]
    assert out["namespace"] is True

# ---- the five engine releases -------------------------------------------

def test_every_profile_answers_every_field():
    # A profile is a release's whole answer, and anything it leaves out
    # falls back to VERIFIED -- so a field missing from VERIFIED would be
    # silently absent from every profile.
    for name, profile in as_early.PROFILES:
        for field in profile:
            assert field in as_early.VERIFIED, "%s: %s" % (name, field)


def test_the_first_profile_is_the_verified_one():
    # The release this reader was built from is tried first, so adding a
    # profile cannot re-describe a module that already landed on EOF.
    _name, first = as_early.PROFILES[0][0], as_early.PROFILES[0][1]
    assert first == {}, "the first profile must be the plain verified set"


def test_a_profile_names_the_release_that_read_it():
    out = as_early.summarize(_module())
    assert out["eof"] is True
    assert out["release"] == as_early.PROFILES[0][0]


def test_the_2010_beta_profile_differs_in_what_the_binary_says():
    beta = dict(as_early.PROFILES[-1][1])
    assert as_early.PROFILES[-1][0] == "2010-07"
    # Each of these was read out of that build's own writer, and each one
    # on its own is enough to desynchronise the walk.
    assert beta["size_before_flags"] is True
    assert beta["section_field"] is False
    assert beta["virtual_functype"] == 4
    assert beta["objvar_three"] is False
    assert beta["body_objinfo"] is False
    assert beta["value_type_sizes"] is False
    assert beta["used_object_props"] is False


def test_the_fallback_still_tries_the_verified_answers_first():
    first = as_early._fallback()[0]
    assert first == as_early.VERIFIED

# ---- the path into the decompiler ---------------------------------------

def _asreader():
    nvgt = os.path.join(TOOLS, "nvgt")
    if nvgt not in sys.path:
        sys.path.insert(0, nvgt)
    import asreader
    return asreader


#: Every type token these five modules use, with the type it is. The right
#: column is read off BGT's own shipped source rather than guessed:
#: `int play_extended_1d(string, int, int, int, int, bool, double, float,
#: float, float, bool)` in `include/sound_pool.bgt` reads as
#: `66 (string, 66, 66, 66, 66, 63, 90, 77, 77, 77, 63)`, and
#: `void position_sound_custom_1d(sound@, int, int, float, float, float,
#: float)` agrees independently.
OBSERVED_TOKENS = {63: "bool", 66: "int", 68: "int16", 73: "uint",
                   74: "uint8", 77: "float", 78: "void", 90: "double"}


def test_every_token_these_modules_use_names_a_type():
    names = _asreader().PRIMITIVE_NAMES
    for stored, want in OBSERVED_TOKENS.items():
        got = names.get(as_early.token(stored))
        assert got == want, "%d -> %r, not %r" % (stored, got, want)


def test_an_identifier_token_is_not_shifted():
    # 5 is `ttIdentifier`, and 5 + 4 is the newer reader's string constant
    # -- a shift applied by threshold rather than by target would take it.
    assert as_early.token(5) == 5
    assert as_early.token(0) == 0


def test_the_shift_is_two_more_than_bgt_1_3s():
    try:
        from tools import bgt_asir
    except ImportError:
        import bgt_asir
    # 1.3 is two below the newer numbering and this generation is four:
    # two keywords went into `eTokenType` between 2.19 and 1.3's
    # AngelScript, and two more after it.
    assert as_early.TOKEN_SHIFT == 4
    assert bgt_asir._token(68) == as_early.token(66) == 70


def test_the_behaviour_map_lands_on_names_the_decompiler_knows():
    try:
        from tools import bgt_asir
    except ImportError:
        import bgt_asir
    nvgt = os.path.join(TOOLS, "nvgt")
    if nvgt not in sys.path:
        sys.path.insert(0, nvgt)
    import decompile

    m = bgt_asir.EARLY_BEHAVIOURS
    assert m[0] in decompile.CTORS, "0 is the constructor"
    assert m[1] in decompile.DTORS, "1 is the destructor, 2 later"
    assert m[2] in decompile.DTORS or m[2] == "$beh3", "2 is the factory"
    assert m[10] == "opAssign", "assignment became a method"
    assert m[4] in decompile.BOOKKEEPING, "4 is the engine's own AddRef"


def test_the_addref_is_droppable_in_both_halves():
    nvgt = os.path.join(TOOLS, "nvgt")
    if nvgt not in sys.path:
        sys.path.insert(0, nvgt)
    import decompile
    import purity
    # One says do not print it; the other says do not report it as lost.
    # Either alone leaves the call in the output or in the census.
    name, = decompile.BOOKKEEPING
    assert name in purity.ENGINE_PURE


def test_the_prologue_opcode_is_skipped_rather_than_unhandled():
    nvgt = os.path.join(TOOLS, "nvgt")
    if nvgt not in sys.path:
        sys.path.insert(0, nvgt)
    import decompile
    assert "PUSH" in decompile.SKIP_OPS
    # ...and no engine the newer reader models has an opcode of that name,
    # which is what makes skipping it unreachable for an NVGT module.
    assert "PUSH" not in {n for n, _b, _s, _i in _asreader().OPCODES.values()}


def test_the_dropped_opcodes_are_this_generations_alone():
    # RDS4, RDS8 and POP were renamed or absorbed by the engine itself, so
    # the newer set has none of them -- which is why mapping them cannot
    # reach a module of the newer generation.
    newer = {n for n, _b, _s, _i in _asreader().OPCODES.values()}
    for name in ("RDS4", "RDS8", "POP"):
        assert name not in newer, name
    assert "RDSPtr" in newer and "PopPtr" in newer


def test_every_bytecode_type_has_a_name_and_a_read():
    # The field layout comes from the numeric type, because the opcode
    # NUMBERING moved: 0x01 is `PUSH` here and `PshGPtr` there.
    try:
        from tools import bgt_asir
    except ImportError:
        import bgt_asir
    for kind, name in as_early.BC_TYPE_NAMES.items():
        if kind == 0:                       # asBCTYPE_INFO: no instruction
            continue
        assert kind in as_early.BC_READS, kind
        assert name in bgt_asir.BC_FIELDS, name
        assert len(bgt_asir.BC_FIELDS[name]) == len(as_early.BC_READS[kind]), \
            "%s: %d fields, %d reads" % (name, len(bgt_asir.BC_FIELDS[name]),
                                         len(as_early.BC_READS[kind]))

# ---- positions, not instruction numbers ---------------------------------

def test_a_position_is_a_dword_offset_on_the_early_path_only():
    """The one operand kind the two engines do NOT serialise alike.

    The newer writer turns every stored program position into an
    instruction-number delta so that one module loads into builds whose
    instruction widths differ; `asreader` restores the dword offset from
    it. The 2011 writer never did that -- `WriteByteCode` at 0x004492D0
    compares the opcode against twenty-four numbers and the jump family
    0x0B..0x11 is not among them -- so there is nothing to restore.

    Measured both ways on every title, and it discriminates in both
    directions: 9,808 early jumps land exactly on an instruction boundary
    as dwords and 73-82% of them do as instruction numbers, while Battle
    of the Hunter is 100% as instruction numbers and 72.5% as dwords.
    """
    try:
        from tools import bgt_asir
    except ImportError:
        import bgt_asir
    nvgt = os.path.join(TOOLS, "nvgt")
    if nvgt not in sys.path:
        sys.path.insert(0, nvgt)
    import asreader

    # The flag defaults off, so nothing about the newer path moves.
    assert asreader._Reader.positions_are_dwords is False
    assert bgt_asir._Translator(None).positions_are_dwords is False
    assert bgt_asir._Translator(None, True).positions_are_dwords is True
    # ...and `_translate_function` is borrowed rather than transcribed, so
    # the flag has to be read off `self` there.
    import inspect
    body = inspect.getsource(asreader._Reader._translate_function)
    assert body.count("self.positions_are_dwords") == 2, \
        "the jump branch and the position conversion each ask once"


def test_a_pointer_operand_is_named_by_the_newer_reader():
    """A 32-bit build calls it a DWORD where the 64-bit engine calls it a
    QWORD, and the field NAME is what every resolver reads.

    `REFCPY` is `asBCTYPE_DW_ARG` in a 2011 runtime and `asBCTYPE_QW_ARG`
    in the engine `asreader` models, and `TranslateFunction` reads
    `qw_arg` -- so the operand was written to `dw_arg` and read as 0,
    which is `used_types[0]` for an object type and `used_strings[0]` for
    a literal. 13,887 instructions across the five titles, `PGA` 4,909 of
    them, which is every string literal in all five games.
    """
    try:
        from tools import bgt_asir
    except ImportError:
        import bgt_asir
    # Every pointer-sized operand the early builds name narrowly.
    for name in ("PGA", "LDG", "PshG4", "SetG4", "CpyVtoG4", "CpyGtoV4",
                 "LdGRdR4", "FREE", "REFCPY", "OBJTYPE", "FuncPtr"):
        newer = bgt_asir.LEGACY_BC_TYPE.get(name,
                                           bgt_asir.NEWER_BC_TYPE.get(name))
        assert newer is not None, name
        assert "qw_arg" in bgt_asir.BC_FIELDS[newer], name
    # ...and the map is keyed by NAME, because the numbering moved: 0x01 is
    # `PUSH` here and `PshGPtr` there, so a lookup by number would answer
    # about a different instruction.
    assert "PUSH" not in bgt_asir.NEWER_BC_TYPE


def test_a_zero_into_a_reference_type_is_null():
    """`@h = null` is `SetV4 h, 0` where there is no `ClrVPtr`.

    BGT's own `sound_pool_item::reset` is the shape, and typed from the
    slot that constant rendered as `sound(0)` -- a constructor `sound` has
    not. `_is_reference_type` is the discriminator, so an enum and a
    value type are untouched and the enum conversion the branch exists for
    still happens.
    """
    nvgt = os.path.join(TOOLS, "nvgt")
    if nvgt not in sys.path:
        sys.path.insert(0, nvgt)
    import inspect
    import decompile
    src = inspect.getsource(decompile.FuncDecompiler._typed_constant)
    null_at = src.index("_is_reference_type")
    enum_at = src.index('kind in ("enum", "app")')
    assert null_at < enum_at, "the reference-type test must come first"


def test_two_handles_compared_want_is():
    """`CMPi h1, h2` is an identity test, and nothing else says so.

    `CmpPtr` sets the flag and a `null` operand is the other witness. This
    engine has neither for the shape: a handle is a four-byte slot, so two
    of them are compared with `CMPi` and the `null` the source wrote has
    been materialised into a slot first.

    **Both** operands must be handles. One is not enough -- a script class
    with an `opEquals` is compared by value through its handle.
    """
    nvgt = os.path.join(TOOLS, "nvgt")
    if nvgt not in sys.path:
        sys.path.insert(0, nvgt)
    from decompile import Atom, _handle_comparison
    try:
        from tools.nvgt.asreader import DataType, TypeInfo
    except ImportError:
        from asreader import DataType, TypeInfo

    sound = TypeInfo(kind="app", name="sound")
    handle = DataType(token_type=5, obj_type=sound, is_object_handle=True)
    value = DataType(token_type=5, obj_type=sound)
    both = (Atom("var", "local_1", data_type=handle),
            Atom("var", "local_2", data_type=handle))
    one = (Atom("var", "local_1", data_type=handle),
           Atom("var", "local_2", data_type=value))
    assert _handle_comparison(both, False) is True
    assert _handle_comparison(one, False) is False
    # The flag and the null operand still answer on their own.
    assert _handle_comparison(one, True) is True
    assert _handle_comparison((Atom("const", "null"),
                               Atom("var", "x")), False) is True


def test_the_string_factory_is_named_in_one_place():
    """A registered name is a per-build field, and this one has three
    spellings. Two places knowing it is the shape this file keeps
    recording -- the construction pre-pass needs the same list as the
    rendering branch, because the 2010-2012 factory CONSTRUCTS its slot.
    """
    nvgt = os.path.join(TOOLS, "nvgt")
    if nvgt not in sys.path:
        sys.path.insert(0, nvgt)
    import decompile
    assert decompile._is_string_factory("_string_factory_")
    assert decompile._is_string_factory("$str")
    assert decompile._is_string_factory("nvgt_stringfactory")
    assert not decompile._is_string_factory("")
    assert not decompile._is_string_factory("string_factory")
    # The construction pre-pass and the rendering branch both go through
    # it, which is the whole point of the helper.
    import inspect
    src = inspect.getsource(decompile.FuncDecompiler)
    assert src.count("_is_string_factory(") == 2
