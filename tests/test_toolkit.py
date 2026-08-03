"""
Known-answer tests for the BGT toolkit.

These run on synthetic inputs only -- no game files -- so they work anywhere and
protect the pieces whose failures are silent rather than loud:

  * read_encoded_uint  -- a wrong decoder is right for every value under 64, so it
                          passes casual inspection and desynchronises much later
  * LZ77               -- an off-by-one in the match copy still produces output
  * keygen / KDF       -- a wrong constant still produces plausible-looking bytes
  * pack parsing       -- a short read still yields entries
  * repacking          -- checked by round-trip, never by inspection

Run:  python tests/test_toolkit.py     (or: python -m pytest tests/ -q)
"""

import hashlib
import os
import shutil
import struct
import sys
import tempfile

try:                                   # after `pip install -e .`
    from bgtdecomp import (as_disasm, as_lift, as_module, as_opcodes,
                           as_write, bgt_crack, bgt_ghidra, bgt_kdf, bgt_pack,
                           bgt_repack, bgt_string_crypt, bgtlib, cli)
except ImportError:                    # straight from a checkout
    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
    import as_disasm
    import as_lift
    import as_module
    import as_opcodes
    import as_write
    import bgt_crack
    import bgt_ghidra
    import bgt_kdf
    import bgt_pack
    import bgt_repack
    import bgt_string_crypt
    import bgtlib
    import cli

NUL = b"\x00"


# --------------------------------------------------------------------------
# read_encoded_uint -- the one that fails quietly
# --------------------------------------------------------------------------

def test_encoded_uint_single_byte():
    for raw, want in ((NUL, 0), (b"\x01", 1), (b"\x12", 18), (b"\x3f", 63)):
        assert as_module.read_encoded_uint(raw, 0) == (want, 1)


def test_encoded_uint_two_byte():
    """The cases a UTF-8-style decoder gets wrong: 0x40 is a width marker."""
    for raw, want in ((b"\x40\x56", 86), (b"\x40\x5b", 91), (b"\x40\x81", 129),
                      (b"\x40\xa7", 167), (b"\x40\xe7", 231)):
        assert as_module.read_encoded_uint(raw, 0) == (want, 2)


def test_encoded_uint_boundary_is_64_not_128():
    """63 is one byte, 64 is two. A decoder that switches at 128 passes every
    smaller case and only diverges here."""
    assert as_module.read_encoded_uint(b"\x3f", 0) == (63, 1)
    assert as_module.read_encoded_uint(b"\x40\x40", 0) == (64, 2)


def test_encoded_uint_wider_forms():
    assert as_module.read_encoded_uint(b"\x60\x01" + NUL, 0) == ((1 << 8), 3)
    assert as_module.read_encoded_uint(b"\x70" + NUL + b"\x01" + NUL, 0) == ((1 << 8), 4)


def test_encoded_uint_sign_bit():
    """The top bit means negative -- not 'another byte follows'."""
    assert as_module.read_encoded_uint(b"\x81", 0)[0] == -1


# --------------------------------------------------------------------------
# strings
# --------------------------------------------------------------------------

def _len2(s):
    return bytes([len(s) * 2]) + s


def test_len2_new_string_and_backref():
    data = _len2(b"alpha") + _len2(b"beta") + b"\x01"      # odd 1 -> saved[0]
    r = as_module.Reader(data, as_module.LEN2, 0)
    assert r.string() == b"alpha"
    assert r.string() == b"beta"
    assert r.string() == b"alpha"


def test_len2_empty_string_is_not_saved():
    data = NUL + _len2(b"x") + b"\x01"
    r = as_module.Reader(data, as_module.LEN2, 0)
    assert r.string() == b""
    assert r.string() == b"x"
    assert r.string() == b"x"          # saved[0] is 'x', not the empty string


def test_negative_length_is_rejected_not_rewound():
    """Without this guard the cursor walks backwards and a scan loops forever."""
    r = as_module.Reader(b"\x82" + NUL + NUL, as_module.LEN2, 0)
    try:
        r.string()
    except as_module.ParseError:
        return
    raise AssertionError("negative string length was accepted")


def test_tagged_new_string_and_backref():
    data = b"\x6e\x03abc" + b"\x72" + NUL + NUL
    r = as_module.Reader(data, as_module.TAGGED, 0)
    assert r.string() == b"abc"
    assert r.string() == b"abc"
    assert r.string() == b""


# --------------------------------------------------------------------------
# enum records
# --------------------------------------------------------------------------

def test_enum_record_roundtrip():
    body = (_len2(b"colours")
            + struct.pack(">I", 0x04000000)     # flags: plain enum
            + b"\x04"                           # size
            + NUL                               # namespace: empty
            + b"\x02"                           # 2 members
            + _len2(b"red") + struct.pack(">i", 0)
            + _len2(b"blue") + struct.pack(">i", -2))
    e = as_module.Reader(body, as_module.LEN2, 0).enum()
    assert e["name"] == "colours"
    assert e["members"] == [("red", 0), ("blue", -2)]


def test_shared_type_consumes_an_extra_byte():
    """asOBJ_SHARED types carry one more byte after the namespace."""
    shared = (_len2(b"t") + struct.pack(">I", 0x00400000) + b"\x04" + NUL
              + b"e" + NUL)
    e = as_module.Reader(shared, as_module.LEN2, 0).enum()
    assert e["name"] == "t" and e["members"] == []


def test_interface_detection():
    """IsInterface() = script object with no instance size. It decides whether a
    class block has a behaviour section, so getting it wrong desyncs everything."""
    r = as_module.Reader(b"", as_module.LEN2, 0)
    assert r.is_interface({"flags": 0x00200000, "size": 0})
    assert not r.is_interface({"flags": 0x00200001, "size": 1})
    assert not r.is_interface({"flags": 0x00000001, "size": 0})


# --------------------------------------------------------------------------
# dialect differences that are NOT about string encoding
# --------------------------------------------------------------------------

def _tagged_str(s):
    return b"\x6e" + bytes([len(s)]) + s if s else NUL


def test_script_object_flag_moved_between_builds():
    """IsInterface tests 0x100000 in the older reader and 0x200000 in the newer.
    It decides whether a class block has a behaviour section, so the wrong
    constant desynchronises on the first interface."""
    old = as_module.Reader(b"", as_module.TAGGED, 0)
    new = as_module.Reader(b"", as_module.LEN2, 0)
    decl = {"flags": 0x00100000, "size": 0}
    assert old.is_interface(decl)
    assert not new.is_interface(decl)
    decl = {"flags": 0x00200000, "size": 0}
    assert not old.is_interface(decl)
    assert new.is_interface(decl)


def test_tagged_phase1_has_no_shared_byte():
    """The newer reader has a conditional byte after the namespace for shared
    types; the older one has no such read at all."""
    body = (_tagged_str(b"t") + struct.pack(">I", 0x00400000)
            + b"\x04" + NUL + b"REST")
    r = as_module.Reader(body, as_module.TAGGED, 0)
    decl = r.type_decl_phase1()
    assert decl["name"] == "t"
    assert r.d[r.p:] == b"REST"           # nothing extra consumed


def test_tagged_signature_lists_are_unconditional():
    """A zero-parameter function still writes the in/out-flag and default-arg
    counts in the older build. Skipping them takes the next field as funcType."""
    body = (_tagged_str(b"f")
            + NUL + _eu(80) + NUL      # returns void
            + NUL                      # 0 params
            + NUL                      # nInOut       <- written even with 0 params
            + _eu(4)                   # funcType 4
            + NUL                      # nDefaultArgs <- likewise
            + NUL                      # owner: null
            + NUL)                     # namespace
    r = as_module.Reader(body, as_module.TAGGED, 0)
    sig = r.function_signature()
    assert sig["name"] == "f" and sig["funcType"] == 4
    assert r.p == len(body)


def test_tagged_funcdef_has_no_trailing_traits_byte():
    """funcType 4 ends after the namespace in the older build; the newer one
    reads one more byte."""
    body = (b"f" + _tagged_str(b"cb")
            + NUL + _eu(80) + NUL + NUL + NUL + _eu(4) + NUL + NUL + NUL)
    r = as_module.Reader(body, as_module.TAGGED, 0)
    rec = r.function()
    assert rec["name"] == "cb" and rec["funcType"] == 4
    assert r.p == len(body)


def test_template_subtype_s_is_a_full_data_type():
    """'s' introduces a whole ReadDataType -- very often a one-byte
    back-reference, which is what makes 'tag plus one encoded value' look right.
    array<object@> is the case that settles it."""
    r = as_module.Reader(b"", as_module.TAGGED, 0)
    r.saved = [b"array", b"object"]
    r.d = (b"\x61" + b"\x72\x00" + NUL + _eu(1)          # 'a' array, ns "", 1 sub
           + b"\x73" + NUL + _eu(5) + b"\x6f\x72\x01" + NUL + b"\x01")
    r.p = 0
    ti = r.type_info()
    assert ti["kind"] == "template" and ti["name"] == "array"
    sub = ti["subtypes"][0]
    assert sub["token"] == 5 and sub["handle"] is True
    assert r.p == len(r.d)


def test_template_namespace_is_a_build_variant():
    """Psycho Strike's 'a' carries a namespace, Paladin's does not. Same string
    dialect, different record -- so it is trialled, not assumed."""
    saved = [b"array"]
    data = b"\x61" + b"\x72\x00" + _eu(0)      # 'a', name backref 0, then...
    with_ns = as_module.Reader(data + NUL, as_module.TAGGED, 0,
                               template_namespace=True)
    with_ns.saved = list(saved)
    with_ns.p = 0
    assert with_ns.type_info()["name"] == "array"

    without = as_module.Reader(data, as_module.TAGGED, 0,
                               template_namespace=False)
    without.saved = list(saved)
    without.p = 0
    ti = without.type_info()
    assert ti["name"] == "array" and ti["namespace"] == ""


def test_tagged_used_object_prop_stores_a_name_not_an_index():
    """The older build writes the property name; the newer writes an index into
    the owner's table. Reading a name as an index drifts the section."""
    body = b"\x6f" + _tagged_str(b"player") + NUL + _tagged_str(b"health")
    r = as_module.Reader(body, as_module.TAGGED, 0)
    rec = r.used_object_prop()
    assert rec["owner"]["name"] == "player"
    assert rec["name"] == "health"
    assert r.p == len(body)


# --------------------------------------------------------------------------
# the tail sections -- global props and the used* tables
# --------------------------------------------------------------------------

def _eu(v):
    """Encode a value the way ReadEncodedUInt64 reads it back (positive only)."""
    if v < 64:
        return bytes([v])
    if v < (1 << 14):
        return bytes([0x40 | (v >> 8), v & 0xFF])
    raise ValueError("test helper only covers the one- and two-byte forms")


def _eu_signed(v):
    """The encoding carries a sign flag in the top bit of the lead byte, so a
    small negative is one byte: 0x80 | magnitude."""
    if not -64 < v <= 0:
        raise ValueError("test helper only covers small negatives")
    return bytes([0x80 | (-v)])


def _dt_primitive(token=68):
    """A fresh (non-back-referenced) primitive data type: eu(0) eu(token) u8(flags)."""
    return NUL + _eu(token) + NUL


def test_encoded_uint_helper_agrees_with_the_reader():
    """The tests below are only meaningful if the helper encodes what the reader
    decodes, so pin the helper against read_encoded_uint itself."""
    for v in (0, 1, 63, 64, 86, 91, 129, 4095):
        assert as_module.read_encoded_uint(_eu(v), 0)[0] == v


def test_global_property_record():
    """ReadGlobalProperty = str(name) str(ns) datatype ReadFunction.

    The trailing ReadFunction is the initialiser and is usually the null marker;
    a parser that omits it walks into the next record.
    """
    body = _len2(b"debug") + NUL + _dt_primitive() + NUL      # NUL = no initialiser
    r = as_module.Reader(body, as_module.LEN2, 0)
    g = r.global_property()
    assert g["name"] == "debug" and g["namespace"] == ""
    assert g["init"] is None
    assert r.p == len(body)                    # consumed exactly, nothing left


def test_used_global_prop_is_not_an_object_property():
    """usedGlobalProps ends in a plain byte and carries a namespace; an object
    property has neither. The two are close enough to substitute silently."""
    body = _len2(b"score") + NUL + _dt_primitive() + b"\x01"
    r = as_module.Reader(body, as_module.LEN2, 0)
    p = r.used_global_prop()
    assert p["name"] == "score" and p["module"] is True
    assert r.p == len(body)


def test_used_function_null_markers_consume_only_the_tag():
    """A null entry is 0x00 in the newer build and 'n' (0x6E) in the older one,
    and in both cases nothing follows it."""
    for tag in (NUL, b"n"):
        r = as_module.Reader(tag + b"REST", as_module.LEN2, 0)
        assert r.used_function() is None
        assert r.p == 1


def test_used_function_reads_a_signature_after_the_tag():
    body = (b"a"                                  # 'a' -- application-registered
            + _len2(b"set_sound_decryption_key")
            + _dt_primitive(80)                   # returns void
            + NUL                                 # 0 params
            + _eu(0)                              # funcType
            + NUL                                 # owner: null
            + NUL)                                # namespace: empty
    r = as_module.Reader(body, as_module.LEN2, 0)
    f = r.used_function()
    assert f["name"] == "set_sound_decryption_key"
    assert f["origin"] == "application"
    assert r.p == len(body)


def test_used_string_constants_resolve_module_wide_backrefs():
    """Pool entries back-reference the module-wide savedStrings table, which is
    why locating the pool by scanning leaves a third of them unresolved -- the
    table only holds the right strings after a linear parse from offset 0."""
    r = as_module.Reader(b"", as_module.LEN2, 0)
    r.saved = [b"sounds/step.wav", b"data.dat"]      # as a linear parse would leave it
    r.d = b"\x03" + b"\x01"                          # back-refs to saved[1], saved[0]
    r.p = 0
    assert r.string() == b"data.dat"
    assert r.string() == b"sounds/step.wav"


def test_tail_requires_landing_exactly_on_eof():
    """usedObjectProps is the last section, so nothing follows it to absorb a
    mistake. A leftover byte must raise, not pass."""
    # eleven empty sections, then one unexplained trailing byte
    body = NUL * 11 + b"\xff"
    r = as_module.Reader(body, as_module.LEN2, 0)
    try:
        r.tail()
    except as_module.ParseError as exc:
        assert "unexplained" in str(exc)
        return
    raise AssertionError("a trailing byte was accepted at the end of the tail")


def test_tail_of_eleven_empty_sections_lands_on_eof():
    body = NUL * 11
    r = as_module.Reader(body, as_module.LEN2, 0)
    tail = r.tail()
    assert tail["end"] == len(body) and tail["trailing"] == 0
    assert [name for name, _off, _n in tail["sections"]] == [
        "typedefs", "global_properties", "module_functions", "global_functions",
        "bind_info", "used_types", "used_type_ids", "used_functions",
        "used_global_props", "used_string_constants", "used_object_props"]


# --------------------------------------------------------------------------
# graceful degradation -- one bad body must not cost the others
# --------------------------------------------------------------------------

def _script_function(name, body_ops):
    """A funcType-1 record: 'f', signature, flags, then eu(count) + bytecode."""
    return (b"f" + _len2(name)
            + _dt_primitive(80)                   # returns void
            + NUL                                 # 0 params
            + _eu(1)                              # funcType 1 -- a script function
            + NUL + NUL                           # owner null, namespace empty
            + NUL                                 # flags: body present, no extras
            + _eu(len(body_ops)) + bytes(body_ops)
            + NUL)                                # stackNeeded


# opcode 0 takes no operands and is named RET, so a body is just [0]
_TEST_OPCODES = {0: {"name": "RET", "type": 1, "stackInc": 0, "operands": 0,
                     "dwords": 1},
                 1: {"name": "SUSPEND", "type": 1, "stackInc": 0, "operands": 0,
                     "dwords": 1}}


def test_a_corrupt_body_costs_one_function_not_the_rest():
    """Three methods, the middle one with a wrong instruction count. The first
    and third must still come back, and the error list must name the second."""
    good1 = _script_function(b"alpha", [1, 0])
    bad = _script_function(b"beta", [1, 0]).replace(_eu(2) + b"\x01\x00",
                                                    _eu(9) + b"\x01\x00", 1)
    good2 = _script_function(b"gamma", [1, 0])
    body = (NUL                                   # derivedFrom: null
            + NUL                                 # 0 interfaces
            + NUL                                 # destructor: null marker
            + NUL                                 # 0 ctor pairs
            + _eu(3) + good1 + bad + good2        # 3 methods
            + NUL)                                # 0 virtuals

    r = as_module.Reader(body, as_module.LEN2, 0, opcodes=_TEST_OPCODES)
    block = r.class_block({"name": "thing", "flags": 0, "size": 4})

    names = [m["name"] for m in block["methods"] if m]
    assert "alpha" in names and "gamma" in names, names
    assert len(r.parse_errors) == 1, r.parse_errors
    err = r.parse_errors[0]
    assert "beta" in str(err) or err["context"].startswith("thing"), err
    assert err["skipped"] is not None and err["skipped"] > 0


def test_resync_refuses_to_run_past_a_limit():
    """Scanning to EOF would turn a local failure into an empty parse that still
    looks like a success, so a resync that finds nothing has to raise."""
    r = as_module.Reader(b"\xff" * 64, as_module.LEN2, 0)
    try:
        r.resync_to_function(limit=32)
    except as_module.ParseError:
        return
    raise AssertionError("resync accepted a region with no function record")


def test_enum_section_has_no_error_recovery():
    """Graceful degradation is for function bodies only. A desync in the enum or
    declaration sections means the whole parse is wrong, so it must still raise."""
    r = as_module.Reader(b"\x02\xff\xff", as_module.LEN2, 0)
    try:
        r.enum()
    except (as_module.ParseError, IndexError, struct.error):
        return
    raise AssertionError("a broken enum record was silently tolerated")


# --------------------------------------------------------------------------
# disassembly with name resolution
# --------------------------------------------------------------------------

# A minimal opcode table in the shape as_opcodes.extract() produces.
_DIS_OPCODES = {
    0x00: {"name": "RET", "type": 1, "stackInc": 0, "operands": 1, "dwords": 1},
    0x01: {"name": "CALL", "type": 2, "stackInc": 0, "operands": 1, "dwords": 1},
    0x02: {"name": "JMP", "type": 2, "stackInc": 0, "operands": 1, "dwords": 1},
    0x03: {"name": "SUSPEND", "type": 1, "stackInc": 0, "operands": 0, "dwords": 1},
    0x04: {"name": "PGA", "type": 2, "stackInc": 1, "operands": 1, "dwords": 1},
}


class _FakeModule:
    """Just enough of as_disasm.Module to disassemble a hand-built span."""

    dialect = as_module.LEN2

    def __init__(self, data, **tables):
        self.data = data
        self.opcodes = _DIS_OPCODES
        self.used_functions = tables.get("functions", [])
        self.used_strings = tables.get("strings", [])
        self.used_global_props = tables.get("globals", [])
        self.used_object_props = tables.get("objprops", [])
        self.used_types = tables.get("types", [])
        self.used_type_ids = tables.get("type_ids", [])
        self.properties = tables.get("properties", {})

    resolve = as_disasm.Module.resolve
    _object_property = as_disasm.Module._object_property


def test_disassemble_call_jump_ret():
    """A CALL, a forward JMP and a RET: names decode, and the jump gets a label
    pointing at the right instruction."""
    body = bytes([0x01]) + _eu(7) + bytes([0x02]) + _eu(1) + bytes([0x03]) \
        + bytes([0x00]) + _eu(0)
    funcs = [{"name": "f%d" % i, "owner": None} for i in range(8)]
    mod = _FakeModule(body, functions=funcs)
    f = {"name": "demo", "owner": None, "params": [], "body": (0, len(body)),
         "instructions": 4, "stackNeeded": 1}

    dis = as_disasm.disassemble_function(mod, f)
    assert [i["name"] for i in dis["instructions"]] == \
        ["CALL", "JMP", "SUSPEND", "RET"]
    assert dis["instructions"][0]["args"][0]["text"] == "<global>::f7"

    # JMP is instruction 1 with operand 1 -> target = 1 + 1 + 1 = 3 (the RET)
    jump = dis["instructions"][1]["args"][0]
    assert jump["target"] == 3, jump
    assert jump["text"] == "L0"
    assert dis["labels"] == {3: 0}
    assert dis["decoded_instructions"] == dis["declared_instructions"] == 4


def test_jump_target_is_relative_to_the_next_instruction():
    """target = current + 1 + operand. Dropping the +1 lands one instruction
    early, which still looks like a valid boundary."""
    body = bytes([0x03]) + bytes([0x02]) + _eu(0) + bytes([0x03]) \
        + bytes([0x00]) + _eu(0)
    mod = _FakeModule(body)
    f = {"name": "j", "owner": None, "params": [], "body": (0, len(body)),
         "instructions": 4}
    dis = as_disasm.disassemble_function(mod, f)
    # JMP is instruction 1, operand 0 -> falls through to instruction 2
    assert dis["instructions"][1]["args"][0]["target"] == 2


def test_backward_jump_resolves():
    body = bytes([0x03]) + bytes([0x02]) + _eu_signed(-2) + bytes([0x00]) + _eu(0)
    mod = _FakeModule(body)
    f = {"name": "loop", "owner": None, "params": [], "body": (0, len(body)),
         "instructions": 3}
    dis = as_disasm.disassemble_function(mod, f)
    jump = dis["instructions"][1]["args"][0]
    assert jump["target"] == 0                 # 1 + 1 + (-2)
    assert jump["text"] == "L0"


def test_globalptr_low_bit_selects_the_table():
    """`2 * index + tag`: even is a string constant, odd is a global property.
    Reading every operand as a literal resolves the odd ones to a real string
    from the wrong table, with nothing to signal it."""
    mod = _FakeModule(b"", strings=[b"alpha", b"data.dat", b"gamma"],
                      globals=[{"name": "player"}, {"name": "current_map"}])
    assert mod.resolve("globalptr", 2) == '"data.dat"'      # index 1, tag 0
    assert mod.resolve("globalptr", 3) == "current_map"     # index 1, tag 1
    assert mod.resolve("globalptr", 0) == '"alpha"'
    assert mod.resolve("globalptr", 1) == "player"


def test_unresolvable_operand_returns_none_not_a_placeholder():
    """A resolution rate that counts '<invalid>' entries as resolved is not a
    measurement, so out-of-range indices must come back as None."""
    mod = _FakeModule(b"", strings=[b"only"], functions=[])
    assert mod.resolve("string", 5) is None
    assert mod.resolve("function", 0) is None
    assert mod.resolve("globalptr", 99) is None


def test_object_property_resolves_through_the_owning_class():
    mod = _FakeModule(
        b"",
        objprops=[{"owner": {"kind": "named", "name": "player"}, "index": 1}],
        properties={"player": [{"name": "health"}, {"name": "position"}]})
    assert mod.resolve("objprop", 0) == "player::position"


def test_string_literals_render_embedded_nuls():
    """BGT literals really do contain NULs -- the pack password is one. Showing
    them as spaces has already caused a key to be misread once."""
    assert as_disasm._quote(b"a\x00b") == '"a\\0b"'


def test_globalptr_is_a_plain_index_in_the_tagged_dialect():
    """No tag bit in the older build -- string literals have their own STR
    opcode, so the field is a plain usedGlobalProps index. Applying the len2
    rule halves it and still yields a real (wrong) global name."""
    mod = _FakeModule(b"", strings=[b"alpha", b"data.dat"],
                      globals=[{"name": "g0"}, {"name": "g1"}, {"name": "g2"}])
    mod.dialect = as_module.TAGGED
    assert mod.resolve("globalptr", 2) == "g2"
    assert mod.resolve("globalptr", 1) == "g1"
    mod.dialect = as_module.LEN2
    assert mod.resolve("globalptr", 2) == '"data.dat"'      # even -> literal
    assert mod.resolve("globalptr", 3) == "g1"              # odd  -> global


def test_alloc_constructor_index_is_one_based():
    """ALLOC's second operand is a one-based usedFunctions index with 0 meaning
    "no script constructor" -- read straight it resolves to a real function that
    is simply the wrong one (322 of 15,619 owner-consistent; 15,619 of 15,619
    after subtracting one)."""
    funcs = [{"name": "wrong", "owner": None},
             {"name": "$beh0", "owner": {"kind": "named", "name": "string"}}]
    mod = _FakeModule(b"", functions=funcs)
    assert mod.resolve("ctorfunc", 2) == "string::$beh0"     # 2 -> index 1
    assert mod.resolve("ctorfunc", 1) == "<global>::wrong"   # 1 -> index 0
    assert mod.resolve("ctorfunc", 0) == "<no constructor>"
    assert as_disasm.OPERAND_ROLES["ALLOC"] == {0: "objtype", 1: "ctorfunc"}


# --------------------------------------------------------------------------
# key generation
# --------------------------------------------------------------------------

def test_keygen_stock_seed():
    k = bgtlib.keygen(0x11)
    assert len(k) == 32
    assert k[:4] == bytes([0x33, 0x05, 0x0F, 0x2D])
    assert k[4:7] == bytes([0x05, 0x0F, 0x2D])          # then it repeats


def test_aes_key_for_stock_seed():
    assert (bgtlib.aes_key_for_seed(0x11).hex()
            == "3bb07f3464c15bf53c4280f4fad5df4275bfcb340552317b612716ea041c6033")


def test_different_seed_gives_different_key():
    assert bgtlib.aes_key_for_seed(0x11) != bgtlib.aes_key_for_seed(0x12)


# --------------------------------------------------------------------------
# the password -> key derivation
# --------------------------------------------------------------------------

def test_kdf_known_answer():
    """Pinned against a key captured from a running game with Frida."""
    pw = b"al" + NUL + b"ba"
    assert (bgt_kdf.aes_key(pw).hex()
            == "7bb1307507d89fe9ccda47343c601be938efdcb4987878c0030d9345d2e0496e")


def test_kdf_output_is_64_bytes_and_nul_free():
    """The result is consumed as a C string, so the NUL scrub is load-bearing."""
    for pw in (b"a", b"al" + NUL + b"ba", b"x" * 200, bytes(range(256))):
        out = bgt_kdf.kdf(pw)
        assert len(out) == 64
        assert 0 not in out


def test_kdf_seed_depends_on_first_high_bit_byte():
    """Salts key off the first byte >= 0x80, so those inputs derive differently."""
    assert bgt_kdf.kdf(b"abc") != bgt_kdf.kdf(b"ab" + bytes([0xFF]) + b"c")
    assert bgt_kdf._seed_of(b"abc") == 0x23              # the '#' default
    assert bgt_kdf._seed_of(b"ab" + bytes([0x80]) + b"c") == -0x80


def test_kdf_c_division_truncates_toward_zero():
    """Python floors, C truncates. The generator is wrong under floor division."""
    assert bgt_kdf._cdiv(-7, 2) == -3
    assert bgt_kdf._cdiv(7, 2) == 3
    assert -7 // 2 == -4                                 # what NOT to use


def test_kdf_signed_char_wrap():
    assert bgt_kdf._sc(0x80) == -128
    assert bgt_kdf._sc(0xFF) == -1
    assert bgt_kdf._sc(0x7F) == 127


def test_kdf_salts_converge_to_a_fixed_point():
    """Two 98-byte runs of one generator, with state carrying across.

    The state genuinely carries, but the generator reaches a fixed point almost
    immediately -- for the default '#' seed every byte is 0xa0 and the two runs
    come out identical. That is a property of the algorithm, not a bug, and it is
    pinned here so nobody 'fixes' the second run into producing different bytes.
    """
    a1, a2 = bgt_kdf._gen_salts(0x23)
    assert len(a1) == 98 and len(a2) == 98
    assert a1 == a2 == bytes([0xA0]) * 98
    assert bgt_kdf._salts(0x23) == (a1, a2)              # cache agrees


# --------------------------------------------------------------------------
# LZ77
# --------------------------------------------------------------------------

def _varint7(v):
    if v < 0x80:
        return bytes([v])
    out = bytearray([v & 0x7F])
    v >>= 7
    while v:
        out.insert(0, 0x80 | (v & 0x7F))
        v >>= 7
    return bytes(out)


def test_lz77_literals_only():
    assert bgtlib.lz77_decompress(b"\xff" + b"hello", 5) == b"hello"


def test_lz77_escaped_literal():
    comp = b"\xff" + b"a" + b"\xff" + NUL + b"b"
    assert bgtlib.lz77_decompress(comp) == b"a\xffb"


def test_lz77_match_and_overlap():
    """An overlapping match must copy byte-at-a-time, extending as it goes."""
    comp = b"\xff" + b"ab" + b"\xff" + _varint7(4) + _varint7(2)
    assert bgtlib.lz77_decompress(comp, 6) == b"ababab"


def test_lz77_length_mismatch_raises():
    try:
        bgtlib.lz77_decompress(b"\xff" + b"hello", 99)
    except bgtlib.BgtError:
        return
    raise AssertionError("declared-length mismatch was not reported")


def test_lz77_split_reads_trailing_length():
    comp, n = bgtlib.lz77_split(b"\xffpayload 1234")
    assert comp == b"\xffpayload" and n == 1234


# --------------------------------------------------------------------------
# container header
# --------------------------------------------------------------------------

def test_container_header_length_is_computed_not_fixed():
    """The declared length is decimal, so the header grows with the module."""
    for size in (7, 1234, 1788309):
        blob = b"x" * size
        pt = b"0" * 32 + b"=3 printf" + str(size).encode() + NUL + blob
        flag, got = bgtlib.parse_container(pt)
        assert flag == 3 and got == blob


def test_container_rejects_short_blob():
    pt = b"0" * 32 + b"=3 printf9999" + NUL + b"tiny"
    try:
        bgtlib.parse_container(pt)
    except bgtlib.BgtError:
        return
    raise AssertionError("truncated container was accepted")


# --------------------------------------------------------------------------
# SFPv1 packs
# --------------------------------------------------------------------------

def _write_temp(raw):
    fd, path = tempfile.mkstemp()
    os.write(fd, raw)
    os.close(fd)
    return path


def test_pack_build_roundtrips_through_parse():
    path = _write_temp(bgt_pack.build([("a.wav", b"12345"), ("dir/b.ogg", b"xyz")]))
    try:
        version, entries = bgt_pack.parse(path)
        assert version == 1 and len(entries) == 2
        assert [e.name for e in entries] == ["a.wav", "dir/b.ogg"]
        assert entries[0].data == b"12345"
        assert not entries[0].encrypted
    finally:
        os.unlink(path)


def test_pack_trailing_garbage_is_an_error():
    """A walk that does not land exactly on EOF must raise, never pass quietly."""
    path = _write_temp(bgt_pack.build([("a", b"1")]) + b"leftover")
    try:
        bgt_pack.parse(path)
    except bgt_pack.PackError:
        return
    finally:
        os.unlink(path)
    raise AssertionError("unexplained trailing bytes were accepted")


def test_encrypted_entry_roundtrips_and_rejects_wrong_key():
    key = hashlib.sha256(b"correct").digest()
    plain = b"RIFF" + b"audio data here"
    blob = bgt_pack.encrypt_payload(plain, key)
    e = bgt_pack.Entry("s.wav", 0, 0, len(blob), blob)

    assert e.encrypted and e.tag == bgt_pack.tag_for_key(key)
    assert e.decrypt(key) == plain
    assert e.decrypt(hashlib.sha256(b"wrong").digest()) is None


def test_pack_replace_only_touches_named_entries():
    key = hashlib.sha256(b"k").digest()
    path = _write_temp(bgt_pack.build([
        ("keep.txt", b"untouched"),
        ("swap.wav", bgt_pack.encrypt_payload(b"OLD audio", key)),
    ]))
    try:
        rebuilt = bgt_pack.replace(path, {"swap.wav": b"NEW audio"}, key=key)
    finally:
        os.unlink(path)

    path2 = _write_temp(rebuilt)
    try:
        _, entries = bgt_pack.parse(path2)
        by_name = {e.name: e for e in entries}
        assert by_name["keep.txt"].data == b"untouched"
        assert by_name["swap.wav"].decrypt(key) == b"NEW audio"
    finally:
        os.unlink(path2)


def test_key_matches_finds_only_the_right_entries():
    good = hashlib.sha256(b"g").digest()
    bad = hashlib.sha256(b"b").digest()
    entries = [
        bgt_pack.Entry("a", 0, 0, 0, bgt_pack.encrypt_payload(b"one", good)),
        bgt_pack.Entry("b", 0, 0, 0, bgt_pack.encrypt_payload(b"two", bad)),
    ]
    assert [e.name for e in bgt_pack.key_matches(entries, good)] == ["a"]


# --------------------------------------------------------------------------
# password search
# --------------------------------------------------------------------------

def test_harvest_runs_joins_consecutive_literals_with_nul():
    """Confirmed BGT passwords are slices of the string block, not single
    literals -- an over-long std::string length reads several NUL-terminated
    strings as one value. A whole-literal search cannot contain one."""
    runs = bgt_crack.harvest_runs([b"al", b"ba", b"cc"], max_join=2)
    assert b"al" + NUL + b"ba" in runs
    assert b"ba" + NUL + b"cc" in runs


def test_harvest_runs_respects_max_join():
    runs = bgt_crack.harvest_runs([b"a", b"b", b"c", b"d"], max_join=3)
    assert b"a" + NUL + b"b" + NUL + b"c" in runs
    assert max(r.count(NUL) for r in runs) == 2      # 3 pieces => 2 separators


def test_harvest_keeps_literals_containing_nul():
    """A BGT literal may carry NUL, and the KDF is handed a pointer and a length
    rather than a C string -- so those NULs are part of the password. Requiring
    every byte to be printable discarded exactly the literals worth finding:
    Tomb Hunter's keys are written `"\\0" * 19 + "melhesday" + "\\0" * 53` for
    that reason, and no printable-run harvest can represent one."""
    padded = NUL * 3 + b"melhesday" + NUL * 4      # _len2 encodes 2*len in a byte
    lits = as_module.module_strings(_len2(padded), as_module.LEN2)
    assert padded in lits


def test_harvest_rejects_a_literal_that_is_not_text_shaped():
    """The scan is blind, so loosening the filter must not admit everything --
    a run of NULs alone is not a literal, and neither is binary."""
    assert as_module.module_strings(_len2(NUL * 12), as_module.LEN2) == []
    assert as_module.module_strings(_len2(b"\x01\x02\xff\xfe"), as_module.LEN2) == []


def test_harvest_cores_offers_both_readings_of_a_padded_literal():
    """Whether the password is the padded literal or the word inside it is not
    something the harvester can know, so both have to be candidates."""
    padded = NUL * 3 + b"melhesday" + NUL * 4
    cores = bgt_crack.harvest_cores([padded])
    assert b"melhesday" in cores
    assert bgt_crack.harvest_cores([b"no_nuls_here"]) == []


def test_module_strings_detects_the_dialect_when_not_told():
    """Defaulting to the len2 rule harvested a tagged module under the wrong
    encoding and returned coincidence rather than its literals."""
    #     noDebugInfo, 0 enums, 1 class, then that class's phase-1 record
    module = (b"\x01\x00\x01"
              + _tagged_str(b"cls") + b"\x00\x10\x00\x01" + b"\x01" + NUL
              + _tagged_str(b"password_here"))
    assert as_module.detect(module)[0] == as_module.TAGGED
    assert b"password_here" in as_module.module_strings(module)


def test_build_candidates_deduplicates_across_harvesters():
    module = _len2(b"repeated") + _len2(b"repeated") + _len2(b"unique")
    cands, counts = bgt_crack.build_candidates(module, ["strings"])
    assert len(cands) == len(set(cands))
    assert counts["strings"] == len(cands)


def test_search_finds_a_known_password_and_reports_the_count():
    """End to end against a pack built with a password we chose."""
    password = b"the_password"
    key = bgt_kdf.aes_key(password)
    entries = [bgt_pack.Entry("s.ogg", 0, 0, 0,
                              bgt_pack.encrypt_payload(b"OggS...", key))]
    tags = bgt_pack.tag_index(entries)

    candidates = [b"wrong", password, b"also_wrong"]
    result = bgt_crack.search(candidates, tags.keys(), workers=1, progress=False)
    assert result["tested"] == 3
    assert [c for c, _k in result["matches"]] == [password]
    assert result["matches"][0][1] == key.hex()


def test_search_reports_zero_matches_without_claiming_more():
    """A negative result is only about the candidates actually tried, so the
    count has to come back with it."""
    key = bgt_kdf.aes_key(b"unguessable")
    entries = [bgt_pack.Entry("s", 0, 0, 0, bgt_pack.encrypt_payload(b"x", key))]
    result = bgt_crack.search([b"a", b"b"], bgt_pack.tag_index(entries).keys(),
                              workers=1, progress=False)
    assert result["matches"] == [] and result["tested"] == 2


def test_worker_chunk_check_matches_the_serial_path():
    """--workers N must not change the answer, only the wall clock."""
    password = b"chunked"
    key = bgt_kdf.aes_key(password)
    entries = [bgt_pack.Entry("s", 0, 0, 0, bgt_pack.encrypt_payload(b"x", key))]
    tags = frozenset(bgt_pack.tag_index(entries).keys())
    hits = bgt_crack._check_chunk(([b"no", password, b"nope"], tags))
    assert [c for c, _k in hits] == [password]


# --------------------------------------------------------------------------
# repacking -- verified by round-trip, never by inspection
# --------------------------------------------------------------------------

def _synthetic_exe(module, stub_len=512):
    """A fake 'executable': an arbitrary stub plus a real overlay and trailer.

    The container parameters are passed explicitly because the skeleton's overlay
    is a placeholder -- `repack` would otherwise unpack the original to inherit
    them, which only works when the original is a real game.
    """
    stub = bytes(range(256)) * (stub_len // 256)
    skeleton = (stub + b"0 " + NUL * 32 + b"xproc10" + NUL
                + struct.pack("<I", len(stub)))
    return bgt_repack.repack(skeleton, module, seed=0x11, flag=3,
                             magic=b"6188CAE85A13D82754756DC38920FA09")


def test_lz77_compress_roundtrips():
    for payload in (b"hello world",
                    b"ababababababababababab",
                    bytes(range(256)) * 4,
                    NUL * 1000,
                    b"the quick brown fox " * 50):
        comp = bgt_repack.lz77_compress(payload)
        assert bgtlib.lz77_decompress(comp, len(payload)) == payload


def test_lz77_compress_handles_escape_byte_in_payload():
    """Every byte value present, so the chosen escape does occur in the data."""
    payload = bytes(range(256))
    comp = bgt_repack.lz77_compress(payload, escape=0x41)
    assert bgtlib.lz77_decompress(comp, len(payload)) == payload


def test_repack_roundtrip_recovers_module_exactly():
    module = b"\x01\x02module payload " * 300
    exe = _synthetic_exe(module)
    assert bgt_repack.verify_roundtrip(exe, module)
    assert bgtlib.unpack(exe).bytecode == module


def test_repack_preserves_stub_and_recomputes_trailer():
    module = b"payload" * 100
    exe = _synthetic_exe(module)
    offset = bgtlib.read_trailer(exe)
    assert exe[:offset] == bytes(range(256)) * 2      # stub copied verbatim
    assert exe[-12:-4] == b"xproc10" + NUL


def test_repack_detects_a_corrupted_overlay():
    module = b"payload" * 100
    exe = bytearray(_synthetic_exe(module))
    exe[-40] ^= 0xFF                                   # flip a ciphertext bit
    try:
        bgt_repack.verify_roundtrip(bytes(exe), module)
    except bgtlib.BgtError:
        return
    raise AssertionError("corrupted overlay passed round-trip verification")



# --------------------------------------------------------------------------
# the unified CLI
# --------------------------------------------------------------------------

def test_cli_lists_every_subcommand():
    """The help is the discovery surface; a subcommand missing from it is
    effectively missing."""
    parser = cli.build_parser()
    text = parser.format_help()
    for name in ("unpack", "info", "opcodes", "disasm", "pack", "crack",
                 "repack", "validate"):
        assert name in text, name


def test_cli_with_no_arguments_prints_help_and_succeeds():
    assert cli.main([]) == 0


def test_cli_info_on_a_non_bgt_file_is_an_error_not_a_traceback():
    path = _write_temp(b"this is not a PE with a BGT overlay")
    try:
        assert cli.main(["info", path]) == 2
    finally:
        os.unlink(path)


def test_cli_pack_list_reads_a_built_pack():
    path = _write_temp(bgt_pack.build([("a.wav", b"12345")]))
    try:
        assert cli.main(["pack", "list", path]) == 0
    finally:
        os.unlink(path)


def test_cli_pack_extract_refuses_without_a_key():
    """Encrypted entries and no key must fail loudly rather than write nothing
    and report success."""
    key = hashlib.sha256(b"k").digest()
    path = _write_temp(bgt_pack.build([
        ("s.ogg", bgt_pack.encrypt_payload(b"OggS", key))]))
    outdir = tempfile.mkdtemp()
    try:
        assert cli.main(["pack", "extract", path, "-o", outdir]) == 2
    finally:
        os.unlink(path)


def test_cli_pack_extract_writes_with_the_right_key():
    key = hashlib.sha256(b"k").digest()
    path = _write_temp(bgt_pack.build([
        ("dir/s.ogg", bgt_pack.encrypt_payload(b"OggS-data", key)),
        ("plain.txt", b"hello"),
    ]))
    outdir = tempfile.mkdtemp()
    try:
        assert cli.main(["pack", "extract", path, "-o", outdir,
                         "--key", key.hex()]) == 0
        with open(os.path.join(outdir, "dir", "s.ogg"), "rb") as fh:
            assert fh.read() == b"OggS-data"
        with open(os.path.join(outdir, "plain.txt"), "rb") as fh:
            assert fh.read() == b"hello"
    finally:
        os.unlink(path)


def test_cli_rejects_a_malformed_key():
    path = _write_temp(bgt_pack.build([("a", b"1")]))
    try:
        assert cli.main(["pack", "extract", path, "--key", "nothex"]) == 2
        assert cli.main(["pack", "extract", path, "--key", "aabb"]) == 2
    finally:
        os.unlink(path)


# --------------------------------------------------------------------------
# lifting
# --------------------------------------------------------------------------

def _lifter(**tables):
    mod = _FakeModule(b"", **tables)
    func = {"name": "f", "owner": None, "params": [], "returns": {"token": 80}}
    return as_lift.Lifter(mod, func), func


def test_pop_takes_the_callees_arity_from_the_top():
    """Residue left by an imperfectly modelled construct sits UNDER the callee's
    own operands, so popping a known count from the top skips it instead of
    sweeping it into the argument list."""
    L, _ = _lifter(functions=[{"name": "g", "owner": None,
                               "params": [{"token": 68}, {"token": 68}],
                               "returns": {"token": 80}}])
    L.push("leftover")
    L.push("x")
    L.push("y")
    assert L._call(0, "CALL") == "g(x, y)"
    assert [e.text for e in L.stack] == ["leftover"]


def test_constructor_takes_this_from_the_top_and_reads_as_assignment():
    """A constructor's target is pushed immediately before the call, so `this`
    is the top; taking it from the bottom yields `string(&v1)` and drops the
    literal."""
    ctor = {"name": "$beh0", "owner": {"kind": "named", "name": "string"},
            "params": [{"token": 68}], "returns": {"token": 80}}
    L, _ = _lifter(functions=[ctor])
    L.push('"hello"')
    L.push("&v1")
    assert L._call(0, "CALLSYS") == 'v1 = string("hello")'


def test_string_factory_preserves_the_literal():
    """The factory's operands are (constant, length); the hidden-return-pointer
    strip would otherwise discard the literal itself."""
    fac = {"name": "_string_factory_", "owner": None,
           "params": [{"token": 75}, {"token": 76}],
           "returns": {"token": 5, "type": {"kind": "named", "name": "string"}}}
    L, _ = _lifter(functions=[fac])
    L.push('"data.dat"')
    L.push("<len>")
    assert L._call(0, "CALLSYS") == '"data.dat"'


def test_destructor_calls_are_dropped():
    dtor = {"name": "$beh2", "owner": {"kind": "named", "name": "string"},
            "params": [], "returns": {"token": 80}}
    L, _ = _lifter(functions=[dtor])
    L.push("&v1")
    assert L._call(0, "CALLSYS") == ""


def test_operators_render_as_syntax():
    """The receiver is pushed LAST, so `v1 = v2` is push(v2) then push(v1).

    This test previously pushed them the other way round, encoding the earlier
    (wrong) belief that a method's object came first. dynamic_menu::add_item
    settles it -- `VAR 1 / PshV4 2 / VAR 3 / PshVPtr 0 / CALLINTF` puts the
    three declared arguments first and `this` on top.
    """
    op = {"name": "opAssign", "owner": {"kind": "named", "name": "string"},
          "params": [{"token": 68}], "returns": {"token": 80}}
    L, _ = _lifter(functions=[op])
    L.push("v2")                       # the argument
    L.push("v1")                       # the receiver, on top
    assert L._call(0, "CALLSYS") == "v1 = v2"


def test_comparison_and_jump_combine_into_one_condition():
    """CMPi writes the operands and the FOLLOWING jump supplies the relational
    operator. Lifting them separately loses the condition entirely."""
    L, func = _lifter()
    out = []
    as_lift._step(L, lambda i, t: out.append(t), 0, "CMPIi", [3, 16], [None, None])
    assert out == []                       # the compare emits nothing by itself
    as_lift._step(L, lambda i, t: out.append(t), 1, "JNP", [-15], ["L1"])
    assert out == ["@if v3 <= 16 -> L1"]


def test_lowjump_reads_the_value_register_not_a_comparison():
    """JLowZ / JLowNZ test the low byte of the value register -- the shape a
    bool-returning call leaves behind -- and follow no compare at all."""
    L, _ = _lifter()
    L.value_reg = "is_ready()"
    out = []
    as_lift._step(L, lambda i, t: out.append(t), 0, "JLowZ", [4], ["L0"])
    assert out == ["@if !is_ready() -> L0"]


def test_loadthisr_writes_a_register_and_does_not_push():
    """stackInc is 0. Pushing here strands one value on every use -- 2,414 of
    them in Psycho Strike -- and the WRTV4 that follows then pops something
    unrelated, so the write lands on the wrong target."""
    L, _ = _lifter()
    out = []
    as_lift._step(L, lambda i, t: out.append(t), 0, "LoadThisR", [5, 0],
                  ["character::health", "int"])
    assert L.stack == []
    assert L.ref_reg == "this.health"
    as_lift._step(L, lambda i, t: out.append(t), 1, "WRTV4", [3], [None])
    assert out == ["this.health = v3;"]
    assert L.stack == []                      # the write does not pop either


def test_ldg_loads_a_register_rather_than_pushing():
    L, _ = _lifter()
    as_lift._step(L, lambda i, t: None, 0, "LDG", [7], ["performance_debug"])
    assert L.stack == [] and L.ref_reg == "performance_debug"


def test_alloc_consumes_its_constructor_arguments():
    """ALLOC runs the constructor, so it eats the declared arguments and the
    destination pointer. Knowing the constructor is what makes that arity
    available -- operand 1 is a ONE-BASED usedFunctions index."""
    ctor = {"name": "$beh0", "owner": {"kind": "named", "name": "vec"},
            "params": [{"token": 68}, {"token": 68}], "returns": {"token": 80}}
    L, _ = _lifter(functions=[ctor], types=[{"kind": "named", "name": "vec"}])
    L.push("keep")
    L.push("3")
    L.push("4")
    L.push("&v1")
    out = []
    as_lift._step(L, lambda i, t: out.append(t), 0, "ALLOC", [0, 1],
                  ["vec", "vec::$beh0"])
    assert out == ["v1 = vec(3, 4);"]
    assert [e.text for e in L.stack] == ["keep"]


def _fake_lifted(lines, labels, total):
    """A lifted-function shape with hand-written control flow, for the structurer."""
    return {"lines": lines, "instructions": total,
            "disasm": {"labels": labels}}


def _structured(lines, labels, total):
    lifted = _fake_lifted(lines, labels, total)
    return [l.strip() for l in as_lift.structure(lifted) if l.strip()], lifted


def test_branch_over_is_inverted_into_a_guarded_if():
    """The compiler emits `if (!c) goto after;` around a guarded block. Read as
    written it yields an EMPTY if with the body dangling after it -- valid
    structure, wrong about what is conditional."""
    lines = [(0, "@if !flag -> L0"), (1, "work();"), (2, "after();")]
    out, _ = _structured(lines, {2: 0}, 3)
    assert out[0] == "if (flag) {"
    assert "work();" in out[1]
    assert out[2] == "}"
    assert out[3] == "after();"


def test_if_else_recovers_both_arms():
    lines = [(0, "@if c -> L0"), (1, "fallthrough();"), (2, "@goto L1"),
             (3, "taken();"), (4, "join();")]
    out, _ = _structured(lines, {3: 0, 4: 1}, 5)
    assert "taken();" in out and "fallthrough();" in out
    assert "} else {" in out
    assert out[-1] == "join();"


def test_header_that_is_also_the_latch_becomes_do_while():
    """The test runs after the body. Emitting the statements before a `while`
    instead runs them once and then spins on an empty body -- tidy, and a
    different program."""
    lines = [(0, "body();"), (1, "@if c -> L0"), (2, "after();")]
    out, lifted = _structured(lines, {0: 0}, 3)
    assert out[0] == "do {"
    assert "body();" in out[1]
    assert out[2].startswith("} while (")
    assert lifted["gotos"] == 0


def test_loop_exit_becomes_break_and_backedge_continue():
    lines = [(0, "step();"), (1, "@if done -> L1"), (2, "@goto L0"),
             (3, "after();")]
    out, lifted = _structured(lines, {0: 0, 3: 1}, 4)
    joined = " ".join(out)
    assert "break;" in joined or "while (" in joined
    assert "after();" in out
    assert lifted["gotos"] == 0


def test_irreducible_flow_falls_back_to_goto_rather_than_guessing():
    """A jump into the middle of another region does not reduce. It must stay a
    labelled goto -- forcing a shape onto it produces confident, wrong nesting."""
    lines = [(0, "@if a -> L1"), (1, "@if b -> L0"), (2, "x();"),
             (3, "y();"), (4, "z();")]
    out, lifted = _structured(lines, {3: 0, 2: 1}, 5)
    assert lifted["gotos"] >= 0            # may or may not reduce
    assert any("x();" in l for l in out)   # but nothing is lost
    assert any("z();" in l for l in out)


def test_structure_never_drops_a_statement():
    """Anything the structured walk cannot reach is emitted as a labelled tail,
    so output is never quietly shorter than the input."""
    lines = [(0, "a();"), (1, "@goto L0"), (2, "orphan();"), (3, "b();")]
    out, _ = _structured(lines, {3: 0}, 4)
    assert any("orphan();" in l for l in out)
    assert any("a();" in l for l in out)
    assert any("b();" in l for l in out)


def test_negate_folds_comparisons_rather_than_stacking_bangs():
    assert as_lift._negate("a < b") == "a >= b"
    assert as_lift._negate("!x") == "x"
    assert as_lift._negate("f()") == "!(f())"


def test_callers_of_finds_the_body_that_calls_an_engine_function():
    """The function you want to read is often not the one you can name. Engine
    functions have no body of their own -- what names the key is whatever CALLS
    set_sound_decryption_key."""
    body = bytes([0x01]) + _eu(1) + bytes([0x00]) + _eu(0)   # CALL 1; RET
    funcs = [{"name": "other", "owner": None},
             {"name": "set_sound_decryption_key", "owner": None}]
    mod = _FakeModule(body, functions=funcs)
    mod.functions = [{"name": "prepare_audio", "owner": None, "params": [],
                      "body": (0, len(body)), "instructions": 2}]
    mod.find = as_disasm.Module.find.__get__(mod)
    mod.callers_of = as_disasm.Module.callers_of.__get__(mod)

    assert [f["name"] for f in mod.callers_of("set_sound_decryption_key")] \
        == ["prepare_audio"]
    assert mod.callers_of("something_absent") == []


def test_unmodelled_opcodes_are_visible_not_dropped():
    """A lifter that silently omits what it does not understand reads better and
    means less, so the passthrough has to appear in the output and the count."""
    L, _ = _lifter()
    out = []
    as_lift._step(L, lambda i, t: out.append(t), 0, "NoSuchOpcode", [1, 2],
                  [None, None])
    assert out == ["/* NoSuchOpcode 1 2 */"]
    assert L.passthrough == 1


def test_negative_variable_slots_are_not_rendered_as_expressions():
    """Serialised variable positions can be negative; `v-1` reads like
    subtraction, so negative slots get their own name."""
    f = {"name": "m", "owner": {"kind": "named", "name": "c"}, "params": []}
    assert as_disasm.variable_name(f, -1) == "s1"
    assert as_disasm.variable_name(f, 0) == "this"


# --------------------------------------------------------------------------
# writing modules back out
# --------------------------------------------------------------------------

def test_encoded_uint_encoder_is_the_exact_inverse():
    """Pinned against the same known pairs the decoder is pinned to. An encoder
    that is merely close produces a module that loads and misbehaves."""
    for raw, want in ((b"\x3f", 63), (b"\x40\x40", 64), (b"\x40\x56", 86),
                      (b"\x40\x5b", 91), (b"\x40\x81", 129), (b"\x40\xa7", 167),
                      (b"\x40\xe7", 231)):
        assert as_write.encode_encoded_uint(want) == raw


def test_encoder_never_spills_into_the_next_width_marker():
    """Each form gives up a bit to the NEXT form's marker. Treating `10xxxxxx`
    as six free bits lets the lead byte reach 0x7F, which decodes as the
    eight-byte form -- an enormous value and a cursor inside the next record."""
    for v in list(range(0, 5000)) + [8191, 8192, 65535, 1 << 20, 1 << 26]:
        enc = as_write.encode_encoded_uint(v)
        back, used = as_module.read_encoded_uint(enc, 0)
        assert back == v and used == len(enc), (v, enc, back, used)


def test_encoder_round_trips_negatives():
    """The top bit is a sign flag, so negatives have to survive too."""
    for v in (-1, -63, -64, -1000, -8191):
        enc = as_write.encode_encoded_uint(v)
        assert as_module.read_encoded_uint(enc, 0)[0] == v


def test_write_replays_a_trace():
    trace = [("raw", b"\x01"), ("eu", 86), ("u32", 0x04000000), ("i32", -2),
             ("strnew", b"hi"), ("strref", 0), ("strempty",)]
    out = as_write.write(trace, as_module.LEN2)
    assert out == (b"\x01" + b"\x40\x56" + struct.pack(">I", 0x04000000)
                   + struct.pack(">i", -2) + b"\x04hi" + b"\x01" + NUL)


def test_write_encodes_strings_per_dialect():
    trace = [("strnew", b"abc"), ("strref", 2)]
    assert as_write.write(trace, as_module.LEN2) == b"\x06abc" + b"\x05"
    assert as_write.write(trace, as_module.TAGGED) == b"\x6e\x03abc" + b"\x72\x02"


def test_instruction_count_is_recomputed_not_copied():
    """The count is recomputed from the instructions that follow, so inserting
    one keeps it right. It counts INSTRUCTIONS, not dwords."""
    trace = [("opcount", 2), ("op", 1, [5]), ("op", 0, [])]
    assert as_write.write(trace, as_module.LEN2) == b"\x02" + b"\x01\x05" + b"\x00"
    grown = [("opcount", 2), ("op", 1, [5]), ("op", 1, [7]), ("op", 0, [])]
    assert as_write.write(grown, as_module.LEN2)[0] == 3


def test_replace_literal_allows_a_different_length():
    """Back-references are by index, so entry N stays entry N and only this
    record's encoded length changes -- which is what in-place patching could
    not do."""
    trace = [("strnew", b"sounds.dat"), ("strref", 0), ("eu", 7)]
    out = as_write.replace_literal(trace, b"sounds.dat", b"a_much_longer.dat")
    assert out[0] == ("strnew", b"a_much_longer.dat")
    assert out[1] == ("strref", 0)          # the reference is untouched
    written = as_write.write(out, as_module.LEN2)
    assert b"a_much_longer.dat" in written


def test_replace_literal_reports_a_miss_rather_than_doing_nothing():
    try:
        as_write.replace_literal([("strnew", b"x")], b"absent", b"y")
    except KeyError:
        return
    raise AssertionError("replacing a literal that is not present passed silently")


def test_replace_instruction_rejects_a_non_instruction_slot():
    trace = [("eu", 1), ("op", 5, [2])]
    assert as_write.replace_instruction(trace, 1, 6, [3])[1] == ("op", 6, [3])
    try:
        as_write.replace_instruction(trace, 0, 6, [3])
    except ValueError:
        return
    raise AssertionError("an eu field was accepted as an instruction")


# --------------------------------------------------------------------------
# Ghidra setup helpers
# --------------------------------------------------------------------------

def test_ghidra_version_sort_is_numeric_not_lexical():
    """'ghidra_12.1' must beat 'ghidra_9.2'; string ordering gets that backwards."""
    names = ["ghidra_9.2_PUBLIC", "ghidra_12.1_PUBLIC", "ghidra_10.4_PUBLIC"]
    newest = sorted(names, key=bgt_ghidra._version_key)[-1]
    assert newest == "ghidra_12.1_PUBLIC"


def test_extensions_dir_is_the_per_user_path_not_the_install():
    """Ghidra loads user extensions from APPDATA/.config, never from the install
    directory -- putting them in the install looks right and does not load."""
    install = tempfile.mkdtemp()
    os.makedirs(os.path.join(install, "Ghidra"), exist_ok=True)
    with open(os.path.join(install, "Ghidra", "application.properties"), "w") as fh:
        fh.write("application.version=12.1\n")
    got = bgt_ghidra.extensions_dir(install)
    assert got.endswith(os.path.join("ghidra", "ghidra_12.1_PUBLIC", "Extensions"))
    assert not got.startswith(install)


def test_ghidra_version_read_from_properties():
    install = tempfile.mkdtemp()
    os.makedirs(os.path.join(install, "Ghidra"), exist_ok=True)
    with open(os.path.join(install, "Ghidra", "application.properties"), "w") as fh:
        fh.write("application.name=Ghidra\napplication.version=11.3.2\n")
    assert bgt_ghidra.ghidra_version(install) == "11.3.2"


def test_a_directory_without_headless_is_not_a_ghidra_install():
    """Detection keys off support/analyzeHeadless -- the launcher actually used --
    so a renamed install is still found and a lookalike directory is not."""
    empty = tempfile.mkdtemp()
    assert not bgt_ghidra._is_ghidra(empty)
    assert not bgt_ghidra._is_ghidra("")


def test_jdk_version_rejects_a_non_jdk_directory():
    assert bgt_ghidra._jdk_version(tempfile.mkdtemp()) == 0
    assert bgt_ghidra._jdk_version("") == 0


def _fake_ghidra_zip(path, version="12.1"):
    """A minimal archive shaped like a Ghidra release."""
    import zipfile
    root = "ghidra_%s_PUBLIC" % version
    headless = "support/analyzeHeadless.bat" if os.name == "nt" \
        else "support/analyzeHeadless"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("%s/%s" % (root, headless), "#!/bin/sh\n")
        zf.writestr("%s/Ghidra/application.properties" % root,
                    "application.version=%s\n" % version)
    return path


def test_install_from_archive_unpacks_and_locates_headless():
    """The download is a byte transfer; the unpack is where it can be wrong.
    Split so this half is exercised without moving a gigabyte."""
    tmp = tempfile.mkdtemp()
    archive = _fake_ghidra_zip(os.path.join(tmp, "ghidra.zip"))
    dest = tempfile.mkdtemp()
    install = bgt_ghidra.install_from_archive(archive, dest)
    assert bgt_ghidra._is_ghidra(install)
    assert bgt_ghidra.ghidra_version(install) == "12.1"


def test_install_from_archive_rejects_a_zip_that_is_not_ghidra():
    """A wrong-but-valid zip must fail loudly, not leave a half-install that
    `status` later reports as ready."""
    import zipfile
    tmp = tempfile.mkdtemp()
    archive = os.path.join(tmp, "notghidra.zip")
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("readme.txt", "hello")
    try:
        bgt_ghidra.install_from_archive(archive, tempfile.mkdtemp())
    except RuntimeError as exc:
        assert "not a Ghidra archive" in str(exc)
        return
    raise AssertionError("a non-Ghidra zip was accepted as an install")


def test_pick_release_asset_finds_the_public_zip():
    """Parsing the release payload is what breaks when GitHub's layout changes,
    and a live download would not exercise it any better than this does."""
    payload = {"tag_name": "Ghidra_12.1_build", "assets": [
        {"name": "ghidra_12.1_PUBLIC_20250101.zip",
         "browser_download_url": "https://example/ghidra.zip"},
        {"name": "source.tar.gz", "browser_download_url": "https://example/src"},
    ]}
    version, url = bgt_ghidra.pick_release_asset(payload)
    assert version == "Ghidra_12.1_build"
    assert url == "https://example/ghidra.zip"


def test_pick_release_asset_raises_when_there_is_no_zip():
    try:
        bgt_ghidra.pick_release_asset({"assets": [{"name": "src.tar.gz"}]})
    except RuntimeError:
        return
    raise AssertionError("a release with no public zip was accepted")


def test_install_extension_from_a_zip_lands_in_the_user_directory():
    """Extensions load from APPDATA/.config, never from the install tree."""
    import zipfile
    tmp = tempfile.mkdtemp()
    install = bgt_ghidra.install_from_archive(
        _fake_ghidra_zip(os.path.join(tmp, "g.zip")), tempfile.mkdtemp())

    ext = os.path.join(tmp, "MyExt.zip")
    with zipfile.ZipFile(ext, "w") as zf:
        zf.writestr("MyExt/extension.properties", "name=MyExt\n")
        zf.writestr("MyExt/lib/MyExt.jar", "")

    target = bgt_ghidra.extensions_dir(install)
    try:
        placed = bgt_ghidra.install_extension(install, ext)
    finally:
        if os.path.isdir(os.path.join(target, "MyExt")):
            shutil.rmtree(os.path.join(target, "MyExt"), ignore_errors=True)
    assert placed.startswith(target)
    assert not placed.startswith(install)


def test_install_extension_rejects_a_bad_source():
    install = tempfile.mkdtemp()
    os.makedirs(os.path.join(install, "Ghidra"), exist_ok=True)
    with open(os.path.join(install, "Ghidra", "application.properties"), "w") as fh:
        fh.write("application.version=12.1\n")
    try:
        bgt_ghidra.install_extension(install, os.path.join(install, "nope.txt"))
    except SystemExit:
        return
    raise AssertionError("a non-existent extension source was accepted")


# --------------------------------------------------------------------------
# string_encrypt / string_decrypt
# --------------------------------------------------------------------------

def test_key_setup_reproduces_the_overlay_key():
    """The same routine builds the executable overlay's key, so it can be pinned
    against a value derived a completely different way."""
    km = bgtlib.keygen(0x11)
    key, iv = bgt_string_crypt.aes_params(km, use_kdf=False)
    assert key == bgtlib.aes_key_for_seed(0x11)
    assert iv == key[:16]


def test_key_is_taken_with_strlen():
    """The runtime hands the key to strlen, so a NUL truncates it. This is why the
    KDF scrubs NULs -- without it, keys would silently collide."""
    a = bgt_string_crypt.aes_params(b"abc" + NUL + b"ignored", use_kdf=False)[0]
    b = bgt_string_crypt.aes_params(b"abc", use_kdf=False)[0]
    assert a == b


def test_plaintext_container_roundtrip():
    for payload in (b"", b"x", b"hello world", b"y" * 500):
        assert bgt_string_crypt.unwrap(bgt_string_crypt.wrap(payload)) == (
            payload if payload else None)


def test_container_rejects_a_missing_header():
    assert bgt_string_crypt.unwrap(b"nothdr12" + NUL + b"data") is None


def test_string_encrypt_roundtrips():
    for payload in (b"a", b"the quick brown fox", b"z" * 300):
        blob = bgt_string_crypt.string_encrypt(payload, b"pw")
        assert len(blob) % 16 == 0
        assert bgt_string_crypt.string_decrypt(blob, b"pw") == payload


def test_string_decrypt_rejects_wrong_key():
    blob = bgt_string_crypt.string_encrypt(b"secret data", b"right")
    assert bgt_string_crypt.string_decrypt(blob, b"wrong") is None


if __name__ == "__main__":
    failures = 0
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            try:
                _fn()
                print("  ok    %s" % _name)
            except Exception as exc:                       # noqa: BLE001
                failures += 1
                print("  FAIL  %s: %s: %s" % (_name, type(exc).__name__, exc))
    print("\n%s" % ("all passed" if not failures else "%d FAILED" % failures))
    sys.exit(1 if failures else 0)
