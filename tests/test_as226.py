"""AngelScript 2.25 and 2.26 -- the BGT builds of 2012-12 and 2013-04.

These records were written from AngelScript's own published `as_restore.cpp`
for the 2.25.x and 2.26.x tags and checked against three shipped modules,
which land exactly on EOF under them. Everything here is synthetic: a few
bytes built by hand. No game file is involved.

Run:  python -m pytest tests/test_as226.py -q
"""

import os
import sys

try:                                   # after `pip install -e .`
    from bgtdecomp import as_early, as_module
    from bgtdecomp.nvgt import decompile
except ImportError:                    # straight from a checkout
    TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
    sys.path.insert(0, TOOLS)
    import as_early
    import as_module
    from nvgt import decompile


def eu(value):
    """One encoded integer in the sign-flag form."""
    assert 0 <= value < 1 << 14
    if value < 64:
        return bytes([value])
    return bytes([0x40 | (value >> 8), value & 0xFF])


def s(text):
    """A new tagged string."""
    raw = text.encode("latin1")
    return b"\x6e" + eu(len(raw)) + raw if raw else b"\x00"


#: One opcode is enough to step a body: RET, one operand.
OPS = {9: {"name": "RET", "operands": 1}}


def _reader(payload, records, debug=False):
    """A reader over `payload`, after a `noDebugInfo` byte (0 = debug)."""
    return as_module.Reader(bytes([0 if debug else 1]) + payload,
                            as_module.TAGGED, pos=1, opcodes=OPS,
                            records=records, template_namespace=False,
                            objvar_three=True, legacy_body=True)


def _void_script_function(name="f"):
    """'f', a 2.26 signature with no owner, and funcType 1."""
    return (b"\x66" + s(name)
            + eu(78) + b"\x00\x00"                  # return: token 78 (void), flags
            + eu(0) + eu(0)                         # no params, no in/out flags
            + eu(1) + eu(0)                         # funcType 1, no defaults
            + b"\x00" + s(""))                      # no owner, empty namespace


def _body():
    return (eu(1) + bytes([9]) + eu(0)      # one instruction: RET 0
            + eu(0) + eu(0) + eu(0))        # variableSpace, objvars, objInfo


# ----------------------------------------------------------------- the table

def test_both_profiles_come_after_every_verified_one():
    """A module that already lands keeps the reading it had."""
    names = [n for n, _ in as_module.RECORD_PROFILES]
    assert names[:3] == ["1.3", "2012-07", "2012-03"]
    assert names[3:] == ["2.26", "2.25"]
    assert as_module.RECORDS_BY_NAME["2.26"] is as_module.RECORDS_2013
    assert as_module.RECORDS_BY_NAME["2.25"] is as_module.RECORDS_2012_12


def test_two_25_differs_from_two_26_in_exactly_what_2_26_1_changed():
    """The subtype count, the debug section list, and how `ALLOC` names its
    constructor -- each read from the two tags' own source."""
    differing = {k for k in as_module.RECORDS_2013
                 if as_module.RECORDS_2013[k] != as_module.RECORDS_2012_12[k]}
    assert differing == {"template_subtype_count", "debug_sections",
                         "alloc_callee_script_only", "alloc_callee_plain"}


def test_2_26_reads_the_alloc_callee_one_based_for_every_type():
    """`1 + FindFunctionIndex(...)` in 2.26.1's writer, for every type: 636
    of X-Wheel's 636 ALLOCs name the allocated type's own constructor read
    that way. Treated as unreadable, a global initialiser lost its literal
    -- `"X-Wheel" = product; product = <?>;` -- and the title would not
    compile."""
    assert as_module.RECORDS_2013["alloc_callee_script_only"] is False
    assert as_module.RECORDS_2013["alloc_callee_plain"] is False


def test_2_25_reads_a_script_class_callee_plain_and_nothing_else():
    """`if( ot->flags & asOBJ_SCRIPT_OBJECT ) ... = FindFunctionIndex(...)`:
    a plain index, and only for a script class. All 18 of zompocalypse's
    script-class ALLOCs name their own constructor read plain."""
    assert as_module.RECORDS_2012_12["alloc_callee_script_only"] is True
    assert as_module.RECORDS_2012_12["alloc_callee_plain"] is True


# ---------------------------------------------------------------- the body

def test_a_release_2_26_body_ends_in_two_bytes():
    """`isShared` and `dontCleanUpOnException`, both outside the debug
    guard. The 2012-07 engine writes one, so reading this generation with
    its records left every body one byte short."""
    rec = _void_script_function() + _body() + b"\x00" + b"\x01"
    r = _reader(rec + b"\x00", as_module.RECORDS_2013)
    f = r.function()
    assert f["instructions"] == 1
    assert f["traits"] == 0 and f["cleanup"] == 1
    # ...and no script section in a release build: `if( !noDebugInfo )`.
    assert "scriptSection" not in f
    assert r.p == len(r.d) - 1


def test_a_debug_2_26_body_puts_the_shared_byte_after_the_sections():
    """lineNumbers, sectionIdxs, isShared, variables, dontCleanUpOnException
    -- then, for every funcType, the script section."""
    rec = (_void_script_function() + _body()
           + eu(2) + eu(0) + eu(6)                  # one line-number pair
           + eu(2) + eu(0) + s("game.bgt")          # sectionIdxs: index, name
           + b"\x01"                                # isShared
           + eu(0)                                  # no variables
           + b"\x00"                                # dontCleanUpOnException
           + b"\x72" + eu(1))                       # section: saved string 1
    r = _reader(rec, as_module.RECORDS_2013, debug=True)
    f = r.function()
    assert f["lineNumbers"] == [0, 6]
    assert f["sections"] == [0, b"game.bgt"]
    assert f["traits"] == 1 and f["cleanup"] == 0
    assert f["scriptSection"] == b"game.bgt"
    assert r.p == len(r.d)


# ---------------------------------------------------------- the class block

def test_an_interface_carries_no_vtable_offset():
    """`for n: intf = ReadObjectType();` and nothing after it. 1.3's tagged
    reader takes an offset there, which here is the destructor marker."""
    decl = {"name": "c", "flags": 0x80001, "size": 1, "namespace": ""}
    block = (b"\x00"                                 # derivedFrom: none
             + eu(1) + b"\x6f" + s("I") + s("")      # one interface, 'o' I
             + b"\x00"                               # destructor: none
             + eu(0) + eu(0) + eu(0))                # ctors, methods, virtuals
    r = _reader(block, as_module.RECORDS_2013)
    out = r.class_block(decl)
    assert out["interfaces"][0]["name"] == "I"
    assert r.p == len(r.d)


def test_the_script_object_bit_is_0x80000():
    """`IsInterface` decides whether a class block has behaviours."""
    r = _reader(b"", as_module.RECORDS_2013)
    assert r.is_interface({"flags": 0x80001, "size": 0})
    assert not r.is_interface({"flags": 0x100001, "size": 0})


# -------------------------------------------------------------- templates

def test_2_26_counts_its_template_subtypes_and_2_25_does_not():
    """2.26.1 made `templateSubType` an array and wrote a count; 2.26.0 and
    every 2.25 write the one subtype's tag straight after the name.
    zompocalypse's first object variable is `61 6e 05 "array" 74 3f`."""
    counted = b"\x61" + s("array") + eu(1) + b"\x74" + eu(63)
    r = _reader(counted, as_module.RECORDS_2013)
    assert r.type_info()["subtypes"] == [{"typeid": 63}]
    assert r.p == len(r.d)

    single = b"\x61" + s("array") + b"\x74" + eu(63)
    r = _reader(single, as_module.RECORDS_2012_12)
    assert r.type_info()["subtypes"] == [{"typeid": 63}]
    assert r.p == len(r.d)


# ------------------------------------------------------- the token numbering

def test_the_question_mark_maps_to_the_irs_60():
    """`?` is 57 in every AngelScript from 2.19 to 2.28 and the decompiler
    recognises a `?&in` argument by 60. Unmapped, a `library::call`'s hidden
    type ids were read as argument values."""
    assert as_early.token(57) == 60
    assert as_early.token(66) == 70          # int, unchanged
    assert as_early.token(5) == 5            # an identifier stays put


# ------------------------------------------------------- the ALLOC arity

def _atom(ptr, text="x"):
    return decompile.Atom("ptr" if ptr else "const", text, is_ptr=ptr)


def test_an_unreadable_alloc_takes_the_values_above_its_destination():
    """zompocalypse: `PshV4 3 ; PSF 5 ; <literal> ; ALLOC string`. The
    literal is a value, not an address, and it is the argument."""
    stack = [_atom(False, "0"), _atom(True, "local_5"), _atom(False, '"x"')]
    assert decompile._alloc_arity_from_stack(stack) == 1


def test_an_address_on_top_is_one_argument_whatever_lies_beneath():
    """`add_item_tts(id, text)` builds as `[VAR 4, PSF 7, PSF 1]`. Taking
    the whole run of addresses made the first item's id the destination."""
    stack = [_atom(True, "local_4"), _atom(True, "local_7"), _atom(True, "tmp1")]
    assert decompile._alloc_arity_from_stack(stack) == 1
    # Screaming Strike's shape, which the old rule was written for
    assert decompile._alloc_arity_from_stack(
        [_atom(True, "local_7"), _atom(True, "tmp6")]) == 1


def test_several_value_arguments_are_counted():
    stack = [_atom(True, "local_2"), _atom(False, "3"), _atom(False, "2"),
             _atom(False, "1")]
    assert decompile._alloc_arity_from_stack(stack) == 3


def test_a_globals_address_on_top_is_the_destination_with_no_arguments():
    """A global initialiser: `STR "X-Wheel" ; PshRPtr ; PGA product ; ALLOC
    string ; PshGPtr product ; opAssign`. The literal is `opAssign`'s, left
    on the stack beneath the ALLOC."""
    stack = [_atom(False, '"X-Wheel"'),
             decompile.Atom("global", "product", is_ptr=True)]
    assert decompile._alloc_arity_from_stack(stack) == 0


# ------------------------------------------------ the funcdef slot retyping

def test_a_funcdef_slot_is_not_retyped_through_an_earlier_call():
    """`retype_funcdef_slots` corrects a guessed funcdef slot from the
    one-parameter call it is passed to. X-Wheel's `reset_menu(callback)` is
    followed by `string`'s copy constructor, and its backward scan reached
    past `reset_menu`'s own call to `VAR 6` and declared the callback
    `string@`. A call in between consumed that argument."""
    from nvgt import asreader
    import bgt_asir
    menu_callback = asreader.TypeInfo(kind="funcdef", name="menu_callback")
    string = asreader.TypeInfo(kind="app", name="string")
    cb = asreader.DataType(token_type=5, obj_type=menu_callback,
                           is_object_handle=True)
    reset_menu = asreader.Function(name="reset_menu", param_types=[cb])
    copy = asreader.Function(name="$beh0", param_types=[
        asreader.DataType(token_type=5, obj_type=string)])

    def ins(name, w=0, func=None):
        return asreader.Instr(pos=0, op=0, name=name, bc_type="", size=1,
                              w_arg=w, func_ref=func)

    body = [ins("VAR", 6), ins("CALL", func=reset_menu),
            ins("PSF", 2), ins("CALLSYS", func=copy)]
    var = asreader.ScriptVariable(stack_offset=6, type=cb)
    f = asreader.Function(name="initialise_menu", bytecode=body,
                          variables=[var])
    m = asreader.Module(funcdefs=[asreader.Function(name="menu_callback")],
                        saved_functions=[f])
    assert bgt_asir.retype_funcdef_slots(m) == 0
    assert var.type.obj_type is menu_callback
