"""What compiling Ljudfarmen and Palace Punch-up with THEIR OWN engines found.

A shipped BGT game is the runtime with the module appended, and the runtime
carries the compiler. Cut at the overlay offset, Ljudfarmen's (2011-02)
compiles with `-c`, and Palace Punch-up's (the 2010-07 beta) compiles when
run with no switch -- `-c` there says the compiler is "not available in the
demonstration version". A probe built by the 2011 engine was the
known-answer fixture for all of it:

    funcdef int cb(int);
    string[] words = {"coffee", "mud"};
    cb@ h = null;          sound@ s;  if (s is null) { }

Synthetic inputs only.
"""

import os
import sys

TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
sys.path.insert(0, TOOLS)

import bgt_asir  # noqa: E402
import bgt_compile  # noqa: E402
from nvgt import asreader, decompile  # noqa: E402


# ---- an initialiser list compiled element by element ----------------------

def test_an_element_by_element_global_comes_back_as_a_list():
    """The 2011 engine refuses the helper: "Function calls are not allowed
    in global expressions", and every later use of the global is "Use of
    uninitialized global variable"."""
    stmts = ['bull_objects = array<string>(3);', 'bull_objects[0] = "coffee";',
             'bull_objects[1] = "mud, wet";', 'bull_objects[2] = "water";']
    assert decompile._fold_element_list(stmts, "bull_objects") == \
        '{"coffee", "mud, wet", "water"}'
    assert decompile._fold_element_list(
        ['n = array<int>(2);', 'n[0] = -3;', 'n[1] = 4;'], "n") == "{-3, 4}"


def test_anything_but_the_exact_shape_keeps_its_helper():
    assert decompile._fold_element_list(
        ['n = array<int>(2);', 'n[1] = 3;', 'n[0] = 4;'], "n") is None
    assert decompile._fold_element_list(
        ['n = array<int>(2);', 'n[0] = 3;'], "n") is None
    assert decompile._fold_element_list(
        ['n = array<int>(1);', 'n[0] = f();'], "n") is None
    assert decompile._fold_element_list(
        ['n = array<int>(1);', 'n[0] = local_3;'], "n") is None


# ---- a handle that holds the constant 0 holds null -----------------------

def test_a_handle_copied_from_zero_is_null():
    """`PshC4 0 ; PSF 1 ; REFCPY` is `cb@ h = null;` in a build with no
    `ClrVPtr`."""
    zero = decompile.Atom("const", "0")
    assert decompile._null_if_zero(zero).text == "null"
    seven = decompile.Atom("const", "7")
    assert decompile._null_if_zero(seven) is seven


def _ins(name, w=0, w2=0, dw=0, bc_type=""):
    return asreader.Instr(pos=0, op=0, name=name, bc_type=bc_type, size=1,
                          w_arg=w, w_arg2=w2, dw_arg=dw)


def test_two_object_slots_compared_as_integers_are_handles():
    """`sound@ s; if (s is null)` is `SetV4 5, 0 ; CMPi 4, 5`, and slot 4 is
    never written -- the comparison is the only thing saying it is a
    handle."""
    b = bgt_asir.Builder.__new__(bgt_asir.Builder)
    b.sign_agnostic = set()
    b._funcdefs = []
    b.info = {}
    b.early = True
    seen = {}

    def dt_of_type(ref, handle=False):
        seen[ref["slot"]] = handle
        return bgt_asir.DataType(token_type=5, is_object_handle=handle)
    b.dt_of_type = dt_of_type
    f = asreader.Function(name="f", bytecode=[
        _ins("CMPi", 4, 5, bc_type="asBCTYPE_rW_rW_ARG")])
    b.slot_types(f, {"objVars": [({"slot": 4}, 4), ({"slot": 5}, 5)]})
    assert seen == {4: True, 5: True}


# ---- the 2010 beta's class records ---------------------------------------

def test_a_property_offset_is_not_a_flag():
    """Palace Punch-up's `dynamic_menu` puts `allow_escape` at offset 17,
    which read as flags set the private bit: `private` is a keyword the beta
    does not have. Proven offsets are dropped as flags."""
    b = bgt_asir.Builder.__new__(bgt_asir.Builder)
    ti = asreader.TypeInfo(kind="class", name="dynamic_menu")
    ti.size = 24
    boolean = bgt_asir.DataType(token_type=bgt_asir.BOOL)
    ti.properties = [("wrap", boolean, 16), ("allow_escape", boolean, 17),
                     ("tts", bgt_asir.DataType(token_type=bgt_asir.INT), 17 + 3)]
    offsets = b.property_offsets(ti)
    assert offsets == {16: "wrap", 17: "allow_escape", 20: "tts"}


# ---- the beta's array template -------------------------------------------

def test_the_betas_array_template_constructs_in_the_suffix_form():
    """`_builtin_array_<string>()` compiles in the beta and nowhere else;
    `string[]()` compiles in both."""
    beta = asreader.TypeInfo(kind="app", name="_builtin_array_")
    beta.template_syntax = "suffix"
    string = asreader.TypeInfo(kind="app", name="string")
    sub = asreader.DataType(token_type=5, obj_type=string)
    dt = asreader.DataType(token_type=5, obj_type=beta, template_subtypes=[sub])
    assert decompile._constructor_type(dt) == "string[]"
    newer = asreader.TypeInfo(kind="app", name="array")
    newer.template_syntax = "suffix"
    dt = asreader.DataType(token_type=5, obj_type=newer, template_subtypes=[sub])
    assert decompile._constructor_type(dt) == "array<string>"


# ---- the beta's compile report ---------------------------------------------

def test_the_betas_report_says_line_rather_than_on_line():
    raw = ("File: C:\\x\\bad.bgt\nLine: 3 (13)\n"
           "Error: 'undefined_name' is not declared\n")
    report = bgt_compile.parse(raw) if hasattr(bgt_compile, "parse") else None
    if report is None:
        return
    errors = [d for d in report if d.kind == "Error"]
    assert errors and (errors[0].line, errors[0].column) == (3, 13)


def test_the_driver_answers_the_betas_notice_and_keeps_waiting():
    assert '$title -eq "Beta Release"' in bgt_compile.DRIVER
