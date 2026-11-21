"""Three shapes Sable (stock BGT 1.3) would not compile with.

- a by-value member constructed with a STRING argument, which arrives in a
  temp string slot rather than as a pushed literal;
- a by-value member constructed from the constructor's own PARAMETER, which
  a member initialiser may name because it is compiled inside the
  constructor (BGT was asked: `needs2 n(x, 5);` beside `holder2(int x)`
  compiles and runs to `35` for `x == 3`);
- an unread `__nvgt_ret_N` holder, which goes back to a bare call.

Synthetic instructions only; no game file is involved.
"""

import os
import sys

try:                                   # after `pip install -e .`
    from bgtdecomp.nvgt import asreader, decompile
except ImportError:                    # straight from a checkout
    TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
    sys.path.insert(0, TOOLS)
    from nvgt import asreader, decompile


STRING = asreader.TypeInfo(kind="app", name="string")


def ins(name, w=0, dw=0, string=None, type_ref=None):
    return asreader.Instr(pos=0, op=0, name=name, bc_type="", size=1,
                          w_arg=w, dw_arg=dw, string_const=string,
                          type_ref=type_ref)


def test_a_string_argument_built_in_a_temp_slot_is_read_as_its_literal():
    """Sable's `droppable_items`:

        PSF 3 ; STR "" ; _string_factory_ ; PshRPtr ; PSF 1 ; $beh0 ;
        PSF 1 ; ALLOC string ; PSF 1 ; $beh2 ; VAR 3 ; GETOBJ 0 ; CALL
    """
    code = [ins("PSF", 3), ins("STR", string="Please select"),
            ins("CALLSYS"), ins("PshRPtr"), ins("PSF", 1), ins("CALLSYS"),
            ins("PSF", 1), ins("ALLOC", type_ref=STRING), ins("PSF", 1),
            ins("CALLSYS"), ins("VAR", 3), ins("GETOBJ", 0), ins("CALL")]
    assert decompile._written_arguments(code, len(code) - 1, 1) == \
        ['"Please select"']


def test_a_parameter_argument_needs_a_single_constructor_to_be_named():
    """`player new_class(arg0, "", 0, ...)`: the parameter is copied into
    slot 13 and the literal into slot 12, and the walk resumes before each
    slot's own construction. Without parameter names -- more than one
    constructor -- the whole argument list is refused."""
    code = [ins("PshC4", dw=0),
            ins("PSF", 12), ins("STR", string=""), ins("CALLSYS"),
            ins("PshRPtr"), ins("PSF", 1), ins("CALLSYS"), ins("PSF", 1),
            ins("ALLOC", type_ref=STRING), ins("PSF", 1), ins("CALLSYS"),
            ins("VAR", 12),
            ins("PSF", 13), ins("PshVPtr", -1 & 0xFFFF),
            ins("ALLOC", type_ref=STRING),
            ins("VAR", 13), ins("GETOBJ", 0), ins("GETOBJ", 1), ins("CALL")]
    call = len(code) - 1
    assert decompile._written_arguments(code, call, 3, {-1: "arg0"}) == \
        ["arg0", '""', "0"]
    assert decompile._written_arguments(code, call, 3) is None


def test_an_unread_holder_goes_back_to_a_bare_call():
    body = ["    bool __nvgt_ret_178;",
            "    __nvgt_ret_178 = savedValues.get(\"x\", __nvgt_out_6_178);",
            "    y = __nvgt_out_6_178;"]
    assert decompile._drop_unread_returns(body) == [
        "    savedValues.get(\"x\", __nvgt_out_6_178);",
        "    y = __nvgt_out_6_178;"]


def test_a_read_holder_is_kept():
    body = ["    bool __nvgt_ret_3372;",
            "    __nvgt_ret_3372 = map_dimensions(a, b, c, true);",
            "    if (!__nvgt_ret_3372) {"]
    assert decompile._drop_unread_returns(body) == body


def test_a_declaration_paired_with_a_read_is_not_an_unread_holder():
    """Two mentions, but no assignment: dropping the declaration would leave
    the read undeclared."""
    body = ["    bool __nvgt_ret_5;", "    if (__nvgt_ret_5) {"]
    assert decompile._drop_unread_returns(body) == body
