"""How the 2010 to 2011-02 engines move a string, and why BGT 1.0's Power
Player would not compile.

Those builds hand a string back in the OBJECT REGISTER -- the string
factory, `string::opAdd`, and a function returning a `string` -- so it
reaches a slot by `STOREOBJ` and leaves by `LOADOBJ`, the two opcodes that
are otherwise the plainest handle witnesses there are. Read that way every
string temp was declared `string@`: "Object handle is not supported for this
type", 22 errors in Power Player, Ljudfarmen's 73 declarations and Palace
Punch-up's 57.

And they copy a string by default-constructing it and assigning into it,
`PshRPtr ; PSF 6 ; ALLOC string ; PshV4 6 ; opAssign`, which the copy
constructor rule read backwards: `list[0] = null; local_6 = <?>;`.

Synthetic inputs only.
"""

import os
import sys

TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
sys.path.insert(0, TOOLS)

import bgt_asir  # noqa: E402
from nvgt import asreader, decompile  # noqa: E402


def _ins(name, w=0, dw=0):
    return asreader.Instr(pos=0, op=0, name=name, bc_type="", size=1,
                          w_arg=w, dw_arg=dw)


STRING = {"kind": "named", "name": "string", "namespace": ""}
SOUND = {"kind": "named", "name": "sound", "namespace": ""}


def _handles(bytecode, used, returns=None, slots=(1,), early=True):
    """Which object slots `slot_types` declares as handles."""
    b = bgt_asir.Builder.__new__(bgt_asir.Builder)
    b.sign_agnostic = set()
    b._funcdefs = []
    b.info = {"tail": {"used_functions": used}}
    b.early = early
    seen = {}

    def dt_of_type(ref, handle=False):
        seen[ref["slot"]] = handle
        return bgt_asir.DataType(token_type=5, is_object_handle=handle)
    b.dt_of_type = dt_of_type
    f = asreader.Function(name="f", bytecode=bytecode)
    rec = {"objVars": [({"slot": s}, s) for s in slots]}
    if returns is not None:
        rec["returns"] = returns
    b.slot_types(f, rec)
    return seen


def _returns(type_, handle):
    return {"token": 5, "type": type_, "handle": handle}


def test_a_literal_stored_from_the_factory_is_not_a_handle():
    """`STR "music" ; CALLSYS _string_factory_ ; STOREOBJ 1`."""
    used = [{"name": "_string_factory_", "returns": _returns(STRING, False)}]
    seen = _handles([_ins("CALLSYS", dw=0), _ins("SUSPEND"),
                     _ins("STOREOBJ", 1)], used)
    assert seen == {1: False}


def test_a_string_returned_by_value_is_not_a_handle():
    """`"music\\\\" + list[0]` is `string::opAdd`, returning a `string`."""
    used = [{"name": "opAdd", "returns": _returns(STRING, False)}]
    assert _handles([_ins("CALLSYS", dw=0), _ins("STOREOBJ", 1)], used) \
        == {1: False}


def test_a_handle_returned_into_the_register_is_still_a_handle():
    """A factory for `sound@` really does store a handle."""
    used = [{"name": "$beh3", "returns": _returns(SOUND, True)}]
    assert _handles([_ins("CALLSYS", dw=0), _ins("STOREOBJ", 1)], used) \
        == {1: True}


def test_a_value_returned_through_the_register_is_not_a_handle():
    """Palace Punch-up's `serialize_player` ends `LOADOBJ 5 ; RET`."""
    seen = _handles([_ins("LOADOBJ", 5), _ins("RET")], [],
                    returns=_returns(STRING, False), slots=(5,))
    assert seen == {5: False}
    seen = _handles([_ins("LOADOBJ", 5), _ins("RET")], [],
                    returns=_returns(SOUND, True), slots=(5,))
    assert seen == {5: True}


class _Ptr:
    def __init__(self, offset):
        self.is_ptr = True
        self.offset = offset


def test_an_alloc_whose_new_object_is_the_next_receiver_takes_no_argument():
    """`PshRPtr ; PSF 6 ; ALLOC string ; PshV4 6 ; opAssign`: the address on
    top is the destination, and the value below it is the `opAssign`'s."""
    code = [_ins("PSF", 6), _ins("ALLOC"), _ins("SUSPEND"), _ins("PshV4", 6)]
    stack = [_Ptr(None), _Ptr(6)]
    assert decompile._alloc_destination_on_top(stack, code, 1)


def test_an_alloc_whose_argument_is_destroyed_after_keeps_its_argument():
    """Screaming Strike's copy: `PSF 7 ... PSF 6 ; ALLOC ; PSF 6 ; $beh1` --
    the temp on top is passed and destroyed, not made a receiver."""
    code = [_ins("PSF", 6), _ins("ALLOC"), _ins("PSF", 6), _ins("CALLSYS")]
    assert not decompile._alloc_destination_on_top([_Ptr(7), _Ptr(6)], code, 1)
    code = [_ins("PSF", 6), _ins("ALLOC"), _ins("PshV4", 7)]
    assert not decompile._alloc_destination_on_top([_Ptr(7), _Ptr(6)], code, 1)


def test_a_newer_engine_keeps_a_reference_type_returned_by_value():
    """Sable (stock 1.3): `find_sounds` returns a `string[]`, which is a
    reference type, and the rule is the early generation's alone."""
    used = [{"name": "find_sounds", "returns": _returns(
        {"kind": "template", "name": "array"}, False)}]
    b_seen = _handles([_ins("CALLSYS", dw=0), _ins("STOREOBJ", 1)], used,
                      early=False)
    assert b_seen == {1: True}
