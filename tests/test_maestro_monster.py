"""Why BGT 1.0's Maestro Monster would not compile: 127 errors, three shapes.

All three are in its copy of BGT 1.0's `form.bgt`:

* a METHOD returning a `string` by value -- `control::type_to_name()`, a
  `CALLINTF` -- reaches its slot by `STOREOBJ` exactly as the string factory
  does, and was declared `string@`;
* a parameter is copied into a temp with the SOURCE pushed after the
  `ALLOC`: `PSF 6 ; ALLOC string ; PshV4 -1 ; PshV4 6 ; opAssign`, which came
  out `string_replace(null, "", string(1), <?>)`;
* `return arg0;` is `PSF 1 ; ALLOC ; PshV4 1 ; opAssign ; LOADOBJ 1`, with
  the receiver pushed BY VALUE, which came out
  `string() = arg0; return string();`.

Synthetic inputs only.
"""

import os
import sys

TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
sys.path.insert(0, TOOLS)

from nvgt import asreader, decompile  # noqa: E402
from nvgt.decompile import Atom, FuncDecompiler  # noqa: E402

from test_bgt10_strings import STRING, _handles, _ins, _returns  # noqa: E402


def test_a_string_returned_by_value_from_a_METHOD_is_not_a_handle():
    used = [{"name": "type_to_name", "returns": _returns(STRING, False)}]
    assert _handles([_ins("CALLINTF", dw=0), _ins("STOREOBJ", 1)], used) \
        == {1: False}


def _call(name):
    ins = _ins("CALLSYS")
    ins.func_ref = asreader.Function(name=name)
    return ins


def _ptr(off):
    return Atom("var", "local_%d" % off, is_ptr=True, offset=off)


def test_the_destination_may_be_the_SECOND_push_before_an_opAssign():
    code = [_ins("ALLOC"), _ins("PshV4", 0xFFFF), _ins("PshV4", 6),
            _call("opAssign")]
    assert decompile._alloc_destination_on_top([_ptr(6)], code, 0)


def test_two_pushes_with_no_opAssign_are_constructor_arguments():
    code = [_ins("ALLOC"), _ins("PshV4", 0xFFFF), _ins("PshV4", 6),
            _call("string_replace")]
    assert not decompile._alloc_destination_on_top([_ptr(6)], code, 0)
    # ...and the old shape still answers.
    assert decompile._alloc_destination_on_top(
        [_ptr(6)], [_ins("ALLOC"), _ins("PshV4", 6), _call("opAssign")], 0)


def _at(code, k, named=()):
    fd = object.__new__(FuncDecompiler)
    fd.instrs = code
    fd.k = k
    fd.is_named_here = lambda off: off in named
    return fd


def test_a_receiver_pushed_by_value_names_its_temp():
    code = [_ins("PshV4", 0xFFFF), _ins("PshV4", 1), _call("opAssign")]
    assert _at(code, 2)._value_pushed_temp() == 1


def test_a_named_slot_or_a_parameter_is_not_a_temp():
    code = [_ins("PshV4", 1), _call("opAssign")]
    assert _at(code, 1, named={1})._value_pushed_temp() is None
    assert _at([_ins("PshV4", 0xFFFF), _call("opAssign")], 1) \
        ._value_pushed_temp() is None
