"""Two things the 2011 and 2012 engines did that stopped Survive compiling.

Survive (2012-02) recovered with every string it copied into an argument
lost -- `pool.play_2d(null, null, ...)` -- and BGT's own `dynamic_menu`
declared a handle by value. Antony, Grodan Gun and Ljudfarmen had the first
too: 101, 77 and 12 such arguments, and `bgt audit` reported 70 and 51
literals lost from the first two. Synthetic inputs only.
"""

import os
import sys

TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
sys.path.insert(0, TOOLS)

import bgt_asir  # noqa: E402
from nvgt import asreader  # noqa: E402


def _builder(info):
    return bgt_asir.Builder(b"", dict({"dialect": "tagged"}, **info), {})


def test_the_2011_and_2012_engines_leave_a_registered_types_callee_unread():
    """`PSF 6 ; <member> ; RDSPtr ; ALLOC string 33`: 33 named a callee with
    no parameters, so the member became the destination and the call got
    `null`. These builds translate the operand only for a script class."""
    for release in ("2011-02", "2011-09", "2011-11", "2012-02", None):
        b = _builder({"early": True, "release": release})
        assert b.m.alloc_callee_script_only is True, release


def test_the_2010_beta_reads_its_alloc_callee():
    """Its operand names the copy constructor: the stack rule put 18 `null`s
    INTO Palace Punch-up, which recovered right before."""
    b = _builder({"early": True, "release": "2010-07"})
    assert b.m.alloc_callee_script_only is False


def test_the_newer_readers_profiles_are_unchanged():
    assert _builder({}).m.alloc_callee_script_only is False
    assert _builder({"alloc_callee_script_only": True}) \
        .m.alloc_callee_script_only is True


def _ins(name, w=0):
    return asreader.Instr(pos=0, op=0, name=name, bc_type="", size=1, w_arg=w)


def test_a_handle_copied_past_a_getobjref_is_still_a_handle():
    """BGT's own `dynamic_menu::run_extended`:

        VAR 8 ; PSF 6 ; GETOBJREF 1 ; REFCPY      @menu_sound = temp

    `GETOBJREF` converts the value below and leaves the destination where it
    is. Missed, the slot was declared `sound local_6;` and assigned by value:
    "No appropriate opAssign method found in 'sound'"."""
    b = bgt_asir.Builder.__new__(bgt_asir.Builder)
    b.sign_agnostic = set()
    b._funcdefs = []
    seen = {}

    def dt_of_type(ref, handle=False):
        seen[ref["slot"]] = handle
        return bgt_asir.DataType(token_type=5, is_object_handle=handle)
    b.dt_of_type = dt_of_type
    f = asreader.Function(name="run_extended", bytecode=[
        _ins("VAR", 8), _ins("PSF", 6), _ins("GETOBJREF", 1), _ins("REFCPY"),
        _ins("PSF", 7), _ins("CALLSYS")])
    rec = {"objVars": [({"slot": 6}, 6), ({"slot": 7}, 7)]}
    b.slot_types(f, rec)
    assert seen == {6: True, 7: False}
