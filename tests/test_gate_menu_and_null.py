"""Two defects found by playing The Gate's recovery.

Every menu had to be answered twice, and a stage died with "Null pointer
access" in `character::find_target` as soon as a fighter looked for a
target. Synthetic inputs only.
"""

import os
import sys

TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
sys.path.insert(0, TOOLS)

from nvgt import asreader, decompile  # noqa: E402
from nvgt.decompile import Atom, FuncDecompiler  # noqa: E402


def _ins(name, w=0, w2=0):
    return asreader.Instr(pos=0, op=0, name=name, bc_type="", size=1,
                          w_arg=w, w_arg2=w2)


def _at(code, k):
    fd = object.__new__(FuncDecompiler)
    fd.instrs = code
    fd.k = k
    return fd


def test_a_handle_copied_for_one_null_test_is_borrowed():
    """`last_attacker.current_weapon !is null` inside an `&&` arm:

        RefCpyV 6 ; PopPtr ; ClrVPtr 7 ; CmpPtr 6 7 ; TNZ ; CpyRtoV4 5 ;
        FREE 6

    Emitted as a statement it sorted ahead of the whole condition and read
    the member before the null test guarding it."""
    code = [_ins("RefCpyV", 6), _ins("PopPtr"), _ins("ClrVPtr", 7),
            _ins("CmpPtr", 6, 7), _ins("TNZ"), _ins("CpyRtoV4", 5),
            _ins("FREE", 6)]
    assert _at(code, 0)._borrowed_for_a_null_test(6)


def test_a_slot_read_twice_or_across_a_jump_is_not_borrowed():
    twice = [_ins("RefCpyV", 6), _ins("CmpPtr", 6, 7), _ins("CmpPtr", 6, 8),
             _ins("FREE", 6)]
    assert not _at(twice, 0)._borrowed_for_a_null_test(6)
    jump = [_ins("RefCpyV", 6), _ins("CmpPtr", 6, 7), _ins("JZ"),
            _ins("FREE", 6)]
    assert not _at(jump, 0)._borrowed_for_a_null_test(6)
    other_use = [_ins("RefCpyV", 6), _ins("CmpPtr", 6, 7), _ins("PshVPtr", 6),
                 _ins("FREE", 6)]
    assert not _at(other_use, 0)._borrowed_for_a_null_test(6)
    never_freed = [_ins("RefCpyV", 6), _ins("CmpPtr", 6, 7)]
    assert not _at(never_freed, 0)._borrowed_for_a_null_test(6)


def _promoting(text, folded, impure):
    fd = object.__new__(FuncDecompiler)
    fd.temps = {10: Atom("call", text)}
    fd.temp_bound = {10: (260, 3)}
    fd.var_names = {}
    fd.var_types = {}
    fd.events = []
    fd.fold_reads = {(10, 260): 1} if folded else {}
    fd.invocations = {text: 255} if impure else {}
    fd.promoted_after_fold = set()
    fd.mixed_boolean_slots = set()
    return fd


def test_a_call_promoted_after_a_read_folded_it_is_carried_to_the_next_pass():
    """`local_10 = menu.run_extended(...); if (menu.run_extended(...) == -1)`:
    the menu ran twice. The next pass promotes before the first read."""
    fd = _promoting("menu.run_extended()", folded=True, impure=True)
    try:
        fd._promote_temp(10)
    except Exception:
        pass
    assert fd.promoted_after_fold == {(10, 260)}


def test_a_pure_value_or_an_unfolded_one_is_not():
    for folded, impure in ((False, True), (True, False)):
        fd = _promoting("menu.run_extended()", folded, impure)
        try:
            fd._promote_temp(10)
        except Exception:
            pass
        assert fd.promoted_after_fold == set()


def _jmp(target_pos):
    ins = asreader.Instr(pos=0, op=0, name="JMP", bc_type="", size=1)
    ins.jump_target = target_pos
    return ins


def test_a_jump_table_is_as_long_as_its_range():
    """`character::set_state`: a switch over 0..12 whose case 8 arm is only a
    `break` -- a `JMP` straight after the table, read as a 14th entry. The
    upper bound in the guard, `CMPIi sel, 12 ; JP`, says the table has 13."""
    guard_hi = asreader.Instr(pos=0, op=0, name="CMPIi", bc_type="", size=1,
                              w_arg=0xFFFF, dw_arg=12)
    jp = asreader.Instr(pos=0, op=0, name="JP", bc_type="", size=1)
    jp.jump_target = 500
    guard_lo = asreader.Instr(pos=0, op=0, name="CMPIi", bc_type="", size=1,
                              w_arg=0xFFFF, dw_arg=0)
    js = asreader.Instr(pos=0, op=0, name="JS", bc_type="", size=1)
    js.jump_target = 500
    sub = asreader.Instr(pos=0, op=0, name="SUBIi", bc_type="", size=1,
                         w_arg=3, w_arg2=0xFFFF, dw_arg=0)
    jmpp = asreader.Instr(pos=0, op=0, name="JMPP", bc_type="", size=1, w_arg=3)
    entries = [_jmp(100 + i) for i in range(13)]
    arm_that_breaks = _jmp(500)
    code = [guard_hi, jp, guard_lo, js, sub, jmpp] + entries + [arm_that_breaks]
    fd = _at(code, 0)
    table = fd._dense_table(5)
    assert table is not None
    cursor = table[0]
    assert cursor == 6 + 13
