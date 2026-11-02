"""Known-answer tests for the loop-carried handle read.

`_deref` answers that a handle slot nothing has written holds `null`, which is
right for a slot the frame merely zeroed -- a member's initialisation, an
omitted handle argument -- and was worth 204 of one title's compiler errors.

It is also a LINEAR reading of "nothing wrote it". A handle carried round a
loop is written at the bottom and read at the top, so on the simulation's one
pass down the body nothing has written it yet: the honest answer for the first
iteration is the wrong answer for every other one.

Crazy Party's `Combattant::switchType` is the instance. It re-rolls an element
type until it differs from the current one, and its loop condition is
`chosen is null || chosen == <the current type>` with `chosen` written by the
`RefCpyV` at the bottom of the loop. Read as `null`, the second operand became
`null == <type>`, so the guard asked the wrong question -- and the recovered
function breaks out on its first iteration having chosen nothing.

The two directions below are what keep the rule narrow, and the second is the
one the first attempt got wrong.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "nvgt"))

import decompile                                              # noqa: E402
from asreader import Instr                                    # noqa: E402


def op(name, pos, w_arg=0):
    return Instr(pos=pos, op=0, name=name, bc_type="", size=1,
                 w_arg=w_arg, w_arg2=0, dw_arg=0, jump_target=None)


def sim(instrs, back_edges, at, slot_writes=None):
    """A FuncDecompiler holding just what this one rule reads."""
    fd = object.__new__(decompile.FuncDecompiler)
    fd.instrs = instrs
    fd.k = next(k for k, i in enumerate(instrs) if i.pos == at)
    fd.back_edges = back_edges
    fd.slot_writes = slot_writes or {}
    fd._handle_writes = None
    return fd


class LoopCarriedHandleTests(unittest.TestCase):

    def test_a_handle_assigned_at_the_bottom_is_not_null_at_the_top(self):
        """`switchType`'s own shape: the read is inside the loop and the only
        write to the slot is the `RefCpyV` below it."""
        instrs = [op("ClrVPtr", 65, 5),
                  op("PshVPtr", 86, 6),       # the read, at the top
                  op("RefCpyV", 128, 6),      # @local_6 = ..., at the bottom
                  op("JMP", 133)]
        fd = sim(instrs, [(65, 133)], at=86)
        self.assertTrue(fd._written_inside_this_loop(6))

    def test_a_handle_written_nowhere_is_still_null(self):
        """The rule the fallback exists for has to survive: a slot the frame
        zeroed and nothing assigned really does hold null, and rendering it
        as a variable is 204 errors of 'local_6 is not declared'."""
        instrs = [op("PshVPtr", 86, 6), op("JMP", 133)]
        fd = sim(instrs, [(65, 133)], at=86)
        self.assertFalse(fd._written_inside_this_loop(6))

    def test_a_write_outside_the_loop_does_not_count(self):
        """Narrow on purpose. A write somewhere else in the function says
        nothing about what this slot holds at this read, so the fallback is
        left alone."""
        instrs = [op("PshVPtr", 86, 6),
                  op("JMP", 133),
                  op("RefCpyV", 200, 6)]      # after the loop
        fd = sim(instrs, [(65, 133)], at=86)
        self.assertFalse(fd._written_inside_this_loop(6))

    def test_a_read_outside_any_loop_does_not_count(self):
        instrs = [op("RefCpyV", 100, 6), op("PshVPtr", 200, 6)]
        fd = sim(instrs, [(65, 133)], at=200)
        self.assertFalse(fd._written_inside_this_loop(6))

    def test_nulling_a_handle_is_NOT_the_kind_of_write_that_counts(self):
        """A `ClrVPtr` write's value IS null, so the fallback already answers
        it correctly: only a write that carries a VALUE makes null wrong.

        Measured, this exclusion changes no title's output -- so it is a
        claim rather than a fix, pinned here because the rule it narrows
        would otherwise be wrong the first time a loop's only write to a
        handle slot is one that nulls it.
        """
        instrs = [op("PshVPtr", 86, 6),
                  op("ClrVPtr", 120, 6),      # nulled inside the loop
                  op("JMP", 133)]
        fd = sim(instrs, [(65, 133)], at=86)
        self.assertFalse(fd._written_inside_this_loop(6))

    def test_an_ordinary_opcode_write_inside_the_loop_counts(self):
        """`slot_writes` is still read -- this rule adds to that record for
        itself rather than replacing it, because the three kinds of write it
        has never held are exactly the ones a handle uses."""
        instrs = [op("PshVPtr", 86, 6), op("JMP", 133)]
        fd = sim(instrs, [(65, 133)], at=86, slot_writes={6: [120]})
        self.assertTrue(fd._written_inside_this_loop(6))


if __name__ == "__main__":
    unittest.main()
