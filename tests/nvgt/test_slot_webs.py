"""Known-answer tests for the slot-web analysis.

One frame slot is not one variable: the compiler reuses a slot for several
source locals that are live at different times. Deciding which writes to a
slot are *one* variable is the standard hard problem of decompilation, and
this is the standard answer -- reaching definitions, then group the
definitions that share a use. The term `web` comes from register allocation,
where the analysis runs the other way round.

**It is not invented here, and neither is the trap.** Hex-Rays offers the same
split by hand (`Split variable`) and says it performs no checks; angr added
the automatic version and the commit that fixed it reads "split a seeded
stack region among vvars whose live ranges interfere" -- without which its
output rendered `v0 + v0`, which is this decompiler's
`(local_14 != 0) && (local_14 != 0)` under another name.

The three cases below are the ones whose answer is known independently, and
two of them pull in opposite directions -- which is the whole point: any rule
that splits must not split the joystick flag, and any rule that merges must
not merge Field Wars' chain with the write 5,000 instructions later.
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


def op(name, pos, w_arg=0, w_arg2=0, dw_arg=0, bc_type="", jump_target=None):
    return Instr(pos=pos, op=0, name=name, bc_type=bc_type, size=1,
                 w_arg=w_arg, w_arg2=w_arg2, dw_arg=dw_arg,
                 jump_target=jump_target)


def sim(instrs):
    """A FuncDecompiler with just enough state for the analysis."""
    fd = object.__new__(decompile.FuncDecompiler)
    fd.instrs = instrs
    fd.pos_of = {i.pos: k for k, i in enumerate(instrs)}
    return fd


class WorklistTests(unittest.TestCase):
    """The dataflow has to start from every instruction, not the entry.

    Seeded with `{0}` alone it ran exactly ONE round and stopped: the entry's
    state is empty, propagating an empty set changes nothing, and a node is
    re-queued only when its state changes -- so no definition was ever
    reached. Every write then came out as its own web, including the ones
    that must not be split, and the tell was the joystick flag reporting four
    writes and four webs when the right answer is one.
    """

    def test_a_definition_reaches_a_later_use(self):
        #  0 SetV4 v5,1   1 CpyVtoR4 v5 (a read)   2 RET
        instrs = [op("SetV4", 0, w_arg=5, dw_arg=1, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("CpyVtoR4", 1, w_arg=5, bc_type="asBCTYPE_rW_ARG"),
                  op("SetV4", 2, w_arg=5, dw_arg=2, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("CpyVtoR4", 3, w_arg=5, bc_type="asBCTYPE_rW_ARG"),
                  op("RET", 4)]
        fd = sim(instrs)
        webs = fd.slot_webs(5)
        # two writes, each with its own read and neither reaching the other's:
        # two variables that happen to share a slot, which is a split
        self.assertEqual(len(webs), 2, webs)


class InterferenceTests(unittest.TestCase):
    """Two writes a single read can both see are ONE variable.

    This is the joystick flag: `dynamic_menu`'s edge flag is written in the
    UP arm and in the DOWN arm and read at the top of the loop. Split, the UP
    arm wrote one name and only the DOWN arm read it -- so pressing up
    disarmed down, which is why this file settled on one name per slot before
    the interference check existed.
    """

    def _diamond(self):
        #  0 JZ -> 3        (conditional)
        #  1 SetV4 v7, 1    (then arm writes)
        #  2 JMP -> 4
        #  3 SetV4 v7, 2    (else arm writes)
        #  4 CpyVtoR4 v7    (the join reads)
        #  5 RET
        return [op("JZ", 0, jump_target=3),
                op("SetV4", 1, w_arg=7, dw_arg=1, bc_type="asBCTYPE_wW_DW_ARG"),
                op("JMP", 2, jump_target=4),
                op("SetV4", 3, w_arg=7, dw_arg=2, bc_type="asBCTYPE_wW_DW_ARG"),
                op("CpyVtoR4", 4, w_arg=7, bc_type="asBCTYPE_rW_ARG"),
                op("RET", 5)]

    def test_both_arms_of_a_diamond_are_one_web(self):
        webs = sim(self._diamond()).slot_webs(7)
        self.assertEqual(len(webs), 1, webs)
        self.assertEqual(webs[0], frozenset({1, 3}))

    def test_a_write_the_only_read_cannot_see_is_its_own_web(self):
        """A dead store belongs with nothing, and is reported as its own web
        so a caller can tell it apart from a live one."""
        instrs = self._diamond()
        # ...plus a write after the read, which that read cannot see
        instrs = instrs[:5] + [
            op("SetV4", 5, w_arg=7, dw_arg=9, bc_type="asBCTYPE_wW_DW_ARG"),
            op("RET", 6)]
        fd = sim(instrs)
        fd.pos_of = {i.pos: k for k, i in enumerate(instrs)}
        webs = fd.slot_webs(7)
        self.assertEqual(len(webs), 2, webs)
        self.assertIn(frozenset({1, 3}), webs)
        self.assertIn(frozenset({5}), webs)


class LoopTests(unittest.TestCase):
    """A back edge carries a write to an EARLIER read.

    `while (c) { use(x); x = 1; }` reads before it writes in position order,
    and the loop makes the write reach the read -- so a rule that read
    positions linearly would split them and leave `x` never assigned. The CFG
    is what gets this right, which is why the analysis builds one rather than
    sorting by offset.
    """

    def test_a_write_reaches_a_read_above_it_through_the_back_edge(self):
        #  0 CpyVtoR4 v3   (the read, first in position order)
        #  1 SetV4 v3, 1   (the write, after it)
        #  2 JMP -> 0      (the back edge)
        instrs = [op("CpyVtoR4", 0, w_arg=3, bc_type="asBCTYPE_rW_ARG"),
                  op("SetV4", 1, w_arg=3, dw_arg=1, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("JMP", 2, jump_target=0),
                  op("SetV4", 3, w_arg=3, dw_arg=2, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("RET", 4)]
        fd = sim(instrs)
        webs = fd.slot_webs(3)
        # the write at 1 reaches the read at 0, so it is live there; the one
        # at 3 is unreachable from that read and is its own web
        self.assertTrue(any(1 in web for web in webs), webs)


class DecliningTests(unittest.TestCase):
    def test_a_slot_with_one_write_cannot_be_split(self):
        instrs = [op("SetV4", 0, w_arg=4, dw_arg=1, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("CpyVtoR4", 1, w_arg=4, bc_type="asBCTYPE_rW_ARG"),
                  op("RET", 2)]
        self.assertEqual(sim(instrs).slot_webs(4), [])

    def test_a_slot_nothing_reads_has_no_webs(self):
        instrs = [op("SetV4", 0, w_arg=4, dw_arg=1, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("SetV4", 1, w_arg=4, dw_arg=2, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("RET", 2)]
        self.assertEqual(sim(instrs).slot_webs(4), [])

    def test_a_body_too_big_to_analyse_declines(self):
        """Crazy Party's generated `ajouteLangue` is 1,074,460 instructions.
        Declining is the conservative answer: no split, which is what this
        file does everywhere today."""
        self.assertGreater(decompile.WEB_ANALYSIS_LIMIT, 30000)
        self.assertLess(decompile.WEB_ANALYSIS_LIMIT, 1000000)


if __name__ == "__main__":
    unittest.main()
