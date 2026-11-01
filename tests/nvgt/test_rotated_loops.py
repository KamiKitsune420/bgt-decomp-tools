"""`_find_latch` on the rotated loop whose CONDITION CALLS something.

The compiler emits a `for`/`while` bottom-tested: an unconditional forward
`JMP` to the condition, the condition last, and a conditional back edge above
the body. Where the condition's own materialisation calls something -- any
`for` whose bound is a call -- this was refused outright, on the grounds that
*anything that calls something is not the materialisation*. It is, and the
refusal left the entry jump and the latch as a pair of `goto`s that
AngelScript has no spelling for.

These are synthetic event lists: `_find_latch` reads only `ev`, `done` and
`_next_index`, so a stand-in exercises exactly the decision without building a
module. What it must get right is which shape is a loop AND which emission
that shape needs, because the previous attempt recognised the loop and wrote a
`for` header that dropped the bound's assignment -- a silent wrong program in
place of a visible failure.
"""
import unittest

from decompile import Event, Structurer


class Stub:
    """Just enough of a Structurer for `_find_latch`."""

    def __init__(self, events):
        self.ev = events
        self.done = [False] * len(events)

    def _next_index(self, pos):
        for k, e in enumerate(self.ev):
            if e.pos >= pos:
                return k
        return len(self.ev)

    find = Structurer._find_latch


def stmt(pos, text):
    return Event("stmt", pos, ("", text))


def branch(pos, cond, target):
    return Event("branch", pos, (cond, target))


def jump(pos, target):
    return Event("jump", pos, target)


class FindLatchTests(unittest.TestCase):

    def test_an_empty_condition_block_is_the_plain_while(self):
        """Nothing to materialise, so the existing emission is untouched."""
        s = Stub([jump(0, 20),               # 0: entry jump to the condition
                  stmt(2, "f();"),           # 1: the body
                  stmt(4, "i++;"),           # 2
                  branch(20, "(i < n)", 2)])  # 3: the latch, at the condition
        self.assertEqual(s.find(0, 20, 4), (3, 2, False))

    def test_a_call_free_materialisation_stays_the_plain_while(self):
        """`for (i = 0; i < bag[n].items.length(); i++)` emits `@handle = bag;`
        there. It is loop-invariant, so leaving it at the END of the body is
        harmless -- and that is what the `while (cond)` form does, so every
        title that already recovered cleanly must keep this answer."""
        s = Stub([jump(0, 20),
                  stmt(2, "f();"),
                  stmt(4, "i++;"),
                  stmt(20, "@handle = bag;"),
                  branch(24, "(i < handle.length)", 2)])
        self.assertEqual(s.find(0, 20, 5), (4, 2, False))

    def test_a_calling_materialisation_asks_for_the_condition_at_the_top(self):
        """rage room's `count_total_items`, Psycho Strike's
        `home::reset_rebels` and Crazy Party's fourteen are this shape. The
        third element is what tells `_block` to write `while (true)` with an
        explicit `break` instead."""
        s = Stub([jump(0, 20),
                  stmt(2, "f();"),
                  stmt(4, "i++;"),
                  stmt(20, "@keys = inv.get_keys();"),
                  stmt(24, "n = keys.length();"),
                  branch(28, "(i < n)", 2)])
        self.assertEqual(s.find(0, 20, 6), (5, 2, True))

    def test_a_condition_reading_the_block_through_a_member_counts(self):
        """The test need not name the assigned slot bare: `keys.length()`
        reads `keys`, and the guard splits the assigned name at the first `.`
        or `[` for exactly that reason."""
        s = Stub([jump(0, 20),
                  stmt(2, "f();"),
                  stmt(20, "@keys = inv.get_keys();"),
                  branch(24, "(i < keys.length())", 2)])
        self.assertEqual(s.find(0, 20, 4), (3, 2, True))

    def test_a_working_block_the_test_does_not_read_is_refused(self):
        """Without this, an unrelated run of assignments before a backward
        branch would be claimed as a loop condition. The block computes
        `total`; the test reads neither it nor anything it assigns."""
        s = Stub([jump(0, 20),
                  stmt(2, "f();"),
                  stmt(20, "total = score.sum();"),
                  branch(24, "(i < n)", 2)])
        self.assertIsNone(s.find(0, 20, 4))

    def test_a_statement_that_is_not_an_assignment_is_still_refused(self):
        """A condition's materialisation computes values. A bare call there
        means this is an if/else merge block, not a loop condition -- which is
        the reason the original guard existed and is kept."""
        s = Stub([jump(0, 20),
                  stmt(2, "f();"),
                  stmt(20, "speak(x);"),
                  branch(24, "(i < n)", 2)])
        self.assertIsNone(s.find(0, 20, 4))

    def test_a_forward_branch_is_not_a_latch(self):
        s = Stub([jump(0, 20),
                  stmt(2, "f();"),
                  branch(20, "(i < n)", 40)])
        self.assertIsNone(s.find(0, 20, 3))

    def test_a_latch_already_claimed_is_not_claimed_twice(self):
        s = Stub([jump(0, 20),
                  stmt(2, "f();"),
                  branch(20, "(i < n)", 2)])
        s.done[2] = True
        self.assertIsNone(s.find(0, 20, 3))


if __name__ == "__main__":
    unittest.main()
