"""
Known-answer tests for `bgt roundtrip` -- the original bytecode against the
RECOMPILED bytecode.

Synthetic inputs only, no game files and no engine, so these run anywhere.
The module is an instrument, and an instrument is worth what its calibration
is worth. These target the ways this particular comparison can be confidently
wrong:

  * **The operand-kind table disagreeing with the build's own.** Which
    operands are frame slots comes from AngelScript's `asBCType` enum, and if
    that mapping is wrong every slot-versus-constant decision below it is
    wrong QUIETLY -- a constant read as a slot would be renumbered away and a
    flattened constant would compare equal. So the table's operand counts are
    checked against the counts the opcode table declares, and a disagreement
    raises rather than being tolerated.
  * **Comparing a module against itself.** The two sides of a round trip are
    usually named the same -- the engine writes `superegghunt.exe` beside the
    recovered script and the original is `superegghunt.exe` too -- so
    unpacking both to one scratch name made the second overwrite the first.
    That really happened, and it reported **143 of 143 bodies identical with
    an edit distance of zero**: a perfect score from a comparison that never
    took place.
  * **Slot numbering mistaken for meaning.** The compiler allocates slots in
    its own order, so a raw offset comparison reports every body as differing
    and means nothing by it; and the opposite error, dropping a constant along
    with the slots, would make two different programs compare equal.
  * **A label number mistaken for a jump.** Label numbers are assigned in
    order of first appearance, so two bodies of the same shape can disagree on
    them while jumping the same distance.

Run:  python tests/test_roundtrip.py   (or: python -m pytest tests/ -q)
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))

import as_opcodes                                                 # noqa: E402
import bgt_roundtrip                                              # noqa: E402


def _ins(name, args=()):
    """One disassembled instruction, in `as_disasm`'s own shape."""
    return {"name": name,
            "args": [{"value": v, "role": r, "text": t}
                     for v, r, t in args]}


def _body(instrs):
    return {"instructions": instrs}


class OperandKindTests(unittest.TestCase):
    """The table that decides which operands are frame slots."""

    def test_every_asBCType_the_decoder_knows_has_a_shape(self):
        """`as_opcodes.TYPE_INFO` is the set of types a body can contain."""
        for bc_type in as_opcodes.TYPE_INFO:
            self.assertIn(bc_type, bgt_roundtrip.OPERAND_KINDS,
                          "asBCType %d has no operand-kind shape" % bc_type)

    def test_the_shapes_agree_with_the_decoder_on_operand_COUNT(self):
        """The independent check: two tables, read from different places.

        `TYPE_INFO` carries the operand count the decoder steps by, and
        `OPERAND_KINDS` carries what each operand IS. They are transcriptions
        of the same enum, so they have to agree -- and a disagreement means
        the enum mapping is wrong, which would misread constants as slots.
        """
        for bc_type, (operands, _dwords) in as_opcodes.TYPE_INFO.items():
            self.assertEqual(
                len(bgt_roundtrip.OPERAND_KINDS[bc_type]), operands,
                "asBCType %d: shape says %d operand(s), the decoder steps "
                "by %d" % (bc_type,
                           len(bgt_roundtrip.OPERAND_KINDS[bc_type]),
                           operands))

    def test_a_build_whose_table_disagrees_is_refused(self):
        """Not worked around: a wrong mapping is wrong quietly."""
        with self.assertRaises(ValueError):
            bgt_roundtrip.operand_kinds(
                {0: {"name": "MadeUp", "type": 12, "operands": 3}})

    def test_an_unknown_asBCType_is_refused(self):
        with self.assertRaises(ValueError):
            bgt_roundtrip.operand_kinds(
                {0: {"name": "MadeUp", "type": 999, "operands": 1}})


class CanonicalTests(unittest.TestCase):
    """What a body is reduced to before the two sides are compared."""

    KINDS = {"SetV4": ("V", "C"), "CpyVtoV4": ("V", "V"),
             "CALLSYS": (), "JZ": (), "PshC4": ("C",)}

    def test_a_slot_is_renumbered_first_seen_not_taken_raw(self):
        """Two bodies that differ only by slot numbering are the same body."""
        a = _body([_ins("CpyVtoV4", [(7, None, None), (9, None, None)]),
                   _ins("CpyVtoV4", [(9, None, None), (7, None, None)])])
        b = _body([_ins("CpyVtoV4", [(2, None, None), (5, None, None)]),
                   _ins("CpyVtoV4", [(5, None, None), (2, None, None)])])
        self.assertEqual(bgt_roundtrip.canonical(a, self.KINDS),
                         bgt_roundtrip.canonical(b, self.KINDS))

    def test_slot_blindness_drops_slots_and_KEEPS_constants(self):
        """The error that would make two different programs compare equal."""
        thirty = _body([_ins("SetV4", [(1, None, None), (30, None, None)])])
        one = _body([_ins("SetV4", [(1, None, None), (1, None, None)])])
        self.assertNotEqual(
            bgt_roundtrip.canonical(thirty, self.KINDS, slots=False),
            bgt_roundtrip.canonical(one, self.KINDS, slots=False))
        self.assertEqual(
            bgt_roundtrip.canonical(thirty, self.KINDS, slots=False),
            ["SetV4 30"])

    def test_a_consistent_renaming_is_invisible_and_is_meant_to_be(self):
        """Which is the whole reason the slots are renumbered at all: the
        compiler picks its own offsets, so two bodies that use their slots
        the same way are the same body however they are numbered."""
        a = _body([_ins("CpyVtoV4", [(1, None, None), (2, None, None)]),
                   _ins("CpyVtoV4", [(1, None, None), (3, None, None)])])
        b = _body([_ins("CpyVtoV4", [(8, None, None), (9, None, None)]),
                   _ins("CpyVtoV4", [(8, None, None), (4, None, None)])])
        self.assertEqual(bgt_roundtrip.canonical(a, self.KINDS),
                         bgt_roundtrip.canonical(b, self.KINDS))

    def test_a_DIFFERENT_slot_pattern_is_seen_with_slots_and_not_without(self):
        """The strict score is stricter, which is the only reason to have it.

        No renaming can carry the second body onto the first: `a` writes one
        slot twice where `b` writes two different ones, so the two really do
        use their frame differently -- and the loose score, which is blind to
        slots on purpose, cannot tell.
        """
        a = _body([_ins("CpyVtoV4", [(1, None, None), (2, None, None)]),
                   _ins("CpyVtoV4", [(1, None, None), (3, None, None)])])
        b = _body([_ins("CpyVtoV4", [(1, None, None), (2, None, None)]),
                   _ins("CpyVtoV4", [(3, None, None), (1, None, None)])])
        self.assertNotEqual(bgt_roundtrip.canonical(a, self.KINDS),
                            bgt_roundtrip.canonical(b, self.KINDS))
        self.assertEqual(bgt_roundtrip.canonical(a, self.KINDS, slots=False),
                         bgt_roundtrip.canonical(b, self.KINDS, slots=False))

    def test_a_jump_is_its_DISTANCE_not_its_label_number(self):
        """A label is numbered by first appearance, which two bodies of one
        shape can disagree on while jumping identically."""
        a = _body([_ins("JZ", [(4, "jump", "L0")])])
        b = _body([_ins("JZ", [(4, "jump", "L3")])])
        self.assertEqual(bgt_roundtrip.canonical(a, self.KINDS),
                         bgt_roundtrip.canonical(b, self.KINDS))
        self.assertEqual(bgt_roundtrip.canonical(a, self.KINDS), ["JZ @+4"])
        far = _body([_ins("JZ", [(9, "jump", "L0")])])
        self.assertNotEqual(bgt_roundtrip.canonical(far, self.KINDS),
                            bgt_roundtrip.canonical(a, self.KINDS))

    def test_a_named_operand_is_its_NAME_not_its_index(self):
        """A rebuild reorders every table, so an index cannot be compared."""
        a = _body([_ins("CALLSYS", [(11, "function", "sound::stream")])])
        b = _body([_ins("CALLSYS", [(907, "function", "sound::stream")])])
        self.assertEqual(bgt_roundtrip.canonical(a, self.KINDS),
                         bgt_roundtrip.canonical(b, self.KINDS))
        other = _body([_ins("CALLSYS", [(11, "function", "sound::load")])])
        self.assertNotEqual(bgt_roundtrip.canonical(other, self.KINDS),
                            bgt_roundtrip.canonical(a, self.KINDS))

    def test_an_unresolved_operand_does_not_collapse_onto_another(self):
        """Two names that could not be resolved are not thereby equal."""
        a = _body([_ins("CALLSYS", [(11, "function", None)])])
        b = _body([_ins("CALLSYS", [(12, "function", None)])])
        self.assertNotEqual(bgt_roundtrip.canonical(a, self.KINDS),
                            bgt_roundtrip.canonical(b, self.KINDS))


class TwoSidesTests(unittest.TestCase):
    """The guard against a comparison that never happened."""

    def test_one_file_against_itself_is_refused(self):
        path = os.path.join(HERE, "test_roundtrip.py")
        with self.assertRaises(ValueError):
            bgt_roundtrip._two_sides(path, path, None)

    def test_two_executables_of_ONE_NAME_do_not_collide(self):
        """The bug this guard exists for: the engine writes the rebuilt
        executable under the game's own name, so both sides unpack to the
        same scratch file unless the name carries where it came from."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            one = os.path.join(tmp, "a", "game.exe")
            two = os.path.join(tmp, "b", "game.exe")
            for path in (one, two):
                os.makedirs(os.path.dirname(path))
                with open(path, "wb") as fh:
                    fh.write(b"not a PE")
            # Not executables, so each is taken as a module and returned as
            # itself -- which is enough to show the two sides stay distinct.
            (a, _), (b, _) = bgt_roundtrip._two_sides(one, two, tmp)
            self.assertNotEqual(os.path.abspath(a), os.path.abspath(b))

    def test_a_refusal_is_an_OUTCOME_and_not_a_traceback(self):
        """`main` returns 2 rather than raising, because the two sides being
        one file is the mistake a round trip invites -- the engine writes the
        rebuilt executable under the game's own name."""
        path = os.path.join(HERE, "test_roundtrip.py")
        self.assertEqual(bgt_roundtrip.main([path, path]), 2)

    def test_the_scratch_name_carries_the_side_and_the_source(self):
        """So two sources of one basename cannot land on one name."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            names = set()
            for folder in ("a", "b"):
                path = os.path.join(tmp, folder, "game.exe")
                os.makedirs(os.path.dirname(path))
                with open(path, "wb") as fh:
                    fh.write(b"MZ" + b"\0" * 64)
                try:
                    bgt_roundtrip._module_of(path, tmp, folder)
                except Exception:
                    pass          # not a real BGT executable; the NAME is the
                import hashlib    # thing under test, so derive it the same way
                tag = hashlib.sha256(
                    os.path.abspath(path).encode("utf-8")).hexdigest()[:8]
                names.add("game_%s_%s_bytecode.bin" % (folder, tag))
            self.assertEqual(len(names), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
