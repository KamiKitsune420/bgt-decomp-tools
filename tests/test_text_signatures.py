"""Known-answer tests for `bgt signatures`.

Every signature is here because a real bug left it behind, so every test
below carries the line the bug actually produced -- and, just as important,
the line that LOOKS like it and is not, because a sweep that fires on
ordinary code is a sweep nobody reads twice.

Synthetic text only: no game files, no engine, no recovered tree.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tools"))

import bgt_signatures                                        # noqa: E402


def kinds(text):
    """The signatures one snippet fires, as a sorted list with duplicates."""
    return sorted(k for k, _line, _body in bgt_signatures.scan(text))


class MaskingTests(unittest.TestCase):
    def test_a_name_inside_a_string_is_not_code(self):
        """The whole sweep is textual, so a literal has to be blanked first --
        and blanked to the same WIDTH, because the rows report a line."""
        line = 'speak("local_4 = local_4;", true);'
        self.assertEqual(kinds(line), [])
        self.assertEqual(len(bgt_signatures.mask(line)), len(line))

    def test_a_comment_is_not_code(self):
        self.assertEqual(kinds("// local_4 = local_4;"), [])
        self.assertEqual(kinds("local_1 = 2;   // and x = x here"), [])

    def test_an_escaped_quote_does_not_end_the_literal(self):
        """`"\\""` is one literal. Read as two, the rest of the line pairs
        with the wrong partner -- the desynchronisation `bgt apicheck`
        records from `url_get("http://...")`."""
        self.assertEqual(
            kinds(r'if ((a != "x \" y") && (local_4 == local_4)) {'),
            ["tautology"])

    def test_a_comparison_must_be_PARENTHESISED_to_be_seen(self):
        """The narrowness is deliberate and worth stating. The renderer
        parenthesises every comparison it emits, so this reaches what the
        decompiler writes; a comparison passed as a bare argument, which is
        source a person wrote, is not swept at all."""
        self.assertEqual(kinds("speak(x, local_4 == local_4);"), [])
        self.assertEqual(kinds("if ((local_4 == local_4)) {"), ["tautology"])


class SelfIdenticalTests(unittest.TestCase):
    def test_a_collapsed_snapshot_assigns_a_thing_to_itself(self):
        """Psycho Strike's `this.damage = this.damage;` -- a save and a
        restore around something that changes it, folded into a no-op."""
        self.assertEqual(kinds("    this.damage = this.damage;"),
                         ["self_identical"])
        self.assertEqual(kinds("    @local_11 = local_11;"),
                         ["self_identical"])
        self.assertEqual(
            kinds("global_interacts[slot].speech = "
                  "global_interacts[slot].speech;"), ["self_identical"])

    def test_an_ordinary_assignment_is_not_one(self):
        self.assertEqual(kinds("    this.damage = this.max_damage;"), [])
        self.assertEqual(kinds("    local_4 = local_5;"), [])
        self.assertEqual(kinds("    local_4 = local_4 + 1;"), [])
        # A handle marker on one side only still names the same thing.
        self.assertEqual(kinds("    @local_4 = local_4;"), ["self_identical"])

    def test_two_identical_CALLS_are_not_a_tautology(self):
        """`rand() == rand()` is two values, and `f() = f()` does not even
        parse. A call is deliberately outside the path pattern, because
        folding one twice is the duplication audit's business and not this."""
        self.assertEqual(kinds("if (recorder.rand(0, 9) == "
                               "recorder.rand(0, 9)) {"), [])


class TautologyTests(unittest.TestCase):
    def test_a_condition_compared_with_itself(self):
        """Paladin's `if (level == level)` after the loop that raised it, and
        `tts_selector`'s six `if (voice.rate == voice.rate)`."""
        self.assertEqual(kinds("    if (level == level) {"), ["tautology"])
        self.assertEqual(kinds("    if (voice.rate != voice.rate) {"),
                         ["tautology"])
        self.assertEqual(
            kinds("if ((a != \"\") && (p.s[i].name != p.s[i].name)) {"),
            ["tautology"])

    def test_both_halves_of_one_condition_are_reported_once_each(self):
        self.assertEqual(
            kinds("if ((x == x) || (y == y)) {"), ["tautology", "tautology"])

    def test_a_real_comparison_is_not_one(self):
        self.assertEqual(kinds("    if (old_level == level) {"), [])
        self.assertEqual(kinds("    if (bag[i].count == bag[j].count) {"), [])


class EmptyArmTests(unittest.TestCase):
    def test_an_empty_arm_is_a_condition_that_lost_its_value(self):
        self.assertEqual(kinds("    if (local_3 == voice.rate) { }"),
                         ["empty_arm"])
        self.assertEqual(kinds("    if (local_3 == voice.rate) {\n    }\n"),
                         ["empty_arm"])

    def test_two_empty_arms_is_the_stronger_form(self):
        """The `||` chain that emitted half its own condition as a statement
        left `if (stick.get_y() >= -100) { } else { }` behind."""
        self.assertEqual(
            kinds("if (stick.get_y() >= -100) { }\nelse { }\n"),
            ["empty_arm", "two_empty_arms"])
        # ...and written over four lines, which the renderer also does.
        self.assertEqual(
            kinds("if (c) {\n}\nelse {\n}\n"),
            ["empty_arm", "two_empty_arms"])

    def test_an_arm_with_a_body_is_not_one(self):
        self.assertEqual(kinds("    if (c) { speak(x); }"), [])
        self.assertEqual(kinds("    if (c) {\n    speak(x);\n    }\n"), [])


class DoubleAssignTests(unittest.TestCase):
    def test_one_slot_carrying_several_operands(self):
        """`get_percent_of_range` parked all three operands in slot 3, and
        every read rendered the same name: `a0 - a0 * (a0 / 100)`."""
        text = ("local_3 = (arg0 - arg1);\n"
                "local_3 = arg2;\n"
                "return int((double(local_3) - (double(local_3) * "
                "(double(local_3) / 100.0))));\n")
        self.assertIn("double_assign", kinds(text))

    def test_two_assignments_read_once_are_not_one(self):
        """A chained conversion through one scratch string is BGT's own
        idiom -- `control::move_left` is three of them in a row -- and
        reading the result once is exactly right."""
        text = ("local_5 = \"a\";\n"
                "local_5 = this.find_appropriate_character(local_5);\n"
                "this.speak(local_5, true);\n")
        self.assertNotIn("double_assign", kinds(text))

    def test_the_window_is_the_LAST_pair_before_the_read(self):
        """Three assignments and then a double read is one hit, not two: the
        pair that matters is the one the read follows, and an assignment in
        between ends the earlier window. Reporting both would make the count
        depend on how many times the slot had been reused earlier."""
        text = ("local_3 = 1;\n"
                "local_3 = 2;\n"
                "local_3 = 3;\n"
                "f(local_3, local_3);\n")
        rows = [(k, n) for k, n, _b in bgt_signatures.scan(text)]
        self.assertEqual([r for r in rows if r[0] == "double_assign"],
                         [("double_assign", 2)])
        #: ...and this fixture is the `same_argument` shape as well,
        #: which is not a clash: the two are the write side and the call
        #: side of one defect, so a snippet that shows both has both.
        #: `double_assign` fires where the reads are in a statement of
        #: any kind; `same_argument` only where they are ARGUMENTS of
        #: one call, which is what made a safezone's six bounds one
        #: number.
        self.assertEqual([r for r in rows if r[0] == "same_argument"],
                         [("same_argument", 4)])


    def test_a_CHAIN_is_not_two_reads_of_one_value(self):
        """BGT's own idiom, and 81 of this shape's 105 rows across the
        corpus. Each line mentions the name twice -- once as the
        DESTINATION -- so a chain of three or more scored, and `cs`'s server
        alone had forty. Only the right-hand side is a read."""
        text = ('local_1 = string_replace(local_1, "north", "0", true);\n'
                'local_1 = string_replace(local_1, "northeast", "45", true);\n'
                'local_1 = string_replace(local_1, "south", "180", true);\n'
                'local_1 = string_replace(local_1, "west", "270", true);\n')
        self.assertNotIn("double_assign", kinds(text))

    def test_a_collapsed_short_circuit_still_fires(self):
        """What is left after the narrowing, and what the shape is for: one
        slot carrying both operands of an `&&`, with the condition reading
        one of them twice. Paladin's gift eligibility and Psycho Strike's
        `home::reset_rebels` are both this, and `if ((x != 0) && (x != 0))`
        is never what a two-operand `&&` meant."""
        text = ("local_7 = ((local_7 == 0) ? 1 : 0);\n"
                'local_7 = ((for_character == "") ? 1 : 0);\n'
                "local_7 = ((local_7 == 0) ? 1 : 0);\n"
                "if ((local_7 != 0) && (local_7 != 0)) {\n")
        self.assertIn("double_assign", kinds(text))


class IdentityCastTests(unittest.TestCase):
    def test_a_value_converted_twice_and_changed_by_neither(self):
        """`fade(..., double(int(music.get_volume())), ...)` is the snapshot
        of a global that folded into a re-read of it."""
        self.assertEqual(
            kinds("fade(local_5, m.get_volume(), "
                  "double(int(m.get_volume())), 250.0, false);"),
            ["identity_cast"])
        self.assertEqual(kinds("pool.volume_step = "
                               "float(double(pool.volume_step));"),
                         ["identity_cast"])

    def test_a_single_conversion_is_not_one(self):
        self.assertEqual(kinds("local_1 = int(music.get_volume());"), [])
        self.assertEqual(kinds("local_8 = int64(local_1);"), [])


class BareReadTests(unittest.TestCase):
    def test_a_statement_that_only_reads(self):
        """The borrowed handle hoisted out of the guard that protected it:
        `find_walls` indexed before the bounds check and threw on every map
        entry."""
        self.assertEqual(kinds("    arg2[int(local_10)];"), ["bare_read"])
        self.assertEqual(kinds("    this.terrain.width;"), ["bare_read"])

    def test_a_call_a_return_and_a_bare_name_are_not_one(self):
        self.assertEqual(kinds("    this.reset();"), [])
        self.assertEqual(kinds("    return local_4;"), [])
        self.assertEqual(kinds("    break;"), [])
        self.assertEqual(kinds("    local_4;"), [])


class DuplicatedCallTests(unittest.TestCase):
    def test_a_call_run_once_per_read(self):
        """`file_menu` read one menu result four times, so the recovered
        function opened its menu four times -- which is what "it keeps
        putting me in the tts selection menu" looked like from the inside."""
        text = ('if (menu.run_extended("x") == -1 || '
                'menu.run_extended("x") == 0 || '
                'menu.run_extended("x") == -200) { }\n')
        self.assertIn("duplicated_call", kinds(text))

    def test_a_duplication_spread_across_statements_is_not_this_check(self):
        """`file_menu` read one menu result in four separate statements, and
        this is a per-statement sweep, so it does not see that. The
        call-sequence comparison in `bgt libcheck` counts those, and the two
        are complementary rather than overlapping."""
        text = ('if (menu.run("x") == -1) { }\n'
                'if (menu.run("x") == 0) { }\n'
                'return menu.get_item_name(menu.run("x"));\n')
        self.assertNotIn("duplicated_call", kinds(text))

    def test_the_limit_is_three_and_two_is_left_alone(self):
        """Two reads are the ordinary cost of a short-circuit rendered
        without a temporary; this file records three as the threshold the
        duplication work settled on."""
        self.assertEqual(bgt_signatures.DUPLICATION_LIMIT, 3)
        self.assertNotIn("duplicated_call",
                         kinds("if (f(x) == 1 || f(x) == 2) { }"))
        self.assertIn("duplicated_call",
                      kinds("if (f(x) == 1 || f(x) == 2 || f(x) == 3) { }"))

    def test_a_keyword_is_not_a_call(self):
        """`if (`, `while (` and the rest open a paren against an identifier
        and are not calls. Nested blocks closed on one line are not swept
        either, which costs nothing: the renderer never writes them."""
        self.assertEqual(kinds("    while (a) { if (a) { if (a) { } } }"), [])
        self.assertEqual(kinds("    while (f(a) && f(a) && f(a)) {"),
                         ["duplicated_call"])


class SweepTests(unittest.TestCase):
    def _tree(self, files):
        import tempfile
        root = tempfile.mkdtemp(prefix="bgtsig")
        for name, text in files.items():
            path = os.path.join(root, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        return root

    def test_a_stock_library_file_is_not_the_recoverys_text(self):
        """`bgt recover` replaces a run that matches a shipped `include/*.bgt`
        with BGT's own source, so that file's shapes are the engine's. Swept
        by default it would report the library's style as this decompiler's."""
        stock = ("// sound_pool.bgt -- BGT's own copy of this file, from\n"
                 "// C:\\BGT\\include\\sound_pool.bgt\n"
                 "if (y == y) { }\n")
        root = self._tree({"includes/sound_pool.bgt": stock,
                           "includes/classes/own.bgt":
                               "if (level == level) { }\n"})
        counts, rows = bgt_signatures.sweep(root)
        self.assertEqual(counts["tautology"], 1)
        self.assertIn("own.bgt", rows["tautology"][0])
        # ...and `--stock` says so out loud rather than pretending.
        with_stock, _rows = bgt_signatures.sweep(root, stock=True)
        self.assertEqual(with_stock["tautology"], 2)

    def test_a_row_names_the_file_and_the_line(self):
        root = self._tree({"a.bgt": "void f()\n{\nif (x == x) { }\n}\n"})
        _counts, rows = bgt_signatures.sweep(root)
        self.assertEqual(rows["tautology"], ["a.bgt:3  if (x == x) { }"])

    def test_sweeping_nothing_is_not_sweeping_clean(self):
        """A check that cannot run is worse than no check, because it is
        counted: an empty directory exits 1 rather than printing zeroes."""
        import tempfile
        self.assertEqual(bgt_signatures.main([tempfile.mkdtemp()]), 1)

    def test_an_unknown_signature_is_refused_rather_than_ignored(self):
        root = self._tree({"a.bgt": "if (x == x) { }\n"})
        self.assertEqual(bgt_signatures.main([root, "--detail", "nosuch"]), 2)
        self.assertEqual(bgt_signatures.main([root, "--detail", "tautology"]), 0)
        self.assertEqual(bgt_signatures.main([root, "--strict"]), 1)


class SameArgumentTests(unittest.TestCase):
    """One call reading one slot for several of its arguments.

    The compiler builds each argument through one scratch slot and consumes
    it as it goes, so the writes and the uses interleave -- and rendering
    the slot's NAME gives every argument whatever it held last. `cs`'s map
    loader built a safezone whose six bounds are one number, and
    `load_bases` passed a base's three coordinates as its health value.
    """

    SIX = """\
        local_17 = local_13[6];
        local_17 = local_13[5];
        local_17 = local_13[4];
        local_17 = local_13[3];
        local_17 = local_13[2];
        local_17 = local_13[1];
        @local_16 = safezone(stn(local_17), stn(local_17), stn(local_17), stn(local_17), stn(local_17), stn(local_17));
"""

    def test_six_bounds_that_are_one_number(self):
        self.assertIn("same_argument", kinds(self.SIX))

    def test_the_sweep_sees_through_a_RUN_of_conversions(self):
        """`base(double(int(stn(local_16))), ...)` is the shape at issue, and
        a pattern with one level of nesting in it cannot see the call at
        all: written that way this reported 9 rows on that server where
        there are 38, and under-reported the baseline it was measuring."""
        text = ("        local_16 = local_14[0];\n"
                "        local_16 = local_14[1];\n"
                "        local_16 = local_14[2];\n"
                "        @local_24 = base(double(int(stn(local_16))), "
                "double(int(stn(local_16))), double(int(stn(local_16))), "
                "local_26);\n")
        self.assertIn("same_argument", kinds(text))

    def test_passing_one_value_twice_is_not_a_hit_without_the_writes(self):
        """The writes above are what make a repeat a defect rather than the
        author doing it on purpose -- `CapturePapillon::setZone` passes one
        coordinate twice and may well be deliberate."""
        text = ("        local_15 = local_12;\n"
                "        this.terrain.setZone(local_31, local_14, local_15, "
                "local_14, local_15, local_26, true);\n")
        self.assertEqual(kinds(text), [])

    def test_a_single_argument_call_is_not_swept(self):
        text = ("        local_17 = a[1];\n"
                "        local_17 = a[2];\n"
                "        f(stn(local_17));\n")
        self.assertNotIn("same_argument", kinds(text))

    def test_the_fixed_shape_does_not_fire(self):
        """What the decompiler writes now: each value taken into a local of
        its own before the slot is rewritten."""
        text = ("        local_17 = local_13[6];\n"
                "        double __nvgt_held_17_264 = stn(local_17);\n"
                "        local_17 = local_13[5];\n"
                "        double __nvgt_held_17_280 = stn(local_17);\n"
                "        @local_16 = safezone(stn(local_17), "
                "__nvgt_held_17_280, __nvgt_held_17_264);\n")
        self.assertEqual(kinds(text), [])


if __name__ == "__main__":
    unittest.main()
