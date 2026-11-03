"""`bgt drive` -- the probe it writes, and the project it must put back.

The run itself needs BGT, so what is pinned here is everything that happens
either side of it: finding the entry, finding `main` wherever it really is,
rendering the probe, reading the table back, and -- the one that matters --
restoring the file it had to edit even when the run raises.

Every case is a synthetic project. No game files, as this repository requires.
"""

import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tools"))

import bgt_drive  # noqa: E402

ENTRY = '''// a recovered project's entry script
#include "includes/types.bgt"
#include "includes/functions/part_0.bgt"
'''

PART0 = '''bool k_ctrl(const int arg0 = 0)
{
\treturn key_down(KEY_LCONTROL);
}

void main()
{
\tk_ctrl(0);
}
'''


def project(root):
    """A project shaped like one `bgt recover` writes."""
    os.makedirs(os.path.join(root, "includes", "functions"), exist_ok=True)
    with open(os.path.join(root, "game.bgt"), "w", encoding="utf-8") as fh:
        fh.write(ENTRY)
    with open(os.path.join(root, "includes", "types.bgt"), "w",
              encoding="utf-8") as fh:
        fh.write("// no enums\n")
    with open(os.path.join(root, "includes", "functions", "part_0.bgt"), "w",
              encoding="utf-8") as fh:
        fh.write(PART0)
    return root


class FindingTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.root = project(self.tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_the_entry_is_the_script_that_includes_others(self):
        self.assertEqual(os.path.basename(bgt_drive.find_entry(self.root)),
                         "game.bgt")

    def test_main_is_NOT_in_the_entry_and_is_found_anyway(self):
        """`main` is one of the game's own global functions, so `bgt recover`
        writes it into `includes/functions/part_0.bgt`. A driver that looked
        only at the script it was handed -- which is what `stage` does, rightly,
        for a compile-only check -- would leave the game's `main` in place and
        hand the compiler two of them."""
        with open(bgt_drive.find_entry(self.root), encoding="utf-8") as fh:
            self.assertNotIn("void main()", fh.read())
        found = bgt_drive.find_main(self.root)
        self.assertIsNotNone(found)
        self.assertEqual(os.path.basename(found), "part_0.bgt")

    def test_a_project_with_no_main_is_reported_rather_than_refused(self):
        path = os.path.join(self.root, "includes", "functions", "part_0.bgt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("bool k_ctrl(const int arg0 = 0) { return true; }\n")
        self.assertIsNone(bgt_drive.find_main(self.root))

    def test_the_probe_is_never_mistaken_for_the_entry(self):
        """Everything this writes carries a reserved prefix, so a second run
        cannot pick up the first run's probe as the project's entry."""
        with open(os.path.join(self.root, bgt_drive.PREFIX + "probe.bgt"),
                  "w", encoding="utf-8") as fh:
            fh.write('#include "game.bgt"\nvoid main() {}\n')
        self.assertEqual(os.path.basename(bgt_drive.find_entry(self.root)),
                         "game.bgt")
        self.assertEqual(
            os.path.basename(bgt_drive.find_main(self.root)), "part_0.bgt")


class ProbeTests(unittest.TestCase):
    def source(self, **kw):
        kw.setdefault("watch", ["k_ctrl(0)"])
        return bgt_drive.probe_source("game.bgt", **kw)

    def test_it_includes_the_entry_by_its_bare_name(self):
        """The probe sits beside the entry, so the include is a bare name and
        nothing has to be repointed -- which is also why it can reach the
        game's data: BGT resolves a pack path against the script too."""
        self.assertIn('#include "game.bgt"', self.source())

    def test_it_silences_the_engine_before_anything_else(self):
        text = self.source()
        self.assertIn("set_sound_master_volume(-100.0)", text)
        self.assertLess(text.index("set_sound_master_volume"),
                        text.index("force_key_down")
                        if "force_key_down" in text else len(text))

    def test_it_opens_NO_window(self):
        """A window is an outcome to `bgt_compile.check`, which kills the
        process to report it -- so a probe that opened one was killed before
        it could write its table. A forced key needs no window: asked
        directly, a script with none answers `down=1 pressed=1`."""
        self.assertNotIn("show_game_window", self.source())

    def test_a_held_key_is_forced_and_released(self):
        text = self.source(hold=["KEY_LCONTROL"])
        self.assertIn("force_key_down(KEY_LCONTROL);", text)
        self.assertIn("reset_all_forced_keys();", text)

    def test_every_watch_becomes_one_column(self):
        text = self.source(watch=["a()", "b.c", "d[0]"])
        self.assertIn('"ms\\ta()\\tb.c\\td[0]\\n"', text)
        for expr in ("a()", "b.c", "d[0]"):
            self.assertIn('string(%s)' % expr, text)

    def test_a_watch_is_sampled_through_string_which_the_engine_HAS(self):
        """All five of `string(bool)`, `string(int)`, `string(double)`,
        `"" + bool` and `"x" + int` were put to the compiler before this
        picked one. `string()` is the one that works for every type."""
        self.assertIn("string(k_ctrl(0))", self.source())

    def test_a_statement_gets_its_semicolon_once(self):
        self.assertIn("\t\tstep();", self.source(call=["step()"]))
        self.assertIn("\t\tstep();", self.source(call=["step();"]))
        self.assertNotIn("step();;", self.source(call=["step();"]))

    def test_everything_it_declares_carries_the_reserved_prefix(self):
        """A recovered project declares thousands of names, so one collision
        would be a compiler error blamed on the recovery."""
        import re
        text = self.source(hold=["KEY_UP"])
        for decl in re.findall(r"(?:file|timer|double)\s+(\w+)", text):
            self.assertTrue(decl.startswith(bgt_drive.PREFIX), decl)


class ResultsTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "t.tsv")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, text):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_a_row_per_tick_keyed_by_the_watched_expression(self):
        self.write("ms\tk_ctrl(0)\tk_ctrl(1)\n0\t1\t0\n100\t1\t1\n")
        rows = bgt_drive.read_results(self.path)
        self.assertEqual([r["ms"] for r in rows], ["0", "100"])
        self.assertEqual([r["k_ctrl(1)"] for r in rows], ["0", "1"])

    def test_a_missing_or_empty_table_is_no_rows_rather_than_a_raise(self):
        self.assertEqual(bgt_drive.read_results(self.path + ".nope"), [])
        self.write("")
        self.assertEqual(bgt_drive.read_results(self.path), [])
        self.write("ms\tk_ctrl(0)\n")
        self.assertEqual(bgt_drive.read_results(self.path), [])


class RestoreTests(unittest.TestCase):
    """The project must come back exactly as it was, however the run ends.

    A run that left a project with no `main`, or with `main` renamed, would
    look exactly like a broken recovery -- and the next thing anybody would do
    is blame the decompiler.
    """

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.root = project(self.tmp)
        self.main = os.path.join(self.root, "includes", "functions",
                                 "part_0.bgt")
        with open(self.main, encoding="utf-8") as fh:
            self.before = fh.read()
        self.saved = bgt_drive.bgt_compile.check

    def tearDown(self):
        import shutil
        bgt_drive.bgt_compile.check = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_with(self, fake):
        bgt_drive.bgt_compile.check = fake
        return bgt_drive.drive(self.root, ["k_ctrl(0)"], duration=10)

    def current(self):
        with open(self.main, encoding="utf-8") as fh:
            return fh.read()

    def leftovers(self):
        found = []
        for root, _dirs, files in os.walk(self.root):
            found += [f for f in files if f.startswith(bgt_drive.PREFIX)
                      or bgt_drive.PREFIX in f]
        return sorted(found)

    def test_main_is_renamed_for_the_run_and_the_probe_is_there(self):
        seen = {}

        def fake(script, **kw):
            seen["main"] = self.current()
            seen["probe"] = os.path.isfile(script)
            return _ok()

        self.run_with(fake)
        self.assertIn("void %s()" % bgt_drive.RENAMED_MAIN, seen["main"])
        self.assertNotIn("void main()", seen["main"])
        self.assertTrue(seen["probe"])

    def test_the_file_is_restored_and_nothing_is_left_behind(self):
        self.run_with(lambda script, **kw: _ok())
        self.assertEqual(self.current(), self.before)
        self.assertEqual(self.leftovers(), [])

    def test_it_is_restored_even_when_the_RUN_RAISES(self):
        def boom(script, **kw):
            raise RuntimeError("the compiler went away")

        with self.assertRaises(RuntimeError):
            self.run_with(boom)
        self.assertEqual(self.current(), self.before)
        self.assertEqual(self.leftovers(), [])

    def test_a_previous_run_s_table_can_never_be_read_as_this_one_s(self):
        """A stale report read as a fresh one is the trap `bgt oracle` records
        paying for: it reads as a pass."""
        stale = os.path.join(self.root, bgt_drive.RESULTS)
        with open(stale, "w", encoding="utf-8") as fh:
            fh.write("ms\tk_ctrl(0)\n0\t1\n")
        out = self.run_with(lambda script, **kw: _ok())
        self.assertEqual(out["rows"], [])


class ScenarioTests(unittest.TestCase):
    def test_every_scenario_says_what_it_expects_and_why(self):
        for name, canned in bgt_drive.SCENARIOS.items():
            self.assertTrue(canned.get("watch"), name)
            self.assertTrue(canned.get("why"), name)
            self.assertTrue(canned.get("expect"), name)
            for col in canned["expect"]:
                self.assertIn(col, canned["watch"], name)

    def test_a_bool_is_expected_as_1_because_that_is_what_the_engine_WRITES(self):
        """`string(true)` is `1`, not `true` -- asked of the engine rather
        than assumed. A scenario expecting the word would have reported a
        correct recovery as wrong, which is the shape this project keeps
        recording."""
        for name, canned in bgt_drive.SCENARIOS.items():
            for col, want in canned["expect"].items():
                self.assertIn(want, ("0", "1"), "%s/%s" % (name, col))


class WatchNamesTests(unittest.TestCase):
    """A watch is looked up in the table by the name the header gave it.

    The header is a BGT string literal, and it used to REPLACE every `"`
    with `'` so the literal would close -- while the summary looked the
    column up by the expression as typed. So every watch containing a quote
    reported `never changed:` with nothing after it.

    `get_string_size("hello")` is how it surfaced: the recovered function is
    correct and answers `5 B`, and the tool said it answered nothing, which
    reads as a defect in the recovery.
    """

    def test_a_quote_is_escaped_rather_than_replaced(self):
        expr = 'get_string_size("hello")'
        self.assertEqual(bgt_drive.column(expr), expr)
        self.assertEqual(bgt_drive._literal(bgt_drive.column(expr)),
                         'get_string_size(\\"hello\\")')

    def test_the_header_and_the_lookup_are_one_function(self):
        """Two places answering one question is what went wrong, so the
        source has to call `column` for the header and for the lookup."""
        source = inspect.getsource(bgt_drive)
        self.assertIn("_literal(column(w))", source)
        self.assertIn("r.get(column(col)", source)

    def test_the_probe_emits_the_expression_and_the_header_together(self):
        source = bgt_drive.probe_source("game.bgt", ['"abc"', "1+1"])
        header = next(l for l in source.splitlines() if "ms\\t" in l)
        self.assertIn('\\"abc\\"', header)
        self.assertIn('string("abc")', source)

    def test_a_tab_cannot_survive_in_a_column_name(self):
        """The table is tab-separated, so a tab in the name would split the
        column -- and it has to go on BOTH sides or the lookup misses again."""
        self.assertEqual(bgt_drive.column('f("a\tb")'), 'f("a b")')


def _ok():
    class R(object):
        outcome, errors, raw, title = "compiled", [], "", None
    return R()


if __name__ == "__main__":
    unittest.main(verbosity=2)
