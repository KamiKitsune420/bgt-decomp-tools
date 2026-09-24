"""`_reconstruct_for_loops` turns a rotated while back into a for, and
`_use_compound_assignment` turns `x = (x + y)` into `x += y` -- both only where
behaviour is preserved. These are synthetic line lists -- no compiler."""
import unittest

from decompile import _reconstruct_for_loops as fold
from decompile import _use_compound_assignment as compound
from decompile import _drop_redundant_parens as unparen
from decompile import _encloses
from decompile import _negate_cond, _atomic


class NegationTests(unittest.TestCase):
    def test_atomic(self):
        for s in ("active", "getf(x)", "a.b[i]", "int64(i)", "arr[f(x)]"):
            self.assertTrue(_atomic(s), s)
        for s in ("a && b", "a == b", "a ? b : c", "a + b"):
            self.assertFalse(_atomic(s), s)

    def test_negation_drops_parens_around_a_single_term(self):
        self.assertEqual(_negate_cond("active"), "!active")
        self.assertEqual(_negate_cond("getf(x)"), "!getf(x)")
        self.assertEqual(_negate_cond("a && b"), "!(a && b)")

    def test_double_negation_cancels_either_form(self):
        self.assertEqual(_negate_cond("!active"), "active")
        self.assertEqual(_negate_cond("!(a && b)"), "a && b")

    def test_comparison_is_flipped_not_wrapped(self):
        self.assertEqual(_negate_cond("(a == b)"), "(a != b)")
        self.assertEqual(_negate_cond("(x < 6)"), "(x >= 6)")


def run(*lines):
    return fold(list(lines))


class RedundantParenTests(unittest.TestCase):
    def test_encloses_only_a_single_outer_pair(self):
        self.assertTrue(_encloses("(a + b)"))
        self.assertTrue(_encloses("(f(x))"))
        self.assertFalse(_encloses("(a) + (b)"))     # first ( closes mid-way
        self.assertFalse(_encloses("a + b"))
        self.assertTrue(_encloses('("x)y")'))        # the ) is inside a string

    def one(self, line):
        return unparen([line])[0].strip()

    def test_return_value(self):
        self.assertEqual(self.one("    return (x);"), "return x;")
        self.assertEqual(self.one("    return (sound_play((a + b), c));"),
                         "return sound_play((a + b), c);")
        self.assertEqual(self.one("    return (a) + (b);"), "return (a) + (b);")

    def test_branch_and_loop_conditions(self):
        self.assertEqual(self.one("    if ((x < 6)) {"), "if (x < 6) {")
        self.assertEqual(self.one("    if ((a) && (b)) {"), "if ((a) && (b)) {")
        self.assertEqual(self.one("    while ((m())) {"), "while (m()) {")
        self.assertEqual(self.one("    } while ((k < 3));"), "} while (k < 3);")

    def test_for_condition(self):
        self.assertEqual(self.one("    for (i = 0; (i < 6); i++) {"),
                         "for (i = 0; i < 6; i++) {")

    def test_a_paren_inside_a_string_is_never_removed(self):
        self.assertEqual(self.one('    return ")";'), 'return ")";')


class CompoundAssignmentTests(unittest.TestCase):
    def one(self, line):
        return compound([line])[0].strip()

    def test_increment_and_decrement(self):
        self.assertEqual(self.one("    i = (i + 1);"), "i++;")
        self.assertEqual(self.one("    i = (i - 1);"), "i--;")

    def test_compound_operators(self):
        self.assertEqual(self.one("    total = (total + v);"), "total += v;")
        self.assertEqual(self.one("    x = (x * 2);"), "x *= 2;")
        self.assertEqual(self.one("    flags = (flags | 4);"), "flags |= 4;")

    def test_member_and_index_lvalues(self):
        self.assertEqual(self.one("    this.c_form[v2].caption = (this.c_form[v2].caption + 1);"),
                         "this.c_form[v2].caption++;")

    def test_not_self_referential_is_left_alone(self):
        self.assertEqual(self.one("    a = (b + c);"), "a = (b + c);")

    def test_a_call_in_the_lvalue_is_left_alone(self):
        # arr[f()] would be evaluated once as `++` but twice as written; a call
        # there could have a side effect, so it is never folded.
        line = "    arr[f()] = (arr[f()] + 1);"
        self.assertEqual(self.one(line), line.strip())

    def test_no_binary_operator_is_left_alone(self):
        self.assertEqual(self.one("    x = (y);"), "x = (y);")


class ForLoopTests(unittest.TestCase):
    def test_basic_while_becomes_for(self):
        self.assertEqual(
            run("    i = 0;", "    while (i < 6) {", "        f(i);",
                "        i = (i + 1);", "    }"),
            ["    for (i = 0; (i < 6); i = (i + 1)) {", "        f(i);", "    }"])

    def test_declaration_init_is_kept(self):
        self.assertEqual(
            run("    int n = 0;", "    while (n < 10) {", "        s += n;",
                "        n = (n + 1);", "    }"),
            ["    for (int n = 0; (n < 10); n = (n + 1)) {", "        s += n;", "    }"])

    def test_continue_blocks_the_rewrite(self):
        # continue skips the increment in a while but runs it in a for, so the
        # rewrite would change behaviour -- inline and braced forms both blocked.
        for guarded in ("        if (x) continue;", "        if (x) { continue; }"):
            lines = ["    i = 0;", "    while (i < 6) {", guarded,
                     "        i = (i + 1);", "    }"]
            self.assertEqual(run(*lines), lines)

    def test_infinite_loop_is_left_alone(self):
        lines = ["    while (true) {", "        f();", "    }"]
        self.assertEqual(run(*lines), lines)

    def test_increment_must_be_the_last_statement(self):
        lines = ["    i = 0;", "    while (i < 6) {", "        i = (i + 1);",
                 "        f();", "    }"]
        self.assertEqual(run(*lines), lines)

    def test_condition_must_test_the_init_variable(self):
        # the loop counts on `i` but the condition tests something else
        lines = ["    i = 0;", "    while (done < 6) {", "        f();",
                 "        i = (i + 1);", "    }"]
        self.assertEqual(run(*lines), lines)

    def test_brace_in_initializer_does_not_confuse_the_matcher(self):
        out = run("    i = 0;", "    while (i < 6) {", "        dictionary d = {{1, 2}};",
                  "        i = (i + 1);", "    }")
        self.assertEqual(out[0].strip(), "for (i = 0; (i < 6); i = (i + 1)) {")
        self.assertIn("        dictionary d = {{1, 2}};", out)

    def test_nested_loop_both_convert(self):
        out = run("    i = 0;", "    while (i < 3) {",
                  "        j = 0;", "        while (j < 3) {", "            f(i, j);",
                  "            j = (j + 1);", "        }",
                  "        i = (i + 1);", "    }")
        self.assertIn("    for (i = 0; (i < 3); i = (i + 1)) {", out)
        self.assertIn("        for (j = 0; (j < 3); j = (j + 1)) {", out)

    def test_compound_increment_operators(self):
        for incr in ("i += 2", "i++", "i = (i * 2)"):
            out = run("    i = 1;", "    while (i < 100) {", "        f(i);",
                      f"        {incr};", "    }")
            self.assertEqual(out[0].strip(), f"for (i = 1; (i < 100); {incr}) {{")


if __name__ == "__main__":
    unittest.main()
