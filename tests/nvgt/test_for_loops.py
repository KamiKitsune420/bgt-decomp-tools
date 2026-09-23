"""`_reconstruct_for_loops` turns a rotated while back into a for, but only where
that is behaviour-preserving. These are synthetic line lists -- no compiler."""
import unittest

from decompile import _reconstruct_for_loops as fold


def run(*lines):
    return fold(list(lines))


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
