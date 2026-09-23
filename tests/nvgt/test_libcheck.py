"""libcheck's own logic, on synthetic inputs -- no nvgt.exe needed.

The full check (`bgt nvgt libcheck`) takes minutes against a real NVGT and is
run as a command, not a unit test. What is pinned here is what could make it
report the wrong number quietly: an include that cannot be built counted as a
decompiler failure, or a failure counted as a pass.
"""
import unittest
from pathlib import Path

import libcheck


class LibcheckTests(unittest.TestCase):
    def test_first_error_prefers_the_error_line(self):
        text = ("Compilation error: file: C:/nvgt/include/logger.nvgt\n"
                "line: 74 (2)\nINFO: Compiling string logger::parse_time()\n"
                "ERROR: No matching symbol 'string_trim_left'\n")
        self.assertEqual(libcheck.first_error(text),
                         "ERROR: No matching symbol 'string_trim_left'")
        self.assertEqual(libcheck.first_error("just this\n"), "just this")
        self.assertEqual(libcheck.first_error(""), "")

    def test_harness_includes_by_absolute_forward_slash_path(self):
        text = libcheck.HARNESS.format(include=Path("C:/nvgt/include/menu.nvgt").as_posix())
        self.assertIn('#include "C:/nvgt/include/menu.nvgt"', text)
        self.assertIn("get_bytecode(false)", text)      # debug build
        self.assertIn("get_bytecode(true)", text)       # stripped build

    def test_broken_includes_are_reported_but_not_scored(self):
        rows = [
            {"name": "menu", "kind": "debug", "compile": "passed"},
            {"name": "menu", "kind": "strip", "compile": "failed",
             "decompiler_errors": 2, "gotos": 1},
            {"name": "logger", "kind": "-", "compile": "include-broken"},
        ]
        text = libcheck.summary(rows)
        self.assertIn("1 / 2 library modules recompile", text)
        self.assertIn("debug  1 / 1", text)
        self.assertIn("strip  0 / 1", text)
        self.assertIn("decompiler errors 2, unhandled opcodes 0, gotos 1", text)
        self.assertIn("not scored (include does not compile as shipped): logger", text)

    def test_missing_compiler_or_include_folder_is_a_usage_error(self):
        # Whichever is missing on this machine, the answer is exit 2 and a
        # message -- never a traceback, never a score over nothing.
        self.assertEqual(libcheck.main(["--include", "Z:/no/such/include"]), 2)


if __name__ == "__main__":
    unittest.main()
