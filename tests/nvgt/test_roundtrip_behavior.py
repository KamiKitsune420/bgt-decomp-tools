"""Decompiled source must behave like the original, not merely compile.

fixtures/decompiler_patterns.nvgt is a script written for this test. Run under
a real NVGT it exports its own module -- `get_bytecode(false)` with debug
information, `get_bytecode(true)` stripped -- and writes the value it computed.
Each bytecode is decompiled into a project, the project is run, and it has to
write the SAME value.

Compiling is the weaker check, and the reason this test exists: three of the
bugs its fixture pins compiled cleanly and computed something else --

* `@h.item = b` was dropped (REFCPY into a member had no case), so the handle
  stayed null;
* `if (!d.get("item", @fetched))` printed the copy out of `fetched` BEFORE
  the call that fills it;
* `d.set("item", @b)` lost its `@`, and a `?&in` then stores a copy of the
  object rather than a handle to it.

A second fixture, control_flow_patterns.nvgt, covers loops, switch, bitwise
arithmetic (including `>>` vs `>>>`, which once differed), arrays, dictionaries
and argument evaluation order -- the same round-trip, a different corner of the
language.

Needs NVGT_COMPILER (an nvgt.exe); skips otherwise.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import recover

FIXTURES = Path(__file__).resolve().parent / "fixtures"
COMPILER = Path(os.environ["NVGT_COMPILER"]) if os.environ.get("NVGT_COMPILER") else None


def _run(script: Path) -> str:
    """Run a script with NVGT in its own folder; return what it wrote.

    A script exception -- a null handle, the usual symptom of a mistranslated
    handle operation -- makes NVGT show a modal alert and wait, so a run that
    does not finish promptly is reported as that rather than waited out. The
    fixture itself finishes in a second or two.
    """
    try:
        result = subprocess.run([str(COMPILER), script.name], cwd=script.parent,
                                capture_output=True, text=True, errors="replace",
                                timeout=45)
    except subprocess.TimeoutExpired:
        raise AssertionError(f"{script} did not finish: most likely a script "
                             "exception, which NVGT reports in a modal dialog") from None
    if result.returncode != 0:
        raise AssertionError(f"{script} failed ({result.returncode}):\n"
                             f"{result.stdout}{result.stderr}")
    return (script.parent / "result.txt").read_text(encoding="utf-8")


@unittest.skipUnless(COMPILER and COMPILER.exists(),
                     "set NVGT_COMPILER to an nvgt.exe for behavioural round-trips")
class _BehaviourFixture(unittest.TestCase):
    """Compile the fixture, run it, then require each decompiled build -- debug
    and stripped -- to run to the same value. Subclasses name the fixture."""
    FIXTURE = None                          # set by each subclass

    @classmethod
    def setUpClass(cls):
        if cls is _BehaviourFixture:
            raise unittest.SkipTest("base class")
        cls.work = Path(tempfile.mkdtemp(prefix="nvgt_behaviour_"))
        original = cls.work / "original"
        original.mkdir()
        fixture = FIXTURES / cls.FIXTURE
        shutil.copy(fixture, original / fixture.name)
        cls.expected = _run(original / fixture.name)
        cls.bytecode = {kind: original / f"{kind}.bin" for kind in ("debug", "strip")}

    @classmethod
    def tearDownClass(cls):
        if cls is not _BehaviourFixture:
            shutil.rmtree(cls.work, ignore_errors=True)

    def _decompiled(self, kind: str) -> Path:
        project = self.work / f"recovered_{kind}"
        manifest = recover.generate_project(str(self.bytecode[kind]), project,
                                            compiler=str(COMPILER))
        self.assertEqual(manifest["source_compilation"], "passed",
                         (project / "compile-report.txt").read_text(errors="replace")
                         if (project / "compile-report.txt").exists() else manifest)
        return project

    def test_debug_build_behaves_identically(self):
        self.assertEqual(_run(self._decompiled("debug") / "main.nvgt"), self.expected)

    def test_stripped_build_behaves_identically(self):
        self.assertEqual(_run(self._decompiled("strip") / "main.nvgt"), self.expected)


class DecompiledBehaviourTests(_BehaviourFixture):
    FIXTURE = "decompiler_patterns.nvgt"

    def test_fixture_computes_its_documented_value(self):
        # Derived by hand, so the reference itself is checked rather than
        # trusted. handles(): weight 3, touched to 4 through the stored
        # handle -> opConv 4, heavier() 9, fetched.weight 4, secret 6 ->
        # 4946. main(): paint 1 + 2, mixed_slots 1 + 25, describe() 2 after
        # polish(), "x".length() 1 -> 4978. A copy stored by set() would
        # leave fetched.weight at 3; a lost `@h.item = b` returns -1.
        self.assertEqual(self.expected, "4978")

    def test_stripped_build_behaves_identically(self):
        project = self._decompiled("strip")
        self.assertEqual(_run(project / "main.nvgt"), self.expected)
        source = "\n".join(p.read_text(encoding="utf-8")
                           for p in project.rglob("*.nvgt"))
        # The shapes behind each fix, stated directly so a failure says which.
        self.assertRegex(source, r"@local_\d+\.item = local_\d+;")
        self.assertRegex(source, r'\.set\("item", @local_\d+\)')
        self.assertRegex(source, r"bool __nvgt_ret_\d+ = local_\d+\.get\(")
        self.assertIn("cast<sword@>(", source)
        self.assertRegex(source, r"\? 1 : 0\)")          # bool stored in a float slot


class ControlFlowBehaviourTests(_BehaviourFixture):
    FIXTURE = "control_flow_patterns.nvgt"

    def test_fixture_computes_its_documented_value(self):
        # loops 3125; classify 7+20+99; bit_math incl. -8>>1 (logical,
        # 2147483644) and -8>>>1 (arithmetic, -4); collections; order 12411;
        # strings 11019 -- summed in an int64 that wraps to this exact value.
        # Pinned so a fixture edit that changes coverage is noticed.
        self.assertEqual(self.expected, "-2147468510")

    def test_stripped_build_keeps_the_two_shift_operators_apart(self):
        # The one that most easily regresses: `>>` is logical, `>>>` arithmetic.
        project = self._decompiled("strip")
        source = "\n".join(p.read_text(encoding="utf-8")
                           for p in project.rglob("*.nvgt"))
        self.assertIn("2147483644", source)     # -8 >> 1, the logical result
        self.assertIn("-4", source)             # -8 >>> 1, the arithmetic result


class TernaryExpressionTests(_BehaviourFixture):
    FIXTURE = "ternary_expression.nvgt"

    def test_stripped_build_keeps_the_ternary_inside_the_expression(self):
        # The bug: `10 + (c ? 3 : 7)` came back as `10 + 7` with an empty if.
        project = self._decompiled("strip")
        source = "\n".join(p.read_text(encoding="utf-8")
                           for p in project.rglob("*.nvgt"))
        # a ternary is still written as one, inside an arithmetic expression
        self.assertRegex(source, r"\+ \(.*\? .* : .*\)")


class ShortCircuitTests(_BehaviourFixture):
    FIXTURE = "short_circuit.nvgt"

    def test_stripped_build_keeps_both_operands_of_a_stored_short_circuit(self):
        # The bug: `bool b = (x>0) && (x<10)` used later dropped the first
        # operand -- `(x<10) ? ...`. Both operands must survive.
        project = self._decompiled("strip")
        source = "\n".join(p.read_text(encoding="utf-8")
                           for p in project.rglob("*.nvgt"))
        self.assertRegex(source, r"\(arg0 > 0\) && \(arg0 < 10\)")   # in_ternary
        self.assertRegex(source, r"\(arg0 > 0\) \|\| \(arg1 > 0\)")  # in_if


class ReusedLoopVariableTests(_BehaviourFixture):
    FIXTURE = "reused_loop_variable.nvgt"

    def test_debug_build_declares_the_reused_counter_once(self):
        # The bug: `for (int i) {} for (uint i) {}` on reused slots hoisted a
        # declaration for the slot's LAST name only, leaving two typed `i`
        # declarations at one scope. The debug project must recompile, and its
        # counter must be declared exactly once.
        project = self._decompiled("debug")
        body = "\n".join(p.read_text(encoding="utf-8") for p in project.rglob("*.nvgt"))
        self.assertEqual(len(re.findall(r"^\s*u?int i;", body, re.M)), 1, body)


if __name__ == "__main__":
    unittest.main()
