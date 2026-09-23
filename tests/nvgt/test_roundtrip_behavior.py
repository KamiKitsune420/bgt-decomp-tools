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

Needs NVGT_COMPILER (an nvgt.exe); skips otherwise.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import recover

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "decompiler_patterns.nvgt"
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
class DecompiledBehaviourTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix="nvgt_behaviour_"))
        original = cls.work / "original"
        original.mkdir()
        shutil.copy(FIXTURE, original / FIXTURE.name)
        cls.expected = _run(original / FIXTURE.name)
        cls.bytecode = {kind: original / f"{kind}.bin" for kind in ("debug", "strip")}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def _decompiled(self, kind: str) -> Path:
        project = self.work / f"recovered_{kind}"
        manifest = recover.generate_project(str(self.bytecode[kind]), project,
                                            compiler=str(COMPILER))
        self.assertEqual(manifest["source_compilation"], "passed",
                         (project / "compile-report.txt").read_text(errors="replace")
                         if (project / "compile-report.txt").exists() else manifest)
        return project

    def test_fixture_computes_its_documented_value(self):
        # Derived by hand, so the reference itself is checked rather than
        # trusted. handles(): weight 3, touched to 4 through the stored
        # handle -> opConv 4, heavier() 9, fetched.weight 4, secret 6 ->
        # 4946. main(): paint 1 + 2, mixed_slots 1 + 25, describe() 2 after
        # polish(), "x".length() 1 -> 4978. A copy stored by set() would
        # leave fetched.weight at 3; a lost `@h.item = b` returns -1.
        self.assertEqual(self.expected, "4978")

    def test_debug_build_behaves_identically(self):
        self.assertEqual(_run(self._decompiled("debug") / "main.nvgt"), self.expected)

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


if __name__ == "__main__":
    unittest.main()
