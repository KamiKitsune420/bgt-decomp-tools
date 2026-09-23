"""Library reuse must reject changed code rather than match names alone."""
import copy
import os
from pathlib import Path
import unittest
import tempfile

from decompile import load_any
from library_recovery import plan_reuse, compile_reference, normalized_function
from asreader import DataType, Function, Instr

ROOT = Path(__file__).resolve().parent / "fixtures"
PROBE = Path(os.environ["NVGT_LIBRARY_PROBE"]) if os.environ.get("NVGT_LIBRARY_PROBE") else None
TARGET = Path(os.environ["NVGT_BOPIT_EXE"]) if os.environ.get("NVGT_BOPIT_EXE") else None
COMPILER = Path(os.environ["NVGT_COMPILER"]) if os.environ.get("NVGT_COMPILER") else None
INCLUDES = Path(os.environ["NVGT_INCLUDE"]) if os.environ.get("NVGT_INCLUDE") else None


class ReferenceMetadataTests(unittest.TestCase):
    def test_type_id_indices_normalize_to_datatypes(self):
        def program(index, token):
            instruction = Instr(0, 0, "TYPEID", "asBCTYPE_DW_ARG", 2, dw_arg=index,
                                data_type=DataType(token_type=token))
            return Function(name="probe", bytecode=[instruction])
        self.assertEqual(normalized_function(program(1, 67)), normalized_function(program(9, 67)))
        self.assertNotEqual(normalized_function(program(1, 67)), normalized_function(program(1, 70)))

    @unittest.skipUnless(COMPILER and INCLUDES and COMPILER.exists() and INCLUDES.is_dir(),
                         "set NVGT_COMPILER and NVGT_INCLUDE for optional compiler checks")
    def test_owned_reference_exports_raw_debug_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            module, hashes, harness = compile_reference(str(COMPILER), ["size.nvgt"],
                str(INCLUDES), directory, reference_mode="runtime")
            self.assertTrue(module.debug_info)
            self.assertTrue(module.entry_point().bytecode)
            self.assertTrue(hashes)
            self.assertGreater(harness.with_suffix(".bin").stat().st_size, 0)


@unittest.skipUnless(PROBE and TARGET and INCLUDES and PROBE.exists() and TARGET.exists() and INCLUDES.is_dir(),
                     "set NVGT_LIBRARY_PROBE, NVGT_BOPIT_EXE and NVGT_INCLUDE for optional probe checks")
class LibraryRecoveryTests(unittest.TestCase):
    def test_all_standard_library_entities_match(self):
        target = load_any(str(TARGET))
        reference = load_any(str(PROBE))
        plan = plan_reuse(target, reference, ["menu.nvgt"], str(INCLUDES),
                          {"snapshot": "test"},
                          [PROBE.with_suffix(".nvgt")])
        self.assertFalse(plan.conflicts)
        self.assertEqual(len(plan.matched["classes"]), 17)
        self.assertEqual(len(plan.matched["globals"]), 84)

    def test_changed_function_rejects_reuse(self):
        target = load_any(str(TARGET))
        reference = load_any(str(PROBE))
        original = next(f for f in reference.script_functions if f.bytecode
                        and f.name != "main")
        candidate = next(f for f in target.script_functions
                         if f.signature(False) == original.signature(False))
        candidate.bytecode = list(candidate.bytecode)
        candidate.bytecode[0] = copy.copy(candidate.bytecode[0])
        candidate.bytecode[0].w_arg ^= 1
        plan = plan_reuse(target, reference, ["menu.nvgt"], str(INCLUDES),
                          {"snapshot": "test"}, [PROBE.with_suffix(".nvgt")])
        self.assertFalse(plan.safe_to_reuse)
        self.assertTrue(any("changed" in conflict for conflict in plan.conflicts))


if __name__ == "__main__":
    unittest.main()
