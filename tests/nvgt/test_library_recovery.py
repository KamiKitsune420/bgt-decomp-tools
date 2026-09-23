"""Library reuse must reject changed code rather than match names alone."""
import copy
import os
from pathlib import Path
import unittest
import tempfile

from decompile import load_any
from library_recovery import (plan_reuse, compile_reference, normalized_function,
                             detect_includes)
from asreader import DataType, Function, Instr, TypeInfo

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

    def test_property_load_type_id_normalizes_across_modules(self):
        # LoadThisR / LoadRObjR / LoadVObjR / ADDSi / ADDProp carry the
        # property's type as a usedTypeIds index in dw_arg. It is module-
        # relative, so the same source built twice gives different indices;
        # left raw it rejected almost every class (every this-property load).
        # asreader resolves it to a DataType, which must normalize equal.
        def program(name, index):
            ins = Instr(0, 0, name, "asBCTYPE_rW_DW_ARG", 2, w_arg=5, dw_arg=index,
                        prop_name="widget.value", data_type=DataType(token_type=67))
            return Function(name="probe", bytecode=[ins])
        for name in ("LoadThisR", "LoadRObjR", "LoadVObjR", "ADDSi", "ADDProp"):
            self.assertEqual(normalized_function(program(name, 3)),
                             normalized_function(program(name, 11)), name)
        # a genuinely different property type must still differ
        a = program("LoadThisR", 3)
        b = program("LoadThisR", 3); b.bytecode[0].data_type = DataType(token_type=70)
        self.assertNotEqual(normalized_function(a), normalized_function(b))

    def test_ref_copy_handle_type_normalizes_across_modules(self):
        # RefCpyV is PSF + REFCPY fused and carries a usedTypes index in qw_arg
        # (the handle type). Raw, it rejected every class that assigns a handle.
        def program(index):
            ins = Instr(0, 0, "RefCpyV", "asBCTYPE_wW_QW_ARG", 3, w_arg=8, qw_arg=index,
                        type_ref=TypeInfo(name="sound"))
            return Function(name="probe", bytecode=[ins])
        self.assertEqual(normalized_function(program(2)), normalized_function(program(9)))
        other = program(2); other.bytecode[0].type_ref = TypeInfo(name="timer")
        self.assertNotEqual(normalized_function(program(2)), normalized_function(other))

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


@unittest.skipUnless(COMPILER and INCLUDES and COMPILER.exists() and INCLUDES.is_dir(),
                     "set NVGT_COMPILER and NVGT_INCLUDE for the auto-include reuse check")
class AutoIncludeReuseTests(unittest.TestCase):
    """A target built with MORE than the file being reused must still confirm
    and reuse it. The extra file shifts the shared file's type tables, which is
    exactly what the un-normalized property/handle type indices used to reject.

    Built only through compile_reference (the proven runtime-export path), so
    it does not run arbitrary game code under the test harness. stat_set.nvgt
    and size.nvgt are used because they declare classes and property loads but
    pull in no audio or TTS, which would block a run under the test harness.
    """

    def test_auto_detect_names_every_library_file_present(self):
        with tempfile.TemporaryDirectory() as directory:
            target, _, _ = compile_reference(
                str(COMPILER), ["stat_set.nvgt", "size.nvgt"], str(INCLUDES),
                directory, reference_mode="runtime")
            detected = detect_includes(target, str(INCLUDES))
            self.assertIn("stat_set.nvgt", detected)
            self.assertIn("size.nvgt", detected)

    def test_reuse_confirms_a_file_whose_type_indices_were_shifted(self):
        with tempfile.TemporaryDirectory() as directory:
            # size.nvgt in the target adds types, so stat_set.nvgt's classes get
            # different usedTypeIds indices than in a stat_set-only reference --
            # the exact shift the property/handle type-id fix has to survive.
            target, _, _ = compile_reference(
                str(COMPILER), ["stat_set.nvgt", "size.nvgt"], str(INCLUDES),
                str(Path(directory) / "t"), reference_mode="runtime")
            reference, hashes, harness = compile_reference(
                str(COMPILER), ["stat_set.nvgt"], str(INCLUDES),
                str(Path(directory) / "r"), reference_mode="runtime")
            plan = plan_reuse(target, reference, ["stat_set.nvgt"], str(INCLUDES),
                              hashes, [harness])
            self.assertEqual(plan.conflicts, [])
            self.assertTrue(plan.safe_to_reuse)
            self.assertGreaterEqual(len(plan.matched["classes"]), 2)


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
