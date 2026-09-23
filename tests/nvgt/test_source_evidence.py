"""Retained-source metadata must be distinguished from synthesized source."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from asreader import DataType, Function, GlobalProperty, ImportedFunction, Instr, Module, ScriptVariable, TypeInfo, _Reader
from decompile import decompile_module, load_any
from recover import generate_project
from source_evidence import function_evidence, recovery_evidence, source_location

ROOT = Path(__file__).resolve().parent / "fixtures"
HOST = ROOT / "build/bcdump.exe"


class SourceEvidenceTests(unittest.TestCase):
    def test_saved_line_and_column_encoding(self):
        self.assertEqual(source_location((7 << 20) | 23), {"line": 23, "column": 7})
        self.assertIsNone(source_location(0))

    def test_switching_debug_sections_and_names(self):
        function = Function(name="owned", has_debug_info=True, script_section="entry.nvgt",
                            declared_at=(2 << 20) | 10, param_names=["message"],
                            param_types=[DataType(token_type=70)],
                            sections=[4, "library.nvgt", 12, "entry.nvgt"],
                            line_numbers=[0, 11, 4, (3 << 20) | 20, 12, 12],
                            variables=[ScriptVariable(name="count", stack_offset=3,
                                                      declared_at=4, type=DataType(token_type=70))])
        saved = function_evidence(function)
        self.assertEqual([m["section"] for m in saved["source_line_mappings"]],
                         ["entry.nvgt", "library.nvgt", "entry.nvgt"])
        self.assertEqual(saved["saved_parameter_names"], ["message"])
        self.assertEqual(saved["locals"][0]["saved_name"], "count")
        self.assertEqual(saved["locals"][0]["declaration_bytecode_dword"], 4)

    def test_stripped_metadata_does_not_claim_saved_identifiers(self):
        function = Function(name="owned", has_debug_info=False, script_section="not_saved",
                            param_names=["arg0"], declared_at=12,
                            variables=[ScriptVariable(name="local_1", declared_at=3)])
        saved = function_evidence(function)
        self.assertIsNone(saved["saved_source_section"])
        self.assertIsNone(saved["saved_declaration"])
        self.assertEqual(saved["saved_parameter_names"], [])
        self.assertIsNone(saved["locals"][0]["saved_name"])
        self.assertIsNone(saved["locals"][0]["declaration_bytecode_dword"])

    def test_reader_restores_declaration_instruction_number_to_dword(self):
        reader = _Reader(b"")
        function = Function(has_debug_info=True,
                            bytecode=[Instr(0, 0, "SetV4", "asBCTYPE_wW_DW_ARG", 3),
                                      Instr(3, 1, "RET", "asBCTYPE_W_ARG", 1)],
                            variables=[ScriptVariable(name="value", declared_at=1)],
                            obj_variable_info=[(2, 0, 3)])
        reader._translate_function(function, [], lambda index: None)
        self.assertEqual(function.variables[0].declared_at, 3)
        self.assertEqual(function.obj_variable_info[0][0], 4)

    def test_evidence_covers_destructors_initializers_and_deduplicates(self):
        function = Function(name="owned", bytecode=[Instr(0, 0, "RET", "asBCTYPE_W_ARG", 1)])
        module = Module(debug_info=False, script_functions=[function, function],
                        globals=[GlobalProperty(name="g", init_func=function)],
                        classes=[TypeInfo(name="Owned", destructor=function)])
        saved = recovery_evidence(module)
        self.assertEqual(saved["summary"]["function_bodies"], 1)
        self.assertEqual(saved["global_declaration_order"][0]["name"], "g")
        self.assertEqual(saved["summary"]["saved_local_names"], 0)

    def test_constructor_explicit_attribute_survives_rendering(self):
        cls = TypeInfo(name="Owned")
        constructor = Function(name="Owned", return_type=DataType(token_type=82),
                               object_type=cls, param_types=[DataType(token_type=70)],
                               flags_byte=32)
        cls.constructors = [constructor]
        source = decompile_module(Module(classes=[cls]))
        self.assertIn("Owned(int arg0) explicit", source)

    def test_saved_import_directive_is_emitted_with_namespace(self):
        function = Function(name="convert", func_type=5, namespace_="owned",
                            return_type=DataType(token_type=70),
                            param_types=[DataType(token_type=70)])
        module = Module(imported_functions=[ImportedFunction(function, 'owned"module')])
        source = decompile_module(module)
        self.assertIn('namespace owned {', source)
        self.assertIn('import int convert(int) from "owned\\"module";', source)
        saved = recovery_evidence(module)
        self.assertEqual(saved["saved_imports"][0]["module"], 'owned"module')

    @unittest.skipUnless(HOST.exists(), "owned compiler unavailable")
    def test_import_directive_survives_owned_compile_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "owned.as"
            source.write_text('namespace math_api { import int convert(int value) from "calculator"; }\nvoid main() {}\n')
            bytecode = directory / "owned.bin"
            result = subprocess.run([str(HOST), str(source), str(bytecode), "--strip"], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            first = load_any(str(bytecode))
            self.assertEqual(len(first.imported_functions), 1)
            recovered = directory / "recovered.as"
            recovered.write_text(decompile_module(first), encoding="utf-8")
            result = subprocess.run([str(HOST), str(recovered), str(directory / "second.bin"), "--strip"], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            second = load_any(str(directory / "second.bin"))
            self.assertEqual(second.imported_functions[0].module, "calculator")
            self.assertEqual(second.imported_functions[0].signature.signature(False),
                             first.imported_functions[0].signature.signature(False))

    @unittest.skipUnless(HOST.exists(), "owned compiler unavailable")
    def test_debug_project_retains_names_positions_and_declaration_order(self):
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            library = work / "audio_form.as"
            library.write_text('''
int early(int value) { int result = value + 1; return result; }
class Item { int number; Item(int value) explicit { number = value; } }
int late(int value) { return value + 2; }
''', encoding="utf-8")
            source = work / "owned.as"
            source.write_text('#include "audio_form.as"\nvoid main() { Item item(3); print("" + early(item.number) + late(1)); }\n', encoding="utf-8")
            original = subprocess.run([str(HOST), str(source), str(work / "owned.bin"), "--run"],
                                      capture_output=True, text=True, timeout=20)
            self.assertEqual(original.returncode, 0, original.stderr)
            manifest = generate_project(work / "owned.bin", work / "project")
            recovered_library = (work / "project/includes/audio_form.nvgt").read_text(encoding="utf-8")
            self.assertLess(recovered_library.index("int early("), recovered_library.index("class Item"))
            self.assertLess(recovered_library.index("class Item"), recovered_library.index("int late("))
            saved = json.loads((work / "project/source_evidence.json").read_text(encoding="utf-8"))
            early = next(f for f in saved["functions"] if f["signature"].startswith("int early("))
            self.assertEqual(early["saved_parameter_names"], ["value"])
            self.assertTrue(any(v["saved_name"] == "result" for v in early["locals"]))
            self.assertEqual(early["saved_declaration"]["line"], 2)
            self.assertTrue(saved["summary"]["source_line_mappings"])
            self.assertEqual(manifest["source_evidence"]["file"], "source_evidence.json")
            self.assertEqual(manifest["source_compilation"], "not_checked")
            recovered = subprocess.run([str(HOST), str(work / "project/main.nvgt"), str(work / "second.bin"), "--run"],
                                       capture_output=True, text=True, timeout=20)
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertEqual(recovered.stdout, original.stdout)
            with zipfile.ZipFile(work / "project/source.zip") as archive:
                self.assertIn("source_evidence.json", archive.namelist())


if __name__ == "__main__":
    unittest.main()
