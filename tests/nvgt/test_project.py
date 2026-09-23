"""Project export must preserve compilation and execution across include files."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from recover import browser, check_compilation, declaration_units, generate_project, generate_archive, source_name

ROOT = Path(__file__).resolve().parent / "fixtures"
HOST = ROOT / "build/bcdump.exe"


class ProjectTests(unittest.TestCase):
    def test_readable_filenames_handle_reserved_names_and_collisions(self):
        used = set()
        self.assertEqual(source_name("audio_form", used), "audioform")
        self.assertEqual(source_name("AudioForm", used), "audioform_2")
        self.assertEqual(source_name("CON", used), "con_source")
        self.assertNotIn("/", source_name("../NUL", used))
    def test_declaration_boundaries_ignore_strings_and_comments(self):
        text = 'string label = "}; //";\nvoid f() {\n /* } */ print("{");\n}\nint n = 3;\n'
        units = list(declaration_units(text))
        self.assertEqual(len(units), 3)
        self.assertIn('print("{")', units[1])

    def test_offline_browser_escapes_script_closing_text(self):
        result = browser({"example.nvgt": 'string text = "</script>";'}, "Test")
        self.assertEqual(result.count("</script>"), 1)
        self.assertIn("split('\\n')", result)

    def test_optional_compiler_check_records_status_without_retaining_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            compiler = folder / "owned_compiler.py"
            compiler.write_text('''import pathlib, sys
assert sys.argv[-2] == "-c"
source = pathlib.Path(sys.argv[-1]).read_text(encoding="utf-8")
pathlib.Path("compiled.zip").write_bytes(b"owned artifact")
if "FAIL" in source:
    print("ERROR: owned compile failure")
    sys.exit(7)
print("owned compile success")
print(pathlib.Path(sys.argv[-1]).as_posix())
''', encoding="utf-8")
            command = [sys.executable, str(compiler)]
            passed, report = check_compilation({"main.nvgt": "void main() {}"}, command)
            self.assertEqual(passed["status"], "passed")
            self.assertEqual(passed["error_lines"], 0)
            self.assertIn("owned compile success", report)
            self.assertIn("<temporary-project>/main.nvgt", report)
            self.assertNotIn("nvgt_compile_", report)
            failed, report = check_compilation({"main.nvgt": "FAIL"}, command)
            self.assertEqual((failed["status"], failed["exit_code"], failed["error_lines"]),
                             ("failed", 7, 1))
            self.assertIn("ERROR: owned compile failure", report)
            self.assertFalse((folder / "compiled.zip").exists())

    @unittest.skipUnless(HOST.exists(), "bcdump unavailable")
    def test_exported_includes_compile_and_preserve_behavior(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
            folder = Path(folder)
            original = folder / "owned.as"
            original.write_text('''
class Counter { int n; Counter(int start) { n = start; } void tick() { n++; } }
int starting = 4;
string label = "}; // still a string";
int twice(int n) { return n * 2; }
void main() { Counter@ c = Counter(starting); c.tick(); print(label + ":" + twice(c.n)); }
''', encoding="utf-8")
            first = subprocess.run([str(HOST), str(original), str(original.with_suffix(".bin")),
                                    "--strip", "--run"], capture_output=True, text=True, timeout=20)
            self.assertEqual(first.returncode, 0, first.stderr)
            output = folder / "project"
            manifest = generate_project(original.with_suffix(".bin"), output, target_lines=5)
            self.assertEqual(manifest["input"], "owned.bin")
            self.assertNotIn(str(folder), (output / "manifest.json").read_text(encoding="utf-8"))
            second = subprocess.run([str(HOST), str(output / "main.nvgt"), str(folder / "second.bin"),
                                     "--strip", "--run"], capture_output=True, text=True, timeout=20)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(second.stdout, first.stdout)
            self.assertGreater(len(manifest["source_files"]), 3)
            check_script = folder / "check.py"
            check_script.write_text('import sys; print("checked", sys.argv[-1])\n', encoding="utf-8")
            checked = generate_project(original.with_suffix(".bin"), folder / "checked",
                                       compiler=[sys.executable, str(check_script)])
            self.assertEqual(checked["source_compilation"], "passed")
            self.assertEqual(checked["compile_check"]["error_lines"], 0)
            self.assertFalse((folder / "checked/main.zip").exists())
            self.assertIn("checked", (folder / "checked/compile-report.txt").read_text(encoding="utf-8"))
            with zipfile.ZipFile(folder / "checked/source.zip") as archive:
                self.assertIn("compile-report.txt", archive.namelist())
                self.assertEqual(json.loads(archive.read("manifest.json"))["source_compilation"], "passed")
            unchecked = generate_project(original.with_suffix(".bin"), folder / "checked")
            self.assertEqual(unchecked["source_compilation"], "not_checked")
            self.assertFalse((folder / "checked/compile-report.txt").exists())
            with zipfile.ZipFile(folder / "checked/source.zip") as archive:
                self.assertNotIn("compile-report.txt", archive.namelist())
            with zipfile.ZipFile(output / "source.zip") as archive:
                self.assertIn("main.nvgt", archive.namelist())
                self.assertIn("browse.html", archive.namelist())
            # Same inputs can be exported again, while manual edits survive.
            generate_project(original.with_suffix(".bin"), output, target_lines=5)
            # An exporter update can regroup its own unchanged generated files.
            generate_project(original.with_suffix(".bin"), output, target_lines=6)
            entry = output / "main.nvgt"
            entry.write_text("// user edit\n", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                generate_project(original.with_suffix(".bin"), output, target_lines=5)
            self.assertEqual(entry.read_text(), "// user edit\n")
            archive_path = folder / "owned-source.zip"
            generate_archive(original.with_suffix(".bin"), archive_path, target_lines=5)
            self.assertEqual(list(folder.glob("nvgt_recovery_*")), [])
            with zipfile.ZipFile(archive_path) as archive:
                self.assertIn("includes/counter.nvgt", archive.namelist())
            before = archive_path.read_bytes()
            with self.assertRaises(FileExistsError):
                generate_archive(original.with_suffix(".bin"), archive_path)
            self.assertEqual(archive_path.read_bytes(), before)

            # Debug builds retain section filenames even after folder splitting.
            debug_bytecode = folder / "debug.bin"
            compiled = subprocess.run([str(HOST), str(original), str(debug_bytecode)],
                                      capture_output=True, text=True, timeout=20)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            debug_project = folder / "debug_project"
            debug_manifest = generate_project(debug_bytecode, debug_project)
            self.assertTrue(debug_manifest["script_section_paths"])
            self.assertTrue((debug_project / "includes/owned.nvgt").exists())
            executed = subprocess.run([str(HOST), str(debug_project / "main.nvgt"), str(folder / "debug_again.bin"),
                                       "--run"], capture_output=True, text=True, timeout=20)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            self.assertEqual(executed.stdout, first.stdout)


if __name__ == "__main__":
    unittest.main()
