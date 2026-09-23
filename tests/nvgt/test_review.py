"""Portable review regressions using only synthetic data and owned programs."""
import errno
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import extract
import recover
from asreader import DataType, Function, Module, ReaderError, _Stream, unwrap_bytecode
from decompile import decompile_module
from inspect_exe import pe_imports
import keyscan
from test_support import owned_pe_stub

ROOT = Path(__file__).resolve().parent / "fixtures"
TOOLS = Path(__file__).resolve().parents[2] / "tools" / "nvgt"


class ReaderValidationTests(unittest.TestCase):
    def test_truncated_integer_reads_are_value_errors_and_preserve_position(self):
        for method, size in (("u8", 1), ("u16", 2), ("u32", 4), ("i32", 4), ("i64", 8)):
            for length in range(size):
                with self.subTest(method=method, length=length):
                    reader = extract.Reader(bytes(length))
                    with self.assertRaises(ValueError):
                        getattr(reader, method)()
                    self.assertEqual(reader.pos, 0)
        with self.assertRaises(ValueError):
            extract.Reader(b"", -1)

    def test_negative_reads_and_out_of_range_varints(self):
        for reader in (extract.Reader(b"abc"), _Stream(b"abc")):
            with self.assertRaises(ValueError):
                (reader.raw if hasattr(reader, "raw") else reader.read)(-1)
            self.assertEqual(reader.pos, 0)
        for value in (-1, 1 << 32):
            with self.assertRaises(ValueError):
                extract.Reader.varint_bytes(value)
        for value in (0, 127, 128, 0xffffffff):
            self.assertEqual(extract.Reader(extract.Reader.varint_bytes(value)).varint(), value)
        for data in (b"\x80", b"\xff" * 5, b"\x80" * 20):
            with self.assertRaises(ValueError):
                extract.Reader(data).varint()

    def test_negative_namespace_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "namespace count"):
            extract.split_stream(bytes(2) + struct.pack("<i", -1) + bytes(50))

    def test_malformed_pe_headers_and_imports_are_rejected(self):
        for data in (b"MZ", b"MZ" + bytes(62), owned_pe_stub()[:450], owned_pe_stub()[:-1]):
            with self.assertRaises(ValueError):
                extract.payload_offset(data)
            with self.assertRaises(ValueError):
                pe_imports(data)
        damaged = bytearray(owned_pe_stub())
        struct.pack_into("<I", damaged, 524, 999999)
        with self.assertRaisesRegex(ValueError, "RVA"):
            pe_imports(damaged)

    def test_asbc_container_rejects_version_size_and_truncated_header(self):
        raw = b"owned bytes"
        self.assertEqual(unwrap_bytecode(raw), raw)
        self.assertEqual(unwrap_bytecode(b"ASBC" + struct.pack("<II", 1, len(raw)) + raw), raw)
        for data in (b"ASBC", b"ASBC" + bytes(7),
                     b"ASBC" + struct.pack("<II", 2, 0),
                     b"ASBC" + struct.pack("<II", 1, 99) + raw):
            with self.assertRaises(ReaderError):
                unwrap_bytecode(data)

    def test_duplicate_function_tables_render_once(self):
        function = Function(name="owned", return_type=DataType(token_type=82))
        module = Module(script_functions=[function, function], global_functions=[function, function])
        self.assertEqual(decompile_module(module).count("void owned()"), 1)


class CommandLineTests(unittest.TestCase):
    def test_corrupt_bytecode_has_clear_cli_error(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "broken.bin"
            source.write_bytes(b"ASBC")
            result = subprocess.run([sys.executable, "-B", str(TOOLS / "decompile.py"), str(source)],
                                    capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("truncated ASBC header", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_extract_refuses_replacing_payload_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"keep input unchanged")
            import contextlib
            import io
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                extract.main(["--payload", str(source)])
            self.assertEqual(source.read_bytes(), b"keep input unchanged")


class OpcodeGeneratorTests(unittest.TestCase):
    def test_explicit_header_and_both_pointer_widths(self):
        import runpy
        import sys
        entries = []
        for slot in range(256):
            if slot == 0:
                entry = "asBCINFO(PopPtr, NO_ARG, -AS_PTR_SIZE)"
            elif slot == 1:
                entry = "asBCINFO(OwnedHex, NO_ARG, 0xFFFF)"
            elif slot == 200:
                entry = "asBCINFO(Thiscall1, DW_ARG, -AS_PTR_SIZE-1)"
            elif slot in (254, 255):
                entry = "asBCINFO(" + ("LINE" if slot == 254 else "LABEL") + ", INFO, 0)"
            else:
                entry = f"asBCINFO_DUMMY({slot})"
            entries.append(entry)
        header_text = ("enum asEBCInstr { asBC_MAXBYTECODE = 201 };\n"
                       "enum asEBCType {\nasBCTYPE_INFO,\nasBCTYPE_NO_ARG,\nasBCTYPE_DW_ARG\n};\n"
                       "const int asBCTypeSize[24] = {" + ",".join(map(str, [0,1,2] + [0]*21)) + "};\n"
                       "const asSBCInfo asBCInfo[256] = {" + ",\n".join(entries) + "};\n")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            header = directory / "angelscript.h"
            header.write_text(header_text)
            for bits in (32, 64):
                output = directory / f"opcodes{bits}.py"
                command = [sys.executable, "-B", str(TOOLS / "gen_opcodes.py"),
                           "--header", str(header), "--output", str(output)]
                if bits == 32:
                    command.append("--32")
                result = subprocess.run(command, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                table = runpy.run_path(str(output))["OPCODES"]
                self.assertEqual(table[1][3], 0xffff)
                self.assertEqual(table[0][3], -1 if bits == 32 else -2)
                self.assertEqual(table[200][3], -2 if bits == 32 else -3)


class ArchivePublicationTests(unittest.TestCase):
    @staticmethod
    def export(input_path, output, *args):
        with zipfile.ZipFile(Path(output) / "source.zip", "w") as archive:
            archive.writestr("main.nvgt", "void main() {}")
        return {"source_files": []}

    def test_competing_writer_is_preserved_and_scratch_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source.zip"
            def competitor(source, destination):
                Path(destination).write_bytes(b"another writer")
                raise FileExistsError(destination)
            with patch.object(recover, "generate_project", self.export), patch.object(recover.os, "link", competitor):
                with self.assertRaises(FileExistsError):
                    recover.generate_archive("unused", archive)
            self.assertEqual(archive.read_bytes(), b"another writer")
            self.assertEqual(list(Path(directory).glob("nvgt_recovery_*")), [])

    def test_unsupported_hardlinks_use_exclusive_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source.zip"
            with patch.object(recover, "generate_project", self.export), patch.object(recover.os, "link", side_effect=OSError(errno.EPERM, "unsupported")):
                recover.generate_archive("unused", archive)
            with zipfile.ZipFile(archive) as exported:
                self.assertIsNone(exported.testzip())
                self.assertIn("main.nvgt", exported.namelist())

    def test_interrupted_fallback_removes_incomplete_output(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source.zip"
            def interrupted(source, destination):
                destination.write(b"partial")
                raise OSError("disk full")
            with patch.object(recover, "generate_project", self.export), patch.object(recover.os, "link", side_effect=OSError(errno.EPERM, "unsupported")), patch.object(recover.shutil, "copyfileobj", interrupted):
                with self.assertRaisesRegex(OSError, "disk full"):
                    recover.generate_archive("unused", archive)
            self.assertFalse(archive.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])


class ArchiveRefinementTests(unittest.TestCase):
    def test_rename_preserves_existing_file_and_debug_mapping(self):
        import json
        from refine_source_archive import refine
        sources = {
            "main.nvgt": '#include "includes/audioform.nvgt"\n#include "includes/classes/class_audio_form.nvgt"\n',
            "includes/audioform.nvgt": "void retained() {}\n",
            "includes/classes/class_audio_form.nvgt": "class audio_form {}\n",
        }
        manifest = {"source_files": [
            {"path": path, "sha256": hashlib.sha256(text.encode()).hexdigest()}
            for path, text in sources.items()],
            "script_section_paths": [{"original": "owned.nvgt", "recovered": "includes/classes/class_audio_form.nvgt"}]}
        text = json.dumps(manifest)
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.zip"
            destination = Path(directory) / "refined.zip"
            with zipfile.ZipFile(original, "w") as archive:
                for path, content in sources.items(): archive.writestr(path, content)
                archive.writestr("README.md", "owned archive")
                archive.writestr("manifest.json", text)
                archive.writestr("manifest.sha256", hashlib.sha256(text.encode()).hexdigest())
            before = original.read_bytes()
            refine(original, destination)
            self.assertEqual(original.read_bytes(), before)
            with zipfile.ZipFile(destination) as archive:
                self.assertEqual(archive.read("includes/audioform.nvgt").decode(), sources["includes/audioform.nvgt"])
                self.assertEqual(archive.read("includes/audioform_2.nvgt").decode(), "class audio_form {}\n")
                saved = json.loads(archive.read("manifest.json"))
                self.assertEqual(saved["script_section_paths"][0]["recovered"], "includes/audioform_2.nvgt")
                self.assertIn(b'"includes/audioform_2.nvgt"', archive.read("main.nvgt"))
            saved_bytes = destination.read_bytes()
            with self.assertRaises(FileExistsError): refine(original, destination)
            self.assertEqual(destination.read_bytes(), saved_bytes)


# Independent byte-oriented expansion, anchored to the AES-256 test vector.
def owned_aes_schedule():
    words = [bytes(range(i, i + 4)) for i in range(0, 32, 4)]
    for i in range(8, 60):
        previous = words[-1]
        if i % 8 == 0:
            previous = previous[1:] + previous[:1]
        if i % 8 in (0, 4):
            previous = bytes(keyscan.SBOX[b] for b in previous)
        if i % 8 == 0:
            previous = bytes([previous[0] ^ keyscan.RCON[i // 8 - 1]]) + previous[1:]
        words.append(bytes(a ^ b for a, b in zip(words[i - 8], previous)))
    return b"".join(words)


class DiagnosticScannerTests(unittest.TestCase):
    def test_aes256_schedule_math_and_corruption(self):
        data = owned_aes_schedule()
        self.assertEqual(data[32:48].hex(), "a573c29fa176c498a97fce93a572c09c")
        self.assertEqual(data[-16:].hex(), "24fc79ccbf0979e9371ac23c6d68de36")
        self.assertTrue(keyscan.validate_full(list(struct.unpack("<60I", data))))
        damaged = bytearray(data)
        damaged[153] ^= 1
        self.assertFalse(keyscan.validate_full(list(struct.unpack("<60I", damaged))))
        self.assertFalse(keyscan.validate_full([]))

    @unittest.skipUnless(importlib.util.find_spec("numpy"), "optional NumPy unavailable")
    def test_scan_every_alignment_and_chunk_boundary(self):
        data = owned_aes_schedule()
        key = bytes(range(32))
        for prefix in (0, 1, 2, 3, 31, 32, 33, 63):
            fixture = bytes(prefix) + data + bytes(7)
            self.assertEqual(list(keyscan.find_schedules(fixture, chunk_size=32)), [(prefix, key)])
        self.assertEqual(list(keyscan.find_schedules(bytes(239))), [])


@unittest.skipUnless((ROOT / "build/bcdump.exe").exists(), "owned compiler unavailable")
class ExportHashTests(unittest.TestCase):
    def test_hashes_match_disk_bytes_when_regrouping(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "owned.as"
            source.write_text("int a() { return 1; }\nint b() { return 2; }\nvoid main() {}\n")
            bytecode = directory / "owned.bin"
            result = subprocess.run([str(ROOT / "build/bcdump.exe"), str(source), str(bytecode), "--strip"], capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            project = directory / "project"
            first = recover.generate_project(bytecode, project, target_lines=1)
            for path, digest in first["generated_file_hashes"].items():
                self.assertEqual(hashlib.sha256((project / path).read_bytes()).hexdigest(), digest)
            second = recover.generate_project(bytecode, project, target_lines=800)
            self.assertLess(len(second["source_files"]), len(first["source_files"]))


if __name__ == "__main__":
    unittest.main()
