"""Run with python -m unittest -v test_regressions."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import struct

import extract
from inspect_exe import identity, pe_imports
from asreader import _Stream
from decompile import load_any, decompile_module
from test_support import owned_pe_stub

ROOT = Path(__file__).resolve().parent / "fixtures"


class ExtractionTests(unittest.TestCase):
    def test_release_encryption_inverse_with_different_payload_lengths(self):
        for data in (b"a", bytes(range(256)) * 20, b"owned diagnostic module" * 300):
            payload = extract.encrypt_official(data)
            self.assertEqual(len(payload) % 16, 0)
            self.assertEqual(extract.decrypt_official(payload), data)

    def test_nine_byte_signed_integer_encoding(self):
        value = 0x123456789ABCDE
        for prefix, expected in ((0x7F, value), (0xFF, (-value) & ((1 << 64) - 1))):
            reader = _Stream(bytes([prefix]) + value.to_bytes(8, "big") + b"\x2a")
            self.assertEqual(reader.read_encoded_uint64(), expected)
            self.assertEqual(reader.u8(), 42)

    def test_engine_identity_literal_evidence(self):
        commit = "0123456789abcdef" * 2 + "01234567"
        date = "Tuesday, September 15, 2026 at 12:58:27 PM Türkiye Standart Saati"
        data = b"\0" + commit.encode() + b"\0" + date.encode("cp1252") + b"\0"
        data += b"0.10.2\0" + b"0.90.0-dev\0"
        report = identity(data)
        self.assertEqual(report["version"], "0.90.0-dev")
        self.assertEqual(report["commit_candidates"][0]["value"], commit)
        self.assertEqual(report["build_time_candidates"][0]["value"], date)
        self.assertEqual(data[report["commit_candidates"][0]["offset"]:41], commit.encode())
        self.assertIsNone(identity(data + b"0.91.0-dev\0")["version"])

    def test_pe_import_directory(self):
        imports = pe_imports(owned_pe_stub())
        self.assertIn("KERNEL32.dll", imports)
        self.assertEqual(pe_imports(b"not a PE"), [])

    def test_plugin_and_namespace_preamble(self):
        encode = extract.Reader.varint_bytes
        def string(value):
            data = value.encode("utf-8")
            return encode(len(data)) + data
        # A multi-byte length checks both the codec and preamble alignment.
        plugin = "p" * 140
        properties = list(range(extract.NUM_ENGINE_PROPERTIES))
        stream = (struct.pack("<H", 2) + string("legacy_sound") + string(plugin)
                  + struct.pack("<i", 1) + string("sound") + string("upcoming")
                  + b"".join(map(encode, properties)) + struct.pack("<qB", 123456, 1)
                  + b"bytecode marker")
        info = extract.split_stream(stream)
        self.assertEqual(info.plugins, ["legacy_sound", plugin])
        self.assertEqual(info.namespaces, [("sound", "upcoming")])
        self.assertEqual(info.engine_properties, properties)
        self.assertEqual(info.timestamp, 123456)
        self.assertEqual(info.no_auto_chdir, 1)
        self.assertEqual(info.bytecode, b"bytecode marker")

    def test_captured_release_key(self):
        key, iv = extract.official_key_iv(128)
        self.assertEqual(key.hex(), "37a5f29e0834648b1215cca9e6028d010232e9031695dce61c30d1b05e1169f6")
        self.assertEqual(iv.hex(), "f36755c35adc8ebf760ebb32ffa1a00d")

    def test_release_fixtures(self):
        if not all((ROOT / (name + ".exe")).exists() for name in ("dbgtest", "test_real", "BopIt")):
            self.skipTest("optional local executable fixtures unavailable")
        for name, size in (("dbgtest", 65), ("test_real", 1102), ("BopIt", 183997)):
            with self.subTest(name=name):
                info, stream = extract.extract(ROOT / (name + ".exe"))
                self.assertEqual(len(info.bytecode), size)
                self.assertEqual(info.plugins, [])
                self.assertGreater(len(stream), size)
        source = decompile_module(load_any(str(ROOT / "dbgtest.exe")))
        self.assertIn("wait(600000);", source)

    def test_repository_package(self):
        stub = owned_pe_stub()
        stream = b"test stream" * 100
        packaged = extract.package(stub, stream)
        self.assertEqual(extract.decrypt(extract.get_payload(packaged)), stream)

    def test_corrupted_release_rejected(self):
        payload = extract.encrypt_official(b"owned corrupt-payload fixture")
        damaged = payload[:-1] + bytes([payload[-1] ^ 1])
        with self.assertRaises(ValueError):
            extract.decrypt(damaged)


class RendererTests(unittest.TestCase):
    def test_bopit_reader(self):
        if not (ROOT / "BopIt.exe").exists():
            self.skipTest("optional BopIt executable unavailable")
        module = load_any(str(ROOT / "BopIt.exe"))
        self.assertEqual(len(module.classes), 17)
        self.assertEqual(len(module.enums), 6)
        self.assertEqual(module.enums[0].enum_values[:3],
                         [("clipboard_flag_copy", 1), ("clipboard_flag_cut", 2), ("clipboard_flag_paste", 4)])
        self.assertTrue(any(c.is_interface for c in module.classes))
        self.assertTrue(any(c.is_shared for c in module.classes))
        self.assertTrue(module.funcdefs)

    def test_bopit_core_vm_operations_are_lifted(self):
        if not (ROOT / "BopIt.exe").exists():
            self.skipTest("optional BopIt executable unavailable")
        source = decompile_module(load_any(str(ROOT / "BopIt.exe")))
        for opcode in ("WRTV1", "CmpPtr", "LDG", "LoadRObjR", "LoadVObjR",
                       "CallPtr", "DECi", "COPY"):
            self.assertNotIn(f"// {opcode} (unhandled)", source)

    def test_debug_corpus_recompiles(self):
        compiler = ROOT / "build/bcdump.exe"
        if not compiler.exists():
            self.skipTest("bcdump test compiler unavailable")
        # These are the original eight debug-enabled fixtures, not release output.
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
            for name in ("arg", "calls", "copy", "def", "hello", "min", "patterns", "real", "str"):
                with self.subTest(name=name):
                    bytecode = Path(folder) / f"original_{name}.bin"
                    first = subprocess.run([str(compiler), str(ROOT / f"test_{name}.as"), str(bytecode)],
                                           capture_output=True, text=True, timeout=30)
                    self.assertEqual(first.returncode, 0, first.stderr)
                    source = decompile_module(load_any(str(bytecode)))
                    path = Path(folder) / (name + ".as")
                    path.write_text(source, encoding="utf-8")
                    result = subprocess.run([str(compiler), str(path), str(path.with_suffix(".bin"))],
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_stripped_control_flow_and_recompile(self):
        compiler = ROOT / "build/bcdump.exe"
        if not compiler.exists():
            self.skipTest("bcdump test compiler unavailable")
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
            bytecode = Path(folder) / "original.bin"
            first = subprocess.run([str(compiler), str(ROOT / "test_real.as"), str(bytecode), "--strip"],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr)
            source = decompile_module(load_any(str(bytecode)))
            self.assertIn("bool alive() const", source)
            self.assertIn("return (health > 0);", source)
            self.assertIn("while (local_1.alive() && (local_5 < 10))", source)
            path = Path(folder) / "stripped.as"
            path.write_text(source, encoding="utf-8")
            result = subprocess.run([str(compiler), str(path), str(path.with_suffix(".bin"))],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_official_stripped_fixture_recompiles(self):
        if not (ROOT / "test_real.exe").exists() or not (ROOT / "build/bcdump.exe").exists():
            self.skipTest("optional official fixture/compiler unavailable")
        source = decompile_module(load_any(str(ROOT / "test_real.exe")))
        self.assertNotIn("tmp26", source)
        compiler = ROOT / "build/bcdump.exe"
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
            path = Path(folder) / "official.as"
            path.write_text(source, encoding="utf-8")
            result = subprocess.run([str(compiler), str(path), str(path.with_suffix(".bin"))],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
