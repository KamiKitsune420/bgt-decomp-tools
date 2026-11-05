"""Owned bytecode checks for pre-versioned NVGT packaging and AngelScript."""
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from Crypto.Cipher import AES
import hashlib
from test_support import owned_pe_stub

import extract
from asreader import _Reader, Function, read_module

ROOT = Path(__file__).resolve().parent / "fixtures"

# A complete owned enum module, with 32-bit flags and no underlying token.
OWNED_ENUM_MODULE = (
    b"\x01\x01\x08Mode" + (1 << 26).to_bytes(4, "big") +
    b"\x04\x00\x02\x06off\x00\x00\x00\x00\x04on\x00\x00\x00\x01" + b"\x00" * 13)


def legacy_payload(stream: bytes) -> bytes:
    """Package a stream the way the pre-versioned loader expects it.

    That loader restores the first zlib header byte after decrypting, so the
    packaged first byte is deliberately not 0x78.
    """
    compressed = zlib.compress(stream)
    plain = b"\x65" + compressed[1:]
    padding = 16 - len(plain) % 16
    plain += bytes([padding]) * padding
    size = len(plain)
    key = hashlib.sha256(f"error {size}".encode()).digest()
    iv = bytes(key[2 * i + 1] ^ (9 * i + 1) for i in range(16))
    return AES.new(key, AES.MODE_CBC, iv).encrypt(plain)


class LegacyTests(unittest.TestCase):
    def test_fixed_width_packaging_restores_zlib_header(self):
        stream = OWNED_ENUM_MODULE
        module = read_module(stream)
        self.assertEqual(module.enums[0].enum_values, [("off", 0), ("on", 1)])
        self.assertEqual(module.bytecode_profile, "legacy_32bit_flags")
        encrypted = legacy_payload(stream)
        stub = owned_pe_stub()
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "owned.exe"
            target.write_bytes(
                stub + struct.pack("<I", len(encrypted) ^ 0xA5B4) + encrypted)
            info, recovered = extract.extract(target)
            self.assertEqual(recovered, stream)
            self.assertEqual(info.bytecode, stream)
        with self.assertRaises(ValueError):
            extract.decrypt_legacy(encrypted[:-1] + bytes([encrypted[-1] ^ 1]))
        with self.assertRaises(Exception):
            read_module(stream + b"unexpected trailing bytes")

    def test_fixed_width_size_field_is_found_past_a_prefix(self):
        """The size field is not always exactly at the last section's end.

        Crazy Party beta82 prefixes the appended block with an embedded-pack
        count and one spare byte, putting the field at +2; reading it only at
        the section end reported that whole game as a build of neither
        engine. The decrypt is self-verifying -- AES, then the pad byte, then
        a COMPLETE zlib stream -- so trialling offsets cannot accept a wrong
        one, which the negative case here pins.
        """
        stream = OWNED_ENUM_MODULE
        encrypted = legacy_payload(stream)
        stub = owned_pe_stub()
        prefix = b"\x00\x00"        # a varint pack count of 0, and a spare byte
        size_field = struct.pack("<I", len(encrypted) ^ 0xA5B4)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "owned.exe"
            target.write_bytes(stub + prefix + size_field + encrypted)
            info, recovered = extract.extract(target)
            self.assertEqual(recovered, stream)
            self.assertEqual(info.packaging_profile, "legacy_fixed_size_a5b4")

            # A payload whose last block is corrupt must still be refused, so
            # the offset search cannot turn an unknown build into a guess.
            bad = Path(folder) / "bad.exe"
            bad.write_bytes(stub + prefix + size_field +
                            encrypted[:-1] + bytes([encrypted[-1] ^ 1]))
            with self.assertRaises(ValueError):
                extract.extract(bad)

    def test_legacy_call_operands_do_not_consume_next_instruction(self):
        data = b"\x03\x40\x00\x00\x3d\x01\xb0\x04"
        reader = _Reader(data, legacy=True)
        function = Function()
        reader._read_bytecode(function)
        self.assertEqual(reader.s.pos, len(data))
        self.assertEqual([i.name for i in function.bytecode],
                         ["ALLOC", "CALLSYS", "CallPtr"])
        self.assertEqual(function.bytecode[1].dw_arg, 1)
        self.assertEqual(function.bytecode[2].w_arg2, 4)
        self.assertEqual([i.pos for i in function.bytecode], [0, 4, 6])


if __name__ == "__main__":
    unittest.main()
