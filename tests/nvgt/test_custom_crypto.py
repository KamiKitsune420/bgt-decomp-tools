"""Owned PE fixtures for executable-bound, authenticated custom NVGT packaging."""
import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

import custom_crypto as crypto
import extract

ROOT = Path(__file__).resolve().parent / "fixtures"


def owned_stub():
    header = bytearray(512)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 128)
    header[128:132] = b"PE\0\0"
    struct.pack_into("<H", header, 134, 1)
    struct.pack_into("<H", header, 148, 240)
    struct.pack_into("<H", header, 152, 0x20B)
    struct.pack_into("<I", header, 212, 512)
    struct.pack_into("<8sIIII", header, 392, b".rdata\0\0", 512, 4096, 512, 512)
    seeds = crypto.INNER_A + crypto.INNER_B + crypto.OUTER_A + crypto.OUTER_B + crypto.MAC_SEED
    return bytes(header) + seeds.ljust(512, b"\0")


class CustomCryptoTests(unittest.TestCase):
    def test_fingerprint_hashes_lengths_and_regions_excluding_overlay(self):
        stub = owned_stub()
        expected = hashlib.sha256(struct.pack("<Q", 512) + stub[:512]
                                  + struct.pack("<Q", 512) + stub[512:]).digest()
        self.assertEqual(crypto.fingerprint(stub + b"unhashed overlay"), expected)
        self.assertTrue(crypto.matches(stub))
        self.assertFalse(crypto.matches(stub[:512] + bytes(512) + stub[512:]))
        with self.assertRaisesRegex(ValueError, "truncated"):
            crypto.fingerprint(stub[:-1])

    def test_roundtrip_boundary_lengths_and_integrity(self):
        stub = owned_stub()
        for size in (0, 1, 15, 16, 62, 256, 10000):
            stream = bytes((i*37) % 256 for i in range(size))
            payload = crypto.encrypt_owned(stream, stub)
            self.assertEqual(crypto.decrypt(payload, stub), stream)
            for index in (0, 24, len(payload)-33, len(payload)-1):
                corrupt = bytearray(payload)
                corrupt[index] ^= 1
                with self.assertRaisesRegex(ValueError, "integrity"):
                    crypto.decrypt(bytes(corrupt), stub)
            changed_stub = bytearray(stub)
            changed_stub[1023] ^= 1
            with self.assertRaisesRegex(ValueError, "integrity"):
                crypto.decrypt(payload, bytes(changed_stub))
        for payload in (b"", bytes(215), bytes(217)):
            with self.assertRaisesRegex(ValueError, "length"):
                crypto.decrypt(payload, stub)

    def test_inflate_rejects_oversized_owned_stream(self):
        compressed = zlib.compress(b"A" * 257)
        self.assertEqual(extract._inflate(compressed, max_output=257), b"A" * 257)
        with self.assertRaisesRegex(ValueError, "size limit"):
            extract._inflate(compressed, max_output=256)
        with self.assertRaisesRegex(ValueError, "trailing"):
            extract._inflate(compressed + b"extra", max_output=257)

    def test_extraction_and_owned_repack_preserve_original_stub(self):
        stub = owned_stub()
        stream = bytes(6) + bytes(41) + struct.pack("<qB", 123, 0) + b"owned bytecode"
        payload = crypto.encrypt_owned(stream, stub)
        packaged = (stub + extract.Reader.varint_bytes(0)
                    + extract.Reader.varint_bytes(len(payload) ^ crypto.SIZE_XOR) + payload)
        self.assertEqual(extract.get_payload(packaged), payload)
        with tempfile.TemporaryDirectory() as work:
            target = Path(work) / "owned.exe"
            target.write_bytes(packaged)
            info, recovered = extract.extract(target)
            self.assertEqual(recovered, stream)
            self.assertEqual(info.bytecode, b"owned bytecode")
            self.assertEqual(info.packaging_profile, crypto.PROFILE)
            replacement = stream[:-14] + b"new owned code"
            repacked = extract.package_owned_module(packaged, replacement)
            self.assertEqual(repacked[:len(stub)], stub)
            target.write_bytes(repacked)
            self.assertEqual(extract.extract(target)[1], replacement)
            with self.assertRaisesRegex(ValueError, "overrides"):
                extract.extract(target, key=bytes(32))


if __name__ == "__main__":
    unittest.main()
