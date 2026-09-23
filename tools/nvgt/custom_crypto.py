"""Authenticated, executable-bound NVGT crypto, verified on the August 2026 build.

Parameters are specific to the custom build supplied as number_quest.exe. Detect
the actual seeds, not the NVGT version: other builds can share a version while
using entirely different security routines. No game execution is needed.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import zlib

PROFILE = "custom_pe_bound_xchacha_aes_20260820"
SIZE_XOR = 0xE03D
INNER_A = bytes.fromhex("c7a594dab08c78816af522e6abe05ec19a1bedc3e3787a88b7")
INNER_B = bytes.fromhex("34e199ab510a939aa530cb0e91fe278046bea97bf42c5ed97d2330e2d4360d8f70a10814414e10b17ea58ef6")
OUTER_A = bytes.fromhex("2d01953985a6ab89450303568d18a99f7d8d370243081dc7973c779778bf49cc6755a0468d33b0bb")
OUTER_B = bytes.fromhex("91efc2b725dbb8da209c9ae49fee6bd25dd01822cb41c73caac7f7ab8684e3578a799d224088af79")
MAC_SEED = bytes.fromhex("7b8ad04a96a17ef7b05a5be5f55b6541b19d8a653d664c0d6453e85ea369ddf66637f7253c40dd1da6b19f466f2cdf")


def pe_regions(executable: bytes) -> list[tuple[int, int]]:
    """Regions hashed by this build: headers followed by each raw PE section."""
    try:
        if executable[:2] != b"MZ":
            raise ValueError("custom crypto requires a PE executable")
        pe = struct.unpack_from("<I", executable, 60)[0]
        if executable[pe:pe + 4] != b"PE\0\0":
            raise ValueError("invalid PE signature")
        count = struct.unpack_from("<H", executable, pe + 6)[0]
        optional_size = struct.unpack_from("<H", executable, pe + 20)[0]
        if optional_size < 64 or not 1 <= count <= 512:
            raise ValueError("invalid PE header/section count")
        header_size = struct.unpack_from("<I", executable, pe + 24 + 60)[0]
        if not 1 <= header_size < 0x100000:
            raise ValueError("invalid PE header size")
        regions = [(0, header_size)]
        for index in range(count):
            section = pe + 24 + optional_size + 40 * index
            size, offset = struct.unpack_from("<II", executable, section + 16)
            if size and offset:
                regions.append((offset, size))
        if any(offset + size > len(executable) for offset, size in regions):
            raise ValueError("truncated PE region")
        return regions
    except struct.error as exc:
        raise ValueError("truncated PE header") from exc


def matches(executable: bytes) -> bool:
    if executable[:2] != b"MZ":
        return False
    regions = pe_regions(executable)
    stub_end = max(offset + size for offset, size in regions)
    stub = executable[:stub_end]
    return all(seed in stub for seed in (INNER_A, INNER_B, OUTER_A, OUTER_B, MAC_SEED))


def fingerprint(executable: bytes) -> bytes:
    digest = hashlib.sha256()
    for offset, size in pe_regions(executable):
        digest.update(struct.pack("<Q", size))
        digest.update(executable[offset:offset + size])
    return digest.digest()


def inner_key_iv(size: int, binding: bytes) -> tuple[bytes, bytes]:
    key = hashlib.sha256(INNER_A + struct.pack("<I", size ^ 0xDE251E99)
                         + binding + INNER_B).digest()
    iv = bytes((((key[2*i] << 2) | (key[2*i] >> 6)) & 255)
               ^ key[i + 14] ^ ((0xCA + 7*i) & 255) for i in range(16))
    return key, iv


def outer_key(size: int, binding: bytes) -> bytes:
    return hashlib.sha256(OUTER_A + struct.pack("<I", size ^ 0x9505D3FB)
                          + binding + OUTER_B).digest()


def decrypt(payload: bytes, executable: bytes) -> bytes:
    from Crypto.Cipher import AES, ChaCha20
    try:                      # installed as a package
        from .extract import _inflate, _unpad
    except ImportError:       # run directly from a checkout
        from extract import _inflate, _unpad

    if len(payload) < 216 or (len(payload) - 136) % 16:
        raise ValueError("invalid executable-bound payload length")
    binding = fingerprint(executable)
    expected = hmac.new(MAC_SEED + binding, payload[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(expected, payload[-32:]):
        raise ValueError("custom payload integrity check failed (changed executable or payload)")
    outer = ChaCha20.new(key=outer_key(len(payload) - 56, binding),
                         nonce=payload[:24]).decrypt(payload[24:-32])
    size = len(outer) - 80
    key, iv = inner_key_iv(size, binding)
    inner = AES.new(key, AES.MODE_CBC, iv).decrypt(outer[80:])
    inner = bytes(value ^ (((size >> 4) - index*0x43 - 0x1E) & 255)
                  for index, value in enumerate(inner))
    compressed = bytes(value ^ inner[index % 62]
                       for index, value in enumerate(inner[62:]))
    return _inflate(_unpad(compressed))


def encrypt_owned(stream: bytes, executable: bytes) -> bytes:
    """Inverse for owned diagnostic fixtures; retain the original stub unchanged."""
    from Crypto.Cipher import AES, ChaCha20

    binding = fingerprint(executable)
    compressed = zlib.compress(stream, 9)
    padding = 16 - (len(compressed) + 62) % 16
    compressed += bytes([padding]) * padding
    mask = secrets.token_bytes(62)
    inner = mask + bytes(value ^ mask[index % 62]
                         for index, value in enumerate(compressed))
    size = len(inner)
    inner = bytes(value ^ (((size >> 4) - index*0x43 - 0x1E) & 255)
                  for index, value in enumerate(inner))
    key, iv = inner_key_iv(size, binding)
    outer = secrets.token_bytes(80) + AES.new(key, AES.MODE_CBC, iv).encrypt(inner)
    nonce = secrets.token_bytes(24)
    payload = nonce + ChaCha20.new(key=outer_key(len(outer), binding),
                                   nonce=nonce).encrypt(outer)
    return payload + hmac.new(MAC_SEED + binding, payload, hashlib.sha256).digest()
