"""
extract.py - Pull the compiled AngelScript payload out of a packaged NVGT
executable (or a raw payload stream) and hand back bytecode that
decompile.py / disasm.py can read.

NVGT compiles a script and appends the payload to a stub binary:

    [stub exe][embedded packs][code_size^XOR varint][encrypted zlib bytecode]

On Windows the payload offset is not stored in a trailer; the loader instead
finds it as the end of the last PE section (LoadCompiledExecutable in
nvgt_angelscript.cpp).  Other platforms write a 4-byte stub-size little-endian
trailer at EOF.

The embedded-pack block is `write_embedded_packs` / `load_embedded_packs`
(src/pack.cpp), read through a Poco BinaryReader:

    7-bit    pack count
    per pack:  7-bit length + name bytes     <- a Poco std::string, NOT a u32
               u32 LE size
               size bytes of pack data       (an NVGT pack; see nvgt_pack.py)

Reading the name length as a u32 -- which this module once did -- consumes
the name's first bytes as a length and loses every executable that bundles an
asset. `read_embedded_packs()` is the one place that walks this block.

The payload is AES-256-CBC encrypted (nvgt_config.h):
    key = SHA256("Kernel32.lib")          (32 bytes, Poco digest)
    iv  = key[2i+1] ^ (31 + 4*i)          for i in 0..15
    pad = PKCS#7-style: last byte = padding count, real size = len - pad
after zlib compression (with its header and checksum).
The bundled official release uses a separate SHA-256-derived profile, implemented
by decrypt_official(). Other compiler releases may use different profiles.

The decrypted stream is Poco BinaryWriter output followed by the AngelScript
SaveByteCode stream:

    u16          plugin count, then 7-bit length + utf8 name per plugin
    i32          system namespace count, then 7-bit length pairs (name, path)
    41 varints   engine properties (asEP_LAST_PROPERTY == 41)
    i64          build timestamp
    u8           app.no_auto_chdir flag
    ...          module bytecode (asCWriter::Write)

Usage:
    python extract.py game.exe out.bin          # extract from a packaged exe
    python extract.py --payload blob.bin out.bin  # decrypt a bare payload

Then:  python decompile.py out.bin
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path


def _custom_crypto():
    """The executable-bound profile, imported lazily.

    custom_crypto imports _inflate/_unpad from this module, so a module-level
    import in either direction would be circular.
    """
    try:                      # installed as a package
        from . import custom_crypto
    except ImportError:       # run directly from a checkout
        import custom_crypto
    return custom_crypto

NVGT_BYTECODE_NUMBER_XOR = 96607          # official release stub (repo src: 47635)
NVGT_BYTECODE_NUMBER_XOR_REPO = 47635      # src/nvgt_config.h default
AES_KEY = hashlib.sha256(b"Kernel32.lib").digest()
AES_IV = bytes(AES_KEY[i * 2 + 1] ^ (31 + i * 4) for i in range(16))
NUM_ENGINE_PROPERTIES = 41                # asEP_LAST_PROPERTY


class Reader:
    """Sequential reader matching Poco BinaryReader + load_embedded_packs."""

    def __init__(self, data: bytes, pos: int = 0):
        if not 0 <= pos <= len(data):
            raise ValueError("reader offset outside input")
        self.data = data
        self.pos = pos

    def u8(self) -> int:
        return self.raw(1)[0]

    def u16(self) -> int:
        (v,) = struct.unpack("<H", self.raw(2))
        return v

    def u32(self) -> int:
        (v,) = struct.unpack("<I", self.raw(4))
        return v

    def i32(self) -> int:
        (v,) = struct.unpack("<i", self.raw(4))
        return v

    def i64(self) -> int:
        (v,) = struct.unpack("<q", self.raw(8))
        return v

    def raw(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError(f"read past end ({self.pos}+{n} > {len(self.data)})")
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def varint(self) -> int:
        """Poco 7-bit-encoded unsigned int (little-endian groups, high bit
        set = more bytes follow)."""
        result = 0
        shift = 0
        for shift in range(0, 35, 7):
            b = self.u8()
            if shift == 28 and b > 15:
                raise ValueError("Poco integer exceeds 32 bits")
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                return result
        raise ValueError("unterminated Poco integer")

    @staticmethod
    def varint_bytes(v: int) -> bytes:
        """Encode a Poco 7-bit-encoded unsigned int."""
        if not 0 <= v <= 0xffffffff:
            raise ValueError("Poco integer must be an unsigned 32-bit value")
        out = bytearray()
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                out.append(b | 0x80)
            else:
                out.append(b)
                return bytes(out)

    def string(self) -> str:
        return self.raw(self.varint()).decode("utf-8", "replace")

    def string_bytes(self) -> bytes:
        """Poco BinaryWriter << std::string: 7-bit length + utf8 bytes."""
        b = self.raw(self.varint())
        return b


# ---------------------------------------------------------------------------
# locating + decrypting the payload
# ---------------------------------------------------------------------------

def payload_offset(data: bytes) -> int:
    """Offset of the embedded-packs region: end of the last PE section, or
    (for non-PE stubs) EOF minus the 4-byte stub-size trailer."""
    if data[:2] == b"MZ":
        if len(data) < 64:
            raise ValueError("truncated DOS header")
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off < 64 or pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
            raise ValueError("invalid or truncated PE header")
        if data[pe_off:pe_off + 4] == b"PE\x00\x00":
            num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
            opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
            first = pe_off + 24 + opt_size
            if not num_sections or first + 40 * num_sections > len(data):
                raise ValueError("invalid or truncated PE section table")
            end = 0
            for i in range(num_sections):
                base = first + 40 * i
                raw_ptr = struct.unpack_from("<I", data, base + 20)[0]
                raw_size = struct.unpack_from("<I", data, base + 16)[0]
                if raw_ptr + raw_size > len(data):
                    raise ValueError("truncated PE section data")
                end = max(end, raw_ptr + raw_size)
            return end
    if len(data) < 4:
        return len(data)
    stub_size = struct.unpack_from("<i", data, len(data) - 4)[0]
    if 0 < stub_size < len(data):
        return stub_size
    return len(data)


@dataclass(frozen=True)
class EmbeddedPack:
    """One pack bundled into the executable by `#pragma asset` / `-a`.

    `offset` is absolute within the executable and `size` is the declared pack
    length, so `data[offset:offset + size]` is a complete NVGT pack that
    nvgt_pack.parse() can read.
    """
    name: str
    offset: int
    size: int


# Poco strings are capped far below this in practice; it only guards against a
# misread count driving an enormous walk.
MAX_EMBEDDED_PACKS = 1 << 16


def read_embedded_packs(data: bytes, offset: int | None = None
                        ) -> tuple[list[EmbeddedPack], int]:
    """Walk the embedded-pack block. Returns (packs, offset just past it).

    Transcribed from `load_embedded_packs` in src/pack.cpp: a 7-bit count, then
    per pack a Poco `std::string` name and a little-endian u32 size, then the
    pack bytes, which the loader skips over with seekg.
    """
    r = Reader(data, payload_offset(data) if offset is None else offset)
    count = r.varint()
    if count > MAX_EMBEDDED_PACKS:
        raise ValueError(f"implausible embedded pack count {count}")
    packs = []
    for _ in range(count):
        name = r.string_bytes().decode("utf-8", "replace")
        size = r.u32()
        packs.append(EmbeddedPack(name, r.pos, size))
        r.raw(size)
    return packs, r.pos


def embedded_packs(data: bytes) -> list[EmbeddedPack]:
    """Every pack bundled into a packaged executable, in file order."""
    return read_embedded_packs(data)[0]


def get_payload(data: bytes) -> bytes:
    """Slice the encrypted bytecode payload out of a packaged executable."""
    _, cursor = read_embedded_packs(data)
    r = Reader(data, cursor)
    encoded_size = r.varint()
    remaining = len(data) - r.pos
    custom_crypto = _custom_crypto()
    if custom_crypto.matches(data):
        size = encoded_size ^ custom_crypto.SIZE_XOR
        if not 216 <= size <= remaining or (size - 136) % 16:
            raise ValueError("invalid custom NVGT payload size")
        return r.raw(size)
    candidates = [encoded_size ^ x for x in
                  (NVGT_BYTECODE_NUMBER_XOR, NVGT_BYTECODE_NUMBER_XOR_REPO)]
    exact = [n for n in candidates if n == remaining and n > 0 and n % 16 == 0]
    valid = exact or [n for n in candidates if 0 < n <= remaining and n % 16 == 0]
    if len(valid) != 1:
        raise ValueError("Cannot identify NVGT payload size/profile")
    return r.raw(valid[0])


def _decrypt_repo(payload: bytes, key: bytes | None = None, iv: bytes | None = None) -> bytes:
    """Repository AES-256-CBC decrypt + padding + zlib inflate.

    key/iv override the standard nvgt_config.h derivation (a packaged
    official release build ships customized constants; recover them from
    the stub in Ghidra and pass --key-hex/--iv-hex).
    """
    if key is None:
        key = AES_KEY
    if iv is None:
        iv = AES_IV
    try:
        from Crypto.Cipher import AES   # pycryptodome
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(payload) + dec.finalize()
    else:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(payload)
    return _inflate(_unpad(padded), allow_raw=True)


def _unpad(data: bytes) -> bytes:
    if not data or not 1 <= data[-1] <= 16 or data[-data[-1]:] != bytes([data[-1]]) * data[-1]:
        raise ValueError("bad padding: wrong key or unsupported NVGT payload")
    return data[:-data[-1]]


MAX_INFLATED_BYTECODE = 256 * 1024 * 1024


def _inflate(data: bytes, allow_raw: bool = False,
             max_output: int = MAX_INFLATED_BYTECODE) -> bytes:
    """Inflate a complete bytecode stream within a bounded output size."""
    if max_output < 1:
        raise ValueError("invalid decompressed bytecode limit")
    # Older versions of this project's packager mistakenly used raw DEFLATE.
    for window in ((15, -15) if allow_raw else (15,)):
        try:
            dec = zlib.decompressobj(window)
            result = dec.decompress(data, max_output + 1)
            if len(result) > max_output or dec.unconsumed_tail:
                raise ValueError("decompressed bytecode exceeds size limit")
            if not dec.eof or dec.unused_data:
                raise ValueError("incomplete or trailing compressed data")
            return result
        except zlib.error:
            if window == -15 or not allow_raw:
                raise
    raise ValueError("invalid compressed stream")


def official_key_iv(n: int) -> tuple[bytes, bytes]:
    """Derivation verified against the bundled 2026-08-30 release stub."""
    seed_a = bytes.fromhex("4a5ba0ed2c9d2c908b22bc6ad570ab9e054ce21f13aecbd6912db543492ab854a3178e92")
    seed_b = bytes.fromhex("33a9c4c6fbc03a88bfc139f1ec3f91e933a56562437fdb628cf3364b0f65")
    key = hashlib.sha256(seed_a + struct.pack("<I", n ^ 0x3CA34893) + seed_b).digest()
    iv = bytes((((key[2*j] << 6) | (key[2*j] >> 2)) & 255) ^ key[j+12] ^ (0xD8+j)
               for j in range(16))
    return key, iv


def decrypt_official(payload: bytes, key: bytes | None = None,
                     iv: bytes | None = None) -> bytes:
    if len(payload) < 128 or len(payload) % 16:
        raise ValueError("invalid release payload length")
    n = len(payload) - 80
    derived_key, derived_iv = official_key_iv(n)
    key = derived_key if key is None else key
    iv = derived_iv if iv is None else iv
    try:
        from Crypto.Cipher import AES
        data = AES.new(key, AES.MODE_CBC, iv).decrypt(payload[80:])
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        data = dec.update(payload[80:]) + dec.finalize()
    data = bytes(v ^ ((i * 15 + (n >> 5) + 36) & 255) for i, v in enumerate(data))
    compressed = bytes(v ^ data[i % 28] for i, v in enumerate(data[28:]))
    return _inflate(_unpad(compressed))


def decrypt(payload: bytes, key: bytes | None = None, iv: bytes | None = None) -> bytes:
    """Try the verified release and repository profiles, validating the stream."""
    errors = []
    for decoder in (decrypt_official, _decrypt_repo):
        try:
            return decoder(payload, key, iv)
        except (ValueError, zlib.error) as exc:
            errors.append(str(exc))
    raise ValueError("Unsupported or corrupt NVGT payload: " + "; ".join(errors))


def encrypt_official(stream: bytes) -> bytes:
    """Inverse of the verified release decoder, for owned diagnostic modules.

    Does not support the randomized parameters of arbitrary newer builds.
    """
    compressed = zlib.compress(stream, 9)
    pad = 16 - ((len(compressed) + 28) % 16)
    compressed += bytes([pad]) * pad
    inner_key = secrets.token_bytes(28)
    plain = inner_key + bytes(value ^ inner_key[index % 28]
                              for index, value in enumerate(compressed))
    size = len(plain)
    plain = bytes(value ^ ((index * 15 + (size >> 5) + 36) & 255)
                  for index, value in enumerate(plain))
    key, iv = official_key_iv(size)
    try:
        from Crypto.Cipher import AES
        encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(plain)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        encrypted = enc.update(plain) + enc.finalize()
    return secrets.token_bytes(80) + encrypted


def package_owned_module(target: bytes, stream: bytes) -> bytes:
    """Put owned bytecode in a separate copy of a verified engine stub.

    Remove all original payload/packs and infer the size XOR from the target.
    Validate its encryption first; never guess a profile from a version label.
    """
    original = get_payload(target)
    custom_crypto = _custom_crypto()
    if custom_crypto.matches(target):
        custom_crypto.decrypt(original, target)
        encrypted = custom_crypto.encrypt_owned(stream, target)
        return (target[:payload_offset(target)] + Reader.varint_bytes(0)
                + Reader.varint_bytes(len(encrypted) ^ custom_crypto.SIZE_XOR) + encrypted)
    try:
        decrypt_official(original)
    except (ValueError, zlib.error):
        _decrypt_repo(original)
        encrypted = encrypt_stream(stream)
    else:
        encrypted = encrypt_official(stream)
    _, after_packs = read_embedded_packs(target)
    cursor = Reader(target, after_packs)
    number_xor = cursor.varint() ^ len(original)
    writer = Reader(b"")
    return (target[:payload_offset(target)] + writer.varint_bytes(0)
            + writer.varint_bytes(len(encrypted) ^ number_xor) + encrypted)


def encrypt_stream(stream: bytes, key: bytes | None = None,
                   iv: bytes | None = None) -> bytes:
    """Repository profile: zlib + PKCS7-style pad + AES-256-CBC.
    Used to package a bytecode stream into a stub the same way nvgt's
    compiler does (write_payload in bundling.cpp)."""
    if key is None:
        key = AES_KEY
    if iv is None:
        iv = AES_IV
    comp = zlib.compressobj(9, zlib.DEFLATED, 15)
    data = comp.compress(stream) + comp.flush()
    r = 16 - (len(data) % 16)
    data += bytes([r]) * r
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return enc.update(data) + enc.finalize()


def package(exe_or_stub: bytes, bytecode: bytes,
            key: bytes | None = None, iv: bytes | None = None) -> bytes:
    """Append a repository-profile stream to a matching bare PE stub.

    bytecode must include the NVGT preamble. This does not convert an official
    stub into a repository-profile loader; use a stub built with matching crypto.
    """
    payload = encrypt_stream(bytecode, key, iv)
    r = Reader(b"")
    out = bytearray(exe_or_stub)
    # distributed stubs ship with the first 2 PE bytes stripped to avoid AV
    # scans; the compiler rewrites them (open_output_stream, bundling.cpp)
    out[0:2] = b"MZ"
    out += r.varint_bytes(0)                       # embedded pack count
    out += r.varint_bytes(len(payload) ^ NVGT_BYTECODE_NUMBER_XOR_REPO)
    out += payload
    return bytes(out)

class NvgtInfo:
    plugins: list[str]
    namespaces: list[tuple[str, str]]
    engine_properties: list[int]
    timestamp: int
    no_auto_chdir: int
    bytecode: bytes


def split_stream(stream: bytes) -> NvgtInfo:
    """Peel the nvgt preamble off a decrypted stream; return the pure
    AngelScript bytecode and the metadata as attributes."""
    info = NvgtInfo()
    r = Reader(stream)
    info.plugins = [r.string() for _ in range(r.u16())]
    namespace_count = r.i32()
    if not 0 <= namespace_count <= (len(stream) - r.pos) // 2:
        raise ValueError("invalid namespace count")
    info.namespaces = [(r.string(), r.string()) for _ in range(namespace_count)]
    info.engine_properties = [r.varint() for _ in range(NUM_ENGINE_PROPERTIES)]
    info.timestamp = r.i64()
    info.no_auto_chdir = r.u8()
    info.bytecode = bytes(stream[r.pos:])
    return info


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def extract(source: Path, raw_payload: bool = False,
            key: bytes | None = None, iv: bytes | None = None) -> tuple[NvgtInfo, bytes]:
    return extract_data(Path(source).read_bytes(), raw_payload, key, iv)


def extract_data(data: bytes, raw_payload: bool = False,
                 key: bytes | None = None, iv: bytes | None = None) -> tuple[NvgtInfo, bytes]:
    """Decode bytes with the complete executable context for bound profiles."""
    custom_crypto = _custom_crypto()
    if not raw_payload and custom_crypto.matches(data):
        if key is not None or iv is not None:
            raise ValueError("key/IV overrides are unsupported for executable-bound crypto")
        stream = custom_crypto.decrypt(get_payload(data), data)
        info = split_stream(stream)
        info.packaging_profile = custom_crypto.PROFILE
        return info, stream
    if not raw_payload and data[:2] == b"MZ":
        offset = payload_offset(data)
        if offset + 4 <= len(data):
            size = struct.unpack_from("<I", data, offset)[0] ^ 0xA5B4
            if 0 < size <= len(data) - offset - 4 and size % 16 == 0:
                try:
                    stream = decrypt_legacy(data[offset + 4:offset + 4 + size])
                except (ValueError, zlib.error):
                    pass
                else:
                    info = NvgtInfo()
                    info.plugins, info.namespaces, info.engine_properties = [], [], []
                    info.timestamp, info.no_auto_chdir, info.bytecode = 0, 0, stream
                    info.packaging_profile = "legacy_fixed_size_a5b4"
                    return info, stream
    payload = data if raw_payload else get_payload(data)
    stream = decrypt(payload, key, iv)
    return split_stream(stream), stream


def decrypt_legacy(payload: bytes) -> bytes:
    """Pre-versioned NVGT profile, statically verified against STW's loader."""
    size = len(payload)
    key = hashlib.sha256(f"error {size}".encode("ascii")).digest()
    iv = bytes(key[2*i + 1] ^ (9*i + 1) for i in range(16))
    try:
        from Crypto.Cipher import AES
        plain = AES.new(key, AES.MODE_CBC, iv).decrypt(payload)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        decoder = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        plain = decoder.update(payload) + decoder.finalize()
    plain = _unpad(plain)
    # This loader explicitly restores the first zlib header byte after AES.
    return _inflate(b"\x78" + plain[1:])


def _write_embedded_packs(source: Path, outdir: Path) -> list[Path]:
    """Copy every embedded pack out verbatim, one file per pack.

    The bytes are written exactly as stored -- an encrypted pack stays
    encrypted, and opens with `bgt nvgt pack ... --key` like any other.
    """
    try:                      # installed as a package
        from .nvgt_pack import _safe_join
    except ImportError:       # run directly from a checkout
        from nvgt_pack import _safe_join
    data = Path(source).read_bytes()
    packs = embedded_packs(data)
    written = []
    for pack in packs:
        dest = Path(_safe_join(str(outdir), pack.name))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data[pack.offset:pack.offset + pack.size])
        written.append(dest)
        print(f"embedded pack {pack.name}: {pack.size} bytes -> {dest}")
    if not packs:
        print(f"{Path(source).name}: no embedded packs")
    return written


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--payload", action="store_true")
    parser.add_argument("--package", action="store_true")
    parser.add_argument("--key-hex")
    parser.add_argument("--iv-hex")
    parser.add_argument("--packs", type=Path, metavar="DIR",
                        help="also write each embedded pack to DIR as a standalone "
                             "pack file (read them with `bgt nvgt pack`)")
    args = parser.parse_args(argv)
    if len(args.paths) not in ((3,) if args.package else (1, 2)):
        parser.error("packaging needs stub, bytecode and output; extraction needs input and optional output")
    if args.packs is not None and not args.package and not args.payload:
        try:
            _write_embedded_packs(args.paths[0], args.packs)
        except (OSError, ValueError) as error:
            parser.exit(1, f"Embedded pack extraction failed: {error}\n")
    try:
        key = bytes.fromhex(args.key_hex) if args.key_hex is not None else None
        iv = bytes.fromhex(args.iv_hex) if args.iv_hex is not None else None
        if key is not None and len(key) != 32:
            raise ValueError("AES-256 key must contain 32 bytes")
        if iv is not None and len(iv) != 16:
            raise ValueError("AES-CBC IV must contain 16 bytes")
        source = args.paths[0]
        if args.package:
            bytecode, output = args.paths[1:]
            if output.resolve() in (source.resolve(), bytecode.resolve()):
                raise ValueError("output must differ from both inputs")
            code = bytecode.read_bytes()
            output.write_bytes(package(source.read_bytes(), code, key, iv))
            print(f"packaged {len(code)} bytes of bytecode -> {output}")
            return 0
        output = (args.paths[1] if len(args.paths) == 2 else source.with_suffix(".bin")).with_suffix(".bin")
        if output.resolve() == source.resolve():
            raise ValueError("output must differ from input; provide a separate .bin path")
        info, _ = extract(source, raw_payload=args.payload, key=key, iv=iv)
        output.write_bytes(info.bytecode)
        print(f"{source.name}: stub payload -> {output.name} "
              f"({len(info.bytecode)} bytes of bytecode, "
              f"{len(info.plugins)} plugins, built {info.timestamp})")
        if info.plugins:
            print("  plugins: " + ", ".join(info.plugins))
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Extraction failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
