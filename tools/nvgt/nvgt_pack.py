"""
nvgt_pack -- NVGT's asset pack format (`pack` / `pack_file` in script).

This is NOT BGT's SFPv1 (see bgt_pack.py). NVGT replaced it outright; the two
share nothing but the idea. Transcribed from `pack::read_mode_internals::load`,
`pack::write_mode_internals::finalize` and `put_blank_header` in NVGT's
src/pack.cpp, and from `chacha_istreambuf` / `chacha_ostreambuf` in
src/crypto.cpp -- read, not inferred:

    header      64 bytes, written blank first and patched on close:
                  u32 LE  magic 0xDADFADED
                  u64 LE  toc_offset          (= 64 + total entry data)
                  u32 LE  checksum            CRC32 of the TOC bytes
                  zero padding to 64
    data        every entry's bytes, back to back, in insertion order
    TOC         from toc_offset to EOF, one record per entry:
                  7-bit   name length (Poco write7BitEncoded)
                  bytes   name, UTF-8, no ASCII controls, <= 65535 bytes
                  7-bit   entry size (64-bit)

Entry offsets are **not stored**. The reader reconstructs them by summing sizes
from 64, which is why it can -- and does -- demand that the sum lands exactly
on `toc_offset`. Together with the CRC and the TOC walk ending exactly on EOF,
every layer is self-verifying: a wrong field width fails, it does not produce a
plausible table.

## Encryption

A pack opened with a key is wrapped, whole, in Caturria's ChaCha stream:

    file   = nonce[24]  ||  XChaCha20(K, nonce)( ASSET_MAGIC || pack )
    K      = BLAKE2b-256(key bytes)             unkeyed, 32-byte digest
    ASSET_MAGIC = i32 LE 0xACEFADED             "is this really an NVGT asset"

Monocypher's `crypto_chacha20_x` is HChaCha20 over nonce[:16] then the DJB
ChaCha20 variant (64-bit counter, 8-byte nonce) over nonce[16:]. For any stream
under 256 GiB the high counter word is zero, which makes it bit-identical to
the IETF XChaCha20 construction pycryptodome implements -- so `ChaCha20.new`
with a 24-byte nonce is the same cipher, not an approximation.

Pack offsets live in the *logical* stream: the reader's seekpos adds the four
magic bytes back, so offset 0 is the first header byte, not the magic.

The asset magic is the key check. It is only 32 bits -- a wrong key passes it
about once in four billion tries -- so the TOC CRC and the exact-landing checks
behind it are what actually settle a key.

## Entry points

    pack = parse(data, key=None)          -> Pack, raises PackError
    pack.read(name)                       -> bytes
    build([(name, data), ...], key=None)  -> bytes NVGT's reader accepts
    looks_like_plain_pack(data)           -> bool, no key needed

Embedded packs inside a compiled executable are located by
`extract.embedded_packs()`; each one is a complete pack, plain or encrypted,
readable by `parse(exe[p.offset:p.offset + p.size], key)`.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
import zlib
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence, Union

PACK_MAGIC = 0xDADFADED
HEADER_SIZE = 64
ASSET_MAGIC = 0xACEFADED            # chacha_iostream_magic, stored as an int32
NONCE_SIZE = 24
MAX_NAME_BYTES = 65535              # the reader refuses anything longer

_PACK_MAGIC_BYTES = struct.pack("<I", PACK_MAGIC)
_ASSET_MAGIC_BYTES = struct.pack("<I", ASSET_MAGIC)

KeyLike = Union[str, bytes, None]


class PackError(ValueError):
    pass


# --------------------------------------------------------------------------
# Poco 7-bit integers
# --------------------------------------------------------------------------
#
# Poco's write7BitEncoded is little-endian base-128 with the high bit meaning
# "more follows" -- unlike AngelScript's ReadEncodedUInt64, where the high bit
# is a SIGN flag. The two appear side by side in an NVGT executable (the
# preamble is Poco, the module is AngelScript), so keeping them apart matters.

def read_7bit(buf: bytes, pos: int, max_bytes: int = 10) -> tuple[int, int]:
    """Decode one Poco 7-bit integer. Returns (value, new position)."""
    value = shift = 0
    for count in range(max_bytes):
        if pos >= len(buf):
            raise PackError("7-bit integer runs past the end at %d" % pos)
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos
    raise PackError("7-bit integer longer than %d bytes" % max_bytes)


def write_7bit(value: int) -> bytes:
    """Poco BinaryWriter::write7BitEncoded, for any non-negative value."""
    if value < 0:
        raise ValueError("7-bit encoding is unsigned, got %d" % value)
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


# --------------------------------------------------------------------------
# the ChaCha asset stream
# --------------------------------------------------------------------------

def _key_bytes(key: KeyLike) -> bytes:
    if key is None:
        raise PackError("no key")
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        # chacha_istreambuf throws on an empty key rather than using a
        # zero-length one, and pack::open treats "" as "not encrypted".
        raise PackError("an empty key means an unencrypted pack")
    return key


def derive_key(key: KeyLike) -> bytes:
    """The 32-byte ChaCha key: unkeyed BLAKE2b with a 32-byte digest.

    `crypto_blake2b(this->key, 32, key.data(), key.size())` -- Monocypher 4's
    four-argument form, confirmed in NVGT's dep/monocypher.c.
    """
    return hashlib.blake2b(_key_bytes(key), digest_size=32).digest()


def _chacha(key: bytes, nonce: bytes):
    try:
        from Crypto.Cipher import ChaCha20
    except ImportError:   # pycryptodomex packaging
        from Cryptodome.Cipher import ChaCha20
    return ChaCha20.new(key=key, nonce=nonce)


def decrypt_stream(blob: bytes, key: KeyLike) -> bytes:
    """Strip the nonce, decrypt, verify the asset magic; return the logical pack."""
    if len(blob) < NONCE_SIZE + 4:
        raise PackError("too short to be an encrypted NVGT asset (%d bytes)" % len(blob))
    plain = _chacha(derive_key(key), blob[:NONCE_SIZE]).decrypt(blob[NONCE_SIZE:])
    if plain[:4] != _ASSET_MAGIC_BYTES:
        raise PackError("asset magic does not match -- wrong key, or not an "
                        "encrypted NVGT asset")
    return plain[4:]


def encrypt_stream(plain: bytes, key: KeyLike, nonce: Optional[bytes] = None) -> bytes:
    """Inverse of decrypt_stream. A fresh random nonce unless one is given."""
    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    if len(nonce) != NONCE_SIZE:
        raise PackError("nonce must be %d bytes" % NONCE_SIZE)
    return nonce + _chacha(derive_key(key), nonce).encrypt(_ASSET_MAGIC_BYTES + plain)


# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Entry:
    name: str
    offset: int          # within the logical (decrypted) pack
    size: int


@dataclass
class Pack:
    entries: list[Entry]
    toc_offset: int
    checksum: int
    encrypted: bool
    data: bytes = field(repr=False)          # the logical pack, decrypted
    _by_name: dict = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._by_name = {e.name: e for e in self.entries}

    def names(self) -> list[str]:
        return [e.name for e in self.entries]

    def __contains__(self, name: str) -> bool:
        return name in self._by_name

    def __len__(self) -> int:
        return len(self.entries)

    def read(self, name: str) -> bytes:
        entry = self._by_name.get(name)
        if entry is None:
            raise KeyError(name)
        return self.data[entry.offset:entry.offset + entry.size]

    def items(self) -> Iterable[tuple[str, bytes]]:
        for e in self.entries:
            yield e.name, self.data[e.offset:e.offset + e.size]


def looks_like_plain_pack(data: bytes) -> bool:
    """Is this an unencrypted pack? An encrypted one starts with a random nonce."""
    return data[:4] == _PACK_MAGIC_BYTES


def _valid_name(raw: bytes) -> Optional[str]:
    """is_valid_utf8(name, ban_ascii_special=true): UTF-8, no C0 controls, no DEL."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        return None
    return text


def parse_plain(data: bytes, encrypted: bool = False) -> Pack:
    """Parse a logical (already decrypted) pack, exactly as `load()` does."""
    size = len(data)
    if size < HEADER_SIZE:
        raise PackError("%d bytes is smaller than the %d-byte header" % (size, HEADER_SIZE))
    if data[:4] != _PACK_MAGIC_BYTES:
        raise PackError("not an NVGT pack (magic %s)" % data[:4].hex())
    toc_offset, checksum = struct.unpack_from("<QI", data, 4)
    if toc_offset >= size or toc_offset < HEADER_SIZE:
        # >= rather than >: the reader's loop always reads at least one TOC
        # record, so a pack with no entries is rejected by NVGT itself.
        raise PackError("TOC offset %d is outside [%d, %d) -- NVGT's reader "
                        "rejects this (an empty pack has no TOC to read)"
                        % (toc_offset, HEADER_SIZE, size))

    crc = zlib.crc32(data[toc_offset:]) & 0xFFFFFFFF
    entries: list[Entry] = []
    seen: set[str] = set()
    pos = toc_offset
    current = HEADER_SIZE                  # entry offsets are rebuilt, never stored
    while True:
        name_len, pos = read_7bit(data, pos)
        if name_len > MAX_NAME_BYTES:
            raise PackError("TOC entry %d: name length %d exceeds %d"
                            % (len(entries), name_len, MAX_NAME_BYTES))
        if pos + name_len > size:
            raise PackError("TOC entry %d: name runs past EOF" % len(entries))
        name = _valid_name(data[pos:pos + name_len])
        if name is None:
            raise PackError("TOC entry %d: name is not valid UTF-8 or contains "
                            "control characters" % len(entries))
        pos += name_len
        if name in seen:
            raise PackError("TOC entry %d: duplicate name %r" % (len(entries), name))
        seen.add(name)
        entry_size, pos = read_7bit(data, pos)
        entries.append(Entry(name, current, entry_size))
        current += entry_size
        if pos == size:
            break                           # EOF exactly: the TOC is complete
        if pos > size:
            raise PackError("TOC overran EOF by %d bytes" % (pos - size))

    if crc != checksum:
        raise PackError("TOC checksum %08x, header declares %08x" % (crc, checksum))
    if current != toc_offset:
        raise PackError("entry sizes end at %d, TOC starts at %d (%+d unexplained)"
                        % (current, toc_offset, toc_offset - current))
    return Pack(entries, toc_offset, checksum, encrypted, data)


def parse(data: bytes, key: KeyLike = None) -> Pack:
    """Parse a pack file's bytes, decrypting first when a key is given.

    Without a key an encrypted pack fails on its magic, with a message saying
    so -- an encrypted pack is not a corrupt one.
    """
    if key is not None and key != "" and key != b"":
        return parse_plain(decrypt_stream(data, key), encrypted=True)
    if not looks_like_plain_pack(data):
        raise PackError("no pack magic -- if this pack is encrypted, pass its key")
    return parse_plain(data)


def parse_file(path: str, key: KeyLike = None) -> Pack:
    with open(path, "rb") as fh:
        return parse(fh.read(), key)


# --------------------------------------------------------------------------
# writing
# --------------------------------------------------------------------------

def build_plain(items: Sequence[tuple[str, bytes]]) -> bytes:
    """Serialise a logical pack exactly as NVGT's writer lays one out.

    Enforces the same rules `put()` does -- valid names, no duplicates -- so
    anything this writes, NVGT's reader accepts (given at least one entry).
    """
    seen: set[str] = set()
    body = bytearray()
    toc = bytearray()
    for name, blob in items:
        raw = name.encode("utf-8")
        if _valid_name(raw) is None:
            raise PackError("invalid entry name %r" % name)
        if len(raw) > MAX_NAME_BYTES:
            raise PackError("entry name longer than %d bytes" % MAX_NAME_BYTES)
        if name in seen:
            raise PackError("duplicate entry %r" % name)
        seen.add(name)
        body += blob
        toc += write_7bit(len(raw)) + raw + write_7bit(len(blob))
    toc_offset = HEADER_SIZE + len(body)
    header = (_PACK_MAGIC_BYTES
              + struct.pack("<QI", toc_offset, zlib.crc32(bytes(toc)) & 0xFFFFFFFF))
    header += bytes(HEADER_SIZE - len(header))
    return header + bytes(body) + bytes(toc)


def build(items: Sequence[tuple[str, bytes]], key: KeyLike = None,
          nonce: Optional[bytes] = None) -> bytes:
    """A complete pack file, encrypted when a key is given."""
    plain = build_plain(items)
    if key is None or key == "" or key == b"":
        return plain
    return encrypt_stream(plain, key, nonce)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _safe_join(root: str, name: str) -> str:
    """Map a pack entry name to a path under `root`, refusing to escape it."""
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts) or not parts:
        raise PackError("refusing to extract entry %r outside the output folder" % name)
    return os.path.join(root, *parts)


def _load_any(path: str, key: KeyLike, embedded: Optional[str]) -> tuple[Pack, str]:
    """A pack file, or one embedded in a compiled executable."""
    with open(path, "rb") as fh:
        data = fh.read()
    if embedded is None and (looks_like_plain_pack(data) or data[:2] != b"MZ"):
        return parse(data, key), os.path.basename(path)
    try:                      # installed as a package
        from . import extract
    except ImportError:       # run directly from a checkout
        import extract
    packs = extract.embedded_packs(data)
    if not packs:
        raise PackError("%s is an executable with no embedded packs" % path)
    chosen = packs[0] if embedded in (None, "", "*") else next(
        (p for p in packs if p.name == embedded), None)
    if chosen is None:
        raise PackError("no embedded pack %r (have: %s)"
                        % (embedded, ", ".join(p.name for p in packs)))
    return (parse(data[chosen.offset:chosen.offset + chosen.size], key),
            "%s:%s" % (os.path.basename(path), chosen.name))


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="nvgt-pack", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=("list", "extract", "create"))
    ap.add_argument("pack", help="pack file, or a compiled NVGT executable")
    ap.add_argument("inputs", nargs="*", help="create: files to add")
    ap.add_argument("-o", "--outdir", default="extracted")
    ap.add_argument("--key", help="pack key (as passed to pack.open in script)")
    ap.add_argument("--embedded", metavar="NAME",
                    help="read the pack embedded in an executable under this name")
    ap.add_argument("--limit", type=int, default=40)
    args = ap.parse_args(argv)

    try:
        if args.action == "create":
            items = []
            for src in args.inputs:
                with open(src, "rb") as fh:
                    items.append((os.path.basename(src), fh.read()))
            if not items:
                raise PackError("nothing to add -- NVGT cannot open an empty pack")
            if os.path.exists(args.pack):
                raise PackError("%s exists; refusing to overwrite" % args.pack)
            blob = build(items, args.key)
            with open(args.pack, "xb") as fh:
                fh.write(blob)
            parse(blob, args.key)            # verify what was written
            print("wrote %s: %d entries, %d bytes%s"
                  % (args.pack, len(items), len(blob), ", encrypted" if args.key else ""))
            return 0

        pack, label = _load_any(args.pack, args.key, args.embedded)
        total = sum(e.size for e in pack.entries)
        print("%s: %d entries, %d bytes of data%s, TOC crc %08x verified"
              % (label, len(pack), total, ", encrypted" if pack.encrypted else "",
                 pack.checksum))
        if args.action == "list":
            for e in pack.entries[:args.limit]:
                print("   %-56s %10d B" % (e.name[:56], e.size))
            if len(pack) > args.limit:
                print("   ... %d more" % (len(pack) - args.limit))
            return 0

        os.makedirs(args.outdir, exist_ok=True)
        for name, blob in pack.items():
            dest = _safe_join(args.outdir, name)
            os.makedirs(os.path.dirname(dest) or args.outdir, exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(blob)
        print("extracted %d entries to %s" % (len(pack), args.outdir))
        return 0
    except (PackError, OSError) as exc:
        print("nvgt-pack: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
