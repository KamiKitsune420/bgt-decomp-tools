"""
bgtlib -- the BGT (BlastBay Gaming Toolkit) executable unpacking chain.

A BGT game ships as: the BGT runtime stub PE, with the compiled AngelScript module
appended past the last section as an overlay, encrypted and compressed.

    game.exe
      |- PE stub (the BGT runtime, itself LZ77-compressed inside BGT's exec.bin)
      `- overlay
           |- "<n> " ASCII field   n = size of an optional embedded pack file
           |- AES-256-CBC ciphertext
           |     key = SHA256(keygen(seed)), IV = key[:16]
           |     plaintext = "<32 hex>=<flag> printf<len>\\0" + LZ77 blob
           |         LZ77 blob ends with " <uncompressed length>"
           |         -> AngelScript bytecode
           `- 12-byte trailer  "xproc10\\0" + LE u32 overlay offset

Everything here was read out of strike.exe (Psycho Strike) with Ghidra; see
STRIKE-DECOMP.md in the Psycho Strike folder for the derivation of each step.
The seed is brute-forced rather than assumed, so builds that changed it still work.
"""

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

try:
    from Crypto.Cipher import AES
except ImportError:  # pycryptodomex packaging
    from Cryptodome.Cipher import AES


TRAILER_MAGIC = b"xproc10"
TRAILER_LEN = 12


class BgtError(Exception):
    pass


# --------------------------------------------------------------------------
# layer 1 -- the overlay
# --------------------------------------------------------------------------

def read_trailer(data: bytes) -> int:
    """Return the overlay offset from the 12-byte "xproc10" trailer.

    FUN_00442240 in strike.exe: seek to end-12, require the magic, then read a
    LE u32 at +8 which is the overlay's own start offset in the file.
    """
    if len(data) < TRAILER_LEN:
        raise BgtError("file too small to hold a trailer")
    trailer = data[-TRAILER_LEN:]
    if trailer[:7] != TRAILER_MAGIC:
        raise BgtError("no xproc10 trailer -- not a BGT executable "
                       "(or a BGT version that packs differently)")
    (offset,) = struct.unpack("<I", trailer[8:12])
    if not 0 < offset < len(data) - TRAILER_LEN:
        raise BgtError("trailer offset 0x%X out of range" % offset)
    return offset


def split_overlay(data: bytes) -> Tuple[int, bytes, bytes]:
    """Split the overlay into (embedded_pack, ciphertext).

    FUN_00472760 reads an ASCII decimal terminated by a space. That number is the
    size of an optional pack file appended ahead of the script -- BGT can bundle
    sounds into the exe. It is 0 in every title checked so far, which is why the
    field reads as the two bytes "0 ".
    """
    offset = read_trailer(data)
    body = data[offset:len(data) - TRAILER_LEN]

    i = body.find(b" ", 0, 16)
    if i < 0:
        raise BgtError("no space-terminated length field at the start of the overlay")
    try:
        n = int(body[:i] or b"0")
    except ValueError:
        raise BgtError("length field %r is not a decimal number" % body[:i])

    start = i + 1
    embedded = body[start:start + n] if n else b""
    ciphertext = body[start + n:]
    return offset, embedded, ciphertext


# --------------------------------------------------------------------------
# layer 2 -- the key, and AES
# --------------------------------------------------------------------------

def keygen(seed: int = 0x11) -> bytes:
    """Reproduce FUN_00441D90 -- the key material, generated rather than stored.

    This is why no string search ever finds a key in a BGT executable.
    For the stock seed 0x11 it produces 33 05 0f 2d then (05 0f 2d) repeating.
    """
    out = bytearray()
    v = seed
    for _ in range(32):
        v *= 3
        if v >= 0x80:
            v = 5
        elif v == 0:
            v = 0xD
        out.append(v & 0xFF)
    return bytes(out)


def aes_key_for_seed(seed: int = 0x11) -> bytes:
    """AES-256 key = SHA256(key material). IV is the first 16 bytes of the same digest.

    BGT uses the AES reference API (rijndael-api-fst.c), which takes key material as
    a hex ASCII string -- makeKey() is handed the 64-char hex of this digest, and
    cipherInit() reads 32 hex chars of it back as the IV.
    """
    return hashlib.sha256(keygen(seed)).digest()


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    n = len(ciphertext) - len(ciphertext) % 16
    return AES.new(key, AES.MODE_CBC, key[:16]).decrypt(ciphertext[:n])


# --------------------------------------------------------------------------
# layer 3 -- the BGT container header
# --------------------------------------------------------------------------

def parse_container(plaintext: bytes) -> Tuple[int, bytes]:
    """Parse "<32 hex>=<flag> printf<length>\\0" and return (flag, blob).

    The header is fixed-shape but not fixed-length: the declared length is decimal,
    so a bigger module means a longer header. Psycho Strike's is 48 bytes,
    Manamon 2's is 49. Compute it, never hardcode it.
    """
    eq = plaintext.find(b"=", 0, 48)
    if eq < 0:
        raise BgtError("no '=' in container header")
    sp = plaintext.find(b" ", eq, 64)
    if sp < 0:
        raise BgtError("no ' ' after the container flag")
    if plaintext[sp + 1:sp + 7] != b"printf":
        raise BgtError("expected 'printf' at offset %d" % (sp + 1))
    nul = plaintext.find(b"\x00", sp)
    if nul < 0:
        raise BgtError("unterminated length field")
    try:
        declared = int(plaintext[sp + 7:nul])
    except ValueError:
        raise BgtError("bad declared length %r" % plaintext[sp + 7:nul])

    flag = int(plaintext[eq + 1:sp])
    header_len = nul + 1
    blob = plaintext[header_len:header_len + declared]
    if len(blob) != declared:
        raise BgtError("container declares %d bytes, only %d present"
                       % (declared, len(blob)))
    return flag, blob


def looks_like_container(plaintext: bytes) -> bool:
    """Cheap validity test, used to identify the right key by trial decryption."""
    try:
        parse_container(plaintext[:96] + b"\x00" * 96)
    except BgtError:
        try:
            parse_container(plaintext)
        except BgtError:
            return False
    head = plaintext[:32]
    return all(c in b"0123456789ABCDEFabcdef" for c in head)


def find_seed(ciphertext: bytes,
              candidates: Optional[Sequence[int]] = None) -> Tuple[int, bytes]:
    """Recover the key seed by trial decryption of the first block.

    Only the first 32 bytes matter -- the container header starts with 32 hex
    characters, which is a strong enough constraint that a wrong seed is never
    mistaken for a right one. Costs one AES block per candidate.
    """
    if candidates is None:
        candidates = [0x11] + [s for s in range(1, 256) if s != 0x11]
    probe = ciphertext[:64]
    for seed in candidates:
        key = aes_key_for_seed(seed)
        head = decrypt(probe, key)
        if all(c in b"0123456789ABCDEFabcdef" for c in head[:32]) and b"=" in head[32:40]:
            return seed, key
    raise BgtError("no seed in the search space decrypts to a BGT container header")


# --------------------------------------------------------------------------
# layer 4 -- LZ77
# --------------------------------------------------------------------------

def _varint7(buf: bytes, p: int) -> Tuple[int, int]:
    """Big-endian base-128; the high bit means 'another byte follows'."""
    v = 0
    while True:
        c = buf[p]
        p += 1
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            return v, p


def lz77_split(blob: bytes) -> Tuple[bytes, int]:
    """Strip the trailing " <decimal>" and return (compressed, uncompressed_length).

    FUN_00450550 scans backwards for the last space.
    """
    ls = blob.rfind(b" ")
    if ls < 0:
        raise BgtError("no trailing length field on the compressed blob")
    try:
        return blob[:ls], int(blob[ls + 1:])
    except ValueError:
        raise BgtError("trailing length %r is not a decimal number" % blob[ls + 1:])


def lz77_decompress(comp: bytes, expected: Optional[int] = None) -> bytes:
    """FUN_0044A5C0 -- LZ77 with a leading escape byte.

    esc = comp[0]. Thereafter a byte equal to esc introduces either an escaped
    literal (esc, 0x00) or a (length, distance) match, both base-128 varints.
    Matches may overlap the output cursor, so the copy is byte-at-a-time.
    """
    if not comp:
        raise BgtError("empty compressed blob")
    esc = comp[0]
    out = bytearray()
    p, n = 1, len(comp)
    while p < n:
        c = comp[p]
        if c != esc:
            out.append(c)
            p += 1
            continue
        if p + 1 >= n:
            break
        if comp[p + 1] == 0:
            out.append(esc)
            p += 2
            continue
        length, p = _varint7(comp, p + 1)
        dist, p = _varint7(comp, p)
        if dist == 0 or dist > len(out):
            raise BgtError("match distance %d out of range at input offset %d"
                           % (dist, p))
        for _ in range(length):
            out.append(out[-dist])
    if expected is not None and len(out) != expected:
        raise BgtError("decompressed %d bytes, container declared %d"
                       % (len(out), expected))
    return bytes(out)


# --------------------------------------------------------------------------
# the whole chain
# --------------------------------------------------------------------------

@dataclass
class Unpacked:
    """Result of unpacking one BGT executable, with every intermediate kept.

    Every layer is kept rather than just the bytecode, because each one is what
    the next stage's correctness is checked against -- `compressed` is what a
    repack has to reproduce, and `container_magic` and `seed` are what it has to
    be rebuilt with.
    """

    overlay_offset: int
    overlay_size: int
    embedded_pack: bytes
    seed: int
    aes_key: bytes
    container_flag: int
    container_magic: str
    compressed: bytes
    bytecode: bytes

    def __repr__(self) -> str:
        return ("<Unpacked overlay=0x%X seed=0x%02X container_flag=%s "
                "bytecode=%d B>" % (self.overlay_offset, self.seed,
                                    self.container_flag, len(self.bytecode)))


def unpack(data: bytes, seed: Optional[int] = None) -> Unpacked:
    """Run the full chain over the bytes of a BGT executable."""
    overlay_offset, embedded, ciphertext = split_overlay(data)

    if seed is None:
        seed, key = find_seed(ciphertext)
    else:
        key = aes_key_for_seed(seed)

    plaintext = decrypt(ciphertext, key)
    flag, blob = parse_container(plaintext)
    comp, declared = lz77_split(blob)
    bytecode = lz77_decompress(comp, declared)

    return Unpacked(
        overlay_offset=overlay_offset,
        overlay_size=len(ciphertext) + TRAILER_LEN,
        embedded_pack=embedded,
        seed=seed,
        aes_key=key,
        container_flag=flag,
        container_magic=plaintext[:32].decode("ascii", "replace"),
        compressed=comp,
        bytecode=bytecode,
    )


def unpack_file(path: str, seed: Optional[int] = None) -> Unpacked:
    with open(path, "rb") as f:
        return unpack(f.read(), seed=seed)
