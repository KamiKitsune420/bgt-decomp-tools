"""
bgt_repack -- rebuild a BGT executable around a modified AngelScript module.

The inverse of bgtlib's chain: compress, wrap in the container header, encrypt, and
reattach as a PE overlay with a fresh "xproc10" trailer.

    python bgt_repack.py game.exe modified_bytecode.bin -o patched.exe

The PE stub is copied verbatim from the original, so only the overlay changes. The
trailer's offset field is the overlay's own start, which is just the stub length --
recompute it, never copy the old one, or a stub of a different size silently points
the loader at the wrong place.

Correctness here is checked by round-trip rather than by inspection: repack, then
unpack again, and require the bytecode to come back identical. `verify_roundtrip()`
does exactly that and the CLI runs it by default.

Compression note: the LZ77 encoder below is a plain greedy matcher, so its output is
usually a little larger than what BGT's own compressor produced. That is harmless --
the container declares its own lengths, so nothing downstream cares -- but it does
mean a repacked executable will not be byte-identical to the original.
"""

import argparse
import struct
import sys
from typing import Optional

try:                      # installed as a package
    from . import bgtlib
except ImportError:       # run directly from a checkout
    import bgtlib


MIN_MATCH = 4          # below this a match costs more bytes than the literals
MAX_MATCH = 4096
WINDOW = 1 << 16


def _varint7_encode(v: int) -> bytes:
    """Big-endian base-128, high bit set on every byte but the last."""
    if v < 0:
        raise ValueError("varint cannot encode %d" % v)
    parts = [v & 0x7F]
    v >>= 7
    while v:
        parts.insert(0, 0x80 | (v & 0x7F))
        v >>= 7
    return bytes(parts)


def choose_escape(data: bytes) -> int:
    """Pick the least common byte as the escape.

    Every occurrence of the escape in the payload costs an extra byte, so the
    rarest byte minimises that. A byte absent from the data entirely costs nothing.
    """
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return min(range(256), key=lambda b: counts[b])


def lz77_compress(data: bytes, escape: Optional[int] = None) -> bytes:
    """Produce a blob that bgtlib.lz77_decompress reverses exactly.

    Greedy matching against a hash of 3-byte prefixes. Matches are allowed to
    overlap the output cursor, matching the decoder's byte-at-a-time copy.
    """
    if not data:
        raise bgtlib.BgtError("nothing to compress")
    esc = choose_escape(data) if escape is None else escape
    out = bytearray([esc])
    table = {}
    i = 0
    n = len(data)
    while i < n:
        best_len = 0
        best_dist = 0
        if i + MIN_MATCH <= n:
            key = data[i:i + 3]
            for cand in reversed(table.get(key, ())):
                dist = i - cand
                if dist <= 0 or dist > WINDOW:
                    continue
                length = 0
                limit = min(MAX_MATCH, n - i)
                while length < limit and data[cand + length] == data[i + length]:
                    length += 1
                if length > best_len:
                    best_len, best_dist = length, dist
                    if length >= 64:
                        break

        if best_len >= MIN_MATCH:
            out.append(esc)
            out += _varint7_encode(best_len)
            out += _varint7_encode(best_dist)
            step = best_len
        else:
            b = data[i]
            if b == esc:
                out += bytes([esc, 0x00])
            else:
                out.append(b)
            step = 1

        for j in range(i, min(i + step, n - 2)):
            table.setdefault(data[j:j + 3], []).append(j)
        i += step

    return bytes(out)


def build_overlay(bytecode: bytes, seed: int = 0x11, flag: int = 3,
                  magic: Optional[bytes] = None, embedded: bytes = b"") -> bytes:
    """Compress, wrap and encrypt -- everything between the stub and the trailer."""
    if magic is None:
        magic = b"6188CAE85A13D82754756DC38920FA09"
    if len(magic) != 32:
        raise bgtlib.BgtError("container magic must be 32 characters")

    comp = lz77_compress(bytecode)
    blob = comp + b" " + str(len(bytecode)).encode()
    header = (magic + b"=" + str(flag).encode() + b" printf"
              + str(len(blob)).encode() + b"\x00")
    plaintext = header + blob

    pad = (-len(plaintext)) % 16          # CBC needs whole blocks; the container
    plaintext += b"\x00" * pad            # declares its length, so slack is ignored

    key = bgtlib.aes_key_for_seed(seed)
    ciphertext = bgtlib.AES.new(key, bgtlib.AES.MODE_CBC,
                                key[:16]).encrypt(plaintext)

    return b"%d " % len(embedded) + embedded + ciphertext


def repack(original: bytes, bytecode: bytes, seed: Optional[int] = None,
           flag: Optional[int] = None, magic: Optional[bytes] = None,
           keep_embedded: bool = True) -> bytes:
    """Return a new executable: the original's stub with a rebuilt overlay."""
    offset, embedded, _ = bgtlib.split_overlay(original)
    stub = original[:offset]

    if seed is None or flag is None or magic is None:
        info = bgtlib.unpack(original)
        seed = info.seed if seed is None else seed
        flag = info.container_flag if flag is None else flag
        magic = info.container_magic.encode() if magic is None else magic

    overlay = build_overlay(bytecode, seed=seed, flag=flag, magic=magic,
                            embedded=embedded if keep_embedded else b"")
    trailer = b"xproc10\x00" + struct.pack("<I", len(stub))
    return stub + overlay + trailer


def verify_roundtrip(new_exe: bytes, bytecode: bytes) -> bool:
    """Unpack what we just built and require the module back byte for byte."""
    got = bgtlib.unpack(new_exe).bytecode
    if got != bytecode:
        raise bgtlib.BgtError(
            "round-trip failed: recovered %d bytes, expected %d"
            % (len(got), len(bytecode)))
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", help="original BGT executable (supplies the PE stub)")
    ap.add_argument("bytecode", help="modified AngelScript module")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the unpack-and-compare check (not recommended)")
    args = ap.parse_args()

    with open(args.exe, "rb") as f:
        original = f.read()
    with open(args.bytecode, "rb") as f:
        bytecode = f.read()

    new_exe = repack(original, bytecode)
    if not args.no_verify:
        verify_roundtrip(new_exe, bytecode)
        print("round-trip verified: module recovers byte for byte")

    with open(args.output, "wb") as f:
        f.write(new_exe)

    print("stub      %d bytes (unchanged)" % bgtlib.read_trailer(new_exe))
    print("module    %d bytes" % len(bytecode))
    print("written   %s  (%d bytes, original was %d)"
          % (args.output, len(new_exe), len(original)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
