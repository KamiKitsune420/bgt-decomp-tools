"""Scan a minidump for AES-256 key schedules.

The expanded schedule (60 words, 240 bytes) is self-validating: every word
W[i] for i >= 8 must equal W[i-8] XOR T(W[i-1]) where T applies the AES
key-schedule transform (SubWord/RotWord + rcon when i % 8 == 0, SubWord only
when i % 8 == 4).  Two vectorized equations cut candidates to ~2**-64, then
survivors are fully validated in Python.  The original key is W[0..7]
(the first 32 bytes of the schedule).

Usage: python keyscan.py <dumpfile> [<dumpfile> ...]
"""
from __future__ import annotations

import struct
import sys

# AES-256 key schedule constants
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)


def validate_full(words: list[int]) -> bool:
    """Check a little-endian 60-word AES-256 encryption schedule."""
    if len(words) != 60:
        return False
    for i in range(8, 60):
        t = words[i - 1]
        if i % 8 == 0:
            t = ((t >> 8) | (t << 24)) & 0xffffffff
        if i % 8 in (0, 4):
            t = sum(SBOX[(t >> (8*j)) & 255] << (8*j) for j in range(4))
        if i % 8 == 0:
            t ^= RCON[i // 8 - 1]
        if words[i] != words[i - 8] ^ t:
            return False
    return True


def find_schedules(data, chunk_size=1 << 20):
    """Scan every byte alignment with bounded NumPy working arrays.

    NumPy is an optional dependency for this diagnostic, not for recovery.
    """
    import numpy as np
    if chunk_size < 1:
        raise ValueError("chunk size must be positive")
    sbox = np.frombuffer(SBOX, dtype=np.uint8)
    for start in range(0, max(0, len(data) - 239), chunk_size):
        count = min(chunk_size, len(data) - 239 - start)
        def word(index):
            return np.ndarray((count,), dtype="<u4", buffer=data,
                              offset=start + 4*index, strides=(1,))
        previous = word(7)
        rotated = (previous >> 8) | (previous << 24)
        sub = sum(sbox[(rotated >> (8*j)) & 255].astype(np.uint32) << (8*j)
                  for j in range(4))
        hits = np.nonzero((word(8) == (word(0) ^ sub ^ 1)) &
                         (word(9) == (word(1) ^ word(8))))[0]
        for index in hits:
            offset = start + int(index)
            words = list(struct.unpack_from("<60I", data, offset))
            if validate_full(words):
                yield offset, struct.pack("<8I", *words[:8])


def scan_dump(path: str) -> None:
    import mmap
    import os
    with open(path, "rb") as file:
        size = os.fstat(file.fileno()).st_size
        print(f"{path}: {size:,} bytes")
        if size < 240:
            return
        seen = set()
        with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            for offset, key in find_schedules(data):
                if key in seen:
                    continue
                seen.add(key)
                print(f"  *** VALID SCHEDULE at file offset {offset:#x} ***")
                print(f"      key: {key.hex()}")
        if not seen:
            print("  no valid schedule found")


def main(argv: list[str] | None = None) -> int:
    paths = sys.argv[1:] if argv is None else argv
    if not paths:
        print(__doc__)
        return 2
    for path in paths:
        scan_dump(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
