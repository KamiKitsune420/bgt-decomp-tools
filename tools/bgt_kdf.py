"""
bgt_kdf -- BGT's password -> AES-key derivation.

The routine between a script's set_sound_decryption_key(password) and the AES key its
packs are encrypted with. Transcribed instruction by instruction from the decompiled
BGT runtime, not inferred from behaviour.

VERIFIED end to end: it recovers a shipped title's pack key, which then opens
974 / 974 encrypted entries, every one decrypting to valid Ogg Vorbis. It also
reproduces a key captured independently at runtime with Frida from a second title.

    KDF(input) -> 64 bytes, guaranteed free of NUL

Shape:

    A = 98-byte buffer, B = 65-byte buffer, both zeroed
    seed = first byte of `input` with the high bit set, else '#'
    seed = (seed - 4) * seed                     (signed char arithmetic)
    state = 16 bits: high = seed, low = seed - 1

    fill(A):  for each of 98 bytes
                  c = low byte of state (signed)
                  if c == 0: c = -0x12
                  c = (int)c / (seedInt + c*2 + 8)      C division, truncates to zero
                  if c == 0: c = highByte(state) + 'c'
                  state = (state & 0xff00) | (c & 0xff)
                  A[i] = c

    sha512 = SHA-512()                            (verified: the stock IV)
    fill(A);  sha512.update(A)                    <- first 98 bytes
    fill(A);                                      <- generator CONTINUES, new bytes
    sha512.update(input)
    sha512.update(A)                              <- the second 98 bytes
    B = sha512.digest()

    for i in 0..63:                               <- make the digest NUL-free
        if B[i] == 0:
            c = (-11 * (i + 1)) & 0xff
            B[i] = c if c else 0x83

Two details worth stating because they are easy to get wrong:

* The two fill loops are written differently in the decompilation -- `(c + 4) * 2`
  versus `c * 2 + 8` -- but those are the same expression. It is one generator run
  twice, with `state` carrying across, so the second 98 bytes differ from the first.
* `char` here is **signed**, the divide is C integer division (truncating toward
  zero, not floor), and `(int)c` sign-extends. Getting any of these wrong yields a
  plausible-looking 64 bytes that is simply not the key.
"""

import hashlib
from typing import Dict, Tuple, Union


def _sc(v: int) -> int:
    """Truncate to a signed 8-bit char, as the C code does at every assignment."""
    v &= 0xFF
    return v - 0x100 if v >= 0x80 else v


def _cdiv(a: int, b: int) -> int:
    """C integer division: truncates toward zero, unlike Python's floor division."""
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


_CACHE: Dict[int, Tuple[bytes, bytes]] = {}


def _salts(pre_seed: int) -> Tuple[bytes, bytes]:
    """The two 98-byte salts for a given pre-transform seed byte.

    They depend on nothing but that byte, so they are worth caching: the generator
    is 196 iterations of Python and would otherwise dominate any bulk search.
    """
    got = _CACHE.get(pre_seed)
    if got is None:
        got = _CACHE[pre_seed] = _gen_salts(pre_seed)
    return got


def _seed_of(data: bytes) -> int:
    """First byte with the high bit set, else '#' -- the only input-dependent part."""
    for b in data:
        if b >= 0x80:
            return _sc(b)
    return 0x23


def kdf(data: Union[bytes, str]) -> bytes:
    """Return the 64-byte NUL-free derived value for `data`."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    first, second = _salts(_seed_of(data))
    h = hashlib.sha512()
    h.update(first)
    h.update(data)
    h.update(second)
    out = bytearray(h.digest())
    for i in range(0x40):
        if out[i] == 0:
            c = (-11 * (i + 1)) & 0xFF
            out[i] = c if c else 0x83
    return bytes(out)


def _gen_salts(seed: int) -> Tuple[bytes, bytes]:
    """Run the generator twice, exactly as FUN_00458800 does."""
    seed = _sc((seed - 4) * seed)
    seed_int = seed                      # sign-extended to int in the original
    hi = seed & 0xFF                     # high byte of the 16-bit state
    lo = _sc(seed - 1)                   # low byte

    def fill():
        out = bytearray()
        nonlocal lo
        for _ in range(0x62):            # 98 bytes
            c = lo
            if c == 0:
                c = -0x12
            div = seed_int + c * 2 + 8
            if div == 0:                 # would trap in the original; never seen
                raise ZeroDivisionError("KDF divisor hit zero")
            c = _sc(_cdiv(c, div))
            if c == 0:
                c = _sc(_sc(hi) + 0x63)
            lo = c
            out.append(c & 0xFF)
        return bytes(out)

    return fill(), fill()                # one generator, run twice; state carries


def aes_key(password: Union[bytes, str]) -> bytes:
    """The pack's AES-256 key: SHA256 over the derived value."""
    return hashlib.sha256(kdf(password)).digest()


if __name__ == "__main__":
    import sys
    for arg in sys.argv[1:] or ["test"]:
        d = kdf(arg)
        print("%-20r kdf=%s..." % (arg, d.hex()[:48]))
        print("%-20s key=%s" % ("", aes_key(arg).hex()))
        print("%-20s nul-free=%s" % ("", 0 not in d))
