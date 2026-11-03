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

Every step here was read out of a game's own runtime with Ghidra rather than
inferred from byte patterns -- `asCReader` and the chain above are statically
linked into every BGT executable, so the build in front of you describes
itself. The key seed and the key GENERATOR are both searched rather than
assumed, so a build that changed either still opens: the 2010 engine advances
its key material by addition where every later one multiplies.
"""

import hashlib
import struct
from dataclasses import dataclass
from typing import Iterator, NamedTuple, Optional, Sequence, Tuple

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


def pe_image_end(data: bytes) -> int:
    """File offset just past the last section's raw data, or 0 if unreadable."""
    try:
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e:e + 4] != b"PE\0\0":
            return 0
        n = struct.unpack_from("<H", data, e + 6)[0]
        optsz = struct.unpack_from("<H", data, e + 20)[0]
        end = 0
        for k in range(n):
            b = e + 24 + optsz + 40 * k
            rsize, raw = struct.unpack_from("<II", data, b + 16)
            if rsize:
                end = max(end, raw + rsize)
        return end
    except struct.error:
        return 0


def trailer_is_stale(data: bytes, offset: int) -> bool:
    """True when the overlay was found somewhere other than where the trailer
    says -- the file was rewritten, and BGT's own loader will not find it."""
    try:
        return read_trailer(data) != offset
    except BgtError:
        return False


def _overlay_body(data: bytes) -> Tuple[int, bytes]:
    """The overlay's bytes and the offset they really start at.

    The trailer stores an absolute file offset, so anything that rewrites the
    PE part of the file (`upx -d`, a resource editor) leaves it pointing at the
    wrong place while the overlay itself moves intact to the new end of the
    image. Look there when the trailer's offset does not open on a pack-size
    field. Nothing is trusted on this basis alone: the AES and container layers
    still have to verify what is found.
    """
    offset = read_trailer(data)
    body = data[offset:len(data) - TRAILER_LEN]

    i = body.find(b" ", 0, 16)
    if i < 0 or (not body[:i].isdigit() and body[:i]):
        pe_end = pe_image_end(data)
        moved = data[pe_end:len(data) - TRAILER_LEN] if pe_end else b""
        j = moved.find(b" ", 0, 16)
        if pe_end and pe_end != offset and j >= 0 and (moved[:j].isdigit() or j == 0):
            return pe_end, moved
    return offset, body


def overlay_candidates(data: bytes) -> Iterator[Tuple[int, bytes, bytes]]:
    """Every reading of the overlay, the better-evidenced one first.

    FUN_00472760 reads an ASCII decimal terminated by a space. That number is
    the size of an optional pack file appended ahead of the script -- BGT can
    bundle sounds into the exe. It is 0 in almost every title, which is why the
    field usually reads as the two bytes `"0 "`.

    **The 2010 engine writes no such field**: its overlay opens on the
    ciphertext. Grodan Gun and Ljudfarmen are both that shape, and it is the
    third thing that generation does differently, after the key generator and
    the absent compression -- and the one that would have kept them shut even
    with the right key, because this reader required the field.

    Both readings are offered rather than chosen, because the container header
    verifies itself: 32 hex characters and an `=` cannot come out of the wrong
    split. The field reading is yielded first, so a build that has one can
    never be re-described as one that has not -- the same tie-break every
    per-build field in this toolkit is trialled under.
    """
    offset, body = _overlay_body(data)

    i = body.find(b" ", 0, 16)
    if i >= 0 and (body[:i].isdigit() or i == 0):
        n = int(body[:i] or b"0")
        if i + 1 + n <= len(body):
            start = i + 1
            yield offset, (body[start:start + n] if n else b""), body[start + n:]

    yield offset, b"", body


def split_overlay(data: bytes) -> Tuple[int, bytes, bytes]:
    """The overlay's best-evidenced reading as (offset, embedded_pack, ciphertext).

    This is the single answer for callers that only need where the overlay is
    -- a repack, an identification. `unpack` trials every reading instead,
    because it has the container header to judge them with.
    """
    for reading in overlay_candidates(data):
        return reading
    raise BgtError("no overlay")


# --------------------------------------------------------------------------
# layer 2 -- the key, and AES
# --------------------------------------------------------------------------

#: How a BGT build advances its key material: the 2014 and 2011 engines
#: multiply by three, and the 2010 engine adds three. The two generators were
#: read out of the two installs and are otherwise identical instruction for
#: instruction -- same clamps, same 32 iterations, same 33-byte buffer with a
#: trailing NUL -- so the arithmetic is the whole difference:
#:
#:     BGT 1.3, 0x084E68    lea ebx,[ebx+ebx*2]    v = v * 3
#:     BGT 1.0, 0x076BE8    add ecx, 3             v = v + 3
#:
#: That controlled comparison is the evidence: everything a wrong reading
#: could have coincided on matches, and one instruction does not.
MULTIPLY = "multiply"
ADD = "add"
#: The verified variant first, so a tie keeps the reading this library held.
KEY_VARIANTS = (MULTIPLY, ADD)

#: How a build turns its key material into an AES-256 key. Every title this
#: toolkit opened before took SHA-256 of the material; **a BGT BETA takes MD5
#: and repeats it** to reach 32 bytes. Palace Punch-up is one -- a runtime
#: dated 2010-07-07, five months before 1.0, registering 177 names against
#: 1.0's 240, and built on AngelScript 2.19 -- and its key GENERATOR is
#: byte-identical to 1.0's, so the material is the same function of the seed
#: and only the digest differs.
#:
#: This is one of the "two earlier encryption methods" issue #6 reports, found
#: by crossing the seed, the derivation and the cipher mode and letting the
#: container header say which combination was right.
SHA256 = "sha256"
MD5X2 = "md5x2"
KEY_DERIVATIONS = (SHA256, MD5X2)


def keygen(seed: int = 0x11, variant: str = MULTIPLY) -> bytes:
    """Reproduce FUN_00441D90 -- the key material, generated rather than stored.

    This is why no string search ever finds a key in a BGT executable.
    For the stock seed 0x11 it produces 33 05 0f 2d then (05 0f 2d) repeating.

    `variant` selects the arithmetic; see `KEY_VARIANTS`. A 2010 title opens
    under `ADD` and under nothing else, which is why a toolchain that knew
    only `MULTIPLY` reported those games as not BGT at all.
    """
    if variant not in KEY_VARIANTS:
        raise BgtError("unknown key variant %r" % variant)
    out = bytearray()
    v = seed
    for _ in range(32):
        v = v * 3 if variant == MULTIPLY else v + 3
        if v >= 0x80:
            v = 5
        elif v == 0:
            v = 0xD
        out.append(v & 0xFF)
    return bytes(out)


def aes_key_for_seed(seed: int = 0x11, variant: str = MULTIPLY,
                     derivation: str = SHA256) -> bytes:
    """AES-256 key = SHA256(key material). IV is the first 16 bytes of the same digest.

    BGT uses the AES reference API (rijndael-api-fst.c), which takes key material as
    a hex ASCII string -- makeKey() is handed the 64-char hex of this digest, and
    cipherInit() reads 32 hex chars of it back as the IV.

    So the hex is where the key material goes IN, not what the key is: the
    reference API parses those 64 characters straight back into the 32 bytes
    of this digest. Hashing the hex text instead would be that conversion
    applied twice, and would open nothing.
    """
    material = keygen(seed, variant)
    if derivation == SHA256:
        return hashlib.sha256(material).digest()
    if derivation == MD5X2:
        return hashlib.md5(material).digest() * 2
    raise BgtError("unknown key derivation %r" % derivation)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    n = len(ciphertext) - len(ciphertext) % 16
    return AES.new(key, AES.MODE_CBC, key[:16]).decrypt(ciphertext[:n])


# --------------------------------------------------------------------------
# layer 3 -- the BGT container header
# --------------------------------------------------------------------------

def parse_container(plaintext: bytes) -> Tuple[Optional[int], bytes]:
    """Parse "<32 hex>=<flag> printf<length>\\0" and return (flag, blob).

    The header is fixed-shape but not fixed-length: the declared length is decimal,
    so a bigger module means a longer header. Psycho Strike's is 48 bytes,
    Manamon 2's is 49. Compute it, never hardcode it.
    """
    # **A BETA writes no edition field at all**: its header is 32 hex
    # characters, a space and then `printf<len>`, where every later build
    # writes `=<edition> printf<len>`. So the `=` is looked for and its
    # absence is a shape rather than an error, and the flag comes back None.
    eq = plaintext.find(b"=", 0, 48)
    if eq < 0:
        sp = plaintext.find(b" ", 0, 48)
        if sp != 32:
            raise BgtError("no '=' in container header, and no space at 32 "
                           "where a beta would put one")
    else:
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

    flag = int(plaintext[eq + 1:sp]) if eq >= 0 else None
    header_len = nul + 1
    blob = plaintext[header_len:header_len + declared]
    if len(blob) != declared:
        raise BgtError("container declares %d bytes, only %d present"
                       % (declared, len(blob)))
    return flag, blob


#: BGT's editions, as the engine itself names them -- BGT 1.0 prints "BGT
#: lite|pro unlimited|pro single version 1.0 was registered successfully".
#: The container flag is which one built the game. Only 3 occurs in the
#: titles here, so the other two numbers are as reported rather than seen.
EDITIONS = {2: "BGT lite", 3: "BGT pro unlimited", 4: "BGT pro single"}

#: The second built-in key, for the licence mark: the same generator at seed
#: 0x3F. BGT's 2014 build puts its output through a further derivation before
#: use, and since that derivation's input is fixed, its result is a constant --
#: reported in issue #6, found by emulating the function at 0x4903D0 in the
#: `bgt.exe` of 2014-06-01, which is the 1.3 this toolkit is developed against.
#:
#: It needs no separate verification because the plaintext verifies it: a wrong
#: key cannot produce the literal `printf`, ASCII digits and a NUL. It decodes
#: Super Egg Hunt, Manamon 1 and The Gate -- three developers, 2014 to 2017.
LICENCE_KEY_2014 = bytes.fromhex(
    "465b2c2743b1855f5a8e0fa520860626a8708808899f8763e6b8233221cb028c"
    "70bfc75445d26867d6c02214fc2fd6ee4813293755e3874881c0bf824a16207d")


class Licence(NamedTuple):
    """The licence a BGT game was built under, out of its container header."""
    code: str
    #: Which of the three keys read it, which dates the build.
    key: str


def licence_mark(magic: str) -> Optional[Licence]:
    """Read the container's 32 hex characters as the licence mark they are.

    This field has been used here as a validity check -- 32 hex characters
    followed by `=` is a strong enough constraint to identify the right
    overlay key. It is not a checksum: it is one AES block under a second
    built-in key, holding `printf<n>\\0` and then an n-character licence code,
    and `*` means the game was built with no licence code at all.

    Returns None when no known key reads it, which is the honest answer for a
    build whose derivation is not one of these three.

    **It is the edition's mark, not the module's.** Super Egg Hunt, Manamon 1
    and The Gate carry byte-identical fields -- three developers across three
    years -- so nothing here is derived from the game, which is the other half
    of why it cannot be a checksum. All three read `*` against edition 3, "pro
    unlimited", so the code looks like a wildcard standing for "no particular
    game" rather than for an absent licence; a "pro single" build is where a
    real code would be expected, and none is on this machine to confirm it.
    """
    try:
        block = bytes.fromhex(magic)
    except ValueError:
        return None
    for name, material in (("derived-2014", LICENCE_KEY_2014),
                           ("2011", keygen(0x3F, MULTIPLY)),
                           ("2010", keygen(0x3F, ADD))):
        key = hashlib.sha256(material).digest()
        plain = AES.new(key, AES.MODE_CBC, key[:16]).decrypt(block)
        tag, _, rest = plain.partition(b"\x00")
        if tag.startswith(b"printf") and tag[6:].isdigit():
            return Licence(rest[:int(tag[6:])].decode("latin1"), name)
    return None


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


class KeyChoice(NamedTuple):
    """Which key opened an overlay: the seed, the key itself, and the variant.

    A named tuple rather than a pair, because the variant decides whether the
    payload is compressed as well -- so code that unpacks this into two names
    fails loudly instead of silently dropping the half that was added.
    """
    seed: int
    key: bytes
    variant: str
    #: Which digest turned the key material into the key -- `SHA256` for every
    #: build from 1.0 onward, `MD5X2` for a beta. It decides the payload's
    #: shape as much as the variant does, so it travels with them.
    derivation: str = SHA256


def find_seed(ciphertext: bytes,
              candidates: Optional[Sequence[int]] = None,
              variants: Sequence[str] = KEY_VARIANTS,
              derivations: Sequence[str] = KEY_DERIVATIONS) -> KeyChoice:
    """Recover the key by trial decryption of the first block.

    Only the first 32 bytes matter -- the container header starts with 32 hex
    characters, which is a strong enough constraint that a wrong key is never
    mistaken for a right one. Costs one AES block per candidate.

    Both the seed and the generator's arithmetic are searched, because both
    vary between builds and neither is stored. The stock seed and the verified
    variant are tried first, so a build this library already opened cannot be
    re-described by the wider search.
    """
    if candidates is None:
        candidates = [0x11] + [s for s in range(1, 256) if s != 0x11]
    probe = ciphertext[:64]
    for derivation in derivations:
        for variant in variants:
            for seed in candidates:
                key = aes_key_for_seed(seed, variant, derivation)
                head = decrypt(probe, key)
                if not all(c in b"0123456789ABCDEFabcdef" for c in head[:32]):
                    continue
                # Every build from 1.0 on writes `=<edition>` here; a beta
                # writes a space straight after the 32 characters, and
                # `printf` is what separates that from a coincidence.
                if b"=" in head[32:40]:
                    return KeyChoice(seed, key, variant, derivation)
                if head[32:33] == b" " and head[33:39] == b"printf":
                    return KeyChoice(seed, key, variant, derivation)
    raise BgtError("no key in the search space decrypts to a BGT container "
                   "header (tried %d seeds x %s x %s)"
                   % (len(candidates), "/".join(variants),
                      "/".join(derivations)))


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
    #: Which key generator opened it, and so whether `compressed` really is
    #: compressed: the 2010 engine stores the module as it stands.
    key_variant: str = MULTIPLY
    #: Which digest turned the key material into the AES key -- `SHA256` for
    #: every build from 1.0 onward, `MD5X2` for a beta.
    key_derivation: str = SHA256

    def __repr__(self) -> str:
        return ("<Unpacked overlay=0x%X seed=0x%02X container_flag=%s "
                "bytecode=%d B>" % (self.overlay_offset, self.seed,
                                    self.container_flag, len(self.bytecode)))


#: String record tags in the dialect every early build uses: a new string, a
#: back-reference, and the empty string.
_STRING_TAGS = (0x6E, 0x72, 0x00)


def _plain_eu(buf: bytes, p: int) -> Tuple[int, int]:
    """The early generations' encoded integer: a plain base-128 varint.

    Read out of `asCWriter::WriteEncodedUInt` in a 2011 runtime: `v < 0x80` is
    one byte, and otherwise the lead byte is `0x80 | (v >> 8)` and the next is
    `v & 0xFF`. **The newer engines spend the lead byte's top bit on a SIGN
    flag**, so they switch to a wide form at 64 where these switch at 128 --
    which is why `as_module`'s reader stops 63 bytes into one of these modules.
    """
    b = buf[p]
    p += 1
    if b < 0x80:
        return b, p
    for mask, match, keep, extra in ((0xC0, 0x80, 0x3F, 1),
                                     (0xE0, 0xC0, 0x1F, 2),
                                     (0xF0, 0xE0, 0x0F, 3)):
        if (b & mask) == match:
            v = b & keep
            for _ in range(extra):
                v = (v << 8) | buf[p]
                p += 1
            return v, p
    raise BgtError("unreadable encoded integer 0x%02X" % b)


def early_module_head(payload: bytes) -> Optional[str]:
    """None if `payload` opens like an early module, else why it does not.

    **The early generations write no `noDebugInfo` byte.** Their module opens
    on the enum count -- read off `asCWriter::WriteInner`, whose first call is
    `WriteEncodedUInt(enumTypes.length)` and whose loop then writes each type's
    name, a four-byte flags field and a size. Confirmed on five titles, from
    the 2010 beta to 2012: Palace Punch-up declares one enum
    (`computer_states`, three values) and six classes, Grodan Gun none and
    nine, Ljudfarmen none and five, Perilous Hearts none and fifteen, Antony
    none and seven.

    This replaces a guard that required the first byte to be 0 or 1 "because
    `noDebugInfo` is the module's first byte". That byte is the **enum count**
    in these builds, and the guard passed only because these games declare no
    enums or one -- which is the most dangerous way for a check to be right.
    """
    try:
        enums, p = _plain_eu(payload, 0)
        if enums > 4096:
            return "implausible enum count %d" % enums
        if enums:
            if payload[p] not in _STRING_TAGS:
                return ("%d enums but no string tag after the count "
                        "(0x%02X)" % (enums, payload[p]))
            return None
        classes, p = _plain_eu(payload, p)
        if classes > 1 << 16:
            return "implausible class count %d" % classes
        if classes and payload[p] not in _STRING_TAGS:
            return ("%d classes but no string tag after the count (0x%02X)"
                    % (classes, payload[p]))
    except (IndexError, BgtError) as exc:
        return "%s" % exc
    return None


def unpack(data: bytes, seed: Optional[int] = None) -> Unpacked:
    """Run the full chain over the bytes of a BGT executable.

    Every reading of the overlay is tried, best-evidenced first, because the
    2010 engine writes no pack-size field and this is the layer that can tell:
    a wrong split cannot produce the container's 32 hex characters and `=`.
    """
    failed: Optional[BgtError] = None
    for reading in overlay_candidates(data):
        try:
            return _unpack_overlay(reading, seed)
        except BgtError as exc:
            failed = failed or exc
    raise failed or BgtError("no overlay")


def _unpack_overlay(reading: Tuple[int, bytes, bytes],
                    seed: Optional[int]) -> Unpacked:
    overlay_offset, embedded, ciphertext = reading

    if seed is None:
        seed, key, variant, derivation = find_seed(ciphertext)
    else:
        variant, derivation = MULTIPLY, SHA256
        key = aes_key_for_seed(seed, variant, derivation)

    plaintext = decrypt(ciphertext, key)
    flag, blob = parse_container(plaintext)
    if variant == ADD or derivation == MD5X2:
        # **The early engines do not compress.** There is no LZ77 step and no
        # trailing " <length>" to read one back from: the number after
        # `printf` is the bytecode's own length, so the container's payload is
        # the module. True of the 2010 and 2011 builds, which this keys on the
        # generator, and of the beta, which keys on the derivation -- a beta
        # whose payload is 55,859 bytes against a container declaring 55,859.
        # Checked below rather than assumed.
        comp = blob
        bytecode = blob
        why = early_module_head(blob)
        if why is not None:
            raise BgtError("an early-key overlay whose payload does not read "
                           "as a module head (%s) -- it may be compressed "
                           "after all" % why)
    else:
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
        key_variant=variant,
        key_derivation=derivation,
    )


def unpack_file(path: str, seed: Optional[int] = None) -> Unpacked:
    with open(path, "rb") as f:
        return unpack(f.read(), seed=seed)
