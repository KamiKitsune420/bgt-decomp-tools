"""
bgt_pack -- BGT's SFPv1 asset pack (pack_file / set_sound_storage).

Format read out of pack::create at 0x0047FFE0 in strike.exe, and confirmed by
parsing three shipped packs end-to-end with zero slack:

    header      "SFPv" u32 version(1) u32 entry_count u32 reserved(0)
    entry       "SFPv" u32 name_len u32 flags u32 data_size
                name[name_len]        (no NUL)
                data[data_size]

Entry payloads are usually encrypted, marked by a "SWCR" magic:

    swcr        "SWCR" u32 plain_size (written three times)
                tag[16]
                ciphertext[...]

`tag` is NOT an IV, which is how it was first read. It is a key-verification
tag equal to AES-256-ECB(key, 16 zero bytes) -- so a candidate password can be
checked without touching the ciphertext, and without knowing what the plaintext
should look like -- so checking a candidate key costs one AES block.

**Deriving the key from a password is UNSOLVED, so this module does not attempt it.**
You supply a key; it tells you whether the key is real and decrypts with it. See
"Sound-pack decryption" in CLAUDE.md for what is known and how people actually obtain
keys today (capture them at runtime).

Plain `SHA256(password)` is specifically ruled out -- do not reintroduce it.
"""

import os
import struct
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES


PACK_MAGIC = b"SFPv"
SWCR_MAGIC = b"SWCR"
ZERO16 = bytes(16)


class PackError(Exception):
    pass


class Entry:
    __slots__ = ("name", "flags", "offset", "size", "_data")

    def __init__(self, name: str, flags: int, offset: int, size: int,
                 data: Optional[bytes] = None) -> None:
        self.name = name
        self.flags = flags
        self.offset = offset
        self.size = size
        self._data = data

    @property
    def encrypted(self) -> bool:
        return self._data is not None and self._data[:4] == SWCR_MAGIC

    @property
    def plain_size(self) -> int:
        if not self.encrypted:
            return self.size
        return struct.unpack_from("<I", self._data, 4)[0]

    @property
    def tag(self) -> Optional[bytes]:
        """The 16-byte key-verification tag, or None if the entry is plaintext."""
        return self._data[16:32] if self.encrypted else None

    @property
    def ciphertext(self) -> Optional[bytes]:
        return self._data[32:] if self.encrypted else None

    @property
    def data(self) -> Optional[bytes]:
        return self._data

    def decrypt(self, key: bytes) -> Optional[bytes]:
        """Return the plaintext, or None if the key does not verify."""
        if not self.encrypted:
            return self._data
        if AES.new(key, AES.MODE_ECB).encrypt(ZERO16) != self.tag:
            return None
        out = AES.new(key, AES.MODE_ECB).decrypt(self.ciphertext)
        return out[:self.plain_size]

    def __repr__(self) -> str:
        return "<Entry %r %d B%s>" % (self.name, self.size,
                                      " SWCR" if self.encrypted else "")


def parse(path: str, load_data: bool = True) -> Tuple[int, List["Entry"]]:
    """Parse an SFPv1 pack. Returns (version, entries).

    Raises if the walk does not land exactly on EOF -- a pack that parses to the
    byte is proof the format is right, and silence about a short read is not.
    """
    entries = []
    total = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(16)
        if head[:4] != PACK_MAGIC:
            raise PackError("not an SFPv pack (magic %r)" % head[:4])
        version, count, _reserved = struct.unpack_from("<III", head, 4)
        if version != 1:
            raise PackError("unsupported pack version %d" % version)

        for i in range(count):
            rec = f.read(16)
            if len(rec) < 16 or rec[:4] != PACK_MAGIC:
                raise PackError("entry %d: bad record magic %r" % (i, rec[:4]))
            name_len, flags, size = struct.unpack_from("<III", rec, 4)
            name = f.read(name_len).decode("utf-8", "replace")
            offset = f.tell()
            data = f.read(size) if load_data else None
            if load_data and len(data) != size:
                raise PackError("entry %d (%s): short read" % (i, name))
            if not load_data:
                f.seek(size, 1)
            entries.append(Entry(name, flags, offset, size, data))

        pos = f.tell()
        if pos != total:
            raise PackError("walk ended at %d, file is %d bytes (%d unexplained)"
                            % (pos, total, total - pos))
    return version, entries


def encrypt_payload(plaintext: bytes, key: bytes) -> bytes:
    """Wrap plaintext as a SWCR blob under `key`.

    The header stores the plain size three times, exactly as the original writer
    does; the tag lets a reader confirm the key before touching ciphertext.
    """
    padded = plaintext + b"\x00" * ((-len(plaintext)) % 16)
    body = AES.new(key, AES.MODE_ECB).encrypt(padded)
    return (SWCR_MAGIC + struct.pack("<III", len(plaintext), len(plaintext),
                                     len(plaintext))
            + tag_for_key(key) + body)


def build(items: Iterable[Tuple[Union[str, bytes], bytes]]) -> bytes:
    """Serialise an SFPv1 pack from (name, data) pairs.

    `data` is written verbatim -- pass plaintext for an unencrypted entry, or the
    output of encrypt_payload() for an encrypted one. Round-trips through parse().
    """
    out = bytearray(PACK_MAGIC + struct.pack("<III", 1, len(items), 0))
    for name, data in items:
        if isinstance(name, str):
            name = name.encode("utf-8")
        out += PACK_MAGIC + struct.pack("<III", len(name), 0, len(data))
        out += name + data
    return bytes(out)


def replace(path: str, replacements: Dict[str, bytes],
            key: Optional[bytes] = None) -> bytes:
    """Rebuild a pack with some entries swapped, leaving the rest untouched.

    `replacements` maps entry name -> new plaintext bytes. Entries that were
    encrypted are re-encrypted with `key`; untouched entries keep their original
    bytes verbatim, so nothing is re-encoded that did not need to be.
    """
    _, entries = parse(path, load_data=True)
    items = []
    for e in entries:
        if e.name in replacements:
            new = replacements[e.name]
            if e.encrypted:
                if key is None:
                    raise PackError("%s is encrypted; a key is required to replace it"
                                    % e.name)
                new = encrypt_payload(new, key)
            items.append((e.name, new))
        else:
            items.append((e.name, e.data))
    return build(items)


def tag_index(entries: Sequence["Entry"]) -> Dict[bytes, List["Entry"]]:
    """Map verification tag -> list of entries, keyed by the AES-ECB(key, zeros) tag."""
    idx = {}
    for e in entries:
        if e.encrypted:
            idx.setdefault(e.tag, []).append(e)
    return idx


def key_matches(entries: Sequence["Entry"], key: bytes) -> List["Entry"]:
    """Return the entries a candidate key actually opens.

    Cheap enough to run over thousands of keys: one AES block per key, no
    ciphertext touched. This is the supported way in -- supply keys from wherever
    you obtained them (see the module docstring) and this tells you which are real.
    """
    tag = tag_for_key(key)
    return [e for e in entries if e.encrypted and e.tag == tag]


def tag_for_key(key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(ZERO16)


if __name__ == "__main__":
    import sys
    for path in sys.argv[1:]:
        version, entries = parse(path, load_data=True)
        enc = sum(1 for e in entries if e.encrypted)
        tags = tag_index(entries)
        print("%s: v%d, %d entries, %d encrypted, %d distinct keys"
              % (os.path.basename(path), version, len(entries), enc, len(tags)))
        for e in entries[:5]:
            print("   ", e)
