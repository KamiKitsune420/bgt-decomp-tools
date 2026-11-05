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
from typing import (Any, Dict, Iterable, List, Optional, Sequence,
                    Tuple, Union)

try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES


PACK_MAGIC = b"SFPv"
SWCR_MAGIC = b"SWCR"
#: magic + three copies of the plain size + the 16-byte key tag.
SWCR_HEADER = 4 + 12 + 16
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

    def load(self, source: Union[str, Any]) -> "Entry":
        """Fill this entry's payload from the pack, and return self.

        `parse(load_data=True)` keeps every payload in memory at once, which is
        the whole pack: Manamon 1's is 314 MB and Crazy Party's is larger, so
        extracting one meant holding all of it. An entry records its own
        offset, so reading them one at a time costs nothing and bounds the
        memory at the largest single entry.

        `source` is a path or an already-open file, because extraction wants
        one handle for two thousand entries and a caller with a path wants not
        to care.
        """
        self._data = payload(source, self)
        return self

    def unload(self) -> None:
        """Drop the payload again, once it has been written out."""
        self._data = None

    def __repr__(self) -> str:
        return "<Entry %r %d B%s>" % (self.name, self.size,
                                      " SWCR" if self.encrypted else "")


def payload(source: Union[str, Any], entry: "Entry") -> bytes:
    """One entry's stored bytes, read at the offset it recorded.

    A short read raises rather than returning what was there: the entry count
    in the header is what the engine trusts, so a payload that is not all
    present means the file is not the pack it claims to be, and half a sound
    written to disk is worse than none.
    """
    if isinstance(source, str):
        with open(source, "rb") as fh:
            fh.seek(entry.offset)
            data = fh.read(entry.size)
    else:
        source.seek(entry.offset)
        data = source.read(entry.size)
    if len(data) != entry.size:
        raise PackError("%s: short read (%d of %d bytes at %d)"
                        % (entry.name, len(data), entry.size, entry.offset))
    return data


def parse(path: str, load_data: bool = True) -> Tuple[int, List["Entry"]]:
    """Parse an SFPv1 pack. Returns (version, entries).

    Every record carries the `SFPv` magic again, and that is the per-entry
    self-check: a wrong field width desynchronises and the next magic fails.
    A short read inside an entry still raises, because that is the same
    failure caught one step later.

    **Bytes after the last entry are reported, not refused.** `pack::create`
    writes the entry count in the header and `pack_file` reads exactly that
    many, so the engine never looks past them -- a pack with a footer opens
    fine in the game. Crazy Party's `data.dat` has 32 such bytes after 2,425
    entries that every one of which validated, and refusing it meant the one
    pack the toolkit could not open was one the engine could. The count is
    left on `parse.trailing` for a caller that wants to say so.
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
        parse.trailing = total - pos
    return version, entries


#: Bytes left after the last entry of the most recent `parse`, which the
#: engine ignores. Non-zero means the pack carries a footer of some kind.
parse.trailing = 0


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


def _pack_header(count: int) -> bytes:
    return PACK_MAGIC + struct.pack("<III", 1, count, 0)


def _entry_header(name: Union[str, bytes], size: int, flags: int = 0) -> bytes:
    """One entry's record, up to but not including its payload.

    Shared with `rebuild` so the layout has one definition: two writers of one
    format drift, and the drift is silent.
    """
    if isinstance(name, str):
        name = name.encode("utf-8")
    return PACK_MAGIC + struct.pack("<III", len(name), flags, size) + name


def build(items: Iterable[Tuple[Union[str, bytes], bytes]]) -> bytes:
    """Serialise an SFPv1 pack from (name, data) pairs.

    `data` is written verbatim -- pass plaintext for an unencrypted entry, or the
    output of encrypt_payload() for an encrypted one. Round-trips through parse().

    The whole pack is assembled in memory, which is fine for building one and
    not for rewriting a shipped one: see `rebuild` for that.
    """
    items = list(items)
    out = bytearray(_pack_header(len(items)))
    for name, data in items:
        out += _entry_header(name, len(data)) + data
    return bytes(out)


def rebuild(path: str, out_path: str, keep: Optional[Iterable[str]] = None,
            drop: Optional[Iterable[str]] = None,
            chunk: int = 1 << 20) -> Dict[str, Any]:
    """Copy a pack with some entries left out, WITHOUT holding it in memory.

    `build` and `replace` assemble the result as one `bytes`, so neither can
    rewrite a shipped pack: Crazy Party's is 372 MB, and this machine has
    killed runs for memory more than once. This streams instead -- the entry
    table comes from `parse(load_data=False)`, which already gives each
    entry's offset, size and flags, and each kept payload is copied a chunk
    at a time. Nothing is re-encoded, so an encrypted entry needs no key.

    Exactly one of `keep` and `drop` is given, as entry names. **A name that
    is in neither the pack nor the result is reported** rather than ignored,
    because a typo in a drop list is otherwise a silent no-op that looks
    exactly like a successful trim.

    Returns a summary: how many entries were kept and dropped, the bytes
    written, and any names that matched nothing.
    """
    if (keep is None) == (drop is None):
        raise PackError("pass exactly one of keep= and drop=")
    if os.path.abspath(path) == os.path.abspath(out_path):
        raise PackError("rebuild writes a new pack; out_path must differ")

    _version, entries = parse(path, load_data=False)
    wanted = {str(n) for n in (keep if keep is not None else drop)}
    names = {e.name for e in entries}
    if keep is not None:
        chosen = [e for e in entries if e.name in wanted]
    else:
        chosen = [e for e in entries if e.name not in wanted]

    written = 0
    with open(path, "rb") as src, open(out_path, "wb") as out:
        out.write(_pack_header(len(chosen)))
        for e in chosen:
            out.write(_entry_header(e.name, e.size, e.flags))
            src.seek(e.offset)
            left = e.size
            while left:
                block = src.read(min(chunk, left))
                if not block:
                    raise PackError("entry %s: short read at %d bytes left"
                                    % (e.name, left))
                out.write(block)
                left -= len(block)
            written += e.size
        total = out.tell()
    return {"kept": len(chosen), "dropped": len(entries) - len(chosen),
            "payload_bytes": written, "pack_bytes": total,
            "unmatched": sorted(wanted - names)}


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


def survey(path: str, sample: int = 0) -> Dict[str, Any]:
    """What a pack holds, without reading its payloads.

    A 372 MB pack cannot be loaded to answer "is it encrypted?", and asking
    `tag_index` without data silently answers "no keys", because the `SWCR`
    tag lives in the payload it did not read. So the header of each entry is
    read directly -- 20 bytes at a known offset -- which is cheap and cannot
    give that wrong answer.

    `sample` limits how many entries are probed; 0 reads them all.
    """
    version, entries = parse(path, load_data=False)
    trailing = parse.trailing
    probe = entries if not sample else entries[:sample]
    tags, encrypted, plain = set(), 0, 0
    with open(path, "rb") as fh:
        for entry in probe:
            fh.seek(entry.offset)
            head = fh.read(SWCR_HEADER)
            if head[:4] == SWCR_MAGIC and len(head) == SWCR_HEADER:
                encrypted += 1
                tags.add(bytes(head[16:32]))
            else:
                plain += 1
    return {"path": path, "version": version, "entries": len(entries),
            "size": os.path.getsize(path), "trailing": trailing,
            "probed": len(probe), "encrypted": encrypted, "plain": plain,
            # The tags themselves, not only how many: a key search needs them,
            # and they are the whole of what it needs -- one AES block against
            # a tag decides a candidate without touching any ciphertext.
            "keys": len(tags), "tags": sorted(tags)}


def _require_payloads(entries: Sequence["Entry"], asking: str) -> None:
    """Refuse a question about payloads that were never read.

    The `SWCR` tag lives in the payload, so after `parse(load_data=False)`
    every entry's `encrypted` is False -- and the two functions below would
    then answer "no keys" and "this key opens nothing". Those are verdicts
    from a check that never ran, which is the worst shape there is: a correct
    key reported as opening 0 of 1,153 entries is indistinguishable from a
    wrong one, and that is how The Gate's key looked for several minutes.

    `survey(path)` is the cheap way to ask -- it reads each entry's header at
    its recorded offset -- and `Entry.load(handle)` fills them one at a time.
    """
    if entries and all(e.data is None for e in entries):
        raise PackError(
            "%s needs each entry's payload and not one was read: use "
            "parse(..., load_data=True), or Entry.load(handle) per entry, or "
            "survey(path), which reads the headers instead" % asking)


def tag_index(entries: Sequence["Entry"]) -> Dict[bytes, List["Entry"]]:
    """Map verification tag -> list of entries, keyed by the AES-ECB(key, zeros) tag."""
    _require_payloads(entries, "tag_index")
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

    It needs the payloads, because that is where the tag is; handed entries
    that were never filled it refuses rather than answering 0.
    """
    _require_payloads(entries, "key_matches")
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
