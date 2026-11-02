r"""`bgt installer` -- the game inside an Inno Setup installer, without running it.

Almost every BGT game that is still downloadable ships as an Inno Setup
installer, and the two things one would normally reach for are both wrong here:
running somebody's installer to get at a game is not a thing to do on a
stranger's machine, and the standard extraction tool is a binary to fetch and
execute. So this reads the installer instead, which needs nothing fetched and
executes nothing.

**What makes it tractable is that the thing being looked for carries its own
extent.** A BGT executable ends with `xproc10\0` and a little-endian stub
length, so once the payload is in hand each game can be cut out of it exactly,
and `bgtlib.unpack` -- the container header, the declared length, the module's
own first byte -- is what accepts the cut. The guessing is all in the
candidates; the acceptance is the format's own self-verification. That is why
this does not need to parse the installer's file list at all, and why it can
ignore the names and directories the installer would have written.

Three layers, each read from the format rather than guessed:

1. **The payload.** A single-file Inno 5.x setup stores the files as one chunk
   introduced by `zlb\x1a`, followed by an LZMA1 stream -- a properties byte
   and a four-byte dictionary size, with no uncompressed length, so the stream
   is decoded with an unknown output size and whatever arrives is kept. The
   setup *header* is a separate block behind its own `Inno Setup Setup Data`
   id, and it is not needed: it holds the names.

2. **The filter.** Inno rewrites the operand of every `call` and `jmp` in that
   stream before compressing it, because absolute addresses compress better
   than relative ones. It does this to the WHOLE stream, so an `0xE8` inside a
   game's compressed module is rewritten too -- which is how this presents
   itself if you miss it: the container header decrypts perfectly, the blob
   carries its usual trailing length, and the LZ77 decode then yields eleven
   kilobytes of a real module before going wrong. Undoing it is five lines and
   is the whole difference between a payload that opens and one that looks like
   a new engine generation.

3. **The carve**, above.

The filter has two forms: from Inno 5.3.9 the high byte flips when bit 23 of
the relative value is set, and before that it does not. The installer states
its own version in its `Inno Setup Setup Data (x.y.z)` id, so that is read
rather than assumed -- and where the id cannot be read, both are tried, since
a wrong choice shows up as a game that will not open.

    bgt installer game_installer.exe -o out/

Checked against four of BlastBay's own installers: Antony, Grodan Gun and
Ljudfarmen each yield exactly one BGT executable that `bgt unpack` opens, and
Q9 yields none, because Q9 is not a BGT game at all -- it is native code that
happens to use BGT's pack format for its sounds.
"""

from __future__ import annotations

import argparse
import lzma
import os
import re
import struct
import sys
from typing import Iterator, List, Optional, Tuple

try:
    from . import bgtlib
except ImportError:  # run directly
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import bgtlib

#: Inno's chunk introducer, ahead of the compressed file data.
CHUNK_MAGIC = b"zlb\x1a"

#: The id that precedes a setup data section, carrying the version in brackets.
DATA_ID = re.compile(rb"Inno Setup Setup Data \(([0-9]+)\.([0-9]+)\.([0-9]+)[^)\x00]{0,20}\)")

#: Inno's call-instruction filter works in blocks of this size, aligned on the
#: stream's own offsets.
FILTER_BLOCK = 0x10000

#: How far back from an overlay a stub may begin. A BGT runtime is about a
#: megabyte; this is generous and only bounds the search.
MAX_STUB = 1 << 23


class InstallerError(Exception):
    """Raised when an installer holds nothing this can read."""


# --------------------------------------------------------------------------
# layer 1 -- the payload
# --------------------------------------------------------------------------

def inno_version(data: bytes) -> Optional[Tuple[int, int, int]]:
    """The setup data version the installer names, or None.

    Several copies of the id occur -- the loader checks it as well -- and they
    agree, so the first is taken.
    """
    m = DATA_ID.search(data)
    if not m:
        return None
    return tuple(int(g) for g in m.groups())  # type: ignore[return-value]


def _lzma1(data: bytes, off: int) -> bytes:
    """An LZMA1 stream at `off` whose output length is not recorded.

    Inno writes the five-byte properties header and nothing else, so the
    13-byte `FORMAT_ALONE` header is synthesised with an unknown size and the
    stream's own end marker is what stops it. A stream that ends early keeps
    what arrived: a partial payload still carries whole files at its front, and
    the carve below refuses anything incomplete anyway.
    """
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    out = bytearray(dec.decompress(data[off:off + 5] + b"\xff" * 8))
    pos, step = off + 5, 1 << 20
    while pos < len(data) and not dec.eof:
        try:
            out += dec.decompress(data[pos:pos + step])
        except lzma.LZMAError:
            break
        pos += step
    return bytes(out)


def payloads(data: bytes) -> Iterator[bytes]:
    """Every file-data chunk in the installer, decompressed."""
    for m in re.finditer(re.escape(CHUNK_MAGIC), data):
        off = m.end()
        if off + 5 > len(data):
            continue
        blob = _lzma1(data, off)
        if blob:
            yield blob


# --------------------------------------------------------------------------
# layer 2 -- Inno's call-instruction filter
# --------------------------------------------------------------------------

def unfilter(data: bytes, flip: bool) -> bytes:
    """Undo the call-instruction translation Inno applies before compressing.

    At each `0xE8`/`0xE9` a five-byte window is considered -- the opcode and a
    32-bit little-endian operand. A window that does not fit inside the
    current 64 KiB block is skipped a byte at a time. The operand's high byte
    must be 0x00 or 0xFF or the window is left alone; otherwise the low 24 bits
    become `(operand - window_end) & 0xFFFFFF`, and for 5.3.9 and later a set
    bit 23 flips the high byte.
    """
    buf = bytearray(data)
    n, i = len(buf), 0
    while i < n:
        if buf[i] != 0xE8 and buf[i] != 0xE9:
            i += 1
            continue
        if (i % FILTER_BLOCK) + 5 > FILTER_BLOCK or i + 5 > n:
            i += 1
            continue
        high = buf[i + 4]
        if high != 0x00 and high != 0xFF:
            i += 5
            continue
        operand = (buf[i + 1] | (buf[i + 2] << 8) | (buf[i + 3] << 16)
                   | (high << 24))
        rel = (operand - (i + 5)) & 0xFFFFFF
        buf[i + 1] = rel & 0xFF
        buf[i + 2] = (rel >> 8) & 0xFF
        buf[i + 3] = (rel >> 16) & 0xFF
        if flip and rel & 0x800000:
            buf[i + 4] = high ^ 0xFF
        i += 5
    return bytes(buf)


# --------------------------------------------------------------------------
# layer 3 -- the carve, accepted by the chain itself
# --------------------------------------------------------------------------

def _stub_starts(blob: bytes, end: int, stub: int) -> Iterator[int]:
    """Offsets where a file whose stub is `stub` bytes could begin.

    An `MZ` with a reachable `PE\\0\\0`, exactly `stub` bytes before the
    overlay, and then one of the two shapes an overlay opens with: the
    pack-size field the 2011-and-later engines write, or -- for 2010 and 2011,
    which write none -- a ciphertext whose length is a whole number of AES
    blocks. Either is only a candidate; `bgtlib.unpack` is what accepts it.
    """
    top = end - stub
    for cand in range(top, max(-1, top - MAX_STUB), -1):
        if blob[cand:cand + 2] != b"MZ" or cand + 0x40 > len(blob):
            continue
        pe = struct.unpack_from("<I", blob, cand + 0x3C)[0]
        if not 0 < pe < (1 << 16) or blob[cand + pe:cand + pe + 4] != b"PE\0\0":
            continue
        field = blob[cand + stub:cand + stub + 12]
        body = end - bgtlib.TRAILER_LEN - (cand + stub)
        if not re.match(rb"[0-9]{1,10} ", field) and body % 16:
            continue
        yield cand


def bgt_games(blob: bytes) -> Iterator[Tuple[int, int, bytes]]:
    """Every BGT executable in a payload, as (start, end, bytes).

    Yielded only when the whole chain opens it, so a second `xproc10` a few
    hundred bytes past the real one cannot produce a game that is 500 bytes too
    long -- which is exactly what an unverified carve does produce.
    """
    for m in re.finditer(re.escape(b"xproc10\x00"), blob):
        end = m.end() + 4
        if end > len(blob):
            continue
        stub = struct.unpack_from("<I", blob, m.end())[0]
        if not 0 < stub < end:
            continue
        for begin in _stub_starts(blob, end, stub):
            exe = blob[begin:end]
            try:
                bgtlib.unpack(exe)
            except Exception:
                continue
            yield begin, end, exe
            break


def sfpv_packs(blob: bytes) -> Iterator[Tuple[int, int, int]]:
    """Every SFPv asset pack in a payload, as (start, end, entry count).

    The games need these. A recovered BGT project that compiles and runs and
    has no pack beside it does not play a sound -- `could not load pack
    data/bgm.dat.` -- so pulling the executable out on its own is half a job.

    A pack can be carved for the same reason an executable can: it declares its
    entry count, every entry repeats the `SFPv` magic, and a walk that does not
    land exactly where the last entry ends was never looking at a pack. No
    guess is involved beyond where to start the walk.
    """
    at = 0
    for m in re.finditer(re.escape(b"SFPv"), blob):
        if m.start() < at:
            continue                     # inside a pack already accounted for
        try:
            version, count, _reserved = struct.unpack_from("<III", blob,
                                                           m.start() + 4)
        except struct.error:
            continue
        if version != 1 or not 0 < count < 1 << 20:
            continue
        p, ok = m.start() + 16, True
        for _ in range(count):
            if blob[p:p + 4] != b"SFPv":
                ok = False
                break
            try:
                name_len, _flags, size = struct.unpack_from("<III", blob, p + 4)
            except struct.error:
                ok = False
                break
            if name_len > 1024 or p + 16 + name_len + size > len(blob):
                ok = False
                break
            p += 16 + name_len + size
        if ok:
            at = p
            yield m.start(), p, count


def pack_names(module: bytes) -> List[str]:
    """The `.dat` names a module holds, as candidates for a carved pack's name.

    A pack's name matters: the script opens it by name, so the file has to be
    called what `set_sound_storage` was passed. The module holds every string
    constant, and which of them reaches that call is not knowable without a
    parse -- and the 2010-to-2012 modules do not parse yet. So these are
    candidates, and the caller uses one only when there is exactly one bare
    filename among them.

    Read as RECORDS rather than scanned as text, which matters: a scan has no
    idea where a string begins, so `junk` immediately before `sounds.dat`
    arrives glued to it. A `tagged` string is `0x6E`, an encoded length and
    then the bytes, so the length says where the name starts -- and a length
    that does not agree with a printable name ending in `.dat` is not a match
    at all. These modules are all `tagged`; a `len2` build would need its own
    reading, and `bgt recover` has the parse for that case anyway.
    """
    seen, out = set(), []
    for pos in range(len(module) - 2):
        if module[pos] != 0x6E:
            continue
        length = module[pos + 1]
        at = pos + 2
        if length >= 0x80:               # the two-byte encoded form
            length = ((length & 0x3F) << 8) | module[pos + 2]
            at = pos + 3
        if not 4 < length <= 60 or at + length > len(module):
            continue
        name = module[at:at + length]
        if not name.endswith(b".dat"):
            continue
        if not all(0x20 <= b < 0x7F for b in name):
            continue
        text = name.decode("latin1")
        if text not in seen:
            seen.add(text)
            out.append(text)
    return out


def games_in(path: str) -> Iterator[Tuple[bytes, str, List[Tuple[str, bytes]]]]:
    """Every BGT game an installer holds: its executable, a note, and its packs.

    The packs come from the same payload as the game, so a caller can write a
    folder that RUNS rather than one executable that starts and is silent.
    """
    with open(path, "rb") as fh:
        data = fh.read()

    version = inno_version(data)
    if version is None:
        flips: List[bool] = [True, False]
        note = "version not stated, both filters tried"
    else:
        flips = [version >= (5, 3, 9)]
        note = "Inno %d.%d.%d" % version

    found = 0
    for blob in payloads(data):
        for flip in flips:
            unfiltered = unfilter(blob, flip)
            games = list(bgt_games(unfiltered))
            if not games:
                continue
            packs = list(sfpv_packs(unfiltered))
            for _begin, _end, exe in games:
                found += 1
                named = _name_packs(exe, unfiltered, packs,
                                    one_game=len(games) == 1)
                yield exe, "%s, filter flip=%s" % (note, flip), named
            break
    if not found:
        raise InstallerError(
            "no BGT executable in %s -- it may hold a game built with another "
            "engine (Q9, for one, is native code that merely uses BGT's pack "
            "format), or an Inno version this does not read"
            % os.path.basename(path))


def _name_packs(exe: bytes, blob: bytes,
                packs: List[Tuple[int, int, int]],
                one_game: bool) -> List[Tuple[str, bytes]]:
    """Give each carved pack a name, and say so honestly when it is a guess.

    The one case that can be named outright is the common one: a single game, a
    single pack, and a single bare `.dat` filename in the module. Anything else
    gets a numbered name, because writing a pack under the wrong name is worse
    than writing it under an obvious placeholder -- the script would open the
    placeholder and find nothing, which reads as a missing pack rather than as
    a mystery.
    """
    if not packs:
        return []
    try:
        module = bgtlib.unpack(exe).bytecode
    except Exception:
        module = b""
    bare = [n for n in pack_names(module) if "/" not in n and "\\" not in n]
    if one_game and len(packs) == 1 and len(bare) == 1:
        return [(bare[0], blob[packs[0][0]:packs[0][1]])]
    return [("pack_%08x.dat" % start, blob[start:end])
            for start, end, _count in packs]


def naming_candidates(exe: bytes) -> List[str]:
    """The `.dat` names a game's own module holds, for a person to choose from.

    Printed when a pack could not be named: Perilous Hearts holds
    `level_1.dat`, `level_2.dat` and `sounds.dat`, only one of which is the
    pack, and which one is not decidable from the string constants alone --
    that needs the call site, which needs a parse, which these modules do not
    yet have. Naming it wrongly would be worse than numbering it: the script
    would open the name it was given, find nothing, and report a missing pack.
    """
    try:
        return pack_names(bgtlib.unpack(exe).bytecode)
    except Exception:
        return []


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="bgt installer",
        description="extract the BGT game from an Inno Setup installer, "
                    "without running it")
    ap.add_argument("installer", nargs="+")
    ap.add_argument("-o", "--out", required=True,
                    help="directory to write each game's folder into")
    ap.add_argument("--no-packs", action="store_true",
                    help="the executable only, without the asset packs beside it")
    args = ap.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)
    total = 0
    for path in args.installer:
        stem = re.sub(r"[^A-Za-z0-9]+", "_",
                      os.path.splitext(os.path.basename(path))[0])[:40]
        print("== %s" % os.path.basename(path))
        try:
            for n, (exe, note, packs) in enumerate(games_in(path)):
                # A folder per game, because the script opens its packs by a
                # relative name: the pack has to sit beside the executable.
                folder = os.path.join(args.out, stem if n == 0
                                      else "%s_%d" % (stem, n))
                os.makedirs(folder, exist_ok=True)
                dest = os.path.join(folder, "%s.exe" % stem)
                with open(dest, "wb") as fh:
                    fh.write(exe)
                up = bgtlib.unpack(exe)
                print("   %-40s %9d bytes  seed 0x%02X  %-8s  module %d bytes"
                      % (os.path.basename(dest), len(exe), up.seed,
                         up.key_variant, len(up.bytecode)))
                print("   %s" % note)
                if args.no_packs:
                    if packs:
                        print("   %d asset pack(s) left behind, so this will "
                              "not play a sound" % len(packs))
                else:
                    for pname, pdata in packs:
                        with open(os.path.join(folder, pname), "wb") as fh:
                            fh.write(pdata)
                        print("   %-40s %9d bytes" % (pname, len(pdata)))
                        if pname.startswith("pack_"):
                            names = naming_candidates(exe)
                            print("   %sthe module does not say which name "
                                  "this pack is opened by; rename it to one "
                                  "of: %s"
                                  % (" " * 4,
                                     ", ".join(names) if names
                                     else "(no .dat name in the module)"))
                    if not packs:
                        print("   no asset pack in the installer")
                total += 1
        except InstallerError as exc:
            print("   %s" % exc)
    print("--- %d game(s) written to %s" % (total, args.out))
    return 0 if total else 1


if __name__ == "__main__":
    raise SystemExit(main())
