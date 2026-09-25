"""
UPX support and relocated overlays -- synthetic inputs only.

The NRV2E streams here are produced by a tiny encoder written from the
decoder's own rules, so the decoder is exercised on literals, new-offset
matches, repeated-offset matches, overlapping copies and the end marker
without shipping any packed binary.

    python -m pytest tests/test_upx.py -q
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

import pytest

try:                                   # after `pip install -e .`
    from bgtdecomp import as_opcodes, bgt_repack, bgtlib, engine, upx
except ImportError:                    # straight from a checkout
    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
    import as_opcodes
    import bgt_repack
    import bgtlib
    import engine
    import upx

NUL = b"\x00"


# --------------------------------------------------------------------------
# a test-only NRV2E encoder (literals and short matches)
# --------------------------------------------------------------------------

class _Enc:
    """Mirror of the decoder's 32-bit LE bit buffer: a dword is reserved the
    moment its first bit is needed, and literal bytes follow it in order."""

    def __init__(self):
        self.out = bytearray()
        self.word_at = None
        self.nbits = 0
        self.word = 0

    def bit(self, b):
        if self.nbits == 0:
            if self.word_at is not None:
                struct.pack_into("<I", self.out, self.word_at, self.word)
            self.word_at = len(self.out)
            self.out += b"\0\0\0\0"
            self.word, self.nbits = 0, 32
        self.nbits -= 1
        self.word |= (b & 1) << self.nbits

    def byte(self, b):
        self.out.append(b)

    def finish(self):
        if self.word_at is not None:
            struct.pack_into("<I", self.out, self.word_at, self.word)
        return bytes(self.out)

    def m_off_code(self, target):
        """Bits that make NRV2E's offset loop produce exactly `target`.

        The loop is `v = v*2 + b; if (stop) break; v = (v-1)*2 + c`, starting
        from 1, so it can be run backwards one step at a time."""
        bits = [target & 1, 1]                      # last value bit, then stop
        v = target >> 1
        while v != 1:
            assert v > 1, target
            c = v & 1
            x = (v >> 1) + 1
            bits = [x & 1, 0, c] + bits             # value bit, continue, c
            v = x >> 1
        for b in bits:
            self.bit(b)


def _nrv2e(ops):
    """ops: ("lit", byte) | ("match", offset, length 2..5). Offsets <= 0x500."""
    e = _Enc()
    last = None
    for op in ops:
        if op[0] == "lit":
            e.bit(1)
            e.byte(op[1])
            continue
        _, off, length = op
        assert 2 <= length <= 5 and off <= 0x500
        e.bit(0)
        lenbit = 1 if length <= 3 else 0
        if off == last:
            e.m_off_code(2)
            e.bit(lenbit)
        else:
            raw = ((off - 1) << 1) | (1 - lenbit)
            e.m_off_code((raw >> 8) + 3)
            e.byte(raw & 0xFF)
            last = off
        if lenbit:
            e.bit(length - 2)                  # 1 + bit, then +1 copies 2..3
        else:
            e.bit(1)
            e.bit(length - 4)                  # 3 + bit, then +1 copies 4..5
    e.bit(0)                                   # end marker: a match whose
    e.m_off_code(0x1000002)                    # offset decodes to 0xFFFFFFFF
    e.byte(0xFF)
    return e.finish()


def test_nrv2e_literals_and_end_marker():
    data = b"hello"
    stream = _nrv2e([("lit", c) for c in data])
    assert upx._nrv(stream, len(data), "e") == data


def test_nrv2e_matches_new_repeated_and_overlapping():
    ops = [("lit", c) for c in b"abc"] + [("match", 3, 5), ("lit", ord("x")),
                                          ("match", 3, 2), ("match", 1, 4)]
    # abc + abcab (offset 3, overlapping) + x + ab? -- follow the copy rules
    ref = bytearray(b"abc")
    for op in ops[3:]:
        if op[0] == "lit":
            ref.append(op[1])
        else:
            for _ in range(op[2]):
                ref.append(ref[-op[1]])
    stream = _nrv2e(ops)
    assert upx._nrv(stream, len(ref), "e") == bytes(ref)


def test_nrv_refuses_a_length_it_does_not_land_on():
    stream = _nrv2e([("lit", c) for c in b"abcd"])
    with pytest.raises(upx.UpxError):
        upx._nrv(stream, 5, "e")
    with pytest.raises(upx.UpxError):
        upx._nrv(stream, 3, "e")


def test_nrv_refuses_a_truncated_stream():
    stream = _nrv2e([("lit", c) for c in b"abcdefgh"])
    with pytest.raises(upx.UpxError):
        upx._nrv(stream[:-3], 8, "e")


# --------------------------------------------------------------------------
# filters -- the encoders transcribed from filter/ct.h and filter/cto.h
# --------------------------------------------------------------------------

def _f_cto32(b, ops, addvalue):
    """Returns (filtered, cto). Like getcto(), the mark is a byte that no
    operand left unconverted starts with -- otherwise it would be ambiguous."""
    b = bytearray(b)
    size = len(b)
    used = set()
    for ic in range(size - 5):
        if b[ic] in ops:
            jc = (struct.unpack_from("<I", b, ic + 1)[0] + ic + 1) & 0xFFFFFFFF
            if jc >= size:
                used.add(b[ic + 1])
    cto = next(c for c in range(0x10, 0x100) if c not in used)
    ic = 0
    while ic < size - 5:
        if b[ic] in ops:
            jc = (struct.unpack_from("<I", b, ic + 1)[0] + ic + 1) & 0xFFFFFFFF
            if jc < size:
                struct.pack_into(">I", b, ic + 1, jc + addvalue + (cto << 24))
                ic += 4
        ic += 1
    return bytes(b), cto


def _code(n=4096):
    """x86-shaped bytes: calls and jumps to targets in and out of range."""
    out = bytearray()
    k = 0
    while len(out) < n:
        k += 1
        if k % 3 == 0:
            out += b"\xE8" + struct.pack("<i", (k * 37) % 900 - 300)
        elif k % 10 == 0:
            out += b"\xE9" + struct.pack("<i", 0x7FFF0000)          # far away
        elif k % 5 == 0:
            out += b"\xE9" + struct.pack("<i", (k * 11) % 500 - 200)
        else:
            out += bytes([0x55, 0x8B, 0xEC, (k * 13) & 0x7F])
    return bytes(out[:n])


def test_cto32_unfilter_inverts_the_filter():
    code = _code()
    for fid, ops in ((0x24, (0xE8,)), (0x25, (0xE9,)), (0x26, (0xE8, 0xE9))):
        filtered, cto = _f_cto32(code, ops, 0x1000)
        assert filtered != code
        buf = bytearray(filtered)
        assert upx.unfilter(buf, fid, cto, 0x1000)
        assert bytes(buf) == code, hex(fid)


def test_ct32_unfilter_inverts_the_filter():
    code = _code()
    for fid in (0x13, 0x16):
        bswap = fid >= 0x14
        b = bytearray(code)
        i = 0
        while i < len(b) - 5:                               # CT32 filter
            if b[i] in (0xE8, 0xE9):
                a = i + 1
                v = (struct.unpack_from("<I", b, a)[0] + a + 0x2000) & 0xFFFFFFFF
                struct.pack_into(">I" if bswap else "<I", b, a, v)
                i += 4
            i += 1
        assert upx.unfilter(b, fid, 0, 0x2000)
        assert bytes(b) == code, hex(fid)


def test_unimplemented_filter_is_reported_not_guessed():
    buf = bytearray(_code(64))
    assert upx.unfilter(buf, 0x49, 0x17, 0) is False
    assert bytes(buf) == _code(64)


# --------------------------------------------------------------------------
# relocations
# --------------------------------------------------------------------------

def test_reloc_list_is_delta_coded_from_minus_four():
    # 8 -> 4, 4 -> 8, then a long jump through the 0xF0 escape (+0x12345)
    data = bytes([8, 4, 0xF1, 0x45, 0x23, 0]) + NUL * 4
    assert upx._reloc_offsets(data, 0) == [4, 8, 8 + 0x12345]


def test_reloc_list_that_runs_off_the_end_is_an_error():
    with pytest.raises(upx.UpxError):
        upx._reloc_offsets(bytes([8, 4]), 0)


# --------------------------------------------------------------------------
# the mapped image is readable by the opcode reader's address translation
# --------------------------------------------------------------------------

def test_mapped_pe_translates_addresses_like_the_original():
    data = bytearray(0x2000)
    data[0x1234:0x1239] = b"hello"
    img = upx.Image(None, 0x400000, 0x1000, bytes(data), [], 0, False)
    pe = upx.mapped_pe(img)
    base, secs = as_opcodes._sections(pe)
    assert base == 0x400000
    rva, size, raw = secs[0]
    va = 0x400000 + 0x1000 + 0x1234
    off = raw + (va - base - rva)
    assert pe[off:off + 5] == b"hello"


def test_plain_pe_is_not_mistaken_for_upx():
    img = upx.Image(None, 0x400000, 0x1000, b"UPX!" + NUL * 0x1000, [], 0, False)
    assert upx.find_header(upx.mapped_pe(img)) is None
    assert upx.find_header(b"not a PE at all") is None


# --------------------------------------------------------------------------
# an overlay whose trailer offset went stale when the PE part was rewritten
# --------------------------------------------------------------------------

def _pe_stub(size):
    img = upx.Image(None, 0x400000, 0x1000, bytes(range(256)) * (size // 256),
                    [], 0, False)
    return upx.mapped_pe(img)


def _game(stub, module):
    skeleton = (stub + b"0 " + NUL * 32 + b"xproc10" + NUL
                + struct.pack("<I", len(stub)))
    return bgt_repack.repack(skeleton, module, seed=0x11, flag=3,
                             magic=b"6188CAE85A13D82754756DC38920FA09")


def test_overlay_is_found_after_the_pe_part_grew():
    """`upx -d` (or any PE rewriter) moves the overlay but leaves the absolute
    offset in the trailer alone. The overlay is still intact at the new end of
    the image, and every later layer still verifies it."""
    module = b"\x01\x02module payload " * 200
    exe = _game(_pe_stub(0x200), module)
    old_offset = bgtlib.read_trailer(exe)
    overlay = exe[old_offset:]
    rewritten = _pe_stub(0x800) + overlay
    offset, _embedded, _ct = bgtlib.split_overlay(rewritten)
    assert offset == bgtlib.pe_image_end(rewritten) != old_offset
    assert bgtlib.trailer_is_stale(rewritten, offset)
    assert bgtlib.unpack(rewritten).bytecode == module
    ident = engine.identify_bytes(rewritten, "rewritten.exe")
    assert ident.known and ident.facts["stale_trailer"] == old_offset
    assert "will not load it" in ident.summary()


def test_intact_overlay_is_not_reported_stale():
    module = b"payload" * 100
    exe = _game(_pe_stub(0x200), module)
    offset, _e, _c = bgtlib.split_overlay(exe)
    assert not bgtlib.trailer_is_stale(exe, offset)
    ident = engine.identify_bytes(exe, "game.exe")
    assert ident.facts["stale_trailer"] is None and ident.facts["upx"] is None


# --------------------------------------------------------------------------
# optional: a real packed file, checked against `upx -d`
# --------------------------------------------------------------------------

SAMPLE = os.environ.get("BGT_UPX_EXE")


@pytest.mark.skipif(not (SAMPLE and shutil.which("upx")),
                    reason="set BGT_UPX_EXE to a UPX-packed win32 exe, with upx on PATH")
def test_decompress_matches_upx_d_outside_the_import_table():
    with open(SAMPLE, "rb") as fh:
        packed = fh.read()
    img = upx.decompress(packed)
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "unpacked.exe")
        subprocess.run(["upx", "-d", "-q", SAMPLE, "-o", out], check=True,
                       stdout=subprocess.DEVNULL)
        with open(out, "rb") as fh:
            ref = fh.read()
    _base, secs = upx._sections(ref)
    e = struct.unpack_from("<I", ref, 0x3C)[0]
    imp_rva, imp_size = struct.unpack_from("<II", ref, e + 24 + 96 + 8)
    for name, rva, _vs, rsize, raw in secs:
        if name == b".reloc":
            continue                       # rebuilt by upx -d, not by us
        mine = img.data[rva - img.rva:rva - img.rva + rsize]
        theirs = ref[raw:raw + rsize]
        diff = [rva + k for k in range(rsize) if mine[k] != theirs[k]]
        # imports are left as UPX's loader data (see upx.py); nothing else may differ
        assert all(d >= imp_rva for d in diff), (name, hex(diff[0]))
