"""
upx -- see through a UPX-packed win32 executable without running `upx -d`.

Some BGT games ship their runtime compressed with UPX. The compiled script is
still a plain overlay, so `bgt unpack` works either way, but everything that
reads the *engine* -- the asBCInfo[] opcode table first of all -- finds only
UPX's stub and a compressed blob. This module rebuilds the memory image the
stub would have produced, so those readers can be pointed at it.

Everything here follows UPX 3.96's own unpacker, PeFile::unpack0:

  1. PackHeader ("UPX!", packhead.cpp) gives method, filter and lengths.
  2. The stream at the start of the second section is decoded (NRV2B/2D/2E,
     ucl's n2*_d.c) to exactly u_len bytes.
  3. Its last dword locates the "extra info": the original PE header and
     section table, then optional import and relocation records.
  4. The code range [codebase, codebase+codesize) is unfiltered (filter/ct.h,
     filter/cto.h) -- the call-trick filters rewrote CALL/JMP operands.
  5. Relocations are replayed (Packer::unoptimizeReloc, rebuildRelocs): UPX
     stored every relocated dword as big-endian `value - imagebase - rvamin`.

Steps 2-3 are checked against UPX's own numbers: the compressed stream's
adler32 and the decompressed stream's adler32 (which UPX takes *before*
unfiltering, so it proves decoding, not step 4), the exact u_len landing, and
an extra-info block whose section table starts at rvamin. Imports are not
rebuilt: the IAT is left as UPX's loader data, which no reader here needs.

A filter this module does not implement (the ctok/ctojr families) leaves the
code range as UPX stored it and sets Image.code_filtered; data sections --
where asBCInfo[] lives -- are unaffected by filters, so readers of data still
work.
"""

import struct
import zlib
from typing import List, NamedTuple, Optional, Tuple

MAGIC = b"UPX!"

METHODS = {2: "NRV2B_LE32", 3: "NRV2B_8", 4: "NRV2B_LE16",
           5: "NRV2D_LE32", 6: "NRV2D_8", 7: "NRV2D_LE16",
           8: "NRV2E_LE32", 9: "NRV2E_8", 10: "NRV2E_LE16",
           14: "LZMA", 15: "DEFLATE"}
FORMATS = {9: "win32/pe", 36: "win64/pe"}

PE32_HEADER = 248                       # sizeof(pe_header_t) for PE32
PEDIR_IMPORT, PEDIR_RELOC = 1, 5
RELOCS_STRIPPED = 1


class UpxError(ValueError):
    pass


class PackHeader(NamedTuple):
    offset: int         # file offset of "UPX!"
    version: int
    format: int
    method: int
    level: int
    u_adler: int
    c_adler: int
    u_len: int
    c_len: int
    u_file_size: int
    filter: int
    filter_cto: int

    def describe(self) -> str:
        return "UPX (%s, %s, filter 0x%02X)" % (
            FORMATS.get(self.format, "format %d" % self.format),
            METHODS.get(self.method, "method %d" % self.method), self.filter)


def _sections(exe: bytes) -> Tuple[int, List[Tuple[bytes, int, int, int, int]]]:
    """ImageBase and (name, rva, vsize, raw_size, raw_offset) per section."""
    e = struct.unpack_from("<I", exe, 0x3C)[0]
    if exe[e:e + 4] != b"PE\0\0":
        raise UpxError("not a PE file")
    n = struct.unpack_from("<H", exe, e + 6)[0]
    optsz = struct.unpack_from("<H", exe, e + 20)[0]
    base = struct.unpack_from("<I", exe, e + 24 + 28)[0]
    out = []
    for i in range(n):
        b = e + 24 + optsz + 40 * i
        name = exe[b:b + 8].rstrip(b"\0")
        vsize, rva, rsize, raw = struct.unpack_from("<4I", exe, b + 8)
        out.append((name, rva, vsize, rsize, raw))
    return base, out


def find_header(exe: bytes) -> Optional[PackHeader]:
    """The PackHeader, or None when the file is not UPX-packed.

    UPX writes the header just before the second section's raw data
    (unpack0 seeks to isection[1].rawdataptr - 64 + buf_offset), so it is
    searched for only in the headers area -- the magic alone also occurs in
    unrelated files.
    """
    if exe[:2] != b"MZ" or len(exe) < 0x40:
        return None
    try:
        _, secs = _sections(exe)
    except (struct.error, UpxError):
        return None
    if len(secs) < 3:
        return None
    limit = secs[1][4]
    at = exe.find(MAGIC, 0, limit)
    if at < 0 or at + 32 > len(exe):
        return None
    (_, ver, fmt, meth, lvl, ua, ca, ul, cl, ufs, flt, cto) = struct.unpack_from(
        "<4s4B5I2B", exe, at)
    if not (0 < cl <= len(exe) and 0 < ul):
        return None
    return PackHeader(at, ver, fmt, meth, lvl, ua, ca, ul, cl, ufs, flt, cto)


# --------------------------------------------------------------------------
# NRV decoders (ucl n2b_d.c / n2d_d.c / n2e_d.c), 32-bit LE bit buffer
# --------------------------------------------------------------------------

def _nrv(src: bytes, u_len: int, variant: str) -> bytes:
    pos = 0
    bb = bc = 0
    n = len(src)

    def bit():
        nonlocal pos, bb, bc
        if bc == 0:
            if pos + 4 > n:
                raise UpxError("compressed stream ends inside a bit buffer")
            bb = src[pos] | src[pos + 1] << 8 | src[pos + 2] << 16 | src[pos + 3] << 24
            pos += 4
            bc = 32
        bc -= 1
        return (bb >> bc) & 1

    def byte():
        nonlocal pos
        if pos >= n:
            raise UpxError("compressed stream ends inside a literal")
        pos += 1
        return src[pos - 1]

    dst = bytearray()
    last_off = 1
    while True:
        while bit():
            dst.append(byte())
        m_off = 1
        while True:
            m_off = m_off * 2 + bit()
            if bit():
                break
            if variant != "b":
                m_off = (m_off - 1) * 2 + bit()
        if m_off == 2:
            m_off = last_off
            m_len = bit()
        else:
            m_off = ((m_off - 3) * 256 + byte()) & 0xFFFFFFFF
            if m_off == 0xFFFFFFFF:
                break                              # end-of-stream marker
            if variant == "b":
                m_off += 1
                m_len = bit()
            else:
                m_len = (m_off ^ 0xFFFFFFFF) & 1
                m_off = (m_off >> 1) + 1
            last_off = m_off
        if variant == "e":
            if m_len:
                m_len = 1 + bit()
            elif bit():
                m_len = 3 + bit()
            else:
                m_len = 1
                while True:
                    m_len = m_len * 2 + bit()
                    if bit():
                        break
                m_len += 3
        else:
            m_len = m_len * 2 + bit()
            if m_len == 0:
                m_len = 1
                while True:
                    m_len = m_len * 2 + bit()
                    if bit():
                        break
                m_len += 2
        m_len += (m_off > (0xD00 if variant == "b" else 0x500))
        m_len += 1
        if m_off > len(dst):
            raise UpxError("match reaches before the start of the output")
        start = len(dst) - m_off
        if m_off >= m_len:
            dst += dst[start:start + m_len]
        else:
            for k in range(m_len):                 # overlaps its own output
                dst.append(dst[start + k])
        if len(dst) > u_len:
            raise UpxError("decoded past the declared length 0x%X" % u_len)
    if len(dst) != u_len:
        raise UpxError("decoded 0x%X bytes, header declares 0x%X" % (len(dst), u_len))
    return bytes(dst)


_DECODERS = {2: "b", 5: "d", 8: "e"}


# --------------------------------------------------------------------------
# filters: undo the CALL/JMP operand rewriting
# --------------------------------------------------------------------------

_COND = {0: (0xE8,), 1: (0xE9,), 2: (0xE8, 0xE9)}


def _u_ct32(b: bytearray, ops, addvalue: int, bswap: bool) -> None:
    """ct.h CT32 unfilter: operand = get(operand) - (offset of operand) - addvalue."""
    end = len(b) - 5
    i = 0
    while i < end:
        if b[i] in ops:
            a = i + 1
            v = struct.unpack_from(">I" if bswap else "<I", b, a)[0]
            struct.pack_into("<I", b, a, (v - a - addvalue) & 0xFFFFFFFF)
            i += 4
        i += 1


def _u_cto32(b: bytearray, ops, addvalue: int, cto: int) -> None:
    """cto.h unfilter: only operands whose first byte is the cto mark were
    rewritten (to big-endian target + addvalue + cto<<24)."""
    size5 = len(b) - 5
    hi = cto << 24
    ic = 0
    while ic < size5:
        if b[ic] in ops:
            if b[ic + 1] == cto:
                jc = struct.unpack_from(">I", b, ic + 1)[0]
                struct.pack_into("<I", b, ic + 1, (jc - ic - 1 - addvalue - hi) & 0xFFFFFFFF)
                ic += 4
        ic += 1


def unfilter(buf: bytearray, fid: int, cto: int, addvalue: int) -> bool:
    """Undo filter `fid` in place. False when the filter is not implemented."""
    if 0x11 <= fid <= 0x16:
        _u_ct32(buf, _COND[(fid - 0x11) % 3], addvalue, fid >= 0x14)
    elif 0x24 <= fid <= 0x26:
        _u_cto32(buf, _COND[fid - 0x24], addvalue, cto)
    elif fid == 0:
        pass
    else:
        return False
    return True


# --------------------------------------------------------------------------
# relocations (Packer::unoptimizeReloc, PeFile::rebuildRelocs)
# --------------------------------------------------------------------------

def _reloc_offsets(data: bytes, p: int) -> List[int]:
    out = []
    jc = -4
    while True:
        if p >= len(data):
            raise UpxError("relocation list runs off the end of the image")
        c = data[p]
        if c == 0:
            return out
        if c < 0xF0:
            jc += c
        else:
            dif = (c & 0x0F) * 0x10000 + struct.unpack_from("<H", data, p + 1)[0]
            p += 2
            if dif == 0:
                dif = struct.unpack_from("<I", data, p + 1)[0]
                p += 4
            jc += dif
        out.append(jc)
        p += 1


# --------------------------------------------------------------------------
# the image
# --------------------------------------------------------------------------

class Image(NamedTuple):
    header: PackHeader
    image_base: int
    rva: int                # RVA of data[0] (the original rvamin)
    data: bytes             # the memory image from rvamin
    sections: List[Tuple[bytes, int, int, int, int]]   # original section table
    relocations: int        # dwords relocated
    code_filtered: bool     # True: filter not implemented, code left filtered


def decompress(exe: bytes) -> Image:
    ph = find_header(exe)
    if ph is None:
        raise UpxError("not a UPX-packed PE")
    if ph.format != 9:
        raise UpxError("UPX format %s is not supported (win32/pe only)"
                       % FORMATS.get(ph.format, ph.format))
    variant = _DECODERS.get(ph.method)
    if variant is None:
        raise UpxError("UPX method %s is not implemented -- run `upx -d` on a copy"
                       % METHODS.get(ph.method, ph.method))
    base, secs = _sections(exe)
    raw = secs[1][4]
    comp = exe[raw:raw + ph.c_len]
    if len(comp) != ph.c_len or zlib.adler32(comp) != ph.c_adler:
        raise UpxError("compressed stream fails its adler32 -- damaged, or not "
                       "where UPX 3.x puts it")
    buf = bytearray(_nrv(comp, ph.u_len, variant))
    if zlib.adler32(buf) != ph.u_adler:
        raise UpxError("decompressed stream fails its adler32")

    # extra info: original header, section table, then optional records
    skip = struct.unpack_from("<I", buf, len(buf) - 4)[0]
    if skip + PE32_HEADER > len(buf):
        raise UpxError("extra-info offset 0x%X out of range" % skip)
    oh = bytes(buf[skip:skip + PE32_HEADER])
    if struct.unpack_from("<H", oh, 24)[0] != 0x10B:
        raise UpxError("stored PE header is not PE32")
    objs = struct.unpack_from("<H", oh, 6)[0]
    flags = struct.unpack_from("<H", oh, 22)[0]
    codesize, = struct.unpack_from("<I", oh, 28)
    codebase, imagebase = struct.unpack_from("<I", oh, 44)[0], struct.unpack_from("<I", oh, 52)[0]
    ddir = lambda k: struct.unpack_from("<II", oh, 120 + 8 * k)
    p = skip + PE32_HEADER
    osecs = []
    for i in range(objs):
        name = bytes(buf[p:p + 8]).rstrip(b"\0")
        vsize, rva, rsize, rawp = struct.unpack_from("<4I", buf, p + 8)
        osecs.append((name, rva, vsize, rsize, rawp))
        p += 40
    if not osecs:
        raise UpxError("stored section table is empty")
    rvamin = osecs[0][1]
    if rvamin != secs[0][1]:
        raise UpxError("stored section table does not start at the packed image "
                       "(0x%X vs 0x%X)" % (rvamin, secs[0][1]))

    filtered = False
    if ph.filter:
        lo = codebase - rvamin
        if not (0 <= lo and lo + codesize <= len(buf)):
            raise UpxError("code range 0x%X+0x%X outside the image" % (codebase, codesize))
        seg = buf[lo:lo + codesize]
        if unfilter(seg, ph.filter, ph.filter_cto, lo):
            buf[lo:lo + codesize] = seg
        else:
            filtered = True

    if ddir(PEDIR_IMPORT)[0]:
        p += 8                                     # cimports, dllstrings
    nrel = 0
    raddr, rsize = ddir(PEDIR_RELOC)
    if raddr and rsize and not (flags & RELOCS_STRIPPED) and rsize != 8:
        crelocs = struct.unpack_from("<I", buf, p)[0]
        for off in _reloc_offsets(buf, crelocs):
            if not 0 <= off <= len(buf) - 4:
                raise UpxError("relocation 0x%X outside the image" % off)
            v = struct.unpack_from(">I", buf, off)[0]
            struct.pack_into("<I", buf, off, (v + imagebase + rvamin) & 0xFFFFFFFF)
            nrel += 1

    return Image(ph, imagebase, rvamin, bytes(buf), osecs, nrel, filtered)


def mapped_pe(img: Image) -> bytes:
    """A minimal PE that maps the recovered image 1:1 at its original
    ImageBase, for readers that translate virtual addresses through the
    section table (as_opcodes). Not runnable, and not meant to be."""
    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", hdr, 0x84, 0x14C, 1)          # i386, one section
    struct.pack_into("<H", hdr, 0x94, 0xE0)               # SizeOfOptionalHeader
    struct.pack_into("<H", hdr, 0x98, 0x10B)              # PE32
    struct.pack_into("<I", hdr, 0x98 + 28, img.image_base)
    sec = 0x98 + 0xE0
    hdr[sec:sec + 8] = b".image\0\0"
    struct.pack_into("<4I", hdr, sec + 8, len(img.data), img.rva, len(img.data), 0x400)
    return bytes(hdr) + img.data


def is_packed(path: str) -> Optional[PackHeader]:
    with open(path, "rb") as fh:
        head = fh.read(0x4000)
    return find_header(head)
