"""
as_opcodes -- recover AngelScript's asBCInfo[] opcode table from a BGT executable.

AngelScript is statically linked into every BGT game, and it carries its own opcode
metadata table. Recovering it from the binary you are analysing is strictly better
than porting a table from another build: opcode numbering shifts between AngelScript
versions, and a stale table decodes into confident nonsense.

    struct asSBCInfo { const char *name; int bc; int type; short stackInc; };  // 16 bytes

Indexed directly by opcode. Two quirks, both established by reading
asCReader::ReadByteCode rather than inferred:

  * name(op)      = table[op + 1].name     <- the name field is one entry out of step
  * type(op)      = table[op].type
  * stackInc(op)  = table[op].stackInc     <- indexed like type, not like name

The name shift is not cosmetic. Without it the raw table claims PopPtr, JMP and RET
share a type, which cannot be true since they take different operands. Applying the
+1 shift makes every opcode match AngelScript semantics.
"""

import json
import re
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

# opcodes whose names are distinctive enough to anchor the table
ANCHORS = (b"PshVPtr", b"CALLSYS", b"SUSPEND", b"SetV4", b"PopPtr", b"CALLINTF")

# operand count and instruction size, in dwords, per type -- transcribed from the
# switch in asCReader::ReadByteCode
TYPE_INFO: Dict[int, Tuple[int, int]] = {
    0x01: (0, 1), 0x02: (1, 1), 0x03: (1, 1), 0x04: (1, 2), 0x05: (2, 2),
    0x06: (1, 3), 0x07: (2, 3), 0x08: (3, 2), 0x09: (2, 3), 0x0A: (2, 2),
    0x0B: (1, 1), 0x0C: (2, 2), 0x0D: (3, 3), 0x0E: (2, 2), 0x0F: (2, 2),
    0x10: (2, 4), 0x11: (2, 3), 0x12: (2, 2), 0x13: (3, 3), 0x14: (3, 3),
}

NAME_RE = re.compile(rb"\A[A-Za-z_][A-Za-z0-9_]{1,23}\Z")


def _sections(exe: bytes) -> Tuple[int, List[Tuple[int, int, int]]]:
    e = struct.unpack_from("<I", exe, 0x3C)[0]
    c = e + 4
    n = struct.unpack_from("<H", exe, c + 2)[0]
    optsz = struct.unpack_from("<H", exe, c + 16)[0]
    base = struct.unpack_from("<I", exe, c + 20 + 28)[0]  # ImageBase
    st = c + 20 + optsz
    out = []
    for i in range(n):
        b = st + i * 40
        out.append((struct.unpack_from("<I", exe, b + 12)[0],   # rva
                    struct.unpack_from("<I", exe, b + 16)[0],   # size
                    struct.unpack_from("<I", exe, b + 20)[0]))  # raw
    return base, out


def extract(path: str, max_ops: int = 256) -> Dict[str, Any]:
    with open(path, "rb") as f:
        exe = f.read()
    base, secs = _sections(exe)

    def v2r(va):
        r = va - base
        for rva, size, raw in secs:
            if rva <= r < rva + size:
                return raw + (r - rva)
        return None

    def cstr(va, limit=32):
        off = v2r(va)
        if off is None:
            return None
        end = exe.find(b"\x00", off, off + limit)
        return exe[off:end] if end > off else None

    # Find a 16-byte-strided run whose first field points at a plausible opcode name.
    # Anchor on a known name so we do not have to scan the whole image blindly.
    anchor_off = exe.find(ANCHORS[0])
    if anchor_off < 0:
        raise ValueError("no AngelScript opcode names found -- not a BGT/AngelScript binary")

    best = None
    for rva, size, raw in secs:
        for pos in range(raw, raw + size - 16 * 8, 4):
            ok = 0
            for k in range(8):
                ptr = struct.unpack_from("<I", exe, pos + k * 16)[0]
                s = cstr(ptr)
                if s and NAME_RE.match(s):
                    ok += 1
                else:
                    break
            if ok == 8:
                entries = []
                p = pos
                while len(entries) < max_ops + 8:
                    if p + 16 > len(exe):
                        break
                    ptr, bc, ty, inc = struct.unpack_from("<IiiH", exe, p)
                    nm = cstr(ptr)
                    if not (nm and NAME_RE.match(nm)):
                        break
                    entries.append({"name": nm.decode(), "bc": bc, "type": ty,
                                    "stackInc": struct.unpack_from("<h", exe, p + 12)[0]})
                    p += 16
                if best is None or len(entries) > len(best[1]):
                    best = (pos, entries)
                if best and len(best[1]) >= max_ops:
                    break
        if best and len(best[1]) >= max_ops:
            break

    if not best:
        raise ValueError("could not locate a 16-byte-strided asBCInfo run")

    pos, entries = best

    # Re-anchor on `bc`, which is the opcode number and therefore counts 0, 1,
    # 2, ... across the table. The scan above cannot be trusted to have found
    # entry zero: because of the +1 name shift, asBCInfo[0]'s *name* field holds
    # the pointer belonging to the entry before the table, and if that string is
    # not identifier-shaped the eight-in-a-row test skips it and starts one
    # entry late. That is exactly what happens in Psycho Strike, where the
    # stray pointer is "%delegate_factory" -- and a table shifted by one entry
    # is the worst possible failure here, because every opcode still decodes to
    # a real name and a real operand count, just the wrong ones.
    pos, entries = _anchor_on_bc_zero(exe, pos, entries, max_ops)

    table = {}
    for op in range(min(max_ops, len(entries) - 1)):
        e = entries[op]
        nxt = entries[op + 1]
        if e["bc"] >= 200 and e["type"] == 0:
            continue                      # dummy padding past the real opcodes
        ops, size = TYPE_INFO.get(e["type"], (0, 1))
        table[op] = {"name": nxt["name"],          # +1 shift, see module docstring
                     "type": e["type"],
                     "stackInc": e["stackInc"],
                     "operands": ops,
                     "dwords": size}
    return {"file_offset": pos, "count": len(table), "table": table}


def _anchor_on_bc_zero(exe: bytes, pos: int, entries: List[Dict[str, Any]],
                       max_ops: int) -> Tuple[int, List[Dict[str, Any]]]:
    """Slide the located run back so that it starts at the entry whose bc is 0.

    `bc` is the opcode number, so a correctly aligned table satisfies
    `entries[k].bc == k` for every k. That is a much stronger anchor than the
    shape of the name strings, and it is checked rather than assumed: if the
    sequence does not come out consecutive from zero, the run is left where the
    scan put it rather than silently shifted somewhere equally wrong.
    """
    if entries and entries[0]["bc"] == 0:
        return pos, entries

    back = 0
    while back < 8:
        probe = pos - (back + 1) * 16
        if probe < 0:
            break
        bc = struct.unpack_from("<i", exe, probe + 4)[0]
        if bc != entries[0]["bc"] - (back + 1):
            break
        back += 1
        if bc == 0:
            break

    if back == 0:
        return pos, entries

    start = pos - back * 16
    if struct.unpack_from("<i", exe, start + 4)[0] != 0:
        return pos, entries                    # not a clean 0,1,2,... run

    rebuilt: List[Dict[str, Any]] = []
    p = start
    while len(rebuilt) < max_ops + 8 and p + 16 <= len(exe):
        ptr, bc, ty, _inc = struct.unpack_from("<IiiH", exe, p)
        if bc != len(rebuilt):                 # the sequence must stay exact
            break
        rebuilt.append({"name": None, "bc": bc, "type": ty,
                        "stackInc": struct.unpack_from("<h", exe, p + 12)[0],
                        "_ptr": ptr})
        p += 16

    # Names come from the following entry (the +1 shift), so fill them in from
    # the run we already validated rather than re-reading the strings.
    for i, e in enumerate(rebuilt):
        if i < back:
            nxt = rebuilt[i + 1] if i + 1 < len(rebuilt) else None
            e["name"] = _name_at(exe, nxt["_ptr"]) if nxt else None
        else:
            src = i - back
            e["name"] = entries[src]["name"] if src < len(entries) else None
    for e in rebuilt:
        e.pop("_ptr", None)
        if e["name"] is None:
            e["name"] = "op%d" % e["bc"]
    return start, rebuilt


def _name_at(exe: bytes, va: int) -> Optional[str]:
    base, secs = _sections(exe)
    r = va - base
    for rva, size, raw in secs:
        if rva <= r < rva + size:
            off = raw + (r - rva)
            end = exe.find(b"\x00", off, off + 32)
            if end > off:
                return exe[off:end].decode("latin1")
    return None


def disassemble(bc: bytes, table: Dict[int, Dict[str, Any]], start: int = 0,
                limit: Optional[int] = None) -> List[Tuple[int, int, str, List[int]]]:
    """Decode a bytecode run. Every operand is one varint regardless of declared width."""
    try:
        from .as_module import read_encoded_uint
    except ImportError:
        from as_module import read_encoded_uint
    out = []
    p = start
    n = len(bc) if limit is None else min(len(bc), start + limit)
    while p < n:
        op = bc[p]
        info = table.get(op)
        if info is None:
            out.append((p, op, "UNKNOWN_%02X" % op, []))
            break
        q = p + 1
        args = []
        try:
            for _ in range(info["operands"]):
                v, q = read_encoded_uint(bc, q)
                args.append(v)
        except IndexError:
            break
        out.append((p, op, info["name"], args))
        p = q
        if info["name"] == "RET":
            break
    return out


if __name__ == "__main__":
    info = extract(sys.argv[1])
    print("asBCInfo at file offset 0x%X -- %d opcodes" % (info["file_offset"], info["count"]))
    for op in sorted(info["table"])[:24]:
        e = info["table"][op]
        print("  %3d  %-12s type=%-3d ops=%d stackInc=%+d"
              % (op, e["name"], e["type"], e["operands"], e["stackInc"]))
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w") as f:
            json.dump({str(k): v for k, v in info["table"].items()}, f, indent=1)
        print("written to", sys.argv[2])
