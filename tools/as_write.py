"""
as_write -- write an AngelScript module back out, byte for byte.

The reader models the format; duplicating that model in a writer would mean two
places to keep in step and two places to get subtly wrong. Instead `as_module`
can emit a **field trace** -- an ordered record of every primitive it read -- and
this module replays it. The format has no absolute offsets anywhere (everything
is counted, length-prefixed or index-referenced), so re-encoding a trace with one
field changed produces a valid module with everything downstream shifted
naturally.

    from bgtdecomp import as_module, as_write
    trace, info = as_module.trace_module(path, opcodes=table)
    assert as_write.write(trace, info["dialect"]) == open(path, "rb").read()

That equality is the whole correctness argument, and it is checked against real
modules rather than asserted: `verify_roundtrip()` requires the module back byte
for byte, and `bgt asm --verify` runs it. A writer that is *nearly* right
produces a module that loads and then behaves differently, which is exactly the
failure this format is good at hiding.

## Editing

Because back-references are by **index**, not by offset, changing a string's
bytes does not disturb anything that refers to it -- the saved-strings table
keeps the same shape, entry N is still entry N, and only the encoded length of
that one record changes. So a literal can be swapped for one of a different
length, which the old in-place patching could not do:

    trace = as_write.replace_literal(trace, b"sounds.dat", b"mysounds.dat")

Instructions can be edited the same way: the trace holds each one as
`("op", opcode, [operands])`, so an operand can be retargeted or an instruction
replaced, and the instruction count is recomputed on write.

**What this does not do** is check that your edit makes sense. Renaming a string
is safe; changing an instruction to one with a different stack effect, or
pointing a `CALL` at an index that is not in `usedFunctions`, will produce a
module that loads and then misbehaves. The round-trip proves the *encoding*, not
the edit.
"""

import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:                      # installed as a package
    from . import as_module
except ImportError:       # run directly from a checkout
    import as_module


# The widths read_encoded_uint recognises, smallest first:
# (extra bytes, marker, value bits still free in the lead byte).
#
# Each form gives up one more bit to the NEXT form's marker, which is easy to
# get wrong in this direction: the decoder only has to mask, but the encoder has
# to stop short. Reading `10xxxxxx` as six free bits lets a lead byte reach 0x7F,
# which decodes as the eight-byte form -- the value comes back enormous and the
# cursor lands in the middle of the next record.
_FORMS = (
    (0, 0x00, 6),      # 0xxxxxxx   0..63
    (1, 0x40, 5),      # 10xxxxxx   bit5 must stay clear
    (2, 0x60, 4),      # 110xxxxx
    (3, 0x70, 3),      # 1110xxxx
    (4, 0x78, 2),      # 11110xxx
    (5, 0x7C, 1),      # 111110xx
    (6, 0x7E, 0),      # 1111110x
    (8, 0x7F, 0),      # 1111111x
)


def encode_encoded_uint(value: int) -> bytes:
    """The exact inverse of as_module.read_encoded_uint.

    Canonical, i.e. the narrowest form that fits -- which is what AngelScript's
    own writer emits, so a trace re-encodes to the original bytes. The top bit
    of the lead byte is the sign flag, NOT a continuation bit; the width is the
    run of set bits below it.
    """
    negative = value < 0
    v = -value if negative else value
    sign = 0x80 if negative else 0x00

    for extra, marker, bits in _FORMS:
        capacity = bits + 8 * extra
        if extra == 0:
            if v < 64:
                return bytes([sign | v])
            continue
        if v < (1 << capacity):
            out = bytearray()
            high = v >> (8 * extra)
            out.append(sign | marker | high)
            for shift in range(extra - 1, -1, -1):
                out.append((v >> (8 * shift)) & 0xFF)
            return bytes(out)
    raise ValueError("value %d does not fit the encoding" % value)


def encode_string(kind: str, payload: Any, dialect: str) -> bytes:
    """Re-encode one string field in whichever dialect the module uses."""
    if dialect == as_module.LEN2:
        if kind == "strempty":
            return b"\x00"
        if kind == "strnew":
            return encode_encoded_uint(len(payload) * 2) + payload
        return encode_encoded_uint(payload * 2 + 1)          # strref
    if kind == "strempty":
        return b"\x00"
    if kind == "strnew":
        return b"\x6e" + encode_encoded_uint(len(payload)) + payload
    return b"\x72" + encode_encoded_uint(payload)            # strref


def write(trace: Sequence[Tuple], dialect: str) -> bytes:
    """Replay a field trace back into module bytes.

    Instruction counts are **recomputed** from the instructions that actually
    follow, so adding or removing one keeps the declared count right. That field
    counts instructions, not dwords -- writing a dword count produces a module
    whose bodies all end in the wrong place.
    """
    out = bytearray()
    for n, item in enumerate(trace):
        kind = item[0]
        if kind == "opcount":
            # Count forward by index. Slicing the remaining trace here instead
            # is quadratic -- on a 4.7 MB module that is ~10,000 counts against
            # a two-million-entry trace, and the write never finishes.
            actual = 0
            j = n + 1
            while j < len(trace) and trace[j][0] == "op":
                actual += 1
                j += 1
            out += encode_encoded_uint(actual)
        elif kind == "eu":
            out += encode_encoded_uint(item[1])
        elif kind == "raw":
            out += item[1]
        elif kind == "u32":
            out += struct.pack(">I", item[1] & 0xFFFFFFFF)
        elif kind == "i32":
            out += struct.pack(">i", item[1])
        elif kind in ("strnew", "strref", "strempty"):
            out += encode_string(kind, item[1] if len(item) > 1 else None, dialect)
        elif kind == "op":
            out += bytes([item[1]])
            for operand in item[2]:
                out += encode_encoded_uint(operand)
        else:
            raise ValueError("unknown trace entry %r" % (kind,))
    return bytes(out)


def verify_roundtrip(path: str, opcodes: Optional[Dict[int, Dict[str, Any]]] = None
                     ) -> Dict[str, Any]:
    """Trace a module, write it back, and require it byte for byte.

    Returns the trace and info on success; raises otherwise. This is the only
    check that means anything for a writer -- inspection cannot tell a module
    that re-encodes exactly from one that re-encodes plausibly.
    """
    with open(path, "rb") as fh:
        original = fh.read()
    trace, info = as_module.trace_module(path, opcodes=opcodes)
    rebuilt = write(trace, info["dialect"])
    if rebuilt != original:
        where = _first_difference(original, rebuilt)
        raise as_module.ParseError(
            "round-trip mismatch: %d bytes in, %d out, first difference at 0x%X"
            % (len(original), len(rebuilt), where))
    return {"trace": trace, "info": info, "size": len(original)}


def _first_difference(a: bytes, b: bytes) -> int:
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return i
    return min(len(a), len(b))


# --------------------------------------------------------------------------
# editing
# --------------------------------------------------------------------------

def find_literals(trace: Sequence[Tuple]) -> List[Tuple[int, bytes]]:
    """Every new-string field in the trace, as (position, bytes)."""
    return [(i, item[1]) for i, item in enumerate(trace)
            if item[0] == "strnew"]


def replace_literal(trace: Sequence[Tuple], old: bytes, new: bytes,
                    count: int = 0) -> List[Tuple]:
    """Swap a string literal for another, of any length.

    Safe because saved-string back-references are by index: entry N stays entry
    N, so nothing that points at this string needs touching and only its own
    encoded length changes. `count` limits how many occurrences are replaced
    (0 = all).
    """
    out = list(trace)
    done = 0
    for i, item in enumerate(out):
        if item[0] == "strnew" and item[1] == old:
            out[i] = ("strnew", new)
            done += 1
            if count and done >= count:
                break
    if not done:
        raise KeyError("literal %r is not a new-string field in this module"
                       % old[:40])
    return out


def replace_instruction(trace: Sequence[Tuple], position: int, opcode: int,
                        operands: Sequence[int]) -> List[Tuple]:
    """Replace one instruction. `position` is an index into the trace."""
    out = list(trace)
    if out[position][0] != "op":
        raise ValueError("trace entry %d is %r, not an instruction"
                         % (position, out[position][0]))
    out[position] = ("op", opcode, list(operands))
    return out


def literal_report(trace: Sequence[Tuple], limit: int = 20) -> str:
    lits = find_literals(trace)
    lines = ["%d new-string fields" % len(lits)]
    for pos, text in lits[:limit]:
        lines.append("  [%6d] %r" % (pos, text[:60]))
    if len(lits) > limit:
        lines.append("  ... %d more" % (len(lits) - limit))
    return "\n".join(lines)
