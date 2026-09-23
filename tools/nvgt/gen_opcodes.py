#!/usr/bin/env python3
"""Generate opcodes.py from the pinned AngelScript SDK header.

Parses the asEBCInstr enum, asEBCType enum, asBCTypeSize table and the
asBCInfo[256] table out of angelscript.h so the Python tooling always
matches the exact engine build NVGT was compiled with.

Run from anywhere:  python tools/nvgt/gen_opcodes.py --nvgt-source <checkout>
"""
import argparse
import os
import re
from pathlib import Path

OUT = Path(__file__).resolve().parent / "opcodes.py"


def parse_enum(text: str, name: str) -> dict:
    match = re.search(rf"enum\s+{name}\s*\{{(.*?)\}};", text, re.S)
    if match is None:
        raise ValueError(f"Header is missing enum {name}")
    body = match.group(1)
    entries = {}
    value = 0
    for line in body.splitlines():
        line = line.split("//")[0].strip().rstrip(",").strip()
        if not line:
            continue
        if "=" in line:
            key, _, num = line.partition("=")
            value = int(num.strip(), 0)
            entries[key.strip()] = value
        else:
            entries[line] = value
        value += 1
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--header", type=Path, help="Path to the matching angelscript.h")
    parser.add_argument("--nvgt-source", type=Path, default=os.environ.get("NVGT_SOURCE"))
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--32", dest="is32", action="store_true")
    args = parser.parse_args()
    header = args.header
    if header is None:
        if args.nvgt_source is None:
            parser.error("provide --header, --nvgt-source or NVGT_SOURCE")
        header = args.nvgt_source / "dep_angelscript/sdk/angelscript/include/angelscript.h"
    text = header.read_text(encoding="utf-8", errors="replace")

    bc = parse_enum(text, "asEBCInstr")
    bct = parse_enum(text, "asEBCType")

    sizes_m = re.search(r"const int asBCTypeSize\[24\]\s*=\s*\{(.*?)\};", text, re.S)
    if sizes_m is None:
        raise ValueError("Header is missing asBCTypeSize[24]")
    sizes = [int(x) for x in re.findall(r"[-]?\d+", sizes_m.group(1))]

    # asBCINFO(Name, TYPE, stackInc) and asBCINFO_DUMMY(n) entries, in table order.
    # Dummies fill unused slots; slots 250-255 are real compiler-temporary entries.
    info_m = re.search(r"const asSBCInfo asBCInfo\[256\]\s*=\s*\{(.*)\};", text, re.S)
    if info_m is None:
        raise ValueError("Header is missing asBCInfo[256]")
    entries = []
    for is_dummy, entry_args in re.findall(r"asBCINFO(_DUMMY)?\s*\(([^)]*)\)", info_m.group(1)):
        if is_dummy:
            slot = int(entry_args.strip(), 0)
            entries.append((f"BC_{slot}", "INFO", "0", slot))
        else:
            name, typ, inc = [a.strip() for a in entry_args.split(",")]
            entries.append((name, typ, inc, None))
    dummies = sum(1 for e in entries if e[3] is not None)

    # The header defines PTR_ARG-style aliases via #if defined(AS_64BIT_PTR).
    # NVGT ships 64-bit builds (AS_PTR_SIZE == 2), so pointer args are QW sized.
    # For 32-bit NVGT builds regenerate with --32 and pointer args become DW sized.
    is64 = not args.is32
    ptr_size = 2 if is64 else 1
    alias = {
        "PTR_ARG": "QW_ARG" if is64 else "DW_ARG",
        "PTR_DW_ARG": "QW_DW_ARG" if is64 else "DW_DW_ARG",
        "W_PTR_DW_ARG": "W_QW_DW_ARG" if is64 else "W_DW_DW_ARG",
        "wW_PTR_ARG": "wW_QW_ARG" if is64 else "wW_DW_ARG",
        "rW_PTR_ARG": "rW_QW_ARG" if is64 else "rW_DW_ARG",
    }

    table = {}
    next_free = 0
    for name, typ, inc, slot in entries:
        if slot is not None:          # dummy entry with an explicit slot number
            idx = slot
        else:                         # real entry: first slot not claimed by a dummy
            while next_free in table:
                next_free += 1
            idx = next_free
        table[idx] = (name, typ, inc)
        typ_full = "asBCTYPE_" + alias.get(typ, typ)
        if typ_full not in bct:
            raise SystemExit(f"unknown bc type {typ} for opcode {name}")
        expression = inc.replace("AS_PTR_SIZE", str(ptr_size))
        if re.fullmatch(r"[+-]?0[xX][0-9a-fA-F]+", expression):
            inc_v = int(expression, 0)
        elif re.fullmatch(r"[+-]?\d+(?:[+-]\d+)*", expression):
            inc_v = sum(int(term) for term in re.findall(r"[+-]?\d+", expression))
        else:
            raise ValueError(f"Unsupported stack increment: {inc}")
        table[idx] = {
            "name": name,
            "type": typ_full,
            "size": sizes[bct[typ_full]],
            "stack": inc_v,
        }
    # Dummy slots (asBC_MAXBYTECODE + temporaries) keep type INFO, size 0.
    for i in range(len(entries), 256):
        table[i] = {"name": f"BC_DUMMY_{i}", "type": "asBCTYPE_INFO", "size": 0, "stack": 0}

    lines = [
        '"""AngelScript bytecode tables, generated from the pinned SDK header.',
        "",
        "Generated by tools/gen_opcodes.py from:",
        f"    {header.name}",
        "Do not edit by hand; regenerate instead.",
        '"""',
        "",
        "# asEBCType -> encoded instruction size in dwords",
        "BC_TYPE_SIZE = {",
    ]
    for name, val in sorted(bct.items(), key=lambda kv: kv[1]):
        lines.append(f"    {name!r}: {sizes[val]},")
    lines += [
        "}",
        "",
        "# opcode number -> (name, bc type, size in dwords, stack delta)",
        f"# stack delta assumes AS_PTR_SIZE == {ptr_size} ({64 if is64 else 32}-bit pointers).",
        "OPCODES = {",
    ]
    for idx in sorted(table):
        e = table[idx]
        lines.append(
            f"    {idx}: ({e['name']!r}, {e['type']!r}, {e['size']}, {e['stack']}),"
        )
    lines += [
        "}",
        "",
        "# name -> opcode number",
        "OPCODE_BY_NAME = {v[0]: k for k, v in OPCODES.items()}",
        "",
        "# Temporary/compiler-only tokens never appear in final bytecode.",
        "TEMPORARY_OPS = {250, 251, 252, 253, 254, 255}",
        "",
        f"# asBC_MAXBYTECODE == {bc['asBC_MAXBYTECODE']}",
        "assert len(OPCODES) == 256, 'table must cover all 256 slots'",
        "assert OPCODES[0][0] == 'PopPtr' and OPCODES[200][0] == 'Thiscall1', 'opcode order sanity'",
        "assert OPCODES[254][0] == 'LINE' and OPCODES[255][0] == 'LABEL', 'temp token sanity'",
        "",
    ]
    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {args.output} ({len(entries)} real opcodes, {dummies} dummy slots)")


if __name__ == "__main__":
    main()
