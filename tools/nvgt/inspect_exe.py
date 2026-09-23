"""Inspect an NVGT executable without running it or consulting game sources.

python inspect_exe.py game.exe --compare path/to/nvgt.exe --output report.json
python inspect_exe.py game.exe --source recovered.nvgt --output report.json
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct

try:                      # installed as a package
    from . import extract
    from .asreader import read_module
    from .decompile import decompile_module
except ImportError:       # run directly from a checkout
    import extract
    from asreader import read_module
    from decompile import decompile_module


def identity(data):
    """Return literal evidence. Ambiguous version strings remain candidates."""
    versions = [{"value": m.group().decode(), "offset": m.start()}
                for m in re.finditer(rb"(?<=\x00)[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?(?=\x00)", data)]
    prerelease = sorted({v["value"] for v in versions if "-" in v["value"]})
    commits = [{"value": m.group().decode(), "offset": m.start()}
               for m in re.finditer(rb"(?<=\x00)[a-f0-9]{40}(?=\x00)", data)]
    def build_time(raw):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("cp1252")  # Windows strftime may use ANSI
    dates = [{"value": build_time(m.group()), "offset": m.start()}
             for m in re.finditer(rb"(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), [^\x00]{1,180}(?=\x00)", data)]
    return {"version": prerelease[0] if len(prerelease) == 1 else None,
            "version_selection": "unique prerelease literal" if len(prerelease) == 1 else "ambiguous; inspect candidates",
            "version_candidates": versions, "commit_candidates": commits,
            "build_time_candidates": dates}


def pe_imports(data):
    if data[:2] != b"MZ":
        return []
    extract.payload_offset(data)  # Validate headers, table and raw sections.
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    if optional_size < 2:
        raise ValueError("missing PE optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10b, 0x20b):
        raise ValueError("unsupported PE optional header")
    directory = optional + (112 if magic == 0x20b else 96)
    if directory + 16 > optional + optional_size:
        return []
    import_rva, import_size = struct.unpack_from("<II", data, directory + 8)
    if not import_rva:
        return []
    table = optional + optional_size
    def offset(rva):
        for index in range(sections):
            base = table + index * 40
            size, address, raw_size, raw = struct.unpack_from("<IIII", data, base + 8)
            if address <= rva < address + raw_size:
                return raw + rva - address
        raise ValueError("Import RVA outside raw PE sections")
    cursor = offset(import_rva)
    limit = min(len(data), cursor + import_size) if import_size else len(data)
    result = []
    while cursor + 20 <= limit:
        if not any(data[cursor:cursor + 20]):
            return result
        name = offset(struct.unpack_from("<I", data, cursor + 12)[0])
        end = data.find(b"\0", name, min(len(data), name + 4096))
        if end < 0:
            raise ValueError("unterminated PE import name")
        result.append(data[name:end].decode("ascii"))
        cursor += 20
    raise ValueError("truncated or unterminated PE import directory")


def inspect(path, compare=None, source=None):
    path = Path(path).resolve()
    data = path.read_bytes()
    info, stream = extract.extract(path)
    module = read_module(info.bytecode)
    module.nvgt_info = info
    report = {"executable": str(path), "executable_sha256": hashlib.sha256(data).hexdigest(),
              "executable_bytes": len(data), "payload_offset": extract.payload_offset(data),
              "engine_identity_evidence": identity(data), "pe_imports": pe_imports(data),
              "plugins": info.plugins, "system_namespaces": info.namespaces,
              "engine_properties": info.engine_properties,
              "program_build_timestamp_microseconds": info.timestamp,
              "program_build_time_utc": datetime.fromtimestamp(info.timestamp / 1_000_000, timezone.utc).isoformat() if info.timestamp else None,
              "no_auto_chdir": bool(info.no_auto_chdir), "decrypted_stream_bytes": len(stream),
              "bytecode_bytes": len(info.bytecode), "debug_info": module.debug_info,
              "packaging_profile": getattr(info, "packaging_profile", "current_preamble"),
              "bytecode_profile": getattr(module, "bytecode_profile", None),
              "classes": len(module.classes), "globals": len(module.globals),
              "script_functions": len(module.script_functions)}
    libraries = []
    for dll in sorted((path.parent / "lib").glob("*.dll")):
        dll_data = dll.read_bytes()
        entry = {"name": dll.name, "bytes": len(dll_data), "sha256": hashlib.sha256(dll_data).hexdigest()}
        if compare:
            candidate = Path(compare).parent / "lib" / dll.name
            entry["matches_comparison_library"] = (hashlib.sha256(candidate.read_bytes()).hexdigest() == entry["sha256"]) if candidate.exists() else None
        libraries.append(entry)
    report["adjacent_libraries"] = libraries
    if compare:
        comparison_data = Path(compare).read_bytes()
        report["comparison_engine"] = {"path": str(Path(compare).resolve()),
                                       "identity_evidence": identity(comparison_data)}
        report["registered_type_literals_absent_from_comparison_core"] = sorted({
            t.name for t in module.used_types if t and t.kind in ("app", "template")
            and t.name.encode() not in comparison_data})
    if source:
        text = decompile_module(module)
        destination = Path(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        report["recovery_diagnostics"] = {"source": str(destination.resolve()),
            "lines": len(text.splitlines()), "explicit_unknown_markers": dict(Counter(re.findall(r"<\?[^>]*>", text))),
            "unstructured_gotos": len(re.findall(r"\bgoto\b", text)),
            "temporary_references": len(re.findall(r"\btmp[0-9]+\b", text)),
            "decompiler_errors": text.count("[decompiler error:"),
            "unhandled_opcodes": text.count("(unhandled)"),
            "working_source_verified": False}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable")
    parser.add_argument("--compare")
    parser.add_argument("--source")
    parser.add_argument("--output")
    args = parser.parse_args()
    report = inspect(args.executable, args.compare, args.source)
    result = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result + "\n", encoding="utf-8")
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
