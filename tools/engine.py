"""
engine -- which toolkit built this executable, BGT or NVGT?

The two engines package a script so differently that the question is settled by
structure, never by strings or file names:

    BGT     a 12-byte "xproc10\\0" + u32 trailer at EOF, pointing back at an
            overlay whose first AES block decrypts (under a generated key) to a
            container header of 32 hex characters and '='.        -> bgtlib
    NVGT    nothing at EOF on Windows. The payload starts where the last PE
            section ends: a Poco 7-bit embedded-pack count, the packs, then the
            XOR-masked payload size, then the encrypted zlib stream. Non-PE
            stubs carry a u32 stub-size trailer instead.           -> nvgt.extract

`identify()` claims an engine only when that engine's own self-verifying layer
agrees: for BGT the seed search has to decrypt a real container header, and for
NVGT one of the verified payload profiles has to decrypt, unpad and inflate to
a complete stream. A file that merely *resembles* one of them is reported as
unknown, with the reason each candidate was rejected -- a wrong guess here would
send the user down the wrong half of the toolkit with confident-looking errors.

    python tools/engine.py game.exe [more.exe ...]
    bgt identify game.exe
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:                      # installed as a package
    from . import bgtlib
except ImportError:       # run directly from a checkout
    import bgtlib

BGT = "bgt"
NVGT = "nvgt"


@dataclass
class Identity:
    """What an executable is, and the evidence for it.

    `engine` is BGT, NVGT or None. `facts` holds whatever the confirming layer
    established (seed, overlay offset, payload profile, embedded packs ...);
    `rejected` records why each engine that was tried did not match, so an
    unknown result still says something useful.
    """

    path: str
    engine: Optional[str] = None
    facts: Dict[str, Any] = field(default_factory=dict)
    rejected: Dict[str, str] = field(default_factory=dict)

    @property
    def known(self) -> bool:
        return self.engine is not None

    def summary(self) -> str:
        name = os.path.basename(self.path)
        if self.engine == BGT:
            return ("%s: BGT (overlay 0x%X, key seed 0x%02X%s)"
                    % (name, self.facts["overlay_offset"], self.facts["seed"],
                       "" if self.facts["seed"] == 0x11 else ", NON-STOCK"))
        if self.engine == NVGT:
            packs = self.facts.get("embedded_packs") or []
            return ("%s: NVGT (%s profile, %d bytes of bytecode%s)"
                    % (name, self.facts.get("packaging_profile", "?"),
                       self.facts.get("bytecode_bytes", 0),
                       ", %d embedded pack%s" % (len(packs), "" if len(packs) == 1 else "s")
                       if packs else ""))
        reasons = "; ".join("%s: %s" % kv for kv in self.rejected.items())
        return "%s: not recognised (%s)" % (name, reasons or "no candidates")


def _probe_bgt(data: bytes, ident: Identity) -> bool:
    try:
        offset, embedded, ciphertext = bgtlib.split_overlay(data)
        seed, _key = bgtlib.find_seed(ciphertext)
    except bgtlib.BgtError as exc:
        ident.rejected[BGT] = str(exc)
        return False
    ident.engine = BGT
    ident.facts.update(overlay_offset=offset, seed=seed,
                       embedded_pack_bytes=len(embedded),
                       ciphertext_bytes=len(ciphertext))
    return True


def _probe_nvgt(data: bytes, ident: Identity) -> bool:
    try:                      # installed as a package
        from .nvgt import extract
    except ImportError:       # run directly from a checkout
        from nvgt import extract

    try:
        start = extract.payload_offset(data)
    except (ValueError, IndexError) as exc:
        ident.rejected[NVGT] = "unreadable executable headers: %s" % exc
        return False
    if start >= len(data):
        ident.rejected[NVGT] = ("nothing is appended after the last PE section "
                                "-- no compiled payload")
        return False

    try:
        info, stream = extract.extract_data(data)
    except (ValueError, OSError) as exc:
        ident.rejected[NVGT] = str(exc)
        return False
    except Exception as exc:  # noqa: BLE001 -- zlib/struct errors from a non-NVGT file
        ident.rejected[NVGT] = "%s: %s" % (type(exc).__name__, exc)
        return False

    ident.engine = NVGT
    try:
        packs = [p.name for p in extract.embedded_packs(data)]
    except (ValueError, IndexError):
        packs = []            # legacy fixed-size profile has no pack block
    ident.facts.update(
        payload_offset=extract.payload_offset(data),
        packaging_profile=getattr(info, "packaging_profile", "current_preamble"),
        plugins=list(info.plugins), system_namespaces=list(info.namespaces),
        build_timestamp=info.timestamp, bytecode_bytes=len(info.bytecode),
        stream_bytes=len(stream), embedded_packs=packs)
    return True


def identify_bytes(data: bytes, path: str = "<bytes>") -> Identity:
    """Identify an executable held in memory. Never raises for a bad input."""
    ident = Identity(path)
    # BGT first: its trailer check fails in microseconds on anything else,
    # while the NVGT probe decrypts and inflates a whole payload.
    if _probe_bgt(data, ident):
        return ident
    _probe_nvgt(data, ident)
    return ident


def identify(path: str) -> Identity:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        ident = Identity(path)
        ident.rejected["io"] = str(exc)
        return ident
    return identify_bytes(data, path)


def redirect_hint(path: str, wanted: str) -> Optional[str]:
    """A one-line pointer when a BGT command is handed an NVGT game or vice versa.

    Returns None when the file is the engine the command wanted, or is neither
    -- there is nothing useful to redirect to then, and the command's own error
    already says what went wrong.
    """
    ident = identify(path)
    if not ident.known or ident.engine == wanted:
        return None
    if ident.engine == NVGT:
        return ("%s is an NVGT game, not BGT -- try: bgt nvgt recover %s -o recovered.zip"
                % (os.path.basename(path), path))
    return ("%s is a BGT game, not NVGT -- try: bgt unpack %s -o work/"
            % (os.path.basename(path), path))


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", nargs="+")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    results = [identify(p) for p in args.exe]
    if args.json:
        print(json.dumps([{"path": r.path, "engine": r.engine, "facts": r.facts,
                           "rejected": r.rejected} for r in results], indent=1))
    else:
        for r in results:
            print(r.summary())
    return 0 if all(r.known for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
