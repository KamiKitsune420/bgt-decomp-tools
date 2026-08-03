"""
bgt_crack -- search a module for the password that opens an encrypted asset pack.

The password is whatever the game's script passed to `set_sound_decryption_key()`.
Sometimes it is a plain literal in the module, in which case harvesting candidates
and running each through the KDF finds it. Often it is *computed*, and then no
amount of searching will -- see "Finding the password" in CLAUDE.md, and prefer
reading the caller out of the disassembly (`as_disasm.py`) over brute force.

    python bgt_crack.py sounds.dat --dict game_bytecode.bin
    python bgt_crack.py sounds.dat --dict game_bytecode.bin --workers 8

Checking a candidate costs **one AES block**: `bgt_pack` compares
AES-ECB(key, 16 zero bytes) against the tag each entry stores, so nothing has to
be decrypted and no plaintext has to be recognised. With `bgt_kdf`'s salt cache
that puts the whole loop at roughly 10^5 candidates/second per core.

## What "no match" means

A negative result here is informative, but only about the candidates actually
tried. The report prints how many that was and where they came from, because
"tested 800k candidates, 0 hits" and "tested the 12 strings I remembered to
harvest, 0 hits" are very different claims and look identical otherwise.

Several harvesters are provided because BGT passwords turn up in several shapes:

  * `strings`  -- every length-prefixed string the module's own encoding yields.
    Exact boundaries, so a literal is recovered as the script wrote it. NUL bytes
    inside a literal are kept: the KDF takes a pointer and a length, not a C
    string, so they are part of the password.
  * `runs`     -- consecutive literals joined with NUL. Real passwords have this
    shape: a pointer into the string block plus an over-long length reads several
    NUL-terminated strings as one value. Manamon 2's confirmed DRM password
    `al ba` and three others are all slices of this kind, so a search over whole
    literals alone would have missed every one.
  * `cores`    -- the readable part of a NUL-padded literal. Tomb Hunter writes
    its keys as `"\\0" * 19 + "melhesday" + "\\0" * 53`, and whether the password
    is the literal or the word inside it is not knowable here, so both are tried.
  * `printable` -- plain printable runs, the crude fallback.
"""

import argparse
import os
import sys
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

try:                      # installed as a package
    from . import as_module, bgt_kdf, bgt_pack
except ImportError:       # run directly from a checkout
    import as_module
    import bgt_kdf
    import bgt_pack


PROGRESS_EVERY = 10_000


# --------------------------------------------------------------------------
# candidate harvesting
# --------------------------------------------------------------------------

def harvest_strings(data: bytes, dialect: Optional[str] = None) -> List[bytes]:
    """Every literal the module's own string encoding yields."""
    return as_module.module_strings(data, dialect)


def harvest_runs(literals: Sequence[bytes], max_join: int = 4) -> List[bytes]:
    """Consecutive literals joined with NUL, 2..max_join at a time.

    This is the shape a real BGT password has: the runtime reads a `std::string`
    whose declared length overruns its own storage, so the value is several
    NUL-terminated strings in a row. Searching only whole literals cannot find one.
    """
    out: List[bytes] = []
    for n in range(2, max_join + 1):
        for i in range(len(literals) - n + 1):
            out.append(b"\x00".join(literals[i:i + n]))
    return out


def harvest_cores(literals: Sequence[bytes]) -> List[bytes]:
    """The readable parts of literals that carry NUL bytes.

    A NUL-padded literal has two readings and only one of them can be right, so
    both are tried: the whole thing, which `strings` already yields, and what is
    left once the padding is taken off. Tomb Hunter ships
    `"\\0" * 19 + "melhesday" + "\\0" * 53` and installs it as a decoy key --
    whether the password is that literal or the word inside it is not something
    the harvester can know.

    Yields the NUL-trimmed literal, the NUL-free concatenation, and each
    NUL-separated piece; `build_candidates` de-duplicates the overlap.
    """
    out: List[bytes] = []
    for lit in literals:
        if b"\x00" not in lit:
            continue
        out.append(lit.strip(b"\x00"))
        out.append(lit.replace(b"\x00", b""))
        out.extend(piece for piece in lit.split(b"\x00") if piece)
    return out


def harvest_printable(data: bytes, minimum: int = 4) -> List[bytes]:
    """Plain printable runs -- the crude sweep, kept as a fallback.

    Boundaries are wrong by construction (a run does not know where the literal
    ended), so this finds things the encoding-aware harvester cannot only when
    the password is not a literal at all.
    """
    out, cur = [], bytearray()
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(b)
        else:
            if len(cur) >= minimum:
                out.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= minimum:
        out.append(bytes(cur))
    return out


HARVESTERS = ("strings", "runs", "cores", "printable")


def build_candidates(module: bytes, which: Sequence[str]) -> Tuple[List[bytes], Dict[str, int]]:
    """Harvest, de-duplicate, and report how many each source contributed."""
    seen = set()
    out: List[bytes] = []
    counts: Dict[str, int] = {}
    literals: List[bytes] = []

    for name in which:
        if name == "strings":
            produced = literals = harvest_strings(module)
        elif name == "runs":
            produced = harvest_runs(literals or harvest_strings(module))
        elif name == "cores":
            produced = harvest_cores(literals or harvest_strings(module))
        elif name == "printable":
            produced = harvest_printable(module)
        else:
            raise SystemExit("unknown harvester %r (pick from %s)"
                             % (name, ", ".join(HARVESTERS)))
        fresh = 0
        for c in produced:
            if c and c not in seen:
                seen.add(c)
                out.append(c)
                fresh += 1
        counts[name] = fresh
    return out, counts


# --------------------------------------------------------------------------
# the search
# --------------------------------------------------------------------------

def _check_chunk(args: Tuple[Sequence[bytes], frozenset]) -> List[Tuple[bytes, str]]:
    """Worker body: return (password, key hex) for candidates whose key verifies."""
    candidates, tags = args
    hits = []
    for cand in candidates:
        key = bgt_kdf.aes_key(cand)
        if bgt_pack.tag_for_key(key) in tags:
            hits.append((cand, key.hex()))
    return hits


def _chunks(seq: Sequence[bytes], size: int) -> Iterator[Sequence[bytes]]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _fmt_eta(seconds: float) -> str:
    if seconds < 90:
        return "%ds" % int(seconds)
    if seconds < 5400:
        return "%dm" % int(seconds / 60)
    return "%.1fh" % (seconds / 3600.0)


def search(candidates: Sequence[bytes], tags: Iterable[bytes],
           workers: int = 1, progress: bool = True,
           chunk: int = 2000) -> Dict[str, Any]:
    """Try every candidate against the pack's key-verification tags."""
    tagset = frozenset(tags)
    total = len(candidates)
    started = time.time()
    hits: List[Tuple[bytes, str]] = []
    done = 0

    def report(force=False):
        if not progress or (not force and done % PROGRESS_EVERY):
            return
        elapsed = time.time() - started
        rate = done / elapsed if elapsed > 0 else 0.0
        remaining = (total - done) / rate if rate > 0 else 0.0
        sys.stderr.write("\r[%s / %s] %5.1f%%  %7.0f/s  ~%s remaining   "
                         % (f"{done:,}", f"{total:,}",
                            100.0 * done / total if total else 100.0,
                            rate, _fmt_eta(remaining)))
        sys.stderr.flush()

    if workers > 1 and total:
        import multiprocessing
        pieces = list(_chunks(list(candidates), chunk))
        with multiprocessing.Pool(workers) as pool:
            for piece, found in zip(
                    pieces, pool.imap(_check_chunk,
                                      ((p, tagset) for p in pieces), chunksize=1)):
                done += len(piece)
                for cand, keyhex in found:
                    hits.append((cand, keyhex))
                    if progress:
                        sys.stderr.write("\r%-70s\n" % "")
                    print("MATCH  %r  ->  %s" % (cand, keyhex))
                report()
    else:
        for cand in candidates:
            key = bgt_kdf.aes_key(cand)
            if bgt_pack.tag_for_key(key) in tagset:
                hits.append((cand, key.hex()))
                if progress:
                    sys.stderr.write("\r%-70s\n" % "")
                print("MATCH  %r  ->  %s" % (cand, key.hex()))
            done += 1
            report()

    report(force=True)
    if progress:
        sys.stderr.write("\n")
    return {"tested": done, "elapsed": time.time() - started,
            "matches": hits, "distinct_keys": len(tagset)}


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pack", help="the encrypted SFPv1 pack (e.g. sounds.dat)")
    ap.add_argument("--dict", dest="dictionary", required=True,
                    help="recovered module bytecode to harvest candidates from")
    ap.add_argument("--harvest", default="strings,runs,cores",
                    help="comma-separated: %s (default: strings,runs,cores)"
                         % ", ".join(HARVESTERS))
    ap.add_argument("--workers", type=int, default=1,
                    help="parallel workers (default 1; 0 = os.cpu_count())")
    ap.add_argument("--extra", action="append", default=[],
                    help="an additional candidate to try, repeatable")
    ap.add_argument("--quiet", action="store_true", help="no progress output")
    args = ap.parse_args()

    try:
        _version, entries = bgt_pack.parse(args.pack)
    except bgt_pack.PackError as exc:
        print("cannot read %s: %s" % (args.pack, exc), file=sys.stderr)
        return 2

    tags = bgt_pack.tag_index(entries)
    encrypted = sum(1 for e in entries if e.encrypted)
    print("%s: %d entries, %d encrypted, %d distinct key%s"
          % (os.path.basename(args.pack), len(entries), encrypted, len(tags),
             "" if len(tags) == 1 else "s"))
    if not tags:
        print("nothing is encrypted -- no password to find")
        return 0

    with open(args.dictionary, "rb") as fh:
        module = fh.read()
    which = [w.strip() for w in args.harvest.split(",") if w.strip()]
    candidates, counts = build_candidates(module, which)
    for extra in args.extra:
        candidates.append(extra.encode("utf-8"))

    print("candidates: %s" % ", ".join("%s=%s" % (k, f"{v:,}")
                                       for k, v in counts.items()), end="")
    print("%s  total %s" % (", extra=%d" % len(args.extra) if args.extra else "",
                            f"{len(candidates):,}"))

    workers = args.workers or (os.cpu_count() or 1)
    result = search(candidates, tags.keys(), workers=workers,
                    progress=not args.quiet)

    print()
    print("tested        %s candidates in %.1fs (%.0f/s, %d worker%s)"
          % (f"{result['tested']:,}", result["elapsed"],
             result["tested"] / result["elapsed"] if result["elapsed"] else 0.0,
             workers, "" if workers == 1 else "s"))
    print("distinct keys %d" % result["distinct_keys"])
    print("matches       %d" % len(result["matches"]))
    for cand, keyhex in result["matches"]:
        opened = len(bgt_pack.key_matches(entries, bytes.fromhex(keyhex)))
        print("   %r -> %s  (opens %d/%d encrypted entries)"
              % (cand, keyhex, opened, encrypted))

    if not result["matches"]:
        print()
        print("No candidate matched. That rules out these %s candidates, not the"
              % f"{result['tested']:,}")
        print("KDF -- if the password is computed rather than stored, no harvest")
        print("can contain it. Disassemble the caller of set_sound_decryption_key")
        print("instead:  bgt disasm <exe> <module> -f set_sound_decryption_key")
    return 0 if result["matches"] else 1


if __name__ == "__main__":
    sys.exit(main())
