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
  * `encrypted` -- `string_decrypt(blob, key)`, composed. A game that cares
    about its sounds does not store the password as a literal; it stores an
    encrypted blob and the key to it, both in the module. Super Egg Hunt's
    `set_sound_decryption_key(string_decrypt(h_key, "af-dc7=rqp+"))` is
    `puppiesandpandas`, and no harvest over literals alone can reach it --
    `module_strings` cannot even represent `h_key`, because its plausibility
    test rejects every byte outside printable ASCII and a cipher blob is
    nothing else. 3,392 candidates, 0 hits, and the password was in the file.
  * `callsite` -- the literals the password EXPRESSION reaches, read out of
    the recovered source. This is the one that is not a sweep: a computed
    password is computed from something, and the something is an argument at
    the `set_sound_decryption_key` call site or a literal in the function it
    calls. Manamon 1 is `set_sound_decryption_key(get("<119 bytes>"), false)`,
    and that literal is the whole input to its key.
  * `hashchain` -- an iterated `string_hash` over those seeds, yielding every
    intermediate digest. The engine offers two algorithms and a binary or hex
    result, so four chains are walked, and a candidate costs one AES block --
    which is why the selection rule at the end of the game's own loop does not
    have to be modelled. Manamon 1 keeps the iteration of 218 whose digest
    holds the most NUL bytes; it is iteration 111, and a plain chain reaches it.
  * `printable` -- plain printable runs, the crude fallback.
"""

import argparse
import base64
import hashlib
import os
import re
import sys
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

try:                      # installed as a package
    from . import as_module, bgt_kdf, bgt_pack, bgt_string_crypt
except ImportError:       # run directly from a checkout
    import as_module
    import bgt_kdf
    import bgt_pack
    import bgt_string_crypt


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


def harvest_blobs(data: bytes, dialect: Optional[str] = None) -> List[bytes]:
    """Every literal that looks like cipher text rather than text."""
    return as_module.module_strings(data, dialect,
                                    accept=as_module.literal_is_cipher_shaped)


#: how many text literals to try as the `string_decrypt` key for one blob.
#: Every one costs a key schedule plus two AES blocks, so the whole cross
#: product is still cheap -- this only bounds the pathological case.
MAX_CRYPT_KEYS = 20_000


def harvest_encrypted(blobs: Sequence[bytes], keys: Sequence[bytes],
                      limit: int = MAX_CRYPT_KEYS) -> List[bytes]:
    """`string_decrypt(blob, key)` -- the shape a BGT game stores a key in.

    A game that cares about its sounds does not write the pack password as a
    literal, because `bgt crack` would find it. It writes
    `set_sound_decryption_key(string_decrypt(h_key, "af-dc7=rqp+"))`, with
    `h_key` an encrypted blob and the *crypt* key the plain literal. Both
    halves are in the module, so the password is recoverable -- but only by a
    harvest that composes them, which is what this does: every blob decrypted
    under every text literal, keeping whatever unwraps to a string.

    `string_decrypt` is self-checking, which is what makes the cross product
    affordable: BGT wraps a plaintext as `printf<len>\\0<data>` and `unwrap`
    returns `None` unless that header is there, so a wrong pairing is rejected
    by the format and never reaches the pack.
    """
    out: List[bytes] = []
    seen = set()
    for blob in blobs:
        for key in keys[:limit]:
            if not key:
                continue
            for use_kdf in (True, False):
                try:
                    plain = bgt_string_crypt.string_decrypt(blob, key, use_kdf)
                except Exception:
                    continue
                if plain and plain not in seen:
                    seen.add(plain)
                    out.append(plain)
    return out


#: The engine function whose argument is the pack password. A game that
#: computes its key computes it for this call.
KEY_API = "set_sound_decryption_key"
_IDENT = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*\(")


def _arguments(text: str, start: int) -> str:
    """The bracket-matched argument list of the call opening at `start`."""
    depth, i, n = 0, start, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if not depth:
                return text[start + 1:i]
        i += 1
    return ""


def harvest_call_site(text: str, api: str = KEY_API,
                      depth: int = 2) -> List[bytes]:
    """The literals the password expression reaches, out of recovered source.

    CLAUDE.md's advice for a computed password is to read the caller of
    `set_sound_decryption_key` rather than sweep the module, and this is that
    advice done mechanically. The argument list at each call site gives its own
    literals; every script function it names gives the literals in its body,
    `depth` levels deep. For Manamon 1 the literal is at the call site itself
    and the function it names is `get`, so one level is enough and the whole
    seed set is **2 strings** where the module holds 82,169 literals.

    Literals are read back with `bgt_audit.unescape`, which is written from the
    engine's lexer rules -- a password holds NUL bytes and bytes above 0x7F,
    and both arrive in the text as `\\xNN`.
    """
    try:                                   # the heavier readers, only if asked
        from . import bgt_audit, bgt_libcheck
    except ImportError:
        import bgt_audit
        import bgt_libcheck
    out: List[bytes] = []
    seen: set = set()

    def take(fragment: str, level: int) -> None:
        for raw in bgt_libcheck._STRING.findall(fragment):
            value = bgt_audit.unescape(raw)
            if value and value not in seen:
                seen.add(value)
                out.append(value)
        if level <= 0:
            return
        for name in {m.group(1) for m in _IDENT.finditer(fragment)}:
            for body in bodies_by_name.get(name, ()):
                take(body, level - 1)

    # Keyed by the BARE name, because that is what a call site writes: a
    # method and a global function of one name both qualify, and taking the
    # literals of both is the cheap side of the mistake.
    bodies_by_name: Dict[str, List[str]] = {}
    for label, bodies in bgt_libcheck.source_functions(text).items():
        for body in bodies:
            bodies_by_name.setdefault(label.rsplit("::", 1)[-1], []).append(body)

    stripped = bgt_libcheck.strip_comments(text)
    for m in re.finditer(r"(?<![\w.])%s\s*\(" % re.escape(api), stripped):
        take(_arguments(stripped, m.end() - 1), depth)
    return out


#: How far to walk a chain. Manamon 1's key is iteration 111 of 218; a
#: candidate costs one AES block, so the bound is generosity rather than a
#: tuned constant -- and it only ever multiplies the seeds the call site named.
CHAIN_DEPTH = 512


def harvest_hashchain(seeds: Sequence[bytes],
                      depth: int = CHAIN_DEPTH) -> List[bytes]:
    """Every intermediate of an iterated `string_hash` over each seed.

    The shape this reaches is the one that defeats every harvester above:
    a password that is a *digest*, so no literal and no composition of literals
    can be it. Manamon 1's is

        string get(string arg0) {
            s = string_base64_decode(arg0);
            for (i = 0; i < 218; i++) {
                s = string_hash(s, 2, true);
                if (i > 100 && i % 84 == 0) s = string_reverse(s);
                ...keep the one whose 64 bytes hold the most NULs...
            }
        }

    **The selection rule does not have to be modelled**, which is the whole
    reason this is affordable: whichever iteration the game picks, that digest
    is somewhere in the chain, and checking one costs a single AES block
    against the tag the pack stores. So the chain is walked and every step is
    offered.

    Four chains per seed, because `string_hash(data, algorithm, binary)` is
    the engine's whole hashing surface and the help file lists exactly two
    algorithms -- 1 SHA256, 2 SHA512 -- each with a binary or a hex result,
    and a chain over the hex form is a different chain. Each seed is also
    tried base64-decoded, since that is how Manamon 1 reads its literal, and
    each digest is offered reversed as well, since `string_reverse` is in the
    same family.

    What it does **not** reach: a reversal (or any other step) that falls
    *before* the iteration the game keeps, because that forks the chain. For
    Manamon 1 the first reversal is iteration 168 and the key is 111, so the
    plain chain reaches it. A title where it does not is the case for reading
    the function, and the recovered source is where it is readable.
    """
    out: List[bytes] = []
    seen: set = set()
    starts: List[bytes] = []
    for seed in seeds:
        if not seed:
            continue
        for value in (seed, _base64(seed)):
            if value and value not in seen:
                seen.add(value)
                starts.append(value)
    out.extend(starts)
    for seed in starts:
        for algorithm in (hashlib.sha256, hashlib.sha512):
            for binary in (True, False):
                current = seed
                for _ in range(depth):
                    digest = algorithm(current).digest()
                    current = digest if binary else digest.hex().encode()
                    # The digest AND what the chain carries forward: in the hex
                    # form they differ, and either can be the password -- the
                    # loop hashes the hex string while a last `binary` round
                    # would hand on the raw digest.
                    for value in (digest, current, digest[::-1],
                                  current[::-1]):
                        if value not in seen:
                            seen.add(value)
                            out.append(value)
    return out


#: base64's own alphabet, spelled out. Padding is recomputed rather than
#: kept, since a literal that is a slice of a larger string has none.
_B64_ALPHABET = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def _base64(value: bytes) -> Optional[bytes]:
    """`string_base64_decode(value)`, or None when nothing decodes.

    Permissive about what is not in the alphabet, because the literal Manamon 1
    decodes holds NUL bytes and spaces and the engine decodes it anyway -- the
    key that comes out is the one the pack's own tag verifies, which is the
    only check that matters here.
    """
    alphabet = bytes(c for c in value if c in _B64_ALPHABET)
    if len(alphabet) < 16:
        return None
    try:
        out = base64.b64decode(alphabet + b"=" * (-len(alphabet) % 4))
    except Exception:
        return None
    return out or None


def read_source(where: str) -> str:
    """The recovered source at `where` -- one .bgt file, or a project tree.

    Concatenated rather than parsed: `callsite` wants the text the call site
    is in and `source_functions` is a brace scanner, so a project read as one
    string answers both. Undecodable bytes are replaced rather than refused --
    a literal above 0x7F is written `\\xNN`, so nothing a seed needs is lost,
    and a file this cannot read is still worth the rest of the tree.
    """
    if os.path.isfile(where):
        paths = [where]
    else:
        paths = [os.path.join(root, name)
                 for root, _, names in os.walk(where)
                 for name in sorted(names) if name.endswith(".bgt")]
    out = []
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            out.append(fh.read())
    return "\n".join(out)


HARVESTERS = ("strings", "runs", "cores", "encrypted", "callsite",
              "hashchain", "printable")


def build_candidates(module: bytes, which: Sequence[str],
                     text: Optional[str] = None) -> Tuple[List[bytes], Dict[str, int]]:
    """Harvest, de-duplicate, and report how many each source contributed.

    `text` is the recovered source, which the `callsite` harvester needs and
    which `hashchain` is seeded from. Without it both yield nothing and say so
    in the counts, because walking a chain from all 82,169 of a module's
    literals is 84 million candidates to avoid reading one function.
    """
    seen = set()
    out: List[bytes] = []
    counts: Dict[str, int] = {}
    literals: List[bytes] = []
    site: List[bytes] = []

    for name in which:
        if name == "strings":
            produced = literals = harvest_strings(module)
        elif name == "runs":
            produced = harvest_runs(literals or harvest_strings(module))
        elif name == "cores":
            produced = harvest_cores(literals or harvest_strings(module))
        elif name == "encrypted":
            produced = harvest_encrypted(harvest_blobs(module),
                                         literals or harvest_strings(module))
        elif name == "callsite":
            produced = site = harvest_call_site(text) if text else []
        elif name == "hashchain":
            # Seeded from the call site, never from the whole module: the
            # chain multiplies its seeds by two thousand.
            if not site and text:
                site = harvest_call_site(text)
            produced = harvest_hashchain(site) if site else []
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
    ap.add_argument("--source", metavar="FILE_OR_DIR",
                    help="a recovered project (or one .bgt) whose text the "
                         "callsite and hashchain harvesters read")
    ap.add_argument("--harvest",
                    default="strings,runs,cores,encrypted,callsite,hashchain",
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
    # The recovered source, for the two harvesters that read the caller
    # rather than sweeping the module. Without it they yield nothing and the
    # counts say so, which is why it is worth passing: a computed password is
    # computed from something the text names.
    text = read_source(args.source) if args.source else None
    candidates, counts = build_candidates(module, which, text=text)
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
