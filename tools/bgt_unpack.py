"""
bgt_unpack -- run the BGT unpacking chain over one or more executables.

    python bgt_unpack.py <game.exe> [more.exe ...] [-o OUTDIR]

Prints a per-layer report and, with -o, writes the recovered AngelScript bytecode
(plus the intermediates) so the next stage has something to read.
"""

import argparse
import collections
import math
import os
import sys

try:                      # installed as a package
    from . import bgtlib
except ImportError:       # run directly from a checkout
    import bgtlib


def entropy(b):
    if not b:
        return 0.0
    counts = collections.Counter(b)
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def angelscript_probe(bc):
    """Peek at the head of a decoded module.

    asCReader::ReadInner reads a one-byte noDebugInfo flag, then an encoded uint
    enum count. The string encoding that follows is what distinguishes BGT builds:
    older ones tag each string 'n' (new) / 'r' (back-reference), newer ones use
    AngelScript's len*2 savedStrings scheme.
    """
    if len(bc) < 8:
        return "too short to identify"
    no_debug = bc[0]
    b = bc[1]
    if b & 0x80 == 0:
        count, nxt = b, bc[2]
    elif b & 0xC0 == 0x80:
        count, nxt = ((b & 0x3F) << 8) | bc[2], bc[3]
    else:
        count, nxt = None, bc[2]

    if nxt == 0x6E:
        style = "tagged strings ('n'/'r') -- Psycho Strike lineage"
    elif nxt % 2 == 0:
        style = "len*2 savedStrings -- newer AngelScript"
    else:
        style = "unrecognised (next byte 0x%02X)" % nxt

    return "noDebugInfo=%d  enums=%s  %s" % (no_debug, count, style)


def report(path, outdir=None, seed=None):
    name = os.path.basename(path)
    size = os.path.getsize(path)
    print("=" * 72)
    print("%s   (%d bytes)" % (name, size))
    print("=" * 72)

    try:
        u = bgtlib.unpack_file(path, seed=seed)
    except bgtlib.BgtError as e:
        print("  FAILED: %s" % e)
        return None

    print("  overlay offset      0x%08X  (%d bytes)" % (u.overlay_offset, u.overlay_size))
    if u.embedded_pack:
        print("  embedded pack       %d bytes" % len(u.embedded_pack))
    print("  key seed            0x%02X%s" % (u.seed, "  (stock)" if u.seed == 0x11 else "  <-- NON-STOCK"))
    print("  aes key             %s" % u.aes_key.hex())
    print("  container           %s=%d" % (u.container_magic, u.container_flag))
    print("  compressed          %d bytes" % len(u.compressed))
    print("  bytecode            %d bytes   entropy %.4f"
          % (len(u.bytecode), entropy(u.bytecode)))
    print("  angelscript         %s" % angelscript_probe(u.bytecode))

    if outdir:
        os.makedirs(outdir, exist_ok=True)
        stem = os.path.splitext(name)[0]
        for suffix, blob in (("bytecode.bin", u.bytecode),
                             ("compressed.bin", u.compressed)):
            dest = os.path.join(outdir, "%s_%s" % (stem, suffix))
            with open(dest, "wb") as f:
                f.write(blob)
        if u.embedded_pack:
            dest = os.path.join(outdir, "%s_embedded.pack" % stem)
            with open(dest, "wb") as f:
                f.write(u.embedded_pack)
        print("  written to          %s" % outdir)
    return u


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", nargs="+", help="BGT executable(s) to unpack")
    ap.add_argument("-o", "--outdir", help="write recovered bytecode here")
    ap.add_argument("--seed", type=lambda s: int(s, 0),
                    help="force a key seed instead of recovering it")
    args = ap.parse_args()

    ok = 0
    for path in args.exe:
        if report(path, args.outdir, args.seed) is not None:
            ok += 1
        print()
    print("%d/%d unpacked" % (ok, len(args.exe)))
    return 0 if ok == len(args.exe) else 1


if __name__ == "__main__":
    sys.exit(main())
