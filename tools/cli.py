"""
bgt -- one entry point for the whole toolkit.

    bgt unpack game.exe -o work/           recover the AngelScript module
    bgt info game.exe                      trailer, seed and container only
    bgt opcodes game.exe                   dump asBCInfo[]
    bgt disasm game.exe work/game_bytecode.bin -o game.asm
    bgt lift   work/game_bytecode.bin game.exe -o game.as
    bgt pack list sounds.dat
    bgt pack extract sounds.dat -o sounds/ --key <hex>
    bgt crack sounds.dat --dict work/game_bytecode.bin
    bgt asm    work/game_bytecode.bin game.exe \
               --replace sounds.dat=my.dat -o modified.bin
    bgt repack game.exe modified.bin -o patched.exe
    bgt validate game.exe patched.exe
    bgt ghidra status                      is Ghidra + a JDK 21+ available?
    bgt ghidra decompile game.exe --string _builtin_function_

Every subcommand is a thin wrapper: it parses arguments, calls the library, and
formats the result. The logic lives in the modules, so `bgt unpack` and
`python tools/bgt_unpack.py` do the same work by the same path.
"""

import argparse
import os
import sys
from typing import List, Optional

try:                      # installed as a package
    from . import (as_disasm, as_lift, as_module, as_opcodes, as_write,
                   bgt_crack, bgt_ghidra, bgt_pack, bgt_repack, bgt_unpack,
                   bgt_validate, bgtlib)
except ImportError:       # run directly from a checkout
    import as_disasm
    import as_lift
    import as_module
    import as_opcodes
    import as_write
    import bgt_crack
    import bgt_ghidra
    import bgt_pack
    import bgt_repack
    import bgt_unpack
    import bgt_validate
    import bgtlib


def _fail(message: str) -> int:
    """A clear one-line error, never a traceback -- these are user mistakes."""
    print("bgt: %s" % message, file=sys.stderr)
    return 2


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------

def cmd_unpack(args: argparse.Namespace) -> int:
    ok = 0
    for path in args.exe:
        if bgt_unpack.report(path, args.outdir, args.seed) is not None:
            ok += 1
        print()
    print("%d/%d unpacked" % (ok, len(args.exe)))
    return 0 if ok == len(args.exe) else 1


def cmd_info(args: argparse.Namespace) -> int:
    """Trailer, seed and container -- no decompression, no module parse."""
    try:
        with open(args.exe, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return _fail(str(exc))

    # Decrypt in full but stop before LZ77: AES over a couple of megabytes is
    # milliseconds, decompressing and parsing the module is not. The container
    # declares its own blob length, so parse_container -- which is the verified
    # one -- needs the whole ciphertext to check that declaration.
    try:
        offset, embedded, ciphertext = bgtlib.split_overlay(data)
        seed, key = bgtlib.find_seed(ciphertext)
        plaintext = bgtlib.decrypt(ciphertext, key)
        flag, blob = bgtlib.parse_container(plaintext)
        _comp, declared = bgtlib.lz77_split(blob)
    except bgtlib.BgtError as exc:
        return _fail("%s: %s" % (os.path.basename(args.exe), exc))

    print("%s   (%d bytes)" % (os.path.basename(args.exe), len(data)))
    print("  overlay offset   0x%08X  (%d bytes)"
          % (offset, len(ciphertext) + bgtlib.TRAILER_LEN))
    if embedded:
        print("  embedded pack    %d bytes" % len(embedded))
    print("  key seed         0x%02X%s"
          % (seed, "  (stock)" if seed == 0x11 else "  <-- NON-STOCK"))
    print("  aes key          %s" % key.hex())
    print("  container        %s=%d" % (plaintext[:32].decode("ascii", "replace"),
                                        flag))
    print("  compressed       %d bytes" % len(blob))
    print("  module           %d bytes (declared; not decompressed)" % declared)
    return 0


def cmd_opcodes(args: argparse.Namespace) -> int:
    try:
        info = as_opcodes.extract(args.exe)
    except (ValueError, OSError) as exc:
        return _fail(str(exc))
    print("asBCInfo at file offset 0x%X -- %d opcodes"
          % (info["file_offset"], info["count"]))
    if args.output:
        import json
        with open(args.output, "w") as fh:
            json.dump({str(k): v for k, v in info["table"].items()}, fh, indent=1)
        print("written to %s" % args.output)
    else:
        for op in sorted(info["table"]):
            e = info["table"][op]
            print("  %3d  %-14s type=%-3d ops=%d stackInc=%+d"
                  % (op, e["name"], e["type"], e["operands"], e["stackInc"]))
    return 0


def cmd_disasm(args: argparse.Namespace) -> int:
    forwarded = [args.module]
    if args.exe:
        forwarded.append(args.exe)
    for flag, value in (("--opcodes", args.opcodes), ("-f", args.function),
                        ("--calls", args.calls),
                        ("-o", args.output), ("--limit", args.limit)):
        if value is not None:
            forwarded += [flag, str(value)]
    if args.json:
        forwarded.append("--json")
    return _run(as_disasm.main, forwarded)


def cmd_lift(args: argparse.Namespace) -> int:
    forwarded = [args.module]
    if args.exe:
        forwarded.append(args.exe)
    for flag, value in (("--opcodes", args.opcodes), ("-f", args.function),
                        ("--calls", args.calls),
                        ("-o", args.output), ("--limit", args.limit)):
        if value is not None:
            forwarded += [flag, str(value)]
    if args.json:
        forwarded.append("--json")
    return _run(as_lift.main, forwarded)


def _opcode_table(exe, table_json):
    if table_json:
        import json
        with open(table_json) as fh:
            return {int(k): v for k, v in json.load(fh).items()}
    if exe:
        return as_opcodes.extract(exe)["table"]
    return None


def cmd_asm(args: argparse.Namespace) -> int:
    """Rewrite a module: verify the round-trip, optionally swap a literal."""
    table = _opcode_table(args.exe, args.opcodes)
    if table is None:
        return _fail("an opcode table is required: pass the game .exe or --opcodes")

    try:
        trace, info = as_module.trace_module(args.module, opcodes=table)
    except as_module.ParseError as exc:
        return _fail(str(exc))

    with open(args.module, "rb") as fh:
        original = fh.read()
    rebuilt = as_write.write(trace, info["dialect"])
    if rebuilt != original:
        return _fail("round-trip is not byte-exact for this module -- refusing "
                     "to write. Nothing downstream can be trusted until it is.")
    print("round-trip verified: %d bytes, %d fields" % (len(original), len(trace)))

    if args.list_literals:
        print(as_write.literal_report(trace, limit=args.limit or 20))
        return 0

    if not args.replace:
        if not args.output:
            return 0
        edited = rebuilt
    else:
        for pair in args.replace:
            if "=" not in pair:
                return _fail("--replace takes OLD=NEW, got %r" % pair)
            old, _, new = pair.partition("=")
            try:
                trace = as_write.replace_literal(
                    trace, old.encode("utf-8"), new.encode("utf-8"))
            except KeyError as exc:
                return _fail(str(exc))
            print("replaced %r -> %r" % (old, new))
        edited = as_write.write(trace, info["dialect"])

    if not args.output:
        return _fail("--output is required when writing")
    with open(args.output, "wb") as fh:
        fh.write(edited)
    print("written %s  (%d bytes, %+d)"
          % (args.output, len(edited), len(edited) - len(original)))

    # An edited module has to still parse end to end, or the edit broke it.
    check = as_module.summarize(args.output, opcodes=table)
    if check["tail"]:
        print("re-parsed: %d/%d class blocks, tail ends at EOF"
              % (len(check["blocks"]), len(check["classes"])))
        return 0
    print("WARNING: the edited module no longer parses to EOF (%s)"
          % (check["tail_error"] or "tail not reached"), file=sys.stderr)
    return 1


def cmd_repack(args: argparse.Namespace) -> int:
    forwarded = [args.exe, args.bytecode, "-o", args.output]
    if args.no_verify:
        forwarded.append("--no-verify")
    return _run(bgt_repack.main, forwarded)


def cmd_crack(args: argparse.Namespace) -> int:
    forwarded = [args.pack, "--dict", args.dictionary,
                 "--harvest", args.harvest, "--workers", str(args.workers)]
    if args.quiet:
        forwarded.append("--quiet")
    for extra in args.extra or []:
        forwarded += ["--extra", extra]
    return _run(bgt_crack.main, forwarded)


def cmd_ghidra(args: argparse.Namespace) -> int:
    """Everything after `bgt ghidra` is handled by bgt_ghidra's own parser."""
    return bgt_ghidra.main(args.rest)


def cmd_validate(args: argparse.Namespace) -> int:
    forwarded = list(args.exe)
    if args.deep:
        forwarded.append("--deep")
    if args.verbose:
        forwarded.append("-v")
    return _run(bgt_validate.main, forwarded)


def cmd_pack(args: argparse.Namespace) -> int:
    try:
        version, entries = bgt_pack.parse(args.pack)
    except (bgt_pack.PackError, OSError) as exc:
        return _fail(str(exc))

    encrypted = [e for e in entries if e.encrypted]
    tags = bgt_pack.tag_index(entries)

    if args.pack_action == "list":
        print("%s: v%d, %d entries, %d encrypted, %d distinct key%s"
              % (os.path.basename(args.pack), version, len(entries),
                 len(encrypted), len(tags), "" if len(tags) == 1 else "s"))
        for e in entries[:args.limit]:
            print("   %-52s %9d B%s"
                  % (e.name[:52], e.size, "  SWCR" if e.encrypted else ""))
        if len(entries) > args.limit:
            print("   ... %d more" % (len(entries) - args.limit))
        return 0

    # extract
    key = None
    if args.key:
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            return _fail("--key must be hex")
        if len(key) != 32:
            return _fail("--key must be 32 bytes (64 hex characters)")
    elif args.password:
        try:
            from . import bgt_kdf
        except ImportError:
            import bgt_kdf
        key = bgt_kdf.aes_key(args.password)
        print("derived key %s" % key.hex())

    if encrypted and key is None:
        return _fail("%d entries are encrypted -- pass --key <hex> or --password"
                     % len(encrypted))

    os.makedirs(args.outdir, exist_ok=True)
    written = skipped = 0
    for e in entries:
        blob = e.decrypt(key) if (e.encrypted and key) else e.data
        if blob is None:                      # the key did not verify
            skipped += 1
            continue
        dest = os.path.join(args.outdir, e.name.replace("\\", "/").lstrip("/"))
        os.makedirs(os.path.dirname(dest) or args.outdir, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(blob)
        written += 1

    print("extracted %d/%d entries to %s" % (written, len(entries), args.outdir))
    if skipped:
        print("%d entries were not written -- the key does not open them "
              "(this pack has %d distinct keys)" % (skipped, len(tags)))
    return 0 if not skipped else 1


def _run(main_fn, argv: List[str]) -> int:
    """Call a module's main() with a synthetic argv."""
    saved = sys.argv
    sys.argv = ["bgt"] + argv
    try:
        return main_fn() or 0
    except SystemExit as exc:
        return int(exc.code or 0)
    finally:
        sys.argv = saved


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="bgt", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser("unpack", help="recover the AngelScript module")
    p.add_argument("exe", nargs="+")
    p.add_argument("-o", "--outdir")
    p.add_argument("--seed", type=lambda s: int(s, 0))
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("info", help="trailer, seed and container only")
    p.add_argument("exe")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("opcodes", help="dump the asBCInfo opcode table")
    p.add_argument("exe")
    p.add_argument("-o", "--output", help="write the table as JSON")
    p.set_defaults(func=cmd_opcodes)

    p = sub.add_parser("disasm", help="annotated disassembly")
    p.add_argument("module", help="recovered bytecode")
    p.add_argument("exe", nargs="?", help="the game exe, for its opcode table")
    p.add_argument("--opcodes", help="opcode table JSON instead of the exe")
    p.add_argument("-f", "--function")
    p.add_argument("--calls", metavar="NAME")
    p.add_argument("-o", "--output")
    p.add_argument("--limit", type=int)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_disasm)

    p = sub.add_parser("lift", help="lift disassembly to pseudo-source")
    p.add_argument("module")
    p.add_argument("exe", nargs="?")
    p.add_argument("--opcodes")
    p.add_argument("-f", "--function")
    p.add_argument("--calls", metavar="NAME")
    p.add_argument("-o", "--output")
    p.add_argument("--limit", type=int)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_lift)

    p = sub.add_parser("pack", help="inspect or extract an SFPv1 asset pack")
    p.add_argument("pack_action", choices=("list", "extract"), metavar="list|extract")
    p.add_argument("pack")
    p.add_argument("-o", "--outdir", default="extracted")
    p.add_argument("--key", help="AES-256 key as 64 hex characters")
    p.add_argument("--password", help="derive the key from this password")
    p.add_argument("--limit", type=int, default=20, help="entries to list")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("crack", help="search a module for a pack password")
    p.add_argument("pack")
    p.add_argument("--dict", dest="dictionary", required=True)
    p.add_argument("--harvest", default="strings,runs")
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--extra", action="append")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_crack)

    p = sub.add_parser("asm", help="rewrite a module (verify, edit literals)")
    p.add_argument("module", help="recovered bytecode")
    p.add_argument("exe", nargs="?", help="the game exe, for its opcode table")
    p.add_argument("--opcodes", help="opcode table JSON instead of the exe")
    p.add_argument("-o", "--output", help="write the rebuilt module here")
    p.add_argument("--replace", action="append", metavar="OLD=NEW",
                   help="swap a string literal, any length; repeatable")
    p.add_argument("--list-literals", action="store_true")
    p.add_argument("--limit", type=int)
    p.set_defaults(func=cmd_asm)

    p = sub.add_parser("repack", help="rebuild an exe around a modified module")
    p.add_argument("exe")
    p.add_argument("bytecode")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--no-verify", action="store_true")
    p.set_defaults(func=cmd_repack)

    p = sub.add_parser(
        "ghidra", help="find/install Ghidra and decompile out of a binary")
    p.add_argument("rest", nargs=argparse.REMAINDER,
                   help="status | install | install-extension | decompile ...")
    p.set_defaults(func=cmd_ghidra)

    p = sub.add_parser("validate", help="run the pipeline over several titles")
    p.add_argument("exe", nargs="+")
    p.add_argument("--deep", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_validate)

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "command", None):
        ap.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
