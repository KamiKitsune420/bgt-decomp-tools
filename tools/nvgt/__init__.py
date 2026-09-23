"""
bgtdecomp.nvgt -- source recovery for games built with NVGT (NonVisual Gaming
Toolkit), BGT's open-source successor.

NVGT runs the same scripting language on a far newer AngelScript, so almost
nothing below the script syntax carries over from BGT: the packaging, the
encryption, the bytecode dialect and the asset packs all differ. This package
is the NVGT half of the toolkit; `bgtdecomp.engine.identify()` decides which
half a given executable needs.

    extract          payload location, the verified encryption profiles, the
                     Poco preamble, embedded packs
    custom_crypto    one verified executable-bound (XChaCha20/AES/HMAC) profile
    asreader         asCReader for AngelScript 2.37-era modules
    opcodes          asBCInfo generated from the pinned SDK header (gen_opcodes)
    disasm           annotated disassembly
    decompile        stack/register simulation and structuring to source
    signatures       declarations rendered from retained metadata
    recover          a complete, browsable, optionally compile-checked project
    source_evidence  what the bytecode actually retained, separated from output
    library_recovery verified reuse of installed include sources
    nvgt_pack        NVGT's asset pack format, plain and encrypted
    inspect_exe      engine identity evidence without running anything
    keyscan          AES-256 key-schedule scanner for memory dumps (diagnostic)
    native_probe     compile-only check in a copied stub (owned harness)

Every module runs both ways, as the BGT modules do:

    python tools/nvgt/recover.py game.exe -o out.zip      # from a checkout
    from bgtdecomp.nvgt import recover                    # installed

Originally developed as nvgt-source-recovery by beyond sight tech (MIT); see
NOTICE.md for the attribution that travels with it.
"""
