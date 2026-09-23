# NVGT: formats and recovery

NVGT (NonVisual Gaming Toolkit) is BGT's open-source successor. Scripts look
alike; almost nothing underneath does. This is the NVGT counterpart to the BGT
sections of `CLAUDE.md`. Every format claim below was read out of NVGT's
published source (the file is named each time), not inferred from bytes.

| | BGT | NVGT |
|---|---|---|
| locate the payload | `xproc10` trailer at EOF | end of the last PE section (Windows); u32 stub size at EOF elsewhere |
| payload | `"<n> "` + AES-256-CBC(generated key) + LZ77 | Poco 7-bit pack count, embedded packs, XOR-masked size, encrypted zlib |
| stream | the module | Poco preamble, then the module |
| AngelScript | 2.2x era, 32-bit, two string dialects | 2.37 era, 64-bit, `len2` strings, 64-bit type flags |
| asset packs | SFPv1, AES-ECB per entry, `SWCR` tag | `0xDADFADED` pack, trailing TOC, CRC32, whole-file XChaCha20 |
| debug info | always stripped | kept in debug builds (names, lines, sections) |

---

## The executable (src/nvgt_angelscript.cpp `LoadCompiledExecutable`, src/pack.cpp)

```
[stub]
7-bit            embedded pack count                  load_embedded_packs
per pack:        7-bit length + name                  a Poco std::string
                 u32 LE size
                 size bytes                           a complete NVGT pack
7-bit            payload size XOR NVGT_BYTECODE_NUMBER_XOR
payload          encrypted, see profiles
```

The pack name is a **Poco string**, not a u32-prefixed one. The recovery code
this was merged from read it as a u32, which consumed the name's own bytes as a
length (`sounds.dat` became a length of 1,970,238,218) and lost every
executable that embeds a pack. `extract.read_embedded_packs()` is now the single
walk of this block, and `tests/test_integration.py` pins it.

## The decrypted stream (`SaveCompiledScript`)

```
u16      plugin count, then Poco strings
i32      system-namespace count, then (name, namespace) Poco string pairs
41 x     7-bit engine properties (asEP_LAST_PROPERTY)
i64      build timestamp
u8       app.no_auto_chdir
...      asCWriter module stream
```

## Packaging profiles

The payload's encryption is not fixed. It comes from `nvgt_config.h`, which a
custom build may rewrite and which NVGT's release CI **regenerates with fresh
random parameters for every official build**. So a version string says nothing
about how a payload is protected, and each profile has to be verified against
real samples before it is supported:

| profile | verified against |
|---|---|
| repository default (`nvgt_config.h` as published) | NVGT source; round-trip tests |
| official release of 2026-08-30 | that release's stub |
| pre-versioned fixed-size profile (`legacy_fixed_size_a5b4`) | one shipped game's loader |
| one executable-bound XChaCha20 / AES / HMAC custom profile | one custom build |

An executable from any other build fails with `Cannot identify NVGT payload
size/profile` or `Unsupported or corrupt NVGT payload`. It never produces a
guessed project. That includes the release installed on the machine this merge
was tested on (0.90.0-dev, 2026-09-15), whose profile is not among the verified
ones. Bytecode you already hold, such as a module your own script exported
with `script_get_module(...).get_bytecode()`, decompiles whatever build made it.
Recovery was checked that way against that release: the result compiled with
its `nvgt.exe`.

Embedded packs sit outside the payload, so `bgt nvgt extract --packs` and
`bgt nvgt pack` read them whatever the payload's profile.

## NVGT packs (src/pack.cpp, src/crypto.cpp)

```
header   64 bytes: u32 0xDADFADED, u64 toc_offset, u32 CRC32(TOC), zeros
data     entries back to back, in insertion order
TOC      toc_offset .. EOF: 7-bit name length, name (UTF-8, no controls),
         7-bit size -- offsets are never stored, only rebuilt
```

The reader demands that the TOC walk ends exactly on EOF, that the CRC matches
and that the sizes sum exactly to `toc_offset`. `nvgt_pack.parse` does the same,
so a wrong field width fails rather than producing a plausible table. NVGT's
own reader also rejects a pack with no entries, and so does this one.

With a key, the whole file is `nonce[24] || XChaCha20(BLAKE2b-256(key), nonce)(
0xACEFADED || pack)`. Monocypher's `crypto_chacha20_x` (DJB counter layout)
matches pycryptodome's IETF XChaCha20 for any stream under 256 GiB, because the
high counter word stays zero. The 4-byte magic is only a 32-bit key check, so
the CRC and the landing checks behind it are what settle a key.

`nvgt_pack.build()` reproduces packs written by NVGT 0.90.0-dev **byte for byte**,
plain and encrypted (given the same nonce). That was checked against packs
created by the real `pack_file` API.

## The module reader and decompiler

`asreader` ports `asCReader` for AngelScript 2.37 (64-bit flags, enum underlying
types, template functions, try/catch), with a legacy mode for 32-bit flags and
the older token numbering. The legacy renumbering (`+1` at >= 36, `+1` at >= 64)
maps BGT's token ids onto the current ones. BGT's `?` (59) becomes NVGT's 60,
which is how the two halves' `?&in` rules line up.

`decompile` simulates each body's stack and registers, and structures loops,
`switch`, `try`/`catch`, ternaries and short-circuit logic. `recover` wraps it
into a project, and `source_evidence.json` separates what the bytecode retained
from what was synthesised.

Both toolkits decode AngelScript's encoded integers independently, from
different builds of `asCReader`. `tests/test_integration.py` requires them to
agree on every width, including the sign flag.

---

## Changes in the merged toolkit

Relative to nvgt-source-recovery at `eaa176b`:

- **Embedded packs:** names are Poco strings (see above). Fixed in
  `get_payload`, `package_owned_module` and the new `read_embedded_packs()`;
  `embedded_packs()` and `extract --packs` expose them.
- **New `nvgt_pack`:** NVGT's asset packs, plain and encrypted, read and write,
  CLI `bgt nvgt pack list|extract|create`, including packs inside an
  executable (`--embedded`).
- **Arithmetic right shift:** `BSRA`/`BSRA64` render as `>>>`. AngelScript's
  `>>` is the *logical* shift (NVGT evaluates `-8 >> 1` to 2147483644 and
  `-8 >>> 1` to -4), so rendering `BSRA` as `>>` changed the meaning of every
  negative shift.
- Package layout: modules live in `bgtdecomp.nvgt`, use the repository's
  "relative import, else flat" convention, and still run as scripts.
  `keyscan` and `native_probe` gained `main()`, `gen_opcodes` writes beside
  itself, and `refine_source_archive` moved into the package, where its tests
  import it.
- Tests run under the shared pytest suite. Fixtures moved to
  `tests/nvgt/fixtures/`, and the `bcdump` host builds into
  `tests/nvgt/fixtures/build/`.

## Usage

```bash
bgt identify game.exe
bgt nvgt recover game.exe -o game-source.zip [--check-with nvgt.exe]
bgt nvgt decompile game.exe -o game.nvgt
bgt nvgt disasm game.exe -o game.asm
bgt nvgt extract game.exe game.bin --packs packs/
bgt nvgt inspect game.exe --output report.json
bgt nvgt pack list packs/sounds.dat --key "..."
bgt nvgt library game.exe --compiler nvgt.exe --include-root include --include form.nvgt ...
```

Recovery never runs the target. `--check-with`, `library` and `probe` run the
NVGT *compiler* or an owned harness in a disposable folder, and say so in their
reports.
