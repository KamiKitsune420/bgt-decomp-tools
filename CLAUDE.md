# BGT & NVGT Games — Decompilation Toolkit

General-purpose tooling for recovering code and assets from games built with **BGT
(BlastBay Gaming Toolkit)**, the 2010 audio-game engine by BlastBay Studios, and
with its open-source successor **NVGT**.

This document covers BGT in depth. NVGT lives in `tools/nvgt/` (the
`bgtdecomp.nvgt` subpackage, merged from nvgt-source-recovery) and is documented
in `docs/nvgt.md`. The two share a scripting language and almost nothing else:
packaging, encryption, AngelScript version and asset packs all differ.
`tools/engine.py` (`bgt identify`) decides which half an executable needs, and
claims an engine only when that engine's own self-verifying layer agrees.

This folder ships **only this document and the Python tools**. It holds no game
files, no extracted binaries and no per-title findings — those belong in the folder
for the game you are working on. Everything here is reproducible from a game
executable in one command.

---

# What these tools assume, and why it holds

A BGT game is the BGT runtime stub with the compiled AngelScript module appended as
a **PE overlay** — past the last section, so it is never mapped into memory and no
section dump will show it.

The important property: **the runtime is the same across titles.** BGT games do not
need per-title reverse engineering. This has been confirmed against six unrelated
shipped titles — same trailer, same key, same container magic, same
compression, same pack format, all opened by this toolchain unmodified. The two
that needed a change needed it in *this reader's guesses*, not in the format: a
hardcoded size limit and one spelling of a name (see **Crazy Party** below).

The corollary is worth stating because it is a common assumption: a developer
shipping several BGT games is almost certainly shipping **stock BGT**. If a title
does not open, suspect a different BGT *version* before suspecting a modified engine.
What genuinely varies between builds is the **AngelScript version** BGT was compiled
against, which changes how strings are serialized *inside* the module — not how the
module is stored.

---

# The chain

```
game.exe
  |- PE stub (BGT runtime, itself LZ77-compressed inside BGT's exec.bin)
  `- overlay
       |- "<n> "               ASCII decimal + space; n = size of an optional
       |                       embedded pack. Usually 0, giving the bytes "0 ".
       |- AES-256-CBC          key = SHA256(keygen(seed)), IV = key[:16]
       |    |- "<32 hex>=<flag> printf<len>\0"      container header
       |    `- LZ77 blob, ending " <uncompressed length>"
       |         `- AngelScript bytecode
       `- 12-byte trailer      "xproc10\0" + LE u32 overlay offset
```

The AES key is **generated, never stored** — which is why no string search in a BGT
executable ever finds one:

```python
v = seed                       # 0x11 in stock BGT
for _ in range(32):
    v *= 3
    v = 5 if v >= 0x80 else (0xd if v == 0 else v)
    key_material.append(v & 0xff)
aes_key = sha256(key_material)
```

`bgtlib.find_seed()` recovers the seed by trial decryption rather than assuming it,
so a build that changed it still opens. The container header — 32 hex characters
followed by `=` — is a strong enough constraint that a wrong seed is never mistaken
for a right one.

Note the container header is **fixed-shape but not fixed-length**: the declared
length is decimal, so a larger module means a longer header. Compute it, never
hardcode it.

## UPX-packed runtimes

Some titles ship the runtime compressed with UPX. The overlay is untouched --
UPX leaves anything past the last section alone -- so unpacking the script
does not care. What breaks is everything that reads the *engine*: `asBCInfo[]`
is inside the compressed blob. `upx.py` rebuilds the memory image following UPX
3.96's own `PeFile::unpack0`, and `as_opcodes.extract()` reads from that:

1. PackHeader (`UPX!`, just before the second section's raw data) names the
   method, filter and lengths.
2. NRV2B/2D/2E decode to exactly `u_len`; `c_adler` and `u_adler` must match.
   (`u_adler` is taken before unfiltering, so it proves decoding only.)
3. The stream's last dword locates the original PE header and section table.
4. The code range `[codebase, codebase+codesize)` is unfiltered (`filter/ct.h`,
   `filter/cto.h`; ids 0x11-0x16, 0x24-0x26). Unimplemented filters leave code
   filtered and say so -- data sections, where the opcode table lives, are
   never filtered.
5. Relocations are replayed: UPX stores each relocated dword big-endian as
   `value - imagebase - rvamin`. Missing this step leaves every pointer in
   `.rdata` wrong while the data *looks* plausible.

Checked against `upx -d` on a shipped title: `.text` and `.data` identical, and
`.rdata` differs only in the import descriptors, which are deliberately not
rebuilt. `bgt opcodes` on the packed file and on the `upx -d` copy give the
same table. The trailer stores an **absolute** overlay offset, so a `upx -d`
copy (or any PE rewrite) has a stale trailer; `split_overlay` then looks for the
overlay at the end of the PE image, and `bgt identify` reports the staleness,
because BGT's own loader will not find the script in such a copy.

---

# Tools

Pure Python 3. Needs `pycryptodome`. Nothing here needs `capstone` — AngelScript
bytecode is not x86, and `as_opcodes.py` disassembles it directly. (Reach for
`capstone` only if you separately want to disassemble the x86 *runtime*.)

| tool | what it does |
|---|---|
| `cli.py` | `bgt` — one entry point dispatching every subcommand below |
| `bgtlib.py` | the chain as a library — `unpack_file(path)` returns every intermediate |
| `bgt_unpack.py` | CLI: unpack one or more executables, report each layer, write bytecode |
| `bgt_pack.py` | SFPv1 asset packs — parse, list, verify a key, decrypt entries |
| `as_module.py` | AngelScript module reader — dialects, enums, classes, function bodies, and every tail table through to EOF |
| `as_opcodes.py` | recovers `asBCInfo[]` from the executable and disassembles AngelScript bytecode |
| `as_disasm.py` | readable disassembly — resolves calls, literals, globals and members to names, and labels jumps |
| `as_lift.py` | lifts disassembly to pseudo-source — a symbolic stack machine plus control flow |
| `as_write.py` | writes a module back out — byte-exact round-trip, and length-changing edits |
| `bgt_asir.py` | presents a BGT module as the AngelScript IR the NVGT decompiler reads |
| `bgt_api.py` | `bgt api`: the engine's API -- documented, from `bgt.chm`, and registered, from `bgt.exe`'s own declaration strings |
| `bgt_apicheck.py` | `bgt apicheck`: every call in a recovered project's text, against every arity its own build declares -- the check for a title the compiler cannot parse |
| `bgt_compile.py` | `bgt compile`: runs BGT's own compiler and reads back every diagnostic; `bgt verbs`: which BGT the shell runs for a `.bgt`, and repoint it |
| `bgt_project.py` | `bgt recover`: a browsable, compilable project — files, ZIP, report |
| `bgt_gui.py` | `bgt gui`: a wxPython window over identify, recover and compile |
| `bgt_repack.py` | the chain in reverse — rebuild an executable around a modified module |
| `bgt_crack.py` | harvest candidate passwords from a module and test them against a pack |
| `bgt_validate.py` | run the whole pipeline over several titles and compare, stage by stage |
| `bgt_ghidra.py` | find/install Ghidra + a JDK, install extensions, drive headless decompiles |
| `bgt_kdf.py` | BGT's password → AES-key derivation for encrypted asset packs |
| `bgt_string_crypt.py` | BGT's `string_encrypt` / `string_decrypt`, and the shared key setup |
| `engine.py` | `bgt identify`: BGT or NVGT, decided by each engine's own verifying layer |
| `upx.py` | the memory image of a UPX-packed runtime, so `asBCInfo[]` can be read without `upx -d` (see below) |
| `script_files.py` | `bgt files`: which source files a stripped module was built from -- library files by name, the game's own as segments |
| `nvgt/` | the NVGT half: extraction, `asCReader` for 2.37, decompiler, project recovery, NVGT packs (`docs/nvgt.md`) |
| `bgt_libcheck.py` | `bgt libcheck`: recovered code against BGT's shipped library source -- the lifter, or `--decompiler` for the `bgt recover` path |
| `nvgt/libcheck.py` | `bgt nvgt libcheck`: decompile NVGT's own `include/`, debug and stripped, and recompile it |

`docs/ghidra_workflow.md` covers how to find `asCReader::ReadInner`, `asBCInfo[]`,
the KDF and `pack::create` in a binary, and how to verify a transcription.

## Installing

Optional. Everything runs straight from a checkout; installing just adds console
scripts and lets other code `import bgtdecomp`.

```bash
pip install -e .        # then: bgt unpack game.exe -o out
```

The whole workflow through the unified CLI:

```bash
bgt unpack game.exe -o work/
bgt disasm work/game_bytecode.bin game.exe -o work/game.asm
bgt lift   work/game_bytecode.bin game.exe -o work/game.as
bgt crack sounds.dat --dict work/game_bytecode.bin --workers 0
bgt lift   work/game_bytecode.bin game.exe --calls set_sound_decryption_key
bgt pack extract sounds.dat -o sounds/ --key <hex>
bgt asm    work/game_bytecode.bin game.exe \
           --replace sounds.dat=my.dat -o work/modified.bin
bgt repack game.exe work/modified.bin -o patched.exe
bgt validate game.exe patched.exe
```

Or, in one command, the whole thing as a project the compiler judges:

```bash
bgt recover game.exe -o recovered/ --compile
bgt recover game.exe -o recovered/ --extract-data # ...and unpack the packs too
bgt compile recovered/game.bgt            # just the compiler, on any script
bgt apicheck recovered/ game.exe          # every call, against the build's own declarations
bgt verbs --repoint                       # make double-clicking a .bgt use the BGT that can parse it
```

Extending the reader means reading `asCReader` out of the binary, and the Ghidra
side of that is scripted too — see `docs/ghidra_workflow.md`:

```bash
bgt ghidra status                                    # Ghidra + JDK 21+ present?
bgt ghidra install                                   # fetch it (asks first)
bgt ghidra decompile game.exe --string _builtin_function_ -o readers.c
```

**Analyse `bgt.exe` once and keep the project.** The engine is the authority
for every "what does BGT actually do here?" question this document keeps
asking, and `--project` makes asking cheap: the import and analysis take
about fifteen minutes, and every query after that takes **about twenty
seconds**.

```bash
bgt ghidra decompile "<BGT>/bgt.exe" --string factstub     --project <somewhere outside this repo>/bgt_ghidra_project --max-mem 4G
```

Two things about that, both learned the hard way on a 15.5 GB machine:

- **The heap has to be 4G.** 2G dies with `OutOfMemoryError: Java heap space`
  in `X86Analyzer`, and 5G dies *before* Java starts, with
  `os::commit_memory ... The paging file is too small` -- which is the system
  refusing the reservation rather than Ghidra needing it. 4G commits and
  completes.
- **A failed import leaves a project that cannot be retried into.** The
  second attempt reuses the directory, finds no program in it, and aborts
  with `No program files found within specified project folder: /`. Delete
  the project directory and start over.

Keep the project and its output outside this repository -- it is 25 MB of
engine, not toolkit.

Modules work both ways on purpose — run directly and the script's own directory is
on `sys.path`; installed, the package-relative import resolves instead. Neither form
needs a `sys.path` fixup at the call site.

```bash
# unpack a game
python tools/bgt_unpack.py path/to/game.exe -o /some/scratch/dir

# identify a recovered module and dump its enums
python tools/as_module.py /some/scratch/dir/game_bytecode.bin

# list an asset pack
python tools/bgt_pack.py path/to/data.dat
```

## Tests

```bash
python -m pytest tests/ -q          # everything: BGT, NVGT, integration
python tests/test_toolkit.py        # the BGT known-answer tests alone
```

`tests/test_toolkit.py` holds the BGT known-answer tests,
`tests/test_recovery.py` those for project recovery — the IR adapter, the
compiler driver and the project writer — `tests/test_integration.py` the checks
that join the two halves (embedded-pack walk, NVGT packs, engine
identification, the two integer codecs agreeing), and `tests/nvgt/` the NVGT
suite, whose compiler-backed tests skip unless their
optional fixtures are configured (`tests/nvgt/README.md`). All of it runs on
**synthetic inputs and owned fixtures only** — no game files — so it runs
anywhere. Every subprocess they and the tools launch is given an explicit
`stdin=subprocess.DEVNULL`: a compiler run non-interactively has no use for
stdin, and on Windows inheriting a handle the parent has closed fails the
*spawn* with `WinError 6`, intermittently and nowhere near the real cause.

They deliberately target the things that fail *quietly* rather than loudly:
the encoded-integer boundary at 64, negative lengths rewinding the cursor, overlapping
LZ77 matches, the keygen constant, a pack walk that does not land on EOF, the SWCR
tag rejecting a wrong key, a tail that does not land on EOF, the low-bit table
selector in a global-pointer operand, jump targets counted in instructions, and a
resynchroniser that must refuse rather than run to EOF, the token mapping
between the two AngelScript generations, a default-argument list stored
last-to-first, the global-pointer shift touching only the pointer field, an
inherited-property prefix that carries no flag, a candidate list that must not
swallow the rest of a compiler report, and a project split that must not
reorder declarations.

Run them after any change here. The runtime checks below validate against real game
files, but they cannot catch a regression before you have a game file in front of you.
For that, `bgt validate` over two or more titles is the check that matters.

## Every layer is self-verifying

A wrong guess fails loudly rather than producing plausible garbage. If any of these
pass, that layer is right:

- the trailer magic is `xproc10`
- the ciphertext length is a multiple of 16
- the decrypted head is 32 hex characters followed by `=`
- LZ77 output length equals the length the container declared, **exactly**
- the module begins with `noDebugInfo` then a parsable enum count
- a pack walk ends **exactly** on EOF (`bgt_pack.parse` raises otherwise — a short
  read is never silent)
- the module's **tail sections end exactly on EOF** (`Reader.tail` raises otherwise);
  nothing follows `usedObjectProps`, so this validates every field width before it
- every function body decodes to **exactly** its declared instruction count
- a bytecode operand's maximum **saturates** its table — one more would not fit, one
  fewer would leave the last entry unreachable

---

# The AngelScript module

## Two string dialects

`as_module.py` handles both. They differ **only** in how a string is written; record
layouts, big-endian integers and varints are shared.

| dialect | encoding |
|---|---|
| `tagged` | `0x6E 'n'` = new (`eu(len)` + bytes), `0x72 'r'` = back-ref `eu(index)`, `0x00` = empty |
| `len2` | `eu(v)`; **even** → new string of `v/2` bytes, **odd** → back-ref `(v-1)/2` |

Both append new strings to a running `savedStrings` table that back-references index
into. `tagged` is the older AngelScript; `len2` is newer.

Detection is by trial parse, not assumption — the wrong dialect dies within one or
two records because an enum name has to be a valid identifier.

## Record layout

```
enum := str(name) u32(flags BE) eu(size) str(ns) eu(count) [str(name) i32(value BE)]*count
```

Integers inside the module are **big-endian**. `ReadData` on a little-endian host
fills its destination backwards, which is what makes the stream big-endian —
confirmed by reading the binary, not assumed.

## `ReadEncodedUInt64` — get this right before anything else

It looks like a UTF-8-style continuation-bit varint. **It is not.** The top bit of
the lead byte is a **sign flag**, and the width is a run of set bits below it:

```
0xxxxxxx                value = b                  (0..63)
10xxxxxx + 1 byte       value = (b & 0x3F) << 8  | next
110xxxxx + 2 bytes      value = (b & 0x1F) << 16 | ...
1110xxxx + 3 bytes      11110xxx + 4 / 111110xx + 5 / 1111110x + 6 / 1111111x + 8
```

So `40 5b` is **one** value, 91 — not 64 followed by `0x5b`.

This is the highest-value item in this document, because getting it wrong fails
**quietly**. Every value below 64 encodes to a single byte under either reading, so a
wrong decoder is correct for the large majority of lengths and counts and only
desynchronises at the first value ≥ 64. In one module that was thousands of records
in; in a smaller title it never happened at all, so the same broken decoder produced
a perfect parse and looked correct.

Two consequences:

- **The sign flag is real.** Lengths, counts and table indices are unsigned, so a
  negative result means you are not looking at the field you think you are. Guard it:
  an unguarded negative length moves the cursor *backwards*, and a scan then appears
  to succeed while ending before it started.
- **Check a decoder against known pairs before trusting anything built on it** —
  `3f`→63, `40 56`→86, `40 5b`→91, `40 81`→129, `40 a7`→167, `40 e7`→231. These are
  in `tests/test_toolkit.py`.

## Hard limit on what is recoverable

BGT compiles with `noDebugInfo = 1`. **Line numbers, source filenames and local
variable names are stripped and unrecoverable.** Function, class, property and enum
names survive, as does every string literal.

So a faithful re-implementation of a BGT game is achievable; a byte-identical one is
not. Locals will read as `v3` and parameters as `a0`, and you name them from context.

## Extending the reader

**Every title parses end to end, from offset 0 to the last byte, in both
dialects.** The sections, in the order `ReadInner` reads them: header, enums,
class declarations, funcdefs, the three class passes (interface phase 2, class
phase 2, class phase 3), typedefs, global properties, module functions, global
functions, bind info, `usedTypes`, `usedTypeIds`, `usedFunctions`,
`usedGlobalProps`, `usedStringConstants`, `usedObjectProps`.

`usedObjectProps` is last, so **it must finish exactly at EOF** — there is nothing
after it to absorb a mistake. That one constraint transitively validates every
field width upstream of it, which makes it the strongest check in the format.
`Reader.tail()` raises unless it lands exactly, and `summarize()` returns the tables
under `"tail"`.

On Manamon 2 this reproduces, independently, every count a separate parser had
recorded: 454 global properties, 2,892 module functions, 1,280 global functions,
1,759 `usedTypes`, 8,180 `usedFunctions`, 539 `usedGlobalProps` — and
`usedFunctions[5343]` is `set_sound_decryption_key`, exactly as documented.

| title | dialect | classes | bodies | tail |
|---|---|---|---|---|
| Psycho Strike | tagged | 68 / 68 | 1,102 | ends exactly at EOF |
| Paladin of the Sky | tagged | 47 / 47 | 926 | ends exactly at EOF |
| Manamon 2 | len2 | 1,604 / 1,604 | 9,924 | ends exactly at EOF |
| SBYW | tagged | 154 / 154 | 2,348 | ends exactly at EOF |
| Super Egg Hunt | tagged | 10 / 10 | 141 | ends exactly at EOF |
| Crazy Party | tagged | 550 / 550 | 4,486 | ends exactly at EOF |

Super Egg Hunt is the fifth, and the first picked up cold after all of the
above: `bgt validate` passed it on every stage, byte-exact rewrite included,
with no reader change. It did find one thing, in the *header peek* rather than
the reader. `bgt unpack`'s one-line dialect probe reads the first enum name's
first byte -- and this module declares **no enums**, so the byte it read was a
class count, and it called a `tagged` module `len2` with no sign of a problem.
The probe now says it cannot tell, which is true and is what the trial parse
is for. A heuristic that answers anyway is worse than one that declines.

SBYW is the fourth title, and the first run after the three above were done. It
passed every `bgt validate` stage with no reader change, byte-exact rewrite
included. What it added was on the lifting side: it is the first title to use
`**` (`POWd`, `POWdi`) and 64-bit shifts (`BSLL64`, `BSRL64`), 19 instructions
the lifter had never needed to model.

Psycho Strike's tail reproduces every count an entirely separate parser recorded:
105 global properties, 288 module functions, 220 global functions, 109
`usedTypes`, 71 `usedTypeIds`, **1,048 `usedFunctions`**, 171 `usedGlobalProps`,
2,660 `usedStringConstants`, 786 `usedObjectProps`.

### The string constant pool resolves completely now

Its entries back-reference the **module-wide** saved-strings table. Reached by a
linear parse from offset 0, **every entry resolves** — 10,181 of 10,181 on
Manamon 2, zero unresolved references.

This supersedes the older note that a scan finds the pool with about a third of its
entries unresolved. Scanning also got the *size* wrong: density-scanning suggested a
17,773-entry table, and four candidate start offsets fit. The linear parse settles
it at 10,181 entries starting `0x3C4C10`, which the `PGA 10050 -> "data.dat"` pin
independently confirms. Do not locate this table by scanning; walk to it.

### The dialects differ in record layout, not only in strings

This is the single biggest trap in the format. `tagged` is not `len2` with a
different string encoding — the *records* differ, and every difference below was
read out of the relevant binary, not inferred:

| what | tagged (strike 0x0041E2A0 etc.) | len2 (rpg 0x0042ACC0 etc.) |
|---|---|---|
| script-object flag | `0x00100000` | `0x00200000` |
| phase 1 shared byte | absent entirely | one byte if `asOBJ_SHARED` |
| in/out + default-arg lists | written **unconditionally** | only when `paramCount != 0` |
| funcdef (`funcType 4`) | ends at the namespace | one more traits byte |
| funcdef namespace | plain string | `'n'`/`'o'` tag first |
| interface vftable offset | always read | skipped for interfaces |
| funcType-1 body | no flags byte | flags byte gates everything |
| object variables | `{typeinfo, eu, eu}` | `{typeinfo, eu}` |
| `nObjInfo` | unconditional | inside the `flags & 0x08` block |
| try/catch block | none | present when `flags & 0x10` |
| body trailer | one traits byte | none |
| funcdef-typed params | `_builtin_function_` + a **nested signature** | the funcdef type is named directly |
| `usedObjectProps` entry | `typeinfo` + property **name** (tagged string) | `typeinfo` + property **name** (a `len2` back-reference — see below) |
| global-pointer operands | plain index | `2 * index + tag` |

Two of these are worth calling out because each was a whole afternoon.

**The script-object flag moved.** `IsInterface()` is `(flags & X) && size == 0`,
and X is `0x100000` in the older reader and `0x200000` in the newer. It decides
whether a class block has a behaviour section, so the wrong constant
desynchronises on the first interface and everything after it is garbage.

**The funcType-1 body trailer.** One traits byte, read unconditionally after the
body and *outside* the debug-info block, which funcTypes 2/3/4 jump straight
past. Without it `character::character` comes out exactly one byte short — the
constructor still parses perfectly, with its declared 177 instructions and a
clean `RET` — and the factory record that follows is one byte out, taking the
whole class block with it.

### One difference is per-build, not per-dialect

`ReadTypeInfo`'s `'a'` (template) form carries a namespace string after the name
in Psycho Strike and Manamon 2, and does **not** in Paladin of the Sky — same
`tagged` dialect, different record. So `as_module` trials both and keeps the one
whose tail lands exactly on EOF, the same way the dialect itself is detected.
`summarize()` reports which won as `template_namespace`.

Do not assume a third title matches either of these two. Run `bgt validate`.

**Read the reader; do not infer the format.** `asCReader` is statically linked into
every BGT executable, so the exact record layout for the build you are looking at is
*in the binary in front of you*. Transcribe the branch from Ghidra.

This is not a style preference. Inferring layouts from byte patterns reliably
produces answers that are confident, plausible and wrong: a signature model built
that way parsed at 92.5% while being wrong about three separate fields, because in
the common case two counts were zero and the layout happened to coincide.

Two units traps that do not fail loudly:

- The bytecode length field counts **instructions**, not dwords.
- Jump offsets count **instructions**, not dwords. Reading them as dwords still lands
  on a valid instruction boundary whenever the target happens to be one dword wide,
  so a majority of jumps "resolve" while silently pointing at the wrong instruction.

---

## Function records

Function bodies are marked `0x66 'f'` followed by the name in whichever string
dialect the module uses, then the signature, then an encoded instruction count and
the bytecode. This marker is the same in both dialects.

For `len2` this is now a linear parse, not a scan: 9,924 bodies recovered from
Manamon 2, **every one decoding to exactly its declared instruction count**.

One bad body no longer costs the rest. `Reader.function_or_error()` records the
failure — name, offset, reason, bytes skipped — in `parse_errors` and resynchronises
to the next `0x66 'f'` / `0x72 'r'` record whose name validates as an identifier.
Note that **`0x00` is deliberately not a resync anchor**: it is a complete record on
its own, so nothing follows it to check, and NUL bytes are dense enough that
accepting it stops a byte or two into the record being skipped and reports success
while still desynchronised. This applies to function bodies only — a desync in the
enum or declaration sections means the whole parse is wrong, and those still raise.

If you are working on a dialect whose bodies do not parse yet, anchor-based scanning
still works as a stopgap: `as_opcodes.disassemble()` stops at `RET`, so a correct
alignment terminates cleanly while a wrong one hits an undefined opcode almost
immediately, and real operands are small where a misaligned decode produces absurd
ones. Scan a few byte offsets after the name and keep the alignment that both
terminates on `RET` and yields plausible operands — but the length field counts
**instructions, not dwords**, so never use it as a byte offset.

---

## Naming bytecode operands

`as_disasm.py` turns a decoded body into something readable. Which operand slot
indexes which table was fixed by **range analysis**, not assumption: collect every
operand an opcode takes across the whole module and compare the maximum against each
table's size. The right table *saturates*.

| operand | max seen | table | size |
|---|---|---|---|
| `CALL` / `CALLSYS` / `CALLINTF` | 8179 | `usedFunctions` | 8180 |
| `PGA` (even) / 2 | 10180 | `usedStringConstants` | 10181 |
| `PshG4` (odd−1) / 2 | 538 | `usedGlobalProps` | 539 |
| `LoadThisR` arg0 | 6522 | `usedObjectProps` | 6523 |
| `LoadThisR` arg1 | 1661 | `usedTypeIds` | 1662 |

A saturating maximum makes an off-by-one impossible in either direction. Across
all four titles this resolves **every operand** — 242,245/242,245 on Manamon 2,
54,682/54,682 on Psycho Strike, 57,798/57,798 on Paladin, 110,291/110,291 on
SBYW — with every jump target
landing on an instruction boundary and every `LoadThisR` property belonging to its
enclosing class. Psycho Strike's 6,612 jump targets and 2,352 `LoadThisR` sites
match an independent parser's counts exactly.

**`usedObjectProps` stores the property NAME in both dialects.** This table once
said `len2` stored an index into the owner's property table. It does not: a
`len2` back-reference is a single encoded value, `2 * index + 1`, so a name
written as a back-reference reads perfectly well as an integer and the tail
still lands exactly on EOF. The giveaways were statistical and semantic. All
6,523 of Manamon 2's values are odd, which chance would not produce. Read as
indices they rendered as `menu_properties_object::prop[11939]` (no class has
11,940 properties), and that placeholder still counted as "resolved". Read as
strings, 6,520 name a real property of their exact owner; the other 3 are
`vector::x`, `y` and `z`, members of a registered type with no script
declaration to check against. (It was 6,507 until same-named classes in different
namespaces were told apart -- see "Classes that share a name" below.) The
module still rewrites byte for byte.

**Classes that share a name.** Manamon 2 declares `sound_pool`, `sound_pool_item`,
`tweener` and `action_item` twice -- globally and in namespace `rhythm`. Phase-3
property tables were attached to class blocks **by name**, so both declarations
wrote to one block: the global `sound_pool` lost every property (its
`destroy_sound_callback` among them) and the other was overwritten. They are
paired by **position** now, as `ReadInner` reads them, blocks carry their
namespace, and type names render qualified (`rhythm::sound_pool`) wherever the
namespace is not empty.
The lesson is the same as for `ALLOC`: a field that parses to EOF can still be
the wrong field, and a resolver that returns a placeholder is not resolving.

**Global-pointer operands are encoded differently per dialect, and both readings
fail quietly.** In `len2` the operand is `2 * index + tag`: tag 0 selects the
string-constant table, tag 1 the global-property table. 149,656 `PGA` operands in
Manamon 2 are even (literals) and 106 are odd (`player`, `current_map`,
`save_data`); reading them all as literals resolves those 106 to a real string
from the wrong table. In `tagged` there is no tag bit at all — the operand is a
plain `usedGlobalProps` index, `STR` carries literals separately, and Psycho
Strike's `PshG4` saturates at 170 against 171 globals. Applying the `len2` rule
there halves every index and still yields a real global name:
`pack_file::open(retreave, ...)` reads as `pack_file::open(money_wanted, ...)`.

**Rare opcodes do not need their own evidence when they share a code path.**
`LoadRObjR` and `LoadVObjR` are the *same branch* in `TranslateFunction`
(0xB8/0xB9), running the identical property lookup and type-id lookup that
`ADDSi` and `LoadThisR` use. `LoadVObjR` occurs 36 times in the whole corpus --
far too few to settle by range analysis -- and does not need to be, because
`LoadRObjR`'s 61,421 sites are the same code. Likewise `Thiscall1` (0xC8)
translates identically to `CALL` / `CALLSYS` / `CALLINTF`, so its operand is a
`usedFunctions` index. Check whether the binary already groups an opcode with a
well-evidenced one before going looking for more samples of it.

**`ALLOC`'s second operand is a ONE-BASED `usedFunctions` index**, with 0 meaning
"this type has no script constructor". Read straight it resolves to a real
function that is simply the wrong one — `ALLOC string  menu_properties_object::reset`
— and the owner matches the allocated type in only **322 of 15,619** sites.
Subtracting one takes that to **15,619 / 15,619**, and to 1,793/1,793 and
2,460/2,460 on the other two titles. `asCReader::TranslateFunction` is explicit:

```c
else if (op == 0x40) {                 // ALLOC
    FindObjectType(arg0);              // usedTypes
    if (arg1 != 0) FindFunction(arg1 - 1);
}
```

The lesson that got this right in the end is the `asBCInfo[]` one: range analysis
said the field *could* be a function index, a consistency check said it was not,
and only the binary said which — a field that is off by one looks exactly like a
field that means something else.

## Lifting

`as_lift.py` turns the instruction stream into statements with a symbolic stack
machine. **Zero passthrough across all 1,111,490 instructions in the four
titles** — every opcode is modelled.

**Checked against the library source, mechanically.** `bgt libcheck` compares
every function that appears once in both BGT's shipped `include/*.bgt` and a
recovered module: the sequence of calls in evaluation order, and the string
literals as a multiset. On Psycho Strike, built with the same library version as
BGT 1.3's include folder, **153 of 155** functions have the source's exact call
sequence (107 before the fixes it drove) and **155 of 155** its exact literals.
Of the two left, `dynamic_menu::run_extended` is the game's own library edit (it
checks `alts_pressed` where 1.3 checks joystick buttons). `control::focus`
differs by one `length()` call's position, and the bytecode settles it in the
lifter's favour: `input_box_speak(mask) + " times " + text.length()` compiles
to `.opAdd` calls whose ARGUMENT is evaluated before the receiver is pushed, so
`text.length()` genuinely runs first. The comparison's "order by closing
parenthesis" is the approximation there, not the lift. Manamon 2
and SBYW ship modified library versions, so they score lower for reasons that
are not the lifter's.

What it drove, each a real bug that read plausibly: arguments rendered in
reverse; `return` values taken from whichever path came last; guard clauses
nesting the rest of the body; arms with no join, and `if`/`else` arms, printed
in the opposite order to the source (the THEN arm is the fall-through, so it
now prints first under the negated jump condition); `INC`/`DEC` printed as
`*this.c_form[a0]--` instead of `this.c_form[a0].list_length--` (they act
through the reference register); a receiver passed by address printed with its
`&` -- `&v1 = v2`, `&v6 + v1`, 888 times in Psycho Strike; and a carriage
return written raw inside string literals. Lifted output reads like this (a
game's own `prepare_audio`, which sets its sound-pack key):

```
void <global>::prepare_audio()
{
    ret = get_SCRIPT_COMPILED();
    if (ret) {
        v1 = 0;
        v2 = string("\0\0able to\0\0learn\0...");
        v3 = string(&v2);
        v2 = get(v3);
        ret = set_sound_decryption_key(&v2, v1);
        v2 = string("data.dat");
        v3 = string(&v2);
        ret = set_sound_storage(v3);
    }
    return;
}
```

### The call frame — read, not fitted

Top of stack first, as `asCContext::CallSystemFunction` consumes it:

```
this                 methods only
return address       only when the callee returns a value type on the stack
argument 0           arguments are pushed LAST TO FIRST
...
argument n-1         (deepest)
```

Each `?&in` argument is two slots: the value, above the `TYPEID` pushed first.
`ALLOC` is the one inversion — its destination address is the **deepest** slot,
because the constructor pops its own arguments before ALLOC pops the address.

Each of these replaced an earlier rule that read plausibly and was wrong:

- **Argument order.** `random(95, 105)` compiles to `PshC4 105 / PshC4 95 /
  CALLSYS random`, and `dynamic_menu.bgt` calls
  `add_item_extended(filename, true, name)` where the bytecode pushes `name`
  first. The lifter used to render bottom-to-top, printing **every
  multi-argument call reversed**. It survived review because the positional
  names (`a0`, `v3`) gave nothing to check the order against. The shipped
  library source and constant arguments did.
- **Parameters live at negative offsets.** `SetupParametersAndReturnVariable`
  lays a frame out downward: `this` at 0, then the return address if any, then
  parameters, two slots for int64/uint64/double. Positive slots are locals and
  temporaries. `as_disasm.frame_layout()` computes it, and the disassembly
  header prints it. Naming slots 1..n as parameters, as before, gave
  temporaries parameter names.
- **The return address is `DoesReturnOnStack`**: a registered value type
  returned by value, on **every** call kind. It never applies to handles,
  references, arrays (a reference type) or script classes. Paladin's
  `generate_maze` returns the script class `map` and is followed by
  `STOREOBJ`, i.e. the object register. The old rule applied it to CALLSYS only
  and to handles too.
- **No hidden argument for templates.** This was the one rule marked
  "inferred rather than read"; `bgt.exe` settles it. `GenerateTemplateFactoryStub`
  (`FUN_0046fd30` there; find it through the `factstub` string) emits
  `OBJTYPE <type>; CALLSYS <factory>; RET`, so the object type is pushed *inside*
  the stub. The stub's parameter list drops the hidden `int&in`, and callers
  push only declared arguments. The compiler emits `TYPEID` only for `?&`
  parameters (`PrepareArgument`, gated on token 59).
- **`>>` is the logical shift**; arithmetic is `>>>`. NVGT evaluates `-8 >> 1`
  as 2147483644 and `-8 >>> 1` as -4, so `BSRA` rendered as `>>` changed every
  negative shift.

Four things decide whether the output means anything:

- **Comparisons are two-part.** `CMPi` writes the operands, the *following* jump
  supplies the relational operator. Lifted separately, every `if` reads as `cond`.
- **`JLowZ` / `JLowNZ` follow no compare at all** — they test the low byte of the
  value register, which is what a bool-returning call leaves behind.
- **Pop the callee's declared arity, from the top.** Residue from an imperfectly
  modelled construct then sits *underneath* and is skipped rather than swept into
  the argument list.
- **`this` is at a different end for constructors.** A constructor's target is
  pushed immediately before the call, so it is on top; an ordinary method gets its
  object first. Taking it from the wrong end turns `v1 = string("x")` into
  `string(&v1)` and loses the literal.

**Registers, not just a stack.** The VM has value, object and *reference*
registers, and several opcodes touch those instead of the stack — `LoadThisR`
and `LDG` load into the reference register, `WRTV*` writes through it, all with
`stackInc 0`. Modelling them as pushes was the single biggest source of
imbalance: it stranded a value on every use (2,414 in Psycho Strike) and made
`WRTV4` pop something unrelated, so the write landed on the wrong target.

**Checking the stack model.** `asBCInfo[].stackInc` is read from the binary, so
for every fixed-shape opcode it is the authoritative answer to what the stack
should do — the lifter can be diffed against it mechanically. It is *not* the
reference for `CALL` / `CALLSYS` / `CALLINTF` / `ALLOC`, which depend on the
callee, and it counts slots where the lifter counts values. The end-to-end check
is the stack being empty at `RET`:

| title | functions ending clean | before the call-frame fixes |
|---|---|---|
| Psycho Strike | 1,102 / 1,102 (100%) | 98.0% |
| Paladin of the Sky | 926 / 926 (100%) | 99.2% |
| Manamon 2 | 9,924 / 9,924 (100%) | 95.8% |
| SBYW | 2,348 / 2,348 (100%) | 95.5% |

Every one of the 14,300 bodies ends with an empty stack, and none has a call
that finds too few values. The last dozen came from three more modelling
gaps: `COPY` (a POD value copy: pop the destination, copy from the source
beneath it, leave the destination -- a no-op dropped `v3 = v4` for a returned
`vector`), a callback fetched from an array (`events[i](this)`: the call's
declared return type now travels through the register to the `PshRPtr` that
pushes it), and a funcdef held in a global (globals now push with their
declared type).

"Residue" now means what it should in both directions. A **shortfall** (a
call asking for more values than the stack holds) counts. It used to vanish
into `?` arguments, which hid 21 such calls in SBYW, all engine enums being
treated as returned on the stack. A value the bytecode **deliberately** leaves
(a `REFCPY` source nothing pops, which `RET` discards) does not count.

Besides the call frame, the last step came from opcodes that had been
modelled as no-ops or bare pops, which dropped real statements:

- **`REFCPY`** is a handle assignment: it pops the destination, then copies the
  handle now on top into it, leaving that source on the stack for `RET` to
  discard. As a bare pop, the initialiser `pool = sound_pool(500)` lifted to an
  empty body. It now reads `@pool = v2;`. `RefCpyV` is the same, into a variable.
- **`STOREOBJ` / `LOADOBJ`** move the object register, where handles are
  returned, to and from a variable. As no-ops, variables appeared from nowhere
  and a factory ended `return ret;` instead of `return v1;`.
- **`CallPtr`** calls the funcdef held in a variable. Its `stackInc` of −1 is
  asBCInfo's `0xFFFF` "depends on the callee" marker, not a literal pop. It
  consumes the funcdef's declared arguments, which the lifter now finds from the
  variable's type (a parameter's, or the property it was copied from). Unknown
  types pop nothing rather than guessing.
- **`ClrVPtr`** nulls a handle, so it reads `@v2 = null;`.
- **The reference register is loaded by more than `LoadThisR` / `LDG`.**
  `PopRPtr` pops an address into it, `LdGRdR4` leaves the global's address in it
  (the compound-assignment pattern), and a call returning a reference returns
  an address there. Each was modelled as a pop or not at all, so reads and
  writes came out as a bare `ref`: 30 of them in Psycho Strike, e.g.
  `v3 = ref;` for `v3 = pool.max_distance;`. None remain in any of the four
  titles. A reference-returning call is held until the `RDR`/`WRTV` that reads
  it, giving `v3 = totals[i]` once instead of the call plus `ref`. If nothing
  reads it, it is still emitted where it was, because the call ran.
- **Engine enums return in the value register.** Their flags are not
  serialised, so a call followed by `CpyRtoV4`/`CpyRtoV8` marks its callee as a
  register return (`Module.register_returns`), the same protocol evidence the
  NVGT decompiler uses. The module's own enums and typedefs are known by name.

The rules were adopted because the binary and the bytecode say so, and the
metric followed. Paladin shows why that order matters. A looser return rule,
which counts script classes as returned on the stack, "balances" one more
Paladin body by swallowing an unrelated leftover value at each call.
`STOREOBJ` after that call says the looser rule is wrong, and it was not
adopted. The old template rule's measured benefit (168 stranded values) likewise
disappears once the return address is modelled correctly: these numbers are
reached without it.

A **`?&in` parameter (token 59)** takes two stack slots for one declared
parameter -- AngelScript's variable-argument type passes the value *and* its type
id. Three functions in this corpus take one; the rule is mechanical and worth 82
balanced bodies.

Residue never corrupts output — it sits *below* the popped arity — but it is the
honest measure of what is still approximate.

**Structuring is real structural analysis**, not pattern-spotting: a CFG,
iterative dominators and post-dominators, natural loops from back edges, then
nested `if` / `else` / `while` / `do-while` with `break` and `continue`.
Residual gotos are **3,597 of 408,764 statements (0.88%)** across the four
titles, and 84-95% of function bodies come out entirely goto-free (84.3% Psycho
Strike, 89.8% Paladin, 94.8% Manamon 2, 91.4% SBYW).

**Returns are placed where the source put them.** `return x;` compiles to the
value moved into the register (`CpyVtoR4`, or `LOADOBJ` for a handle) and a
jump to the function's single exit, which runs only cleanup before `RET`. The
lifter used to print a value only at that `RET`, so every path returned
whatever the *last* path in the bytecode loaded -- BGT's own
`sound_pool::destroy_sound` read as always returning false. A register load that
flows only through cleanup to `RET` now emits `return x;` on the spot, and in a
void function a jump to the exit is a `return;`. Guard clauses
(`if (handle.active == false) return;`) come out as the source wrote them
instead of wrapping the rest of the body in a branch.

**Arms that never rejoin keep the compiler's order.** When both arms of a
branch end in their own `return` there is no join point, and either arm can be
the nested one. Nesting the fall-through keeps the bytecode's order -- which is
the source's: `form.bgt`'s `edit_silent` has three guarded returns, and nesting
the jump target instead printed them in reverse.

Three shapes decide whether that output is right, and each was wrong first:

- **Branch-over is the common case.** The compiler emits `if (!c) goto after;`
  around a guarded block, so the branch targets the reconvergence point and the
  guarded body is the *fallthrough*. Read as written it yields an empty `if`
  with the body dangling after it -- valid structure, wrong about what is
  conditional.
- **A header that is also the latch is a `do-while`.** Emitting its statements
  before a `while` runs them once and then spins on an empty body.
- **A pre-tested loop re-evaluates its condition every iteration**, so whatever
  the header computes must stay inside the loop.

And one that the object-model got wrong: **the receiver is pushed LAST**, for
ordinary methods as well as constructors. `dynamic_menu::add_item` settles it --
`VAR 1 / PshV4 2 / VAR 3 / PshVPtr 0 / CALLINTF` is three declared arguments
then `this`. Taking it from the bottom turns the receiver into an argument and
an argument into the receiver, which reads perfectly well and is wrong.

Validated against source nobody here wrote, since BGT ships its own library:
`dynamic_menu::run_extended` recovers the same three nested guards in the same
order as `dynamic_menu.bgt`; `set_speech_mode` recovers exactly the two branches
its short-circuit `||` must compile to; `get_position` comes back as one
`if`/`else` with the `-1` in a branch.

Unmodelled opcodes are emitted as `/* OPCODE ... */` and counted rather than
dropped — a lifter that silently omits what it cannot model reads better and means
less, so the passthrough count is the number that says how much is really
recovered.

# Source file names

**The game's own file names are not recoverable, and nothing will change that.**
They live only in AngelScript's debug information -- each function's script
section -- and BGT always strips it. NVGT strips it too in release builds
(`SaveByteCode(stream, !g_debug)`), so no stripped build stores them, hidden or
otherwise. A search of four BGT modules for script-file names in string
literals found one, which was the name of a sound in a list, not a record of
the game's source. NVGT *debug* builds do keep them, and `bgt nvgt recover`
uses them.

What survives is **structure**, and `bgt files` recovers it:

```bash
bgt files work/game_bytecode.bin game.exe      # BGT: module + exe
bgt files game.exe                             # NVGT: executable or module
```

- **Declarations come out in file order.** The builder handles script sections
  one after another. Types come in one pass and global functions in another,
  and both walk the files in the same order. So any change of file along the
  module's order is a real file boundary. Two of the game's own files side by
  side are still indistinguishable, which gives *where* files split, but never
  how many unnamed files a run holds.
- **Library files are named exactly.** A run that declares what a shipped
  `include/*.bgt` or `*.nvgt` declares *is* that file. A class counts only when
  its methods agree with the source's in both directions, so a game's own
  `menu` isn't claimed. A file counts only when most of what it declares is
  present *and* it explains something no other file does.
- **The two passes merge into one file order.** A file seen in only one pass is
  placed by its neighbours there. The library's own `#include` graph settles
  what they leave open, because an included file is processed straight after
  its includer, so nothing sits between them. That usually pins the main
  file's functions exactly.

**Checked against ground truth.** An NVGT debug build records every
declaration's true file, so the stripped build of the same module can be scored
against it. On all 26 modules of the library corpus that is **439 / 439**, and
the recovered `#include` list matches the harness exactly in **24 of 25**. The
25th, `clear_compiled_basename.nvgt`, is only a `#pragma`, so it compiles to
nothing any build could show. On the four BGT titles the passes never
disagree, and each game's `main()` lands in the first segment.

Every one of these was wrong first, and read plausibly:

- **Inherited methods:** an NVGT class's method list includes them, so no
  derived class matched its source. A class's own methods are the vftable
  entries it owns.
- **Two library files declaring one class** (`sound_pool.nvgt` and
  `legacy_sound_pool.nvgt`): the tie went to alphabetical order. It now goes
  to the better method match, and a file whose every match another file
  explains as well is not claimed at all.
- **Namespaces:** a game's namespaced copy of library code
  (`rhythm::position_sound_1d`) matched the library. The gap-fill between the
  two copies then absorbed the game code in between. Attribution has been
  right about this for a while, and it bit `bgt recover` anyway: the
  attribution is keyed by name, and a *section* was keyed by the bare one,
  so Manamon 2's `rhythm::position_sound_1d` looked up the global entry and
  inherited `sound_positioning.bgt` — moving 71 lines fifty thousand lines
  earlier. Qualify the key wherever a namespace can exist; the same name at
  two scopes is two declarations, and the module keeps them apart.
- **Lambdas** are compiled after every declaration, so their position says
  nothing. They belong to the file of the function whose `FuncPtr` creates
  them.
- **Source quirks:** `pack@open_pack(` and `#include"form.nvgt"` have no space
  where a regex expected one. `form.nvgt` and `speech.nvgt` include each other,
  so "nested" means included by a file *earlier* in the order, not by any file.
- **Direct evidence first:** the order a pass shows outranks the include
  graph, which only settles what the pass order leaves open.

# Recovering a compilable project

`bgt lift` produces pseudo-source: readable, faithful to the bytecode, and not
something a compiler accepts. `bgt recover` produces a **project** — a tree of
`.bgt` files, an entry script that includes them, a ZIP, a report, and, where
BGT is installed, the compiler's own verdict on the result.

```bash
bgt recover game.exe -o recovered/ --compile
```

```
recovered/
  game.bgt                  the entry script: #include for every file, in order
  includes/
    types.bgt               enums, typedefs, funcdefs
    globals.bgt             every global, in declaration order
    dynamic_menu.bgt        a library file, named exactly
    classes/menu.bgt        one class per file, for the game's own classes
    functions/part_1.bgt    the game's own global functions, in recovered segments
  recovery.json             counts, origins, problems, compiler diagnostics
  game_project.zip          the same tree, integrity-checked
```

The original file *names* of a game's own code are not recoverable and never
will be (see **Source file names**), so the layout is generated and says so in
every file header. Library files are the exception: a run that declares what a
shipped `include/*.bgt` declares **is** that file, so those keep their real
names — 7 of Psycho Strike's 68 classes.

**The split must not reorder anything, and it is checked.** `#include` is
textual in BGT, so a project is its files concatenated in include order, and
`bgt_project.verify` compares that concatenation against the one-file render.
This is not a formality: moving a declaration can change global
initialisation order, which compiles perfectly and then behaves differently.
The compiler agrees in practice: the project and the single file report the
same diagnostics, from 12 of Psycho Strike's 75 files.

A mismatch is reported as a **problem** rather than refused, so the project
is still there to read — and `recovery.json` says `verified: false`.

It earned its keep on Manamon 2, which was the only title to fail it, and
for exactly one reason: a 71-line block, `namespace rhythm { void
position_sound_1d ... }`, emitted fifty thousand lines early. The project
still compiled and still read correctly; the concatenation check was the
only thing that knew a declaration had moved. See the namespace note under
**Source file names** for the cause. All four titles that parse verify now.

## Why BGT can drive the other engine's decompiler

The NVGT half already had a decompiler that emits *compilable* source, checked
by recompiling 50 library builds. BGT had a lifter. Rather than write a second
decompiler, `bgt_asir.py` presents a BGT module as the IR that one reads. Two
facts make that sound, and both were checked rather than assumed:

- **The opcode tables are identical.** All 200 opcodes BGT's own `asBCInfo[]`
  declares match the newer engine's numbering *and* name, exactly. The
  decompiler dispatches on the name, so the instruction layer needs no
  translation.
- **BGT is the "legacy" generation `asreader` already models.** Its token ids
  are the older `eTokenType` numbering, recovered by `t + (t>=36) + (t>=64)`:
  BGT's 65/68/79/92 are the newer 67/70/81/94, i.e. bool/int/float/double. The
  only three opcodes whose operand count disagrees are exactly the three that
  reader's legacy mode overrides — `CALLSYS`, `ALLOC`, `CallPtr` — all of them
  pointer-width differences of a 32-bit build.

The agreement is **asserted per module**, not trusted: a build whose own table
declared a different operand count would decode every later instruction of that
body at the wrong offset while still producing real opcode names.

One reader stays one reader. `as_module` remains the only thing that parses
BGT's format — the adapter translates its dicts into dataclasses — for the same
reason `as_write` replays a field trace instead of duplicating the format: two
models of one format drift, and the drift is silent.

## What the module does not record, and what fills the gap

The newer engine saves a declaration for **every** local — offset and type
always, name only with debug info. BGT's generation saves it only for *object*
locals (`objVariableTypes`), so scalar slots have no type at all. That matters
more than readability: a slot with no type cannot be declared, so the
decompiler folds it into the expressions that read it, and folded into
*several* reads a call is written — and run — once per read. One body came out
as a 21,000-character expression calling `enemies_in_range` fourteen times
where the source called it once.

So `bgt_asir.slot_types()` types the scalar slots from the bytecode, which is
a sound source for them: AngelScript has a separate opcode per operand type
for every arithmetic, comparison and two-slot conversion. Object types come
from the engine's own record and win; between inferences a type-tagged opcode
beats a width-only hint, because `SetV4` is as true of an int as of a float.

**A slot serves several source locals, and that has to be recorded, not
resolved.** `clear_pathway` writes slot 1 with `SetV1`/`WRTV1` — one byte,
through a `bool&out` parameter — and reads it with `RDR4`/`CMPIi` as the int it
returns. Typed as either one alone it was 104 errors in that one body. Both
declarations are recorded instead, which is exactly what the newer format holds
for a reused slot and what the decompiler already reads to pick the numeric
type and convert the boolean uses.

Alongside that, the decompiler now refuses to duplicate an impure expression:
a temporary whose **same value** is read twice becomes a variable. Twice means
the same value — a slot written again between the reads is an ordinary reused
temporary, and folding each value into its one read is both correct and what
lets the structurer still see a loop condition as an expression rather than as
a statement before a jump.

## The compiler is the judge, and it has to be driven

`bgt.exe` takes a script path and *runs* it. There is no console mode and no
switches: it is a GUI program that reports compilation through a window of its
own class (`bgtgame`) with no child controls. The message is exposed only to
the accessibility tree — which is also how the engine's intended audience reads
it — so `bgt_compile` launches the compiler, waits for the report window or for
the process to exit, and reads the text out through UI Automation. The report
is exactly what a developer sees, file and line and source line and message,
and `Information: Candidates are:` carries the signatures the engine *does*
have for a call that did not match.

Three things about that are worth keeping:

- **A clean exit is not the same as a clean compile.** Some modules make the
  compiler die silently — no window, no message, exit `0xC0000005`. Read
  as success, a module that crashes the compiler looks perfect. A
  compile-only check also has to disarm `main`, or a *successful* compile
  looks exactly like a hang. The reverse trap is worse, because it is
  quiet: the engine reports through its window and *then* exits, and the
  driver dismisses that window so it can finish — so a report and a clean
  exit arrive together. Reading the exit code first threw the report away,
  and Psycho Strike's 33 errors came back as `compiled cleanly`. The text
  is parsed before the exit code is believed.
- **One compiler at a time, and say so when it could not run.** `bgt.exe` is
  a GUI program read through the accessibility tree, and two of them at once
  do not both get read: checking two titles in parallel here gave one real
  report and one blank `nodriver`, which looks like a broken check rather
  than a busy one. Checks take a lock and queue; a stale lock from a killed
  run is cleared rather than waited on. And `nodriver` now carries its
  reason into both the summary line and `recovery.json`, because an outcome
  with no explanation reads like a result — and this is the one outcome
  that is not one.
- **Ask the compiler about the language rather than guessing.** `string[]()`
  is valid and `weapon@[]()` is a parse error, because the parser takes
  `weapon@[]` as the start of a declaration and nothing else; the template's
  own name works as an expression, so a constructor is emitted as
  `array<weapon@>()` while declarations keep the idiomatic `T[]`. Both forms
  were put to the compiler before either was emitted.
- **A parser that drops diagnostics flatters the result.** The first candidate
  list swallowed every later message in the report, so 318 errors came back as
  seven and the recovery looked almost finished. Any count that improves
  suspiciously fast is a count worth re-deriving.

## Where it stands

Every title that parses recovers with **0 unmodelled opcodes and 0 bodies
that failed to decompile**. What the compiler says, and what the project's own
checks say:

| title | lines | files | goto | unbalanced | split | calls read back | compiler says |
|---|---|---|---|---|---|---|---|
| Super Egg Hunt | 6,564 | 16 | 0 | 0 | yes | 1,607 | **compiled cleanly, and it runs** |
| Paladin of the Sky | 28,223 | 61 | 0 | 0 | yes | 7,145 | **compiled cleanly, and it runs** |
| Psycho Strike | 28,067 | 75 | 0 | 0 | yes | 6,462 | 33, every one the engine's |
| Manamon 2 | 175,032 | 1,638 | 4 | 0 | yes | 51,249 | 33 parse errors, so **nothing** |
| Crazy Party | 196,488 | 560 | 0 | 0 | yes | 90,494 | **compiled cleanly, and it runs** |

The line and goto counts are a fresh run of all five, not the figures this
table carried before: Manamon 2's gotos are 4 rather than 6, and the rest
moved by a few hundred lines as the decompiler improved. **And Paladin has
to be recovered from the game**, not from `paladin_fixed/game.exe`, which is
the 1.27 MB executable `bgt compile --build release` *wrote* from an earlier
recovery. Decompiling that is a round trip rather than a recovery, and it
reads as one: 36,151 lines against the original's 28,223, because recovered
source does not compile to the bytecode the original was built from.

Paladin's window now reads `Paladin of the sky`, which supersedes the note
below about it reporting `command`: that was the uncompiled-build path, and
reaching the real title means the module got further than it used to.

**Three titles compile clean and run**, including the largest. Crazy Party is
195,364 lines across 558 files and reports `compiled with 2 warning(s)`;
`bgt compile --run` on it opens a window of its own titled `Crazy Party
beta77`. Super Egg Hunt reports `compiled cleanly` and `--run` opens
`Super Egg Hunt Version 1.53` — the title the original executable shows,
checked by launching it. That is the end-to-end check: executable in, source
out, source back into the engine, game on screen.

**And a window on screen is not the check that matters** — Super Egg Hunt
passed every line of this table while its menu could not be navigated. See
**When a folded temporary stops being the value the bytecode computed**: the
counts above say the recovery is *structurally* complete, and three separate
bugs that compiled cleanly and ran were found by pressing an arrow key.

**A window title is still only evidence that the module reached the engine**,
and Paladin is the title that taught it twice. It used to report `command`,
because run as a *script* `get_SCRIPT_COMPILED()` is false, the game takes its
own uncompiled-build path, and the first titled window that path opens is an
`input_box("command", ...)`. Then it reported `Paladin of the sky` — the real
one — while the game was unusable: no audio, and the menu looping back into
`tts_selector` (see **Every body must match too**). So the title moves for
reasons that have nothing to do with whether the recovery is right, in both
directions. It is a liveness check and nothing more.

**Psycho Strike's 33 are all the installed engine's.** 32 are uses of
`elias`, a plugin type, and one is `tts_voice::speak_to_sound`, which this
engine does not document and the game's own executable registers. Nothing
there is the recovery's.

**On both titles that still report errors, every error is the installed
engine's.** Psycho Strike's 33 are 32 uses of the `elias` plugin type and one
`tts_voice::speak_to_sound`. Manamon 2's 33 are in five files, and each one
starts on `protected` or `weakref<T>`: its own newer BGT has both and this one
has neither, and a parse error stops the compiler, so the rest of each file
follows from the first line. Nothing left on either title is the recovery's.

**SBYW is absent from this table on purpose.** Its executable is no longer in
the folder it was read from, so its numbers could not be re-measured against
the current code and are not quoted as if they were. Everything above it in
this document that mentions SBYW is a *parse* and *lift* result, which stands
— it is only the recovery table that needs a run.

**Manamon 2 got there by three fixes, and the brace count is what found all
three.** It began the day at 68 errors, three unparseable files, 25 residual
gotos and a split that did not verify, and the compiler's own messages said
none of that — they blamed declarations hundreds of lines downstream with
"Expected method or property", which is exactly what a missing engine keyword
looks like. Reporting `unbalanced files` separated the two causes
immediately: the structurally broken files were 2, 10 and 1 braces short
while the `protected` file balanced at zero. What they were:

- a **namespaced section keyed by its bare name**, which moved 71 lines
  fifty thousand lines early and was the whole of the split failure;
- a **jump table claimed by neither switch matcher**, whose arms were emitted
  with ten unmatched `}`;
- **`goto` treated as a terminator** by `_drop_unreachable`, which deleted
  seven live lines of `cure_all_statuses` including its `if (...) {`. The
  structurer's output was valid; the pass broke it.

It now reports 0 unbalanced files, 0 dangling `else`, a verified split, no
problems at all, and 3 bodies given up on and counted — the jump tables
above. 6 residual gotos remain.

## The engine documents itself

`bgt.chm` sits next to `bgt.exe` and answers, authoritatively, every question
of the form "does this engine have that?": one reference page per registered
function, class and method, each carrying its signature verbatim.

```bash
bgt api garbage_collect            # void garbage_collect()
bgt api --list sound_pool          # the type and its methods
bgt api elias weakref --missing    # NOT documented
```

`bgt_api` unpacks it with Windows' own `hh.exe` (the only thing that reads the
format), caches the result outside this repository, and parses the reference
tree -- 125 functions and 25 types with 273 methods, from 413 of its 421
pages. Tutorial pages are skipped, because example code is not an API.

**And example code inside a *reference* page was not.** A reference page is
named after the one API it documents, so `garbage_collect`'s page defines
`generate_garbage` to have something to collect, `get_call_stack`'s defines
`first_dummy_method`, `serialize`'s defines `save`. Every signature on a page
whose name is not the page's own is example code, and eleven of them were
being counted as engine API -- which is the count above moving from 140 to
125. That matters in the dangerous direction: this list is what decides
whether an absence gets reported, so **a name it wrongly holds is a gap it
will not report**. The engine's own registrations settle it, and so does the
help file's own tree -- not one of the eleven has a page. The `PROPERTY`
branch two lines below had applied exactly this rule all along, which is the
recurring shape here: two places answering one question, one of them stricter.

Three things it settles that were guesses before:

- **The documented type list is the oracle for the engine gap.** Searching a
  binary for a name is a guess; this is a list. `bgt recover` uses it, and
  falls back to the binary search only when the help file cannot be read.
  It is not the *whole* list, though -- see **The engine registers itself**
  below, because `bgt.exe` holds a list too, and a longer one.
- **The language has no `goto` and no `protected`.** Neither word appears
  anywhere in the help file. So a residual `goto` can never compile, however
  it is spelled -- and Manamon 2's `protected` really is a newer engine's.
  Confirmed independently since, in the binaries: neither string occurs in
  BGT 1.0's `bgt.exe` or 1.3's, while `private`, `funcdef`, `interface` and
  `cast` occur in both.
- **The command-line options are documented** (Appendix G), and match what the
  installer's shell verbs do: `-c` debug, `-C` release, `-r` the registration
  manager, no space before a quoted path, and a bare `-c` opens a file dialog.

### What the documentation does not say, the engine will

A signature is not semantics, and recovered source is only as meaningful as
the primitives it calls. These were put to `bgt.exe` directly -- a script
that calls each one and writes the result to a file through `file::write`,
compared byte for byte against Python:

| primitive | what it actually does |
|---|---|
| `string_hash(s, 2, true)` | raw SHA-512, 64 bytes, NULs and all |
| `string_reverse(s)` | reverses **bytes**, not characters |
| `string_base64_encode(s)` | standard alphabet, standard `=` padding |
| `string_mid(s, start, count)` | **1-based**: `(s, 5, 4)` of `0123456789abcdef` is `4567` |

`string_mid` is the one worth the trouble. Nothing in a decompiled body can
settle 1-based against 0-based -- both read perfectly -- so every recovered
`string_mid(x, n, k)` is `x[n-1 : n-1+k]`, and reading it as `x[n : n+k]` is
off by one in a way that only shows up in the output. The same probe shape
settles any other primitive the same way, and it is cheaper than arguing
about it.

### The engine registers itself, and the binary is the longer list

AngelScript registers everything by handing the engine a **declaration
string**, and that string is a literal in the executable. So the whole
registered interface is sitting in `bgt.exe` -- exact parameter types,
`&in`/`&out`, `const`, and the default arguments the engine gives its own
functions. `bgt_api.registered()` reads it (432 names and 34 types in BGT
1.3, 240 and 23 in 1.0), and `bgt api` consults it alongside the help file:

```bash
bgt api string_compress        # registered, not documented
bgt api --missing network_event weakref
```

**The help file is not the whole list, and the gap has teeth.** BGT 1.3
registers `string_compress`, `string_decompress`, `crc32`, `add_fx`,
`delete_fx`, `hex_string_to_number`, `screen_reader_braille` and
`string_create_from_pointer`, and documents **none** of them -- and
Paladin's save path is
`serialize_all()` -> `serialize()` -> `string_compress()` -> `string_encrypt(...)`.
Asked of the documentation alone, "does this engine have that?" answered no
about a function a shipped title calls. It registers two *types* the help
file omits as well, `network_event` (what `network::request()` returns) and
`library_structure`, so a game using either would have been reported as
needing a newer engine than the one installed.

**Nothing on the four titles moves**, and that is the result rather than a
disappointment: `engine_gap` and `method_gap` are identical before and after
on Paladin, Psycho Strike, Manamon 2 and Super Egg Hunt. The hole is
provable and latent, which is the only honest way to describe it -- the
evidence is `string_compress` and `network_event`, not a changed report.

That gives three sources that answer three different questions, and the
split is clean:

| where a name is | what it is |
|---|---|
| a registration string in `bgt.exe` | engine API -- authoritative |
| a declaration in `include/*.bgt` | library API, which recovers like any script |
| a reference page named after it | documented |
| a signature on some *other* page | example code, and not an API at all |

The five documented functions that are registered nowhere --
`position_sound_1d`, `position_sound_2d`, `position_sound_custom_1d`,
`position_sound_custom_2d` and `convert_to_currency` -- are exactly the
library ones, in `sound_positioning.bgt` and `finance.bgt`. The same split
holds for types: the nine documented types with no factory registration are
`array`, `string` and `vector` (value types) plus `audio_form`,
`dynamic_menu`, `logger`, `number_speaker`, `sound_pool` and `soundtrack`,
which are the helper-layer *script* classes.

Three refusals make this a reader rather than a guess, and each was a real
false positive first:

- **An array return.** `string[]@ find_files(string& in)` was rejected by
  the first pattern, which reported four functions as absent that the help
  file *did* document -- and the documentation disagreeing is the only
  reason it was caught. An extractor that answers anyway, in a new costume.
- **The handle marker sits against either side.** The engine writes a
  factory `network_event @f()` and a getter `network_event@ request()`, so
  demanding whitespace between the type and the name finds the second and
  silently loses all eighteen of the first.
- **A return type and a name must be separated by something.** The type
  pattern backtracks, so a bare `send()` from the import table splits into a
  return type `sen` and a function `d`. Four import names became registered
  types that way. And a file-dialog filter is shaped exactly like a
  declaration (`All Files (*.*)`), which is told apart by the fact that a
  declaration's parameters are *types*.

### A game's own executable is an engine, and it will tell you which one

This is the one that pays for everything above. **A BGT game is the runtime
with the module appended**, and the runtime is not compressed in the game --
only in `exec.bin`, which is how `bgt.exe` carries it. So the same
registration strings are in `strike.exe` and `rpg.exe`, and reading them
gives the whole interface of the build that produced that module:

```bash
bgt api --exe "<game>.exe" weakref garbage_collect    # that build's answer
```

| engine | registered names | types | built |
|---|---|---|---|
| BGT 1.0 | 240 | 23 | 2010-12-30 |
| BGT 1.3 | 432 | 32 | 2014-06-01 00:41 |
| Super Egg Hunt | 432 | 32 | 2014-06-01 00:38 |
| Paladin of the Sky | 432 | 32 | stock |
| Psycho Strike | 453 | 40 | 2015-04-19 |
| Manamon 2 | 509 | 52 | 2019-11-15 |

Egg Hunt's runtime was built **three minutes before** the `bgt.exe` that
embeds it, which is one compile session: that title is stock 1.3 and the
timestamps say so without being asked.

**Psycho Strike and Manamon 2 are the same custom engine, four years
apart.** Twenty of Psycho Strike's twenty-one additions over 1.3 are in
Manamon 2 as well; the twenty-first is its own `string substring(uint
offset, uint count)`, which Manamon 2 drops for AngelScript's stock
`string substr(uint start = 0, int count = -1)`. Both are VGStorm titles,
so this is one developer's BGT fork and not two.

What Manamon 2's fork adds, read off its own runtime:

- **Crypto++.** `ecdh` (`generate_keys`, `get_public_key`, `get_private_key`,
  `agree(decryption_key@)`), `encryption`/`decryption` with
  `process(string&in, string&out)` and `set_input_format(data_formats)`, and
  `Crypto++ RNG` as a literal in the file. That is the whole of what
  `engine_gap` had been reporting as four mysterious absent types.
- **A much newer AngelScript**, from its stock add-ons: `opImplCast`
  (2.28.1+), `findByRef(const T&in if_handle_then_const value)` (2.30+),
  `get_extended_exception_info(bool showStack=false)`, `formatInt`,
  `parseFloat`, `sortAsc`, `weakref`/`const_weakref`, `dictionaryValue`.
- **`void garbage_collect(int number_of_cycles=0)`**, with the parameter
  named. So a recovered `garbage_collect(int(1000))` is that build's
  signature used correctly, and dropping the argument to match stock 1.3
  would have changed the program.
- `string_regular_expression`, `create_pack_file_index`,
  `set_garbage_collector_panic_threshhold`, and the sized integer types.

#### `elias` is a binding compiled into the engine, not a plugin

BGT has no plugin mechanism -- its `#include` takes a script or a pack file,
and handed a DLL it says "Expected identifier". So the question is how
`elias` becomes a *type*, and the binaries answer it from three directions:

- The `elias` type and its seventeen methods (`start`, `silence`,
  `request_change`, `play_stinger`, `set_level`, `set_key`, `set_urgency`,
  `get_transitioning` ...) are **registration strings inside the runtime**,
  in both `strike.exe` and `rpg.exe`. A DLL cannot put them there.
- `elias.dll` is **not in either executable's import table**, and both
  runtimes carry its C export names verbatim -- so it is loaded with
  `LoadLibrary` at run time.
- The DLL exports 92 functions (`elias_theme_create_from_xml`,
  `elias_theme_read_samples`, `elias_track_set_crossfade_minimum` ...), and
  the seventeen script methods are a thin binding over about twenty of
  them: the theme-level half. The track-authoring half is not exposed,
  because a theme arrives as XML.

So it is a **BGT built to use that DLL**, which is the second of the two
possibilities and not the first. Manamon 2 has it too, so it came with the
fork rather than with Psycho Strike.

#### What that is worth to the gap checks

`engine_gap` and `method_gap` corroborated an absence by searching the
game's raw bytes for the name. A registration is proof where a substring
match cannot be told from a coincidence, so both now ask the game's own
runtime and keep the raw search only as the fallback for a runtime whose
strings cannot be read.

It found a false negative immediately. **`string::insert` was hidden by
`array::insert_at`**: `insert` is a substring of `insert_at` and
`insert_last`, which BGT 1.3 registers, so Manamon 2's use of the newer
AngelScript `string::insert` went unreported while `string::erase` -- a
name nothing else contains -- was reported. Manamon 2's method gap is 3,
not 2. Nothing else moves on any of the four titles.

### What else the two binaries differ on

The compiler's diagnostic table is a per-version artifact -- a message
exists only if the code path that emits it does -- so diffing the two
installed engines' strings gives a **list** of what the language gained,
where `capabilities()` launches a compiler to ask about one item of it.
BGT 1.0 has none of `namespace`, `mixin`, `final`, `override`, `shared` or
`auto`, nor default arguments; 1.3 has all of them. `protected`, `weakref`
and `goto` are in neither, which independently confirms what the help file
said about Manamon 2 and about residual gotos.

**And `garbage_collect()` takes no argument** -- the registration string
says so, matching the help file. So a recovered Manamon 2 calling
`garbage_collect(int(1000))` is not a decompilation error but one more
newer-engine gap, alongside its `protected` and `weakref`.

## Which BGT compiled it, and an entry script that declares something

Two things that between them cost a user an afternoon, both because the
toolkit was quiet rather than wrong.

**BGT 1.0 has no default arguments at all.** A recovered module uses them
wherever the original did, so compiling a perfectly good project with 1.0
gives a cascade that reads exactly like a broken decompilation:
`Expected ')' or ','` at the `=`, then "Expected method or property",
then "Unexpected token '}'" at the end of the class. The same project
compiles cleanly under 1.3.

`bgt_compile.capabilities()` answers which install this is, and
`bgt recover --compile` reports **which** `bgt.exe` it used, saying so
plainly when that one cannot parse what the source contains. The missing
fact was never the diagnostics; it was whose.

### Asking the file instead of the compiler

This section used to say there is no version string in `bgt.exe` and no
version metadata on the file, so the installs could only be told apart by
putting something to them. Both halves were wrong, and the correction is
worth more than the fact: **BGT 1.0 carries the AngelScript library version
`2.20.2`** as a literal (1.3 carries none), and both carry a PE
`TimeDateStamp` -- 2010-12-30 for 1.0 and 2014-06-01 for 1.3. Neither of
those is the *capability*, though, which is why the better answer is a
different one.

The capability is in the file too, twice over:

- **The engine registers three of its own functions with a default
  argument** -- `string_create_from_pointer(uint, uint size=0)`,
  `tone_synth`'s `void f(float, float y = 0, float z = 0)`, and
  `dictionary::call`'s ten `?&in paramN=null`. A registration string goes
  through the same parser a script does, so this is **the feature in use**
  rather than a marker that might coincide with it. BGT 1.0 has none.
- **And the compiler carries the diagnostics for a bad one**: `Failed while
  compiling default arg for parameter %d in function '%s'` and two others.
  A message exists only if the code path that emits it does.

`_default_args_in_binary` requires both markers to agree, and on the two
installs here they do -- 1.3 both, 1.0 neither, matching what the probe had
already measured. Where they disagree it returns `None` and the probe
decides, because two markers pointing opposite ways is the case a reader
should decline rather than answer.

**Why bother, when the answer was already cached once per install:** the
probe launches the compiler, and a compiler that *rejects* the probe puts a
modal error dialog in front of whoever is at the machine. That is the 1.0
case -- the very one worth knowing about -- and `bgt verbs --repoint` pays
it again per candidate it considers.

**What the markers prove is not symmetric, and the code says so rather than
implying otherwise.** A registration using the feature proves support;
neither marker appearing is the absence of the implementation's own strings,
which is strong evidence and not a proof. So a negative is believed only
from a file whose interface is *legible* -- at least 50 registrations, where
1.0 has 240 and 1.3 has 432. Everything is absent from a file this cannot
read: a stub, or a packed `bgt.exe` whose strings sit inside the compressed
image, which is not hypothetical when BGT's own runtime ships exactly that
way inside `exec.bin`. Without that guard a packed engine would be reported,
confidently, as having no default arguments.

**A test must not write to the user's cache**, which this one had been doing
all along. `capabilities()` remembers its answer on disk, and the test that
pins "an inconclusive check is not an answer" hands it a throwaway 13-byte
`bgt.exe` -- so every run appended an entry to the real
`%TEMP%/bgt_capabilities.json`, thirty of them on this machine. Nothing was
ever read back wrongly, because a temp path never recurs; a test that used a
stable path would have poisoned the answer for a real install.

**And the compiler this toolkit picks is not the one a person reaches.**
BGT's installer registers five shell verbs for a `.bgt` file, and
installing 1.0 after 1.3 leaves three of them pointing at 1.0:

| verb | after installing 1.0 over 1.3 |
|---|---|
| `open` (double-click) | **BGT 1.0** |
| `run` ("Run Script") | **BGT 1.0** |
| `compile` ("Compile Script") | **BGT 1.0** |
| `compile_debug`, `compile_release` | BGT 1.3 |

So a project that reports `compiled cleanly` here gives a hundred
`Expected ')' or ','` on a double-click, which is how it was reported.
`bgt_compile.shell_verbs()` reads them out of the registry and
`verb_warnings()` names any whose engine cannot parse what was just written.

### Repointing them, which needs no administrator

Naming the fault is not fixing it, and "use Compile Script (Debug) instead"
is a workaround a person has to remember every time. `bgt verbs` shows what
the shell will run and `--repoint` changes it:

```bash
bgt verbs                      # what the shell runs for a .bgt file
bgt verbs --repoint            # point open/run/compile at a BGT that parses this
bgt verbs --restore            # remove the override again
```

Three things decide the shape of it, and each is what makes a change to
somebody's machine safe to offer at all:

- **It writes `HKEY_CURRENT_USER`, never `HKEY_LOCAL_MACHINE`.** The machine
  key needs an administrator and would change the association for every
  account on the box. The per-user key needs neither **and wins anyway**,
  because `HKEY_CLASSES_ROOT` is a merged view in which HKCU outranks HKLM.
- **The undo is structural, not a saved copy.** `--restore` deletes the
  override and HKLM's own value applies again *by construction*. There is no
  backup file to lose, and no way for a restore to write a path that was
  never registered.
- **Only the executable is substituted.** The rest of the command string is
  kept verbatim, because the switch is the whole difference between running a
  script and compiling it -- `open` passes it bare, `compile` passes
  `-c"%1"`, `compile_release` `-C"%1"`. Rebuilding the command from a table
  of switches would work right up until BGT's installer used a different one,
  and a `compile` verb that quietly started *running* the game instead would
  look exactly like a repoint that had worked.

It refuses rather than guesses when the target cannot parse a default
argument -- including when the probe was inconclusive -- since repointing a
verb at a *second* engine with the same gap reports success and fixes
nothing.

**And the check that was supposed to confirm this would have denied it.**
`shell_verbs()` read HKLM first and stopped on the first hit, which is the
wrong way round: the shell resolves a ProgID through the merged view, where
the per-user key wins. With an override in place the old order went on
reporting the *overridden* path -- so the fix would have worked while the
only thing able to see it said it had not. It reads `HKEY_CLASSES_ROOT` now,
which is what the docstring always claimed.

**Verified against the shell, not against the registry.** Reading your own
write back through your own function proves nothing about what Windows will
do with it. Two independent checks, in order of strength: `AssocQueryStringW`
-- the shell's own resolver -- reports the 1.3 path for `open`, `run`,
`compile` and for the *default* verb, which is the double-click; and a
`ShellExecuteW` of a probe script whose only unusual feature is a default
argument reaches `main()` and leaves its file behind, which BGT 1.0 could
never do, because it stops at the `=`.

Both installs were put to each failing shape rather than assumed:

| shape | BGT 1.3 | BGT 1.0 |
|---|---|---|
| `bool b = false` | accepts | `Expected ')' or ','` |
| `int b = -2` | accepts | `Expected ')' or ','` |
| `int b = )` | **accepts** | `Expected ')' or ','` |
| `double[] d(256);` | accepts | `Expected ';'` |

**`capabilities()` was answering from runs that never happened.** A check
that comes back `nodriver`, `timeout` or `crashed` carries no diagnostics,
and `not report.errors` read that as "this compiler is fine" -- so BGT 1.0
was reported as *supporting* default arguments, and the whole warning this
section exists for never fired. One busy lock is enough, because two checks
cannot run at once. An inconclusive outcome is now not an answer.

**And asking has a cost that lands on a person.** Probing launches the
compiler, and a compiler that rejects the probe shows a modal error dialog
on whoever is at the machine -- which happened repeatedly, once per run,
while chasing this. The answer is cached to disk keyed by the executable's
path, size and mtime, so it is asked once per install rather than once per
process. A diagnostic that interrupts the user every time is a cost, not
just a slow path.

**"The script section is empty" was not cosmetic.** BGT reports warnings
in a modal dialog and waits on it, so an unattended compile stops there;
and a warning nobody can explain invites the conclusion that an entry
script of nothing but `#include` lines is why a recovery does not run.
It is not — `#include` is textual, so the module is the concatenation, and
`main()` inside an included file runs, which was checked directly with a
two-file probe rather than argued. The entry script now carries the
module's own types section (enums, typedefs, funcdefs) inline instead of
only includes. That section was already first in the order, so nothing
moves, and Super Egg Hunt went from `compiled with 1 warning(s)` to
`compiled cleanly, and ran`.

## A literal has to reach the engine as the bytes the module held

This is the worst failure shape in the whole toolkit, because everything
reports success: the project recovers with 0 errors, compiles cleanly, opens
its own window with the right title, and has **no sound**.

The engine reads source as bytes, and a recovered literal is bytes. Every byte
above 0x7F used to be emitted as a *character* into a UTF-8 file, so `0xAC`
became `C2 AC` and the engine got two bytes where the module had one. For
ordinary text that is invisible; for Super Egg Hunt's pack key, which is a
32-byte AES blob in a literal, it is fatal and the engine says so exactly
once, in a pane next to the window title:

```
Error streaming logo.ogg.  Decryption failed because the key was incorrect.
```

Two cases, and the test between them is decoding rather than taste:

- **The bytes are valid UTF-8.** Then the characters they decode to encode
  back to exactly those bytes, so they are written as themselves — Crazy
  Party's `caractère` stays `caractère` *and* stays correct. Correctness here
  is by construction, not by luck: the round trip is the criterion.
- **They are not.** Then no character spelling can be trusted and every byte
  from 0x7F up is written `\xNN`.

**BGT was asked rather than assumed**, the way everything else here is:
`"\xac\x71\x96"` compiles with no warning and produces those three bytes,
raw bytes in a byte-preserving file do too, and the octal form `"\254"` is
`Warning: Invalid escape sequence`. The probe wrote all three spellings to a
file through `file::write` and the bytes were read back.

`test_regressions.LiteralRenderingTests` renders **all 256 byte values**,
passes the result through UTF-8, and parses it back with an unescaper written
from the lexer's rules rather than as `_esc`'s inverse — an inverse built from
the same table would agree with a wrong table.

Afterwards, `bgt compile --run` on the recovered project reports `compiled
cleanly, and ran: it opened a window of its own titled 'Super Egg Hunt Version
1.53'` with **no runtime complaint at all**.

**What found it was the engine talking, so that is now read.** The driver had
the line in `raw` the whole time; `Report.runtime_complaints` pulls what the
engine said at run time out of what it said about the source, and the summary
carries it. A clean compile says nothing about whether the project has the
files it opens, and this is the one check that costs nothing.

## A staged copy does not sit where its includes point

`bgt compile` stages the script into `_compile_check/` so the executable the
compiler writes lands there instead of in the project. BGT resolves an include
against the *including script's* directory, so the copy looked for
`includes/classes/player.bgt` beside itself and reported, truthfully, that
there is no such file — one error, blaming the first file it could not find.

Only `bgt recover --compile` knew that, with a `'#include "includes/'` →
`'../includes/'` string replace of its own. So `bgt compile` on the project
`bgt recover` had just written — the obvious next command — failed, which
reads as a broken recovery. One `bgt_compile.stage` now disarms `main` and
repoints every relative include with `relpath`, and the CLI, the GUI and
`bgt recover` all go through it. The GUI had the opposite half of the same
bug: it compiled in place, so the engine's output landed in the folder being
read.

## A window, for people who read screens with a screen reader

`bgt gui` is a wxPython front end over `identify`, `recover` and `compile`.
It calls the same functions the CLI does with the same defaults, so the
command line stays the reference and anything the window reports can be
rechecked in one command.

These are audio games, and that decides the design rather than decorating it:

- **Stock controls, and a label on every one.** The label goes on twice —
  as the `StaticText` beside the field and as the control's accessible name —
  because which one a screen reader picks up varies, and a field announced
  as "edit" is a field nobody can fill in. `tests/test_gui.py` asserts it,
  with the generic names taken **from wx itself**: `CheckBox` defaults to
  `check`, not `checkbox`, and a plausible-looking list would have let the
  real case through.
- **The log is a read-only multiline text box**, because that is the one
  widget a screen reader can review line by line afterwards. Progress is
  appended, so nothing already said is overwritten.
- **Finishing raises a dialog.** A screen reader announces a dialog without
  being asked and does not announce a label that quietly changed, so the end
  of a job arrives as a message box while the detail stays in the log.
- **Work runs on a thread**, every widget touch through `wx.CallAfter`.
  Recovering Crazy Party takes minutes, and a frozen window cannot even say
  it is still working.
- **There is no Stop button.** `recover` has no cancellation point, and a
  button that cannot stop what it claims to invites you to believe a
  half-written output folder is consistent. The controls disable instead,
  and closing mid-job asks first.

## The stock library files come from BGT, not from the module

A shipped `include/*.bgt` is not what anyone is trying to recover. It
comes with the engine, and its real source has the parameter names and
the comments, which compilation threw away:

```
decompiled:  int play_stationary(string arg0, bool arg1, bool arg2 = false)
BGT's own:   int play_stationary(string filename, bool looping, bool persistent=false)
```

So a run attributed to a shipped file is replaced by that file, and the
decompiled sections for it are dropped. **Games edit this library
constantly**, though, and substituting over an edit silently undoes it,
so each of the following has to pass. Every one of them is here because a
title broke when the check was weaker:

- **It must declare no types of its own.** `form.bgt` declares four
  enums, and `types.bgt` already carries every enum in the module, so
  taking the stock file too is four "Name conflict" errors. Psycho
  Strike, 33 errors to 37.
- **Every member must exist in the stock file.** Super Egg Hunt's
  `dynamic_menu` has `is_main`, and its `dynamic_menu_item` an
  `item_id`, which stock BGT has never heard of. The first version of
  this compared class *names*, which matched, and the game's own code
  then failed against the engine's class.
- **Every signature must match, parameter types and all.** Paladin's
  `dynamic_menu::set_tts_object` takes its own `voice_manager@` where
  stock takes `tts_voice@`, and Super Egg Hunt's `sound_pool::update`
  takes three ints where stock takes two. The names match in both cases,
  which is exactly why names were not enough: Paladin went from 0 errors
  to 2, at the call site rather than the definition.

- **Every body must match too.** This was the one check that *reported*
  rather than blocked, on the argument that a body difference is either
  the game's edit or this decompiler's own rendering and the comparison
  cannot tell them apart. That is true and it is not the point, because
  **the costs are not symmetric**: keeping the decompiled copy loses
  parameter names and comments in a file nobody was trying to recover,
  while substituting over a real edit replaces the game's code with the
  engine's and says nothing.

  Paladin's `sound_pool` — the audio engine — matches on every member and
  every signature and differs in four bodies, so it was being replaced
  wholesale. `sound_positioning.bgt` still substitutes on all three
  titles because it genuinely matches, which is the readability this was
  for; `sound_pool` no longer does.

  **This was adopted on the argument, not on a measured fix, and that
  distinction was briefly lost.** It was first claimed as the cause of a
  recovered Paladin playing no audio and looping through its TTS voice
  selector, on the evidence that `--no-stock-includes` changed the window
  title from `command` to `Paladin of the sky`. A window title is not
  causation, the symptom survived the change, and the real explanation was
  elsewhere (see **Run as a script, a game takes its developer path**).
  The rule stands on the cost asymmetry alone; it fixed nothing known.

`bgt libcheck --decompiler` is what says which differing bodies are the
game's edits and which are this decompiler's rendering, and
`--no-stock-includes` keeps everything decompiled.

A note on reading that report: Super Egg Hunt's `number_speaker.bgt`
differed on `speak_next` before the fold fixes below and matches now. A
"differs" line is a statement about the decompiler as much as about the
game, so it moves as the decompiler improves.

`#include` and `funcdef` lines are stripped from the copied file: the
entry script lists every file in order, and `types.bgt` already declares
the funcdefs, so leaving either in is a duplicate declaration.

**A file written is not a file registered, and the ZIP is where that
showed.** `substitute_stock` writes the engine's copy itself, while
`project.files` was appended to as each *decompiled* group was written — so
every substituted file was missing from the file list, from the count, and
from `game_project.zip`. Unzipping Super Egg Hunt gave an entry script that
included `number_speaker.bgt` and `sound_positioning.bgt` and two files that
were not there, which from outside is indistinguishable from "it does not
copy the stock includes" and is how it was reported. The list is built from
the include order and from what is actually on disk now, so the three claims
cannot drift apart.

`recovery.json` also listed `includes/types.bgt` as included when the entry
script had inlined it. A file list nothing reads is still a claim about the
project: `includes` is what the entry script really includes, `inlined` is
the one section it carries instead, `order` is the concatenation the split
check uses, and the inlined section is no longer also written as a file
nothing includes.

## The assets, which the script will go looking for

A recovered script still calls `set_sound_storage("data.dat")`, and if the
pack is not where it looks the engine does not politely do without sound —
it can die at startup. So `bgt recover` always reports what the project
needs, and can bring it:

```bash
bgt recover game.exe -o out/                  # copies the packs: the default
bgt recover game.exe -o out/ --extract-data   # ...and unpack their entries too
bgt recover game.exe -o out/ --no-data        # bring nothing, and cannot play audio
```

**Copying is the default, and the two are not alternatives.** Both of those
were wrong and both were reported from real runs. A project whose script calls
`set_sound_storage("data/bgm.dat")` with no pack beside it reports

```
ERROR!  dialog  could not load pack data/bgm.dat.
```

and plays nothing, so opt-in was the wrong default for the one thing that
makes a recovery runnable. And copying and extracting answer different
questions — "can this run?" and "what is in the pack?" — so forcing a choice
meant the obvious way to get the assets out also produced a silent game.

Finding the packs takes two pieces of evidence, because neither alone is
enough. The *names* come from the module's string constants, since the calls
pass locals (`set_sound_storage(local_8)`) and the literal never reaches the
call site. The *filter* is the `SFPv` magic of a file sitting beside the
executable, which is what separates `data.dat` from the `log.txt`,
`save.bin`, `.` and `/` that are also in those constants.

**Finding nothing is the case that matters.** Recovering from a copy of the
executable — the normal thing to do — finds no pack beside it, and silence
there is the whole problem. So the module's own calls are the fallback
evidence: `set_sound_storage` means it opens a pack at all, and
`set_sound_decryption_key` means the entries are encrypted and the key is a
separate hunt (`bgt crack`). Either way the report says so.

Three things this turned up:

- **A pack may have a footer, and refusing it was stricter than the engine.**
  `pack::create` writes the entry count in the header and `pack_file` reads
  exactly that many, so bytes after the last entry are never read. Crazy
  Party's `data.dat` carries 32 of them after 2,425 entries whose record
  magic every one validated, and the old "must land exactly on EOF" rule
  meant the one pack this toolkit could not open was one the game opens
  without complaint. The per-entry magic is the real self-check; trailing
  bytes are counted and reported now.
- **`tag_index` without payloads answers "no keys", which is wrong.** The
  `SWCR` tag lives in the payload, so asking after `parse(load_data=False)`
  reports every pack as unencrypted — and a 372 MB pack cannot be loaded
  just to ask. `bgt_pack.survey` reads each entry's 20-byte header at its
  known offset instead, which is cheap and cannot give that answer.
- **A string constant is data, and two guards follow from that.** A name must
  not reach outside the game's folder, and an entry name must not write
  outside the extraction folder. `os.path.commonpath` raises `ValueError`
  across drives rather than returning a verdict, and Crazy Party's constants
  hit exactly that, so the exception is the answer — different drive,
  therefore outside — rather than a crash out of `bgt recover`.
- **Packs need not sit beside the executable.** Super Egg Hunt keeps seven in
  a `data/` subdirectory and names them `data/bgm.dat`, so the name from the
  string constants is joined to the game's folder rather than looked for in
  it. Both guards above are what make joining a module's string to a path
  safe.

### Extracting means decrypting, and the key is in the module

`--extract-data` used to answer *"holds 16 encrypted entries and needs its
key: bgt crack …"* for every pack and write nothing. That reads like advice
and is really a gap: the key is whatever the script passed to
`set_sound_decryption_key`, and the script is in the file being recovered.
`pack_keys` searches for it, and extraction decrypts with what it finds —
Super Egg Hunt's seven packs, **344 of 344 entries, every one valid Ogg
Vorbis, from one key**.

An entry whose key does not verify is **skipped and counted**, never written.
A file of ciphertext named `music.ogg` is worse than no file, because it looks
like the extraction worked.

**The harvest could not have found that key, and the reason is a quiet one.**
`module_strings` accepts a literal only if every byte is printable ASCII, NUL
or whitespace — which is right for a blind scan and discards exactly the
literal a game stores a key in. BGT's idiom is

```
set_sound_decryption_key(string_decrypt(h_key, "af-dc7=rqp+"), true);
```

where `h_key` is a 32-byte AES-CBC blob. So `bgt crack` reported *3,392
candidates, 0 hits* while both halves of the password sat in the module, and a
negative result over a candidate set that **cannot contain the answer** is the
most convincing kind of wrong.

Two things fix it, and both are narrow:

- `as_module.literal_is_cipher_shaped` — a whole number of 16-byte blocks, at
  least one, mostly bytes that are not text. `module_strings` takes an
  `accept` predicate so the blind scan's own filter is unchanged.
- `bgt_crack.harvest_encrypted` — every blob decrypted under every text
  literal. The cross product is affordable **because `string_decrypt` is
  self-checking**: BGT wraps a plaintext as `printf<len>\0<data>`, so a wrong
  pairing is rejected by the format and never reaches the pack. On Super Egg
  Hunt it yields exactly **one** candidate, `puppiesandpandas`, which opens
  every entry.

A pack key is confirmed by one AES block against the tag each entry stores, so
none of this is guesswork: `tag == AES-ECB(key, 16 zero bytes)` cannot be
satisfied by a wrong key. `bgt_pack.survey` returns the tags themselves now,
not only how many, because that is all a search needs.

**Extracted assets are not what the script opens.** It still calls
`set_sound_storage("data/bgm.dat")`, so `--extract-data` gives a project that
compiles, runs, and says `could not load pack data/bgm.dat.` — which the
report says first -- though it no longer arises on its own, because
copying is the default and `--extract-data` now adds to it rather than
replacing it.

## Compiling without the GUI

`bgt.exe` has no documented switches, and the installer's own shell verbs are
where they are written down:

```
HKLM\SOFTWARE\Classes\bgtscript\shell\compile_debug   bgt.exe -c"%1"
HKLM\SOFTWARE\Classes\bgtscript\shell\compile_release  bgt.exe -C"%1"
```

**No space before the path.** With a switch the engine compiles to an
executable beside the script; without one it *runs* the script. `bgt compile`
uses `-c` by default, which is a stronger check than running: nothing of the
program executes, so a game cannot open a window and sit there, and the whole
module still has to satisfy the compiler.

Two things about that to keep in mind:

- **The report dialog blocks it.** The engine shows one modal window for
  warnings as well as errors and waits on it before writing the executable.
  The driver dismisses it, which is why `_drop_unreachable` exists: a warning
  nobody can answer is a compile that never finishes.
- **`--run` has to look *past* that dialog.** It used to report the first
  window with a title, which with any warning at all is the report -- so a
  title that compiled with warnings and then ran was indistinguishable from
  one that only compiled. Run mode now dismisses a `Compilation*` window and
  keeps waiting, and reports the script's own window title when it appears.
  That is what `bgt compile --run` answers: `compiled with 1 warning(s), and
  ran: it opened a window of its own titled 'Super Egg Hunt Version 1.53'`.
- **`--build` built nothing at all, and said it had.** This section used to
  report that building a module this size hangs, with a small script building
  fine "so the mechanism works". Both halves were wrong, and from the same
  cause: **a PowerShell parameter named `$Switch` silently breaks every
  `switch` statement in that script.** The driver chose its mode with

  ```powershell
  param(..., [string]$Switch = "run")
  $flag = switch ($Switch) { "debug" { "-c" } "release" { "-C" } default { "" } }
  ```

  and that statement matched nothing, so `$flag` was always empty, no switch
  reached the engine, and BGT **ran** the script instead of compiling it. A
  disarmed entry point exiting 0 is exactly the compile-only success case, so
  the report read `compiled cleanly` while no executable existed -- in either
  mode, for as long as the option existed. Run mode passes no flag at all, so
  it was correct by accident and hid the whole thing, and the "hang" was run
  mode sitting in a game that had opened a window.

  Renaming it to `-Mode` is the entire fix. `bgt compile --build release`
  now builds Paladin's 28,028-line recovery to a 1.27 MB executable that
  `bgt identify` reads as `BGT (overlay 0xDDC00, key seed 0x11)` -- the same
  overlay offset and seed as the original -- and a two-line script builds in
  both modes. There is no module-size limit here; there was a parameter name.

  The lesson is the one this file keeps relearning from the other direction:
  the earlier note was not a guess, it was a *measurement* of a run that
  never happened. `tests/test_recovery.py` now asserts the driver declares no
  `$Switch`, that its mode really is chosen by a `switch`, and that the name
  Python passes is the name the driver declares.

Each of these was found by the compiler, and the quiet bugs *behind* them were
found by reading what it said rather than by inspection:

- **The global-pointer pre-shift touched the value field too.** The older
  dialect has no table-selector bit, so a global pointer is pre-shifted to
  `2n + 1` — but `SetG4` carries the value being stored in the other operand,
  and shifting that rewrote every constant assigned to a global. `const int
  male = 1` came out as 3, which is a plausible constant and not a plausible
  bug.
- **A derived class re-declared its base's properties.** A derived class's
  property table opens with its base's, in the base's order, and this
  generation records no flag to say so. Re-declared, every one is a name
  conflict: 1,700 of the first 1,827 errors. They are marked with the bit the
  newer format uses rather than dropped — the entries are still needed to
  resolve a member access by name — and only when the table really does open
  with the base's, because marking by position would hide a real property.
- **`STR`'s string index is a word operand here and a dword one there.** Left
  in the word field it resolves to whichever literal sits at index 0: a real
  string, in every body that has one.
- **A folded short-circuit outlived its slot.** `(A && B)` is bound to its
  slot so later reads see the whole value; left there after the slot was
  assigned again, every later read came back as that stale expression — 104 of
  the errors were one `clear_pathway` temporary read six times.
- **A constructor's generated member initialisation is not source.** A member
  declared by value but held by reference is created by code the compiler puts
  at the top of every constructor. `_refcpy` already dropped the store for
  exactly that reason; what was left behind was the creation, `@local_3 =
  weapon@[]();`, which is not expressible at all. The whole eight-instruction
  idiom is skipped now, and it is identified by the member being declared *by
  value* — the same shape with a handle member is a real assignment.

- **`CallPtr` names its variable in the other operand.** It takes one operand
  here and two there, and the funcdef-holding variable is the *second* one --
  which is where everything downstream looks. Left in the first, the call read
  slot 0 as its target (`this`) and took the slot *number* as its argument
  count: `this(local_8, <?>, <?>, ...)`, nine arguments for a nine-ary nothing,
  in 20 of Paladin's errors.
- **The sized array factory's length was thrown away.** The array template has
  a factory that takes a length (`double[]@ factstub(uint)`) and another that
  takes an initialiser-list buffer (`string[]@ factstub(int&in)`); the first
  is by value and the second by reference, which is the only thing that tells
  them apart. Dropping the length left two of `input_recorder`'s members
  unsized, and its constructor then wrote past the end of them -- which the
  engine reports as `Failed to initialize global variable 'recorder'` and
  nothing else. The length survives only on the member's *declaration*, since
  the store that applies it is generated prologue and is dropped.
- **Two matchers for one construct, and nothing owns the gap.** A computed
  jump is recognised twice: strictly in the simulation (`_begin_switch`, which
  demands the exact five-instruction prologue) and loosely in the structurer
  (`_dense_switch_pattern`). When *both* decline, the table's entries are
  never consumed: each becomes a `goto`, and each arm is emitted as an
  ordinary block — closing brace and all — with nothing that opened it.
  Manamon 2's `number_key_pressed` is a `switch` over 0..9 that came out with
  ten unmatched `}`, so the file could not parse and the compiler blamed a
  `return true;` hundreds of lines further on. An unclaimed table now raises
  `UnstructuredSwitch`, which gives up on that one body and counts it, rather
  than emitting most of it and corrupting the file. **The three bodies left
  are diagnosed rather than mysterious now** -- see **The three tables
  nothing claims** below. Eight sites in Manamon 2,
  none in any other title. Half-emitting a construct is worse than refusing
  it, because the damage lands somewhere else.
- **The last link of a switch chain may be a compare, not a table.** Where
  one of those ranges holds a *single* value there is no table to build, so
  the compiler emits `CMPIi sel, K ; JZ case ; JMP exit` instead. Read as a
  table that is not there the chain simply stops, and the compare is left
  behind as a branch to the switch's own exit -- a block the switch handler
  has already consumed, so it is a `goto` to a label that is never emitted.
  Super Egg Hunt's `submit_score` is one switch written both ways, `case 1..3`
  as a table and `case 27` as a compare, and it was the single error in that
  title's whole recovery.
- **A pass with no test can stop working and nothing fails.**
  `_drop_unreachable` deletes the statements that follow a `return` in a
  block, because BGT reports warnings in a modal dialog and waits on it. Its
  pattern's word boundaries were replaced by literal **backspace bytes** when
  it was edited -- `` eaten by a shell -- which matches nothing, so
  `return` and `goto` silently stopped terminating a block while `break;` and
  `continue;` went on working. Output stayed valid and two "Unreachable code"
  warnings per title looked like something the compiler had a right to say.
  Paladin's four are gone, and both the pass and the dialect probe now have
  tests.
- **A constant that is only ever stored is typed by where it is stored.**
  `slot_types` types a slot from the opcodes that *compute* with it, which
  says nothing about `pool.pan_step = 1.5`: `SetV4 v2, 0x3FC00000` is width
  only, no float opcode touches slot 2, and in Psycho Strike's `main` that
  slot is a bool elsewhere -- so it compiled to `pool.pan_step = true`. The
  destination's declared type settles it, and it has to be the *constant*
  that gets typed, not the slot: declaring the slot makes it a variable, and a
  variable is no longer folded into its use. Tried that way first,
  `sound_pool::reset` went from nine lines identical to BGT's own source to
  thirty-six lines of slot traffic -- a fix that read as a fix and made the
  output worse. Cross-validation is what caught it, exactly as it is supposed
  to.
- **One source `switch` is several jump tables.** A dense `switch` compiles to
  a bounds check, a normalisation and a computed jump into a table of jumps --
  and a switch over scattered values becomes a *chain* of such tables, each
  guard sending the value on to the next range. Read one table at a time, the
  first switch's extent swallows the later ranges' bodies, which come out as
  `return` statements with no `case` above them: `day_to_word` answered
  "twentieth" for every day from 13 to 31. Merged, it is one switch with all
  fourteen cases the source wrote. **And a gap of more than five splits the
  table** -- see **Reading the compiler, not only the reader** below, where
  that constant comes from and what it is worth.
- **A `for` header may not hoist the increment** when something jumps straight
  to the condition. That jump is a `continue` in a loop whose increment is
  part of the body; hoisted into the header it would run on that path too.
- **The funcdef placeholder names no funcdef.** `objVariableTypes` records a
  funcdef-typed local as `_builtin_function_` with no signature, so with more
  than one funcdef in the module there is nothing to resolve it to. A slot
  recorded that way *and* used by integer opcodes is a reused slot, and the
  placeholder is the half that cannot be declared.

## A build newer than the one installed

Manamon 2's 28 diagnostics are all *parse* errors, and they are not about the
recovery: its source says `protected` and `weakref<character>`, and both
strings are in its own `rpg.exe` and in neither BGT 1.0's nor 1.3's compiler.
It was built with a newer BGT. A parse error stops the compiler before it
checks anything, so those 28 are also all it can say about a 171,223-line
module.

`bgt recover` reports this from the one piece of evidence available: a type the
module uses, does not declare, appears in the game's own executable, and does
not appear in the installed compiler or its `exec.bin`. For Manamon 2 that
names five: `weakref`, and a Crypto++ family -- `ecdh`, `encryption`,
`decryption` and `decryption_key`. (`protected` is a keyword rather than a type, so it
is found the same way by hand and not by that check.) Saying so is the
difference between a report and a mystery -- and it is why a diagnostic count
is only ever a statement about *this* engine.

**It can also be one method of a type the engine does have**, which is the
same finding one level down and needs the documentation to prove: a *list* of
a type's methods makes an absence provable where a binary search for a short
name does not. Psycho Strike calls `tts_voice::speak_to_sound`, which returns
the speech as a `sound@`. BGT 1.3 documents `speak`, `speak_interrupt`,
`speak_interrupt_wait`, `speak_to_file` and `speak_wait`, and not that one --
and `speak_to_sound` appears in the game's own `strike.exe` and in neither
`bgt.exe` nor `exec.bin`. `method_gap` reports it next to the plugin, with the
same corroboration `engine_gap` uses.

That closes Psycho Strike out: **all 33 of its remaining diagnostics are the
installed engine's absences** -- 32 uses of the `elias` plugin type and this
one method -- and none of them is the recovery's.

## Reading the calls back, where the compiler cannot

The section above is the problem: Manamon 2's 33 diagnostics are all *parse*
errors, a parse error stops the compiler before it checks anything, and the
largest recovery in the corpus has therefore never had a single call read
back by anything. `bgt recover --compile` is the measure, and on the title
that most needs measuring it measures nothing at all.

`bgt apicheck` reads them back, and `bgt recover` now runs it on every
project without being asked. **The simulation pops a callee's declared arity
by construction**, so an arity mismatch cannot exist in the IR -- which is
exactly why the check belongs on the *text*. The rendered source is a
different artefact: it has been through temporary folding, slot promotion,
scope qualification and stock-include substitution, and every one of those
has dropped a real argument at least once in this file's history.

The oracle is three sources, and none of them is a guess:

| source | what it knows |
|---|---|
| the module's own `usedFunctions` | every callee's parameters and defaults **as the engine that compiled this module declared them** -- so a fork is checked against its fork |
| the game's own runtime | the whole registered interface of that build (`bgt_api.registered`) |
| the recovered text | the script's classes, methods, globals, locals and parameters |

A name may legitimately carry several arities, from overloads and from
methods of unrelated types sharing a name, so a call is judged against all
of them and reported only when **nothing** fits. That is deliberately weaker
than resolving the receiver's type, and it is what makes a false alarm
impossible from an overload the check failed to consider.

**What it will not judge, it counts rather than guessing at.** AngelScript
registers every constructor and factory under the literal name `f`, with the
owner type as a separate string argument, so `vector @f()` and `void
f(float, float y=0, float z=0)` sit in the binary with nothing to say which
type either belongs to. Taking the union of every `f` would accept nought to
three arguments for anything, which is not a check. A call through a
funcdef-typed local is declined for the same reason: the arity is the
funcdef's, not the variable's.

| title | calls read back | what the compiler can say |
|---|---|---|
| Super Egg Hunt | 1,607 | compiled cleanly |
| Psycho Strike | 6,462 | 33, every one the engine's |
| Paladin of the Sky | 7,145 | compiled cleanly |
| Manamon 2 | 51,249 | **nothing** -- 33 parse errors stop it |
| Crazy Party | 90,494 | compiled cleanly |

**156,957 calls, and not one mismatch.** That is worth nothing on its own --
a check that reports nothing may simply be blind -- so it is measured in
both directions. Injecting a defect into the recovered text finds it every
time: an argument dropped from `string_replace(a, b, c, d)`, an argument
added to `key_pressed(x)`, and a callee renamed to one nothing declares are
all reported, and four of its five guards move the measurement when broken
(the fifth guards the *declared-name set*, which it moves by 2,198 names on
Manamon 2 without any current call depending on it). And the four titles the
compiler *can* judge come back clean from both, which is the cross-validation
rather than the absence of evidence.

Four things had to be right, and each was wrong first:

- **Comments and strings are scrubbed in ONE left-to-right pass.** Each
  construct can contain the other's opener, so two regexes in sequence
  desynchronise. Manamon 2 calls
  `url_get("http://www.vgstorm.com/playmmn.txt")`, and a comment pass run
  first eats `//www.vgstorm...` as a line comment and takes the closing
  quote with it -- after which every quote in the rest of the file pairs
  with the wrong partner. That reported a one-argument call as taking ten,
  and then thirty-three.
- **A declaration is not a call.** `string serialize(dictionary@ d)` in a
  class body is a definition; read as a call it is a two-argument call to
  the engine's one-argument `serialize`, and every class in Manamon 2 that
  declares one produced that. What tells them apart is the token before the
  name -- a declaration has a *type* there.
- **A funcdef in call position is a delegate, not a call.**
  `pathfinder_callback(arg0.callbackPf)` binds one method; it does not call
  the callback with the five arguments it declares. Read the other way it
  reported all thirteen of Crazy Party's delegates.
- **...and a name-keyed oracle unions, it never replaces.** `event` is a
  global funcdef in Manamon 2 **and** the class `rhythm::event`. Replacing
  its entry with the delegate's arity threw the class's constructor away and
  reported five good `event()` calls as taking too few arguments -- the same
  collision as `string::insert` hiding behind `array::insert_at`, one level
  up.

The honest summary is that this found no defect in the current recovery and
closed the one thing that looked like one: a `tmp0(local_7, <?>, <?>, ...)`
in a stale Manamon 2 project, which is the old `CallPtr`-operand bug and
renders `local_6(local_7)` under current code. What it changes is that
Manamon 2 is no longer unmeasured.

## Run as a script, a game takes its developer path

`bgt compile --run` and double-clicking a recovered entry script both *run*
it, and `get_SCRIPT_COMPILED()` is false for a script. A game that branches on
that does not take the path its players see.

Paladin is the clearest case and it cost a wrong diagnosis. Its recovered
build played no audio and looped through the TTS voice selector -- arrows
cycling voices, enter saying "success", nothing else -- which reads exactly
like a decompiler bug in `dynamic_menu`. It is not. An instrumented build,
with an `alert` before every `return -1` in `run_extended` and one printing
what `file_menu` received, fired **none of them** and reported

```
Please enter command line code
```

which is Paladin's own uncompiled-build prompt. `file_menu` was never
failing. Four of the ten `get_SCRIPT_COMPILED()` sites in that title gate
sound loading, so a script run has no pack open and no voice configured, and
the selector is where it sends you.

So **run mode proves the module reaches the engine and nothing about
behaviour**, and the way to exercise a recovered game is the executable:
`bgt compile --build release`, which works now (see **`--build` built nothing
at all** above -- for a long time it did not, and quietly). The lesson for diagnosing the next one is the
cheap part: an `alert` before each suspect return answers in one run what
reading the source argues about for an afternoon.

## A recovered game keeps its own licensing, and reads the same store

Worth knowing before concluding that a port behaves differently from the
original. A game's registration check is ordinary script code, so it recovers
like everything else and **still runs**: Super Egg Hunt's `match_id` and
`register_check` come back in full, the latter called from inside the menu
loop, and it `exit()`s the process when the stored id does not match.

It reads the *same* store, too. `game_data.setup("LWorks", "Super Egg Hunt",
false)` keys the settings by company and product rather than by executable
path, so a recovered build sees whatever the installed original wrote. A
registered install stays registered in the port, and an unregistered one
stays unregistered -- neither is something the recovery changes.

## The screen-reader client, which decides whose voice the game has

These are audio games, and a recovered one that calls `screen_reader_speak`
needs `nvdaControllerClient32.dll` beside its script to reach NVDA. Without
it the engine **does not fail** -- it falls back to SAPI, so the game talks,
in the wrong voice, and nothing in any report says why.

BGT ships both clients under `redist/screen_readers/`, so `bgt recover`
copies them in rather than mentioning them: `nvdaControllerClient32.dll` for
NVDA and `SAAPI32.dll` for System Access. Only when the module actually calls
one of the `screen_reader_*` APIs, which is what makes it evidence rather
than a DLL scattered into every project, and a client BGT does not have is
reported with the consequence rather than skipped.

**The ZIP had the same ordering bug as the stock library files.** Plugin DLLs
were copied *after* the archive was written and appended to `project.files`
afterwards, so they were listed in `recovery.json` and absent from
`game_project.zip` -- and the archive's own "holds n of m files" check ran
before the append, so it passed. Everything a project needs beside its script
is now copied before the ZIP.

## The other way a game needs a DLL: the script loads it itself

`elias` is a type a *plugin* registers, and `plugin_dlls` finds its DLL by
matching the file's stem against a type the module uses but does not
declare. That is good evidence and it is the wrong shape for the second
case, which leaves no trace of that kind at all.

**BGT ships a `library` type**, and it is stock, documented and ordinary.
Read out of `bgt.exe` -- the registration block is one function, so the
whole interface comes out together:

```c
RegisterObjectType      ("library", 0, asOBJ_REF)   // size 0, flags 1
RegisterObjectBehaviour ("library", FACTORY, "library @f()", ...)
RegisterObjectMethod    ("library", "bool load(const string& in)", ...)
RegisterObjectMethod    ("library", "bool unload()", ...)
RegisterObjectMethod    ("library", "dictionary@ call(const string& in, "
                         "?&in param1=null, ... ?&in param10=null)", ...)
RegisterObjectMethod    ("library", "bool get_active()", ...)
```

Three things there that the help file does not say. `call` takes **exactly
ten** optional parameters, where the documentation writes the whole tail as
`? list_of_parameters`. There is an undocumented **`active` property**. And
the signature is a `const string& in`, so a script names its DLL with an
ordinary **string literal** -- no type, nothing for `plugin_dlls` to match.

### What `library::call` does, read rather than inferred

`library_structure` -- the registered-but-undocumented type -- is one
resolved export: the decompiled `GetProcAddress` site reads the symbol name
out of a `std::string` at `+0x64`, stores the `FARPROC` at `+0xA4`, and on
failure formats `GetProcAddress failed for '%s' : Error code %d` and
**throws a C++ exception**. So a missing *export* is a runtime error
(`library exception (%s)`), not a `false` from `load`. The signature string
is parsed first, with `Signature parse error "..."` when it will not go; the
token tables beside it (`CDECL STDCALL FASTCALL PASCAL cdecl ...` and
`FAR EXPORT const volatile struct class enum WINUSERAPI WINAPI __in_opt
__in`) say it accepts a C declaration with a calling convention and skips
the Win32 and SAL decoration. I did not reverse the grammar past that, and
nothing here depends on it.

### Manamon 2 is the live case, and it would have been left behind

`sqlite3_legacy::load_library` calls `library::load("sqlite3.dll")`, and the
game ships `sqlite3.dll` beside `rpg.exe` with `Unable to locate
sqlite3.dll.` as its own error text. Recovered without it the project
compiles, runs, and loses whatever that database held -- the same shape as a
missing asset pack, one layer over, and `bgt recover` had no way to see it.

`script_loaded_dlls` brings it, on the same pair of evidence the pack search
uses, because neither half is enough alone: the **name** comes from the
module's string constants, since the call site passes a local; the
**filter** is a PE file of that name sitting beside the executable. The
module must really call `library::load` or `library::call`, or any `.dll`
mentioned anywhere would qualify -- and a system DLL is never brought, which
matters because a game folder may well hold one. On the four titles it finds
`sqlite3.dll` for Manamon 2 and nothing at all for the other three.

It is copied without being called a plugin, and a missing one is a note
rather than a problem: nothing needs it to **compile**. That is exactly why
it was invisible.

## Plugins: a type no stock engine has

Psycho Strike uses `elias`, and the installed BGT 1.3 has no such type, no
plugin directive, and no mention of either. The game's own executable has both
`elias.dll` and the registered `elias @f()`, so the build that produced it had
that plugin compiled in. **Compiled in is exactly right, and the binaries
prove it** -- see **`elias` is a binding compiled into the engine, not a
plugin** above: the type's seventeen methods are registration strings inside
the runtime, `elias.dll` is absent from the import table and loaded with
`LoadLibrary`, and the script methods are a thin binding over about twenty of
the DLL's ninety-two exports. Manamon 2's fork has it too.
`bgt recover` reports it — a DLL named after a type
the module uses but does not declare is evidence, where a list of every DLL in
the file would not be — copies the DLL into the project, and says in the entry
script that compiling needs that engine build. It deliberately does **not**
emit `#include "elias.dll"`: this engine's `#include` takes a script or a pack
file, and handed a DLL it says "Expected identifier".

## A clean compile is not the check that matters

Compiling proves the source is valid BGT and that every call resolves. It does
not prove the program does what the original did: an argument dropped to make
a call match, or a condition inverted, compiles perfectly. So `bgt libcheck`
scores this path too, against BGT's own shipped library -- source nobody here
wrote:

```bash
bgt libcheck work/game_bytecode.bin game.exe --decompiler
```

On Psycho Strike, of the 149 library functions that appear exactly once on
both sides: **140 have the source's exact call sequence in evaluation order**,
3 more are within 80%, and **148 of 149 have its exact string literals**. The
lifter, measured the same way over 155 functions, gets 153 and 155 -- it is
still the better-validated path for reading one function, and this is the path
that compiles.

That check found the duplication the compiler cannot see:
`sound_pool::play_extended_1d` called `reserve_slot()` forty-five times where
the source calls it once and keeps the result in a local. **That is fixed**
-- see the fold rules below, cases one and four -- and `play_extended_1d`,
`play_extended_2d` and `play_stationary_extended` now have the source's exact
call sequence on Crazy Party where all three differed.

**It was never only a readability problem, which is why it is worth stating
plainly.** Running a call once per read runs it once per read: `reserve_slot`
reserves a different slot each time, and Paladin's `file_menu` re-opened its
menu for every comparison it made against the result. A duplication count is
a correctness number.

Where a difference survives, read it as a lead rather than a verdict, and
re-read it after a decompiler change: Super Egg Hunt's `number_speaker.bgt`
differed on `speak_next` before the fold fixes and matches now. Shape
differences that are not defects do occur -- stock ends a loop with
`if(current.handle.playing==false) { slot=i; break; }` where the recovery
writes `if (local_4.handle.get_playing()) { continue; }` and the assignment
after it, which is the same program -- and the way to tell is to read both,
which is what the report is for.

## When a folded temporary stops being the value the bytecode computed

The fold is **load-bearing**, which is why this took three attempts and two
measured rejections. Promoting every compiler temporary to a variable takes
Super Egg Hunt from **0 residual gotos to 182** and, since AngelScript has no
`goto`, from **0 compiler errors to 187**: a loop condition promoted to a
statement before a jump stops being a loop condition. So "fold less" is not
the fix, and the diagnostic count is not the metric. The question is *when* a
fold stops being faithful, and there are four answers so far. Every one of
them produced a program that recovered with 0 errors, compiled cleanly, ran,
and did the wrong thing -- and every one surfaced in a **menu**, because a
menu is the first thing a player touches and the only part of an audio game
whose misbehaviour is unmistakable from the outside.

**One: the receiver was mutated in between.** `dynamic_menu::add_item` keeps
the length *before* resizing, and BGT ships the source to prove it:

```
int new_index = item_list.length();          // the source: length BEFORE
item_list.resize(new_index + 1);
item_list[new_index].option = filename;

item_list.resize((item_list.length() + 1));  // folded: re-read AFTER
item_list[item_list.length()].option = arg0; // ...out of bounds
```

That is an out-of-bounds write, and Super Egg Hunt's and Crazy Party's
recovered menus both died on the first item they added with `A runtime error
occurred.` (Both titles keep their own `dynamic_menu`, for real edits, so the
stock substitution does not hide it.)

"A statement ran in between" is too broad a test -- it costs 46 residual
gotos, because a value computed before a loop body and read at the latch has
statements in between and has not changed. What is required is that something
ran **that touched what the value reads**: `item_list.length()` is invalidated
by `item_list.resize(...)` and by nothing else in that function, which is
precisely the dependency the source expressed by keeping the result in a
local. A repeatable value -- a constant, a plain variable, `this` -- still
folds, so conditions stay expressions.

Two details in that test are each worth a title:

- **The receiver is the whole expression, not its first word.**
  `this.terrain.getTailleX()` has receiver `this.terrain`; taking the leading
  identifier makes it `this`, and since almost every statement in a method
  mentions `this`, the test matches everything. That promoted a reused scratch
  slot inside two nested `for` loops and cost Crazy Party **4 residual gotos
  and 4 compiler errors** -- caught only because the second title was
  measured.
- **Mentioning a receiver is not touching it.** `@local_7 = this.terrain;`
  reads `this.terrain` and cannot change it. What counts is a call *on* the
  receiver or an assignment *to* it, never its name on the right of one.

With both: Super Egg Hunt **0 gotos, +19 lines, compiles cleanly**; Crazy
Party **0 gotos, 0 errors**, and three of the four `sound_pool` bodies that
differed from BGT's shipped source now match it -- including
`play_extended_1d`, which is where the forty-five `reserve_slot()` calls
were. Only `reserve_slot` itself is left, and that one is a shape difference
rather than a defect (see the section above).

**Two: the value was computed on only one path.** The simulation walks the
bytecode linearly, so a store inside a branch and a read after the join look
like one straight line. `dynamic_menu::run_extended` sets a joystick flag
inside a branch and reads it in the arrow condition after it, and the fold
carried the constant that branch happened to store across the join:

```
if (key_pressed(KEY_UP) || key_pressed(KEY_I) || true)      // always taken
if (key_pressed(KEY_DOWN) || key_pressed(KEY_K) || false)   // dead operand
```

The game launched, spoke its menu, and **the arrow keys did nothing** -- which
is how it was reported, and is not something a compiler or a window title can
tell you. A forward conditional jump that starts before the store and lands
after it but at or before the read says the store is skipped on the other path
while the read happens either way; the value is then promoted, with its
assignment put back at the store's own position. Events are sorted by bytecode
position rather than kept in append order, which is what lets a promotion
insert its assignment where the value was computed instead of where it is
read.

**Two and a half: the rule is about the PATH, and only about the path.**
This test read `value.kind == "const"` before consulting the path, on the
argument that both bugs it caught were constants. A parameter copy proved the
line was in the wrong place. `dynamic_menu::run_extended` opens with

```
bool initial = auto_speak_first;        // the parameter, copied
```

and clears it at **five** sites once the first item has been announced. A
parameter is *repeatable* -- reading it again costs nothing and yields the
same thing -- so the fold took it before the path test could run: every read
became `arg3`, which never changes, and all five `initial = false;` stores
went with it. The block then re-armed `speak_item` on every iteration, so
arrowing to an item and stopping made the menu say its name again, and again,
forever. It is the same defect as `|| true` and `if (false)`, and what decides
it is whether the slot is written again on another path.

So the test is the path, not the kind. It said `const`, then *repeatable*,
and each narrowing left real stores on the floor -- the third one being
`sound_pool`'s clamp, `int true_y = listener_y; if (listener_y <
delta_backward) true_y = delta_backward;`, a **computed** store that folded
away so the call received `delta_forward` and positioned 2D sound from the
wrong y.

**That boundary was measured, and the measurement went stale.** Promoting
computed values was rejected for taking Paladin from 0 compiler errors to 16,
with holds like `__nvgt_hold_7_116 = __nvgt_out_7_215;` as the evidence --
and those names say what really caused it: a *fresh local per promotion*,
which was separately fixed to one name per slot (see below). Re-measured
after that fix, promoting any declarable conditional bind holds all three
titles at 0 residual gotos with a verified split, leaves every `bgt libcheck`
score untouched, and takes Paladin's empty-bodied `if`s -- the signature this
class of bug leaves behind -- from 33 to 9 and Super Egg Hunt's from 5 to 4.
A value with no declarable type still folds, because a slot that cannot be
declared cannot be a variable.

It is worth knowing what else came back with it, because it was never only a
menu bug. `sound_pool`'s distance code is

```
int true_x = listener_x;                        // the parameter, copied
if (listener_x < delta_left) true_x = delta_left;
else if (listener_x > delta_right) true_x = delta_right;
```

-- a clamp, written exactly this way. Folded, `true_x` was `listener_x`
everywhere and both assignments vanished, so every recovered title positioned
its sounds from the **unclamped** coordinate. Nothing reports that: it
compiles, it runs, and the audio is simply in the wrong place.

**Three: the value was computed before a loop and read inside it.** The same
problem through a back edge, and the one that mattered most. `dynamic_menu`
declares `bool speak_item = false;` before its loop, and every arrow branch
inside the loop sets it true; the read at the top of the loop runs once per
iteration while the initialisation ran once. Folded, the loop read

```
if (false) {            // ...speak the current item
```

so **the menu never spoke anything**. Arrowing worked perfectly --
`menu_position` moved, wrapped and bounded exactly as the source says -- and
for an audio game that is indistinguishable from the arrow keys being dead,
which is how it was reported, twice. A read inside `[loop head, back edge]`
whose value was bound before the head is promoted.

Nothing about this is visible to the compiler, to a window title, or even to
`bgt libcheck`'s call-sequence score: `if (false) { speak(...) }` *contains*
the call, in the right order, with the right literals. It took someone
pressing an arrow key.

**Four: the value is read three or more times, and it is a call.** The duplication
`bgt libcheck` had been measuring all along, and it is not a readability
problem. `file_menu` keeps one menu result and compares it three ways:

```
int result = menu.run_extended("Select an Option.", true, 1, true);
if (result == -1) return "";
if (result == 0 || result == -200) return "cancel";
return menu.get_item_name(result);
```

Folded into all four reads, Paladin's recovered `file_menu` **ran its menu
four times**. Every comparison re-opened it, so a selection was consumed by a
comparison and the menu came back — which is what "it keeps putting me in the
tts selection menu" looks like from the player's side.

This one cannot be fixed at the read: by the time a second read proves the
value is used twice, the first has already folded the call inline. So it takes
a second simulation that knows in advance — and `_body` already re-simulates a
function while each pass discovers more, for lvalues, so the fold counts ride
along: pass one records `(slot, bind position) -> folds`, and the next
promotes every pair folded more than once. Counting only *new* pairs each
round is what makes it terminate, since a promoted bind is no longer folded
and would otherwise be rediscovered forever.

**The threshold is three, and it is measured rather than principled.** At two
it cost Crazy Party **36 residual gotos and 36 compiler errors** against 0 --
the same structuring damage every over-broad promotion in this section causes.
The duplications worth catching are far worse than doubled anyway:
`file_menu` reads one result 4 times and `play_extended_1d` read one
`reserve_slot()` 45 times. A two-read duplication is left folded and
`bgt libcheck` still counts it.

### A base class's method, called through `this`, recurses forever

The worst one yet, because it is a *crash* and the project reports nothing:
0 residual gotos, a verified split, `compiled cleanly`, an executable that
starts -- and then

```
BGT Runtime Error: A runtime error occurred.
In function: void person::reset()
Description: Stack overflow
```

with 10,000 identical frames of `person::reset` under it. The stack's base
names the path in: `main` -> `handle_file_menu` -> `init_game` ->
`create_passengers` -> `create_room_passengers` -> `person()`, so it died
building the first passenger of a new game.

Paladin's `class person : interact` opens its override the way source has to:

```
void reset()
{
    interact::reset();          // the base's, then this class's own fields
    type = 3;
    sound_file = "person";
}
```

and that came out as `this.reset();`. A method's `Function.name` in the IR is
the **bare** one, so splitting it on `::` yields no class and the owner has to
come from `fr.object_type` instead -- read off the name, this never found a
base at all. With the owner in hand, `_calls_a_base_method` qualifies the call
when that owner is a strict ancestor of the class the body belongs to and that
class declares the name as well. Where it does not, the unqualified call
already reaches the base's one and saying so adds nothing.

**What makes it safe is the chain that is walked, not the opcode.** Only
`derived_from` is followed, and an interface's methods are reached through
`interfaces`, so an interface dispatch can never match and can never be
pinned to a base by mistake. Gating on the opcode as well was tried and
rejected on measurement: it kept `person::reset` qualified while letting
`clock::reset` fall back to `this.reset()` -- still unbounded recursion --
even though both sites disassemble to a plain `CALL` of `interact::reset`.
Why the two differed was not established, and the honest conclusion is the
narrow one: the opcode is the wrong field to read here, and the ancestor walk
does not need it. `base::method()` was put to BGT 1.3 before being emitted,
and it compiles.

Paladin had **62** of these, in one base class's descendants: `reset`, `init`,
`act`, `make_noise`, `pause`, `resume`, `is_inside`. Only the same-name ones
recurse; the others quietly ran the derived override where the source asked
for the base, which compiles and is simply a different program. Crazy Party,
with 530 derived classes, had **167**.

**The sweep that counts them has to compare arity, not just the name.** A
method forwarding to its own overload -- `focus()` calling
`focus(a, b, c)` -- is ordinary delegation, and Crazy Party has 18 of those;
a name-only sweep reports 184 self-recursive calls there and means nothing by
it. What cannot terminate is the same name with the same number of arguments.

| title | same-arity self-calls | after |
|---|---|---|
| Paladin | 62 | **2** |
| Crazy Party | 167 | **15** |
| Super Egg Hunt | 0 | 0 -- it declares no base class |

Fixing it also took Crazy Party's last two compiler warnings
(`The operand is implicitly converted to handle in order to compare them`)
away, so all three titles now report `compiled cleanly`.

**And verifying that found the driver claiming a game had started when none
had.** Compiling emits its own `Compilation Result` window on success, which
carries no diagnostics and no "error" in its name -- and the rule for "the
script itself drew a window" was *any* window that is not an error report. So
`bgt compile` on Crazy Party answered `compiled cleanly, and ran: it opened a
window of its own titled 'Compilation Result'`. Nothing ran; the engine had
just said it wrote the executable. Only run mode may draw that conclusion
now, and only from the driver's own `$ran`. Claiming a game started when it
did not is the one thing this driver exists to get right, and it is exactly
the shape of everything else in this section: a confident report of something
that never happened.

Every survivor reads as real recursion. Paladin's two are `interact::act()`
calling itself, guarded, after `add_mode(1)` has advanced the state, in a
class with no base to be confused with. Crazy Party's are flood fills and
accumulators that change an argument (`brule(arg0 - 1, arg1)`,
`att(5, arg1)`). One is worth another look and is recorded rather than
claimed fixed: `Equipe::opCmp(x)` returns `this.opCmp(x)` unchanged.

### A declaration list with no declaration order

The rule above decides whether a slot is *foldable*. A separate one decides
whether it is a **variable at all**, and it reads something BGT does not have.

The newer engine writes one declaration per local in the order the builder
declared them, and that order is information: the source's own locals come
first, and where the offset steps *backwards* the compiler's scratch begins.
`FuncDecompiler` uses exactly that -- the prefix before the first backward
step is forced to stay an lvalue.

BGT records no scalar local at all (see **What the module does not record**),
so `bgt_asir` synthesises the list: object slots from `objVariableTypes` in
record order, then every scalar appended the first time a typed opcode happens
to mention it. That is **bytecode order, with no scope in it** -- and read as
declaration order it finds a backward step wherever the bytecode later touches
a lower slot. `use_screen_reader` is four synthesised entries at offsets
1, 3, 3, 2, and the 2 ends the prefix, so slots 1 and 3 were declared
variables in a function whose source has no locals whatsoever.

What that costs is a whole condition. `screen_reader && voice.reader > -2 &&
voice.sapi_only == false` compiles to two short-circuit merges over three
scratch slots, and the compiler **reuses** them -- slot 3 carries
`screen_reader` and then `sapi_only`, slot 1 carries `reader > -2` and then a
literal. Forced to be variables, each arm's computation is emitted as an
*unconditional* statement, so every term is overwritten before the `if` reads
it:

```
local_3 = (screen_reader ? 1 : 0);          // then clobbered by sapi_only
local_1 = ((voice.reader > -2) ? 1 : 0);    // then clobbered by a literal
...
if (((local_3 != 0) && (local_1 != 0)) && (local_1 != 0))   // == !sapi_only
```

It returned **true where the source returns false**, so every `speak` went to
`screen_reader_speak_interrupt(-1, ...)`, which fails. `run_extended` returns
-1 when it cannot speak its intro, `file_menu` turns that into `""`, and
Paladin's main loop reads that as "no TTS" and reopens the voice selector.
Selecting a voice fixed nothing, because the selector's own
`speak_sapi_only()` is what made speech work while it was open -- so it asked
again, forever, which is how it was reported.

`f.synthetic_variables` marks the list, so nothing mistakes it for the real
thing. The fix is **not** to drop the order rule, and measuring says so
loudly: without it Crazy Party went from 0 residual gotos to **44**, which is
44 compiler errors, because the rule is load-bearing for the mutable scalars
it was written for. Instead `_short_circuit_slots()` finds the slots a merge
carries its value through, from the bytecode alone, and those are excluded:

* `dest`, which the merge's value arrives in on both paths;
* every slot the **arm** writes, which holds part of the right-hand operand;
* every **object** slot the arm constructs or destroys, which no opcode in
  that first list mentions at all -- see below.

**The slot the jump tested is deliberately not one of them**, and that is the
whole difference between this working and doing harm. The left-hand operand is
usually an ordinary local -- `int d = get_total_distance(a, b); if (d > limit
&& ...)` -- so excluding it unforces a real variable and the value folds into
each of its reads instead. Taking it cost Super Egg Hunt three duplicated
calls: `sound_pool` ran `get_total_distance` twice, a menu ran its item
callback twice, and the "erase all data" confirmation asked **twice** while
the branch choosing the other wording of the prompt vanished.

With both, all three titles hold at 0 residual gotos and a verified split, and
`bgt libcheck --decompiler` scores identically before and after on every one
of them -- 39/47 call sequences on Paladin, 43/47 on Super Egg Hunt, 129/153
on Crazy Party -- which is the check that says no call was duplicated.

#### An object slot is written by a behaviour, not by an opcode

"Every slot the arm writes" means the slots named by an opcode that assigns
to them, and a string is not one of those. It is filled by pushing its
address and calling the constructor -- `PSF n` then `CALLSYS $beh0` -- and
emptied by `$beh2`, so nothing that names slot `n` appears in the arm. A slot
constructed *or* destroyed inside an arm belongs to that arm, by scope: one
declared outside is built and torn down outside.

Paladin's `item_type_to_function` is what that costs:

```
if (arg0 == "healing potion" || arg0 == "medical miracle"
    || arg0 == "levelup erb" || arg0 == "perfect healing") return 0;
```

over one reused string slot. Forced to be a variable, the four assignments
hoisted out ahead of the `if` and every comparison read the last of them --

```
local_2 = "healing potion";
local_2 = "medical miracle";
local_2 = "levelup erb";
local_2 = "perfect healing";
if ((((arg0 == local_2) || (arg0 == local_2)) || ...
```

-- so three of the four healing items were classified as something else. It
compiles, it runs, and the only way to notice is to use a potion.

**And a behaviour has two spellings**, which is the delegate factory's
`%delegate_factory` / `$dlgte` all over again. The disassembler prints
`string::_beh_0_`, which is what a reader sees and reaches for; the name the
module stores and the IR carries is `$beh0`. Matching only the pretty one
matched nothing, silently, and the output did not change by a single line.

With it, Paladin recovers 83 lines shorter and `get_active_reader` -- whose
four `return`s used to collapse into one `return WINDOW_EYES;` -- comes back
as the accumulator the source wrote, from the same pass. What is left of this
class is one case and it is the expensive one: a **computed** value bound on
one path and read past the join, which `sound_pool`'s `true_y` clamp is
(`if (listener_y < delta_backward) true_y = delta_backward;` folds away and
the call receives `delta_forward` instead). Promoting computed values the
same way took Paladin from 0 compiler errors to 16, so it stays open rather
than guessed at, and the signature to grep for is an `if` with two empty arms.

### Reading the compiler, not only the reader

This document's first rule is to read `asCReader` rather than infer the
format. The same rule applies one level up and had never been used: the
*shapes* the structurer matches are emitted by `asCCompiler`, which is in
the same binary. `CompileSwitchStatement` is at `FUN_00426160`, found
through `Switch expressions must be integral numbers`.

**The first thing it said killed a hypothesis, cheaply.** The compiler emits
a range guard as `SetV4 tmp,K ; CMPi var,tmp` and the normalisation as
`SetV4 tmp,min ; SUBi var,tmp` -- never the immediate forms. `_begin_switch`
accepts only `CMPIi`/`SUBIi`, so it looked as though an unfused table would
slip past every matcher and explain the bodies given up on. It does not:
the peephole pass fuses every one. All **82** computed jumps in the four
titles carry the fused form. Worth ten minutes to find out, and worth
writing down so nobody pays for it twice.

**The second thing it said is a constant worth having.** After sorting the
case values the compiler starts a new table whenever

    values[n-1] + 5 < values[n]

so a gap of up to five is absorbed into the current table, filled with
entries pointing at the default, and a gap of six or more splits. That makes
a prediction the bytecode can refuse: **no table can hold a run of more than
four default entries.** Measured across all 82 tables -- Paladin 3, Psycho
Strike 4, Manamon 2 4, Super Egg Hunt 3. Reached twice, never exceeded,
which is the same saturating-maximum argument that settled the operand
tables.

#### The entry the gaps share is not always the default

`_dense_table` identified the default by counting: the most common target in
the table, on the argument that the gaps all carry the default label. The
constant above says how far that argument reaches, and it is not far enough.
Several case labels stacked on one body,

```
case 1: case 2: case 3: speak("..."); break;
```

put that arm in the table as many times, and nothing stops a real case
outnumbering the gaps.

Where a switch is a *single* table there is no next range to be sent to, so
every guard jumps to the same place -- and that place is the default, said
outright rather than counted. Checked against every single-table switch in
the corpus, the two answers agree 25 times and **disagree twice**, both in
Manamon 2. `ms_davidson`'s table is `[38, 45, 45, 52, 59, 66, 144]` with the
default at `0x95`, which is not in the table at all: counted, the default
became the arm that `case 2` and `case 3` share, so both labels vanished
from the output and a `break` landed in the wrong arm.
`get_madam_boveels_table_text_seulee` is the same shape. Both are dialogue
functions, so the symptom is an NPC answering the wrong line -- it compiles,
it runs, and nothing reports it.

Counting still answers where the guards disagree, which is a link in a chain:
its own high bound sends larger values on to the next range, so the guards
differ and the gaps are the only evidence left.

`get_madam_boveels_table_text_seulee` lost a whole arm the same way --
`case 20: case 22:` and the line of dialogue they return.

**Which switches this can touch is exhaustive, not sampled.** The new
branch fires only when every guard agrees; there, a table with no repeated
entry already took `guards[0]`, which *is* that agreed target, so nothing
moves. What moves is a table with a repeated entry whose count disagrees
with the guards -- and every single-table switch in the corpus was
enumerated for exactly that: 2 in Manamon 2, 0 in the other three.

Paladin, Psycho Strike and Super Egg Hunt render **byte-identical** before
and after, which is what a correctly scoped structurer change looks like.

#### The three tables nothing claims

Manamon 2's three given-up bodies have been "claimed by neither switch
matcher" for as long as the message has existed, which is a symptom and not
a cause. `_dense_table` reads all three perfectly; it is
`_dense_switch_pattern`'s checks *after* it that decline, and they decline
for **three different reasons**. Written down so the next attempt starts
from a diagnosis:

- **`number_key_pressed`** -- the arms leave the switch to two places.
  Cases 0..8 end `JMP 0x12C` and case 9 ends `JMP 0x12F`, and the check
  wants one shared join. 0x12C is the function's tail and 0x12F is three
  instructions into it, so both *are* leaving; one arm jumps deeper in. A
  switch that is the last statement of a function exits straight into the
  epilogue, and the epilogue has more than one entry point.
- **`type_effectiveness`** -- the chain's tables and arms interleave.
  Twenty-two tables, laid out `table, arms, table, arms`, so merging the
  chain grows `cursor` to 0x508 while the first merged table's arms sit at
  0xAE. The guard `entries[0] <= instrs[cursor - 1].pos`, which exists to
  catch an entry jumping *backwards into the table*, then fires on a
  perfectly ordinary layout. The check assumes tables come before arms.
- **`artisoul_tutor`** -- the same guard, failing by one: the span ends at
  exactly 0x263 and the first arm begins at exactly 0x263, and the
  comparison is `<=`.

Each wants a different relaxation and each relaxation is the kind this
file keeps recording as expensive -- "generalising the existing do-while
handler took Crazy Party from 17 gotos to 55". So they stay counted.
What is new is that they are three problems rather than one, and named.

### Typing the promoted local took three tries, and the declaration wins

Promotion gives a slot a name, and then the name has to have a type. Measured,
on Paladin:

- **The value's type, overriding the slot's: 377 errors.** A scratch slot
  carries a bool here and an int there, so declaring it from one value's type
  makes every other use of it an error. `Can't implicitly convert from 'int'
  to 'bool'`, hundreds of times.
- **A fresh local per promotion: the flag comes apart.** Egg Hunt's joystick
  edge flag became `__nvgt_hold_20_403 = 0` with the up arm reading it and
  *writing* `__nvgt_hold_20_1152 = 1`, which only the down arm read — so
  pressing up disarmed down. **One slot carries one source variable, so it
  gets one name.**
- **The slot's own type, value's as fallback: right.** Plus two coercions,
  because a promoted name outlives the atom that described it:
  - dropping a comparison against a bool literal leaves the operand *as* the
    condition, so a numeric one needs `(x != 0)`. `x == false` became `!x` on
    an `int`, which is "Illegal operation on this datatype" — and the same
    operand reached through the value register converted correctly, which is
    what made the gap findable.
  - the bool→numeric wrap must not fire on a bare name that is *declared*
    numeric: `local_24 = (local_3 ? 1 : 0);` with `int local_3` is "Expression
    must be of boolean type". The atom claimed bool because that was the last
    value the slot held. **A declaration outranks an atom that outlived its
    value.**

### And a condition dropped on the floor

Fixing the fold left the right shape and the wrong condition:
`... || (local_20 == 0)`, preceded by `if (stick.get_y() >= -100) { } else { }`
-- an `if` with two empty arms, which is a condition that has lost its value.
The `&&` inside the `||` chain was declining to merge, so half the expression
was emitted as a statement that does nothing and the other half stayed in the
condition. **An `if` whose both arms are empty is the signature of this class
of bug**, and worth grepping for.

It declined on a **type**. `_begin_bool_merge` required the slot the merge
stores into to be declared `bool`, and this one is a compiler scratch slot
that `slot_types` had typed from widths -- `SetV4` is as true of an int as of
a bool. The bytecode says it outright instead: the stored value is loaded and
tested with `JLowZ`, and `JLow*` follows no compare at all, it tests the low
byte of the value register, which is the bool protocol and nothing else.
Taking that as evidence recovers

```
if (key_pressed(KEY_UP) || key_pressed(KEY_I) || (stick.get_y() < -100 && local_20 == 0))
```

which is the menu the game shipped. **Read the protocol, not the inferred
type**: on a generated slot the inference is the weaker witness, and it was
the one being trusted.

The general lesson is the one this file keeps relearning, in both directions.
**A clean compile measured nothing here** -- all three bugs compiled -- and
neither did the diagnostic count on the two rejected fixes. Running the result
found the bugs; a *different* metric, the goto count, rejected the cures.

# Repacking

`bgt_repack.py` runs the chain backwards: compress, wrap in the container header,
encrypt, and reattach as an overlay with a freshly computed trailer.

```bash
python tools/bgt_repack.py game.exe modified_bytecode.bin -o patched.exe
```

The PE stub is copied verbatim, so only the overlay changes. The trailer's offset
field is **recomputed** from the stub length — never copy the old one.

**Correctness is checked by round-trip, not by inspection.** The CLI repacks, unpacks
its own output, and requires the module back byte for byte before writing anything;
`--no-verify` skips that and is not recommended. This has been exercised on a real
509 KB module, including patching a string literal in place and confirming it
survives the rebuild.

## Writing a module back out

`as_write.py` rebuilds a module from a **field trace** the reader emits -- an
ordered record of every primitive it consumed. Duplicating the format in a
separate writer would mean two models to keep in step; replaying the reader's own
trace means there is only one.

The correctness argument is a byte-for-byte round-trip, checked against real
modules rather than asserted, and it is now a stage in `bgt validate`:

| title | module | trace fields | round-trip |
|---|---|---|---|
| Psycho Strike | 509,207 B | 236,348 | byte-exact |
| Paladin of the Sky | 631,015 B | 227,236 | byte-exact |
| Manamon 2 | 4,736,046 B | 2,247,023 | byte-exact |

**This lifts the equal-length restriction.** The format stores no absolute
offsets anywhere -- everything is counted, length-prefixed or index-referenced --
and saved-string back-references are by **index**, so entry N stays entry N and
only the edited record's own encoded length changes:

```bash
bgt asm work/game_bytecode.bin game.exe --replace sounds.dat=my_custom.dat -o mod.bin
bgt repack game.exe mod.bin -o patched.exe
```

Verified end to end: `sounds.dat` → `my_custom_sounds.dat` grows the module by 10
bytes, the edited module still parses to EOF with 68/68 class blocks, the
repacked executable round-trips, and `bgt validate` passes it on every stage.

Two details that make this work rather than merely appear to:

- **The encoder must stop short of the next width's marker.** Each form of the
  encoded integer gives up one more bit to the marker above it, so reading
  `10xxxxxx` as six free bits lets a lead byte reach `0x7F` -- which decodes as
  the eight-byte form, returning an enormous value and leaving the cursor inside
  the next record. The decoder only has to mask; the encoder has to stop.
- **The instruction count is recomputed, not copied.** It counts instructions,
  not dwords, and recomputing it from the instructions actually present is what
  lets one be inserted or removed.

What this does **not** do is check that an edit makes sense. Renaming a string is
safe; changing an instruction to one with a different stack effect, or pointing a
`CALL` at an index outside `usedFunctions`, produces a module that loads and then
misbehaves. The round-trip proves the encoding, not the edit.

Two things to expect:

- **Output is not byte-identical to the original.** The LZ77 encoder here is a plain
  greedy matcher and compresses slightly worse than BGT's, so the file grows by a
  percent or two. Nothing downstream cares — every length is declared in the
  container — but do not diff against the original and conclude something broke.
- **Editing a module in place is safest at equal length.** Changing a literal to a
  different length shifts every following offset, and the operand tables are not yet
  rewritten by any tool here.

For asset packs, `bgt_pack.build()` serialises entries and `bgt_pack.replace()`
swaps named ones while copying the rest verbatim — so a single sound can be replaced
without re-encoding the other thousand. Replacing an encrypted entry needs the key,
which is the unsolved part below.

# Asset packs (SFPv1)

`pack_file` / `set_sound_storage`. Format read out of `pack::create` in a BGT binary.

```c
struct pack_header {  char magic[4];  // "SFPv"
                      u32 version;    // 1
                      u32 entry_count;
                      u32 reserved; };

struct pack_entry  {  char magic[4];  // "SFPv" again
                      u32 name_len; u32 flags; u32 data_size;
                      char name[name_len];   // no NUL
                      u8   data[data_size]; };
```

Entry payloads are usually encrypted, marked `SWCR`:

```c
struct swcr {  char magic[4];        // "SWCR"
               u32 plain_size;       // written three times
               u32 plain_size2;
               u32 plain_size3;
               u8  tag[16];
               u8  ciphertext[]; };  // AES-256-ECB
```

`tag` is **not an IV** — that reading is wrong and costs time. It is a
key-verification tag:

```
tag == AES-256-ECB(key, 16 zero bytes)
```

which means a candidate key is checked with one AES block, without touching
ciphertext and without needing to recognise the plaintext. `bgt_pack.Entry.decrypt()`
returns `None` rather than garbage when the key does not verify.

Whether a game uses one global key or a per-file key is visible immediately:
`bgt_pack.tag_index()` returns one entry per distinct key.

---

# Sound-pack decryption - SOLVED

`bgt_kdf.py` implements BGT's password -> key derivation, transcribed instruction by
instruction from the decompiled runtime.

```python
from bgtdecomp import bgt_kdf, bgt_pack
key = bgt_kdf.aes_key(password)          # SHA256(KDF(password))
_, entries = bgt_pack.parse("sounds.dat")
for e in bgt_pack.key_matches(entries, key):
    open(e.name, "wb").write(e.decrypt(key))
```

Verified end to end: on one shipped title it recovers the pack key, which opens
**974 / 974** encrypted entries, every one decrypting to valid Ogg Vorbis. It also
independently reproduces a key captured at runtime with Frida from a second title.

## The derivation

```
seed  = first byte of the password with the high bit set, else '#'
seed  = (seed - 4) * seed                      signed char arithmetic
state = 16 bits: high = seed, low = seed - 1

fill(98 bytes):  c = low byte of state (signed)
                 if c == 0: c = -0x12
                 c = (int)c / (seedInt + c*2 + 8)     C division, truncates to zero
                 if c == 0: c = highByte(state) + 'c'
                 state = (state & 0xff00) | (c & 0xff)

A1 = fill();  A2 = fill()                      ONE generator run twice, state carries
digest = SHA512(A1 || password || A2)          the stock SHA-512 IV
for i in 0..63: if digest[i] == 0:             scrub NULs -> result is a C string
                    c = (-11 * (i+1)) & 0xff
                    digest[i] = c or 0x83
AES key = SHA256(digest)
```

Four details that each silently produce a plausible-but-wrong 64 bytes:

- `char` is **signed**, and the divide is **C integer division** (truncating toward
  zero, not Python's floor).
- The two fill loops read differently in the decompiler - `(c + 4) * 2` versus
  `c * 2 + 8` - but those are the same expression. It is one generator run twice,
  with state carrying across. In practice the generator reaches a **fixed point**
  almost immediately, so the two salts come out identical for 127 of the 129
  reachable seeds (for the default `'#'` seed both are 98 bytes of `0xa0`). Do not
  "fix" the second run into producing different bytes.
- The password goes **between** the two salts, not before or after both.
- The NUL scrub is not cosmetic: the result is consumed as a C string.

The salts depend only on the seed byte, so `bgt_kdf` caches them per seed. That takes
a bulk search from ~8k to ~120k candidates per second.

## Finding the password

The password is whatever the script passed to `set_sound_decryption_key()`, and it is
often **computed rather than stored**. In the title above it was a base64 literal put
through a script function that iterated SHA-512 218 times, reversing the digest at one
point, and returned the iteration whose 64 bytes held the most NUL bytes. Read that
function out of the recovered bytecode rather than guessing - the raw disassembly is
clearer than the lifted output here, because the selection loop lifts poorly.

Note `string_hash(data, algorithm=2, binary)` is **SHA-512**, verified against
the engine along with `string_reverse`, `string_base64_encode` and
`string_mid` -- see **What the documentation does not say, the engine will**.

Titles differ in whether they use one global key or a key per file - `tag_index()`
shows which immediately, and that decides whether one password is enough.

**The common shape is one step, not a loop, and `bgt crack` does it now.**
Super Egg Hunt's is

```
set_sound_decryption_key(string_decrypt(h_key, "af-dc7=rqp+"), true);
```

- not a literal, so a harvest over literals cannot find it, and not computed
far enough to need reading either: both halves are in the module. The
`encrypted` harvester composes them (see **Extracting means decrypting**) and
`bgt recover --extract-data` runs it without being asked. Where that fails,
the recovered **source** is now the place to read the caller - `grep -rn
set_sound_decryption_key` over the project found this one in seconds, where
the disassembly would have taken an afternoon. Recovering first and cracking
second is the better order.

## If you cannot find the password

Capture the key at runtime instead: hook the AES setup and read the 32-byte key as it
is installed. `bgt_pack.key_matches(entries, key)` then confirms a candidate against
the entry tags in one AES block, and `Entry.decrypt(key)` returns the plaintext or
`None`.

# What is still open

Everything below is known and characterised, not merely suspected. Nothing here
blocks reading or rewriting a module.

**Stack balance is complete on the four titles** -- 14,300 / 14,300 bodies --
so it no longer points at anything. The open work was readability, and
`as_lift.fold_temporaries` now does it: it folds a compiler-materialised
temporary back into its single use. Two folds, each with its own safety
argument:

- **A pure value** (a string or numeric literal, or a `string(param)` copy)
  folds into its one by-value use anywhere in the basic block. `v5 = string("");
  v6 = string("&"); v7 = string(a0); v8 = string_replace(v7, v6, v5, v1)` reads
  `string_replace(string(a0), "&", "", v1)`, and `string("x")` collapses to
  `"x"`. A pure value has no side effect, so moving it reorders nothing.
- **A whole-value copy** folds a value-register or variable copy into the
  assignment above it: `ret = f(); v1 = ret` becomes `v1 = f()`, and
  `ret = f(); return ret` becomes `return f()`. This one may move a *call*, so
  it fires only when the use consumes the value whole (`L = var;` or
  `return var;`) and stands immediately after the definition -- no other
  subexpression is evaluated in between, so again nothing reorders.

Both are confined to a basic block and blocked by any reassignment of the
temporary or of what its right-hand side reads; a string literal is masked when
scanning for uses so a name inside it is never taken for one. Because only these
two safe shapes move, the fold is **invisible to `bgt libcheck`**: per function,
the call sequences (153 / 155 on Psycho Strike) and literal multisets (155 /
155) are identical with folding on or off. It removes **18-25% of body lines**
(strike 18.7, paladin 25.4, sbyw 24.3, manamon2 23.1), and all 14,300 bodies
fold without error.

The `!v1 != !v2` bool-test pattern an earlier note listed as remaining work does
not actually occur in any title's lifted output -- the two-part `CMP`-plus-jump
handling already renders those as the comparison they are. `bgt libcheck` is the
check to run for any further readability change: one that alters a call sequence
or a literal is wrong.

**Residual gotos: Crazy Party went from 17 to 0, and every one was a loop
whose body folded into its condition.** They had been the dominant error
source — 17 of that title's 19 compiler errors — and AngelScript has no
`goto`, so each line was an error rather than a blemish.

The shape is a backward branch whose target resolves to **the branch's own
event index**: no *event* lies between the target and the branch, because the
whole body folded into the condition expression. Source like

```
do { y = random(0, h - 1); } while (absolute(centre - y) < 3);
```

arrives as one expression that does the work and one branch that repeats it.
An empty-bodied `while (cond) { }` says exactly that, since the condition is
re-evaluated per iteration either way — and unlike a `goto` it compiles.
Almost all fifteen were a minigame's `placeZone` picking a spot far enough
from something; `DescenteMine::choisisDirection` is the same thing as
`do { v = random(-1, 1); } while (v == 0);`.

**Two wrong attempts came first, and the second is the lesson.** Generalising
the existing do-while handler to "the first backward branch anywhere in the
slice" took Crazy Party from 17 gotos to **55**: claiming the first back edge
claims an *inner* loop before the outer one is recognised, which breaks the
real enclosing loop and turns its `continue`s and `break`s into gotos. A
`loop.is_continue` guard cannot save that, because at a function's top level
there is no enclosing loop context yet. It was reverted. The point is not
that the idea was bad but that **neither attempt matched the actual shape**,
and the only reason that was visible is that each one was measured.

**Measure a structurer change per attempt, and make it cheap enough to.**
Decompiling Crazy Party's 4,601 bodies takes minutes; the sixteen that
contained gotos take about twenty seconds. That difference is what turned
this from guessing into looking, and it is worth rebuilding for the next
shape. Cross-check the titles that are already clean by **diffing their
rendered output**, not just their counts: this fix leaves Super Egg Hunt,
Paladin and Psycho Strike byte-identical, which is what a correctly scoped
structurer change looks like.

What is left is irreducible flow, switch tails and multi-entry loops in other
titles — Manamon 2 still reports 4 — which stay labelled rather than forced
into a shape they do not have.

**No semantic checking on edits.** `bgt asm` proves the *encoding* round-trips,
not that your edit makes sense. Renaming a literal is safe; changing an
instruction's stack effect or pointing a `CALL` outside `usedFunctions` yields a
module that loads and then misbehaves.

**Crazy Party was the sixth title, and the first that did not parse. It was
not a new format.** It is the biggest by a wide margin -- a 9.3 MB module,
`tagged` dialect, 550 classes, 4,486 bodies -- and two *guesses in this
reader* were the entire obstacle. Both are the same mistake in different
clothes: a round number, and one spelling of a name.

- **A sanity guard rejecting real data.** The instruction count was checked
  against `1 << 20`. Crazy Party generates part of its own source, and the
  generated `ajouteLangue` declares **1,074,460** instructions, which walk to
  exactly that count and end on `RET`. The bound is now the bytes remaining,
  since every instruction costs at least its opcode byte. That is exact where
  the constant was a guess, and the constant was the only thing between this
  title and a full parse.
- **The delegate factory has two names.** `usedFunctions[334]` is
  `%delegate_factory`; the reader knew only `$dlgte`. That record is the name
  alone, and nothing in the stream says so, so reading on takes the next
  field as a parameter count — which surfaced 200 entries later as an
  "inOutFlag count 660 > 28 params". Both spellings are known now.

With those two, **every stage passes, byte-exact rewrite included**, and the
module recovers to 190,277 lines across 559 files with 0 unmodelled opcodes
and 0 bodies that failed.

Recovery went from **170 compiler errors to 2, and both are the same single
line** -- the engine funcdef described below. It found five latent decompiler
bugs on the way, none of which any earlier title happened to need:

- **A delegate is not a call to the factory, and naming it takes two
  sources.** The handling existed and was right as far as it went — bind the
  object and method, take the funcdef type from the following `STOREOBJ` —
  but it matched `$dlgte` only, so 43 sites emitted
  `fadeOut(arg0, %delegate_factory(), arg1)`. Matching the other spelling was
  not enough: where the delegate is passed **straight into a call** there is
  no `STOREOBJ`, so no slot to take the type from, and the bare method is
  rejected just as firmly ("Can't pass class method as arg directly"). The
  bound method's own signature names it instead — `Jeu::att(int, bool)`
  against the module's one matching `void CbFade(int, bool)` — and an
  ambiguous match is left unwrapped on purpose, because that fails visibly
  while the wrong funcdef would compile and bind the wrong callback. The
  source form `CbFade(this.att)` was put to BGT 1.3 rather than assumed.
- **`do while` had a second emit site** that never went through `_condition`,
  which is why fixing the first one left `} while (local_4 - local_1) < 1;`
  behind. Two places answering one question is the recurring shape of
  everything in this list.
- **`_condition` asked the wrong question.** It tested
  `startswith("(") and endswith(")")`, which is true of `(0 + 2) < (x)` —
  a string enclosing nothing — so it added no parentheses and emitted
  `while (0 + 2) < (x) {`. 110 errors, in `while` and `do while` alike. The
  file already had `_encloses` for exactly this; the wrapper was not using it.
- **A global function a method shadows needs its scope said out loud.**
  `Case::lanceMenu` calls the *global* 8-parameter `lanceMenu`; unqualified,
  the class's own 6-parameter method shadows it and the compiler reports a
  6-parameter candidate called with 8 arguments, which reads like an arity
  bug in the lifter and is a scoping one. `::lanceMenu(...)` is what source
  would write, and the compiler accepts it. The change alters no output at
  all on the other titles, which is how a fix of this shape should look.

**Crazy Party generates part of its own source**, which is worth knowing
before reading its code and is the one real exception to the note above about
file names. `genereHelp` and `genereAjouteLangue` emit `.bgt` text at runtime --
the module carries literals like `// ce code est généré automatiquement
par la fonction genereAjouteLangue`, `void ajouteLangue() {` and the file
names `help.bgt` and `ajouteLangue.bgt`. Those are real names of the game's
own source files, but they are a *generator's output*, not a record of the
build, so they still do not give the compiler's file list. They do mean a
string search for `.bgt` in this title finds source rather than a sound —
and they explain why one function is a million instructions long.

**One site needs a name the module does not carry, and both sources have it.**
`pathfinder::set_callback_function` takes an *engine* funcdef, and
`objVariableTypes` records every funcdef-typed value under the
`_builtin_function_` placeholder with no signature, so neither the slot nor
the module's own funcdefs can name it. `bgt_asir.name_engine_funcdefs` asks
outside the module: the documentation (`bgt api pathfinder` gives `bool
set_callback_function(pathfinder_callback@ callback)`) and, where BGT is not
installed or does not reach, the registration strings in the game's **own**
runtime -- the one executable always on hand, since it is the input. Crazy
Party's `JoueurTerrain::setPf` now recovers as
`pf.set_callback_function(pathfinder_callback(arg0.callbackPf))`.

**How much surface that has is measured, and it is one name.** A registered
*funcdef* is declared the way a function is, so it appears in `registered()`
under its own name, while a registered *type* never does -- every constructor
and factory is declared under the literal name `f`, with the owner as a
separate string. Asked of six binaries that way, the answer does not move:
BGT 1.3, Paladin, Super Egg Hunt and Crazy Party at 432 registrations, Psycho
Strike's fork at 453 and Manamon 2's at 509, spanning 2010 to 2019, register
**exactly one funcdef** -- `pathfinder_callback`, taken by exactly one method.
Not even the fork that added Crypto++ and a newer AngelScript adds a second
callback type. So this is a complete answer rather than a sample, and the
two sources agree on it.

**What Ghidra contributed here was nothing, and that is worth recording.**
The binary analysed fine (at a 5G heap; 2G runs out on this one), but the
xref search for `LoadByteCode failed` found no referencing function. What
cracked it was the self-verifying criteria the rest of this document is
built on: a declared count that walks to exactly a `RET`, and a tail that
lands exactly on EOF. Read the reader when the format is in question; when
your *own* reader is in question, the checks are what tell you.

**`--string` finds nobody more often than it should, and the fix is four
bytes.** That `LoadByteCode failed` dead end repeated exactly on
`GetProcAddress failed for '%s'`, which *is* referenced -- once, from
`0x0048107a`. This is a 32-bit build, so a literal's address is pushed as an
immediate: compute the string's VA from the section table and search the
file for those four bytes little-endian, then hand the hit to `--at`. That
turned three "no referencing function" answers into the `library`
registration block, the `GetProcAddress` site and the signature parser. Use
`--string` first and this when it comes back empty.

**A fifth title may differ again.** Three builds produced two answers for the
template-namespace field and two for the script-object flag. The fourth (SBYW)
parsed unchanged but used opcodes none of the others did. Run `bgt validate`
before assuming a new title matches, and check the lifter's passthrough count
as well as the stages.

And run `bgt recover` on more than one, for the reason Paladin showed: the
default-argument order was wrong from the start, and Psycho Strike has too few
defaults for it to matter there. A title that recovers well is not evidence.

**What the recovered source still does not compile.** `bgt recover --compile`
is the measure, and the groups it leaves are known rather than mysterious:

**Three of the four groups this list used to name are gone, and the counts
it quoted for them were stale** -- 50 residual gotos in Psycho Strike, 10
`<?>` sites in Paladin and 1 in Psycho Strike, 7 funcdef-typed locals in
Psycho Strike. Re-measured against a fresh run of every title: **0, 0 and
0.** Only Manamon 2 still carries anything, and both of its groups are
named below rather than counted. A number in this file is a measurement
with a date on it, and these three had outlived theirs.

- **Residual `goto`.** The structurer labels flow it cannot shape, and
  AngelScript has no `goto`, so every one of those lines is an error. Four
  remain, all in Manamon 2; Paladin, Psycho Strike, Super Egg Hunt and Crazy
  Party are at zero. Either the shape gets recognised or those bodies need a
  dispatch rewrite; a label is not an option.
- **A body no switch matcher claims.** Three, all in Manamon 2, and they are
  three separate diagnoses rather than one mystery -- see **The three tables
  nothing claims**.
- **A call the simulation could not supply arguments for** printed `<?>`
  rather than inventing values. There is no longer one in any title.
- **A funcdef-typed local** had no name source could use. There is no longer
  a `_builtin_function_` anywhere in any recovered file, and the engine's
  whole funcdef surface turns out to be one name -- see **One site needs a
  name the module does not carry**.
- **A type no stock engine registers** (Psycho Strike's `elias`): reported,
  with the DLL it comes from, and not compilable here at all. This is the
  one that stands.

**The NVGT library corpus is checked for compiling, not meaning.** 40 of 52
library builds recompile -- six modules fail, the same six at HEAD and after
every change here, all on one generated list local that is used but not
declared. NVGT decompiler bugs compile cleanly while computing something
else, so a new construct belongs in a fixture, not only in the corpus.

**And the fixtures that *run* have to be able to run.** `test_roundtrip_behavior`
is the check that catches a decompile which compiles and lies, and in this
environment it was inert: without `NVGT_COMPILER` it skips, and with it every
case died in `subprocess` before the compiler started. So the BGT work changed
`decompile.py` by 774 lines with that check silently not running, and three
regressions got in. Each was found by making it run, and fixed rather than
accommodated:

- **A dense switch's default is not last.** The arms come out in bytecode
  order, and a jump table's default target is the code right after the table
  -- before every case body. AngelScript rejects that ("The default case must
  be the last one"), so three fixtures and the library's `native_form` did not
  compile at all. `_default_last` moves it, but only when it neither falls
  through nor is fallen into: its own statements must end in `return`, `break`
  or `continue`, and so must the arm above it. Otherwise the order stands,
  because a switch that does not compile beats one that runs the wrong arm.
- **A bool-literal comparison stopped simplifying.** Typing a reused slot
  numeric renders a bool operand as `(X ? 1 : 0)`, and the simplification
  matched only a bare `true`/`false`, so `x == false` came back as
  `(!getf(arg0) ? 1 : 0) == (false ? 1 : 0)` -- correct, compiling, and
  saying nothing. `_unwrap_bool` sees through the wrapper; its paren-balance
  check is load-bearing, because `(a ? 1 : 0) + (b ? 1 : 0)` also begins with
  `(` and ends with `)`.
- **A generated local's declaration is hoisted**, which split
  `bool __nvgt_ret_N = d.get(...)` into a declaration and an assignment. That
  is the safer shape -- such a local can be read outside the block whose call
  created it -- so the fixture now pins the intent rather than the old
  spelling.

The lesson is about the harness, not the decompiler: **a check that cannot run
is worse than no check**, because it is counted. Every `subprocess` call in
this repository now passes `stdin=subprocess.DEVNULL`, and that is the reason.

**Two narrow NVGT constructs still decompile wrong** (repros in `docs/nvgt.md`),
both pre-existing and found while fixing the three below: a `? :` over the
constants 0 and 1 *added inside an expression* (`(x>0 ? 1:0) + ...` -- the `0/1`
arms make `_begin_bool_merge` claim it before `_begin_value_merge` can, and its
`ADDi` merge produces an empty `if`), and a guarded increment in a stripped
build (`if (f()) total += 10;` sometimes hoists the `+= 10` out of the `if`).

**Three compiles-and-lies bugs found with the control-flow fixture are fixed:**
a ternary used *inside* a larger expression (`10 + (c ? 3 : 7)` no longer
becomes `10 + 7` -- the value-merge derives the ternary's slot from its arms
when the merge is arithmetic); a `for` variable reused across sibling scopes
(hoisting takes scalar names from every debug variable, not just the last per
slot); and a `&&`/`||` whose result is *stored* in a bool and used later (the
merge folds `(A op B)` into the stored slot at its `CpyVtoV4`, so an `if`, a
ternary or an expression reading it later sees the whole value -- guarded to a
bool destination so a uint ternary still goes to the value-merge).

**NVGT payloads from unverified builds.** Official NVGT releases get fresh
packaging parameters per build, so executables from releases without a verified
profile are reported as unsupported (see `docs/nvgt.md`). That is deliberate. A
profile is added only after it has been verified against real samples.

# Conventions

- **Read the reader, don't guess the format.** Every format detail here came out of a
  game's own `asCReader` / `pack::create` in Ghidra -- or, for NVGT, its published
  source. `bgt.exe` itself is worth opening: it settled the template-stub question
  (`bgt ghidra decompile "<BGT>/bgt.exe" --string factstub`).
- **Compiling is not meaning; run it.** Output that recompiles is valid, not
  equivalent. A dropped `@h.item = b`, an out argument copied before the call
  that fills it, and a `?&in` handle passed as a copy all compiled cleanly.
  Running the result and comparing it with the original caught each one.
- **Make each layer self-verifying.** Exact declared lengths, exact EOF landings,
  identifier-shaped names. A parser that "mostly works" is a parser that is silently
  desynchronised.
- **Validate against something you did not write.** BGT ships the source of several
  standard-library classes under its install directory; a lifter can be checked
  against them objectively rather than by spot-checking output that looks plausible.
- **Cross-validate across titles.** These games share a runtime, so a change that
  improves one title and breaks another is wrong.
- **A metric can be confidently wrong.** A greedy search optimising stack residue once
  adopted eight opcode stack-effect changes and was wrong about seven of them. Read
  `asBCInfo[]` out of the binary instead.
- Keep this folder free of game files and per-title findings. Scratch output goes
  somewhere else and is reproducible in one command.
